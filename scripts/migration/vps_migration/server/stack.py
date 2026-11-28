import base64
from contextlib import closing
import json
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import quote, urlencode
import uuid

from vps_migration.core import common as c

IMAGES = {
    'substore-node': 'node:24.22.1-bookworm-slim',
    'xray': 'ghcr.io/xtls/xray-core:latest',
    'awg': 'amneziavpn/amneziawg-go:latest',
    'telemt': 'ghcr.io/telemt/telemt:latest',
    'hysteria': 'tobyxdd/hysteria:latest',
    'xui': 'ghcr.io/mhsanaei/3x-ui@sha256:ed329189f0f743fea3584fe2f1d197a68951c76c7671622655a91e82348bf7fd',
    'backend': 'ghcr.io/denpiligrim/3dp-manager-server@sha256:3f760f1ecf6162595b3291c7bd90c689506647333641cad62a7b27ca57d2ace4',
    'frontend': 'ghcr.io/denpiligrim/3dp-manager-client@sha256:373bfcaee91e07e29f97e6a673cf54cdda0b3affda85592504eda2c7ff99ea84',
    'postgres': 'postgres:18-alpine',
    'nginx': 'nginx@sha256:8eb04fe3b385090e9aa02961f77398ad09b6bf33ab07f6669a5bb7acce22c0d3',
    'haproxy': 'haproxy@sha256:7816a9801a6846b912bc37e48529808e2fa87c3c47992441940f68e393ebcfeb',
}
ROLES = ['personal', 'shared']
NETWORK = 'vps-stack-network'


def exists(name):
    return c.run(['docker', 'inspect', name], check=False).returncode == 0


def image(component):
    reference = IMAGES[component]
    registry = c.ROOT / 'image-lock.json'
    values = json.loads(registry.read_text()) if registry.exists() else {}
    previous = values.get(component)
    if previous and c.run(['docker', 'image', 'inspect', previous['id']], check=False).returncode == 0:
        return previous['id']
    c.run(['docker', 'pull', reference], timeout=1800)
    current = c.docker_json('image', 'inspect', reference)[0]
    values[component] = {'requested': reference, 'id': current['Id'], 'digests': current.get('RepoDigests', [])}
    c.write(registry, values)
    return current['Id']


def tools_image():
    context = c.JOB / 'tools-image'
    context.mkdir(exist_ok=True)
    c.write(context / 'Dockerfile', 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends bash ca-certificates curl openssl iptables iproute2 wireguard-tools openvpn easy-rsa procps && rm -rf /var/lib/apt/lists/*\n')
    c.run(['docker', 'build', '-t', 'vps-stack-tools:' + c.JOB.name, str(context)], timeout=1800)
    return 'vps-stack-tools:' + c.JOB.name


def network():
    if c.run(['docker', 'network', 'inspect', NETWORK], check=False).returncode:
        c.api('POST', '/networks/create', {'Name': NETWORK, 'Driver': 'bridge',
              'Labels': {'vps-stack': 'managed'}})


def create(name, reference, command=None, ports=None, mounts=None, environment=None,
           aliases=None, entrypoint=None, tunnel=False, readonly=False, working=None, healthcheck=None, request=None):
    if exists(name):
        raise RuntimeError('Контейнер уже существует: ' + name)
    network()
    bindings = {}
    for inside, outside in (ports or {}).items():
        bindings[inside] = [{'HostIp': address, 'HostPort': str(port)} for address, port in outside]
    if bindings:
        bindings = c.exposure_bindings(name, bindings, request or {})
    host = {'NetworkMode': NETWORK, 'PortBindings': bindings,
            'RestartPolicy': {'Name': 'unless-stopped'}, 'Mounts': mounts or [],
            'LogConfig': {'Type': 'local', 'Config': {'max-size': '10m', 'max-file': '3'}},
            'ReadonlyRootfs': readonly, 'SecurityOpt': ['no-new-privileges:true']}
    if tunnel:
        host.update({'CapAdd': ['NET_ADMIN'], 'Devices': [{'PathOnHost': '/dev/net/tun',
                     'PathInContainer': '/dev/net/tun', 'CgroupPermissions': 'rwm'}],
                     'Sysctls': {'net.ipv4.ip_forward': '1'}})
    if readonly:
        host['Tmpfs'] = {'/run/telemt': 'rw,mode=1777,size=8m', '/tmp': 'rw,size=8m'}
    payload = {'Image': reference, 'User': '0', 'Labels': {'vps-stack': 'managed'},
               'HostConfig': host, 'Env': [key + '=' + str(value) for key, value in (environment or {}).items()],
               'ExposedPorts': {key: {} for key in bindings},
               'NetworkingConfig': {'EndpointsConfig': {NETWORK: {'Aliases': aliases or [name]}}}}
    if command is not None:
        payload['Cmd'] = command
    if entrypoint is not None:
        payload['Entrypoint'] = entrypoint
    if working:
        payload['WorkingDir'] = working
    if healthcheck:
        payload['Healthcheck'] = healthcheck
    created = c.api('POST', '/containers/create?name=' + quote(name, safe=''), payload)
    c.run(['docker', 'start', created['Id']])
    return created['Id']


def bind(path, target, readonly=True):
    return {'Type': 'bind', 'Source': str(path), 'Target': target, 'ReadOnly': readonly}


def published(port):
    return [('0.0.0.0', port)]


def configuration(name, value, suffix='json'):
    path = c.ROOT / 'config' / name / ('server.' + suffix)
    c.write(path, value)
    return path


def wg_key(reference, tool, operation, content=None):
    return c.run(['docker', 'run', '--rm', '-i', '--entrypoint', tool,
                  reference, operation], content).stdout.decode().strip()


def wireguard(request, reference, awg=False):
    name = 'amnezia-awg2' if awg else 'vpn-wireguard'
    if exists(name):
        return
    tool = '/usr/bin/awg' if awg else '/usr/bin/wg'
    port = 46872 if awg else 51820
    subnet = '10.8.1' if awg else '10.9.1'
    interface = 'awg0' if awg else 'wg0'
    private = wg_key(reference, tool, 'genkey')
    public = wg_key(reference, tool, 'pubkey', (private + '\n').encode())
    extras = ''
    if awg:
        headers = secrets.SystemRandom().sample(range(5, 2 ** 31), 4)
        extras = 'Jc = 4\nJmin = 40\nJmax = 70\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\n'
        extras += ''.join('H' + str(index + 1) + ' = ' + str(value) + '\n' for index, value in enumerate(headers))
    server = '[Interface]\nPrivateKey = ' + private + '\nAddress = ' + subnet + '.1/24\nListenPort = ' + str(port) + '\n'
    server += extras + 'PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n'
    for index, role in enumerate(ROLES, 2):
        client_private = wg_key(reference, tool, 'genkey')
        client_public = wg_key(reference, tool, 'pubkey', (client_private + '\n').encode())
        psk = wg_key(reference, tool, 'genpsk')
        server += '\n[Peer]\nPublicKey = ' + client_public + '\nPresharedKey = ' + psk + '\nAllowedIPs = ' + subnet + '.' + str(index) + '/32\n'
        client = '[Interface]\nPrivateKey = ' + client_private + '\nAddress = ' + subnet + '.' + str(index) + '/32\nDNS = 1.1.1.1\n' + extras
        client += '\n[Peer]\nPublicKey = ' + public + '\nPresharedKey = ' + psk + '\nEndpoint = ' + request['domain'] + ':' + str(port)
        client += '\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'
        c.export_access(role, 'amneziawg' if awg else 'wireguard', client, extension='conf')
    directory = c.ROOT / 'config' / name
    c.write(directory / (interface + '.conf'), server)
    script = ('awg-quick' if awg else 'wg-quick') + ' up /etc/vpn/' + interface + '.conf; exec tail -f /dev/null'
    create(name, reference, ['-ec', script], {str(port) + '/udp': published(port)},
           [bind(directory, '/etc/vpn')], entrypoint=['/bin/bash'], tunnel=True, request=request)


def xray(request):
    private, public = c.x25519_pair()
    short_id = secrets.token_hex(8)
    clients = [{'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision'} for role in ROLES]
    camouflage = request['camouflage']
    inbound = {'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
               'settings': {'clients': clients, 'decryption': 'none'},
               'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                   'show': False, 'target': camouflage + ':443', 'serverNames': [camouflage],
                   'privateKey': private, 'shortIds': [short_id]}}}
    path = configuration('xray', {'log': {'loglevel': 'warning'}, 'inbounds': [inbound],
                                  'outbounds': [{'protocol': 'freedom'}]})
    create('amnezia-xray', image('xray'), ['run', '-c', '/etc/vpn/server.json'],
           {'443/tcp': published(443)}, [bind(path.parent, '/etc/vpn')], request=request)
    table = []
    for role, client in zip(ROLES, clients):
        reality = {'serverName': camouflage, 'publicKey': public, 'shortId': short_id, 'fingerprint': c.fingerprint(request)}
        c.export_access(role, 'xray', c.xray_client(client['id'], request['domain'], 443, reality),
                        c.vless_link(client['id'], request['domain'], 443, reality, 'VPN-' + role))
        table.append({'clientId': client['id'], 'userData': {'clientName': 'VPN-' + role}})
    c.write(path.parent / 'clientsTable', table)


def telemt(request):
    secrets_by_role = {role: secrets.token_hex(16) for role in ROLES}
    config = '[general]\nuse_middle_proxy = true\n[general.modes]\nclassic = false\nsecure = false\ntls = true\n'
    config += '[server]\nport = 50553\n[server.api]\nenabled = false\n[censorship]\ntls_domain = "' + request['camouflage'] + '"\n[access.users]\n'
    config += ''.join(role + ' = "' + value + '"\n' for role, value in secrets_by_role.items())
    path = configuration('telemt', config, 'toml')
    create('amnezia-telemt', image('telemt'), ['/etc/telemt/server.toml'],
           {'50553/tcp': published(50553)}, [bind(path.parent, '/etc/telemt')], readonly=True, working='/run/telemt',
           healthcheck={'Test': ['CMD', '/app/telemt', 'healthcheck', '/etc/telemt/server.toml', '--mode', 'liveness'],
                        'Interval': 30_000_000_000, 'Timeout': 5_000_000_000, 'StartPeriod': 20_000_000_000, 'Retries': 3}, request=request)
    for role, value in secrets_by_role.items():
        secret = 'ee' + value + request['camouflage'].encode().hex()
        link = 'tg://proxy?' + urlencode({'server': request['domain'], 'port': 50553, 'secret': secret})
        c.export_access(role, 'telegram', {'server': request['domain'], 'port': 50553, 'secret': secret}, link)


def shadowsocks(request):
    method = 'chacha20-ietf-poly1305'
    inbounds = []
    ports = {}
    for index, role in enumerate(ROLES):
        port = 8388 + index
        secret = c.password()
        inbounds.append({'port': port, 'listen': '0.0.0.0', 'protocol': 'shadowsocks',
                         'settings': {'method': method, 'password': secret, 'network': 'tcp,udp'}})
        ports.update({str(port) + '/tcp': published(port), str(port) + '/udp': published(port)})
        auth = base64.urlsafe_b64encode((method + ':' + secret).encode()).decode().rstrip('=')
        link = 'ss://' + auth + '@' + request['domain'] + ':' + str(port) + '#' + role
        c.export_access(role, 'shadowsocks', {'server': request['domain'], 'server_port': port,
                         'method': method, 'password': secret, 'local_port': 1080}, link)
    path = configuration('shadowsocks', {'inbounds': inbounds, 'outbounds': [{'protocol': 'freedom'}]})
    create('vpn-shadowsocks', image('xray'), ['run', '-c', '/etc/vpn/server.json'], ports, [bind(path.parent, '/etc/vpn')], request=request)


def hysteria(request):
    credentials = {role: c.password() for role in ROLES}
    obfuscation = c.password()
    cert = '/etc/letsencrypt/live/' + request['domain']
    config = {'listen': ':2443', 'tls': {'cert': cert + '/fullchain.pem', 'key': cert + '/privkey.pem'},
              'auth': {'type': 'userpass', 'userpass': credentials},
              'obfs': {'type': 'salamander', 'salamander': {'password': obfuscation}}}
    path = configuration('hysteria', config)
    create('vpn-hysteria2', image('hysteria'), ['server', '-c', '/etc/vpn/server.json'],
           {'2443/udp': published(2443)}, [bind(path.parent, '/etc/vpn'), bind('/etc/letsencrypt', '/etc/letsencrypt')], request=request)
    for role, secret in credentials.items():
        client = {'server': request['domain'] + ':2443', 'auth': role + ':' + secret,
                  'tls': {'sni': request['domain']}, 'obfs': config['obfs'],
                  'socks5': {'listen': '127.0.0.1:1080'}}
        link = 'hysteria2://' + quote(role + ':' + secret, safe=':') + '@' + request['domain'] + ':2443/?'
        link += urlencode({'sni': request['domain'], 'obfs': 'salamander', 'obfs-password': obfuscation}) + '#' + role
        c.export_access(role, 'hysteria2', client, link)


def openvpn(request, reference):
    directory = c.ROOT / 'config/openvpn'
    directory.mkdir(parents=True)
    script = 'export EASYRSA_PKI=/etc/openvpn/pki EASYRSA_BATCH=1 EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1; '
    script += '/usr/share/easy-rsa/easyrsa init-pki; EASYRSA_REQ_CN=VPN-CA /usr/share/easy-rsa/easyrsa build-ca nopass; '
    for name in ['server', *ROLES]:
        script += '/usr/share/easy-rsa/easyrsa build-' + ('server' if name == 'server' else 'client') + '-full ' + name + ' nopass; '
    script += 'openvpn --genkey secret /etc/openvpn/tls-crypt.key'
    c.run(['docker', 'run', '--rm', '--mount', 'type=bind,source=' + str(directory) + ',target=/etc/openvpn',
           '--entrypoint', '/bin/bash', reference, '-ec', script], timeout=900)
    server = 'port 1194\nproto udp\ndev tun\ntopology subnet\nserver 10.10.1.0 255.255.255.0\n'
    server += 'ca /etc/openvpn/pki/ca.crt\ncert /etc/openvpn/pki/issued/server.crt\nkey /etc/openvpn/pki/private/server.key\ndh none\n'
    server += 'tls-crypt /etc/openvpn/tls-crypt.key\ntls-version-min 1.2\nverify-client-cert require\nremote-cert-tls client\n'
    server += 'data-ciphers AES-256-GCM:CHACHA20-POLY1305\nkeepalive 10 120\npersist-key\npersist-tun\nduplicate-cn\nuser nobody\ngroup nogroup\n'
    server += 'push "redirect-gateway def1"\npush "dhcp-option DNS 1.1.1.1"\nverb 3\n'
    c.write(directory / 'server.conf', server)
    start = 'iptables -A FORWARD -i tun0 -j ACCEPT; iptables -A FORWARD -o tun0 -j ACCEPT; '
    start += 'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; exec openvpn --config /etc/openvpn/server.conf'
    create('vpn-openvpn', reference, ['-ec', start], {'1194/udp': published(1194)},
           [bind(directory, '/etc/openvpn')], entrypoint=['/bin/bash'], tunnel=True, request=request)
    for role in ROLES:
        client = 'client\ndev tun\nproto udp\nremote ' + request['domain'] + ' 1194\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nverify-x509-name server name\ntls-version-min 1.2\nverb 3\n'
        for tag, path in [('ca', directory / 'pki/ca.crt'), ('cert', directory / ('pki/issued/' + role + '.crt')),
                          ('key', directory / ('pki/private/' + role + '.key')), ('tls-crypt', directory / 'tls-crypt.key')]:
            text = path.read_text()
            if tag == 'cert':
                text = text[text.index('-----BEGIN CERTIFICATE-----'):]
            client += '<' + tag + '>\n' + text.strip() + '\n</' + tag + '>\n'
        c.export_access(role, 'openvpn', client, extension='ovpn')


def wait_xui_user(directory, username=None):
    database = directory / 'x-ui.db'
    for attempt in range(60):
        if database.is_file():
            try:
                with closing(sqlite3.connect(database)) as connection:
                    if username is None:
                        count = connection.execute('SELECT count(*) FROM users').fetchone()[0]
                    else:
                        count = connection.execute('SELECT count(*) FROM users WHERE username=?', (username,)).fetchone()[0]
                if count > 0:
                    return
            except sqlite3.OperationalError:
                count = 0
        time.sleep(1)
    raise RuntimeError('Пользователь панели 3x-ui не появился в базе')


def panels(request):
    administrator = {'login': 'owner', 'xui_password': c.password(), 'manager_password': c.password(),
                     'xui_base_path': '/' + secrets.token_hex(10) + '/',
                     'xui_url': 'http://127.0.0.1:2053', 'manager_url': 'https://' + request['domain'] + ':6659'}
    c.write(c.ROOT / 'exports/admin/panels.json', administrator)
    xui = c.ROOT / 'config/xui'
    xui.mkdir(parents=True)
    create('3x-ui', image('xui'), ports={'2053/tcp': [('127.0.0.1', 2053)]}, mounts=[bind(xui, '/etc/x-ui', False)])
    wait_xui_user(xui)
    c.run(['docker', 'exec', '3x-ui', '/app/x-ui', 'setting', '-username', administrator['login'],
           '-password', administrator['xui_password'], '-port', '2053', '-webBasePath', administrator['xui_base_path']])
    wait_xui_user(xui, administrator['login'])
    c.run(['docker', 'restart', '3x-ui'])
    db_password = c.password()
    pg = c.ROOT / 'config/postgres'
    pg.mkdir(parents=True)
    pg.chmod(0o755)
    create('3dp-postgres', image('postgres'), mounts=[bind(pg, '/var/lib/postgresql', False)],
           environment={'POSTGRES_USER': 'manager', 'POSTGRES_PASSWORD': db_password, 'POSTGRES_DB': 'manager'}, aliases=['postgres'])
    for attempt in range(60):
        if c.run(['docker', 'exec', '3dp-postgres', 'pg_isready', '-U', 'manager', '-d', 'manager'], check=False).returncode == 0:
            break
        time.sleep(2)
    else:
        raise RuntimeError('PostgreSQL не готов')
    create('3dp-backend', image('backend'), environment={'DB_HOST': 'postgres', 'DB_PORT': '5432',
           'DB_USERNAME': 'manager', 'DB_PASSWORD': db_password, 'DB_NAME': 'manager',
           'DB_SYNCHRONIZE': 'true', 'DB_MIGRATIONS_RUN': 'false', 'JWT_SECRET': c.password(),
           'ADMIN_LOGIN': administrator['login'], 'ADMIN_PASSWORD': administrator['manager_password'],
           'PORT': '3100', 'NODE_ENV': 'production', 'ALLOWED_ORIGINS': administrator['manager_url']}, aliases=['backend'])
    nginx = 'server { listen 443 ssl; server_name ' + request['domain'] + ';\n'
    nginx += 'ssl_certificate /etc/letsencrypt/live/' + request['domain'] + '/fullchain.pem;\n'
    nginx += 'ssl_certificate_key /etc/letsencrypt/live/' + request['domain'] + '/privkey.pem;\n'
    nginx += 'root /usr/share/nginx/html; index index.html; location / { try_files $uri $uri/ /index.html; }\n'
    nginx += 'location /api/ { proxy_pass http://backend:3100/api/; proxy_set_header Host $host; }\n'
    nginx += 'location /bus/ { proxy_pass http://backend:3100/bus/; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; } }\n'
    path = configuration('frontend', nginx, 'conf')
    create('3dp-frontend', image('frontend'), ports={'443/tcp': published(6659)}, mounts=[
           bind(path, '/etc/nginx/conf.d/default.conf'), bind('/etc/letsencrypt', '/etc/letsencrypt')], request=request)
    administrator['network_profile'] = c.network_profile(request)
    administrator['ssh_tunnel_required'] = c.network_profile(request) == 'filtered'
    c.write(c.ROOT / 'exports/admin/panels.json', administrator)


def fresh(request):
    reference = tools_image()
    wireguard(request, image('awg'), awg=True)
    xray(request)
    telemt(request)
    panels(request)
    reserves(request, reference)


def reserves(request, reference=None):
    missing = [name for name in ['vpn-wireguard', 'vpn-openvpn', 'vpn-shadowsocks', 'vpn-hysteria2'] if not exists(name)]
    if request.get('self_steal') and 'vpn-hysteria2' in missing:
        missing.remove('vpn-hysteria2')
    if not missing:
        return
    reference = reference or tools_image()
    if 'vpn-wireguard' in missing:
        wireguard(request, reference)
    if 'vpn-openvpn' in missing:
        openvpn(request, reference)
    if 'vpn-shadowsocks' in missing:
        shadowsocks(request)
    if 'vpn-hysteria2' in missing:
        hysteria(request)
