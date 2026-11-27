import copy
import json
import secrets
from urllib.parse import quote, urlencode
import uuid

from vps_migration.core import common as c
from vps_migration.server import stack

NAMES = ['vpn-selfsteal-xray', 'vpn-selfsteal-site', 'vpn-selfsteal-hysteria2', 'vpn-edge']


def tls_client(identifier, request, path=None):
    transport = {'network': 'xhttp' if path else 'tcp', 'security': 'tls',
                 'tlsSettings': {'serverName': request['domain'], 'fingerprint': c.fingerprint(request)}}
    user = {'id': identifier, 'encryption': 'none'}
    if path:
        transport['xhttpSettings'] = {'path': path, 'mode': 'packet-up'}
    else:
        user['flow'] = 'xtls-rprx-vision'
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 10808,
            'protocol': 'socks', 'settings': {'udp': True}}], 'outbounds': [{'protocol': 'vless',
            'settings': {'vnext': [{'address': request['domain'], 'port': 443, 'users': [user]}]},
            'streamSettings': transport}]}


def link(identifier, request, role, path=None):
    query = {'encryption': 'none', 'security': 'tls', 'sni': request['domain'],
             'fp': c.fingerprint(request), 'type': 'xhttp' if path else 'tcp'}
    if path:
        query.update({'path': path, 'mode': 'packet-up'})
    else:
        query['flow'] = 'xtls-rprx-vision'
    return 'vless://' + identifier + '@' + request['domain'] + ':443?' + urlencode(query) + '#' + quote('SelfSteal-' + role)


def configuration(request, clients, path):
    certificate = '/etc/letsencrypt/live/' + request['domain']
    main = {'tag': 'selfsteal-main', 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
            'settings': {'decryption': 'none', 'clients': [dict(item, flow='xtls-rprx-vision') for item in clients],
                         'fallbacks': [{'alpn': 'h2', 'dest': 'vpn-selfsteal-site:8081'},
                                       {'dest': 'vpn-selfsteal-site:8080'}]},
            'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                'minVersion': '1.2', 'alpn': ['h2', 'http/1.1'], 'certificates': [{
                    'certificateFile': certificate + '/fullchain.pem', 'keyFile': certificate + '/privkey.pem'}]}}}
    xhttp = {'tag': 'selfsteal-xhttp', 'listen': '0.0.0.0', 'port': 18080, 'protocol': 'vless',
             'settings': {'decryption': 'none', 'clients': copy.deepcopy(clients)},
             'streamSettings': {'network': 'xhttp', 'security': 'none',
                                'xhttpSettings': {'path': path, 'mode': 'packet-up'}}}
    return {'log': {'loglevel': 'warning'}, 'inbounds': [main, xhttp], 'outbounds': [{'protocol': 'freedom'}]}


def site_configuration(path):
    return ('server { listen 8080; listen 8081 http2; server_name _;\n'
            'root /usr/share/nginx/html; index index.html;\n'
            'location ' + path + ' { proxy_pass http://vpn-selfsteal-xray:18080; '
            'proxy_http_version 1.1; proxy_set_header Host $host; proxy_buffering off; '
            'proxy_request_buffering off; proxy_read_timeout 3600s; client_max_body_size 0; }\n'
            'location / { try_files $uri $uri/ =404; } }\n')


def edge_configuration(domain):
    c.validate_domain(domain)
    return ('global\n  log stdout format raw local0\n'
            'defaults\n  mode tcp\n  timeout connect 10s\n  timeout client 1h\n  timeout server 1h\n'
            'frontend tls_entry\n  bind :443\n  tcp-request inspect-delay 5s\n'
            '  tcp-request content accept if { req.ssl_hello_type 1 }\n'
            '  use_backend selfsteal if { req.ssl_sni -i ' + domain + ' }\n'
            '  default_backend legacy\n'
            'backend selfsteal\n  server selfsteal vpn-selfsteal-xray:443\n'
            'backend legacy\n  server legacy amnezia-xray:443\n')


def export_access(request):
    config = json.loads((c.ROOT / 'config/selfsteal-xray/server.json').read_text())
    path = config['inbounds'][1]['streamSettings']['xhttpSettings']['path']
    for client in config['inbounds'][0]['settings']['clients']:
        role = client['email'].split('@', 1)[0]
        if role not in stack.ROLES:
            raise RuntimeError('Неизвестная роль доступа Self-Steal')
        for protocol, route in [('selfsteal-vless', None), ('selfsteal-xhttp', path)]:
            c.export_access(role, protocol, tls_client(client['id'], request, route), link(client['id'], request, role, route))
    hy = json.loads((c.ROOT / 'config/selfsteal-hysteria/server.json').read_text())
    for role, secret in hy['auth']['userpass'].items():
        if role not in stack.ROLES:
            raise RuntimeError('Неизвестная роль доступа Hysteria2 Self-Steal')
        client = {'server': request['domain'] + ':443', 'auth': role + ':' + secret,
                  'tls': {'sni': request['domain']}, 'obfs': hy['obfs'], 'socks5': {'listen': '127.0.0.1:1080'}}
        query = {'sni': request['domain'], 'obfs': 'salamander', 'obfs-password': hy['obfs']['salamander']['password']}
        uri = 'hysteria2://' + quote(role + ':' + secret, safe=':') + '@' + request['domain'] + ':443/?' + urlencode(query) + '#' + role
        c.export_access(role, 'selfsteal-hysteria2', client, uri)


def install(request):
    present = [name for name in NAMES if stack.exists(name)]
    if present:
        if set(present) != set(NAMES):
            raise RuntimeError('Восстановлена неполная схема Self-Steal; автоматическая перезапись запрещена')
        export_access(request)
        return
    legacy = c.docker_json('inspect', 'amnezia-xray')[0]
    if any(item.get('HostIp') not in ['127.0.0.1', '::1'] for item in legacy['HostConfig']['PortBindings'].get('443/tcp', [])):
        raise RuntimeError('Старый XRay должен иметь закрытую публикацию TCP 443 перед добавлением маршрутизатора')
    local = c.ROOT / 'config/xray/server.json'
    if local.exists():
        legacy_config = json.loads(local.read_text())
    else:
        legacy_config = json.loads(c.run(['docker', 'exec', 'amnezia-xray', 'cat', '/opt/amnezia/xray/server.json']).stdout)
    for inbound in legacy_config.get('inbounds', []):
        if inbound.get('port') != 443:
            continue
        stream = inbound.get('streamSettings', {})
        if inbound.get('protocol') != 'vless' or stream.get('network', 'tcp') not in ['tcp', 'raw']:
            raise RuntimeError('Автоматическое совместное использование TCP 443 поддерживает прежний VLESS RAW/REALITY')
        if stream.get('security') == 'tls' or request['domain'] in stream.get('realitySettings', {}).get('serverNames', []):
            raise RuntimeError('SNI старого XRay конфликтует с Self-Steal; требуется отдельный домен и явная настройка маршрута')
    stack.network()
    if stack.NETWORK not in legacy['NetworkSettings']['Networks']:
        c.api('POST', '/networks/' + stack.NETWORK + '/connect', {'Container': 'amnezia-xray', 'EndpointConfig': {}})
    clients = [{'id': str(uuid.uuid4()), 'email': role + '@local'} for role in stack.ROLES]
    path = '/' + secrets.token_hex(16) + '/'
    xray = stack.configuration('selfsteal-xray', configuration(request, clients, path))
    site = stack.configuration('selfsteal-site', site_configuration(path), 'conf')
    c.write(site.parent / 'index.html', '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title>'
            '<style>body{font:18px system-ui;max-width:52rem;margin:12vh auto;padding:2rem;color:#203040}</style>'
            '<h1>Welcome</h1><p>This website is online.</p></html>\n')
    (site.parent / 'index.html').chmod(0o644)
    stack.create('vpn-selfsteal-xray', stack.image('xray'), ['run', '-c', '/etc/vpn/server.json'],
                 mounts=[stack.bind(xray.parent, '/etc/vpn'), stack.bind('/etc/letsencrypt', '/etc/letsencrypt')])
    stack.create('vpn-selfsteal-site', stack.image('nginx'), mounts=[
        stack.bind(site, '/etc/nginx/conf.d/default.conf'), stack.bind(site.parent / 'index.html', '/usr/share/nginx/html/index.html')])
    edge = stack.configuration('selfsteal-edge', edge_configuration(request['domain']), 'cfg')
    stack.create('vpn-edge', stack.image('haproxy'), ports={'443/tcp': stack.published(443)},
                 mounts=[stack.bind(edge, '/usr/local/etc/haproxy/haproxy.cfg')], request=request)
    certificate = '/etc/letsencrypt/live/' + request['domain']
    hy = {'listen': ':443', 'tls': {'cert': certificate + '/fullchain.pem', 'key': certificate + '/privkey.pem'},
          'auth': {'type': 'userpass', 'userpass': {role: c.password() for role in stack.ROLES}},
          'obfs': {'type': 'salamander', 'salamander': {'password': c.password()}},
          'masquerade': {'type': 'proxy', 'proxy': {'url': 'http://vpn-selfsteal-site:8080/', 'rewriteHost': True}}}
    hysteria = stack.configuration('selfsteal-hysteria', hy)
    stack.create('vpn-selfsteal-hysteria2', stack.image('hysteria'), ['server', '-c', '/etc/vpn/server.json'],
                 {'443/udp': stack.published(443)}, [stack.bind(hysteria.parent, '/etc/vpn'),
                 stack.bind('/etc/letsencrypt', '/etc/letsencrypt')], request=request)
    export_access(request)
