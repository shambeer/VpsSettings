import argparse
import base64
import datetime
import ipaddress
import hashlib
from http.cookies import SimpleCookie
import http.client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import sqlite3
import sys
import time
import tomllib
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

import common as c
import snapshot
import stack


def progress(value):
    print(value, flush=True)
    if c.JOB:
        c.write(c.JOB / 'progress.json', {'stage': value})


def preflight(request, target=True):
    if os.geteuid() != 0 or platform.system() != 'Linux':
        raise RuntimeError('Нужен root на Linux-сервере')
    if platform.machine() not in ['x86_64', 'amd64']:
        raise RuntimeError('Эта версия сценария рассчитана только на Linux x86_64')
    values = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip('"')
    supported = {'ubuntu': ['24.04', '26.04'], 'debian': ['12', '13']}
    if values.get('VERSION_ID') not in supported.get(values.get('ID'), []):
        raise RuntimeError('Поддерживаются Ubuntu 24.04/26.04 и Debian 12/13')
    if sys.version_info < (3, 11) or not hasattr(__import__('tarfile'), 'data_filter'):
        raise RuntimeError('Нужен Python 3.11+ с актуальными исправлениями безопасности tarfile')
    if target:
        if c.run(['sh', '-c', 'command -v docker'], check=False).returncode == 0:
            if c.run(['docker', 'ps', '-aq']).stdout.strip():
                raise RuntimeError('Целевой сервер должен быть чистым: контейнеры уже существуют')
        if c.ROOT.exists():
            raise RuntimeError('/opt/vps-stack уже существует; автоматическая перезапись запрещена')
        memory = int(re.search(r'MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text()).group(1))
        if memory < 1500 * 1024 or shutil.disk_usage('/').free < 6 * 1024 ** 3:
            raise RuntimeError('Нужно минимум 1.5 GiB RAM и 6 GiB свободного диска; рекомендуется 2–4 GiB RAM')
        addresses = {item[4][0] for item in socket.getaddrinfo(request['domain'], None, socket.AF_INET)}
        if addresses != {request['ip']}:
            raise RuntimeError('Все A-записи домена должны указывать только на целевой IPv4')
        try:
            ipv6 = socket.getaddrinfo(request['domain'], None, socket.AF_INET6)
        except socket.gaierror:
            ipv6 = []
        if ipv6:
            raise RuntimeError('Этот сценарий настраивает IPv4: удалите AAAA домена до установки')
        if not Path('/dev/net/tun').exists():
            c.run(['modprobe', 'tun'])
        if not Path('/dev/net/tun').exists():
            raise RuntimeError('/dev/net/tun недоступен; проверьте настройки VPS у провайдера')
        listening = c.run(['ss', '-H', '-lntu']).stdout.decode()
        reserved = {80, 443, 1194, 2053, 2443, 6659, 8388, 8389, 46872, 50553, 51820}
        for line in listening.splitlines():
            fields = line.split()
            if len(fields) > 4:
                match = re.search(r':(\d+)$', fields[4])
                if match and int(match.group(1)) in reserved:
                    raise RuntimeError('На целевом сервере занят порт ' + match.group(1))


def packages():
    progress('Установка системных пакетов из репозитория ОС')
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    c.run(['apt-get', 'update'], timeout=900)
    c.run(['apt-get', 'install', '-y', 'docker.io', 'openssl', 'ca-certificates', 'curl', 'ufw',
           'fail2ban', 'python3-systemd', 'certbot', 'iproute2', 'kmod', 'unattended-upgrades'], timeout=1800)
    c.run(['systemctl', 'enable', '--now', 'docker'])
    c.run(['systemctl', 'stop', 'certbot.timer'], check=False)


def firewall(request):
    c.write('/etc/sysctl.d/90-vps-stack.conf', 'net.ipv4.ip_forward=1\n')
    c.run(['sysctl', '-p', '/etc/sysctl.d/90-vps-stack.conf'])
    server_port = os.environ.get('SSH_CONNECTION', '').split()
    server_port = int(server_port[-1]) if server_port else request.get('ssh_server_port', request['ssh_port'])
    c.run(['ufw', 'allow', str(server_port) + '/tcp'])
    tcp_ports = [80, 443]
    udp_ports = []
    if c.network_profile(request) == 'all':
        tcp_ports += [50553, 6659, 8388, 8389]
        udp_ports = [46872, 51820, 1194, 2443, 8388, 8389]
    for port in tcp_ports:
        c.run(['ufw', 'allow', str(port) + '/tcp'])
    for port in udp_ports:
        c.run(['ufw', 'allow', str(port) + '/udp'])
    c.run(['ufw', 'default', 'deny', 'incoming'])
    c.run(['ufw', 'default', 'allow', 'outgoing'])
    c.run(['ufw', '--force', 'enable'])
    c.run(['systemctl', 'restart', 'docker'])


def check_camouflage(request, domain=None, target=None):
    domain = c.validate_domain(domain or request['camouflage'])
    target = target or domain + ':443'
    endpoint = urlsplit('tls://' + target)
    if not endpoint.hostname or endpoint.port != 443:
        raise RuntimeError('В этой версии проверка REALITY поддерживает HTTPS-цель на порту 443')
    if domain == request['domain'] or endpoint.hostname == request['domain']:
        raise RuntimeError('Сайт REALITY не должен указывать на домен этого VPS: это создаёт петлю соединений')
    addresses = {item[4][0] for item in socket.getaddrinfo(endpoint.hostname, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)}
    if request['ip'] in addresses:
        raise RuntimeError('Цель REALITY указывает на этот VPS; выберите другой HTTPS-сайт')
    result = c.run(['openssl', 's_client', '-4', '-connect', target, '-servername', domain,
                    '-tls1_3', '-alpn', 'h2', '-verify_hostname', domain,
                    '-verify_return_error', '-no_ign_eof'], content=b'', timeout=25, check=False)
    text = (result.stdout + result.stderr).decode(errors='replace')
    supported = result.returncode == 0 and 'TLSv1.3' in text and bool(re.search(r'ALPN protocol:\s*h2(?:\s|$)', text))
    if c.JOB:
        name = 'camouflage-' + hashlib.sha256(domain.encode()).hexdigest()[:12] + '.json'
        c.write(c.JOB / name, {'domain': domain, 'target': target, 'tls13_h2_and_certificate_verified': supported})
    if not supported:
        raise RuntimeError('HTTPS-цель не прошла проверку сертификата, TLS 1.3 и HTTP/2; выберите другой сайт')


def certificate(request):
    if request.get('acme_agreed') is not True:
        raise RuntimeError('Не подтверждены условия выпуска сертификата Let’s Encrypt')
    command = ['certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos',
               '--keep-until-expiring', '--cert-name', request['domain'], '-d', request['domain']]
    if request.get('email'):
        command += ['--email', request['email']]
    else:
        command += ['--register-unsafely-without-email']
    c.run(command, timeout=900)
    legacy_cert = Path('/root/3x-ui/cert')
    if legacy_cert.exists():
        destination = legacy_cert / request['domain']
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ['fullchain.pem', 'privkey.pem']:
            c.write(destination / name, (Path('/etc/letsencrypt/live') / request['domain'] / name).read_bytes())
    c.run(['systemctl', 'enable', '--now', 'certbot.timer'])
    legacy_hook = Path('/etc/letsencrypt/renewal-hooks/deploy/60-3x-ui-domain-cert.sh')
    if legacy_hook.exists():
        shutil.move(str(legacy_hook), str(c.JOB / 'previous-60-3x-ui-domain-cert.sh'))
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/90-vps-stack')
    text = '#!/bin/sh\nset -eu\n'
    text += 'domain=' + request['domain'] + '\n'
    text += '[ "${RENEWED_LINEAGE:-}" = "/etc/letsencrypt/live/$domain" ] || exit 0\n'
    text += 'if [ -d /root/3x-ui/cert ]; then\n'
    text += '  domain=' + request['domain'] + '\n  install -d -m 700 "/root/3x-ui/cert/$domain"\n'
    text += '  install -m 600 "$RENEWED_LINEAGE/fullchain.pem" "/root/3x-ui/cert/$domain/fullchain.pem"\n'
    text += '  install -m 600 "$RENEWED_LINEAGE/privkey.pem" "/root/3x-ui/cert/$domain/privkey.pem"\nfi\n'
    text += 'for name in vpn-hysteria2 3dp-frontend 3x-ui; do\n'
    text += '  if [ "$(docker inspect -f \'{{.State.Running}}\' "$name" 2>/dev/null || true)" = true ]; then docker restart "$name" >/dev/null; fi\n'
    text += 'done\n'
    c.write(hook, text)
    hook.chmod(0o700)


def replace_endpoint(value, old_ip, old_domain, request, key=''):
    secret_keys = ['id', 'uuid', 'password', 'privatekey', 'publickey', 'shortid', 'shortids', 'token',
                   'secret', 'psk', 'presharedkey', 'auth', 'jwt_secret', 'db_password', 'postgres_password',
                   'username', 'login', 'email', 'admin_login']
    if key.lower() in secret_keys:
        return value
    if isinstance(value, dict):
        return {name: replace_endpoint(item, old_ip, old_domain, request, name) for name, item in value.items()}
    if isinstance(value, list):
        return [replace_endpoint(item, old_ip, old_domain, request, key) for item in value]
    if isinstance(value, str):
        try:
            nested = json.loads(value)
        except (ValueError, TypeError):
            nested = None
        if isinstance(nested, (dict, list)):
            return json.dumps(replace_endpoint(nested, old_ip, old_domain, request), ensure_ascii=False)
        if value.startswith('vmess://'):
            encoded = value[len('vmess://'):]
            parsed = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            updated = replace_endpoint(parsed, old_ip, old_domain, request)
            return 'vmess://' + base64.b64encode(json.dumps(updated).encode()).decode()
        if '://' in value:
            parts = urlsplit(value)
            if parts.hostname in [old_ip, old_domain]:
                address = request['ip'] if parts.hostname == old_ip else request['domain']
                auth = parts.netloc.rsplit('@', 1)[0] + '@' if '@' in parts.netloc else ''
                netloc = auth + address + (':' + str(parts.port) if parts.port else '')
                query = [(name, request['domain'] if item == old_domain and name in ['sni', 'serverName', 'host'] else item)
                         for name, item in parse_qsl(parts.query, keep_blank_values=True)]
                return urlunsplit((parts.scheme, netloc, parts.path, urlencode(query), parts.fragment))
            return value
        if value == old_ip:
            return request['ip']
        if value == old_domain:
            return request['domain']
        if value.startswith('/'):
            return value.replace('/' + old_domain + '/', '/' + request['domain'] + '/')
        return value
    return value


def rewrite_host_settings(manifest, request):
    old_ip = c.validate_ip(manifest['source_ip'])
    old_domain = c.validate_domain(manifest['source_domain'])
    paths = [Path(value) for value in manifest['host_roots'] if value != '/etc/letsencrypt']
    for base in paths:
        candidates = base.rglob('*') if base.is_dir() else [base]
        for path in candidates:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 ** 2:
                continue
            if path.suffix not in ['.json', '.conf', '.toml', '.txt', '.yml', '.yaml']:
                continue
            if any(part in ['pki', 'cert', 'certs', 'postgres', 'node_modules'] for part in path.parts):
                continue
            try:
                text = path.read_text()
            except (UnicodeError, OSError):
                continue
            if path.suffix == '.json':
                try:
                    value = json.loads(text)
                except ValueError:
                    continue
                updated = json.dumps(replace_endpoint(value, old_ip, old_domain, request), ensure_ascii=False, indent=2) + '\n'
            else:
                lines = []
                for line in text.splitlines(keepends=True):
                    if path.suffix == '.txt' and '://' in line:
                        line = replace_endpoint(line.rstrip(), old_ip, old_domain, request) + '\n'
                    elif re.match(r'\s*(?:server_name\s|ssl_certificate(?:_key)?\s|proxy_pass\s|remote\s|Endpoint\s*=)', line):
                        line = line.replace(old_ip, request['ip']).replace(old_domain, request['domain'])
                    lines.append(line)
                updated = ''.join(lines)
            if updated != text:
                path.write_text(updated)
    for container in manifest['containers']:
        if container['Name'].lstrip('/') != '3x-ui':
            continue
        for mount in container['Mounts']:
            if mount['Destination'] != '/etc/x-ui':
                continue
            directory = Path(mount['Source'])
            if mount['Type'] == 'volume':
                directory = Path(c.docker_json('volume', 'inspect', mount['Name'])[0]['Mountpoint'])
            db = directory / 'x-ui.db'
            if not db.exists():
                continue
            with sqlite3.connect(db) as connection:
                for rowid, settings in connection.execute('SELECT id,stream_settings FROM inbounds').fetchall():
                    updated = replace_endpoint(json.loads(settings), old_ip, old_domain, request)
                    connection.execute('UPDATE inbounds SET stream_settings=? WHERE id=?', (json.dumps(updated), rowid))


def start_restored(manifest, request):
    order = ['3dp-postgres', 'amnezia-xray', 'amnezia-awg2', 'amnezia-telemt', '3x-ui', '3dp-backend', '3dp-frontend']
    names = [item['Name'].lstrip('/') for item in manifest['containers']]
    for name in order + [value for value in names if value not in order]:
        if name not in names:
            continue
        if name == '3dp-backend':
            for attempt in range(60):
                result = c.run(['docker', 'exec', '3dp-postgres', 'sh', '-c',
                    'pg_isready -U "${POSTGRES_USER:-postgres}"'], check=False)
                if result.returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Восстановленный PostgreSQL не готов')
        c.run(['docker', 'start', name])
        if name == '3dp-postgres':
            for attempt in range(60):
                ready = c.run(['docker', 'exec', name, 'sh', '-c', 'pg_isready -U "${POSTGRES_USER:-postgres}"'], check=False)
                if ready.returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Восстановленная база не готова')
            rewrite_database(manifest, request)
        original = next(item for item in manifest['containers'] if item['Name'].lstrip('/') == name)
        policy = original['HostConfig']['RestartPolicy']['Name'] or 'unless-stopped'
        c.run(['docker', 'update', '--restart=' + policy, name])


def database_sql(query):
    return c.run(['docker', 'exec', '-i', '3dp-postgres', 'sh', '-c',
        'exec psql -X -q -A -t -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" '
        '"${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"'], query.encode()).stdout.decode().strip()


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def sql_text(value):
    encoded = base64.b64encode(value.encode()).decode()
    return "convert_from(decode('" + encoded + "','base64'),'UTF8')"


def private_panel_url(value, manifest, request):
    if c.network_profile(request) != 'filtered' or not isinstance(value, str):
        return value
    parts = urlsplit(value)
    owned = [manifest['source_ip'], manifest['source_domain'], request['ip'], request['domain']]
    if parts.hostname not in owned:
        return value
    if parts.scheme != 'http':
        raise RuntimeError('Локальный HTTPS API панели требует отдельной настройки TLS; используйте профиль all')
    panel = next((item for item in manifest['containers'] if item['Name'].lstrip('/') == '3x-ui'), None)
    if not panel:
        return value
    port = parts.port or 80
    internal = None
    for exposed, bindings in panel['HostConfig'].get('PortBindings', {}).items():
        if exposed.endswith('/tcp') and any(str(item['HostPort']) == str(port) for item in bindings or []):
            internal = exposed.split('/')[0]
    if not internal:
        raise RuntimeError('Не найден внутренний порт API 3x-ui для закрытого профиля')
    credentials = parts.netloc.rsplit('@', 1)[0] + '@' if '@' in parts.netloc else ''
    return urlunsplit((parts.scheme, credentials + '3x-ui:' + internal, parts.path, parts.query, parts.fragment))


def rewrite_database(manifest, request):
    rotation = manifest.get('rotation_original') or database_sql("SELECT value FROM setting WHERE key='rotation_status';")
    c.write(c.JOB / 'rotation-before.json', {'value': rotation})
    database_sql("UPDATE setting SET value='stopped' WHERE key='rotation_status';")
    query = "SELECT coalesce(json_agg(t),'[]') FROM (SELECT table_name,column_name,udt_name FROM information_schema.columns WHERE table_schema='public' AND udt_name IN ('text','varchar','bpchar','json','jsonb')) t;"
    columns = json.loads(database_sql(query))
    primary_query = "SELECT coalesce(json_agg(t),'[]') FROM (SELECT k.table_name,k.column_name FROM information_schema.table_constraints c JOIN information_schema.key_column_usage k ON c.constraint_name=k.constraint_name AND c.table_schema=k.table_schema WHERE c.table_schema='public' AND c.constraint_type='PRIMARY KEY') t;"
    keys = {}
    for row in json.loads(database_sql(primary_query)):
        keys.setdefault(row['table_name'], []).append(row['column_name'])
    grouped = {}
    for column in columns:
        grouped.setdefault(column['table_name'], []).append(column)
    statements = ['BEGIN;']
    for table, fields in grouped.items():
        if len(keys.get(table, [])) != 1:
            continue
        primary = keys[table][0]
        rows = json.loads(database_sql("SELECT coalesce(json_agg(t),'[]') FROM public." + identifier(table) + ' t;'))
        for row in rows:
            for field in fields:
                column = field['column_name']
                before = row.get(column)
                after = replace_endpoint(before, manifest['source_ip'], manifest['source_domain'], request, column)
                if table == 'node' and column == 'url':
                    after = private_panel_url(after, manifest, request)
                if after == before:
                    continue
                value = json.dumps(after, ensure_ascii=False) if field['udt_name'] in ['json', 'jsonb'] else after
                expression = sql_text(value) + '::' + field['udt_name']
                statements.append('UPDATE public.' + identifier(table) + ' SET ' + identifier(column) + '=' + expression
                   + ' WHERE ' + identifier(primary) + '::text=' + sql_text(str(row[primary])) + ';')
    statements.append('COMMIT;')
    database_sql('\n'.join(statements))


def export_existing_awg(request):
    if (c.ROOT / 'exports/personal/configurations/amneziawg.conf').exists() and (c.ROOT / 'exports/shared/configurations/amneziawg.conf').exists():
        return
    path = '/opt/amnezia/awg/awg0.conf'
    original = c.run(['docker', 'exec', 'amnezia-awg2', 'cat', path]).stdout.decode()
    c.write(c.JOB / 'awg-before-new-export.conf', original)
    interface = original.split('[Peer]', 1)[0]
    values = {}
    for line in interface.splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    network = ipaddress.ip_interface(values['Address'].split(',')[0]).network
    used = set(re.findall(r'AllowedIPs\s*=\s*([0-9.]+)/32', original))
    used.add(str(ipaddress.ip_interface(values['Address'].split(',')[0]).ip))
    hosts = [str(address) for address in reversed(list(network.hosts())) if str(address) not in used]
    if len(hosts) < 2:
        raise RuntimeError('В подсети AWG нет двух свободных адресов')
    def key(operation, data=None):
        return c.run(['docker', 'exec', '-i', 'amnezia-awg2', '/usr/bin/awg', operation], data).stdout.decode().strip()
    public = key('pubkey', (values['PrivateKey'] + '\n').encode())
    extras = ''.join(name + ' = ' + value + '\n' for name, value in values.items()
                     if re.fullmatch(r'Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey|ContentPaddingAddition|RekeyAfterTime|RekeyTimeout|RejectAfterTime|KeepaliveTimeout|MaxHandshakeAttempts|RandomTrailers|DisableCookies', name))
    updated = original.rstrip() + '\n'
    new_clients = []
    for role, address in zip(stack.ROLES, hosts):
        private = key('genkey')
        client_public = key('pubkey', (private + '\n').encode())
        psk = key('genpsk')
        updated += '\n[Peer]\nPublicKey = ' + client_public + '\nPresharedKey = ' + psk + '\nAllowedIPs = ' + address + '/32\n'
        config = '[Interface]\nPrivateKey = ' + private + '\nAddress = ' + address + '/32\nDNS = 1.1.1.1\n' + extras
        config += '\n[Peer]\nPublicKey = ' + public + '\nPresharedKey = ' + psk + '\nEndpoint = ' + request['domain'] + ':' + values['ListenPort']
        config += '\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'
        c.export_access(role, 'amneziawg', config, extension='conf')
        new_clients.append({'clientId': client_public, 'userData': {'clientName': 'Migrated-' + role,
                            'creationDate': datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')}})
    c.run(['docker', 'exec', '-i', 'amnezia-awg2', 'sh', '-ec',
           'cat > /opt/amnezia/awg/awg0.conf.new; chmod 600 /opt/amnezia/awg/awg0.conf.new; mv /opt/amnezia/awg/awg0.conf.new /opt/amnezia/awg/awg0.conf'], updated.encode())
    table = c.run(['docker', 'exec', 'amnezia-awg2', 'cat', '/opt/amnezia/awg/clientsTable'], check=False)
    if table.returncode == 0:
        records = json.loads(table.stdout)
        if not isinstance(records, list):
            raise RuntimeError('Неподдерживаемый формат AWG clientsTable')
        c.run(['docker', 'exec', '-i', 'amnezia-awg2', 'sh', '-ec', 'cat > /opt/amnezia/awg/clientsTable'],
              json.dumps(records + new_clients).encode())
    c.run(['docker', 'restart', '--time', '10', 'amnezia-awg2'])


def export_existing_xray(request):
    inspection = c.docker_json('inspect', 'amnezia-xray')[0]
    if not inspection['State']['Running']:
        raise RuntimeError('Восстановленный XRay не запущен')
    path = '/opt/amnezia/xray/server.json'
    raw = c.run(['docker', 'exec', 'amnezia-xray', 'cat', path], check=False)
    if raw.returncode:
        path = str(c.ROOT / 'config/xray/server.json')
        raw_config = Path(path).read_bytes()
    else:
        raw_config = raw.stdout
    config = json.loads(raw_config)
    table = c.run(['docker', 'exec', 'amnezia-xray', 'cat', '/opt/amnezia/xray/clientsTable'], check=False)
    labels = {}
    if table.returncode == 0:
        labels = {item['clientId']: item.get('userData', {}).get('clientName', '') for item in json.loads(table.stdout)}
    for inbound in config['inbounds']:
        if inbound.get('protocol') != 'vless' or inbound.get('streamSettings', {}).get('security') != 'reality':
            continue
        settings = inbound['streamSettings']['realitySettings']
        check_camouflage(request, settings['serverNames'][0], settings.get('target', settings.get('dest')))
        reality = {'serverName': settings['serverNames'][0], 'publicKey': c.public_x25519(settings['privateKey']),
                   'shortId': settings['shortIds'][0], 'fingerprint': c.fingerprint(request)}
        for index, client in enumerate(inbound['settings']['clients']):
            label = labels.get(client['id'], '').lower()
            role = 'personal' if 'personal' in label else 'shared' if 'shared' in label else 'legacy/user-' + str(index + 1)
            c.export_access(role, 'xray', c.xray_client(client['id'], request['domain'], inbound['port'], reality),
                c.vless_link(client['id'], request['domain'], inbound['port'], reality, 'Migrated-' + role.replace('/', '-')))


def export_existing_telemt(request):
    if (c.ROOT / 'exports/personal/strings/telegram.txt').exists():
        return
    raw = c.run(['docker', 'exec', 'amnezia-telemt', 'cat', '/data/config.toml'], check=False)
    if raw.returncode:
        raw = c.run(['docker', 'exec', 'amnezia-telemt', 'cat', '/etc/telemt/server.toml'])
    config = tomllib.loads(raw.stdout.decode())
    modes = config.get('general', {}).get('modes', {})
    for index, (name, secret) in enumerate(config['access']['users'].items(), 1):
        role = name if name in stack.ROLES else 'legacy/telegram-' + str(index)
        if modes.get('tls', True):
            secret = 'ee' + secret + config['censorship']['tls_domain'].encode().hex()
        elif modes.get('secure'):
            secret = 'dd' + secret
        port = config['server'].get('port', 50553)
        data = {'server': request['domain'], 'port': port, 'secret': secret}
        c.export_access(role, 'telegram', data, 'tg://proxy?' + urlencode(data))


def security_prepare(request, job):
    if not (job / 'deploy-result.json').exists() or not json.loads((job / 'deploy-result.json').read_text()).get('success'):
        raise RuntimeError('SSH защищается только после успешного развёртывания и проверок')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if not connection:
        raise RuntimeError('SSH_CONNECTION отсутствует; защита SSH должна запускаться через проверенный SSH')
    client_ip = str(ipaddress.ip_address(connection[0]))
    server_ip = str(ipaddress.ip_address(connection[2]))
    ssh_port = int(connection[3])
    jail = '[sshd]\nenabled = true\nbackend = systemd\nport = ' + str(ssh_port) + '\n'
    jail += 'maxretry = 5\nfindtime = 10m\nbantime = 1h\nignoreip = 127.0.0.1/8 ::1 ' + client_ip + '\n'
    c.write('/etc/fail2ban/jail.d/90-vps-stack.local', jail)
    c.run(['fail2ban-client', '-t'])
    c.run(['systemctl', 'enable', '--now', 'fail2ban'])
    c.run(['systemctl', 'restart', 'fail2ban'])
    for attempt in range(15):
        if c.run(['fail2ban-client', 'status', 'sshd'], check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Fail2ban sshd jail не запустился')
    main = Path('/etc/ssh/sshd_config')
    if (job / 'sshd_config.before').exists():
        raise RuntimeError('Защита SSH для этой операции уже запускалась')
    c.write(job / 'sshd_config.before', main.read_bytes())
    include = Path('/etc/ssh/vps-stack-key-only.conf')
    if include.exists():
        raise RuntimeError('SSH-конфигурация vps-stack уже существует')
    c.write(include, 'PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nPermitRootLogin prohibit-password\n')
    original = main.read_bytes()
    c.write(main, b'Include /etc/ssh/vps-stack-key-only.conf\n' + original)
    unit = 'vps-ssh-rollback-' + job.name
    c.write(job / 'security-state.json', {'unit': unit, 'committed': False})
    try:
        c.run(['/usr/sbin/sshd', '-t'])
        effective = c.run(['/usr/sbin/sshd', '-T', '-C', 'user=root,host=' + client_ip + ',addr=' + client_ip + ',laddr=' + server_ip + ',lport=' + str(ssh_port)]).stdout.decode()
        required = ['passwordauthentication no', 'kbdinteractiveauthentication no', 'pubkeyauthentication yes', 'authenticationmethods publickey']
        if not all(value in effective.splitlines() for value in required):
            raise RuntimeError('Эффективные параметры SSH не соответствуют защите')
        c.run(['systemd-run', '--unit=' + unit, '--on-active=180s', '--timer-property=AccuracySec=1s', '/usr/bin/python3',
               str(job / 'remote.py'), 'rollback-ssh', '--job', str(job)])
        c.run(['systemctl', 'reload', 'ssh'])
    except Exception:
        rollback_ssh(job)
        raise


def rollback_ssh(job):
    if (job / 'security-state.json').exists():
        state = json.loads((job / 'security-state.json').read_text())
        if state.get('committed'):
            return
    original = job / 'sshd_config.before'
    if original.exists():
        c.write('/etc/ssh/sshd_config', original.read_bytes())
        c.run(['/usr/sbin/sshd', '-t'])
        c.run(['systemctl', 'reload', 'ssh'])
        if (job / 'security-state.json').exists():
            state['rolled_back'] = True
            c.write(job / 'security-state.json', state)


def security_commit(job):
    state = json.loads((job / 'security-state.json').read_text())
    if state.get('rolled_back'):
        raise RuntimeError('Сработал откат SSH; защита не подтверждена')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) != 4:
        raise RuntimeError('Подтверждение SSH требует нового SSH-соединения')
    client_ip = str(ipaddress.ip_address(connection[0]))
    server_ip = str(ipaddress.ip_address(connection[2]))
    port = int(connection[3])
    context = 'user=root,host=' + client_ip + ',addr=' + client_ip + ',laddr=' + server_ip + ',lport=' + str(port)
    effective = c.run(['/usr/sbin/sshd', '-T', '-C', context]).stdout.decode().splitlines()
    required = ['passwordauthentication no', 'kbdinteractiveauthentication no',
                'pubkeyauthentication yes', 'authenticationmethods publickey']
    if not all(value in effective for value in required):
        raise RuntimeError('SSH уже не находится в режиме входа только по ключу')
    c.run(['systemctl', 'stop', state['unit'] + '.timer'])
    state['committed'] = True
    c.write(job / 'security-state.json', state)


class LocalPanelConnection(http.client.HTTPSConnection):
    def __init__(self, domain):
        self.tls_context = ssl.create_default_context()
        super().__init__(domain, 6659, timeout=20, context=self.tls_context)

    def connect(self):
        transport = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        try:
            self.sock = self.tls_context.wrap_socket(transport, server_hostname=self.host)
        except Exception:
            transport.close()
            raise


def verify_manager(request):
    inspection = c.docker_json('inspect', '3dp-backend')[0]
    environment = dict(item.split('=', 1) for item in inspection['Config']['Env'] if '=' in item)
    credentials = {'login': environment['ADMIN_LOGIN'], 'password': environment['ADMIN_PASSWORD']}
    connection = LocalPanelConnection(request['domain'])
    for attempt in range(30):
        try:
            connection.request('POST', '/api/auth/login', json.dumps(credentials),
                {'Content-Type': 'application/json', 'Origin': 'https://' + request['domain'] + ':6659'})
            response = connection.getresponse()
            response.read()
            if response.status in [200, 201]:
                break
        except (OSError, http.client.HTTPException):
            connection.close()
            connection = LocalPanelConnection(request['domain'])
        time.sleep(2)
    else:
        raise RuntimeError('Не удалось проверить вход в 3DP')
    cookies = SimpleCookie()
    for name, value in response.getheaders():
        if name.lower() == 'set-cookie':
            cookies.load(value)
    cookie = '; '.join(name + '=' + value.value for name, value in cookies.items())
    if not cookie:
        raise RuntimeError('3DP не выдал cookie после входа')
    for route in ['subscriptions', 'nodes', 'settings']:
        connection.request('GET', '/api/' + route, headers={'Cookie': cookie})
        response = connection.getresponse()
        response.read()
        if response.status != 200:
            raise RuntimeError('Не пройдена проверка защищённого API 3DP: ' + route)
    connection.close()
    if not (c.ROOT / 'exports/admin/panels.json').exists():
        c.write(c.ROOT / 'exports/admin/manager.json', {'url': 'https://' + request['domain'] + ':6659', **credentials})


def verify_proxy_client(role, protocol, request):
    profile = c.ROOT / 'exports' / role / 'configurations' / (protocol + '.json')
    if not profile.exists():
        raise RuntimeError('Не найден экспорт доступа для проверки: ' + role + '/' + protocol)
    config = json.loads(profile.read_text())
    if protocol == 'xray':
        config['inbounds'] = [{'listen': '0.0.0.0', 'port': 10808, 'protocol': 'socks', 'settings': {'udp': False}}]
        server = c.docker_json('inspect', 'amnezia-xray')[0]
        reference = server['Image']
        binary = None
        for candidate in ['/usr/bin/xray', '/usr/local/bin/xray']:
            if c.run(['docker', 'exec', 'amnezia-xray', candidate, 'version'], check=False).returncode == 0:
                binary = candidate
                break
        if not binary:
            raise RuntimeError('Не найден бинарный файл XRay')
        entrypoint = [binary]
        command = ['run', '-c', '/etc/check/client.json']
    else:
        config['socks5'] = {'listen': '0.0.0.0:10808'}
        server = c.docker_json('inspect', 'vpn-hysteria2')[0]
        reference = server['Image']
        if c.network_profile(request) == 'filtered':
            address = server['NetworkSettings']['Networks'][stack.NETWORK]['IPAddress']
            config['server'] = address + ':2443'
        entrypoint = None
        command = ['client', '-c', '/etc/check/client.json']
    name = 'vps-check-' + protocol + '-' + role + '-' + c.JOB.name[-8:]
    directory = c.JOB / 'checks' / (role + '-' + protocol)
    c.write(directory / 'client.json', config)
    created = None
    try:
        created = stack.create(name, reference, command, mounts=[stack.bind(directory, '/etc/check')], entrypoint=entrypoint)
        time.sleep(2)
        temporary = c.docker_json('inspect', name)[0]
        address = temporary['NetworkSettings']['Networks'][stack.NETWORK]['IPAddress']
        response = c.run(['curl', '--silent', '--show-error', '--connect-timeout', '10', '--max-time', '30',
            '--proxy', 'socks5h://' + address + ':10808', '--output', '/dev/null', '--write-out', '%{http_code}',
            'https://example.com/'], timeout=40)
        if response.stdout.strip() != b'200':
            raise RuntimeError('HTTPS через ' + protocol + '/' + role + ' не прошёл проверку')
    finally:
        if created:
            current = c.docker_json('inspect', name)[0]
            if current['Id'] != created:
                raise RuntimeError('Не совпал ID временного контейнера')
            c.run(['docker', 'rm', '-f', name])
        (directory / 'client.json').unlink(missing_ok=True)


def verify_and_export(request, job):
    time.sleep(5)
    checks = {}
    for name in c.CONTAINERS:
        if not stack.exists(name):
            checks[name] = {'running': False, 'missing': True}
            continue
        item = c.docker_json('inspect', name)[0]
        checks[name] = {'running': item['State']['Running'], 'restart_count': item['RestartCount'],
                        'health': item['State'].get('Health', {}).get('Status', 'not-configured'),
                        'image_id': item['Image']}
        if name == '3dp-postgres':
            checks[name]['ready'] = c.run(['docker', 'exec', name, 'sh', '-c',
                        'pg_isready -U "${POSTGRES_USER:-postgres}"'], check=False).returncode == 0
    if not all(item['running'] and item.get('ready', True) and item.get('health') != 'unhealthy' for item in checks.values()):
        c.write(job / 'verification.json', checks)
        raise RuntimeError('Не все контейнеры запущены; подробности в verification.json')
    response = c.run(['curl', '--silent', '--show-error', '--max-time', '20', '--output', '/dev/null',
                      '--resolve', request['domain'] + ':6659:127.0.0.1',
                      '--write-out', '%{http_code}', 'https://' + request['domain'] + ':6659/'])
    if response.stdout.strip() != b'200':
        raise RuntimeError('HTTPS панели 3DP не прошёл проверку')
    verify_manager(request)
    for role in stack.ROLES:
        verify_proxy_client(role, 'xray', request)
        verify_proxy_client(role, 'hysteria2', request)
    for name, previous in checks.items():
        current = c.docker_json('inspect', name)[0]
        if not current['State']['Running'] or current['RestartCount'] != previous['restart_count']:
            raise RuntimeError('Обнаружен выход или перезапуск сервиса при проверках: ' + name)
    if (job / 'rotation-before.json').exists():
        rotation = json.loads((job / 'rotation-before.json').read_text())['value']
        database_sql("UPDATE setting SET value=" + sql_text(rotation) + " WHERE key='rotation_status';")
    c.write(c.ROOT / 'exports/network-profile.txt', 'Профиль: ' + c.network_profile(request) + '\nВ filtered удалённо доступен только XRay TCP 443. Остальные VPN и панели слушают loopback; их экспортированные конфиги не работают удалённо без изменения публикации портов. SSH и HTTP для ACME сохранены. Ограничения скорости не установлены.\n')
    c.write(c.ROOT / 'exports/README.md', '# Доступы VPN\n\npersonal/ — личные доступы; shared/ — для остальных. Не раздавать весь архив: admin/ и legacy/ содержат другие действующие доступы.\n\nTXT импортировать целиком через вставку ключа; .conf в WireGuard/AmneziaWG, .ovpn в OpenVPN, Hysteria2 в совместимый клиент. Не все протоколы поддерживаются одним приложением.\n\nПроверка контейнеров не доказывает работоспособность VPN в сети провайдера. Проверить сайты с телефона через Wi-Fi и мобильную сеть. IPv6-маршрутизация для резервных туннелей отдельно не настроена и не испытана.\n')
    result = {'success': True, 'mode': request['mode'], 'containers': checks,
              'network_profile': c.network_profile(request), 'fingerprint': c.fingerprint(request),
              'external_vpn_protocols': ['xray'] if c.network_profile(request) == 'filtered' else ['xray', 'amneziawg', 'telegram', 'wireguard', 'openvpn', 'shadowsocks', 'hysteria2'],
              'panel_https': 200, 'client_network_tests': 'required',
              'manager_login_and_protected_api': True,
              'vless_and_hysteria_https_for_both_roles': True,
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    c.write(c.ROOT / 'exports/deployment-result.json', result)
    c.archive_tree(c.ROOT / 'exports', job / 'access-files.tar.gz')
    c.write(job / 'deploy-result.json', result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['preflight', 'backup', 'deploy', 'harden', 'commit-ssh', 'rollback-ssh'])
    parser.add_argument('--job', type=Path, required=True)
    arguments = parser.parse_args()
    job = arguments.job.resolve()
    if job.parent != Path('/root/vps-transfer') or not re.fullmatch(r'[a-z0-9-]+', job.name):
        raise ValueError('Недопустимый рабочий каталог')
    c.JOB = job
    os.umask(0o077)
    operation_lock = None
    if arguments.action in ['backup', 'deploy']:
        import fcntl
        operation_lock = Path('/run/lock/vps-transfer.lock').open('a')
        try:
            fcntl.flock(operation_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('На сервере уже выполняется другая операция миграции')
    if arguments.action in ['rollback-ssh', 'commit-ssh', 'harden']:
        import fcntl
        with (job / 'security.lock').open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if arguments.action == 'rollback-ssh':
                rollback_ssh(job)
            elif arguments.action == 'commit-ssh':
                security_commit(job)
            else:
                request = json.loads((job / 'request.json').read_text())
                security_prepare(request, job)
                progress('Парольный вход отключён; ожидается новый SSH-вход, откат через 180 секунд')
        return
    request = json.loads((job / 'request.json').read_text())
    c.validate_ip(request['ip'])
    c.validate_domain(request['domain'])
    c.validate_domain(request['camouflage'])
    c.network_profile(request)
    c.fingerprint(request)
    if arguments.action == 'preflight':
        preflight(request, request['mode'] != 'backup')
        progress('Предварительная проверка пройдена')
    elif arguments.action == 'backup':
        preflight(request, False)
        snapshot.backup(request, job)
        progress('Самодостаточная копия создана; исходные сервисы запущены снова')
    else:
        preflight(request)
        packages()
        if request['mode'] == 'fresh':
            progress('Проверка HTTPS-цели REALITY: сертификат, TLS 1.3, HTTP/2 и отсутствие петли')
            check_camouflage(request)
        progress('Настройка firewall и маршрутизации')
        firewall(request)
        manifest = None
        if request['mode'] == 'restore':
            progress('Восстановление образов, томов и файлов из самодостаточной копии')
            manifest = snapshot.restore(job / 'migration-bundle.tar.gz', job)
            c.ROOT.mkdir(parents=True, exist_ok=True)
        else:
            c.ROOT.mkdir(parents=True, exist_ok=False)
        progress('Выпуск или проверка TLS-сертификата')
        certificate(request)
        if manifest:
            rewrite_host_settings(manifest, request)
            snapshot.restore_containers(manifest, request)
            start_restored(manifest, request)
            export_existing_xray(request)
            export_existing_awg(request)
            export_existing_telemt(request)
            stack.reserves(request)
        else:
            progress('Установка основного набора и резервных протоколов')
            stack.fresh(request)
        progress('Проверка контейнеров и подготовка доступа')
        verify_and_export(request, job)
        progress('Развёртывание завершено; далее отдельная проверка защиты SSH')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if c.JOB:
            c.write(c.JOB / (sys.argv[1] + '-error.json'), {'success': False, 'error': str(error)})
        print('ОШИБКА: ' + str(error), file=sys.stderr)
        sys.exit(1)
