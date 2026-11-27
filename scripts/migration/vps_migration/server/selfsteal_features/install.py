import copy
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import tarfile

from vps_migration.core import common as c
from vps_migration.core.selfsteal_options import validate
from vps_migration.server.selfsteal_features import profiles, subscriptions, warp, certificates


def bound_write(path, text):
    if path.exists():
        with path.open('w', encoding='utf-8', newline='\n') as target:
            target.write(text)
            target.flush()
            os.fsync(target.fileno())
    else:
        c.write(path, text)


def site_configuration(request, path, subscription_locations=''):
    from vps_migration.server import selfsteal
    plain = selfsteal.site_configuration(path)
    plain = plain.replace('location ' + path + ' {', 'location ^~ ' + path + ' {')
    plain = plain.replace('proxy_set_header Host $host;', 'proxy_set_header Host $host; proxy_set_header Connection "";')
    plain = plain.replace('proxy_request_buffering off;', 'proxy_request_buffering off; proxy_cache off; gzip off; proxy_socket_keepalive on;')
    plain = plain.replace('server { listen 8080;', 'server { access_log off; http2 on; listen 8080;')
    plain = plain.replace('listen 8081 http2;', 'listen 8081;')
    plain = plain.replace('location / {', subscription_locations + 'location ~ /\\. { deny all; } location / {')
    certificate = '/etc/letsencrypt/live/' + request['domain']
    secure = plain.replace('listen 8080; listen 8081;',
        'listen 8443 ssl; ssl_protocols TLSv1.2 TLSv1.3; '
        + 'ssl_certificate ' + certificate + '/fullchain.pem; ssl_certificate_key ' + certificate + '/privkey.pem;')
    redirect = 'server { listen 80; access_log off; server_name ' + request['domain'] + '; '
    redirect += 'location ^~ /.well-known/acme-challenge/ { root /var/lib/vps-acme; } '
    redirect += 'location / { return 301 https://' + request['domain'] + ':' + str(c.selfsteal_port(request)) + '$request_uri; } }\n'
    return plain + secure + redirect


def content(request):
    site = c.ROOT / 'config/selfsteal-site'
    directory = site / 'content'
    directory.mkdir(exist_ok=True)
    if request.get('site_sha256'):
        archive = c.JOB / 'site-content.tar.gz'
        if c.checksum(archive) != request['site_sha256']:
            raise RuntimeError('Контрольная сумма своего сайта не совпала')
        staging = c.JOB / 'site-staging'
        if staging.exists():
            raise RuntimeError('Папка подготовки сайта уже существует')
        c.safe_extract(archive, staging)
        if not (staging / 'index.html').is_file():
            raise RuntimeError('В папке сайта нужен index.html')
        for item in staging.rglob('*'):
            if item.is_symlink() or not (item.is_file() or item.is_dir()):
                raise RuntimeError('Специальные файлы сайта запрещены')
        shutil.copytree(staging, directory, dirs_exist_ok=True)
    elif not (directory / 'index.html').exists():
        shutil.copy2(site / 'index.html', directory / 'index.html')
    directory.chmod(0o755)
    for item in directory.rglob('*'):
        item.chmod(0o755 if item.is_dir() else 0o644)


def enhance(config, state, options, warp_outbound):
    config = copy.deepcopy(config)
    clients = [{key: value for key, value in item.items() if key != 'flow'}
               for item in config['inbounds'][0]['settings']['clients']]
    config['inbounds'] = [item for item in config['inbounds'] if item.get('tag') not in ['selfsteal-warp', 'selfsteal-reality']]
    main = config['inbounds'][0]
    fallbacks = [item for item in main['settings'].get('fallbacks', []) if item.get('path') != state['warp_path']]
    if options['warp']:
        fallbacks.insert(0, {'path': state['warp_path'], 'dest': '18081', 'xver': 1})
        config['inbounds'].append({'tag': 'selfsteal-warp', 'listen': '127.0.0.1', 'port': 18081,
            'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': clients},
            'streamSettings': {'network': 'tcp', 'security': 'none', 'tcpSettings': {
                'acceptProxyProtocol': True, 'header': {'type': 'http', 'request': {
                    'version': '1.1', 'method': 'GET', 'path': [state['warp_path']], 'headers': {}},
                    'response': {'version': '1.1', 'status': '200', 'reason': 'OK', 'headers': {}}}}}})
    main['settings']['fallbacks'] = fallbacks
    xhttp = next(item for item in config['inbounds'] if item.get('tag') == 'selfsteal-xhttp')
    old_path = xhttp['streamSettings']['xhttpSettings']['path']
    xhttp['streamSettings']['xhttpSettings'] = {**copy.deepcopy(options['xhttp']),
        'path': options['xhttp'].get('path', old_path), 'sessionIDTable': state['session_id_table']}
    if options['reality']:
        reality = copy.deepcopy(main)
        reality.update(tag='selfsteal-reality', port=444)
        reality['streamSettings'] = {'network': 'tcp', 'security': 'reality', 'realitySettings': {
            'show': False, 'target': 'vpn-selfsteal-site:8443', 'xver': 0,
            'serverNames': state['server_names'], 'privateKey': state['private_key'], 'shortIds': [state['short_id']]}}
        config['inbounds'].append(reality)
    config['outbounds'] = [item for item in config['outbounds'] if item.get('tag') != 'selfsteal-warp-out']
    if not config['outbounds']:
        raise RuntimeError('Нужен исходный прямой outbound')
    rules = config.setdefault('routing', {}).setdefault('rules', [])
    rules[:] = [item for item in rules if item.get('inboundTag') != ['selfsteal-warp']]
    if options['warp']:
        config['outbounds'].append(warp_outbound)
        rules.insert(0, {'type': 'field', 'inboundTag': ['selfsteal-warp'], 'outboundTag': 'selfsteal-warp-out'})
    return config


def xray_binary():
    for name in ['/usr/bin/xray', '/usr/local/bin/xray']:
        result = c.run(['docker', 'exec', 'vpn-selfsteal-xray', name, 'version'], check=False)
        if result.returncode != 0:
            continue
        match = re.search(r'Xray (\d+)\.(\d+)\.(\d+)', result.stdout.decode(errors='replace'))
        if not match or tuple(map(int, match.groups())) < (26, 11, 9):
            raise RuntimeError('Полный FR-17 требует Xray 26.11.9+; обновите ядро штатным способом')
        return name
    raise RuntimeError('Не найден Xray для новых вариантов')


def install(request):
    from vps_migration.server import selfsteal
    options = validate(request.get('selfsteal_options'))
    binary = xray_binary()
    state_path = c.ROOT / 'config/selfsteal-features/state.json'
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if any(state.get(key) and not options[key] for key in ['warp', 'reality', 'subscriptions']):
            raise RuntimeError('Отключение уже действующих вариантов требует отдельного плана отзыва доступов')
    else:
        private, public = c.x25519_pair()
        state = {'private_key': private, 'public_key': public, 'short_id': secrets.token_hex(8),
                 'warp_path': options.get('warp_path', '/' + secrets.token_hex(12)),
                 'session_id_table': options['xhttp'].get('sessionIDTable', secrets.token_hex(4) + '............')}
    backup = c.JOB / 'selfsteal-before-features.tar.gz'
    if not backup.exists():
        with tarfile.open(backup, 'w:gz', dereference=False) as archive:
            for name in ['selfsteal-xray', 'selfsteal-site', 'selfsteal-edge', 'selfsteal-features']:
                source = c.ROOT / 'config' / name
                if source.exists():
                    archive.add(source, arcname=name)
    state.update({key: options[key] for key in ['warp', 'reality', 'subscriptions']})
    state['server_names'] = [request['domain'], *options['additional_domains']]
    c.write(state_path, state)
    target = c.ROOT / 'config/selfsteal-xray/server.json'
    original = target.read_bytes()
    original_site = c.ROOT / 'config/selfsteal-site/server.conf'
    site_before = original_site.read_text()
    c.write(c.JOB / 'progress.json', {'stage': 'Проверка новых транспортов до регистрации WARP'})
    placeholder = {'tag': 'selfsteal-warp-out', 'protocol': 'blackhole'} if options['warp'] else None
    config = enhance(json.loads(original), state, options, placeholder)
    candidate = target.with_name('server.next.json')
    c.write(candidate, config)
    c.run(['docker', 'exec', 'vpn-selfsteal-xray', binary, 'run', '-test', '-c', '/etc/vpn/server.next.json'])
    if options['warp']:
        c.write(c.JOB / 'progress.json', {'stage': 'Регистрация или восстановление отдельного выхода WARP'})
        registered = warp.register(request)
        config['outbounds'] = [registered if item.get('tag') == 'selfsteal-warp-out' else item for item in config['outbounds']]
        c.write(candidate, config)
        c.run(['docker', 'exec', 'vpn-selfsteal-xray', binary, 'run', '-test', '-c', '/etc/vpn/server.next.json'])
    profiles.export(request, config, state)
    locations = subscriptions.export(request, state, options) if options['subscriptions'] else ''
    c.write(state_path, state)
    path = next(item for item in config['inbounds'] if item['tag'] == 'selfsteal-xhttp')['streamSettings']['xhttpSettings']['path']
    content(request)
    if options['sub_store']:
        from vps_migration.server.selfsteal_features import substore
        locations = substore.configure(request, state)
        c.write(state_path, state)
    try:
        bound_write(original_site, site_configuration(request, path, locations))
        c.run(['docker', 'exec', 'vpn-selfsteal-site', 'nginx', '-t'])
        c.write(target, config)
        c.run(['docker', 'restart', 'vpn-selfsteal-xray'])
        c.run(['docker', 'exec', 'vpn-selfsteal-site', 'nginx', '-s', 'reload'])
    except Exception:
        c.write(target, original)
        bound_write(original_site, site_before)
        c.run(['docker', 'restart', 'vpn-selfsteal-xray'], check=False)
        c.run(['docker', 'exec', 'vpn-selfsteal-site', 'nginx', '-s', 'reload'], check=False)
        raise
    certificates.configure(request)
    c.write(state_path, state)
    candidate.unlink(missing_ok=True)
