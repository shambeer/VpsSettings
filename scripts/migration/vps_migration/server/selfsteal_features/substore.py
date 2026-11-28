import hashlib
import html
import io
import json
from pathlib import Path
import re
import socket
import time
import urllib.request
import zipfile

from vps_migration.core import common as c
from vps_migration.server import stack

BACKEND_URL = 'https://github.com/sub-store-org/Sub-Store/releases/download/2.44.31/sub-store.bundle.js'
BACKEND_SHA = '263e7709692908a87c98736b5bcbc1e9f22c690c51c97b2824474c47f63bd048'
FRONTEND_URL = 'https://github.com/sub-store-org/Sub-Store-Front-End/releases/download/2.34.5/dist.zip'
FRONTEND_SHA = '168140e29b527c2a81f5f77a5403faca78235aaa72bc7b426d3c89070195a266'
HEADERS = 'access_log off; add_header Cache-Control "no-store" always; add_header Referrer-Policy "no-referrer" always; add_header X-Content-Type-Options "nosniff" always; add_header X-Robots-Tag "noindex, nofollow" always; add_header Content-Security-Policy "default-src \'none\'; frame-ancestors \'none\'; form-action \'none\'" always; '


def download(url, digest, target):
    if target.exists() and c.checksum(target) == digest:
        return
    with urllib.request.urlopen(url, timeout=90) as response:
        content = response.read(50 * 1024 ** 2 + 1)
    if len(content) > 50 * 1024 ** 2 or hashlib.sha256(content).hexdigest() != digest:
        raise RuntimeError('Контрольная сумма релиза Sub-Store не совпала')
    c.write(target, content)


def api(method, path, payload=None):
    script = ('import fs from "node:fs";const input=JSON.parse(fs.readFileSync(0,"utf8"));'
              'const r=await fetch("http://127.0.0.1:3000"+input.path,{method:input.method,'
              'headers:{"Content-Type":"application/json"},body:input.payload===null?undefined:JSON.stringify(input.payload),'
              'signal:AbortSignal.timeout(15000)});if(!r.ok)process.exit(1);process.stdout.write(await r.text());')
    return c.run(['docker', 'exec', '-i', 'vpn-sub-store', 'node', '--input-type=module', '-e',
                  script],
                 content=json.dumps({'method': method, 'path': path, 'payload': payload}).encode(), timeout=30).stdout


def install(state):
    root = c.ROOT / 'config/sub-store'
    root.mkdir(parents=True, exist_ok=True)
    if stack.exists('vpn-sub-store'):
        if not state.get('sub_store_port'):
            raise RuntimeError('Неизвестный существующий Sub-Store; автоматическая перезапись запрещена')
        return
    download(BACKEND_URL, BACKEND_SHA, root / 'sub-store.bundle.js')
    download(FRONTEND_URL, FRONTEND_SHA, root / 'frontend.zip')
    frontend = root / 'frontend'
    frontend.mkdir(exist_ok=True)
    with zipfile.ZipFile(root / 'frontend.zip') as archive:
        if len(archive.infolist()) > 5000 or sum(item.file_size for item in archive.infolist()) > 100 * 1024 ** 2:
            raise RuntimeError('Слишком большой frontend Sub-Store')
        for item in archive.infolist():
            destination = frontend / item.filename
            if not destination.resolve().is_relative_to(frontend.resolve()) or item.filename.startswith('/') or '\\' in item.filename:
                raise RuntimeError('Недопустимый путь frontend Sub-Store')
        archive.extractall(frontend)
    indexes = list(frontend.rglob('index.html'))
    if len(indexes) != 1:
        raise RuntimeError('Не найден однозначный frontend Sub-Store')
    port = None
    for candidate in range(43000, 43100):
        try:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', candidate))
            port = candidate
            break
        except OSError:
            continue
    if port is None:
        raise RuntimeError('Нет свободного loopback-порта для Sub-Store')
    (root / 'data').mkdir(exist_ok=True)
    stack.create('vpn-sub-store', stack.image('substore-node'), ['node', '/app/sub-store.bundle.js'],
                 ports={'3001/tcp': [('127.0.0.1', port)]}, working='/data',
                 mounts=[stack.bind(root / 'sub-store.bundle.js', '/app/sub-store.bundle.js'),
                         stack.bind(frontend, '/frontend'), stack.bind(root / 'data', '/data', False)],
                 environment={'SUB_STORE_BACKEND_API_HOST': '0.0.0.0', 'SUB_STORE_BACKEND_API_PORT': '3000',
                              'SUB_STORE_FRONTEND_HOST': '0.0.0.0', 'SUB_STORE_FRONTEND_PORT': '3001',
                              'SUB_STORE_FRONTEND_PATH': '/frontend/' + indexes[0].parent.relative_to(frontend).as_posix(),
                              'SUB_STORE_FRONTEND_BACKEND_PATH': '/backend', 'SUB_STORE_DATA_BASE_PATH': '/data',
                              'SUB_STORE_CORS_ALLOWED_ORIGINS': 'http://127.0.0.1:' + str(port)})
    state['sub_store_port'] = port
    c.write(c.ROOT / 'config/selfsteal-features/state.json', state)


def upload(role, content):
    name = 'vps-' + role
    listing = json.loads(api('GET', '/api/files'))
    existing = listing.get('data', [])
    method, path = ('PATCH', '/api/file/' + name) if any(item['name'] == name for item in existing) else ('POST', '/api/files')
    api(method, path, {'name': name, 'source': 'local', 'type': 'text', 'content': content, 'process': []})
    if api('GET', '/api/file/' + name).strip() != content.encode().strip():
        raise RuntimeError('Sub-Store изменил содержимое подписки; публикация остановлена')


def portal(request, role, token):
    if role not in ['personal', 'shared'] or not re.fullmatch(r'[a-f0-9]{64}', token):
        raise ValueError('Недопустимая роль или токен выдачи')
    directory = c.ROOT / 'exports' / role
    base = 'https://' + request['domain'] + ':' + str(c.selfsteal_port(request))
    url = base + '/access/' + token
    subscription = base + '/sub/' + token
    target = c.ROOT / 'config/selfsteal-site/content/.client-access' / token
    target.mkdir(parents=True, exist_ok=True)
    target.parent.chmod(0o755)
    target.chmod(0o755)
    entries, rows, locations, featured = [], [], [], []
    package = io.BytesIO()
    total = 0
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
        for folder in ['configurations', 'strings', 'subscriptions']:
            source = directory / folder
            if source.is_symlink():
                raise RuntimeError('Символические ссылки в клиентском экспорте запрещены')
            for path in sorted(source.rglob('*')):
                if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
                    raise RuntimeError('Недопустимый путь клиентского экспорта')
                if not path.is_file():
                    continue
                if len(entries) >= 5000 or path.stat().st_size > 10 * 1024 ** 2:
                    raise RuntimeError('Слишком большой клиентский экспорт')
                content = path.read_bytes()
                total += len(content)
                if total > 50 * 1024 ** 2:
                    raise RuntimeError('Слишком большой клиентский экспорт')
                suffix = path.suffix if re.fullmatch(r'\.[a-zA-Z0-9]{1,8}', path.suffix) else '.txt'
                name = str(len(entries)) + suffix
                c.write(target / name, content)
                (target / name).chmod(0o644)
                relative = path.relative_to(directory).as_posix()
                archive.writestr(relative, content)
                entries.append({'file': relative, 'url': url + '/' + name, 'sha256': hashlib.sha256(content).hexdigest()})
                rows.append('<li><a href="' + url + '/' + name + '">' + html.escape(relative) + '</a></li>')
                if relative in ['configurations/amneziawg.conf', 'configurations/wireguard.conf', 'configurations/openvpn.ovpn']:
                    featured.append('<p><a href="' + url + '/' + name + '">Скачать ' + html.escape(path.stem) + '</a></p>')
                if relative == 'strings/telegram.txt':
                    telegram = content.decode('utf-8').strip()
                    if telegram.startswith('tg://proxy?') and not any(char in telegram for char in ['\r', '\n', '"', '<', '>']):
                        featured.append('<p><a href="' + html.escape(telegram, quote=True) + '">Открыть Telegram-прокси</a></p>')
        manifest = {'role': role, 'subscription': subscription, 'files': entries}
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    c.write(target / 'all.zip', package.getvalue())
    c.write(target / 'manifest.json', manifest)
    page = ('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<meta name="referrer" content="no-referrer"><title>Все подключения</title><body>'
            '<h1>Все подключения</h1><p>Скопируйте ссылку подписки в совместимый клиент:</p>'
            '<textarea readonly rows="3" cols="60">' + html.escape(subscription) + '</textarea>'
            '<p>XRay, XHTTP, Shadowsocks и Hysteria2 — в подписке. AmneziaWG, WireGuard и OpenVPN — файлами ниже; Telegram — в strings/telegram.txt.</p>'
            '<p>AmneziaWG требует поддержки AWG; обычный WireGuard не заменяет его.</p>'
            + ''.join(featured) + '<p><a href="' + url + '/all.zip">Скачать все конфигурации ZIP</a></p><ul>' + ''.join(rows) + '</ul></body></html>')
    c.write(target / 'index.html', page)
    c.write(directory / 'delivery/manifest.json', manifest)
    c.write(directory / 'delivery/index.html', page)
    c.write(directory / 'delivery/all.zip', package.getvalue())
    c.write(directory / 'delivery/start.txt', url + '\nПодписка: ' + subscription + '\n')
    for name in ['index.html', 'all.zip', 'manifest.json', *[str(index) + Path(entry['url']).suffix for index, entry in enumerate(entries)]]:
        (target / name).chmod(0o644)
        route = '/access/' + token + ('' if name == 'index.html' else '/' + name)
        mime = 'text/html' if name == 'index.html' else 'application/zip' if name == 'all.zip' else 'application/octet-stream'
        locations.append('location = ' + route + ' { ' + HEADERS + 'default_type ' + mime + '; types {} alias /usr/share/nginx/html/.client-access/' + token + '/' + name + '; }\n')
    return ''.join(locations)


def verify(request, state):
    for role in ['personal', 'shared']:
        token = state['subscription_tokens'][role]
        url = 'https://' + request['domain'] + ':' + str(c.selfsteal_port(request)) + '/access/' + token
        for remote, local in [('', 'index.html'), ('/manifest.json', 'manifest.json'), ('/all.zip', 'all.zip')]:
            response = c.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '60', '--config', '-'],
                             content=('url = "' + url + remote + '"\n').encode(), timeout=70).stdout
            expected = c.ROOT / 'exports' / role / 'delivery' / local
            if hashlib.sha256(response).hexdigest() != c.checksum(expected):
                raise RuntimeError('Единая HTTPS-выдача не прошла проверку для роли ' + role)


def configure(request, state):
    for token in state['subscription_tokens'].values():
        if not re.fullmatch(r'[a-f0-9]{64}', token):
            raise ValueError('Недопустимый токен подписки')
    install(state)
    for attempt in range(30):
        try:
            api('GET', '/api/files')
            break
        except Exception:
            if attempt == 29:
                raise RuntimeError('Sub-Store не готов') from None
            time.sleep(1)
    locations = []
    for role in ['personal', 'shared']:
        token = state['subscription_tokens'][role]
        content = (c.ROOT / 'exports' / role / 'subscriptions/base64.txt').read_text()
        upload(role, content)
        locations.append('location = /sub/' + token + ' { ' + HEADERS + 'limit_except GET { deny all; } set $args ""; proxy_pass http://vpn-sub-store:3000/api/file/vps-' + role + '; }\n')
        locations.append(portal(request, role, token))
    c.write(c.ROOT / 'exports/admin/sub-store.json', {'local_port': state['sub_store_port'],
            'url': 'http://127.0.0.1:' + str(state['sub_store_port']),
            'ssh_forward': str(state['sub_store_port']) + ':127.0.0.1:' + str(state['sub_store_port']),
            'note': 'Открывать только через SSH-туннель. Files/vps-personal и vps-shared хранят готовые подписки без конвертации.'})
    return ''.join(locations)
