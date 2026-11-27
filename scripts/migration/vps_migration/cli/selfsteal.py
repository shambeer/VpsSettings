import json
from pathlib import Path
import tarfile

from vps_migration.cli import session
from vps_migration.core import common as c
from vps_migration.core.selfsteal_options import validate


def options(path):
    value = json.loads(Path(path).read_text(encoding='utf-8')) if path else {}
    result = validate(value)
    if result.get('site_directory'):
        result['site_directory'] = str(Path(result['site_directory']).expanduser().resolve())
    return result


def choose_warp(address, settings, read):
    from vps_migration.cli import console as ui
    ui.section('Cloudflare WARP — отдельный выход по желанию')
    print('Маршрут: устройство → ваш VPS → Cloudflare → сайт. Только профили WARP используют этот выход.')
    print('Регистрация устройства выполняется автоматически; аккаунт, почта и перенос домена не нужны.')
    print('Amnezia и обычные профили сохраняют свой маршрут. Скорость зависит от дополнительного пути.')
    ui.menu('Подключать WARP?', [('1', 'Добавить WARP-профили и разрешить регистрацию устройства'),
                                ('2', 'Без WARP и без регистрации в Cloudflare')])
    default = '1' if settings.get('warp', True) else '2'
    choice = ui.select('Выберите вариант WARP', ['1', '2'], default, read=read)
    if choice == '2':
        return False
    print('Условия Cloudflare: https://www.cloudflare.com/application/terms/')
    if read('Для согласия с регистрацией и условиями введите WARP ' + address) != 'WARP ' + address:
        raise RuntimeError('Регистрация WARP не подтверждена; установка не начата')
    return True


def site_archive(output, settings):
    if not settings.get('site_directory'):
        return None
    source = Path(settings['site_directory'])
    if source.is_symlink() or not source.is_dir() or not (source / 'index.html').is_file():
        raise ValueError('Папка сайта должна содержать index.html и не быть ссылкой')
    def build():
        entries = sorted(source.rglob('*'))
        if len(entries) > 5000 or any(item.is_symlink() or not (item.is_file() or item.is_dir()) for item in entries):
            raise ValueError('Сайт должен содержать не более 5000 обычных файлов/папок, без ссылок')
        allowed = {'.html', '.htm', '.css', '.js', '.mjs', '.json', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.txt', '.xml', '.webmanifest', '.mp4', '.webm', '.mp3', '.ogg', '.wav', '.pdf', '.wasm', '.map'}
        if any(any(part.startswith('.') for part in item.relative_to(source).parts) or (item.is_file() and item.suffix.lower() not in allowed) for item in entries):
            raise ValueError('Используйте статический экспорт сайта без скрытых файлов, серверного кода, ключей и баз данных')
        if sum(item.stat().st_size for item in entries if item.is_file()) > 20 * 1024 ** 2:
            raise ValueError('Папка сайта должна быть не больше 20 MiB')
        target = output / 'site-content.tar.gz'
        with tarfile.open(target, 'w:gz', dereference=False) as archive:
            for item in entries:
                archive.add(item, arcname=item.relative_to(source).as_posix(), recursive=False)
        return {'path': str(target), 'sha256': c.checksum(target)}
    result = session.checkpoint('static-site', build)
    if c.checksum(Path(result['path'])) != result['sha256']:
        raise RuntimeError('Локальная копия своего сайта изменилась после подтверждения')
    return result


def export_tunnel(host, output, base_path):
    import os
    import shlex
    arguments = ['ssh', *host.options, '-N', '-L', '127.0.0.1:2053:127.0.0.1:2053',
                 '-p', str(host.port), 'root@' + host.address]
    if os.name == 'nt':
        command = '& ' + ' '.join("'" + value.replace("'", "''") + "'" for value in arguments)
    else:
        command = shlex.join(arguments)
    text = command + '\n\nПанель после запуска туннеля: http://127.0.0.1:2053' + base_path + '\n'
    c.write(output / 'access/admin/ssh-tunnel.txt', text)
