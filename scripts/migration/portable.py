import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

FILES = ['.gitignore', *['scripts/migration/' + name for name in [
    'common.py', 'migrate.py', 'remote.py', 'snapshot.py', 'stack.py',
    'README.md', 'deploy.ps1', 'deploy.sh']]]


def installation_directory(archive):
    override = os.environ.get('VPS_MIGRATION_HOME')
    if override:
        base = Path(override).expanduser()
    elif os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData/Local')) / 'VpsSettings/migration'
    else:
        base = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share')) / 'VpsSettings/migration'
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    directory = base / digest[:16]
    if directory.is_symlink():
        raise RuntimeError('Каталог установки не должен быть символической ссылкой')
    directory.mkdir(parents=True, exist_ok=True)
    return directory.resolve()


def unpack(archive, directory):
    with zipfile.ZipFile(archive) as package:
        expected = {'__main__.py', 'manifest.json', *['payload/' + name for name in FILES]}
        names = package.namelist()
        if set(names) != expected or len(names) != len(expected):
            raise RuntimeError('В пакете отсутствуют ожидаемые файлы или есть посторонние')
        manifest = json.loads(package.read('manifest.json'))
        if manifest.get('format') != 1 or set(manifest.get('files', {})) != set(FILES):
            raise RuntimeError('Неизвестный формат пакета')
        verified = {}
        for name in FILES:
            content = package.read('payload/' + name)
            if hashlib.sha256(content).hexdigest() != manifest['files'][name]:
                raise RuntimeError('Нарушена целостность файла: ' + name)
            destination = directory / name
            if destination.is_symlink() or not destination.parent.resolve().is_relative_to(directory):
                raise RuntimeError('Недопустимый путь установки')
            if destination.exists() and destination.read_bytes() != content:
                raise RuntimeError('Локальный файл изменён; автоматическая перезапись запрещена: ' + str(destination))
            verified[destination] = content
        for destination, content in verified.items():
            if not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as target:
                    target.write(content)


def main():
    archive = Path(sys.argv[0]).resolve()
    directory = installation_directory(archive)
    unpack(archive, directory)
    print('Мигратор без Git. Локальная папка: ' + str(directory), flush=True)
    return subprocess.call([sys.executable, '-X', 'utf8', str(directory / 'scripts/migration/migrate.py'), *sys.argv[1:]])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Ошибка переносимого пакета: ' + str(error), file=sys.stderr)
        sys.exit(1)
