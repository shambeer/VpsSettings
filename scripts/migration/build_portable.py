import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

from portable import FILES

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent


def build(output, repository='shambeer/VpsMigration'):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Нужен адрес репозитория в формате owner/name')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    contents = {name: (REPOSITORY / name).read_bytes() for name in FILES}
    manifest = {'format': 1, 'files': {name: hashlib.sha256(content).hexdigest() for name, content in contents.items()}}
    entries = {'__main__.py': (HERE / 'portable.py').read_bytes(),
               'manifest.json': (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()}
    entries.update({'payload/' + name: content for name, content in contents.items()})
    archive = output / 'vps-migration.pyz'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name, content in sorted(entries.items()):
            information = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            information.compress_type = zipfile.ZIP_DEFLATED
            information.external_attr = 0o100644 << 16
            package.writestr(information, content)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    tag = 'migration-' + digest[:16]
    url = 'https://github.com/' + repository + '/releases/download/' + tag + '/vps-migration.pyz'
    launcher = (HERE / 'run.sh.in').read_text(encoding='utf-8')
    launcher = launcher.replace('@PACKAGE_URL@', url).replace('@PACKAGE_SHA256@', digest)
    (output / 'run.sh').write_text(launcher, encoding='utf-8', newline='\n')
    launcher_url = 'https://github.com/' + repository + '/releases/download/' + tag + '/run.sh'
    (output / 'run-linux.txt').write_text('curl -fsSL ' + launcher_url + ' | bash\n', encoding='utf-8')
    powershell = (HERE / 'run.ps1.in').read_text(encoding='utf-8')
    powershell = powershell.replace('@PACKAGE_URL@', url).replace('@PACKAGE_SHA256@', digest)
    (output / 'run.ps1').write_text(powershell, encoding='utf-8', newline='\n')
    powershell_url = 'https://github.com/' + repository + '/releases/download/' + tag + '/run.ps1'
    command = "& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing -Uri '" + powershell_url + "').Content))"
    (output / 'run-windows.txt').write_text(command + '\n', encoding='utf-8')
    (output / 'vps-migration.pyz.sha256').write_text(digest + '  vps-migration.pyz\n', encoding='utf-8')
    release = {'repository': repository, 'tag': tag, 'sha256': digest, 'asset_url': url,
               'launcher_url': launcher_url, 'powershell_launcher_url': powershell_url,
               'release_assets': ['vps-migration.pyz', 'vps-migration.pyz.sha256', 'run.sh', 'run.ps1'],
               'payload_files': FILES, 'archive_bytes': archive.stat().st_size,
               'publication_required': True}
    (output / 'release.json').write_text(json.dumps(release, indent=2) + '\n', encoding='utf-8')
    return release


def main():
    parser = argparse.ArgumentParser(description='Сборка переносимого мигратора без Git и без приватных файлов')
    parser.add_argument('--output', type=Path, default=REPOSITORY / 'dist/migration')
    parser.add_argument('--repository', default='shambeer/VpsMigration')
    arguments = parser.parse_args()
    release = build(arguments.output, arguments.repository)
    print('Пакет и проверяемая команда: ' + str(arguments.output.resolve()))
    print('SHA256: ' + release['sha256'])
    print('Для команды по URL требуется публикация релиза ' + release['tag'])


if __name__ == '__main__':
    main()
