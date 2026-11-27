import re
import shutil
from pathlib import Path

from vps_migration.core import common as c


def webroot(request):
    directory = c.ROOT / 'config/selfsteal-site/acme'
    directory.mkdir(parents=True, exist_ok=True)
    challenge = directory / '.well-known/acme-challenge'
    challenge.mkdir(parents=True, exist_ok=True)
    for path in [directory, directory / '.well-known', challenge]:
        path.chmod(0o755)
    return directory


def configure(request):
    directory = webroot(request)
    source = Path('/etc/letsencrypt/renewal') / (request['domain'] + '.conf')
    backup = c.JOB / 'certificate-renewal-before-webroot.conf'
    if source.exists() and not backup.exists():
        shutil.copy2(source, backup)
    version = c.run(['certbot', '--version']).stdout.decode(errors='replace')
    match = re.search(r'(\d+)\.(\d+)', version)
    if not match:
        raise RuntimeError('Не удалось определить версию Certbot для webroot')
    common = ['--cert-name', request['domain'], '--authenticator', 'webroot',
              '--webroot-path', str(directory), '--non-interactive', '--agree-tos']
    if request.get('email'):
        common.extend(['--email', request['email']])
    else:
        common.append('--register-unsafely-without-email')
    commands = []
    if tuple(map(int, match.groups())) >= (2, 3):
        commands.append(['certbot', 'reconfigure', *common])
    else:
        commands.extend([['certbot', 'renew', *common, '--dry-run'],
                         ['certbot', 'renew', *common, '--force-renewal']])
    for command in commands:
        c.run(['sh', '-c', 'umask 022; exec "$@"', 'certbot-webroot', *command], timeout=1800)
    c.write(c.JOB / 'certificate-webroot.json', {'success': True, 'authenticator': 'webroot',
                                               'legacy_forced_renewal': len(commands) == 2})
