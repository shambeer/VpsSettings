import json
from pathlib import Path
import shutil

from vps_migration.core import common as c
from vps_migration.server.maintenance import apt


def protected_container(item):
    name = item['Name'].lstrip('/')
    labels = item['Config'].get('Labels') or {}
    image = item['Config'].get('Image', '').lower()
    return (name in c.CONTAINERS or labels.get('vps-stack') == 'managed'
            or name.startswith(('amnezia-', 'vpn-', '3dp-')) or name == '3x-ui'
            or any(word in image for word in ['amnezia', 'wireguard', 'openvpn', 'shadowsocks',
                    'hysteria', 'xray', '3x-ui', '3dp-manager', 'telemt']))


def container_signature(item):
    return apt.fingerprint({key: item.get(key) for key in ['Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts']})


def inspect_container(identifier):
    from urllib.parse import quote
    return c.api('GET', '/containers/' + quote(identifier, safe='') + '/json?size=true')


def inventory():
    packages = apt.installed_packages()
    protected = apt.protected_packages(packages)
    manual = set(apt.command(['apt-mark', 'showmanual']).stdout.decode().splitlines())
    orphans = apt.parse_simulation(apt.command(['apt-get', '-s', 'autoremove']).stdout.decode())['removals']
    eligible = manual | {row['package'] for row in orphans}
    package_candidates = [row for row in packages if (row['package'] in eligible or row['package'].split(':', 1)[0] in eligible)
                          and not apt.is_protected(row['package'], protected)]
    containers = []
    if shutil.which('docker'):
        for summary in c.api('GET', '/containers/json?all=1'):
            item = inspect_container(summary['Id'])
            containers.append({'id': item['Id'], 'name': item['Name'].lstrip('/'),
                'image': item['Config']['Image'], 'running': item['State']['Running'],
                'protected': protected_container(item), 'auto_remove': item['HostConfig'].get('AutoRemove', False),
                'size': item.get('SizeRootFs', 0), 'signature': container_signature(item),
                'mounts': [{key: mount.get(key) for key in ['Type', 'Name', 'Source', 'Destination', 'RW']}
                           for mount in item.get('Mounts', [])]})
    return {'task': 'cleanup', 'packages': package_candidates, 'containers': containers,
            'installed_before': packages, 'protected_packages': sorted(protected),
            'failed_units_before': apt.failed_units(),
            'native_arch': apt.command(['dpkg', '--print-architecture']).stdout.decode().strip()}


def preview(inventory_plan, selection):
    package_candidates = {row['package'] for row in inventory_plan['packages']}
    packages = sorted(set(selection.get('packages', [])))
    if not set(packages).issubset(package_candidates):
        raise ValueError('Выбран пакет, отсутствующий в разрешённом списке кандидатов')
    for package in packages:
        apt.package_name(package)
    candidates = {row['id']: row for row in inventory_plan['containers'] if not row['protected'] and not row['auto_remove']}
    identifiers = sorted(set(selection.get('containers', [])))
    if not set(identifiers).issubset(candidates):
        raise ValueError('Выбран защищённый, временный AutoRemove или неизвестный контейнер')
    if not packages and not identifiers:
        raise ValueError('Не выбрано ни одного объекта очистки')
    arguments = ['apt-get', '-s', 'remove']
    if selection.get('autoremove'):
        arguments.append('--auto-remove')
    transaction = {'changes': [], 'removals': []}
    if packages:
        transaction = apt.parse_simulation(apt.command([*arguments, '--', *packages]).stdout.decode())
    protected = set(inventory_plan['protected_packages'])
    forbidden = [row['package'] for row in transaction['removals'] if apt.is_protected(row['package'], protected)]
    if forbidden or transaction['changes']:
        raise RuntimeError('Удаление затрагивает защищённые зависимости или устанавливает новые пакеты: '
                           + ', '.join(forbidden))
    operation = {'packages': packages, 'containers': [candidates[value] for value in identifiers],
                 'autoremove': bool(selection.get('autoremove')), 'transaction': transaction}
    return {**inventory_plan, 'operation': operation, 'fingerprint': apt.fingerprint(operation)}


def validate_current(plan):
    operation = plan['operation']
    current = inventory()
    selection = {'packages': operation['packages'], 'containers': [row['id'] for row in operation['containers']],
                 'autoremove': operation['autoremove']}
    rechecked = preview(current, selection)
    if rechecked['fingerprint'] != plan['fingerprint']:
        raise RuntimeError('Состав контейнеров или план удаления APT изменился; подтвердите новый план')


def resume_original(plan, removed=()):
    failed = []
    for row in plan['operation']['containers']:
        if row['running'] and row['name'] not in removed:
            if c.run(['docker', 'start', row['id']], check=False).returncode:
                failed.append(row['name'])
    if failed:
        raise RuntimeError('Не удалось вернуть ранее работавшие контейнеры: ' + ', '.join(failed))


def backup(plan, job):
    directory = job / 'cleanup-backup'
    directory.mkdir(mode=0o700)
    required = sum(int(row.get('size') or 0) for row in plan['operation']['containers'])
    if shutil.disk_usage(job).free < required * 2 + 1024 ** 3:
        raise RuntimeError('Недостаточно диска для резервной копии выбранных контейнеров')
    apt.backup_config(directory, plan, 'system-config.tar.gz')
    c.write(directory / 'cleanup-plan.json', plan)
    try:
        for row in plan['operation']['containers']:
            c.write(job / 'progress.json', {'stage': 'Резервная копия контейнера ' + row['name']})
            item = inspect_container(row['id'])
            tag = 'vps-cleanup-backup:' + row['id'][:20] + '-' + job.name
            c.write(directory / (row['id'] + '.json'), {**item, 'cleanup_backup_image': tag})
            if row['running']:
                c.run(['docker', 'stop', '--time', '30', row['id']])
            c.run(['docker', 'commit', '--pause=false', row['id'], tag], timeout=1800)
            c.run(['docker', 'save', '-o', str(directory / (row['id'] + '.tar')), tag], timeout=7200)
        target = job / 'cleanup-backup.tar.gz'
        c.archive_tree(directory, target)
        return target
    except Exception:
        resume_original(plan)
        raise


def apply_approved(job):
    plan = json.loads((job / 'cleanup-plan.json').read_text())
    approval = json.loads((job / 'cleanup-approval.json').read_text())
    if approval.get('fingerprint') != plan['fingerprint']:
        raise RuntimeError('Не подтверждён точный план очистки')
    validate_current(plan)
    archive = backup(plan, job)
    try:
        for row in plan['operation']['containers']:
            item = inspect_container(row['id'])
            if protected_container(item) or container_signature(item) != row['signature'] or item['State']['Running']:
                raise RuntimeError('Контейнер изменился, перезапущен или стал защищённым; удаление остановлено')
        if plan['operation']['packages']:
            current = inventory()
            selection = {'packages': plan['operation']['packages'], 'containers': [],
                         'autoremove': plan['operation']['autoremove']}
            if preview(current, selection)['operation']['transaction'] != plan['operation']['transaction']:
                raise RuntimeError('План APT изменился после резервирования; удаление не начато')
    except Exception:
        resume_original(plan)
        raise
    removed = []
    try:
        for row in plan['operation']['containers']:
            c.write(job / 'progress.json', {'stage': 'Удаление подтверждённого контейнера ' + row['name']})
            c.run(['docker', 'rm', row['id']])
            removed.append(row['name'])
            c.write(job / 'cleanup-progress.json', {'removed_containers': removed, 'backup_file': archive.name})
        packages = plan['operation']['packages']
        if packages:
            current = inventory()
            selection = {'packages': packages, 'containers': [], 'autoremove': plan['operation']['autoremove']}
            transaction = preview(current, selection)['operation']['transaction']
            if transaction != plan['operation']['transaction']:
                raise RuntimeError('План APT изменился после резервирования; пакеты не удалены')
            arguments = ['apt-get', '-y', '-o', 'DPkg::Lock::Timeout=120', 'remove']
            if plan['operation']['autoremove']:
                arguments.append('--auto-remove')
            apt.command([*arguments, '--', *packages], timeout=7200)
        apt.verify_system(plan)
        native_arch = plan.get('native_arch', 'amd64')
        suffix = ':' + native_arch
        remaining = {row['package'].removesuffix(suffix) for row in apt.installed_packages()}
        removed_packages = [row['package'] for row in plan['operation']['transaction']['removals']]
        if remaining.intersection(name.removesuffix(suffix) for name in removed_packages):
            raise RuntimeError('Не все подтверждённые пакеты удалены')
        existing = {row['Id'] for row in c.api('GET', '/containers/json?all=1')} if shutil.which('docker') else set()
        if existing.intersection(row['id'] for row in plan['operation']['containers']):
            raise RuntimeError('Не все подтверждённые контейнеры удалены')
        return {'success': True, 'task': 'cleanup', 'removed_packages': removed_packages,
                'removed_containers': [row['name'] for row in plan['operation']['containers']],
                'backup_file': archive.name, 'backup_sha256': c.checksum(archive),
                'volumes_and_bind_directories_deleted': False, 'package_configs_purged': False}
    except Exception:
        resume_original(plan, removed)
        raise
