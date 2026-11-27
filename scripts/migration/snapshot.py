import copy
import base64
import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import tarfile
import time
from urllib.parse import quote

import common as c


def selected():
    available = {item['Names'][0].lstrip('/') for item in c.api('GET', '/containers/json?all=1')}
    names = [name for name in c.CONTAINERS if name in available]
    if not names:
        raise RuntimeError('Контейнеры поддерживаемого набора не найдены')
    if not set(c.CONTAINERS[:7]).issubset(names):
        raise RuntimeError('Для полной копии нужны все семь контейнеров основного набора')
    return [c.docker_json('inspect', name)[0] for name in names]


def tree_size(path):
    path = Path(path)
    if path.is_file():
        return path.stat().st_size
    total = 0
    for directory, subdirectories, files in os.walk(path, followlinks=False):
        for name in files:
            total += (Path(directory) / name).lstat().st_size
    return total


def database_sql(query):
    return c.run(['docker', 'exec', '-i', '3dp-postgres', 'sh', '-c',
        'exec psql -X -q -A -t -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" '
        '"${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"'], query.encode()).stdout.decode().strip()


def host_roots(containers):
    paths = []
    for location in ['/opt/amnezia', '/opt/3dp-manager', '/root/3x-ui', '/etc/letsencrypt', str(c.ROOT)]:
        if Path(location).exists():
            paths.append(Path(location))
    for container in containers:
        for mount in container['Mounts']:
            if mount['Type'] != 'bind':
                continue
            path = Path(mount['Source'])
            if not any(path == item or path.is_relative_to(item) for item in paths):
                paths.append(path)
    paths = sorted(set(paths), key=lambda path: len(path.parts))
    accepted = []
    for path in paths:
        if not any(path.is_relative_to(parent) for parent in accepted):
            if path == Path('/root') or path.is_relative_to(Path('/root/.ssh')) or path.is_relative_to(Path('/var/lib/docker')):
                raise RuntimeError('Нельзя включать домашний каталог root, SSH-ключи или весь Docker data root')
            if not any(path.is_relative_to(Path(base)) for base in ['/opt', '/root', '/srv', '/etc/letsencrypt', '/var/lib']):
                raise RuntimeError('Неподдерживаемый bind mount: ' + str(path))
            if not path.exists():
                raise RuntimeError('Bind mount отсутствует: ' + str(path))
            accepted.append(path)
    return accepted


def backup(request, job):
    containers = selected()
    roots = host_roots(containers)
    names = [item['Name'].lstrip('/') for item in containers]
    running = [item['Name'].lstrip('/') for item in containers if item['State']['Running']]
    if c.run(['docker', 'ps', '-aq', '--filter', 'status=paused']).stdout.strip():
        raise RuntimeError('На источнике есть paused-контейнеры; требуется ручная проверка')
    directory = job / 'bundle'
    directory.mkdir()
    (directory / 'volumes').mkdir()
    networks = {}
    volumes = {}
    for container in containers:
        for name in container['NetworkSettings']['Networks']:
            if name not in ['bridge', 'host', 'none']:
                current = c.docker_json('network', 'inspect', name)[0]
                if current['Driver'] != 'bridge':
                    raise RuntimeError('Поддерживаются только bridge-сети')
                networks[name] = current
        for mount in container['Mounts']:
            if mount['Type'] == 'volume':
                volumes[mount['Name']] = c.docker_json('volume', 'inspect', mount['Name'])[0]
    all_containers = c.api('GET', '/containers/json?all=1')
    selected_ids = {item['Id'] for item in containers}
    for volume in volumes.values():
        if volume['Driver'] != 'local' or volume.get('Options'):
            raise RuntimeError('Поддерживаются обычные локальные Docker-тома без driver options')
    for item in all_containers:
        if item['Id'] in selected_ids:
            continue
        inspection = c.docker_json('inspect', item['Id'])[0]
        if any(mount.get('Name') in volumes for mount in inspection['Mounts']):
            raise RuntimeError('Том используется контейнером вне выбранного набора')
    image_bytes = sum(c.docker_json('image', 'inspect', item['Image'])[0]['Size'] for item in containers)
    data_bytes = sum(tree_size(path) for path in roots) + sum(tree_size(volume['Mountpoint']) for volume in volumes.values())
    restored_bytes = image_bytes + data_bytes
    if shutil.disk_usage(job).free < restored_bytes * 2 + 1024 ** 3:
        raise RuntimeError('Недостаточно свободного места для полного снимка образов и данных')
    snapshots = []
    rotation = None
    manifest = {'format': 1, 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'architecture': platform.machine(), 'source_ip': request['ip'], 'source_domain': request['domain'],
                'containers': containers, 'networks': networks, 'volumes': volumes,
                'host_roots': [str(path) for path in roots], 'snapshot_images': {},
                'required_unpacked_bytes': restored_bytes,
                'running_before_backup': running}
    try:
        if '3dp-postgres' in running:
            rotation = database_sql("SELECT value FROM setting WHERE key='rotation_status';")
            if rotation not in ['active', 'stopped']:
                raise RuntimeError('Неизвестный режим ротации 3DP')
            database_sql("UPDATE setting SET value='stopped' WHERE key='rotation_status';")
            manifest['rotation_original'] = rotation
            if database_sql("SELECT to_regclass('public.operation') IS NOT NULL;") == 't':
                for attempt in range(60):
                    count = database_sql("SELECT count(*) FROM operation WHERE status IN ('running','queued','pending','processing');")
                    if count == '0':
                        break
                    time.sleep(1)
                else:
                    raise RuntimeError('Операции 3DP не завершились; копирование остановлено')
        stop_order = ['3dp-frontend', '3dp-backend', '3x-ui']
        stop_order += [name for name in running if name not in stop_order and name != '3dp-postgres']
        stop_order += ['3dp-postgres']
        for name in stop_order:
            if name in running:
                c.run(['docker', 'stop', '--time', '60', name], timeout=120)
        for container in containers:
            name = container['Name'].lstrip('/')
            tag = 'vps-transfer/' + name + ':' + job.name
            c.run(['docker', 'commit', '--pause=false', container['Id'], tag])
            snapshots.append(tag)
            manifest['snapshot_images'][name] = tag
        c.run(['docker', 'save', '-o', str(directory / 'images.tar'), *snapshots], timeout=3600)
        for name, volume in volumes.items():
            c.archive_tree(volume['Mountpoint'], directory / 'volumes' / (name + '.tar.gz'))
        with tarfile.open(directory / 'host.tar.gz', 'w:gz', dereference=False) as archive:
            for path in roots:
                archive.add(path, arcname=str(path).lstrip('/'))
        c.write(directory / 'manifest.json', manifest)
        files = [path for path in directory.rglob('*') if path.is_file()]
        c.write(directory / 'checksums.json', {path.relative_to(directory).as_posix(): c.checksum(path) for path in files})
    finally:
        failures = []
        start_order = ['3dp-postgres'] + [name for name in running if name != '3dp-postgres']
        for name in start_order:
            if name not in running:
                continue
            if c.run(['docker', 'start', name], check=False).returncode:
                failures.append(name)
            elif name == '3dp-postgres':
                for attempt in range(60):
                    ready = c.run(['docker', 'exec', name, 'sh', '-c',
                                   'pg_isready -U "${POSTGRES_USER:-postgres}"'], check=False)
                    if ready.returncode == 0:
                        break
                    time.sleep(1)
                else:
                    failures.append(name)
        if rotation is not None and '3dp-postgres' not in failures:
            encoded = base64.b64encode(rotation.encode()).decode()
            database_sql("UPDATE setting SET value=convert_from(decode('" + encoded + "','base64'),'UTF8') WHERE key='rotation_status';")
        for tag in snapshots:
            c.run(['docker', 'image', 'rm', tag], check=False)
        if failures:
            raise RuntimeError('Не удалось вернуть исходные контейнеры: ' + ', '.join(failures))
    result = job / 'migration-bundle.tar.gz'
    c.archive_tree(directory, result)
    c.write(job / 'backup-result.json', {'success': True, 'sha256': c.checksum(result),
            'containers': names, 'source_services_started_again': True})
    return result


def load_bundle(path, job):
    destination = job / 'restored-bundle'
    c.safe_extract(path, destination)
    checksums = json.loads((destination / 'checksums.json').read_text())
    actual_files = {path.relative_to(destination).as_posix() for path in destination.rglob('*')
                    if path.is_file() and path.name != 'checksums.json'}
    if set(checksums) != actual_files or not {'images.tar', 'host.tar.gz', 'manifest.json'}.issubset(actual_files):
        raise RuntimeError('Список контрольных сумм неполный')
    for name, digest in checksums.items():
        target = (destination / name).resolve()
        if not target.is_relative_to(destination.resolve()) or not target.is_file() or c.checksum(target) != digest:
            raise RuntimeError('Резервная копия повреждена или содержит опасный путь')
    manifest = json.loads((destination / 'manifest.json').read_text())
    if manifest['format'] != 1 or manifest['architecture'] != platform.machine():
        raise RuntimeError('Формат копии или архитектура не совпадает с целевым сервером')
    names = {item['Name'].lstrip('/') for item in manifest['containers']}
    required = {'amnezia-awg2', 'amnezia-xray', 'amnezia-telemt', '3x-ui', '3dp-postgres', '3dp-backend', '3dp-frontend'}
    if not required.issubset(names) or not names.issubset(set(c.CONTAINERS)):
        raise RuntimeError('В копии отсутствует основной набор или есть неподдерживаемые контейнеры')
    if set(manifest['snapshot_images']) != {item['Name'].lstrip('/') for item in manifest['containers']}:
        raise RuntimeError('Неполный список образов')
    if shutil.disk_usage(destination).free < manifest['required_unpacked_bytes'] * 1.3 + 1024 ** 3:
        raise RuntimeError('Недостаточно диска для распаковки образов и данных')
    return destination, manifest


def restore(path, job):
    directory, manifest = load_bundle(path, job)
    for name in manifest['volumes']:
        if c.run(['docker', 'volume', 'inspect', name], check=False).returncode == 0:
            raise RuntimeError('На целевом сервере уже существует том: ' + name)
    for name in manifest['networks']:
        if c.run(['docker', 'network', 'inspect', name], check=False).returncode == 0:
            raise RuntimeError('На целевом сервере уже существует сеть: ' + name)
    host_stage = job / 'host-stage'
    c.safe_extract(directory / 'host.tar.gz', host_stage)
    for name in manifest['host_roots']:
        target = Path(name)
        if not target.is_absolute() or '..' in target.parts or target == Path('/root') or target.is_relative_to(Path('/root/.ssh')):
            raise RuntimeError('Опасный путь восстановления')
        if not any(target.is_relative_to(Path(base)) for base in ['/opt', '/root', '/srv', '/etc/letsencrypt', '/var/lib']):
            raise RuntimeError('Недопустимый путь восстановления')
        if str(target) == '/etc/letsencrypt' and target.exists():
            if any(target.rglob('*.pem')):
                raise RuntimeError('На целевом сервере уже есть TLS-ключи или сертификаты')
            shutil.move(str(target), str(job / 'os-letsencrypt-before'))
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise RuntimeError('Восстановление не перезаписывает существующий путь: ' + name)
    c.run(['docker', 'load', '-i', str(directory / 'images.tar')], timeout=3600)
    for name, original in manifest['networks'].items():
        c.api('POST', '/networks/create', {'Name': name, 'Driver': 'bridge', 'Internal': original['Internal'],
              'EnableIPv6': original.get('EnableIPv6', False), 'IPAM': original['IPAM'],
              'Options': original.get('Options', {}), 'Labels': {'vps-migration': job.name}})
    for name in manifest['volumes']:
        volume = c.api('POST', '/volumes/create', {'Name': name, 'Labels': {'vps-migration': job.name}})
        c.safe_extract(directory / 'volumes' / (name + '.tar.gz'), volume['Mountpoint'])
    for name in manifest['host_roots']:
        source = host_stage / name.lstrip('/')
        target = Path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.rmdir()
        shutil.move(str(source), str(target))
    return manifest


def restore_containers(manifest, request):
    for original in manifest['containers']:
        name = original['Name'].lstrip('/')
        config = copy.deepcopy(original['Config'])
        config['Image'] = manifest['snapshot_images'][name]
        config.pop('Hostname', None)
        host = copy.deepcopy(original['HostConfig'])
        host.pop('ContainerIDFile', None)
        host.pop('Links', None)
        host.pop('VolumesFrom', None)
        host.pop('ConsoleSize', None)
        if c.network_profile(request) == 'filtered' and (host['NetworkMode'] == 'host' or host['NetworkMode'].startswith('container:')):
            raise RuntimeError('Нельзя закрыть порты host-network контейнера профилем filtered: ' + name)
        if host.get('PortBindings') or name == 'amnezia-xray':
            host['PortBindings'] = c.exposure_bindings(name, host.get('PortBindings') or {}, request)
        if c.network_profile(request) == 'filtered':
            host['PublishAllPorts'] = False
        host['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
        host['Binds'] = []
        host['Mounts'] = []
        for mount in original['Mounts']:
            if mount['Type'] == 'tmpfs':
                continue
            item = {'Type': mount['Type'], 'Source': mount.get('Name') if mount['Type'] == 'volume' else mount['Source'],
                    'Target': mount['Destination'], 'ReadOnly': not mount['RW']}
            if mount['Type'] == 'bind':
                updated = item['Source'].replace(manifest['source_domain'], request['domain'])
                if updated != item['Source']:
                    if not Path(updated).exists():
                        raise RuntimeError('Новый путь bind mount отсутствует: ' + updated)
                    item['Source'] = updated
            if item['Type'] not in ['bind', 'volume']:
                raise RuntimeError('Неподдерживаемый тип mount')
            host['Mounts'].append(item)
        networks = original['NetworkSettings']['Networks']
        primary = host['NetworkMode']
        if primary == 'default':
            primary = 'bridge'
        if primary not in networks and primary not in ['host', 'none']:
            primary = next(iter(networks))
            host['NetworkMode'] = primary
        payload = {**config, 'HostConfig': host}
        environment = []
        for item in config.get('Env', []):
            key, separator, value = item.partition('=')
            if not any(word in key.lower() for word in ['password', 'secret', 'token', 'key', 'login', 'user']):
                value = value.replace(manifest['source_ip'], request['ip']).replace(manifest['source_domain'], request['domain'])
            environment.append(key + separator + value)
        payload['Env'] = environment
        if primary in networks and primary not in ['bridge', 'host', 'none']:
            payload['NetworkingConfig'] = {'EndpointsConfig': {primary: endpoint(networks[primary])}}
        created = c.api('POST', '/containers/create?name=' + quote(name, safe=''), payload)
        for network, settings in networks.items():
            if network != primary:
                c.api('POST', '/networks/' + quote(network, safe='') + '/connect',
                      {'Container': created['Id'], 'EndpointConfig': {} if network == 'bridge' else endpoint(settings)})

    if c.network_profile(request) == 'filtered':
        names = {item['Name'].lstrip('/') for item in manifest['containers']}
        if {'3dp-backend', '3x-ui'}.issubset(names):
            backend = c.docker_json('inspect', '3dp-backend')[0]
            panel = c.docker_json('inspect', '3x-ui')[0]
            backend_networks = backend['NetworkSettings']['Networks']
            panel_networks = panel['NetworkSettings']['Networks']
            usable = [name for name in backend_networks if name not in ['bridge', 'host', 'none']]
            network = next((name for name in usable if name in panel_networks), None)
            if not network:
                network = usable[0] if usable else 'vps-stack-private'
                if not usable:
                    c.api('POST', '/networks/create', {'Name': network, 'Driver': 'bridge', 'Internal': True})
                    c.api('POST', '/networks/' + network + '/connect', {'Container': '3dp-backend', 'EndpointConfig': {}})
                c.api('POST', '/networks/' + quote(network, safe='') + '/connect',
                      {'Container': '3x-ui', 'EndpointConfig': {'Aliases': ['3x-ui']}})


def endpoint(settings):
    result = {'Aliases': [value for value in (settings.get('Aliases') or [])
                          if not re.fullmatch(r'[0-9a-f]{12}|[0-9a-f]{64}', value)]}
    if settings.get('IPAddress'):
        result['IPAMConfig'] = {'IPv4Address': settings['IPAddress']}
    return result
