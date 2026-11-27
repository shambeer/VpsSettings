import json
from pathlib import Path
import shutil
import time

from vps_migration.core import common as c
from vps_migration.server.maintenance import apt, cleanup


def running_containers():
    if not shutil.which('docker'):
        return []
    result = []
    for row in c.api('GET', '/containers/json'):
        if row.get('State') == 'running' and not cleanup.inspect_container(row['Id'])['HostConfig'].get('AutoRemove'):
            result.append(row['Id'])
    return result


def check_containers(identifiers):
    from urllib.parse import quote
    for identifier in identifiers:
        for attempt in range(60):
            try:
                item = c.api('GET', '/containers/' + quote(identifier, safe='') + '/json')
            except (OSError, RuntimeError) as error:
                if attempt == 59:
                    raise RuntimeError('Не удалось проверить контейнер после обслуживания: ' + identifier) from error
                time.sleep(2)
                continue
            health = item['State'].get('Health', {}).get('Status', 'not-configured')
            if item['State']['Running'] and health not in ['starting', 'unhealthy']:
                break
            time.sleep(2)
        else:
            raise RuntimeError('После обслуживания контейнер остановлен или не прошёл healthcheck: ' + item['Name'])


def plan(request, job):
    task = request.get('task')
    if task == 'os':
        result = apt.upgrade_plan()
        result['running_containers_before'] = running_containers()
        c.write(job / 'os-plan.json', result)
    elif task == 'cleanup':
        result = cleanup.inventory()
    else:
        raise ValueError('Неизвестная операция обслуживания')
    c.write(job / 'maintenance-plan.json', result)
    return result


def preview_cleanup(job):
    inventory = json.loads((job / 'maintenance-plan.json').read_text())
    selection = json.loads((job / 'cleanup-selection.json').read_text())
    result = cleanup.preview(inventory, selection)
    c.write(job / 'cleanup-plan.json', result)


def apply(request, job):
    if request.get('task') == 'os':
        plan = json.loads((job / 'os-plan.json').read_text())
        c.write(job / 'progress.json', {'stage': 'Полное обновление APT; служебные журналы сохраняются на сервере'})
        result = apt.apply_approved(job)
        check_containers(plan.get('running_containers_before', []))
    elif request.get('task') == 'cleanup':
        c.write(job / 'progress.json', {'stage': 'Резервирование подтверждённых объектов перед очисткой'})
        result = cleanup.apply_approved(job)
    else:
        raise ValueError('Неизвестная операция обслуживания')
    c.write(job / 'maintenance-result.json', result)
    return result


def check_after_reboot(request, job):
    plan = json.loads((job / 'maintenance-plan.json').read_text())
    apt.verify_system(plan)
    if plan.get('task') == 'os':
        plan = json.loads((job / 'os-plan.json').read_text())
        check_containers(plan.get('running_containers_before', []))
    deployment = c.ROOT / 'exports/deployment-result.json'
    if deployment.exists():
        names = json.loads(deployment.read_text()).get('containers', {})
        check_containers(list(names))
        if '3dp-postgres' in names:
            c.run(['docker', 'exec', '3dp-postgres', 'sh', '-c',
                   'pg_isready -U "${POSTGRES_USER:-postgres}"'])
    if Path('/etc/vps-relay.json').exists():
        c.run(['systemctl', 'is-active', 'vps-relay.service'])
    result = json.loads((job / 'os-upgrade-result.json').read_text())
    kernel = c.run(['uname', '-r']).stdout.decode().strip()
    if result.get('expected_kernel_releases') and kernel not in result['expected_kernel_releases']:
        raise RuntimeError('После перезагрузки загружено другое ядро; проверьте настройки загрузчика: ' + kernel)
    c.write(job / 'reboot-check.json', {'success': True, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                                      'kernel_release': kernel})


def schedule_reboot(request, job):
    result = json.loads((job / 'os-upgrade-result.json').read_text())
    approval = json.loads((job / 'reboot-approval.json').read_text())
    current = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if result.get('success') is not True or not result.get('reboot_required'):
        raise RuntimeError('Перезагрузка разрешена только после успешного обновления, которое её требует')
    if approval.get('confirm') != 'REBOOT ' + request['ip'] or approval.get('boot_id') != current:
        raise RuntimeError('Перезагрузка не подтверждена для текущего сервера и запуска ОС')
    unit = 'vps-reboot-' + job.name
    loaded = c.run(['systemctl', 'show', unit + '.timer', '-p', 'LoadState', '--value'], check=False).stdout.strip()
    if loaded == b'loaded':
        return
    c.run(['systemd-run', '--unit=' + unit, '--on-active=10s',
           '/usr/bin/systemctl', 'reboot'])
