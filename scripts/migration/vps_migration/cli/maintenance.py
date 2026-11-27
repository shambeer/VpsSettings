import json
from pathlib import Path
import shlex
import time

from vps_migration.cli import console as ui, session
from vps_migration.core import common as c


def show_os_plan(plan, path):
    ui.section('Полное обновление пакетов текущей ОС')
    changes = plan['transaction']['changes']
    removals = plan['transaction']['removals']
    print('Обновление/установка: ' + str(len(changes)) + '; удаление: ' + str(len(removals)))
    for row in changes[:20]:
        print('  ' + row['package'] + ': ' + str(row['from'] or 'не установлен') + ' → ' + row['to'])
    if len(changes) > 20:
        print('  Остальные изменения приведены в полном плане.')
    for row in removals:
        print('  Удаление APT: ' + row['package'] + ' ' + str(row['version']))
    if plan['held']:
        print('Удержанные пакеты: ' + ', '.join(plan['held']))
    print('Полный план: ' + str(path))
    print('APT может перезапустить SSH/Docker и временно прервать VPN. Смена версии ОС не выполняется.')


def approve_os_updates(host, job, output):
    from vps_migration.cli.wizard import action, ask
    directory = output / ('os-' + host.address)
    directory.mkdir(mode=0o700, exist_ok=True)
    action(host, job, 'packages-plan')
    path = directory / 'os-plan.json'
    host.download(job + '/os-plan.json', path)
    plan = json.loads(path.read_text(encoding='utf-8'))
    show_os_plan(plan, path)
    if ask('Для подтверждения всех показанных изменений введите UPGRADE ' + host.address) != 'UPGRADE ' + host.address:
        raise RuntimeError('Обновление ОС отменено')
    approval = directory / 'os-approval.json'
    c.write(approval, {'fingerprint': plan['fingerprint'], 'removals': plan['transaction']['removals']})
    host.upload(approval, job + '/os-approval.json')


def download_backups(host, job, output):
    failed = []
    for name in ['os-config-backup.tar.gz', 'cleanup-backup.tar.gz', 'os-upgrade-result.json', 'cleanup-progress.json', 'selfsteal-before-features.tar.gz', 'certificate-renewal-before-webroot.conf', 'certificate-webroot.json']:
        try:
            command = 'if test -f ' + shlex.quote(job + '/' + name) + '; then printf yes; fi'
            if host.ssh(command, capture=True, quiet=True).strip() == b'yes':
                digest = host.ssh('sha256sum ' + shlex.quote(job + '/' + name), capture=True).decode().split()[0]
                host.download(job + '/' + name, output / name)
                if c.checksum(output / name) != digest:
                    raise RuntimeError('Контрольная сумма скачанной резервной копии не совпала')
        except Exception:
            failed.append(name)
            print('Не удалось скачать ' + name + '. Серверная копия: ' + job + '/' + name)
    return failed


def restart_if_needed(host, job, output):
    from vps_migration.cli.wizard import action, ask
    directory = output / ('os-' + host.address)
    directory.mkdir(mode=0o700, exist_ok=True)
    host.download(job + '/os-upgrade-result.json', directory / 'os-upgrade-result.json')
    result = json.loads((directory / 'os-upgrade-result.json').read_text(encoding='utf-8'))
    if not result.get('reboot_required'):
        return
    ui.section('Нужна перезагрузка: ' + host.address)
    print('VPN/SSH этого сервера временно отключатся. При необходимости переподключите VPN на компьютере.')
    choice = ui.select('Перезагрузить сейчас? 1 — да, 2 — отложить', ['1', '2'], '2', read=ask)
    if choice == '2':
        c.write(directory / 'reboot-deferred.json', {'reboot_required': True, 'server_ip': host.address})
        print('Перезагрузка отложена. Для полного применения системных изменений она ещё нужна.')
        return
    if ask('Подтвердите: REBOOT ' + host.address) != 'REBOOT ' + host.address:
        raise RuntimeError('Перезагрузка отменена')
    approval = directory / 'reboot-approval.json'
    if approval.exists():
        before = json.loads(approval.read_text())['boot_id'].encode()
    else:
        before = host.ssh('cat /proc/sys/kernel/random/boot_id', capture=True).strip()
        c.write(approval, {'confirm': 'REBOOT ' + host.address, 'boot_id': before.decode()})
    host.upload(directory / 'reboot-approval.json', job + '/reboot-approval.json')
    current = host.ssh('cat /proc/sys/kernel/random/boot_id', capture=True, quiet=True).strip()
    if current == before:
        action(host, job, 'maintenance-reboot')
    deadline = time.monotonic() + 900
    print('[ВЫПОЛНЯЕТСЯ] Ожидание нового запуска сервера и SSH, до 15 минут...')
    while time.monotonic() < deadline:
        try:
            after = host.ssh('cat /proc/sys/kernel/random/boot_id', capture=True, quiet=True).strip()
        except RuntimeError:
            time.sleep(5)
            continue
        if after and after != before:
            action(host, job, 'maintenance-check')
            host.download(job + '/reboot-check.json', directory / 'reboot-check.json')
            print('Сервер перезагружен, SSH и служебные проверки прошли.')
            return
        time.sleep(5)
    raise RuntimeError('Новый запуск сервера не подтверждён. Нужна проверка через консоль провайдера.')


def choose_rows(rows, question, ask):
    for number, row in enumerate(rows, 1):
        print('  ' + str(number) + '. ' + row)
    if not rows:
        return []
    while True:
        value = ask(question + '; номера через запятую, ALL — все показанные, Enter — ничего', '')
        if not value:
            return []
        if value.strip().lower() in ['all', 'все']:
            return list(range(len(rows)))
        try:
            indices = sorted({int(item.strip()) - 1 for item in value.split(',')})
            if any(index < 0 or index >= len(rows) for index in indices):
                raise ValueError()
            return indices
        except ValueError:
            ui.error('Укажите существующие номера через запятую')


def run(output):
    from vps_migration.cli.wizard import connection, ask, prepare, action, background_action
    host = connection('Существующий VPS для обслуживания: root по ключу')
    access = ui.select('SSH: 1 — напрямую, 2 — через доступный relay', ['1', '2'], '1', read=ask)
    if access == '2':
        host.use_jump(connection('SSH relay для доступа к обслуживаемому серверу'), output)
    ui.menu('Обслуживание существующего VPS', [('1', 'Полное обновление пакетов ОС'),
                                              ('2', 'Удаление выбранных посторонних контейнеров и пакетов')])
    task = ui.select('Операция обслуживания', ['1', '2'], '1', read=ask)
    print('Сначала будут загружены служебные файлы и собран план. Для обновления освежается кэш APT; приложения пока не меняются.')
    if ask('Разрешить подготовку плана: PLAN ' + host.address) != 'PLAN ' + host.address:
        raise RuntimeError('Подготовка плана отменена')
    request = {'mode': 'maintenance', 'task': 'os' if task == '1' else 'cleanup',
               'ip': host.address, 'ssh_port': host.port}
    job = prepare(host, request, output)
    c.write(output / 'maintenance-operation.json', {'server_ip': host.address, 'remote_job': job, 'task': request['task']})
    if task == '1':
        session.checkpoint('os-approval:' + job + ':' + host.address, lambda: approve_os_updates(host, job, output))
    else:
        action(host, job, 'maintenance-plan')
        host.download(job + '/maintenance-plan.json', output / 'maintenance-plan.json')
        plan = json.loads((output / 'maintenance-plan.json').read_text(encoding='utf-8'))
        containers = [row for row in plan['containers'] if not row['protected'] and not row['auto_remove']]
        ui.section('Кандидаты на удаление контейнеров — это не доказательство их ненужности')
        selected = choose_rows([row['name'] + ' | ' + row['image'] + (' | работает' if row['running'] else ' | остановлен')
                                for row in containers], 'Контейнеры', ask)
        ui.section('Кандидаты на удаление APT-пакетов')
        selected_packages = choose_rows([row['package'] + ' ' + row['version'] for row in plan['packages']], 'Пакеты', ask)
        autoremove = False
        if selected_packages:
            autoremove = ui.select('Убирать ненужные зависимости? 1 — да, 2 — нет', ['1', '2'], '2', read=ask) == '1'
        selection = {'containers': [containers[index]['id'] for index in selected],
                     'packages': [plan['packages'][index]['package'] for index in selected_packages], 'autoremove': autoremove}
        if not selection['containers'] and not selection['packages']:
            print('Ничего не выбрано. Удаление не выполнялось.')
            return
        c.write(output / 'cleanup-selection.json', selection)
        host.upload(output / 'cleanup-selection.json', job + '/cleanup-selection.json')
        action(host, job, 'cleanup-preview')
        host.download(job + '/cleanup-plan.json', output / 'cleanup-plan.json')
        approved = json.loads((output / 'cleanup-plan.json').read_text(encoding='utf-8'))
        ui.section('Точный план удаления')
        for row in approved['operation']['containers']:
            print('  Контейнер: ' + row['name'])
        for row in approved['operation']['transaction']['removals']:
            print('  Пакет: ' + row['package'] + ' ' + str(row['version']))
        print('Полный план: ' + str(output / 'cleanup-plan.json'))
        print('Выбранные работающие приложения будут остановлены. Сначала создаётся резервная копия. '
              'Тома/bind-каталоги и конфиги пакетов не очищаются; purge/prune не выполняются.')
        if ask('Подтвердите точное удаление: DELETE ' + host.address) != 'DELETE ' + host.address:
            raise RuntimeError('Очистка отменена')
        c.write(output / 'cleanup-approval.json', {'fingerprint': approved['fingerprint']})
        host.upload(output / 'cleanup-approval.json', job + '/cleanup-approval.json')
    backup_errors = []
    try:
        background_action(host, job, 'maintenance-apply', 'maintenance-result.json')
    finally:
        backup_errors = download_backups(host, job, output)
    host.download(job + '/maintenance-result.json', output / 'maintenance-result.json')
    if backup_errors:
        raise RuntimeError('Действия на VPS завершены, но не все резервные файлы скачаны: ' + ', '.join(backup_errors)
                           + '. Они сохранены на сервере в ' + job)
    if host.ssh('id -u', capture=True).strip() != b'0':
        raise RuntimeError('Новый SSH-вход после обслуживания не подтверждён')
    if task == '1':
        session.checkpoint('reboot:' + host.address + ':' + job, lambda: restart_if_needed(host, job, output))
    print('Обслуживание завершено. Результаты и резервные копии: ' + str(output))
