import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import tarfile
import uuid

from vps_migration.core import common as c
from vps_migration.cli import topology, session
from vps_migration.cli import console as ui
from vps_migration.packaging.portable import SERVER_FILES
from vps_migration.cli.maintenance import approve_os_updates, restart_if_needed, download_backups

HERE = Path(__file__).resolve().parents[2]
REPOSITORY = HERE.parent.parent


def ask(prompt, default=None):
    if session.ACTIVE:
        return session.ACTIVE.prompt(prompt, default, ui.prompt)
    return ui.prompt(prompt, default)


def ask_validated(prompt, validate, default=None):
    while True:
        value = ask(prompt, default)
        try:
            return validate(value)
        except (ValueError, OSError) as error:
            ui.error(error)


def ssh_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('SSH-порт должен быть от 1 до 65535')
    return port


def existing_key(value):
    path = local_path(value)
    if not path.is_file():
        raise ValueError('Файл SSH-ключа не найден; укажите полный путь к существующему файлу')
    return path


def local_path(value):
    value = str(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ['"', "'"]:
        value = value[1:-1]
    return Path(value).expanduser().resolve()


def user_folder(name):
    if os.name == 'nt':
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') as key:
            value = winreg.QueryValueEx(key, 'Desktop' if name == 'Desktop' else 'Personal')[0]
        return Path(os.path.expandvars(value)).expanduser().resolve()
    configuration = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'user-dirs.dirs'
    if configuration.is_file():
        variable = 'XDG_' + name.upper() + '_DIR'
        for line in configuration.read_text(encoding='utf-8').splitlines():
            key, separator, value = line.partition('=')
            if separator and key.strip() == variable:
                values = shlex.split(value)
                if len(values) == 1:
                    return local_path(values[0].replace('${HOME}', str(Path.home())).replace('$HOME', str(Path.home())))
    return Path.home() / name


def choose_output_directory(identifier):
    ui.menu('Сохранение бэкапов, конфигов и результатов', [
        ('1', 'Рабочий стол'), ('2', 'Документы (по умолчанию)'), ('3', 'Свой путь')])
    choice = ui.select('Каталог сохранения', ['1', '2', '3'], '2', read=ask)
    if choice in ['1', '2']:
        base = user_folder('Desktop' if choice == '1' else 'Documents')
    elif choice == '3':
        base = local_path(ask('Путь к папке на этом компьютере'))
    else:
        raise ValueError('Выберите 1, 2 или 3')
    if session.ACTIVE and session.ACTIVE.path:
        return session.ACTIVE.path.parent
    output = base / 'VpsMigration' / identifier
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    if session.ACTIVE:
        session.ACTIVE.attach(output)
        print('Продолжение после закрытия: ' + session.ACTIVE.recovery_command(), flush=True)
    print('\nРезультаты будут сохранены в: ' + str(output), flush=True)
    print('Файл бэкапа: ' + str(output / 'migration-bundle.tar.gz'), flush=True)
    return output


class Connection:
    def __init__(self, address, port, key):
        self.address = c.validate_ip(address)
        self.port = int(port)
        if not 1 <= self.port <= 65535:
            raise ValueError('Некорректный SSH-порт')
        self.key = local_path(key)
        if not self.key.is_file():
            raise ValueError('Файл приватного SSH-ключа не найден')
        self.options = ['-i', str(self.key), '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=ask',
                        '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no',
                        '-o', 'KbdInteractiveAuthentication=no', '-o', 'ControlMaster=no',
                        '-o', 'ControlPath=none', '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=20',
                        '-o', 'ServerAliveCountMax=6']

    def use_jump(self, entry, output):
        if entry.address == self.address:
            raise ValueError('SSH relay не должен совпадать с целевым сервером')
        key = entry.key.as_posix()
        if any(character in key for character in ['\n', '\r', '\0']):
            raise ValueError('Недопустимый путь SSH-ключа')
        key = key.replace('%', '%%').replace('"', '\\"')
        config = ('Host vps-migration-relay\n  HostName ' + entry.address + '\n  User root\n  Port ' + str(entry.port)
                  + '\n  IdentityFile "' + key + '"\n  IdentitiesOnly yes\n  StrictHostKeyChecking ask\n  ForwardAgent no\n'
                  'Host ' + self.address + '\n  ProxyJump vps-migration-relay\n  ForwardAgent no\n')
        path = output / ('ssh-routing-' + self.address + '.conf')
        c.write(path, config)
        self.options = ['-F', str(path), *self.options]

    def ssh(self, command, capture=False, quiet=False):
        arguments = ['ssh', *self.options, '-p', str(self.port), 'root@' + self.address, command]
        process = subprocess.run(arguments, stdout=subprocess.PIPE if capture else None,
                                 stderr=subprocess.PIPE if quiet else None)
        if process.returncode:
            raise RuntimeError('SSH-команда не выполнена; исходный сервер автоматически не удаляется')
        return process.stdout if capture else None

    def upload(self, source, destination):
        digest = c.checksum(Path(source))
        def transfer():
            temporary = destination + '.upload-part'
            arguments = ['scp', *self.options, '-P', str(self.port), str(source),
                         'root@' + self.address + ':' + temporary]
            subprocess.run(arguments, check=True)
            command = 'test "$(sha256sum ' + shlex.quote(temporary) + ' | cut -d " " -f 1)" = ' + digest
            command += ' && chmod 600 ' + shlex.quote(temporary) + ' && mv -f ' + shlex.quote(temporary) + ' ' + shlex.quote(destination)
            self.ssh(command)
        session.checkpoint('upload:' + self.address + ':' + destination + ':' + digest, transfer)

    def download(self, source, destination):
        destination = Path(destination)
        temporary = destination.with_name(destination.name + '.download-part')
        if temporary.is_symlink():
            raise RuntimeError('Недопустимый временный путь скачивания')
        digest = self.ssh('sha256sum ' + shlex.quote(source), capture=True).decode().split()[0]
        arguments = ['scp', *self.options, '-P', str(self.port),
                     'root@' + self.address + ':' + source, str(temporary)]
        subprocess.run(arguments, check=True)
        temporary.chmod(0o600)
        if c.checksum(temporary) != digest:
            raise RuntimeError('Контрольная сумма скачанного файла не совпала; исходный файл сохранён')
        temporary.replace(destination)


def connection(label):
    ui.section(label)
    address = ask_validated('IPv4 сервера', c.validate_ip)
    port = ask_validated('SSH-порт', ssh_port, 22)
    key = ask_validated('Полный путь к приватному SSH-ключу на этом компьютере; содержимое ключа не вставляйте', existing_key)
    return Connection(address, port, key)


def prepare(remote, request, output):
    key = 'prepare:' + remote.address + ':' + c_digest(request)
    return session.checkpoint(key, lambda: prepare_files(remote, request, output))


def c_digest(value):
    import hashlib
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def prepare_files(remote, request, output):
    print('\n[ВЫПОЛНЯЕТСЯ] Проверка SSH и загрузка файлов. SSH может запросить подтверждение отпечатка или пароль ключа.', flush=True)
    if remote.ssh('id -u', capture=True).strip() != b'0':
        raise RuntimeError('Требуется успешный вход root по указанному ключу')
    session = remote.ssh('printf "%s" "$SSH_CONNECTION"', capture=True).decode().split()
    if len(session) != 4:
        raise RuntimeError('Не удалось определить текущий SSH-порт сервера')
    request = {**request, 'ssh_server_port': int(session[3])}
    name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]
    job = '/root/vps-transfer/' + name
    remote.ssh('umask 077; mkdir -p /root/vps-transfer; mkdir ' + shlex.quote(job))
    directories = sorted({Path(name).parent.as_posix() for name in SERVER_FILES if '/' in name})
    remote.ssh(shlex.join(['mkdir', '-p', *[job + '/' + name for name in directories]]))
    for filename in SERVER_FILES:
        remote.upload(HERE / filename, job + '/' + filename)
    request_file = output / ('request-' + name + '.json')
    c.write(request_file, request)
    remote.upload(request_file, job + '/request.json')
    return job


def action(remote, job, name):
    if name in ['harden', 'commit-ssh', 'maintenance-check']:
        return action_command(remote, job, name)
    return session.checkpoint('action:' + remote.address + ':' + job + ':' + name,
                              lambda: action_command(remote, job, name))


def action_command(remote, job, name):
    command = 'python3 ' + shlex.quote(job + '/remote.py') + ' ' + name + ' --job ' + shlex.quote(job)
    remote.ssh(command)


def background_action(remote, job, name, result_name):
    unit = 'vps-' + name + '-' + job.rsplit('/', 1)[-1]
    arguments = ['systemd-run', '--unit=' + unit, '--no-block',
                 '--property=UMask=0077', '--property=StandardOutput=append:' + job + '/' + name + '-console.log',
                 '--property=StandardError=inherit', '/usr/bin/python3', job + '/remote.py', name, '--job', job]
    known = [job + '/' + result_name, job + '/' + name + '-error.json', job + '/' + name + '-execution.json']
    checks = ' || '.join('test -f ' + shlex.quote(path) for path in known)
    dispatch = 'if ' + checks + '; then exit 0; fi; '
    dispatch += 'state=$(systemctl show ' + shlex.quote(unit) + ' -p LoadState --value); '
    dispatch += 'if test "$state" = loaded; then exit 0; fi; ' + shlex.join(arguments)
    launch = shlex.join(['flock', '-x', job + '/dispatch.lock', 'sh', '-c', dispatch])
    attached = False
    print('Операция работает через systemd и продолжится при обрыве SSH.')
    if name == 'backup':
        print('Если интернет компьютера идёт через этот VPN, при необходимости переподключите его после восстановления сервиса.')
    deadline = time.monotonic() + 4 * 3600
    last_status = None
    while time.monotonic() < deadline:
        command = 'if test -f ' + shlex.quote(job + '/' + result_name) + '; then cat ' + shlex.quote(job + '/' + result_name)
        command += '; elif test -f ' + shlex.quote(job + '/' + name + '-error.json') + '; then cat ' + shlex.quote(job + '/' + name + '-error.json')
        command += '; elif systemctl is-failed --quiet ' + shlex.quote(unit) + '; then printf \'{"success":false,"error":"Серверная задача завершилась аварийно. Проверьте systemd journal."}\''
        command += '; elif test -f ' + shlex.quote(job + '/' + name + '-execution.json') + ' && ! systemctl is-active --quiet ' + shlex.quote(unit) + '; then printf \'{"success":false,"error":"Серверная задача остановлена без результата; автоматический повтор запрещён. Проверьте её журнал и консоль VPS."}\''
        command += '; elif test -f ' + shlex.quote(job + '/progress.json') + '; then cat ' + shlex.quote(job + '/progress.json')
        command += '; else printf \'{"stage":"Ожидание запуска"}\'; fi'
        try:
            if not attached:
                remote.ssh(launch, quiet=True)
                attached = True
            response = remote.ssh(command, capture=True, quiet=True)
        except RuntimeError:
            attached = False
            status = {'stage': 'Связь или запуск пока не подтверждены; восстанавливается наблюдение той же задачи'}
        else:
            try:
                status = json.loads(response)
            except ValueError as error:
                raise RuntimeError('Повреждён результат серверной задачи; автоматическое продолжение остановлено') from error
            if not isinstance(status, dict):
                raise RuntimeError('Некорректный формат результата серверной задачи')
        if status.get('success') is True:
            return
        if status.get('success') is False:
            raise RuntimeError(status.get('error', 'Серверная операция завершилась ошибкой'))
        stage = status.get('stage', 'Работа продолжается')
        if stage != last_status:
            print(stage, flush=True)
            last_status = stage
        time.sleep(5)
    raise RuntimeError('Истекло время наблюдения; задача может продолжаться. Проверить systemd unit ' + unit)


def harden_connection(host, job):
    def verify():
        action(host, job, 'harden')
        if host.ssh('id -u', capture=True).strip() != b'0':
            raise RuntimeError('Новый SSH-вход не подтверждён; ожидается таймер отката')
        action(host, job, 'commit-ssh')
    session.checkpoint('security:' + host.address + ':' + job, verify)


def bundle_from_source(output):
    source = connection('Старый сервер: создание полной копии временно остановит выбранные VPN и панели')
    access = ui.select('SSH к старому серверу: 1 — напрямую, 2 — через доступный relay', ['1', '2'], '1', read=ask)
    if access == '2':
        entry = connection('SSH relay для доступа к старому серверу; пересылка VPN здесь не настраивается')
        source.use_jump(entry, output)
    elif access != '1':
        raise ValueError('Выберите вариант SSH 1 или 2')
    domain = c.validate_domain(ask('Текущий домен старого сервера'))
    if ask('Для согласия на временную остановку введите BACKUP ' + source.address) != 'BACKUP ' + source.address:
        raise RuntimeError('Создание копии отменено')
    request = {'mode': 'backup', 'ip': source.address, 'domain': domain,
               'camouflage': 'www.googletagmanager.com', 'ssh_port': source.port}
    job = prepare(source, request, output)
    c.write(output / 'source-operation.json', {'remote_job': job, 'source_ip': source.address})
    background_action(source, job, 'backup', 'backup-result.json')
    destination = output / 'migration-bundle.tar.gz'
    source.download(job + '/migration-bundle.tar.gz', destination)
    source.download(job + '/backup-result.json', output / 'backup-result.json')
    result = json.loads((output / 'backup-result.json').read_text())
    if not result['success'] or c.checksum(destination) != result['sha256']:
        raise RuntimeError('Контрольная сумма полученной копии не совпала')
    return destination


def main():
    parser = argparse.ArgumentParser(description='Развёртывание и миграция VPN без передачи SSH-приватного ключа')
    parser.add_argument('--check', action='store_true', help='проверить локальные файлы; не подключаться к серверу')
    parser.add_argument('--resume', type=Path, help='продолжить операцию из session.json')
    parser.add_argument('--options', type=Path, help='JSON с дополнительными параметрами Self-Steal')
    args = parser.parse_args()
    state = session.Session(args.resume)
    if args.resume:
        if ui.prompt('Продолжить ранее согласованную операцию? Введите RESUME', None) != 'RESUME':
            raise RuntimeError('Продолжение отменено')
    with session.active(state):
        if args.resume and args.options:
            raise RuntimeError('При --resume параметры берутся из журнала; --options менять нельзя')
        if not args.resume:
            from vps_migration.cli.selfsteal import options
            state.state['selfsteal_options'] = options(args.options)
        try:
            execute_wizard(args)
            state.state['done'] = True
            state.save()
        except BaseException:
            if state.path:
                print('Продолжить эту операцию: ' + state.recovery_command(), file=sys.stderr)
            raise


def execute_wizard(args):
    if sys.version_info < (3, 11) or not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Нужен Python 3.11+ с актуальными исправлениями tarfile')
    if args.check:
        import ast
        for path in HERE.rglob('*.py'):
            ast.parse(path.read_text(encoding='utf-8'))
        print('Синтаксис локальных Python-файлов корректен. Развёртывание не выполнялось.')
        return
    for tool in ['ssh', 'scp']:
        if shutil.which(tool) is None:
            raise RuntimeError('Не найден OpenSSH: ' + tool)
    ui.section('VPS Migration • установка и перенос VPN')
    print('  Выбирайте пункты цифрой и нажимайте Enter. Отмена: Ctrl+C.', flush=True)
    print('При отметке [ОЖИДАНИЕ ВВОДА] программа ждёт ваш ответ после >. Отмена: Ctrl+C.', flush=True)
    ui.menu('Операция', [('1', 'Новая установка с личными и общими доступами'),
                        ('2', 'Перенос существующих доступов из полной резервной копии'),
                        ('3', 'Только создать полную копию старого сервера'),
                        ('4', 'Обслуживание текущего VPS: пакеты ОС и очистка')])
    mode = ui.select('Выберите операцию', ['1', '2', '3', '4'], '2', read=ask)
    identifier = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]
    output = choose_output_directory(identifier)
    if mode == '4':
        from vps_migration.cli.maintenance import run as maintain
        maintain(output)
        return
    if mode == '3':
        path = bundle_from_source(output)
        print('Копия сохранена:', path)
        return
    bundle = None
    if mode == '2':
        selection = ui.select('1 — Создать свежую полную копию; 2 — использовать готовую', ['1', '2'], '1', read=ask)
        if selection == '1':
            bundle = bundle_from_source(output)
        elif selection == '2':
            bundle = local_path(ask('Путь к migration-bundle.tar.gz'))
            if not bundle.is_file():
                raise ValueError('Архив не найден')
            expected = ask('Ожидаемый SHA-256 из backup-result.json').lower()
            if not re.fullmatch(r'[0-9a-f]{64}', expected) or c.checksum(bundle) != expected:
                raise ValueError('Контрольная сумма архива не совпала')
        else:
            raise ValueError('Неизвестный вариант копии')
    target = connection('Новый сервер: только чистая установка, Ubuntu/Debian, root и Python 3.11+')
    scheme, entry = topology.choose(connection, ask, target)
    scheme.update(topology.bundle_settings(bundle, scheme))
    scheme['selfsteal_options'] = dict(session.ACTIVE.state['selfsteal_options']) if session.ACTIVE else {}
    for option, setting in [('tls_port', 'selfsteal_port'), ('reality_port', 'selfsteal_reality_port')]:
        if option in scheme['selfsteal_options']:
            port = scheme['selfsteal_options'][option]
            if port in scheme.get('reserved_binding_ports', []):
                raise ValueError('Выбранный новый порт занят сохранённым приложением; Amnezia не будет изменена')
            scheme[setting] = port
    if scheme['selfsteal_options'].get('reality', True):
        c.selfsteal_reality_port(scheme)
    if entry:
        target.use_jump(entry, output)
    public_ip = entry.address if entry else target.address
    domain = c.validate_domain(ask('Домен входа; заранее направьте A-запись только на ' + public_ip))
    camouflage = c.validate_domain(ask('HTTPS-сайт для новых REALITY/Telegram-конфигов: TLS 1.3 и HTTP/2, не домен этого VPS', ''))
    ui.menu('Публикация портов', [('1', 'TCP 443 Amnezia + отдельный порт новых способов; остальные локальны'),
                                ('2', 'Сохранить доступность старых VPN-портов и панели 3DP')])
    profile_choice = ui.select('Сетевой профиль', ['1', '2'], '2' if scheme['self_steal'] else '1', read=ask)
    network_profile = 'filtered' if profile_choice == '1' else 'all'
    selected_fingerprint = ask('TLS fingerprint клиента REALITY: firefox или safari', 'firefox')
    c.fingerprint({'fingerprint': selected_fingerprint})
    email = ask('Email для Let’s Encrypt, можно оставить пустым', '')
    if email and (not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or email.startswith('-')):
        raise ValueError('Некорректный email')
    warp_accepted = False
    if scheme.get('full_selfsteal'):
        from vps_migration.cli.selfsteal import choose_warp
        warp_accepted = choose_warp(target.address, scheme['selfsteal_options'], ask)
        scheme['selfsteal_options']['warp'] = warp_accepted
    ui.section('Проверка плана перед изменениями')
    print('Будут установлены Docker, VPN, 3x-ui/3DP, Fail2ban, firewall и Certbot.')
    print('Протоколы: XRay, AmneziaWG, Telegram MTProxy, WireGuard, OpenVPN, Shadowsocks, Hysteria2.')
    print('Приватный SSH-ключ останется на этом компьютере. Парольный вход отключится после проверки ключа.')
    print('Сетевой профиль: ' + network_profile + '. Маскировка не устраняет блокировку всего IP.')
    print('Основной VPS: ' + target.address + '; вход: ' + public_ip + '; домен: ' + domain)
    print('Приоритет: Amnezia → новые способы → остальные. Порт новых способов: ' + str(c.selfsteal_port(scheme)))
    if scheme.get('full_selfsteal'):
        print('Полный набор Self-Steal: TLS, REALITY на собственный сайт, XHTTP, WARP и HTTPS-подписки.')
        print('HTTP 80 будет обслуживать ACME/webroot и перенаправление на сайт; старый Certbot может дополнительно перевыпустить сертификат.')
        if scheme['selfsteal_options'].get('reality', True):
            print('Дополнительный TCP-порт REALITY: ' + str(c.selfsteal_reality_port(scheme)))
        if scheme['selfsteal_options'].get('warp', True):
            print('WARP: включён, отдельное согласие получено. Amnezia через Cloudflare не направляется.')
        else:
            print('WARP: выключен; регистрации в Cloudflare не будет.')
    if entry:
        print('Relay будет пересылать TCP/UDP без расшифровки; дополнительный участок может увеличить задержку.')
    print('Подтверждение также означает согласие с условиями Let’s Encrypt: https://letsencrypt.org/repository/')
    if ask('Для запуска введите DEPLOY ' + target.address) != 'DEPLOY ' + target.address:
        raise RuntimeError('Развёртывание отменено')
    if entry and ask('Для настройки перенаправления введите RELAY ' + entry.address) != 'RELAY ' + entry.address:
        raise RuntimeError('Настройка relay отменена')
    request = {'mode': 'fresh' if mode == '1' else 'restore', 'ip': target.address, 'domain': domain,
               'camouflage': camouflage, 'email': email, 'acme_agreed': True, 'ssh_port': target.port,
               'network_profile': network_profile, 'fingerprint': selected_fingerprint,
               'warp_terms_accepted': warp_accepted, **scheme}
    from vps_migration.cli.selfsteal import site_archive
    site = site_archive(output, scheme['selfsteal_options'])
    if site:
        request['site_sha256'] = site['sha256']
    job = prepare(target, request, output)
    c.write(output / 'operation.json', {'remote_job': job, 'target_ip': target.address, 'mode': request['mode']})
    if site:
        target.upload(site['path'], job + '/site-content.tar.gz')
    action(target, job, 'preflight')
    entry_job = None
    if entry:
        entry_job = prepare(entry, topology.relay_request(entry, target, request), output)
        topology.save_relay_instructions(output, entry, entry_job)
        action(entry, entry_job, 'relay-preflight')
    session.checkpoint('os-approval:' + job + ':' + target.address, lambda: approve_os_updates(target, job, output))
    if entry:
        session.checkpoint('os-approval:' + entry_job + ':' + entry.address, lambda: approve_os_updates(entry, entry_job, output))
    if bundle:
        target.upload(bundle, job + '/migration-bundle.tar.gz')
    backup_errors = []
    try:
        if entry:
            background_action(entry, entry_job, 'relay', 'relay-result.json')
        background_action(target, job, 'deploy', 'deploy-result.json')
        target.download(job + '/access-files.tar.gz', output / 'access-files.tar.gz')
        target.download(job + '/deploy-result.json', output / 'deploy-result.json')
        c.safe_extract(output / 'access-files.tar.gz', output / 'access')
        panels = output / 'access/admin/panels.json'
        from vps_migration.cli.selfsteal import export_tunnel
        base_path = json.loads(panels.read_text())['xui_base_path'] if panels.exists() else '/'
        export_tunnel(target, output, base_path)
        harden_connection(target, job)
        if entry:
            harden_connection(entry, entry_job)
    finally:
        for host, host_job in [(target, job), *([(entry, entry_job)] if entry else [])]:
            directory = output / ('os-' + host.address)
            directory.mkdir(mode=0o700, exist_ok=True)
            failed = download_backups(host, host_job, directory) or []
            backup_errors.extend(host.address + ": " + name for name in failed)
    if backup_errors:
        raise RuntimeError('Развёртывание завершено, но серверные резервные копии не все скачаны: ' + '; '.join(backup_errors))
    for host, host_job in [(target, job), *([(entry, entry_job)] if entry else [])]:
        session.checkpoint('reboot:' + host.address + ':' + host_job, lambda: restart_if_needed(host, host_job, output))
    c.write(output / 'security-result.json', {'key_login_verified_after_hardening': True,
            'password_login_disabled': True, 'fail2ban_sshd_enabled': True})
    print('\nГотово. Конфиги и строки:', output / 'access')
    print('personal — себе; shared — остальным; admin и legacy не раздавать.')
    print('Проверьте VPN с телефона по Wi-Fi и мобильной сети. Старый сервер не удалён.')


def run():
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('\nОперация остановлена: ' + str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    run()
