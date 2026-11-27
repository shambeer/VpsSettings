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

import common as c

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent


def ask(prompt, default=None):
    print('\n[ОЖИДАНИЕ ВВОДА] ' + prompt, flush=True)
    if default is None:
        print('Введите значение и нажмите Enter. Поле обязательно.', flush=True)
    elif default == '':
        print('Введите значение и нажмите Enter. Чтобы пропустить, нажмите Enter.', flush=True)
    else:
        print('Введите значение и нажмите Enter. Enter без ввода: ' + str(default), flush=True)
    while True:
        value = input('> ').strip()
        if value:
            return value
        if default is not None:
            return default
        print('Значение не введено. Введите его после > и нажмите Enter.', flush=True)


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
    print('\nГде сохранить бэкап, конфиги и результаты?', flush=True)
    print('1 — Рабочий стол\n2 — Документы (по умолчанию)\n3 — Свой путь', flush=True)
    choice = ask('Каталог сохранения', '2')
    if choice in ['1', '2']:
        base = user_folder('Desktop' if choice == '1' else 'Documents')
    elif choice == '3':
        base = local_path(ask('Путь к папке на этом компьютере'))
    else:
        raise ValueError('Выберите 1, 2 или 3')
    output = base / 'VpsMigration' / identifier
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
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

    def ssh(self, command, capture=False, quiet=False):
        arguments = ['ssh', *self.options, '-p', str(self.port), 'root@' + self.address, command]
        process = subprocess.run(arguments, stdout=subprocess.PIPE if capture else None,
                                 stderr=subprocess.PIPE if quiet else None)
        if process.returncode:
            raise RuntimeError('SSH-команда не выполнена; исходный сервер автоматически не удаляется')
        return process.stdout if capture else None

    def upload(self, source, destination):
        arguments = ['scp', *self.options, '-P', str(self.port), str(source),
                     'root@' + self.address + ':' + destination]
        subprocess.run(arguments, check=True)

    def download(self, source, destination):
        arguments = ['scp', *self.options, '-P', str(self.port),
                     'root@' + self.address + ':' + source, str(destination)]
        subprocess.run(arguments, check=True)


def connection(label):
    print('\n' + label)
    address = c.validate_ip(ask('IPv4 сервера'))
    port = int(ask('SSH-порт', 22))
    key = ask('Путь к приватному SSH-ключу, не его содержимое')
    return Connection(address, port, key)


def prepare(remote, request, output):
    print('\n[ВЫПОЛНЯЕТСЯ] Проверка SSH и загрузка файлов на сервер. Ввод не требуется.', flush=True)
    if remote.ssh('id -u', capture=True).strip() != b'0':
        raise RuntimeError('Требуется успешный вход root по указанному ключу')
    session = remote.ssh('printf "%s" "$SSH_CONNECTION"', capture=True).decode().split()
    if len(session) != 4:
        raise RuntimeError('Не удалось определить текущий SSH-порт сервера')
    request = {**request, 'ssh_server_port': int(session[3])}
    name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]
    job = '/root/vps-transfer/' + name
    remote.ssh('umask 077; mkdir -p /root/vps-transfer; mkdir ' + shlex.quote(job))
    for filename in ['common.py', 'stack.py', 'snapshot.py', 'remote.py']:
        remote.upload(HERE / filename, job + '/' + filename)
    request_file = output / ('request-' + name + '.json')
    c.write(request_file, request)
    remote.upload(request_file, job + '/request.json')
    return job


def action(remote, job, name):
    command = 'python3 ' + shlex.quote(job + '/remote.py') + ' ' + name + ' --job ' + shlex.quote(job)
    remote.ssh(command)


def background_action(remote, job, name, result_name):
    unit = 'vps-' + name + '-' + job.rsplit('/', 1)[-1]
    arguments = ['systemd-run', '--unit=' + unit, '--no-block', '--collect',
                 '--property=UMask=0077', '--property=StandardOutput=append:' + job + '/' + name + '-console.log',
                 '--property=StandardError=inherit', '/usr/bin/python3', job + '/remote.py', name, '--job', job]
    remote.ssh(shlex.join(arguments))
    print('Операция работает через systemd и продолжится при обрыве SSH.')
    if name == 'backup':
        print('Если интернет компьютера идёт через этот VPN, при необходимости переподключите его после восстановления сервиса.')
    deadline = time.monotonic() + 4 * 3600
    last_status = None
    while time.monotonic() < deadline:
        command = 'if test -f ' + shlex.quote(job + '/' + result_name) + '; then cat ' + shlex.quote(job + '/' + result_name)
        command += '; elif test -f ' + shlex.quote(job + '/' + name + '-error.json') + '; then cat ' + shlex.quote(job + '/' + name + '-error.json')
        command += '; elif test -f ' + shlex.quote(job + '/progress.json') + '; then cat ' + shlex.quote(job + '/progress.json')
        command += '; else printf \'{"stage":"Ожидание запуска"}\'; fi'
        try:
            status = json.loads(remote.ssh(command, capture=True, quiet=True))
        except (RuntimeError, ValueError):
            status = {'stage': 'SSH временно недоступен; серверная операция продолжается'}
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


def bundle_from_source(output):
    source = connection('Старый сервер: создание полной копии временно остановит выбранные VPN и панели')
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
    args = parser.parse_args()
    if sys.version_info < (3, 11) or not hasattr(tarfile, 'data_filter'):
        raise RuntimeError('Нужен Python 3.11+ с актуальными исправлениями tarfile')
    if args.check:
        import ast
        for path in HERE.glob('*.py'):
            ast.parse(path.read_text(encoding='utf-8'))
        print('Синтаксис локальных Python-файлов корректен. Развёртывание не выполнялось.')
        return
    for tool in ['ssh', 'scp']:
        if shutil.which(tool) is None:
            raise RuntimeError('Не найден OpenSSH: ' + tool)
    print('\nМастер готов. Выбирайте пункты цифрой и нажимайте Enter.', flush=True)
    print('При отметке [ОЖИДАНИЕ ВВОДА] программа ждёт ваш ответ после >. Отмена: Ctrl+C.', flush=True)
    print('1 — Новая установка с личными и общими доступами')
    print('2 — Перенос существующих доступов из полной копии + резервные протоколы')
    print('3 — Только создать полную копию старого сервера')
    mode = ask('Режим', '2')
    if mode not in ['1', '2', '3']:
        raise ValueError('Неизвестный режим')
    identifier = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]
    output = choose_output_directory(identifier)
    if mode == '3':
        path = bundle_from_source(output)
        print('Копия сохранена:', path)
        return
    bundle = None
    if mode == '2':
        selection = ask('1 — Создать свежую полную копию; 2 — использовать готовую', '1')
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
    domain = c.validate_domain(ask('Домен нового сервера; заранее направьте A-запись на его IPv4'))
    camouflage = c.validate_domain(ask('HTTPS-сайт для новых REALITY/Telegram-конфигов: TLS 1.3 и HTTP/2, не домен этого VPS', ''))
    print('1 — Сеть с фильтрацией: снаружи только XRay TCP 443; панели и резервные протоколы локально')
    print('2 — Все VPN-порты и HTTPS-панель 3DP опубликованы, как в обычной установке')
    profile_choice = ask('Сетевой профиль', '1')
    if profile_choice not in ['1', '2']:
        raise ValueError('Неизвестный сетевой профиль')
    network_profile = 'filtered' if profile_choice == '1' else 'all'
    selected_fingerprint = ask('TLS fingerprint клиента REALITY: firefox или safari', 'firefox')
    c.fingerprint({'fingerprint': selected_fingerprint})
    email = ask('Email для Let’s Encrypt, можно оставить пустым', '')
    if email and (not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or email.startswith('-')):
        raise ValueError('Некорректный email')
    print('\nБудут установлены Docker, VPN, 3x-ui/3DP, Fail2ban, firewall и Certbot.')
    print('Протоколы: XRay, AmneziaWG, Telegram MTProxy, WireGuard, OpenVPN, Shadowsocks, Hysteria2.')
    print('Приватный SSH-ключ останется на этом компьютере. Парольный вход отключится после проверки ключа.')
    print('Сетевой профиль: ' + network_profile + '. Маскировка не устраняет блокировку всего IP.')
    print('Подтверждение также означает согласие с условиями Let’s Encrypt: https://letsencrypt.org/repository/')
    if ask('Для запуска введите DEPLOY ' + target.address) != 'DEPLOY ' + target.address:
        raise RuntimeError('Развёртывание отменено')
    request = {'mode': 'fresh' if mode == '1' else 'restore', 'ip': target.address, 'domain': domain,
               'camouflage': camouflage, 'email': email, 'acme_agreed': True, 'ssh_port': target.port,
               'network_profile': network_profile, 'fingerprint': selected_fingerprint}
    job = prepare(target, request, output)
    c.write(output / 'operation.json', {'remote_job': job, 'target_ip': target.address, 'mode': request['mode']})
    action(target, job, 'preflight')
    if bundle:
        target.upload(bundle, job + '/migration-bundle.tar.gz')
    background_action(target, job, 'deploy', 'deploy-result.json')
    target.download(job + '/access-files.tar.gz', output / 'access-files.tar.gz')
    target.download(job + '/deploy-result.json', output / 'deploy-result.json')
    c.safe_extract(output / 'access-files.tar.gz', output / 'access')
    action(target, job, 'harden')
    if target.ssh('id -u', capture=True).strip() != b'0':
        raise RuntimeError('Новый SSH-вход не подтверждён; через 180 секунд сработает откат SSH')
    action(target, job, 'commit-ssh')
    c.write(output / 'security-result.json', {'key_login_verified_after_hardening': True,
            'password_login_disabled': True, 'fail2ban_sshd_enabled': True})
    print('\nГотово. Конфиги и строки:', output / 'access')
    print('personal — себе; shared — остальным; admin и legacy не раздавать.')
    print('Проверьте VPN с телефона по Wi-Fi и мобильной сети. Старый сервер не удалён.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('\nОперация остановлена: ' + str(error), file=sys.stderr)
        sys.exit(1)
