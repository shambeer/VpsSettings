import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile

from vps_migration.core import common as c

BASE_PACKAGES = {'apt', 'dpkg', 'bash', 'coreutils', 'sudo', 'systemd', 'systemd-sysv',
    'openssh-server', 'openssh-client', 'python3', 'python3-minimal', 'iproute2', 'iptables',
    'nftables', 'ufw', 'fail2ban', 'certbot', 'curl', 'openssl', 'ca-certificates', 'kmod',
    'docker.io', 'docker-ce', 'docker-ce-cli', 'containerd', 'containerd.io', 'runc',
    'netplan.io', 'ifupdown', 'network-manager', 'systemd-resolved', 'resolvconf',
    'wireguard-tools', 'openvpn', 'python3-systemd', 'unattended-upgrades',
    'cloud-init', 'cloud-guest-utils', 'qemu-guest-agent', 'open-vm-tools', 'walinuxagent',
    'google-guest-agent', 'openssh-sftp-server', 'intel-microcode', 'amd64-microcode',
    'initramfs-tools', 'initramfs-tools-core', 'dracut', 'dracut-core', 'cryptsetup',
    'cryptsetup-initramfs', 'lvm2', 'mdadm'}


def command(arguments, timeout=1800):
    os.environ['LC_ALL'] = 'C'
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    return c.run(arguments, timeout=timeout)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def package_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?', value):
        raise ValueError('Недопустимое имя APT-пакета')
    return value


def parse_simulation(text):
    changes, removals = [], []
    for line in text.splitlines():
        install = re.match(r'^Inst\s+(\S+)(?:\s+\[([^]]+)\])?\s+\((\S+)', line)
        remove = re.match(r'^Remv\s+(\S+)(?:\s+\[([^]]+)\])?', line)
        if install:
            changes.append({'package': package_name(install[1]), 'from': install[2], 'to': install[3]})
        elif remove:
            removals.append({'package': package_name(remove[1]), 'version': remove[2]})
    return {'changes': sorted(changes, key=lambda row: row['package']),
            'removals': sorted(removals, key=lambda row: row['package'])}


def installed_packages():
    text = command(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Essential}\t${Protected}\t${Priority}\t${db:Status-Status}\n']).stdout.decode()
    result = []
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) == 6 and fields[5] == 'installed':
            result.append({'package': fields[0], 'version': fields[1],
                           'essential': fields[2] == 'yes', 'protected': fields[3] == 'yes', 'priority': fields[4]})
    if not result:
        raise RuntimeError('Не удалось прочитать список установленных пакетов dpkg')
    return result


def critical(package):
    name = package.split(':', 1)[0]
    return name in BASE_PACKAGES or name.startswith(('linux-', 'grub', 'shim-', 'systemd-', 'cloud-', 'postgresql', 'amnezia', 'python3.'))


def protected_packages(packages):
    roots = {row['package'] for row in packages if row['essential'] or row.get('protected')
             or row['priority'] in ['required', 'important'] or critical(row['package'])}
    if not roots:
        return roots
    text = command(['apt-cache', 'depends', '--recurse', '--installed', '--important',
                    '--no-recommends', '--no-suggests', *sorted(roots)]).stdout.decode()
    installed = {row['package'] for row in packages}
    by_base = {}
    for name in installed:
        by_base.setdefault(name.split(':', 1)[0], set()).add(name)
    for line in text.splitlines():
        words = re.findall(r'[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?', line)
        for word in words:
            if word in installed:
                roots.add(word)
            else:
                roots.update(by_base.get(word, []))
    return roots


def is_protected(name, protected):
    return name in protected or name.split(':', 1)[0] in {item.split(':', 1)[0] for item in protected}


def failed_units():
    text = command(['systemctl', '--failed', '--no-legend', '--plain', '--no-pager']).stdout.decode()
    return sorted(line.split()[0] for line in text.splitlines() if line.strip())


def refresh():
    if shutil.disk_usage('/').free < 2 * 1024 ** 3:
        raise RuntimeError('Для полного обновления ОС нужно минимум 2 GiB свободного диска')
    audit = command(['dpkg', '--audit']).stdout.decode().strip()
    if audit:
        raise RuntimeError('Состояние dpkg требует исправления до обновления: ' + audit[:500])
    command(['apt-get', '-o', 'APT::Update::Error-Mode=any', 'update'], timeout=1800)


def upgrade_plan(refresh_indexes=True):
    if refresh_indexes:
        refresh()
    transaction = parse_simulation(command(['apt-get', '-s', 'dist-upgrade']).stdout.decode())
    packages = installed_packages()
    forbidden = {row['package'] for row in packages if row['essential'] or row.get('protected') or critical(row['package'])}
    unsafe = [row['package'] for row in transaction['removals'] if is_protected(row['package'], forbidden) or critical(row['package'])]
    if unsafe:
        raise RuntimeError('APT предлагает удалить защищённые системные/VPN-пакеты: ' + ', '.join(unsafe))
    held = command(['apt-mark', 'showhold']).stdout.decode().splitlines()
    return {'task': 'os', 'transaction': transaction, 'fingerprint': fingerprint(transaction),
            'held': sorted(held), 'failed_units_before': failed_units(), 'installed_before': packages}


def backup_config(job, plan, filename='os-config-backup.tar.gz'):
    packages = plan['installed_before'] if 'installed_before' in plan else installed_packages()
    c.write(job / 'packages-before.json', packages)
    target = job / filename
    with tarfile.open(target, 'w:gz', dereference=False) as archive:
        if Path('/etc').exists():
            archive.add('/etc', arcname='etc')
        archive.add(job / 'packages-before.json', arcname='packages-before.json')
    return target


def remaining_upgrades():
    text = command(['apt', 'list', '--upgradable']).stdout.decode()
    return sorted({line.split('/', 1)[0] for line in text.splitlines()
                   if re.match(r'^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?/', line)})


def verify_system(plan):
    audit = command(['dpkg', '--audit']).stdout.decode().strip()
    if audit:
        raise RuntimeError('После операции dpkg сообщает о незавершённой настройке: ' + audit[:500])
    if Path('/usr/sbin/sshd').exists():
        command(['/usr/sbin/sshd', '-t'])
        command(['systemctl', 'is-active', 'ssh'])
    new_failures = sorted(set(failed_units()) - set(plan.get('failed_units_before', [])))
    if new_failures:
        raise RuntimeError('После операции появились неисправные systemd-службы: ' + ', '.join(new_failures))


def apply_approved(job):
    plan = json.loads((job / 'os-plan.json').read_text())
    approval = json.loads((job / 'os-approval.json').read_text())
    current = upgrade_plan(False)
    if approval.get('fingerprint') != plan['fingerprint'] or current['fingerprint'] != plan['fingerprint']:
        raise RuntimeError('План APT изменился; требуется новый просмотр и подтверждение')
    if approval.get('removals') != plan['transaction']['removals']:
        raise RuntimeError('Не подтверждён точный список удалений APT')
    backup = backup_config(job, plan)
    os.environ['NEEDRESTART_MODE'] = 'a'
    command(['apt-get', '-y', '-o', 'DPkg::Lock::Timeout=120',
             '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold',
             'dist-upgrade'], timeout=10800)
    verify_system(plan)
    pending = remaining_upgrades()
    reboot_packages = {'libc6', 'systemd', 'systemd-sysv', 'dbus', 'libssl3', 'libssl3t64',
                       'intel-microcode', 'amd64-microcode'}
    reboot = Path('/var/run/reboot-required').exists() or any(
        row['package'].startswith('linux-image') or row['package'].split(':', 1)[0] in reboot_packages
        for row in plan['transaction']['changes'])
    kernels = set()
    for row in plan['transaction']['changes']:
        match = re.match(r'^linux-image-(?:unsigned-)?(\d+\.\d+\..+)$', row['package'].split(':', 1)[0])
        if match:
            kernels.add(match[1])
    result = {'success': not pending, 'complete': not pending, 'task': 'os', 'pending': pending,
              'held': current['held'], 'reboot_required': reboot, 'backup_file': backup.name,
              'backup_sha256': c.checksum(backup), 'expected_kernel_releases': sorted(kernels)}
    if pending:
        result['error'] = 'APT оставил необновлённые пакеты (hold, phased updates или ограничения зависимостей): ' + ', '.join(pending)
    c.write(job / 'os-upgrade-result.json', result)
    if pending:
        raise RuntimeError(result['error'])
    return result
