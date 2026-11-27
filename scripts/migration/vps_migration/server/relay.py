import argparse
import json
import os
from pathlib import Path
import re
import shutil
import shlex

from vps_migration.core import common as c

DIRECTORY = Path('/opt/vps-relay')
CONFIG = Path('/etc/vps-relay.json')
CHAINS = [('nat', 'PREROUTING', 'VPS_RELAY_IN'),
          ('nat', 'POSTROUTING', 'VPS_RELAY_OUT'),
          ('filter', 'FORWARD', 'VPS_RELAY_FWD')]
TCP_PORTS = [80, 443, 50553, 6659, 8388, 8389]
UDP_PORTS = [443, 46872, 51820, 1194, 2443, 8388, 8389]


def selected_ports(request):
    if c.network_profile(request) == 'filtered':
        return [('tcp', [80, 443]), ('udp', [443])]
    result = []
    for protocol, defaults in [('tcp', TCP_PORTS), ('udp', UDP_PORTS)]:
        extras = request.get('extra_' + protocol + '_ports', [])
        if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in extras):
            raise ValueError('Недопустимый дополнительный порт')
        result.append((protocol, sorted(set(defaults + extras))))
    return result


def assert_local_public_ip(address):
    c.validate_ip(address)
    interfaces = json.loads(c.run(['ip', '-j', 'address', 'show']).stdout)
    assigned = {item['local'] for interface in interfaces for item in interface.get('addr_info', [])
                if item.get('family') == 'inet'}
    if address not in assigned:
        raise RuntimeError('Указанный публичный IPv4 должен быть назначен интерфейсу VPS; серверы за внешним NAT автоматически не поддерживаются')


def rules(request):
    origin = c.validate_ip(request['origin_ip'])
    entry = c.validate_ip(request['ip'])
    result = []
    for protocol, ports in selected_ports(request):
        for port in ports:
            result.append(('nat', 'VPS_RELAY_IN', ['-d', entry, '-p', protocol, '--dport', str(port),
                           '-j', 'DNAT', '--to-destination', origin + ':' + str(port)]))
            result.append(('nat', 'VPS_RELAY_OUT', ['-d', origin, '-p', protocol, '--dport', str(port),
                           '-m', 'conntrack', '--ctstate', 'DNAT', '-j', 'SNAT', '--to-source', entry]))
            result.append(('filter', 'VPS_RELAY_FWD', ['-d', origin, '-p', protocol, '--dport', str(port),
                           '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED', '--ctorigdst', entry, '-j', 'ACCEPT']))
    result.append(('filter', 'VPS_RELAY_FWD', ['-s', origin, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']))
    return result


def preflight(request):
    if os.geteuid() != 0 or not Path('/etc/debian_version').exists():
        raise RuntimeError('Для relay нужен root на Debian/Ubuntu с systemd и Python 3.11+')
    c.validate_ip(request['origin_ip'])
    c.validate_ip(request['ip'])
    if request['origin_ip'] == request['ip']:
        raise RuntimeError('Relay и основной VPS должны иметь разные IPv4')
    assert_local_public_ip(request['ip'])
    if DIRECTORY.exists() or CONFIG.exists():
        raise RuntimeError('Relay уже настроен; автоматическая перезапись запрещена')
    if shutil.which('docker') and c.run(['docker', 'ps', '-aq']).stdout.strip():
        raise RuntimeError('Для relay требуется чистый сервер без контейнеров')
    ssh = os.environ.get('SSH_CONNECTION', '').split()
    port = int(ssh[-1]) if ssh else request['ssh_port']
    if port in dict(selected_ports(request))['tcp']:
        raise RuntimeError('SSH-порт relay совпадает с пересылаемым портом; выберите отдельный SSH-порт')
    listening = c.run(['ss', '-H', '-lntu']).stdout.decode()
    for line in listening.splitlines():
        fields = line.split()
        if len(fields) > 4:
            match = re.search(r':(\d+)$', fields[4])
            if match and int(match.group(1)) in {port for protocol, ports in selected_ports(request) for port in ports}:
                raise RuntimeError('На relay занят пересылаемый порт ' + match.group(1))


def apply(request):
    c.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    for table, parent, chain in CHAINS:
        c.run(['iptables', '-w', '-t', table, '-N', chain], check=False)
        c.run(['iptables', '-w', '-t', table, '-F', chain])
    for table, chain, arguments in rules(request):
        c.run(['iptables', '-w', '-t', table, '-A', chain, *arguments])
    for table, parent, chain in CHAINS:
        check = ['iptables', '-w', '-t', table, '-C', parent, '-j', chain]
        if c.run(check, check=False).returncode:
            c.run(['iptables', '-w', '-t', table, '-I', parent, '1', '-j', chain])


def remove():
    for table, parent, chain in reversed(CHAINS):
        while c.run(['iptables', '-w', '-t', table, '-C', parent, '-j', chain], check=False).returncode == 0:
            c.run(['iptables', '-w', '-t', table, '-D', parent, '-j', chain])
        c.run(['iptables', '-w', '-t', table, '-F', chain], check=False)
        c.run(['iptables', '-w', '-t', table, '-X', chain], check=False)


def install(request, job):
    preflight(request)
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    c.run(['apt-get', 'update'], timeout=900)
    c.run(['apt-get', 'install', '-y', 'iptables', 'fail2ban', 'python3-systemd', 'unattended-upgrades'], timeout=900)
    c.write(job / 'iptables-before.txt', c.run(['iptables-save']).stdout)
    previous = c.run(['sysctl', '-n', 'net.ipv4.ip_forward']).stdout.decode().strip()
    DIRECTORY.mkdir(mode=0o700)
    package = Path(__file__).resolve().parents[1]
    for name in ['__init__.py', 'core/__init__.py', 'core/common.py', 'server/__init__.py', 'server/relay.py']:
        c.write(DIRECTORY / 'vps_migration' / name, (package / name).read_bytes())
    c.write(CONFIG, request)
    c.write(DIRECTORY / 'previous-forwarding.json', {'ip_forward': previous})
    unit = ('[Unit]\nDescription=Managed VPN relay forwarding\nAfter=network-online.target\nWants=network-online.target\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nWorkingDirectory=/opt/vps-relay\n'
            'ExecStart=/usr/bin/python3 -m vps_migration.server.relay apply\n'
            'ExecStop=/usr/bin/python3 -m vps_migration.server.relay remove\n[Install]\nWantedBy=multi-user.target\n')
    c.write('/etc/systemd/system/vps-relay.service', unit)
    c.run(['systemctl', 'daemon-reload'])
    try:
        c.run(['systemctl', 'enable', '--now', 'vps-relay.service'])
    except Exception:
        c.run(['systemctl', 'disable', '--now', 'vps-relay.service'], check=False)
        remove()
        c.run(['sysctl', '-w', 'net.ipv4.ip_forward=' + previous])
        raise
    c.write(job / 'relay-result.json', {'success': True, 'origin_ip': request['origin_ip'],
            'forwarded_tcp': dict(selected_ports(request))['tcp'],
            'forwarded_udp': dict(selected_ports(request))['udp']})


def origin_gate_script(request, interface):
    origin = c.validate_ip(request['ip'])
    entry = c.validate_ip(request['relay_ip'])
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+', interface):
        raise ValueError('Недопустимый сетевой интерфейс')
    commands = ['#!/bin/sh', 'set -eu',
        'iptables -w -N DOCKER-USER 2>/dev/null || iptables -w -S DOCKER-USER >/dev/null',
        'iptables -w -N VPS_ORIGIN_GATE 2>/dev/null || iptables -w -S VPS_ORIGIN_GATE >/dev/null',
        'iptables -w -F VPS_ORIGIN_GATE']
    for protocol, ports in selected_ports({**request, 'network_profile': 'all'}):
        for port in ports:
            arguments = ['iptables', '-w', '-A', 'VPS_ORIGIN_GATE', '-i', interface, '!', '-s', entry,
                         '-p', protocol, '-m', 'conntrack', '--ctorigdst', origin,
                         '--ctorigdstport', str(port), '-j', 'DROP']
            commands.append(shlex.join(arguments))
    commands += ['iptables -w -A VPS_ORIGIN_GATE -j RETURN',
        'iptables -w -C DOCKER-USER -j VPS_ORIGIN_GATE 2>/dev/null || iptables -w -I DOCKER-USER 1 -j VPS_ORIGIN_GATE',
        'iptables -w -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -w -I FORWARD 1 -j DOCKER-USER']
    return '\n'.join(commands) + '\n'


def install_origin_gate(request):
    route = json.loads(c.run(['ip', '-j', 'route', 'get', request['relay_ip']]).stdout)
    script = Path('/usr/local/sbin/vps-origin-gate.sh')
    c.write(script, origin_gate_script(request, route[0]['dev']))
    unit = ('[Unit]\nDescription=Restrict managed VPN ingress to relay\nAfter=docker.service\nRequires=docker.service\n'
            'PartOf=docker.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /usr/local/sbin/vps-origin-gate.sh\n'
            '[Install]\nWantedBy=multi-user.target\n')
    c.write('/etc/systemd/system/vps-origin-gate.service', unit)
    c.run(['systemctl', 'daemon-reload'])
    c.run(['systemctl', 'enable', 'vps-origin-gate.service'])
    c.run(['systemctl', 'restart', 'vps-origin-gate.service'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['apply', 'remove'])
    arguments = parser.parse_args()
    request = json.loads(CONFIG.read_text())
    if arguments.action == 'apply':
        apply(request)
    else:
        remove()
        previous = json.loads((DIRECTORY / 'previous-forwarding.json').read_text())['ip_forward']
        c.run(['sysctl', '-w', 'net.ipv4.ip_forward=' + previous])
