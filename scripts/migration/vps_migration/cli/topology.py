from vps_migration.core import common as c
import json
import tarfile
from vps_migration.cli import console as ui


def choose(connect, ask, target):
    ui.menu('Режим подключения • прежние VPN + Self-Steal', [
        ('1', 'Один сервер — всё на основном VPS, без российского сервера'),
        ('2', 'Два сервера — вход через российский relay, выход через основной VPS')])
    choice = ui.select('Выберите режим подключения: 1 или 2', ['1', '2'], '2', read=ask)
    entry = None
    if choice == '2':
        entry = connect('Российский relay: отдельный чистый VPS, root по SSH-ключу и Python 3.11+')
        if entry.address == target.address:
            raise ValueError('Relay и основной VPS должны быть разными серверами')
    return {'self_steal': True, 'relay_ip': entry.address if entry else None}, entry


def relay_request(entry, origin, request):
    return {**request, 'mode': 'relay', 'ip': entry.address,
            'origin_ip': origin.address, 'ssh_port': entry.port}


def bundle_settings(path, scheme):
    if not path:
        return {}
    print('Читаю состав резервной копии для настройки портов и совместимости...', flush=True)
    with tarfile.open(path) as archive:
        member = archive.getmember('manifest.json')
        if not member.isfile() or member.size > 16 * 1024 ** 2:
            raise ValueError('Недопустимый манифест копии')
        with archive.extractfile(member) as source:
            manifest = json.load(source)
    if manifest.get('format') != 1:
        raise ValueError('Поддерживается полная копия формата 1')
    tcp, udp = set(), set()
    preferred_port = 8443
    has_selfsteal = any(item['Name'].lstrip('/') == 'vpn-edge' for item in manifest['containers'])
    self_steal = scheme.get('self_steal') or has_selfsteal
    if scheme.get('relay_ip') and any(item.get('EnableIPv6') for item in manifest.get('networks', {}).values()):
        raise ValueError('Автоматическая relay-схема рассчитана на IPv4; IPv6-сети в копии требуют отдельного переноса')
    for item in manifest['containers']:
        host = item['HostConfig']
        if self_steal and (host['NetworkMode'] == 'host' or host['NetworkMode'].startswith('container:')):
            raise ValueError('Добавление Self-Steal к host/container network требует ручного переноса; прежний сервер не менялся')
        for inside, bindings in (host.get('PortBindings') or {}).items():
            for binding in bindings or []:
                if binding.get('HostIp') in ['127.0.0.1', '::1']:
                    continue
                port = int(binding['HostPort'])
                if not 1 <= port <= 65535:
                    raise ValueError('Недопустимый порт в копии')
                if item['Name'].lstrip('/') == '3x-ui' and inside == '2053/tcp':
                    continue
                if item['Name'].lstrip('/') in ['vpn-edge', 'vpn-selfsteal-hysteria2']:
                    if item['Name'].lstrip('/') == 'vpn-edge' and port != 443:
                        preferred_port = port
                    continue
                (tcp if inside.endswith('/tcp') else udp).add(port)
    occupied = tcp | udp
    port = next((value for value in [preferred_port, *range(8443, 8544)] if value not in occupied and value != 443), None)
    if port is None:
        raise ValueError('Не найден свободный порт для новых способов в диапазоне 8443–8543')
    return {'self_steal': self_steal, 'selfsteal_port': port, 'restore_shared_edge': has_selfsteal,
            'extra_tcp_ports': sorted(tcp), 'extra_udp_ports': sorted(udp)}


def save_relay_instructions(output, entry, job):
    c.write(output / 'relay-operation.json', {'relay_ip': entry.address, 'remote_job': job,
            'stop_forwarding': 'systemctl stop vps-relay.service',
            'start_forwarding': 'systemctl start vps-relay.service',
            'check_forwarding': 'systemctl status vps-relay.service'})
