import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tarfile
from urllib.parse import urlencode, quote

CONTAINERS = ['amnezia-awg2', 'amnezia-xray', 'amnezia-telemt', '3x-ui',
              '3dp-postgres', '3dp-backend', '3dp-frontend', 'vpn-wireguard',
              'vpn-openvpn', 'vpn-shadowsocks', 'vpn-hysteria2', 'vpn-edge',
              'vpn-selfsteal-xray', 'vpn-selfsteal-site', 'vpn-selfsteal-hysteria2', 'vpn-sub-store']
ROOT = Path('/opt/vps-stack')
JOB = None


def validate_ip(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError('Нужен публичный IPv4 сервера')
    return str(address)


def validate_domain(value):
    value = value.rstrip('.').lower()
    if len(value) > 253 or '.' not in value or not re.search(r'[a-z]', value.rsplit('.', 1)[-1]) or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in value.split('.')):
        raise ValueError('Нужен домен без схемы, порта и пути; IDN указывать в punycode')
    return value


def network_profile(request):
    profile = request.get('network_profile', 'all')
    if profile not in ['filtered', 'all']:
        raise ValueError('Неизвестный сетевой профиль')
    return profile


def fingerprint(request):
    value = request.get('fingerprint', 'firefox')
    if value not in ['firefox', 'safari']:
        raise ValueError('Для REALITY поддерживаются fingerprint firefox и safari')
    return value


def selfsteal_port(request):
    port = request.get('selfsteal_port', 8443)
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError('Недопустимый отдельный порт Self-Steal')
    return port


def selfsteal_reality_port(request):
    port = request.get('selfsteal_reality_port', selfsteal_port(request) + 1)
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535 or port == selfsteal_port(request):
        raise ValueError('Нужен отдельный порт Self-Steal REALITY')
    return port


def selfsteal_tcp_ports(request):
    if not request.get('self_steal'):
        return []
    ports = [selfsteal_port(request)]
    if request.get('full_selfsteal') and request.get('selfsteal_options', {}).get('reality', True):
        ports.append(selfsteal_reality_port(request))
    return ports


def exposure_bindings(name, bindings, request):
    if request.get('relay_ip'):
        bindings = copy.deepcopy(bindings)
        for port, values in bindings.items():
            normalized = set()
            for value in values or []:
                address = '127.0.0.1' if value.get('HostIp') in ['127.0.0.1', '::1'] else '0.0.0.0'
                normalized.add((address, str(value['HostPort'])))
            bindings[port] = [{'HostIp': address, 'HostPort': published} for address, published in sorted(normalized)]
    if (request.get('self_steal') or request.get('relay_ip')) and name == '3x-ui' and '2053/tcp' in bindings:
        bindings = copy.deepcopy(bindings)
        bindings['2053/tcp'] = [{'HostIp': '127.0.0.1', 'HostPort': port}
                                for port in sorted({str(value['HostPort']) for value in bindings['2053/tcp'] or []})]
    if request.get('self_steal') and name in ['vpn-edge', 'vpn-selfsteal-hysteria2']:
        bindings = copy.deepcopy(bindings)
        for inside, values in bindings.items():
            for value in values or []:
                value['HostPort'] = str(selfsteal_reality_port(request) if inside == '444/tcp' else selfsteal_port(request))
        if name == 'vpn-edge' and len(selfsteal_tcp_ports(request)) == 2:
            bindings['444/tcp'] = [{'HostIp': '0.0.0.0', 'HostPort': str(selfsteal_reality_port(request))}]
    if request.get('full_selfsteal') and name == 'vpn-selfsteal-site':
        bindings = copy.deepcopy(bindings)
        bindings['80/tcp'] = [{'HostIp': '0.0.0.0', 'HostPort': '80'}]
    if request.get('restore_shared_edge') and name == 'amnezia-xray':
        bindings = copy.deepcopy(bindings)
        for inside, values in bindings.items():
            if inside in ['443/tcp', '443/udp']:
                for value in values or []:
                    if value.get('HostIp') in ['127.0.0.1', '::1'] and str(value['HostPort']) == '1443':
                        value.update(HostIp='0.0.0.0', HostPort='443')
    if network_profile(request) == 'all':
        return copy.deepcopy(bindings)
    result = {}
    for port, values in bindings.items():
        accepted = []
        seen = set()
        for value in values or []:
            address = '127.0.0.1'
            if name == 'amnezia-xray' and port == '443/tcp' and str(value['HostPort']) == '443':
                address = '0.0.0.0'
            if name == 'vpn-selfsteal-site' and request.get('full_selfsteal') and port == '80/tcp':
                address = '0.0.0.0'
            if name in ['vpn-edge', 'vpn-selfsteal-hysteria2'] and port in ['443/tcp', '444/tcp', '443/udp']:
                address = '0.0.0.0'
            key = (address, str(value['HostPort']))
            if key not in seen:
                accepted.append({'HostIp': address, 'HostPort': key[1]})
                seen.add(key)
        result[port] = accepted
    if name == 'amnezia-xray' and not any(
            item['HostIp'] == '0.0.0.0' for item in result.get('443/tcp', [])):
        raise ValueError('Профиль filtered требует XRay на внешнем TCP 443; для других портов выберите all')
    return result


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    if isinstance(value, str):
        value = value.encode()
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_bytes(value)
    temporary.chmod(0o600)
    temporary.replace(path)


def run(arguments, content=None, timeout=600, check=True):
    process = subprocess.run(arguments, input=content, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=timeout)
    if check and process.returncode:
        if JOB:
            write(JOB / 'last-command-error.log', process.stdout + process.stderr)
        raise RuntimeError('Команда завершилась ошибкой; подробности в приватном last-command-error.log')
    return process


def docker_json(*arguments):
    return json.loads(run(['docker', *arguments]).stdout)


def api(method, path, payload=None):
    connection = http.client.HTTPConnection('localhost', timeout=120)
    connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.sock.settimeout(120)
    connection.sock.connect('/var/run/docker.sock')
    try:
        body = None if payload is None else json.dumps(payload).encode()
        connection.request(method, path, body, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        result = response.read()
        if response.status >= 400:
            if JOB:
                write(JOB / 'docker-error.json', result)
            raise RuntimeError('Docker API отказал; подробности в приватном docker-error.json')
        return json.loads(result) if result else None
    finally:
        connection.close()


def checksum(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_extract(archive, destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        def checked(member, directory):
            if member.isdev() or member.isfifo():
                raise ValueError('Специальные файлы в архиве запрещены')
            filtered = tarfile.data_filter(member, directory)
            return filtered.replace(uid=member.uid, gid=member.gid, uname=None, gname=None)
        source.extractall(destination, filter=checked)


def archive_tree(source, target):
    with tarfile.open(target, 'w:gz', dereference=False) as archive:
        for child in sorted(Path(source).iterdir()):
            archive.add(child, arcname=child.name, recursive=True)


def export_access(role, protocol, config=None, link=None, extension='json'):
    directory = ROOT / 'exports' / role
    directory.mkdir(parents=True, exist_ok=True)
    if config is not None:
        write(directory / 'configurations' / (protocol + '.' + extension), config)
    if link is not None:
        write(directory / 'strings' / (protocol + '.txt'), link.rstrip() + '\n')


def vless_link(identifier, domain, port, reality, title):
    query = urlencode({'encryption': 'none', 'security': 'reality', 'sni': reality['serverName'],
                       'fp': fingerprint(reality), 'pbk': reality['publicKey'], 'sid': reality['shortId'],
                       'type': 'tcp', 'flow': 'xtls-rprx-vision'})
    return 'vless://' + identifier + '@' + domain + ':' + str(port) + '?' + query + '#' + quote(title)


def xray_client(identifier, domain, port, reality):
    reality = {**reality, 'fingerprint': fingerprint(reality)}
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 10808,
            'protocol': 'socks', 'settings': {'udp': True}}], 'outbounds': [{'protocol': 'vless',
            'settings': {'vnext': [{'address': domain, 'port': port, 'users': [{'id': identifier,
              'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': reality}}]}


def x25519_pair():
    private = run(['openssl', 'genpkey', '-algorithm', 'X25519', '-outform', 'DER']).stdout
    public = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], private).stdout
    encoded_private = base64.urlsafe_b64encode(private[-32:]).decode().rstrip('=')
    encoded_public = base64.urlsafe_b64encode(public[-32:]).decode().rstrip('=')
    return encoded_private, encoded_public


def public_x25519(private):
    raw = base64.urlsafe_b64decode(private + '=' * (-len(private) % 4))
    if len(raw) != 32:
        raise ValueError('Некорректный REALITY-ключ')
    der = bytes.fromhex('302e020100300506032b656e04220420') + raw
    public = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], der).stdout
    return base64.urlsafe_b64encode(public[-32:]).decode().rstrip('=')


def password():
    return secrets.token_urlsafe(30)
