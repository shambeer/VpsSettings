import base64
import datetime
import ipaddress
import hashlib
import json
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from vps_migration.core import common as c

API = 'https://api.cloudflareclient.com/v0a4005/reg'


def key(value):
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError('Некорректный ключ WireGuard WARP')
    return value


def outbound(registration):
    config = registration['config']
    addresses = config['interface']['addresses']
    local = [str(ipaddress.ip_interface(addresses['v4'] + '/32'))]
    if addresses.get('v6'):
        local.append(str(ipaddress.ip_interface(addresses['v6'] + '/128')))
    peer = config['peers'][0]
    endpoint = peer['endpoint']['host']
    parsed = urlsplit('//' + endpoint)
    if not parsed.hostname or parsed.username or parsed.password or not parsed.port or parsed.path:
        raise ValueError('Некорректный endpoint WARP')
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        c.validate_domain(parsed.hostname)
    else:
        if not address.is_global:
            raise ValueError('Endpoint WARP должен быть публичным')
    reserved = list(base64.b64decode(config['client_id'], validate=True))
    if len(reserved) != 3:
        raise ValueError('Некорректный client_id WARP')
    return {'tag': 'selfsteal-warp-out', 'protocol': 'wireguard', 'settings': {
        'secretKey': key(registration['private_key']), 'address': local,
        'peers': [{'publicKey': key(peer['public_key']), 'endpoint': endpoint,
                   'allowedIPs': ['0.0.0.0/0', '::/0'], 'keepAlive': 25}],
        'reserved': reserved, 'mtu': 1280, 'noKernelTun': True}}


def register(request):
    if request.get('warp_terms_accepted') is not True:
        raise RuntimeError('Не подтверждена регистрация WARP и условия Cloudflare')
    directory = c.ROOT / 'config/selfsteal-features'
    node = hashlib.sha256(c.validate_ip(request['ip']).encode()).hexdigest()[:16]
    path = directory / ('warp-' + node + '.json')
    if path.exists():
        registration = json.loads(path.read_text())
        if registration.get('status') != 'ready':
            raise RuntimeError('Регистрация WARP была прервана; автоматическая повторная регистрация запрещена')
        return outbound(registration)
    private, public = c.x25519_pair()
    private = base64.b64encode(base64.urlsafe_b64decode(private + '=' * (-len(private) % 4))).decode()
    public = base64.b64encode(base64.urlsafe_b64decode(public + '=' * (-len(public) % 4))).decode()
    c.write(path, {'status': 'pending', 'private_key': private})
    body = {'key': public, 'tos': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            'type': 'PC', 'model': 'x-ui', 'name': 'VpsMigration'}
    message = Request(API, data=json.dumps(body).encode(), headers={
        'Content-Type': 'application/json', 'CF-Client-Version': 'a-6.30-3596'}, method='POST')
    try:
        with urlopen(message, timeout=40) as response:
            raw = response.read(2 * 1024 ** 2 + 1)
        if len(raw) > 2 * 1024 ** 2:
            raise ValueError('Ответ WARP слишком большой')
        result = json.loads(raw)
        registration = {'status': 'ready', 'private_key': private, 'config': result['config'],
                        'device_id': result['id'], 'access_token': result['token']}
        result = outbound(registration)
        c.write(path, registration)
        return result
    except Exception as error:
        raise RuntimeError('Не удалось зарегистрировать/проверить WARP; данные попытки сохранены приватно, прямого обхода WARP не будет') from error
