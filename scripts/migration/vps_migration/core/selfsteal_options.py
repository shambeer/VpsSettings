import copy
import re

DEFAULT_XHTTP = {
    'mode': 'packet-up', 'xPaddingBytes': '4-10', 'xPaddingObfsMode': True,
    'xPaddingKey': '_token', 'xPaddingHeader': 'X-Client-Version', 'xPaddingPlacement': 'query',
    'xPaddingMethod': 'tokenish', 'sessionIDPlacement': 'path', 'sessionIDKey': 'sid',
    'sessionIDLength': '16-24', 'seqPlacement': 'query', 'seqKey': 'offset',
    'uplinkDataPlacement': 'body', 'uplinkDataKey': '', 'scMaxEachPostBytes': '500000-1000000',
    'noSSEHeader': False, 'scMaxBufferedPosts': 50, 'scStreamUpServerSecs': '20-80',
    'serverMaxHeaderBytes': 0, 'uplinkHTTPMethod': 'GET', 'headers': {},
    'scMinPostsIntervalMs': '50-150', 'uplinkChunkSize': 0, 'noGRPCHeader': False,
    'xmux': {'maxConcurrency': '16-32', 'maxConnections': 0, 'cMaxReuseTimes': 0,
             'hMaxRequestTimes': '300-600', 'hMaxReusableSecs': '900-1800', 'hKeepAlivePeriod': 0},
}


def validate(value=None):
    value = copy.deepcopy({} if value is None else value)
    if not isinstance(value, dict):
        raise ValueError('Настройки Self-Steal должны быть JSON-объектом')
    allowed = {'sub_store', 'warp', 'reality', 'subscriptions', 'xhttp', 'warp_path', 'site_directory',
               'additional_domains', 'direct_domains', 'direct_networks', 'guide_whitelist', 'tls_port', 'reality_port'}
    if set(value) - allowed:
        raise ValueError('Неизвестная настройка Self-Steal')
    result = {'sub_store': False, 'warp': True, 'reality': True, 'subscriptions': True, 'guide_whitelist': False,
              'additional_domains': [], 'direct_domains': [], 'direct_networks': []}
    result.update(value)
    for key in ['sub_store', 'warp', 'reality', 'subscriptions', 'guide_whitelist']:
        if not isinstance(result[key], bool):
            raise ValueError('Настройка ' + key + ' должна быть true/false')
    if result['sub_store'] and not result['subscriptions']:
        raise ValueError('Sub-Store требует включённых subscriptions')
    xhttp = value.get('xhttp', {})
    if not isinstance(xhttp, dict) or set(xhttp) - (set(DEFAULT_XHTTP) | {'path', 'sessionIDTable'}):
        raise ValueError('Неизвестный параметр XHTTP')
    result['xhttp'] = {**copy.deepcopy(DEFAULT_XHTTP), **xhttp}
    if result['xhttp']['mode'] != 'packet-up':
        raise ValueError('Проксирование через Nginx рассчитано на packet-up')
    for name in ['tls_port', 'reality_port']:
        if name in result and (not isinstance(result[name], int) or isinstance(result[name], bool) or not 1024 <= result[name] <= 65535 or result[name] in {2053, 6659, 50553, 46872, 1194, 2443, 8388, 8389, 51820}):
            raise ValueError('Нужен порт от 1024 до 65535, не занятый установленным набором VPN/панелей')
    xmux = result['xhttp'].get('xmux')
    if not isinstance(xmux, dict) or set(xmux) - set(DEFAULT_XHTTP['xmux']):
        raise ValueError('Некорректные параметры XMUX')
    result['xhttp']['xmux'] = {**copy.deepcopy(DEFAULT_XHTTP['xmux']), **xmux}
    headers = result['xhttp'].get('headers')
    if not isinstance(headers, dict) or any(not isinstance(key, str) or not isinstance(value, str) or '\n' in key + value or '\r' in key + value for key, value in headers.items()):
        raise ValueError('Недопустимые заголовки XHTTP')
    for key, item in result['xhttp'].items():
        if isinstance(item, str) and (len(item) > 1024 or any(char in item for char in ['\r', '\n', '\0'])):
            raise ValueError('Недопустимый параметр XHTTP: ' + key)
    for path in [result.get('warp_path'), result['xhttp'].get('path')]:
        if path is not None and not re.fullmatch(r'/[A-Za-z0-9_./-]{1,160}/?', path):
            raise ValueError('Путь транспорта должен начинаться с / и не содержать специальных символов')
        if path and ('..' in path or '//' in path):
            raise ValueError('Переходы .. в пути запрещены')
    for key in ['additional_domains', 'direct_domains', 'direct_networks']:
        if not isinstance(result[key], list) or len(result[key]) > 100:
            raise ValueError('Недопустимый список ' + key)
    from vps_migration.core import common as c
    import ipaddress
    result['additional_domains'] = [c.validate_domain(item) for item in result['additional_domains']]
    result['direct_domains'] = [c.validate_domain(item) for item in result['direct_domains']]
    result['direct_networks'] = [str(ipaddress.ip_network(item, strict=True)) for item in result['direct_networks']]
    if result.get('site_directory') is not None and not isinstance(result['site_directory'], str):
        raise ValueError('site_directory должен содержать путь к папке')
    return result
