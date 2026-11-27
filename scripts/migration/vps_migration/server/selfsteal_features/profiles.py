import copy
from urllib.parse import urlencode, quote

from vps_migration.core import common as c


def client(identifier, request, kind, state, xhttp):
    reality = kind.startswith('reality')
    warp = kind.endswith('warp')
    split_http = kind.endswith('xhttp')
    port = c.selfsteal_reality_port(request) if reality else c.selfsteal_port(request)
    stream = {'network': 'xhttp' if split_http else 'tcp', 'security': 'reality' if reality else 'tls'}
    if reality:
        stream['realitySettings'] = {'serverName': request['domain'], 'fingerprint': c.fingerprint(request),
                                     'publicKey': state['public_key'], 'shortId': state['short_id']}
    else:
        stream['tlsSettings'] = {'serverName': request['domain'], 'fingerprint': c.fingerprint(request)}
    user = {'id': identifier, 'encryption': 'none'}
    if split_http:
        stream['xhttpSettings'] = copy.deepcopy(xhttp)
    elif warp:
        stream['tcpSettings'] = {'header': {'type': 'http', 'request': {
            'version': '1.1', 'method': 'GET', 'path': [state['warp_path']],
            'headers': {'Host': [request['domain']]}}}}
    else:
        user['flow'] = 'xtls-rprx-vision'
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 10808,
        'protocol': 'socks', 'settings': {'udp': True}}], 'outbounds': [{'protocol': 'vless',
        'settings': {'vnext': [{'address': request['domain'], 'port': port, 'users': [user]}]},
        'streamSettings': stream}]}


def uri(identifier, request, role, kind, state, xhttp):
    config = client(identifier, request, kind, state, xhttp)['outbounds'][0]
    stream = config['streamSettings']
    peer = config['settings']['vnext'][0]
    query = {'encryption': 'none', 'security': stream['security'], 'sni': request['domain'],
             'fp': c.fingerprint(request), 'type': stream['network']}
    if stream['security'] == 'reality':
        query.update(pbk=state['public_key'], sid=state['short_id'])
    if kind.endswith('xhttp'):
        import json
        extra = {key: value for key, value in xhttp.items() if key not in ['path', 'mode', 'host']}
        query.update(path=xhttp['path'], mode=xhttp['mode'], extra=json.dumps(extra, separators=(',', ':')))
    elif kind.endswith('warp'):
        query.update(headerType='http', path=state['warp_path'], host=request['domain'])
    else:
        query['flow'] = 'xtls-rprx-vision'
    return 'vless://' + identifier + '@' + request['domain'] + ':' + str(peer['port']) + '?' + urlencode(query) + '#' + quote('SelfSteal-' + kind + '-' + role)


def export(request, config, state):
    xhttp = next(item for item in config['inbounds'] if item['tag'] == 'selfsteal-xhttp')['streamSettings']['xhttpSettings']
    clients = config['inbounds'][0]['settings']['clients']
    kinds = [('tls', 'selfsteal-vless'), ('tls-xhttp', 'selfsteal-xhttp')]
    if state['warp']:
        kinds.append(('tls-warp', 'selfsteal-warp'))
    if state['reality']:
        kinds.extend([('reality', 'selfsteal-reality'), ('reality-xhttp', 'selfsteal-reality-xhttp')])
        if state['warp']:
            kinds.append(('reality-warp', 'selfsteal-reality-warp'))
    for item in clients:
        role = item['email'].split('@', 1)[0]
        if role not in ['personal', 'shared']:
            raise RuntimeError('Неизвестная роль доступа')
        for kind, name in kinds:
            c.export_access(role, name, client(item['id'], request, kind, state, xhttp),
                            uri(item['id'], request, role, kind, state, xhttp))


def checks(request):
    result = ['selfsteal-vless', 'selfsteal-xhttp', 'selfsteal-hysteria2']
    if request.get('full_selfsteal'):
        options = request.get('selfsteal_options', {})
        if options.get('warp', True):
            result.append('selfsteal-warp')
        if options.get('reality', True):
            result.extend(['selfsteal-reality', 'selfsteal-reality-xhttp'])
            if options.get('warp', True):
                result.append('selfsteal-reality-warp')
    return result
