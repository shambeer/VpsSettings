import base64
import json
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vps_migration.core import common as c


def canonical(uri):
    value = urlsplit(uri)
    return urlunsplit((value.scheme, value.netloc, value.path,
                      urlencode(sorted(parse_qsl(value.query, keep_blank_values=True))), ''))


def routing(options):
    result = {'Name': 'Self-Steal', 'GlobalProxy': 'true', 'UseChunkFiles': 'true',
        'RemoteDns': '1.1.1.1', 'RemoteDNSType': 'DoH', 'RemoteDNSDomain': 'https://1.1.1.1/dns-query',
        'DomesticDns': '1.1.1.1', 'DomesticDNSType': 'DoH', 'DomesticDNSDomain': 'https://1.1.1.1/dns-query',
        'RouteOrder': 'block-proxy-direct', 'DirectSites': ['geosite:private', *['domain:' + domain for domain in options['direct_domains']]],
        'DirectIp': ['geoip:private', *options['direct_networks']], 'ProxySites': [], 'ProxyIp': [],
        'BlockSites': [], 'BlockIp': [], 'DomainStrategy': 'IPIfNonMatch', 'FakeDNS': 'false'}
    if options['guide_whitelist']:
        result['Geositeurl'] = 'https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite@202610120948/release/geosite.dat'
        result['Geoipurl'] = 'https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip@202611231224/release/geoip.dat'
        result['DirectSites'].append('geosite:whitelist')
        result['DirectIp'].append('geoip:whitelist')
    return result


def export(request, state, options):
    locations = []
    for role in ['personal', 'shared']:
        token = state.setdefault('subscription_tokens', {}).setdefault(role, secrets.token_hex(32))
        links, seen = [], set()
        directory = c.ROOT / 'exports' / role
        for path in sorted((directory / 'strings').glob('*.txt')):
            for line in path.read_text().splitlines():
                if not line.startswith(('vless://', 'hysteria2://', 'ss://')):
                    continue
                normalized = canonical(line)
                if normalized not in seen:
                    links.append(line)
                    seen.add(normalized)
        if not links:
            raise RuntimeError('Нельзя опубликовать пустую подписку')
        content = base64.b64encode(('\n'.join(links) + '\n').encode()).decode()
        c.write(directory / 'subscriptions/links.txt', '\n'.join(links) + '\n')
        c.write(directory / 'subscriptions/base64.txt', content + '\n')
        url = 'https://' + request['domain'] + ':' + str(c.selfsteal_port(request)) + '/sub/' + token
        c.export_access(role, 'subscription', link=url)
        profile = routing(options)
        encoded = base64.b64encode(json.dumps(profile, separators=(',', ':')).encode()).decode()
        for application in ['happ', 'incy']:
            c.write(directory / ('subscriptions/' + application + '-routing.json'), profile)
            c.write(directory / ('subscriptions/' + application + '-routing.txt'), application + '://routing/onadd/' + encoded + '\n')
        chunks = [content[index:index + 1800] for index in range(0, len(content), 1800)]
        location = 'location = /sub/' + token + ' { access_log off; default_type text/plain; '
        for index, chunk in enumerate(chunks):
            location += 'set $sub_' + role + '_' + str(index) + ' "' + chunk + '"; '
        location += 'return 200 "' + ''.join('$sub_' + role + '_' + str(index) for index in range(len(chunks))) + '"; }\n'
        locations.append(location)
    return ''.join(locations)


def verify(request):
    state = json.loads((c.ROOT / 'config/selfsteal-features/state.json').read_text())
    for role in ['personal', 'shared']:
        token = state['subscription_tokens'][role]
        url = 'https://' + request['domain'] + ':' + str(c.selfsteal_port(request)) + '/sub/' + token
        response = c.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '30', '--config', '-'],
                         content=('url = "' + url + '"\n').encode(), timeout=40).stdout.strip()
        expected = (c.ROOT / 'exports' / role / 'subscriptions/base64.txt').read_bytes().strip()
        if response != expected:
            raise RuntimeError('HTTPS-подписка не прошла проверку для роли ' + role)
