import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common as c
import selfsteal


class SelfStealTests(unittest.TestCase):
    def setUp(self):
        self.request = {'domain': 'entry.example.org', 'fingerprint': 'firefox',
                        'network_profile': 'filtered', 'self_steal': True}

    def test_edge_routes_new_sni_and_keeps_legacy_as_default_without_decryption(self):
        config = selfsteal.edge_configuration(self.request['domain'])
        self.assertIn('req.ssl_sni -i entry.example.org', config)
        self.assertIn('default_backend legacy', config)
        self.assertIn('amnezia-xray:443', config)
        self.assertNotIn('ssl crt', config)
        self.assertNotIn('rate-limit', config)

    def test_tls_fallbacks_and_xhttp_share_domain_but_not_internal_port(self):
        clients = [{'id': 'personal-id', 'email': 'personal@local'}]
        config = selfsteal.configuration(self.request, clients, '/route/')
        main, xhttp = config['inbounds']
        self.assertEqual(main['port'], 443)
        self.assertEqual(xhttp['port'], 18080)
        self.assertEqual(main['settings']['fallbacks'][0]['alpn'], 'h2')
        self.assertEqual(xhttp['streamSettings']['xhttpSettings']['path'], '/route/')
        self.assertEqual(clients, [{'id': 'personal-id', 'email': 'personal@local'}])
        for path in [None, '/route/']:
            client = selfsteal.tls_client('personal-id', self.request, path)
            transport = client['outbounds'][0]['streamSettings']
            self.assertEqual(transport['security'], 'tls')
            self.assertNotIn('allowInsecure', transport['tlsSettings'])
            uri = selfsteal.link('personal-id', self.request, 'personal', path)
            query = parse_qs(urlsplit(uri).query)
            self.assertEqual(query['security'], ['tls'])
            self.assertEqual(query['sni'], ['entry.example.org'])
            self.assertEqual(query['type'], ['xhttp' if path else 'tcp'])

    def test_legacy_public_port_is_replaced_by_edge_without_changing_container_port(self):
        original = {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}
        legacy = c.exposure_bindings('amnezia-xray', original, self.request)
        edge = c.exposure_bindings('vpn-edge', original, self.request)
        self.assertEqual(legacy, {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '1443'}]})
        self.assertEqual(edge, original)
        self.assertEqual(original['443/tcp'][0]['HostPort'], '443')
        both = {**original, '443/udp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}
        self.assertEqual(c.exposure_bindings('amnezia-xray', both, self.request)['443/udp'][0]['HostPort'], '1443')

    def test_new_access_export_does_not_overwrite_old_profiles(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as directory, patch.object(c, 'ROOT', Path(directory)):
            clients = [{'id': role + '-id', 'email': role + '@local'} for role in ['personal', 'shared']]
            c.write(c.ROOT / 'config/selfsteal-xray/server.json', selfsteal.configuration(self.request, clients, '/route/'))
            c.write(c.ROOT / 'config/selfsteal-hysteria/server.json', {
                'auth': {'userpass': {'personal': 'one', 'shared': 'two'}},
                'obfs': {'type': 'salamander', 'salamander': {'password': 'test'}}})
            old = c.ROOT / 'exports/personal/strings/xray.txt'
            c.write(old, 'old-profile')
            selfsteal.export_access(self.request)
            self.assertEqual(old.read_text(), 'old-profile')
            personal = json.loads((c.ROOT / 'exports/personal/configurations/selfsteal-vless.json').read_text())
            shared = json.loads((c.ROOT / 'exports/shared/configurations/selfsteal-vless.json').read_text())
            self.assertNotEqual(personal['outbounds'][0]['settings'], shared['outbounds'][0]['settings'])

    def test_partial_restoration_is_not_silently_replaced(self):
        with patch('stack.exists', side_effect=lambda name: name == 'vpn-edge'), self.assertRaises(RuntimeError):
            selfsteal.install(self.request)

    def test_addition_keeps_legacy_configuration_and_publishes_only_entry_containers(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        legacy = {'HostConfig': {'PortBindings': {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '1443'}]}},
                  'NetworkSettings': {'Networks': {'vps-stack-network': {}}}}
        with tempfile.TemporaryDirectory(dir=parent) as directory, patch.object(c, 'ROOT', Path(directory)), \
             patch('stack.exists', return_value=False), patch('stack.network'), patch('stack.image', return_value='image'), \
             patch('stack.create') as create, patch.object(c, 'docker_json', return_value=[legacy]):
            original = {'inbounds': [{'port': 443, 'protocol': 'vless', 'settings': {'clients': [{'id': 'old-id'}]},
                        'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {'serverNames': ['mask.example.org']}}}]}
            path = c.ROOT / 'config/xray/server.json'
            c.write(path, original)
            selfsteal.install(self.request)
            self.assertEqual(json.loads(path.read_text()), original)
            self.assertEqual([call.args[0] for call in create.call_args_list],
                             ['vpn-selfsteal-xray', 'vpn-selfsteal-site', 'vpn-edge', 'vpn-selfsteal-hysteria2'])
            self.assertNotIn('ports', create.call_args_list[0].kwargs)
            self.assertNotIn('ports', create.call_args_list[1].kwargs)
            index = c.ROOT / 'config/selfsteal-site/index.html'
            self.assertIn('<title>Welcome</title>', index.read_text())
            if os.name != 'nt':
                self.assertEqual(index.stat().st_mode & 0o444, 0o444)


if __name__ == '__main__':
    unittest.main()
