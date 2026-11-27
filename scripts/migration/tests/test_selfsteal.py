import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.server import selfsteal


class SelfStealTests(unittest.TestCase):
    def setUp(self):
        self.request = {'domain': 'entry.example.org', 'fingerprint': 'firefox',
                        'network_profile': 'filtered', 'self_steal': True}

    def test_edge_serves_only_new_transports_without_intercepting_amnezia(self):
        config = selfsteal.edge_configuration(self.request['domain'])
        self.assertIn('default_backend selfsteal', config)
        self.assertNotIn('amnezia-xray', config)
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
            self.assertEqual(urlsplit(uri).port, 8443)
            self.assertEqual(client['outbounds'][0]['settings']['vnext'][0]['port'], 8443)
            self.assertEqual(query['security'], ['tls'])
            self.assertEqual(query['sni'], ['entry.example.org'])
            self.assertEqual(query['type'], ['xhttp' if path else 'tcp'])

    def test_amnezia_keeps_public_port_and_new_entry_uses_separate_port(self):
        original = {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}
        legacy = c.exposure_bindings('amnezia-xray', original, self.request)
        edge = c.exposure_bindings('vpn-edge', original, self.request)
        self.assertEqual(legacy, original)
        self.assertEqual(edge['443/tcp'][0]['HostPort'], '8443')
        self.assertEqual(original['443/tcp'][0]['HostPort'], '443')
        both = {**original, '443/udp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}
        self.assertEqual(c.exposure_bindings('amnezia-xray', both, {**self.request, 'network_profile': 'all'}), both)

    def test_old_shared_edge_restores_direct_amnezia_entry(self):
        original = {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '1443'}]}
        restored = c.exposure_bindings('amnezia-xray', original, {**self.request, 'restore_shared_edge': True})
        self.assertEqual(restored['443/tcp'], [{'HostIp': '0.0.0.0', 'HostPort': '443'}])
        self.assertEqual(original['443/tcp'][0]['HostPort'], '1443')

    def test_new_install_does_not_add_second_hysteria(self):
        with patch.object(selfsteal.stack, 'exists', return_value=False), \
             patch.object(selfsteal.stack, 'tools_image', return_value='tools'), \
             patch.object(selfsteal.stack, 'wireguard'), patch.object(selfsteal.stack, 'openvpn'), \
             patch.object(selfsteal.stack, 'shadowsocks'), patch.object(selfsteal.stack, 'hysteria') as create:
            selfsteal.stack.reserves(self.request)
            create.assert_not_called()
        with patch.object(selfsteal.stack, 'exists', return_value=False), \
             patch.object(selfsteal.stack, 'tools_image', return_value='tools'), \
             patch.object(selfsteal.stack, 'wireguard'), patch.object(selfsteal.stack, 'openvpn'), \
             patch.object(selfsteal.stack, 'shadowsocks'), patch.object(selfsteal.stack, 'hysteria') as create:
            selfsteal.stack.reserves({**self.request, 'self_steal': False})
            create.assert_called_once()

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

    def test_existing_full_scheme_exports_without_creating_duplicates(self):
        with patch.object(selfsteal.stack, 'exists', return_value=True), \
             patch.object(selfsteal, 'export_access') as export, patch.object(selfsteal.stack, 'create') as create:
            selfsteal.install(self.request)
            export.assert_called_once_with(self.request)
            create.assert_not_called()

    def test_partial_restoration_is_not_silently_replaced(self):
        with patch('vps_migration.server.stack.exists', side_effect=lambda name: name == 'vpn-edge'), self.assertRaises(RuntimeError):
            selfsteal.install(self.request)

    def test_addition_keeps_legacy_configuration_and_publishes_only_entry_containers(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        legacy = {'HostConfig': {'PortBindings': {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}},
                  'NetworkSettings': {'Networks': {'vps-stack-network': {}}}}
        with tempfile.TemporaryDirectory(dir=parent) as directory, patch.object(c, 'ROOT', Path(directory)), \
             patch('vps_migration.server.stack.exists', return_value=False), patch('vps_migration.server.stack.network'), patch('vps_migration.server.stack.image', return_value='image'), \
             patch('vps_migration.server.stack.create') as create, patch.object(c, 'docker_json', return_value=[legacy]) as inspect:
            original = {'inbounds': [{'port': 443, 'protocol': 'vless', 'settings': {'clients': [{'id': 'old-id'}]},
                        'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {'serverNames': [self.request['domain']]}}}]}
            path = c.ROOT / 'config/xray/server.json'
            c.write(path, original)
            selfsteal.install(self.request)
            self.assertEqual(json.loads(path.read_text()), original)
            inspect.assert_not_called()
            self.assertEqual(create.call_args_list[2].kwargs['ports']['443/tcp'][0][1], 8443)
            self.assertEqual(create.call_args_list[3].args[3]['443/udp'][0][1], 8443)
            self.assertEqual([call.args[0] for call in create.call_args_list],
                             ['vpn-selfsteal-xray', 'vpn-selfsteal-site', 'vpn-edge', 'vpn-selfsteal-hysteria2'])
            self.assertNotIn('ports', create.call_args_list[0].kwargs)
            self.assertFalse(create.call_args_list[1].kwargs.get('ports'))
            index = c.ROOT / 'config/selfsteal-site/index.html'
            self.assertIn('<title>Welcome</title>', index.read_text())
            if os.name != 'nt':
                self.assertEqual(index.stat().st_mode & 0o444, 0o444)


if __name__ == '__main__':
    unittest.main()
