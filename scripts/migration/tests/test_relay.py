import io
import json
from pathlib import Path
import shlex
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.server import relay
from vps_migration.cli import topology
from vps_migration.cli import console as ui
from vps_migration.server import worker as remote


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.request = {'ip': '1.1.1.1', 'origin_ip': '8.8.8.8', 'network_profile': 'all'}

    def test_nat_preserves_old_ports_and_adds_tcp_udp_443_without_ssh(self):
        rules = relay.rules(self.request)
        forwarded = {(args[args.index('-p') + 1], args[args.index('--dport') + 1])
                     for table, chain, args in rules if chain == 'VPS_RELAY_IN'}
        self.assertIn(('tcp', '443'), forwarded)
        self.assertIn(('udp', '443'), forwarded)
        self.assertIn(('udp', '46872'), forwarded)
        self.assertIn(('tcp', '50553'), forwarded)
        self.assertNotIn(('tcp', '22'), forwarded)
        self.assertNotIn(('tcp', '2053'), forwarded)
        for table, chain, args in rules:
            if chain == 'VPS_RELAY_IN':
                self.assertEqual(args[args.index('-d') + 1], self.request['ip'])
            if chain == 'VPS_RELAY_OUT':
                self.assertIn('DNAT', args)
                self.assertIn('SNAT', args)
                self.assertEqual(args[-1], self.request['ip'])

    def test_public_address_must_be_assigned_before_nat_is_configured(self):
        interfaces = [{'addr_info': [{'family': 'inet', 'local': '1.1.1.1'}]}]
        with patch.object(c, 'run', return_value=SimpleNamespace(stdout=json.dumps(interfaces).encode())):
            relay.assert_local_public_ip('1.1.1.1')
            with self.assertRaises(RuntimeError):
                relay.assert_local_public_ip('8.8.8.8')

    def test_filtered_nat_exposes_only_acme_and_new_vpn_ports(self):
        rules = relay.rules({**self.request, 'network_profile': 'filtered', 'self_steal': True})
        incoming = [args for table, chain, args in rules if chain == 'VPS_RELAY_IN']
        self.assertEqual(len(incoming), 4)
        self.assertEqual({args[args.index('--dport') + 1] for args in incoming}, {'80', '443', '8443'})

    def test_additional_backup_ports_are_validated(self):
        selected = dict(relay.selected_ports({**self.request, 'extra_tcp_ports': [12345]}))
        self.assertIn(12345, selected['tcp'])
        with self.assertRaises(ValueError):
            relay.selected_ports({**self.request, 'extra_tcp_ports': ['22;id']})

    def test_bundle_inspection_preserves_custom_ports_and_excludes_loopback_admin(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        manifest = {'format': 1, 'containers': [{'Name': '/3x-ui', 'HostConfig': {
            'NetworkMode': 'bridge', 'PortBindings': {
                '2053/tcp': [{'HostPort': '2053', 'HostIp': '0.0.0.0'}],
                '12345/tcp': [{'HostPort': '12345', 'HostIp': '0.0.0.0'}],
                '12346/udp': [{'HostPort': '12346', 'HostIp': '127.0.0.1'}]}}}]}
        with tempfile.TemporaryDirectory(dir=parent) as directory:
            bundle = Path(directory) / 'bundle.tar.gz'
            content = json.dumps(manifest).encode()
            with tarfile.open(bundle, 'w:gz') as archive:
                member = tarfile.TarInfo('manifest.json')
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            with patch('sys.stdout', new_callable=io.StringIO):
                settings = topology.bundle_settings(bundle, {'self_steal': True})
            self.assertEqual(settings['extra_tcp_ports'], [12345])
            self.assertEqual(settings['extra_udp_ports'], [])

    def test_apply_is_idempotent_and_never_flushes_unmanaged_chains(self):
        with patch.object(c, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            relay.apply(self.request)
        commands = [call.args[0] for call in run.call_args_list]
        for command in commands:
            if '-F' in command:
                self.assertTrue(command[command.index('-F') + 1].startswith('VPS_RELAY_'))
        self.assertFalse(any('-I' in command for command in commands))

    def test_origin_gate_matches_original_destination_and_preserves_other_docker_traffic(self):
        script = relay.origin_gate_script({'ip': '8.8.8.8', 'relay_ip': '1.1.1.1'}, 'eth0')
        self.assertIn('--ctorigdst 8.8.8.8', script)
        self.assertIn('--ctorigdstport 443', script)
        for line in script.splitlines():
            args = shlex.split(line)
            if 'DROP' in args:
                self.assertIn('1.1.1.1', args)
                self.assertIn('!', args)
                self.assertIn('eth0', args)
            if '-F' in args:
                self.assertEqual(args[-1], 'VPS_ORIGIN_GATE')
        self.assertIn('-A VPS_ORIGIN_GATE -j RETURN', script)
        with self.assertRaises(ValueError):
            relay.origin_gate_script({'ip': '8.8.8.8', 'relay_ip': '1.1.1.1'}, 'eth0;id')

    def test_bundle_new_ports_do_not_displace_amnezia_or_drift_on_restore(self):
        import tarfile
        import tempfile
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        for existing, expected in [(None, 8444), (8445, 8445)]:
            containers = [{'Name': '/amnezia-xray', 'HostConfig': {'NetworkMode': 'bridge',
                'PortBindings': {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8443'}]}}}]
            if existing:
                containers.append({'Name': '/vpn-edge', 'HostConfig': {'NetworkMode': 'bridge',
                    'PortBindings': {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': str(existing)}]}}})
            with tempfile.TemporaryDirectory(dir=parent) as folder:
                manifest = Path(folder) / 'manifest.json'
                manifest.write_text(json.dumps({'format': 1, 'containers': containers}))
                bundle = Path(folder) / 'bundle.tar.gz'
                with tarfile.open(bundle, 'w:gz') as archive:
                    archive.add(manifest, arcname='manifest.json')
                with patch('sys.stdout', new_callable=io.StringIO):
                    settings = topology.bundle_settings(bundle, {'self_steal': True})
                self.assertEqual(settings['selfsteal_port'], expected)
                self.assertEqual(settings['extra_tcp_ports'], [8443])
                self.assertEqual(settings['restore_shared_edge'], bool(existing))

    def test_topology_rejects_same_server_and_keeps_keys_local(self):
        target = SimpleNamespace(address='8.8.8.8', port=22)
        with patch('sys.stdout', new_callable=io.StringIO), self.assertRaises(ValueError):
            topology.choose(lambda prompt: target, lambda *args: '2', target)
        entry = SimpleNamespace(address='1.1.1.1', port=2222, key='local-secret-path')
        with patch('sys.stdout', new_callable=io.StringIO):
            scheme, selected = topology.choose(lambda prompt: entry, lambda *args: '2', target)
        request = topology.relay_request(selected, target, {'domain': 'entry.example.org', **scheme})
        self.assertEqual(request['origin_ip'], '8.8.8.8')
        self.assertEqual(request['ip'], '1.1.1.1')
        self.assertNotIn('key', request)

    def test_single_server_mode_never_requests_relay_access(self):
        connect = Mock()
        with patch('sys.stdout', new_callable=io.StringIO):
            scheme, entry = topology.choose(connect, lambda *args: '1', SimpleNamespace(address='8.8.8.8'))
        connect.assert_not_called()
        self.assertIsNone(entry)
        self.assertTrue(scheme['self_steal'])

    def test_menu_retries_wrong_choice_without_losing_previous_fields(self):
        read = Mock(side_effect=['not-a-number', '2'])
        with patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(ui.select('Mode', ['1', '2'], '2', read), '2')
        self.assertEqual(read.call_count, 2)

    def test_origin_firewall_uses_relay_source_and_docker_gate(self):
        request = {'ip': '8.8.8.8', 'relay_ip': '1.1.1.1', 'self_steal': True,
                   'network_profile': 'filtered', 'ssh_port': 22}
        with patch.object(c, 'write'), patch.object(c, 'run') as run, patch.object(relay, 'install_origin_gate') as gate, patch.dict(remote.os.environ, {'SSH_CONNECTION': ''}):
            remote.firewall(request)
        gate.assert_called_once_with(request)
        allowed = [call.args[0] for call in run.call_args_list if call.args[0][:2] == ['ufw', 'allow']]
        self.assertIn(['ufw', 'allow', '22/tcp'], allowed)
        self.assertTrue(all('1.1.1.1' in command for command in allowed if command != ['ufw', 'allow', '22/tcp']))


if __name__ == '__main__':
    unittest.main()
