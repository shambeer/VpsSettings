import base64
from contextlib import closing
import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.cli import wizard as migrate
from vps_migration.server import worker as remote
from vps_migration.server import snapshot
from vps_migration.server import stack
from vps_migration.packaging import portable
from vps_migration.packaging import build as build_portable


class MigrationTests(unittest.TestCase):
    def test_low_memory_requires_explicit_opt_in_and_real_swap(self):
        host = 'MemTotal: 1079628 kB\nSwapTotal: 2097148 kB\n'
        with self.assertRaises(RuntimeError):
            remote.validate_memory({}, host)
        remote.validate_memory({'low_memory': True}, host)
        with self.assertRaises(RuntimeError):
            remote.validate_memory({'low_memory': True}, 'MemTotal: 1079628 kB\nSwapTotal: 0 kB\n')
        with self.assertRaises(RuntimeError):
            remote.validate_memory({'low_memory': True}, 'MemTotal: 524288 kB\nSwapTotal: 4194304 kB\n')
        remote.validate_memory({}, 'MemTotal: 2097148 kB\nSwapTotal: 0 kB\n')

    def test_panels_save_access_before_startup_and_allow_postgres_parent_traversal(self):
        events = []
        original_chmod = Path.chmod
        def chmod(path, mode, *args, **kwargs):
            events.append((path, mode))
            return original_chmod(path, mode, *args, **kwargs)
        def create(name, *args, **kwargs):
            self.assertTrue((self.directory / 'exports/admin/panels.json').is_file())
            if name == '3dp-postgres':
                self.assertIn((self.directory / 'config/postgres', 0o755), events)
                self.assertEqual(kwargs['mounts'][0]['Target'], '/var/lib/postgresql')
        with patch.object(c, 'ROOT', self.directory), patch.object(c, 'password', return_value='TEST-ONLY'), \
             patch.object(stack, 'image', return_value='test-image'), patch.object(stack, 'create', side_effect=create), \
             patch.object(stack, 'wait_xui_user'), patch.object(c, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'')), \
             patch.object(Path, 'chmod', chmod):
            stack.panels({'domain': 'entry.example.org'})

    def test_output_directory_choices_keep_backups_in_separate_operation_folders(self):
        for choice, folder in [('1', 'Desktop'), ('2', 'Documents'), ('3', 'Custom')]:
            base = self.directory / folder
            with patch.object(migrate, 'ask', side_effect=[choice, '"' + str(base) + '"']), patch.object(migrate, 'user_folder', return_value=base) as known_folder, patch('sys.stdout', new_callable=io.StringIO):
                output = migrate.choose_output_directory('operation-id')
            self.assertEqual(output, base / 'VpsMigration/operation-id')
            self.assertTrue(output.is_dir())
            if choice != '3':
                known_folder.assert_called_once_with(folder)
        with patch.object(migrate, 'ask', side_effect=['4', '2']), patch.object(migrate, 'user_folder', return_value=self.directory / 'retry'), patch('sys.stdout', new_callable=io.StringIO):
            output = migrate.choose_output_directory('retry-choice')
        self.assertTrue(output.is_dir())

    def test_prompts_explain_waiting_defaults_and_retry_required_input(self):
        with patch('builtins.input', side_effect=['', 'answer']), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(migrate.ask('Required'), 'answer')
        self.assertIn('[ОЖИДАНИЕ ВВОДА]', output.getvalue())
        self.assertIn('Поле обязательно', output.getvalue())
        with patch('builtins.input', return_value=''), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(migrate.ask('Mode', '2'), '2')
        self.assertIn('Enter без ввода: 2', output.getvalue())
        with patch('builtins.input', return_value=''), patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(migrate.ask('Optional', ''), '')

    def test_quoted_local_paths(self):
        path = Path(__file__).resolve()
        for value in [str(path), '"' + str(path) + '"', "'" + str(path) + "'"]:
            self.assertEqual(migrate.local_path(value), path)

    def test_kernel_modules_are_not_copied_between_kernels(self):
        containers = [{'Mounts': [{'Type': 'bind', 'Source': '/lib/modules'},
                                  {'Type': 'bind', 'Source': '/usr/lib/modules'}]}]
        with patch.object(Path, 'exists', return_value=False):
            self.assertEqual(snapshot.host_roots(containers), [])
        containers[0]['Mounts'].append({'Type': 'bind', 'Source': '/etc/shadow'})
        with patch.object(Path, 'exists', return_value=False), self.assertRaises(RuntimeError):
            snapshot.host_roots(containers)

    def setUp(self):
        self.repository = Path(__file__).resolve().parents[3]
        parent = self.repository / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.directory = Path(self.temporary.name).resolve()
        self.assertTrue(self.directory.is_relative_to(self.repository.resolve()))

    def tearDown(self):
        self.assertTrue(self.directory.is_relative_to((self.repository / 'private-vpn').resolve()))
        self.temporary.cleanup()

    def test_filtered_bindings_are_private_without_mutating_source(self):
        bindings = {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}, {'HostIp': '::', 'HostPort': '443'}]}
        self.assertEqual(c.exposure_bindings('amnezia-xray', bindings, {'network_profile': 'filtered'}),
                         {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]})
        self.assertEqual(c.exposure_bindings('other', bindings, {'network_profile': 'filtered'})['443/tcp'],
                         [{'HostIp': '127.0.0.1', 'HostPort': '443'}])
        self.assertEqual(len(bindings['443/tcp']), 2)
        self.assertEqual(c.exposure_bindings('other', bindings, {}), bindings)
        with self.assertRaises(ValueError):
            c.exposure_bindings('amnezia-xray', {}, {'network_profile': 'filtered'})

    def test_selected_fingerprint_reaches_both_exports(self):
        reality = {'publicKey': 'key', 'shortId': 'abcd', 'serverName': 'mask.example.org', 'fingerprint': 'safari'}
        self.assertEqual(parse_qs(urlsplit(c.vless_link('id', 'vpn.example.org', 443, reality, 'test')).query)['fp'], ['safari'])
        self.assertEqual(c.xray_client('id', 'vpn.example.org', 443, reality)['outbounds'][0]['streamSettings']['realitySettings']['fingerprint'], 'safari')
        with self.assertRaises(ValueError):
            c.fingerprint({'fingerprint': 'random'})

    def test_camouflage_requires_verified_tls13_h2(self):
        request = {'domain': 'vpn.example.org', 'ip': '8.8.8.8', 'camouflage': 'mask.example.org'}
        with patch.object(remote.socket, 'getaddrinfo', return_value=[(None, None, None, None, ('1.1.1.1', 443))]), patch.object(c, 'JOB', None):
            for output, accepted in [(b'TLSv1.3 ALPN protocol: h2\n', True), (b'TLSv1.3 ALPN protocol: http/1.1\n', False), (b'TLSv1.2 ALPN protocol: h2\n', False)]:
                with patch.object(c, 'run', return_value=SimpleNamespace(returncode=0, stdout=output, stderr=b'')) as run:
                    if accepted:
                        remote.check_camouflage(request)
                        self.assertIn('-verify_return_error', run.call_args.args[0])
                        self.assertIn('-4', run.call_args.args[0])
                    else:
                        with self.assertRaises(RuntimeError):
                            remote.check_camouflage(request)
        with self.assertRaises(RuntimeError):
            remote.check_camouflage(request, domain=request['domain'])

    def test_filtered_firewall_exposes_only_main_vpn_ssh_and_acme(self):
        with patch.object(c, 'write'), patch.object(c, 'run') as run, patch.dict(remote.os.environ, {'SSH_CONNECTION': ''}):
            remote.firewall({'network_profile': 'filtered', 'ssh_port': 2222})
        allowed = [call.args[0][2] for call in run.call_args_list if call.args[0][:2] == ['ufw', 'allow']]
        self.assertEqual(allowed, ['2222/tcp', '80/tcp', '443/tcp'])

    def test_private_panel_route_preserves_basepath_and_external_nodes(self):
        manifest = {'source_ip': '1.1.1.1', 'source_domain': 'old.example.org', 'containers': [
            {'Name': '/3x-ui', 'HostConfig': {'PortBindings': {'2053/tcp': [{'HostPort': '2053'}]}}}]}
        request = {'ip': '8.8.8.8', 'domain': 'vpn.example.org', 'network_profile': 'filtered'}
        self.assertEqual(remote.private_panel_url('http://old.example.org:2053/base/?x=1', manifest, request), 'http://3x-ui:2053/base/?x=1')
        outside = 'https://external.example.org:2053/base/'
        self.assertEqual(remote.private_panel_url(outside, manifest, request), outside)
        with self.assertRaises(RuntimeError):
            remote.private_panel_url('https://old.example.org:2053/base/', manifest, request)

    def test_filtered_restore_rejects_host_network_before_creation(self):
        manifest = {'containers': [{'Name': '/vpn', 'Config': {}, 'HostConfig': {'NetworkMode': 'host'}}], 'snapshot_images': {'vpn': 'snapshot'}}
        with patch.object(c, 'api') as api:
            with self.assertRaises(RuntimeError):
                snapshot.restore_containers(manifest, {'network_profile': 'filtered'})
        api.assert_not_called()

    def test_local_panel_connection_keeps_certificate_hostname(self):
        connection = remote.LocalPanelConnection('vpn.example.org')
        with patch.object(remote.socket, 'create_connection') as connect, patch.object(connection.tls_context, 'wrap_socket') as wrap:
            connection.connect()
            connect.assert_called_once_with(('127.0.0.1', 6659), 20)
            wrap.assert_called_once_with(connect.return_value, server_hostname='vpn.example.org')
        self.assertTrue(connection.tls_context.check_hostname)

    def test_reject_shell_and_private_endpoints(self):
        for value in ['127.0.0.1', '10.1.2.3', '8.8.8.8; touch /tmp/x', '-oProxyCommand=evil']:
            with self.assertRaises(ValueError):
                c.validate_ip(value)
        for value in ['https://vpn.example.org', 'vpn.example.org;id', '*.example.org', 'vpn.example.org:22']:
            with self.assertRaises(ValueError):
                c.validate_domain(value)
        self.assertEqual(c.validate_ip('8.8.8.8'), '8.8.8.8')
        self.assertEqual(c.validate_domain('VPN.example.org.'), 'vpn.example.org')

    def archive(self, name, member, content=b'content'):
        path = self.directory / name
        with tarfile.open(path, 'w:gz') as archive:
            if member.isfile():
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            else:
                archive.addfile(member)
        return path

    def test_tar_traversal_is_rejected(self):
        archive = self.archive('bad.tar.gz', tarfile.TarInfo('../../outside'))
        with self.assertRaises((tarfile.FilterError, ValueError)):
            c.safe_extract(archive, self.directory / 'out')
        self.assertFalse((self.directory.parent / 'outside').exists())

    def test_tar_escape_symlink_is_rejected(self):
        member = tarfile.TarInfo('link')
        member.type = tarfile.SYMTYPE
        member.linkname = '../../outside'
        archive = self.archive('link.tar.gz', member)
        with self.assertRaises((tarfile.FilterError, ValueError)):
            c.safe_extract(archive, self.directory / 'out')

    def test_tar_regular_file_is_restored(self):
        archive = self.archive('valid.tar.gz', tarfile.TarInfo('nested/file.txt'))
        c.safe_extract(archive, self.directory / 'out')
        self.assertEqual((self.directory / 'out/nested/file.txt').read_bytes(), b'content')

    def test_endpoint_update_preserves_credentials(self):
        request = {'ip': '1.1.1.1', 'domain': 'new.example.org'}
        value = {'id': 'old.example.org', 'password': '8.8.8.8-old.example.org',
                 'privateKey': 'old.example.org', 'domain': 'old.example.org',
                 'url': 'https://old.example.org:6659/api/',
                 'certificateFile': '/root/cert/old.example.org/fullchain.pem',
                 'settings': json.dumps({'address': '8.8.8.8', 'password': 'old.example.org'})}
        result = remote.replace_endpoint(value, '8.8.8.8', 'old.example.org', request)
        self.assertEqual(result['id'], value['id'])
        self.assertEqual(result['password'], value['password'])
        self.assertEqual(result['privateKey'], value['privateKey'])
        self.assertEqual(result['domain'], 'new.example.org')
        self.assertEqual(result['url'], 'https://new.example.org:6659/api/')
        self.assertEqual(result['certificateFile'], '/root/cert/new.example.org/fullchain.pem')
        self.assertEqual(json.loads(result['settings']), {'address': '1.1.1.1', 'password': 'old.example.org'})

    def test_link_and_vmess_update_do_not_change_password_or_uuid(self):
        request = {'ip': '1.1.1.1', 'domain': 'new.example.org'}
        link = 'hysteria2://user:old.example.org@old.example.org:2443/?sni=old.example.org'
        result = remote.replace_endpoint(link, '8.8.8.8', 'old.example.org', request)
        parts = urlsplit(result)
        self.assertEqual(parts.password, 'old.example.org')
        self.assertEqual(parts.hostname, 'new.example.org')
        original = {'add': '8.8.8.8', 'id': 'do-not-change', 'port': '12345'}
        encoded = 'vmess://' + base64.b64encode(json.dumps(original).encode()).decode()
        updated = remote.replace_endpoint(encoded, '8.8.8.8', 'old.example.org', request)
        decoded = json.loads(base64.b64decode(updated[len('vmess://'):]))
        self.assertEqual(decoded['add'], '1.1.1.1')
        self.assertEqual(decoded['id'], original['id'])

    def test_profiles_are_distinct_and_firefox(self):
        with patch.object(c, 'ROOT', self.directory):
            for role, identifier in [('personal', 'personal-id'), ('shared', 'shared-id')]:
                reality = {'publicKey': 'public', 'shortId': '1234', 'serverName': 'mask.example.org', 'fingerprint': 'firefox'}
                client = c.xray_client(identifier, 'vpn.example.org', 443, reality)
                link = c.vless_link(identifier, 'vpn.example.org', 443, reality, role)
                c.export_access(role, 'xray', client, link)
        identifiers = []
        for role in ['personal', 'shared']:
            link = urlsplit((self.directory / 'exports' / role / 'strings/xray.txt').read_text().strip())
            config = json.loads((self.directory / 'exports' / role / 'configurations/xray.json').read_text())
            self.assertEqual(parse_qs(link.query)['fp'], ['firefox'])
            self.assertEqual(link.username, config['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'])
            identifiers.append(link.username)
        self.assertNotEqual(*identifiers)

    def test_ssh_has_no_password_fallback_or_key_upload(self):
        key = self.directory / 'key'
        key.write_text('FAKE TEST KEY')
        connection = migrate.Connection('8.8.8.8', 2222, key)
        with patch('vps_migration.cli.wizard.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'0')) as execute:
            connection.ssh('id -u', capture=True)
        arguments = execute.call_args.args[0]
        self.assertIn('IdentitiesOnly=yes', arguments)
        self.assertIn('PasswordAuthentication=no', arguments)
        self.assertIn('KbdInteractiveAuthentication=no', arguments)
        self.assertIn('StrictHostKeyChecking=ask', arguments)
        self.assertNotIn('FAKE TEST KEY', arguments)

    def test_proxyjump_uses_distinct_local_keys_without_forwarding_agent(self):
        key = self.directory / 'target key'
        relay_key = self.directory / 'relay key'
        key.write_text('FAKE TARGET KEY')
        relay_key.write_text('FAKE RELAY KEY')
        target = migrate.Connection('8.8.8.8', 22, key)
        entry = migrate.Connection('1.1.1.1', 2222, relay_key)
        target.use_jump(entry, self.directory)
        config = Path(target.options[1]).read_text()
        self.assertIn('ProxyJump vps-migration-relay', config)
        self.assertIn('Port 2222', config)
        self.assertIn('IdentityFile "' + relay_key.as_posix() + '"', config)
        self.assertIn('ForwardAgent no', config)
        self.assertNotIn('FAKE RELAY KEY', config)
        self.assertNotIn('FAKE TARGET KEY', config)

    def test_restored_clients_use_relay_while_server_settings_use_origin(self):
        request = {'ip': '9.9.9.9', 'relay_ip': '1.1.1.1', 'domain': 'entry.example.org'}
        with patch.object(c, 'ROOT', self.directory):
            client = self.directory / 'exports/personal/configurations/old.json'
            server = self.directory / 'config/xray/server.json'
            c.write(client, {'server': '8.8.8.8', 'password': '8.8.8.8'})
            c.write(server, {'address': '8.8.8.8'})
            remote.rewrite_host_settings({'source_ip': '8.8.8.8', 'source_domain': 'old.example.org',
                                          'host_roots': [str(self.directory)], 'containers': []}, request)
            self.assertEqual(json.loads(client.read_text()), {'server': '1.1.1.1', 'password': '8.8.8.8'})
            self.assertEqual(json.loads(server.read_text())['address'], '9.9.9.9')

    def test_two_server_wizard_orders_setup_and_hardens_both_hosts(self):
        key = self.directory / 'local-key'
        key.write_text('FAKE LOCAL KEY')
        answers = ['1', '3', str(self.directory / 'results'), '8.8.8.8', '22', str(key),
                   '2', '1.1.1.1', '2222', str(key), 'entry.example.org', 'mask.example.org',
                   '2', 'firefox', '', '1', 'WARP 8.8.8.8', 'DEPLOY 8.8.8.8', 'RELAY 1.1.1.1']
        operations = []
        def prepare(host, request, output):
            self.assertNotIn('key', request)
            self.assertNotIn('FAKE LOCAL KEY', json.dumps(request))
            return '/root/vps-transfer/' + request['mode']
        with patch('sys.argv', ['migrate.py']), patch('builtins.input', side_effect=answers), \
             patch('sys.stdout', new_callable=io.StringIO), patch.object(migrate, 'prepare', side_effect=prepare), \
             patch.object(migrate, 'approve_os_updates', return_value=None), patch.object(migrate, 'restart_if_needed', return_value=None), patch.object(migrate, 'download_backups'), \
             patch.object(migrate, 'action') as action, patch.object(migrate, 'background_action',
                side_effect=lambda host, job, operation, result: operations.append((host.address, operation))), \
             patch.object(migrate.Connection, 'ssh', return_value=b'0'), \
             patch.object(migrate.Connection, 'download'), patch.object(c, 'safe_extract'), \
             patch.object(migrate.shutil, 'which', return_value='tool'):
            migrate.main()
        self.assertEqual(operations, [('1.1.1.1', 'relay'), ('8.8.8.8', 'deploy')])
        security = [(call.args[0].address, call.args[2]) for call in action.call_args_list
                    if call.args[2] in ['harden', 'commit-ssh']]
        self.assertEqual(security, [('8.8.8.8', 'harden'), ('8.8.8.8', 'commit-ssh'),
                                    ('1.1.1.1', 'harden'), ('1.1.1.1', 'commit-ssh')])

    def test_canceling_relay_confirmation_prevents_all_remote_actions(self):
        key = self.directory / 'local-key'
        key.write_text('FAKE LOCAL KEY')
        answers = ['1', '3', str(self.directory / 'cancel'), '8.8.8.8', '22', str(key),
                   '2', '1.1.1.1', '2222', str(key), 'entry.example.org', 'mask.example.org',
                   '2', 'firefox', '', '1', 'WARP 8.8.8.8', 'DEPLOY 8.8.8.8', 'NO']
        with patch('sys.argv', ['migrate.py']), patch('builtins.input', side_effect=answers), \
             patch('sys.stdout', new_callable=io.StringIO), patch.object(migrate, 'prepare') as prepare, \
             patch.object(migrate.shutil, 'which', return_value='tool'), self.assertRaises(RuntimeError):
            migrate.main()
        prepare.assert_not_called()

    def test_all_inclusive_preset_keeps_warp_optional_and_requires_deploy(self):
        for topology_choice in ['1', '2']:
            with self.subTest(topology=topology_choice):
                key = self.directory / ('preset-key-' + topology_choice)
                key.write_text('FAKE LOCAL KEY')
                answers = ['5', '1', '3', str(self.directory / ('preset-' + topology_choice)),
                           '8.8.8.8', '22', str(key), topology_choice]
                if topology_choice == '2':
                    answers.extend(['1.1.1.1', '22', str(key)])
                answers.extend(['entry.example.org', 'mask.example.org', 'firefox', '', '2', 'NO'])
                with patch('sys.argv', ['migrate.py']), patch('builtins.input', side_effect=answers), \
                     patch('sys.stdout', new_callable=io.StringIO) as output, \
                     patch.object(migrate, 'prepare') as prepare, \
                     patch.object(migrate.shutil, 'which', return_value='tool'), self.assertRaises(RuntimeError):
                    migrate.main()
                prepare.assert_not_called()
                self.assertIn('Сетевой профиль: all', output.getvalue())
                self.assertIn('WARP: выключен', output.getvalue())
                self.assertIn('Дополнительный TCP-порт REALITY', output.getvalue())

    def test_backup_failure_starts_source_containers_again(self):
        container = {'Id': 'source-id', 'Name': '/amnezia-xray', 'State': {'Running': True},
                     'Image': 'image-id', 'Mounts': [], 'NetworkSettings': {'Networks': {'bridge': {}}}}
        calls = []
        def execute(arguments, **kwargs):
            calls.append(arguments)
            if arguments[:2] == ['docker', 'stop']:
                raise RuntimeError('simulated stop failure')
            return SimpleNamespace(returncode=0, stdout=b'')
        with patch('vps_migration.server.snapshot.selected', return_value=[container]), patch('vps_migration.server.snapshot.host_roots', return_value=[]), \
             patch.object(c, 'run', side_effect=execute), patch.object(c, 'api', return_value=[{'Id': 'source-id'}]), \
             patch.object(c, 'docker_json', return_value=[{'Size': 1}]), \
             patch('vps_migration.server.snapshot.shutil.disk_usage', return_value=SimpleNamespace(free=1024 ** 4)):
            with self.assertRaises(RuntimeError):
                snapshot.backup({'ip': '8.8.8.8', 'domain': 'old.example.org'}, self.directory)
        self.assertIn(['docker', 'start', 'amnezia-xray'], calls)

    def test_restore_keeps_pg18_mount_and_secrets(self):
        original = {'Name': '/3dp-postgres', 'Config': {'Image': 'original',
            'Env': ['DB_PASSWORD=old.example.org', 'ALLOWED_ORIGINS=https://old.example.org']},
            'HostConfig': {'NetworkMode': 'application', 'RestartPolicy': {'Name': 'always'}},
            'Mounts': [{'Type': 'volume', 'Name': 'pg-data', 'Destination': '/var/lib/postgresql', 'RW': True}],
            'NetworkSettings': {'Networks': {'application': {'IPAddress': '172.19.0.2', 'Aliases': ['postgres']}, 'bridge': {}}}}
        manifest = {'containers': [original], 'snapshot_images': {'3dp-postgres': 'snapshot'},
                    'source_ip': '8.8.8.8', 'source_domain': 'old.example.org'}
        calls = []
        def docker_api(method, path, payload):
            calls.append((path, payload))
            return {'Id': 'restored-id'}
        with patch.object(c, 'api', side_effect=docker_api):
            snapshot.restore_containers(manifest, {'ip': '1.1.1.1', 'domain': 'new.example.org'})
        payload = calls[0][1]
        self.assertEqual(payload['HostConfig']['Mounts'][0]['Target'], '/var/lib/postgresql')
        self.assertIn('DB_PASSWORD=old.example.org', payload['Env'])
        self.assertIn('ALLOWED_ORIGINS=https://new.example.org', payload['Env'])
        self.assertEqual(calls[1][1]['EndpointConfig'], {})

    def test_late_ssh_commit_is_rejected(self):
        c.write(self.directory / 'security-state.json', {'rolled_back': True, 'unit': 'test'})
        with self.assertRaises(RuntimeError):
            remote.security_commit(self.directory)

    def test_multicast_and_ip_instead_of_domain_are_rejected(self):
        with self.assertRaises(ValueError):
            c.validate_ip('224.0.0.1')
        with self.assertRaises(ValueError):
            c.validate_domain('8.8.8.8')

    def test_ssh_commit_checks_root_match_context_before_canceling_timer(self):
        c.write(self.directory / 'security-state.json', {'committed': False, 'unit': 'rollback-test'})
        effective = b'passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\nauthenticationmethods publickey\n'
        with patch.dict('vps_migration.server.worker.os.environ', {'SSH_CONNECTION': '8.8.8.8 50000 1.1.1.1 22'}), \
             patch.object(c, 'run', return_value=SimpleNamespace(stdout=effective)) as execute:
            remote.security_commit(self.directory)
        first = execute.call_args_list[0].args[0]
        self.assertIn('-C', first)
        self.assertIn('user=root', first[-1])
        self.assertEqual(execute.call_args_list[1].args[0], ['systemctl', 'stop', 'rollback-test.timer'])
        self.assertTrue(json.loads((self.directory / 'security-state.json').read_text())['committed'])

    def test_bad_root_effective_config_keeps_rollback_timer(self):
        c.write(self.directory / 'security-state.json', {'committed': False, 'unit': 'rollback-test'})
        with patch.dict('vps_migration.server.worker.os.environ', {'SSH_CONNECTION': '8.8.8.8 50000 1.1.1.1 22'}), \
             patch.object(c, 'run', return_value=SimpleNamespace(stdout=b'passwordauthentication yes\n')) as execute:
            with self.assertRaises(RuntimeError):
                remote.security_commit(self.directory)
        self.assertEqual(execute.call_count, 1)
        self.assertFalse(json.loads((self.directory / 'security-state.json').read_text())['committed'])

    def test_xui_waits_for_actual_user_initialization(self):
        def initialize(seconds):
            with closing(sqlite3.connect(self.directory / 'x-ui.db')) as connection:
                with connection:
                    connection.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)')
                    connection.execute("INSERT INTO users(username) VALUES ('owner')")
        with patch('vps_migration.server.stack.time.sleep', side_effect=initialize) as wait:
            stack.wait_xui_user(self.directory, 'owner')
        self.assertEqual(wait.call_count, 1)

    def test_portable_package_is_deterministic_and_has_only_allowed_files(self):
        first = build_portable.build(self.directory / 'first')
        second = build_portable.build(self.directory / 'second')
        self.assertEqual(first['sha256'], second['sha256'])
        archive = self.directory / 'first/vps-migration.pyz'
        with zipfile.ZipFile(archive) as package:
            names = package.namelist()
        self.assertEqual(set(names), {'__main__.py', 'manifest.json', *['payload/' + name for name in portable.FILES]})
        self.assertFalse(any('private-vpn/' in name for name in names))
        launcher = (self.directory / 'first/run.sh').read_text()
        self.assertIn(first['sha256'], launcher)
        self.assertIn(first['asset_url'], launcher)
        self.assertNotIn('@PACKAGE_', launcher)
        powershell = (self.directory / 'first/run.ps1').read_text()
        self.assertIn(first['sha256'], powershell)
        self.assertIn(first['asset_url'], powershell)
        self.assertNotIn('@PACKAGE_', powershell)
        self.assertIn('finally', powershell)
        self.assertIn('Remove-Item -LiteralPath $packagePath', powershell)
        self.assertEqual(first['release_assets'], ['vps-migration.pyz', 'vps-migration.pyz.sha256', 'run.sh', 'run.ps1'])

    def test_server_upload_contains_every_dependency_without_local_cli(self):
        directory = self.directory / 'remote-worker'
        for name in portable.SERVER_FILES:
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repository / 'scripts/migration' / name, target)
        result = subprocess.run([sys.executable, str(directory / 'remote.py'), '--help'],
                                cwd=directory, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('relay-preflight', result.stdout)
        self.assertFalse((directory / 'vps_migration/cli').exists())

    def test_persistent_relay_imports_as_a_minimal_package(self):
        directory = self.directory / 'persistent-relay'
        names = ['__init__.py', 'core/__init__.py', 'core/common.py', 'server/__init__.py', 'server/relay.py']
        for name in names:
            target = directory / 'vps_migration' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.repository / 'scripts/migration/vps_migration' / name, target)
        result = subprocess.run([sys.executable, '-m', 'vps_migration.server.relay', '--help'],
                                cwd=directory, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('apply', result.stdout)

    def test_portable_install_preserves_state_and_refuses_changed_code(self):
        build_portable.build(self.directory / 'package')
        archive = self.directory / 'package/vps-migration.pyz'
        destination = self.directory / 'installation'
        destination.mkdir()
        portable.unpack(archive, destination)
        state = destination / 'private-vpn/example.txt'
        c.write(state, 'preserve me')
        portable.unpack(archive, destination)
        self.assertEqual(state.read_text(), 'preserve me')
        source = destination / 'scripts/migration/migrate.py'
        source.write_bytes(source.read_bytes() + b'\n')
        with self.assertRaises(RuntimeError):
            portable.unpack(archive, destination)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is not installed locally')
    def test_x25519_public_derivation(self):
        private, public = c.x25519_pair()
        self.assertEqual(c.public_x25519(private), public)
        self.assertEqual(len(base64.urlsafe_b64decode(private + '=')), 32)


if __name__ == '__main__':
    unittest.main()
