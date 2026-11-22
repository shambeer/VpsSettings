import base64
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common as c
import migrate
import remote
import snapshot
import stack


class MigrationTests(unittest.TestCase):
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
        with patch('migrate.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'0')) as execute:
            connection.ssh('id -u', capture=True)
        arguments = execute.call_args.args[0]
        self.assertIn('IdentitiesOnly=yes', arguments)
        self.assertIn('PasswordAuthentication=no', arguments)
        self.assertIn('KbdInteractiveAuthentication=no', arguments)
        self.assertIn('StrictHostKeyChecking=ask', arguments)
        self.assertNotIn('FAKE TEST KEY', arguments)

    def test_backup_failure_starts_source_containers_again(self):
        container = {'Id': 'source-id', 'Name': '/amnezia-xray', 'State': {'Running': True},
                     'Image': 'image-id', 'Mounts': [], 'NetworkSettings': {'Networks': {'bridge': {}}}}
        calls = []
        def execute(arguments, **kwargs):
            calls.append(arguments)
            if arguments[:2] == ['docker', 'stop']:
                raise RuntimeError('simulated stop failure')
            return SimpleNamespace(returncode=0, stdout=b'')
        with patch('snapshot.selected', return_value=[container]), patch('snapshot.host_roots', return_value=[]), \
             patch.object(c, 'run', side_effect=execute), patch.object(c, 'api', return_value=[{'Id': 'source-id'}]), \
             patch.object(c, 'docker_json', return_value=[{'Size': 1}]), \
             patch('snapshot.shutil.disk_usage', return_value=SimpleNamespace(free=1024 ** 4)):
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

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is not installed locally')
    def test_x25519_public_derivation(self):
        private, public = c.x25519_pair()
        self.assertEqual(c.public_x25519(private), public)
        self.assertEqual(len(base64.urlsafe_b64decode(private + '=')), 32)


if __name__ == '__main__':
    unittest.main()
