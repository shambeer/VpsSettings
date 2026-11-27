import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.server import relay, worker
from vps_migration.server.maintenance import apt as system_apt


class SecurityTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.directory = Path(self.temporary.name).resolve()

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_relay_result_allows_hardening_and_verified_commit(self):
        job = self.directory / 'job'
        job.mkdir()
        request = {'mode': 'relay', 'ip': '1.1.1.1', 'origin_ip': '8.8.8.8', 'network_profile': 'all'}
        paths = {name: self.directory / 'system' / name.lstrip('/') for name in [
            '/etc/ssh/sshd_config', '/etc/ssh/vps-stack-key-only.conf',
            '/etc/fail2ban/jail.d/90-vps-stack.local', '/etc/systemd/system/vps-relay.service']}
        actual_write = c.write
        actual_write(paths['/etc/ssh/sshd_config'], 'Port 2222\n')
        def write(path, content):
            destination = paths.get(str(path), Path(path)).resolve()
            self.assertTrue(destination.is_relative_to(self.directory))
            actual_write(destination, content)
        effective = (b'passwordauthentication no\nkbdinteractiveauthentication no\n'
                     b'pubkeyauthentication yes\nauthenticationmethods publickey\n')
        def run(arguments, *args, **kwargs):
            output = effective if arguments[:2] == ['/usr/sbin/sshd', '-T'] else b'0\n'
            return SimpleNamespace(returncode=0, stdout=output, stderr=b'')
        with patch.object(relay, 'preflight'), patch.object(relay, 'DIRECTORY', self.directory / 'installed'), \
             patch.object(system_apt, 'apply_approved'), \
             patch.object(relay, 'CONFIG', self.directory / 'relay.json'), \
             patch.object(c, 'write', side_effect=write), patch.object(c, 'run', side_effect=run) as execute, \
             patch.object(worker, 'Path', side_effect=lambda value: paths.get(str(value), Path(value))), \
             patch.dict(worker.os.environ, {'SSH_CONNECTION': '8.8.4.4 50000 1.1.1.1 2222'}):
            relay.install(request, job)
            self.assertTrue((job / 'relay-result.json').exists())
            self.assertFalse((job / 'deploy-result.json').exists())
            worker.security_prepare(request, job)
            state = json.loads((job / 'security-state.json').read_text())
            self.assertFalse(state['committed'])
            commands = [call.args[0] for call in execute.call_args_list]
            self.assertTrue(any(command[0] == 'systemd-run' and '--on-active=180s' in command for command in commands))
            self.assertNotIn(['systemctl', 'stop', state['unit'] + '.timer'], commands)
            worker.rollback_ssh(job)
            self.assertTrue(json.loads((job / 'security-state.json').read_text())['rolled_back'])
            worker.security_prepare(request, job)
            self.assertFalse(json.loads((job / 'security-state.json').read_text()).get('rolled_back', False))
            worker.security_commit(job)
            self.assertTrue(json.loads((job / 'security-state.json').read_text())['committed'])
            self.assertIn('PasswordAuthentication no', paths['/etc/ssh/vps-stack-key-only.conf'].read_text())
            self.assertIn('port = 2222', paths['/etc/fail2ban/jail.d/90-vps-stack.local'].read_text())

    def test_only_successful_result_for_the_current_role_is_accepted(self):
        for mode, expected, other in [('relay', 'relay-result.json', 'deploy-result.json'),
                                      ('fresh', 'deploy-result.json', 'relay-result.json'),
                                      ('restore', 'deploy-result.json', 'relay-result.json')]:
            for index, data in enumerate([None, {'success': False}, {'success': 'true'}, [], 'broken-json']):
                with self.subTest(mode=mode, data=data):
                    job = self.directory / (mode + '-' + str(index))
                    job.mkdir()
                    c.write(job / other, {'success': True})
                    if data is not None:
                        c.write(job / expected, data)
                    with patch.object(c, 'run') as run, patch.object(c, 'write') as write:
                        with self.assertRaises(RuntimeError):
                            worker.security_prepare({'mode': mode}, job)
                    run.assert_not_called()
                    write.assert_not_called()

    def test_main_server_results_still_require_an_authenticated_ssh_context(self):
        for mode in ['fresh', 'restore']:
            job = self.directory / mode
            job.mkdir()
            c.write(job / 'deploy-result.json', {'success': True})
            with patch.dict(worker.os.environ, {'SSH_CONNECTION': ''}), patch.object(c, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'SSH_CONNECTION'):
                    worker.security_prepare({'mode': mode}, job)
            run.assert_not_called()

    def test_backup_mode_cannot_trigger_hardening_with_a_deployment_result(self):
        c.write(self.directory / 'deploy-result.json', {'success': True})
        with patch.object(c, 'run') as run, patch.object(c, 'write') as write:
            with self.assertRaisesRegex(RuntimeError, 'режима'):
                worker.security_prepare({'mode': 'backup'}, self.directory)
        run.assert_not_called()
        write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
