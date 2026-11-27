import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.cli import maintenance, wizard
from vps_migration.core import common as c


class MaintenanceCliTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.directory = Path(self.temporary.name)
        self.host = Mock(address='8.8.8.8', port=22)

    def tearDown(self):
        self.temporary.cleanup()

    def test_declining_plan_never_prepares_remote_files(self):
        with patch.object(wizard, 'connection', return_value=self.host), patch.object(wizard, 'ask', side_effect=['1', '2', 'NO']), \
             patch.object(wizard, 'prepare') as prepare, patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaisesRegex(RuntimeError, 'отменена'):
                maintenance.run(self.directory)
        prepare.assert_not_called()

    def test_declining_upgrade_never_uploads_approval(self):
        plan = {'transaction': {'changes': [], 'removals': []}, 'held': [], 'fingerprint': 'hash'}
        self.host.download.side_effect = lambda source, target: Path(target).write_text(json.dumps(plan))
        with patch.object(wizard, 'action'), patch.object(wizard, 'ask', return_value='NO'), \
             patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaisesRegex(RuntimeError, 'отменено'):
                maintenance.approve_os_updates(self.host, '/root/vps-transfer/test', self.directory)
        self.host.upload.assert_not_called()

    def test_declining_delete_never_starts_cleanup(self):
        row = {'id': 'a' * 64, 'name': 'old-app', 'image': 'example/old:latest',
               'protected': False, 'auto_remove': False, 'running': False}
        inventory = {'containers': [row], 'packages': []}
        approved = {'fingerprint': 'hash', 'operation': {'containers': [row], 'transaction': {'removals': []}}}
        def download(source, target):
            data = inventory if source.endswith('maintenance-plan.json') else approved
            Path(target).write_text(json.dumps(data))
        self.host.download.side_effect = download
        answers = ['1', '2', 'PLAN 8.8.8.8', '1', 'NO']
        with patch.object(wizard, 'connection', return_value=self.host), patch.object(wizard, 'ask', side_effect=answers), \
             patch.object(wizard, 'prepare', return_value='/root/vps-transfer/test'), patch.object(wizard, 'action'), \
             patch.object(wizard, 'background_action') as apply, patch('sys.stdout', new_callable=io.StringIO):
            with self.assertRaisesRegex(RuntimeError, 'отменена'):
                maintenance.run(self.directory)
        apply.assert_not_called()
        self.assertFalse((self.directory / 'cleanup-approval.json').exists())

    def test_backup_checksum_mismatch_is_reported_to_caller(self):
        def ssh(command, **kwargs):
            if command.startswith('sha256sum'):
                return ('0' * 64 + '  archive').encode()
            return b'yes' if '/os-config-backup.tar.gz' in command else b''
        self.host.ssh.side_effect = ssh
        self.host.download.side_effect = lambda source, target: Path(target).write_bytes(b'wrong content')
        with patch('sys.stdout', new_callable=io.StringIO):
            failed = maintenance.download_backups(self.host, '/root/vps-transfer/test', self.directory)
        self.assertEqual(failed, ['os-config-backup.tar.gz'])

    def test_reboot_can_be_deferred_without_sending_any_server_action(self):
        self.host.download.side_effect = lambda source, target: Path(target).write_text(json.dumps({'reboot_required': True}))
        with patch.object(wizard, 'ask', return_value='2'), patch.object(wizard, 'action') as action, \
             patch('sys.stdout', new_callable=io.StringIO):
            maintenance.restart_if_needed(self.host, '/root/vps-transfer/test', self.directory)
        action.assert_not_called()
        self.host.ssh.assert_not_called()
        self.assertTrue((self.directory / 'os-8.8.8.8/reboot-deferred.json').exists())

    def test_reboot_waits_for_changed_boot_id_then_checks_services(self):
        self.host.download.side_effect = lambda source, target: Path(target).write_text(json.dumps({'reboot_required': True}))
        self.host.ssh.side_effect = [b'old-boot', b'old-boot', b'new-boot']
        with patch.object(wizard, 'ask', side_effect=['1', 'REBOOT 8.8.8.8']), patch.object(wizard, 'action') as action, \
             patch.object(maintenance.time, 'sleep'), patch('sys.stdout', new_callable=io.StringIO):
            maintenance.restart_if_needed(self.host, '/root/vps-transfer/test', self.directory)
        self.assertEqual([call.args[2] for call in action.call_args_list], ['maintenance-reboot', 'maintenance-check'])
        approval = json.loads((self.directory / 'os-8.8.8.8/reboot-approval.json').read_text())
        self.assertEqual(approval, {'confirm': 'REBOOT 8.8.8.8', 'boot_id': 'old-boot'})
    def test_resume_after_reboot_does_not_request_another_reboot(self):
        directory = self.directory / 'os-8.8.8.8'
        directory.mkdir()
        c.write(directory / 'reboot-approval.json', {'confirm': 'REBOOT 8.8.8.8', 'boot_id': 'old-boot'})
        self.host.download.side_effect = lambda source, target: Path(target).write_text(json.dumps({'reboot_required': True}))
        self.host.ssh.side_effect = [b'new-boot', b'new-boot']
        with patch.object(wizard, 'ask', side_effect=['1', 'REBOOT 8.8.8.8']), \
             patch.object(wizard, 'action') as action, patch('sys.stdout', new_callable=io.StringIO):
            maintenance.restart_if_needed(self.host, '/root/vps-transfer/test', self.directory)
        self.assertEqual([call.args[2] for call in action.call_args_list], ['maintenance-check'])



if __name__ == '__main__':
    unittest.main()
