import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.server.maintenance import apt, operations


class OsUpdateTests(unittest.TestCase):
    def test_grub_update_refuses_stale_provider_disk_before_apt_changes(self):
        changes = [{'package': 'grub-pc', 'from': '1', 'to': '2'}]
        settings = b'* grub-pc/install_devices: /dev/disk/by-id/missing-template-disk\n'
        with patch.object(apt.shutil, 'which', return_value='/usr/bin/debconf-show'), \
             patch.object(apt, 'command', return_value=SimpleNamespace(stdout=settings)) as execute, \
             patch.object(apt.Path, 'exists', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'отсутствующий диск'):
                apt.validate_grub_devices(changes)
            self.assertEqual(execute.call_args.args[0], ['debconf-show', 'grub-pc'])
        with patch.object(apt.shutil, 'which', return_value='/usr/bin/debconf-show'), \
             patch.object(apt, 'command', return_value=SimpleNamespace(stdout=b'* grub-pc/install_devices: /dev/sda\n')), \
             patch.object(apt.Path, 'exists', return_value=True):
            apt.validate_grub_devices(changes)
        with patch.object(apt, 'command') as execute:
            apt.validate_grub_devices([{'package': 'curl', 'from': '1', 'to': '2'}])
            execute.assert_not_called()

    def setUp(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_plan(self, changes=None):
        transaction = {'changes': changes or [], 'removals': []}
        plan = {'transaction': transaction, 'fingerprint': apt.fingerprint(transaction),
                'held': [], 'installed_before': [], 'failed_units_before': []}
        c.write(self.directory / 'os-plan.json', plan)
        c.write(self.directory / 'os-approval.json', {'fingerprint': plan['fingerprint'], 'removals': []})
        return plan

    def test_apt_simulation_preserves_versions_additions_and_removals(self):
        result = apt.parse_simulation('Inst curl [1:8.0-1] (1:8.1-2 Debian:stable [amd64])\n'
                                      'Inst libnew (2.0 Debian [amd64])\nRemv obsolete [0.1]\nConf curl (1:8.1-2)\n')
        self.assertEqual(result['changes'][0], {'package': 'curl', 'from': '1:8.0-1', 'to': '1:8.1-2'})
        self.assertEqual(result['changes'][1]['from'], None)
        self.assertEqual(result['removals'], [{'package': 'obsolete', 'version': '0.1'}])

    def test_dpkg_inventory_keeps_protected_flag_and_ignores_removed_packages(self):
        data = b'boot-package\t1.0\tno\tyes\toptional\tinstalled\nold-app\t1.0\tno\tno\toptional\tconfig-files\n'
        with patch.object(apt, 'command', return_value=SimpleNamespace(stdout=data)):
            packages = apt.installed_packages()
        self.assertEqual(len(packages), 1)
        self.assertTrue(packages[0]['protected'])

    def test_changed_transaction_is_rejected_before_backup_or_upgrade(self):
        plan = self.write_plan()
        with patch.object(apt, 'upgrade_plan', return_value={**plan, 'fingerprint': 'changed'}), \
             patch.object(apt, 'backup_config') as backup, patch.object(apt, 'command') as execute:
            with self.assertRaisesRegex(RuntimeError, 'изменился'):
                apt.apply_approved(self.directory)
        backup.assert_not_called()
        execute.assert_not_called()

    def test_full_upgrade_backs_up_first_preserves_configs_and_reports_kernel_reboot(self):
        plan = self.write_plan([{'package': 'linux-image-6.8.0-90-generic', 'from': '1', 'to': '2'}])
        archive = self.directory / 'os-config-backup.tar.gz'
        events = []
        def backup(job, saved):
            events.append('backup')
            archive.write_bytes(b'backup')
            return archive
        def execute(arguments, **kwargs):
            self.assertEqual(events, ['backup'])
            events.append('upgrade')
            self.assertIn('dist-upgrade', arguments)
            self.assertIn('Dpkg::Options::=--force-confold', arguments)
            self.assertNotIn('--allow-change-held-packages', arguments)
            return SimpleNamespace(stdout=b'', returncode=0)
        with patch.object(apt, 'upgrade_plan', return_value=plan), patch.object(apt, 'backup_config', side_effect=backup), \
             patch.object(apt, 'command', side_effect=execute), patch.object(apt, 'verify_system'), \
             patch.object(apt, 'remaining_upgrades', return_value=[]):
            result = apt.apply_approved(self.directory)
        self.assertEqual(events, ['backup', 'upgrade'])
        self.assertTrue(result['success'])
        self.assertTrue(result['reboot_required'])
        self.assertEqual(result['expected_kernel_releases'], ['6.8.0-90-generic'])
        self.assertEqual(result['backup_sha256'], c.checksum(archive))

    def test_held_pending_packages_are_not_reported_as_complete(self):
        plan = self.write_plan()
        archive = self.directory / 'backup.tar.gz'
        archive.write_bytes(b'backup')
        with patch.object(apt, 'upgrade_plan', return_value={**plan, 'held': ['held-app']}), \
             patch.object(apt, 'backup_config', return_value=archive), patch.object(apt, 'command'), \
             patch.object(apt, 'verify_system'), patch.object(apt, 'remaining_upgrades', return_value=['held-app']):
            with self.assertRaisesRegex(RuntimeError, 'held-app'):
                apt.apply_approved(self.directory)
        result = json.loads((self.directory / 'os-upgrade-result.json').read_text())
        self.assertFalse(result['complete'])
        self.assertFalse(result['success'])

    def test_removal_of_ssh_or_kernel_is_refused_in_upgrade_plan(self):
        packages = [{'package': 'openssh-server', 'version': '1', 'essential': False, 'priority': 'optional'}]
        with patch.object(apt, 'command', return_value=SimpleNamespace(stdout=b'Remv openssh-server [1]\n')), \
             patch.object(apt, 'installed_packages', return_value=packages):
            with self.assertRaisesRegex(RuntimeError, 'openssh-server'):
                apt.upgrade_plan(False)

    def test_reboot_without_matching_confirmation_never_calls_systemd(self):
        c.write(self.directory / 'os-upgrade-result.json', {'success': True, 'reboot_required': True})
        c.write(self.directory / 'reboot-approval.json', {'confirm': 'REBOOT wrong', 'boot_id': 'boot-1'})
        boot = self.directory / 'boot-id'
        boot.write_text('boot-1')
        with patch.object(operations, 'Path', return_value=boot), patch.object(c, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'не подтверждена'):
                operations.schedule_reboot({'ip': '8.8.8.8'}, self.directory)
        run.assert_not_called()

    def test_confirmed_reboot_is_delayed_and_requires_successful_upgrade(self):
        c.write(self.directory / 'os-upgrade-result.json', {'success': True, 'reboot_required': True})
        c.write(self.directory / 'reboot-approval.json', {'confirm': 'REBOOT 8.8.8.8', 'boot_id': 'boot-1'})
        boot = self.directory / 'boot-id'
        boot.write_text('boot-1')
        with patch.object(operations, 'Path', return_value=boot), patch.object(c, 'run') as run:
            operations.schedule_reboot({'ip': '8.8.8.8'}, self.directory)
        arguments = run.call_args.args[0]
        self.assertIn('--on-active=10s', arguments)
        self.assertEqual(arguments[-1], 'reboot')

    def test_container_health_check_waits_for_boot_startup(self):
        values = [{'Name': '/vpn', 'State': {'Running': False}},
                  {'Name': '/vpn', 'State': {'Running': True, 'Health': {'Status': 'starting'}}},
                  {'Name': '/vpn', 'State': {'Running': True, 'Health': {'Status': 'healthy'}}}]
        with patch.object(c, 'api', side_effect=values) as api, patch.object(operations.time, 'sleep'):
            operations.check_containers(['container-id'])
        self.assertEqual(api.call_count, 3)

    def test_wrong_kernel_after_reboot_is_not_reported_as_success(self):
        c.write(self.directory / 'maintenance-plan.json', {'task': 'os'})
        c.write(self.directory / 'os-plan.json', {'running_containers_before': []})
        c.write(self.directory / 'os-upgrade-result.json', {'expected_kernel_releases': ['new-kernel']})
        missing = self.directory / 'missing'
        with patch.object(apt, 'verify_system'), patch.object(c, 'ROOT', missing), \
             patch.object(operations, 'Path', return_value=missing), \
             patch.object(c, 'run', return_value=SimpleNamespace(stdout=b'old-kernel\n')):
            with self.assertRaisesRegex(RuntimeError, 'другое ядро'):
                operations.check_after_reboot({}, self.directory)
        self.assertFalse((self.directory / 'reboot-check.json').exists())


if __name__ == '__main__':
    unittest.main()
