import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.server.maintenance import apt, cleanup


class CleanupTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.directory = Path(self.temporary.name)
        self.item = {'Id': 'a' * 64, 'Name': '/old-dashboard', 'Image': 'sha256:old',
                     'Config': {'Image': 'example/dashboard:latest', 'Labels': {}},
                     'HostConfig': {'AutoRemove': False}, 'Mounts': [], 'State': {'Running': False}}
        self.row = {'id': self.item['Id'], 'name': 'old-dashboard', 'image': 'example/dashboard:latest',
                    'protected': False, 'auto_remove': False, 'running': False, 'size': 1,
                    'signature': cleanup.container_signature(self.item)}
        self.inventory = {'packages': [{'package': 'old-app', 'version': '1'}], 'containers': [self.row],
                          'protected_packages': ['openssh-server', 'docker.io'], 'installed_before': []}

    def tearDown(self):
        self.temporary.cleanup()

    def test_vpn_containers_are_protected_by_name_label_or_image(self):
        for name, image, labels in [('amnezia-custom', 'custom', {}), ('3dp-backend', 'custom', {}),
                                    ('arbitrary', 'ghcr.io/xtls/xray-core:latest', {}),
                                    ('custom-name', 'custom', {'vps-stack': 'managed'})]:
            item = copy.deepcopy(self.item)
            item['Name'] = '/' + name
            item['Config'] = {'Image': image, 'Labels': labels}
            self.assertTrue(cleanup.protected_container(item))
        self.assertFalse(cleanup.protected_container(self.item))

    def test_unknown_protected_and_auto_remove_containers_are_not_selectable(self):
        for values in [{'protected': True}, {'auto_remove': True}]:
            inventory = {**self.inventory, 'containers': [{**self.row, **values}]}
            with self.assertRaises(ValueError):
                cleanup.preview(inventory, {'containers': [self.row['id']], 'packages': []})
        with self.assertRaises(ValueError):
            cleanup.preview(self.inventory, {'containers': ['unknown']})

    def test_package_dependency_removal_cannot_remove_ssh(self):
        with patch.object(apt, 'command', return_value=SimpleNamespace(stdout=b'Remv old-app [1]\nRemv openssh-server [1]\n')) as execute:
            with self.assertRaisesRegex(RuntimeError, 'openssh-server'):
                cleanup.preview(self.inventory, {'packages': ['old-app'], 'autoremove': True})
        self.assertIn('-s', execute.call_args.args[0])
        self.assertNotIn('-y', execute.call_args.args[0])

    def test_protection_includes_installed_dependency_closure(self):
        packages = [{'package': 'docker.io', 'essential': False, 'priority': 'optional'},
                    {'package': 'containerd', 'essential': False, 'priority': 'optional'},
                    {'package': 'libdependency', 'essential': False, 'priority': 'optional'}]
        with patch.object(apt, 'command', return_value=SimpleNamespace(stdout=b'docker.io\n Depends: containerd\ncontainerd\n Depends: libdependency\n')):
            self.assertIn('libdependency', apt.protected_packages(packages))

    def test_native_and_multiarch_names_cannot_bypass_dependency_protection(self):
        self.assertTrue(apt.is_protected('libdependency', {'libdependency:amd64'}))
        self.assertTrue(apt.is_protected('libdependency:i386', {'libdependency:amd64'}))

    def save_plan(self):
        plan = cleanup.preview(self.inventory, {'containers': [self.row['id']]})
        c.write(self.directory / 'cleanup-plan.json', plan)
        c.write(self.directory / 'cleanup-approval.json', {'fingerprint': plan['fingerprint']})
        return plan

    def test_backup_failure_prevents_deleting_anything(self):
        self.save_plan()
        with patch.object(cleanup, 'validate_current'), patch.object(cleanup, 'backup', side_effect=RuntimeError('disk full')), \
             patch.object(c, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'disk full'):
                cleanup.apply_approved(self.directory)
        run.assert_not_called()

    def test_container_removed_only_after_backup_without_removing_volumes(self):
        self.save_plan()
        archive = self.directory / 'cleanup-backup.tar.gz'
        events = []
        def backup(plan, job):
            archive.write_bytes(b'saved image and configuration')
            events.append('backup')
            return archive
        def run(arguments, **kwargs):
            self.assertEqual(events, ['backup'])
            self.assertEqual(arguments, ['docker', 'rm', self.row['id']])
            self.assertNotIn('-v', arguments)
            events.append('remove')
        with patch.object(cleanup, 'validate_current'), patch.object(cleanup, 'backup', side_effect=backup), \
             patch.object(cleanup, 'inspect_container', return_value=self.item), patch.object(c, 'run', side_effect=run), \
             patch.object(apt, 'verify_system'), patch.object(apt, 'installed_packages', return_value=[]), \
             patch.object(cleanup.shutil, 'which', return_value='docker'), patch.object(c, 'api', return_value=[]):
            result = cleanup.apply_approved(self.directory)
        self.assertEqual(events, ['backup', 'remove'])
        self.assertFalse(result['volumes_and_bind_directories_deleted'])
        self.assertFalse(result['package_configs_purged'])

    def test_failed_image_save_starts_the_original_container_again(self):
        row = {**self.row, 'running': True}
        plan = {'operation': {'containers': [row]}, 'installed_before': []}
        calls = []
        def run(arguments, **kwargs):
            calls.append(arguments)
            if arguments[:2] == ['docker', 'save']:
                raise RuntimeError('save failed')
            return SimpleNamespace(returncode=0)
        with patch.object(cleanup, 'inspect_container', return_value=self.item), patch.object(apt, 'backup_config'), \
             patch.object(cleanup.shutil, 'disk_usage', return_value=SimpleNamespace(free=10**12)), \
             patch.object(c, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'save failed'):
                cleanup.backup(plan, self.directory)
        self.assertIn(['docker', 'start', row['id']], calls)
        self.assertFalse(any(command[:2] == ['docker', 'rm'] for command in calls))


if __name__ == '__main__':
    unittest.main()
