import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.cli import session, wizard, maintenance
from vps_migration.core import common as c
from vps_migration.server import execution


class ResumeTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_replay_skips_completed_effect_and_its_questions(self):
        original = session.Session()
        effect = Mock(return_value='remote-job')
        read = Mock(side_effect=['host', 'UPGRADE host', 'next'])
        with session.active(original):
            self.assertEqual(original.prompt('server', None, read), 'host')
            original.attach(self.directory)
            def execute():
                original.prompt('approval', None, read)
                return effect()
            self.assertEqual(original.step('deploy', execute), 'remote-job')
        resumed = session.Session(self.directory / 'session.json')
        with session.active(resumed):
            resumed.prompt('server', None, read)
            self.assertEqual(resumed.step('deploy', effect), 'remote-job')
            self.assertEqual(resumed.prompt('next', None, read), 'next')
        effect.assert_called_once()

    def test_interrupted_step_is_not_falsely_marked_done(self):
        original = session.Session()
        with session.active(original):
            original.attach(self.directory)
            with self.assertRaises(KeyboardInterrupt):
                original.step('download', lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        resumed = session.Session(self.directory / 'session.json')
        with session.active(resumed):
            effect = Mock(return_value='complete')
            self.assertEqual(resumed.step('download', effect), 'complete')
            effect.assert_called_once()

    def test_wrong_version_and_changed_questions_are_refused(self):
        original = session.Session()
        original.prompt('server', None, lambda *args: 'one')
        with session.active(original):
            original.attach(self.directory)
        resumed = session.Session(self.directory / 'session.json')
        with self.assertRaises(RuntimeError):
            resumed.prompt('different', None, Mock())
        path = self.directory / 'session.json'
        value = json.loads(path.read_text())
        value['code'] = 'old'
        c.write(path, value)
        with self.assertRaises(RuntimeError):
            session.Session(path)

    def test_same_session_cannot_run_twice(self):
        original = session.Session()
        with session.active(original):
            original.attach(self.directory)
            second = session.Session(original.path)
            with self.assertRaises(RuntimeError):
                second.acquire()

    def test_finished_session_cannot_be_replayed(self):
        original = session.Session()
        with session.active(original):
            original.attach(self.directory)
            original.state['done'] = True
            original.save()
        with self.assertRaises(RuntimeError):
            session.Session(self.directory / 'session.json')

    def test_lost_dispatch_response_reattaches_same_systemd_unit(self):
        calls = []
        host = Mock()
        def ssh(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                raise RuntimeError('SSH lost after launch')
            if kwargs.get('capture'):
                return b'{"success":true}'
            return b''
        host.ssh.side_effect = ssh
        with patch.object(wizard.time, 'sleep'), patch('sys.stdout', new_callable=io.StringIO):
            wizard.background_action(host, '/root/vps-transfer/job', 'deploy', 'deploy-result.json')
        self.assertEqual(calls[0], calls[1])
        self.assertIn('deploy-execution.json', calls[0])
        self.assertIn('flock', calls[0])
        self.assertIn('LoadState', calls[0])
        self.assertNotIn('--collect', calls[0])

    def test_failed_background_task_is_reported_without_new_job(self):
        host = Mock()
        host.ssh.side_effect = [None, b'{"success":false,"error":"stopped"}']
        with patch('sys.stdout', new_callable=io.StringIO), self.assertRaisesRegex(RuntimeError, 'stopped'):
            wizard.background_action(host, '/root/vps-transfer/job', 'backup', 'backup-result.json')
        self.assertEqual(host.ssh.call_count, 2)

    def test_two_server_wizard_resumes_after_either_background_result(self):
        for interrupted in ['relay', 'deploy']:
            with self.subTest(interrupted=interrupted):
                folder = self.directory / interrupted
                folder.mkdir()
                key = folder / 'key'
                key.write_text('FAKE KEY')
                answers = ['1', '3', str(folder / 'results'), '8.8.8.8', '22', str(key),
                           '2', '1.1.1.1', '2222', str(key), 'entry.example.org', 'mask.example.org',
                           '2', 'firefox', '', '1', 'WARP 8.8.8.8', 'DEPLOY 8.8.8.8', 'RELAY 1.1.1.1']
                if interrupted == 'relay':
                    offset = answers.index('WARP 8.8.8.8')
                    answers[offset - 1:offset + 1] = ['2']
                created, finished = [], set()
                disconnected = False
                def prepare(host, request, output):
                    self.assertIs(request['low_memory'], True)
                    def create():
                        created.append(host.address)
                        return '/root/vps-transfer/' + request['mode']
                    return session.checkpoint('test-prepare:' + host.address, create)
                def background(host, job, name, result):
                    nonlocal disconnected
                    finished.add(name)
                    if name == interrupted and not disconnected:
                        disconnected = True
                        raise KeyboardInterrupt()
                with patch.object(wizard, 'prepare', side_effect=prepare), \
                     patch.object(wizard, 'background_action', side_effect=background), \
                     patch.object(wizard, 'approve_os_updates', return_value=None) as approvals, \
                     patch.object(wizard, 'restart_if_needed', return_value=None), \
                     patch.object(wizard, 'download_backups', return_value=[]), \
                     patch.object(wizard.Connection, 'ssh', return_value=b'0'), \
                     patch.object(wizard.Connection, 'download'), patch.object(c, 'safe_extract'), \
                     patch.object(wizard.shutil, 'which', return_value='tool'), \
                     patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO):
                    with patch('sys.argv', ['migrate.py', '--low-memory']), patch('builtins.input', side_effect=answers):
                        with self.assertRaises(KeyboardInterrupt):
                            wizard.main()
                    journal = next((folder / 'results').rglob('session.json'))
                    with patch('sys.argv', ['migrate.py', '--resume', str(journal)]), \
                         patch('builtins.input', side_effect=['RESUME']) as read:
                        wizard.main()
                    read.assert_called_once()
                    self.assertEqual(approvals.call_count, 2)
                    self.assertEqual(created, ['8.8.8.8', '1.1.1.1'])
                    self.assertEqual(finished, {'relay', 'deploy'})
                    self.assertTrue(json.loads(journal.read_text())['done'])

    def test_cleanup_wizard_resumes_same_plan_and_same_job(self):
        key = self.directory / 'key'
        key.write_text('FAKE KEY')
        answers = ['4', '3', str(self.directory / 'results'), '8.8.8.8', '22', str(key),
                   '1', '2', 'PLAN 8.8.8.8', '1', 'DELETE 8.8.8.8']
        inventory = {'containers': [{'name': 'unused', 'id': 'one', 'image': 'image',
            'running': False, 'protected': False, 'auto_remove': False}], 'packages': []}
        plan = {'fingerprint': 'exact-plan', 'operation': {'containers': [{'name': 'unused'}],
                                                        'transaction': {'removals': []}}}
        documents = {'maintenance-plan.json': inventory, 'cleanup-plan.json': plan,
                     'maintenance-result.json': {'success': True}}
        def download(host, source, target):
            c.write(target, documents[source.rsplit('/', 1)[-1]])
        prepared = Mock(return_value='/root/vps-transfer/cleanup')
        def prepare(*args):
            return session.checkpoint('test-cleanup-prepare', prepared)
        with patch.object(wizard, 'prepare', side_effect=prepare), \
             patch.object(wizard, 'background_action', side_effect=[KeyboardInterrupt(), None]), \
             patch.object(wizard.Connection, 'ssh', return_value=b'0'), \
             patch.object(wizard.Connection, 'upload'), patch.object(wizard.Connection, 'download', download), \
             patch.object(maintenance, 'download_backups', return_value=[]), \
             patch.object(wizard.shutil, 'which', return_value='tool'), \
             patch('sys.stdout', new_callable=io.StringIO), patch('sys.stderr', new_callable=io.StringIO):
            with patch('sys.argv', ['migrate.py']), patch('builtins.input', side_effect=answers):
                with self.assertRaises(KeyboardInterrupt):
                    wizard.main()
            journal = next((self.directory / 'results').rglob('session.json'))
            with patch('sys.argv', ['migrate.py', '--resume', str(journal)]), \
                 patch('builtins.input', side_effect=['RESUME']):
                wizard.main()
            prepared.assert_called_once()
            self.assertTrue(json.loads(journal.read_text())['done'])

    def test_successful_upload_is_not_repeated_during_replay(self):
        key = self.directory / 'key'
        key.write_text('FAKE KEY')
        source = self.directory / 'archive'
        source.write_bytes(b'archive contents')
        host = wizard.Connection('8.8.8.8', 22, key)
        original = session.Session()
        with patch.object(host, 'ssh'), patch.object(wizard.subprocess, 'run') as send:
            with session.active(original):
                original.attach(self.directory)
                host.upload(source, '/root/vps-transfer/job/archive')
            resumed = session.Session(original.path)
            with session.active(resumed):
                host.upload(source, '/root/vps-transfer/job/archive')
            send.assert_called_once()

    def test_wrong_confirmation_is_not_replayed_as_permission(self):
        original = session.Session()
        with session.active(original):
            original.attach(self.directory)
            self.assertEqual(original.prompt('UPGRADE 8.8.8.8', None, lambda *args: 'NO'), 'NO')
        resumed = session.Session(original.path)
        with session.active(resumed):
            read = Mock(return_value='UPGRADE 8.8.8.8')
            self.assertEqual(resumed.prompt('UPGRADE 8.8.8.8', None, read), 'UPGRADE 8.8.8.8')
            read.assert_called_once()

    def test_download_failure_preserves_previous_complete_file(self):
        key = self.directory / 'key'
        key.write_text('FAKE KEY')
        host = wizard.Connection('8.8.8.8', 22, key)
        target = self.directory / 'backup.tar.gz'
        target.write_bytes(b'previous complete copy')
        with patch.object(host, 'ssh', return_value=b'abc  archive'), \
             patch.object(wizard.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'scp')):
            with self.assertRaises(subprocess.CalledProcessError):
                host.download('/root/archive', target)
        self.assertEqual(target.read_bytes(), b'previous complete copy')

    def test_remote_execution_claim_prevents_repetition_after_failure(self):
        job = self.directory / 'job'
        job.mkdir()
        lock = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=Mock())
        real_read = Path.read_text
        def read(path, *args, **kwargs):
            if path.as_posix().endswith('/proc/sys/kernel/random/boot_id'):
                return 'boot-one'
            return real_read(path, *args, **kwargs)
        with patch.object(execution, 'BASE', self.directory), patch.dict(sys.modules, {'fcntl': lock}), \
             patch.object(Path, 'read_text', read):
            with self.assertRaisesRegex(RuntimeError, 'partial failure'):
                with execution.claim(job, 'deploy'):
                    raise RuntimeError('partial failure')
            with self.assertRaises(execution.AlreadyStarted):
                with execution.claim(job, 'deploy'):
                    self.fail('must never execute twice')
        self.assertEqual(json.loads((job / 'deploy-execution.json').read_text())['phase'], 'failed')


if __name__ == '__main__':
    unittest.main()
