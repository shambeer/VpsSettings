import base64
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vps_migration.core import common as c
from vps_migration.core.selfsteal_options import validate
from vps_migration.server import selfsteal, relay
from vps_migration.server.selfsteal_features import install, profiles, subscriptions, warp, certificates
from vps_migration.cli.selfsteal import site_archive


class FullSelfStealTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[3] / 'private-vpn/server-settings/tools/test-runtime'
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temporary.name)
        self.request = {'domain': 'entry.example.org', 'ip': '1.1.1.1', 'self_steal': True,
                        'full_selfsteal': True, 'warp_terms_accepted': True}
        self.state = {'private_key': 'server-private', 'public_key': 'server-public', 'short_id': 'abcdef1234567890',
                      'warp_path': '/warp-route', 'session_id_table': 'abcdefgh............',
                      'server_names': ['entry.example.org'], 'warp': True, 'reality': True, 'subscriptions': True}
        self.clients = [{'id': 'personal-id', 'email': 'personal@local'}, {'id': 'shared-id', 'email': 'shared@local'}]

    def tearDown(self):
        self.temporary.cleanup()

    def registration(self):
        return {'private_key': base64.b64encode(bytes(range(32))).decode(),
            'config': {'client_id': 'AQID', 'interface': {'addresses': {'v4': '172.16.0.2', 'v6': '2606:4700::2'}},
            'peers': [{'public_key': base64.b64encode(bytes(range(32, 64))).decode(),
                       'endpoint': {'host': '162.159.192.1:2408'}}]}}

    def test_only_warp_inbound_uses_warp_and_existing_clients_are_preserved(self):
        original = selfsteal.configuration(self.request, self.clients, '/route/')
        before = copy.deepcopy(original)
        outbound = warp.outbound(self.registration())
        enhanced = install.enhance(original, self.state, validate(), outbound)
        self.assertEqual(original, before)
        self.assertEqual(enhanced['inbounds'][0]['settings']['clients'], before['inbounds'][0]['settings']['clients'])
        self.assertEqual(enhanced['outbounds'][0]['protocol'], 'freedom')
        self.assertEqual(enhanced['routing']['rules'], [{'type': 'field', 'inboundTag': ['selfsteal-warp'],
                                                       'outboundTag': 'selfsteal-warp-out'}])
        self.assertTrue(enhanced['outbounds'][1]['settings']['noKernelTun'])
        reality = next(item for item in enhanced['inbounds'] if item['tag'] == 'selfsteal-reality')
        self.assertEqual(reality['streamSettings']['realitySettings']['target'], 'vpn-selfsteal-site:8443')
        self.assertNotIn('amnezia', json.dumps(enhanced))

    def test_all_six_profiles_share_compatible_settings_without_server_secrets(self):
        enhanced = install.enhance(selfsteal.configuration(self.request, self.clients, '/route/'),
                                   self.state, validate(), warp.outbound(self.registration()))
        xhttp = enhanced['inbounds'][1]['streamSettings']['xhttpSettings']
        for kind in ['tls', 'tls-xhttp', 'tls-warp', 'reality', 'reality-xhttp', 'reality-warp']:
            client = profiles.client('personal-id', self.request, kind, self.state, xhttp)
            uri = profiles.uri('personal-id', self.request, 'personal', kind, self.state, xhttp)
            self.assertNotIn('server-private', json.dumps(client) + uri)
            self.assertNotIn('allowInsecure', json.dumps(client))
            stream = client['outbounds'][0]['streamSettings']
            if kind.endswith('xhttp'):
                self.assertEqual(stream['xhttpSettings'], xhttp)
                self.assertIn('extra=', uri)
            if kind.endswith('warp'):
                self.assertIn('headerType=http', uri)
                self.assertNotIn('flow', client['outbounds'][0]['settings']['vnext'][0]['users'][0])
        self.assertEqual(len(profiles.checks(self.request)), 7)

    def test_repeated_enhancement_does_not_duplicate_inbounds_or_outbounds(self):
        config = selfsteal.configuration(self.request, self.clients, '/route/')
        options = validate()
        outbound = warp.outbound(self.registration())
        once = install.enhance(config, self.state, options, outbound)
        twice = install.enhance(once, self.state, options, outbound)
        self.assertEqual(once, twice)

    def test_warp_is_optional_and_cannot_be_substituted_by_direct(self):
        options = validate({'warp': False, 'reality': False})
        config = install.enhance(selfsteal.configuration(self.request, self.clients, '/route/'), self.state, options, None)
        self.assertEqual(len(config['inbounds']), 2)
        self.assertEqual(len(config['outbounds']), 1)
        with self.assertRaises(RuntimeError), patch.object(warp, 'urlopen') as send:
            warp.register({**self.request, 'warp_terms_accepted': False})
        send.assert_not_called()

    def test_public_ports_keep_amnezia_and_include_new_reality_in_relay(self):
        original = {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}
        self.assertEqual(c.exposure_bindings('amnezia-xray', original, self.request), original)
        edge = c.exposure_bindings('vpn-edge', original, self.request)
        self.assertEqual(edge['443/tcp'][0]['HostPort'], '8443')
        self.assertEqual(edge['444/tcp'][0]['HostPort'], '8444')
        selected = dict(relay.selected_ports({**self.request, 'network_profile': 'filtered'}))
        self.assertEqual(selected, {'tcp': [80, 443, 8443, 8444], 'udp': [8443]})

    def test_site_accepts_http2_on_default_fallback_and_keeps_tls_certificate(self):
        site = install.site_configuration(self.request, '/route/')
        self.assertEqual(site.count('http2 on;'), 2)
        self.assertIn('listen 8080; listen 8081;', site)
        self.assertIn('listen 8443 ssl;', site)
        self.assertIn('/etc/letsencrypt/live/entry.example.org/fullchain.pem', site)
        self.assertIn('location ^~ /route/', site)
        self.assertIn('location ~ /\\.', site)
        self.assertIn('access_log off;', site)
        self.assertIn('proxy_request_buffering off;', site)

    def test_subscriptions_are_separate_stable_and_deduplicate_links(self):
        with patch.object(c, 'ROOT', self.root):
            config = install.enhance(selfsteal.configuration(self.request, self.clients, '/route/'),
                                      self.state, validate(), warp.outbound(self.registration()))
            profiles.export(self.request, config, self.state)
            first = self.root / 'exports/personal/strings'
            original = (first / 'selfsteal-vless.txt').read_text().strip()
            c.write(first / 'duplicate.txt', original.split('#')[0] + '#different-label')
            locations = subscriptions.export(self.request, self.state, validate())
            tokens = copy.deepcopy(self.state['subscription_tokens'])
            subscriptions.export(self.request, self.state, validate())
            self.assertEqual(tokens, self.state['subscription_tokens'])
            self.assertNotEqual(tokens['personal'], tokens['shared'])
            payload = (self.root / 'exports/personal/subscriptions/base64.txt').read_text()
            links = base64.b64decode(payload).decode().splitlines()
            self.assertEqual(len(links), 6)
            self.assertIn('access_log off;', locations)
            self.assertTrue((first / 'subscription.txt').read_text().startswith('https://entry.example.org:8443/sub/'))
            routing = json.loads((self.root / 'exports/personal/subscriptions/happ-routing.json').read_text())
            self.assertNotIn('geosite:whitelist', routing['DirectSites'])
            enabled = subscriptions.routing(validate({'guide_whitelist': True}))
            self.assertIn('geosite:whitelist', enabled['DirectSites'])

    def test_invalid_options_and_injected_paths_are_rejected(self):
        for value in [[], {'unknown': True}, {'warp': 'yes'}, {'warp_path': '/a;return 200'},
                      {'xhttp': {'path': '/../private'}}, {'xhttp': {'unknown': 1}}, {'tls_port': 443}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)

    def test_warp_response_is_validated_without_revealing_registration(self):
        result = warp.outbound(self.registration())
        self.assertEqual(result['settings']['reserved'], [1, 2, 3])
        for endpoint in ['127.0.0.1:1234', 'https://example.org:443', 'user:password@example.org:443']:
            value = self.registration()
            value['config']['peers'][0]['endpoint']['host'] = endpoint
            with self.assertRaises(ValueError):
                warp.outbound(value)

    def test_registration_is_cached_per_server_and_pending_is_not_repeated(self):
        registration = self.registration()
        response = {'config': registration['config'], 'id': 'device', 'token': 'private-token'}
        pair = tuple(base64.urlsafe_b64encode(bytes(range(offset, offset + 32))).decode().rstrip('=') for offset in [0, 32])
        transport = Mock()
        transport.__enter__ = Mock(return_value=transport)
        transport.__exit__ = Mock(return_value=False)
        transport.read.return_value = json.dumps(response).encode()
        with patch.object(c, 'ROOT', self.root), patch.object(c, 'x25519_pair', return_value=pair), \
             patch.object(warp, 'urlopen', return_value=transport) as send:
            first = warp.register(self.request)
            self.assertEqual(warp.register(self.request), first)
            send.assert_called_once()
            warp.register({**self.request, 'ip': '8.8.8.8'})
            self.assertEqual(send.call_count, 2)
            self.assertEqual(len(list((self.root / 'config/selfsteal-features').glob('warp-*.json'))), 2)
        other = self.root / 'pending'
        with patch.object(c, 'ROOT', other), patch.object(c, 'x25519_pair', return_value=pair), \
             patch.object(warp, 'urlopen', side_effect=TimeoutError()) as send:
            with self.assertRaises(RuntimeError):
                warp.register(self.request)
            with self.assertRaises(RuntimeError):
                warp.register(self.request)
            send.assert_called_once()

    def test_old_core_is_rejected_before_warp_registration(self):
        with patch.object(c, 'ROOT', self.root), patch.object(c, 'run',
                return_value=SimpleNamespace(returncode=0, stdout=b'Xray 25.1.1')), \
                patch.object(warp, 'register') as register:
            with self.assertRaisesRegex(RuntimeError, '26.11.9'):
                install.install(self.request)
            register.assert_not_called()
        self.assertFalse((self.root / 'config/selfsteal-features/state.json').exists())

    def test_feature_install_checks_candidate_and_rolls_back_bad_nginx(self):
        for fail in [False, True]:
            with self.subTest(fail=fail):
                root = self.root / str(fail)
                job = self.root / ('job-' + str(fail))
                job.mkdir()
                original = selfsteal.configuration(self.request, self.clients, '/route/')
                site = root / 'config/selfsteal-site'
                target = root / 'config/selfsteal-xray/server.json'
                c.write(target, original)
                c.write(site / 'server.conf', selfsteal.site_configuration('/route/'))
                c.write(site / 'index.html', '<title>Welcome</title>')
                before_site = (site / 'server.conf').read_text()
                commands = []
                def run(arguments, *args, **kwargs):
                    commands.append(arguments)
                    if arguments[-1] == 'version':
                        return SimpleNamespace(returncode=0, stdout=b'Xray 26.11.9')
                    if fail and arguments[-2:] == ['nginx', '-t']:
                        raise RuntimeError('bad nginx')
                    return SimpleNamespace(returncode=0, stdout=b'')
                with patch.object(c, 'ROOT', root), patch.object(c, 'JOB', job), \
                     patch.object(c, 'x25519_pair', return_value=('private', 'public')), \
                     patch.object(c, 'run', side_effect=run), \
                     patch.object(warp, 'register', return_value=warp.outbound(self.registration())), \
                     patch.object(install.certificates, 'configure'):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, 'bad nginx'):
                            install.install(self.request)
                        self.assertEqual(json.loads(target.read_text()), original)
                        self.assertEqual((site / 'server.conf').read_text(), before_site)
                    else:
                        install.install(self.request)
                        self.assertEqual(len(json.loads(target.read_text())['inbounds']), 4)
                        state = json.loads((root / 'config/selfsteal-features/state.json').read_text())
                        self.assertEqual(len(state['subscription_tokens']), 2)
                        self.assertTrue(any('-test' in command for command in commands))
                        self.assertTrue((job / 'selfsteal-before-features.tar.gz').exists())

    def test_private_files_are_not_published_as_a_static_site(self):
        site = self.root / 'unsafe-site'
        site.mkdir()
        (site / 'index.html').write_text('public')
        (site / '.env').write_text('FAKE_SECRET=not-for-publication')
        output = self.root / 'output'
        output.mkdir()
        with self.assertRaises(ValueError):
            site_archive(output, {'site_directory': str(site)})

    def test_certbot_webroot_uses_supported_reconfiguration_flow(self):
        for version, expected in [('certbot 2.9.0', ['reconfigure']), ('certbot 2.1.0', ['--dry-run', '--force-renewal'])]:
            with self.subTest(version=version):
                job = self.root / version.replace(' ', '-')
                job.mkdir()
                calls = []
                def run(arguments, **kwargs):
                    calls.append(arguments)
                    return SimpleNamespace(returncode=0, stdout=version.encode())
                with patch.object(c, 'ROOT', job), patch.object(c, 'JOB', job), patch.object(c, 'run', side_effect=run):
                    certificates.configure(self.request)
                self.assertEqual(len(calls), len(expected) + 1)
                for command, option in zip(calls[1:], expected):
                    self.assertIn(option, command)
                    self.assertIn('--webroot-path', command)
                    self.assertIn('umask 022; exec "$@"', command)
                self.assertTrue(json.loads((job / 'certificate-webroot.json').read_text())['success'])

    def test_certbot_does_not_force_renewal_after_failed_dry_run(self):
        def run(arguments, **kwargs):
            if '--dry-run' in arguments:
                raise RuntimeError('challenge failed')
            return SimpleNamespace(returncode=0, stdout=b'certbot 2.1.0')
        with patch.object(c, 'ROOT', self.root), patch.object(c, 'JOB', self.root), \
             patch.object(c, 'run', side_effect=run) as execute:
            with self.assertRaisesRegex(RuntimeError, 'challenge failed'):
                certificates.configure(self.request)
        self.assertFalse(any('--force-renewal' in call.args[0] for call in execute.call_args_list))

    def test_custom_site_archive_is_local_and_checksum_protected(self):
        site = self.root / 'site'
        site.mkdir()
        (site / 'index.html').write_text('own static site')
        output = self.root / 'output'
        output.mkdir()
        archive = site_archive(output, {'site_directory': str(site)})
        self.assertEqual(c.checksum(Path(archive['path'])), archive['sha256'])
        self.assertTrue(Path(archive['path']).is_relative_to(output))


if __name__ == '__main__':
    unittest.main()
