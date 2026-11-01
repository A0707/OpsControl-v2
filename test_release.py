"""Déploiement : manifeste vérifié, releases versionnées, bascule atomique, rollback."""
import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
from testing_tools import run_tool, shell_path
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE / 'deploy'))
import release  # noqa: E402


class FakeLinks(release.Links):
    """Liens simulés par des fichiers texte (Windows sans privilège de lien symbolique)."""

    def point(self, link, target):
        tmp = link.with_name('.' + link.name + '.tmp')
        tmp.write_text(target, encoding='utf-8')
        os.replace(tmp, link.with_name(link.name + '.link'))

    def read(self, link):
        path = link.with_name(link.name + '.link')
        return path.read_text(encoding='utf-8') if path.is_file() else None

    def share(self, link, target):
        link.with_name(link.name + '.shared').write_text(str(target), encoding='utf-8')


def build_archive(root: Path, files: dict) -> Path:
    src = root / 'infraops'
    for rel, content in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_bytes(content.encode())
    manifest = ''.join(f'{hashlib.sha256((src / rel).read_bytes()).hexdigest()}  {rel}\n' for rel in sorted(files))
    (src / 'MANIFEST.sha256').write_text(manifest, encoding='utf-8')
    return src


CODE = {'app.py': 'print("v1")\n', 'requirements.txt': 'fastapi\n', 'web/index.html': '<html></html>',
        'deploy/release.py': '# copie\n', 'hosts.yaml': 'hosts: [archive]\n', 'data/state.sqlite3': 'archive-db',
        'ssh/known_hosts': 'archive-known-hosts'}


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src = build_archive(self.tmp, CODE)

    def test_valid_archive(self):
        result = release.verify(self.src)
        self.assertEqual(result['files'], len(CODE))
        self.assertEqual(len(result['manifest_sha256']), 64)

    def test_modified_file_refused(self):
        (self.src / 'app.py').write_text('print("pirate")\n')
        with self.assertRaisesRegex(release.ReleaseError, 'empreinte différente : app.py'):
            release.verify(self.src)

    def test_unlisted_file_refused(self):
        (self.src / 'web' / 'extra.js').write_text('alert(1)')
        with self.assertRaisesRegex(release.ReleaseError, 'hors manifeste : web/extra.js'):
            release.verify(self.src)

    def test_missing_file_and_manifest(self):
        (self.src / 'requirements.txt').unlink()
        with self.assertRaisesRegex(release.ReleaseError, 'manquant : requirements.txt'):
            release.verify(self.src)
        (self.src / 'MANIFEST.sha256').unlink()
        with self.assertRaisesRegex(release.ReleaseError, 'absent'):
            release.verify(self.src)

    def test_path_traversal_and_malformed_lines(self):
        for line in ('0' * 64 + '  ../etc/passwd', '0' * 64 + '  /etc/passwd', 'zz  app.py', '0' * 64 + ' app.py'):
            (self.src / 'MANIFEST.sha256').write_text(line + '\n')
            with self.assertRaises(release.ReleaseError, msg=line):
                release.verify(self.src)

    def test_archive_digest_checked(self):
        archive = self.tmp / 'a.tar.gz'
        archive.write_bytes(b'archive')
        release.verify(self.src, archive, hashlib.sha256(b'archive').hexdigest())
        with self.assertRaisesRegex(release.ReleaseError, 'Empreinte de l’archive incorrecte'):
            release.verify(self.src, archive, '0' * 64)

    def test_cli_refuses_with_nonzero_exit(self):
        (self.src / 'app.py').write_text('modifié')
        self.assertEqual(release.main(['verify', str(self.src)]), 2)


class StageActivateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.src = build_archive(self.tmp / 'a', CODE)
        self.dest = self.tmp / 'opt'
        (self.dest / 'data').mkdir(parents=True)
        (self.dest / 'data' / 'state.sqlite3').write_text('PRODUCTION-DB')
        (self.dest / 'hosts.yaml').write_text('hosts: [production]\n')
        self.links = FakeLinks()
        self.calls = []

    def stage(self, minute=0):
        return release.stage(self.src, self.dest, self.links, now=datetime(2026, 9, 29, 10, minute, tzinfo=timezone.utc))

    def test_stage_copies_code_only_and_never_touches_shared_data(self):
        rid = self.stage()
        rel = self.dest / 'releases' / rid
        self.assertTrue((rel / 'app.py').is_file())
        self.assertTrue((rel / 'RELEASE').is_file())
        for persistent in ('hosts.yaml', 'data/state.sqlite3', 'ssh/known_hosts'):
            self.assertFalse((rel / persistent).exists(), persistent)
        self.assertEqual((self.dest / 'data' / 'state.sqlite3').read_text(), 'PRODUCTION-DB')
        self.assertEqual((self.dest / 'hosts.yaml').read_text(), 'hosts: [production]\n')
        self.assertTrue((rel / 'data.shared').is_file() and (rel / 'hosts.yaml.shared').is_file())
        self.assertFalse(any(p.name.endswith('.partial') for p in (self.dest / 'releases').iterdir()))

    def test_stage_refuses_bad_archive_without_creating_release(self):
        (self.src / 'app.py').write_text('modifié')
        with self.assertRaises(release.ReleaseError):
            self.stage()
        self.assertFalse((self.dest / 'releases').exists())

    def test_activate_healthy_keeps_previous(self):
        first = self.stage(0)
        release.activate(self.dest, first, lambda: self.calls.append('restart'), lambda: True, self.links)
        self.src = build_archive(self.tmp / 'b', {**CODE, 'app.py': 'print("v2")\n'})
        second = self.stage(1)
        result = release.activate(self.dest, second, lambda: self.calls.append('restart'), lambda: True, self.links)
        self.assertEqual(result, {'active': second, 'previous': first, 'rolled_back': False})
        self.assertEqual(self.links.read(self.dest / 'current'), 'releases/' + second)
        self.assertEqual((self.dest / 'releases' / '.previous').read_text(), first)

    def test_failed_start_rolls_back_automatically(self):
        first = self.stage(0)
        release.activate(self.dest, first, lambda: None, lambda: True, self.links)
        self.src = build_archive(self.tmp / 'b', {**CODE, 'app.py': 'cassé'})
        second = self.stage(1)
        health = iter([False, True])
        result = release.activate(self.dest, second, lambda: self.calls.append('restart'), lambda: next(health), self.links)
        self.assertTrue(result['rolled_back'])
        self.assertTrue(result['restored_healthy'])
        self.assertEqual(result['active'], first)
        self.assertEqual(self.links.read(self.dest / 'current'), 'releases/' + first)
        self.assertEqual(self.calls, ['restart', 'restart'])
        self.assertTrue((self.dest / 'releases' / second).is_dir(), 'release en échec conservée pour analyse')

    def test_restart_exception_also_rolls_back(self):
        first = self.stage(0)
        release.activate(self.dest, first, lambda: None, lambda: True, self.links)
        self.src = build_archive(self.tmp / 'b', {**CODE, 'app.py': 'v3'})
        second = self.stage(1)
        state = {'n': 0}

        def restart():
            state['n'] += 1
            if state['n'] == 1:
                raise RuntimeError('systemctl a échoué')
        result = release.activate(self.dest, second, restart, lambda: True, self.links)
        self.assertTrue(result['rolled_back'])

    def test_failed_first_install_without_previous_is_reported(self):
        rid = self.stage()
        with self.assertRaisesRegex(release.ReleaseError, 'aucune release précédente'):
            release.activate(self.dest, rid, lambda: None, lambda: False, self.links)

    def test_manual_rollback_and_prune(self):
        ids = []
        for minute in range(5):
            self.src = build_archive(self.tmp / f's{minute}', {**CODE, 'app.py': f'v{minute}'})
            ids.append(self.stage(minute))
            release.activate(self.dest, ids[-1], lambda: None, lambda: True, self.links)
        result = release.rollback(self.dest, lambda: None, lambda: True, self.links)
        self.assertEqual(result['active'], ids[3])
        removed = release.prune(self.dest, self.links, keep=2)
        remaining = sorted(p.name for p in (self.dest / 'releases').iterdir() if p.is_dir() and not p.name.startswith('.'))
        self.assertIn(ids[3], remaining)
        self.assertIn(ids[4], remaining, 'la release précédente est toujours conservée')
        self.assertTrue(removed)

    @unittest.skipIf(os.name == 'nt', 'Lien symbolique : privilège requis sous Windows')
    def test_real_symlink_switch_is_atomic(self):
        links = release.Links()
        first = release.stage(self.src, self.dest, links)
        release.activate(self.dest, first, lambda: None, lambda: True, links)
        self.assertTrue((self.dest / 'current').is_symlink())
        self.assertTrue((self.dest / 'current' / 'app.py').is_file())
        self.assertEqual((self.dest / 'current' / 'hosts.yaml').read_text(), 'hosts: [production]\n')


class ScriptTests(unittest.TestCase):
    script = (BASE / 'deploy/install-vm.sh').read_text(encoding='utf-8')

    def test_manifest_verified_before_any_change(self):
        verify = self.script.index('release.py" verify')
        for later in ('apt-get', 'useradd', 'install -d', 'cp -a', 'release.py" stage', 'systemctl'):
            self.assertLess(verify, self.script.index(later), later)

    def test_release_check_before_switch_and_no_destructive_sync(self):
        self.assertLess(self.script.index('--release-check'), self.script.index('release.py" activate'))
        self.assertNotIn('rsync -a --delete', self.script)
        self.assertNotRegex(self.script, r'rm -rf "\$DEST"(\s|$)')
        self.assertIn('[ ! -f "$DEST/.ssh/id_ed25519" ]', self.script)
        self.assertIn('INFRAOPS_TRUSTED_PROXY_SECRET', self.script)

    def test_backup_before_switch_passes_valid_arguments(self):
        # « --db"$DEST/…" » formait un seul argument inconnu : argparse sortait en 2 et
        # l'installation était annulée sur toute VM ayant déjà une base.
        import shlex
        start = self.script.index('deploy/backup_state.py"') + len('deploy/backup_state.py"')
        command = self.script[start:self.script.index('; then', start)].replace('\\\n', ' ')
        args = shlex.split(command)
        options = [a for a in args if a.startswith('-')]
        self.assertEqual(options, ['--base', '--db', '--dest', '--tag'], args)
        self.assertEqual(len(args), 2 * len(options), 'chaque option suivie de sa valeur')
        self.assertNotRegex(self.script, r'\s--[a-z][a-z-]*"\$', 'option collée à sa valeur')

    def test_service_account_cannot_modify_code(self):
        # OC-AUDIT-007 : racine, releases et lien current à root ; seul l'état reste au service.
        self.assertIn('install -d -o root -g "$SVC" -m 1770 "$DEST"', self.script)
        self.assertIn('install -d -o root -g "$SVC" -m 0750 "$DEST/releases"', self.script)
        self.assertIn('chown -R root:"$SVC" "$DEST/releases"', self.script)
        self.assertNotRegex(self.script, r'chown -R "\$SVC:\$SVC" "\$(REL|DEST/releases|DEST)"')
        self.assertNotRegex(self.script, r'install -d -o "\$SVC"[^\n]*"\$DEST"( |\n)')
        self.assertLess(self.script.index('chown -R root:"$SVC" "$DEST/releases"'), self.script.index('--release-check'))
        unit = (BASE / 'deploy/infraops.service').read_text(encoding='utf-8')
        self.assertIn('ReadOnlyPaths=/opt/infraops/releases', unit)

    def test_data_takeover_stops_service_and_drops_stale_wal(self):
        # OC-AUDIT-022 : reprise sous service arrêté, sauvegarde avant remplacement, ni -wal ni -shm anciens.
        takeover = self.script[self.script.index('== 3/9'):self.script.index('== 4/9')]
        stop, save = takeover.index('systemctl stop "$SVC"'), takeover.index('cp -a "$DEST/data" "$SAUVE"')
        drop, copy = takeover.index('rm -f "$DEST/data/state.sqlite3-wal" "$DEST/data/state.sqlite3-shm"'), \
            takeover.index('cp -a "$f" "$DEST/data/$b"')
        self.assertLess(stop, save)
        self.assertLess(save, drop)
        self.assertLess(drop, copy)
        self.assertIn('*.sqlite3-wal|*.sqlite3-shm|*.lock) continue', takeover)

    def test_linux_files_use_lf(self):
        # Règle du dépôt : fichiers exécutés sous Linux en LF, y compris la copie de travail.
        files = [*BASE.glob('deploy/*.sh'), *BASE.glob('deploy/*.service'), *BASE.glob('deploy/*.timer')]
        self.assertTrue(files)
        crlf = [p.name for p in files if b'\r\n' in p.read_bytes()]
        self.assertEqual(crlf, [])

    def test_bash_syntax(self):
        bash = shell_path(self)
        result = run_tool(self, [bash, '-n', str(BASE / 'deploy/install-vm.sh')], kind='bash', capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_service_uses_current_release_and_shared_data(self):
        unit = (BASE / 'deploy/infraops.service').read_text(encoding='utf-8')
        self.assertIn('WorkingDirectory=/opt/infraops/current', unit)
        self.assertIn('/opt/infraops/current/.venv/bin/uvicorn', unit)
        self.assertIn('COCKPIT_DB=/opt/infraops/data/state.sqlite3', unit)
        self.assertIn('COCKPIT_AUDIT=/opt/infraops/audit.log', unit)
        self.assertIn('INFRAOPS_ALLOWED_HOSTS=', unit)
        self.assertIn('INFRAOPS_DEFAULT_ROLE=viewer', unit)
        self.assertIn('--workers 1', unit, 'jobs et verrous en mémoire : un seul worker')

    def test_nginx_overrides_identity_headers(self):
        conf = (BASE / 'deploy/nginx-infraops.conf').read_text(encoding='utf-8')
        self.assertEqual(conf.count('proxy_set_header X-OpsControl-User $ops_user;'), 2)
        self.assertEqual(conf.count('include /etc/nginx/snippets/infraops-proxy-secret.conf;'), 2)
        self.assertIn('proxy_set_header X-OpsControl-User "";', conf)
        self.assertEqual(conf.count('proxy_set_header X-Request-ID $request_id;'), 2)
        # IP cliente de l'audit : X-Forwarded-For écrasé dans chaque emplacement proxifié.
        self.assertEqual(conf.count('proxy_set_header X-Forwarded-For $remote_addr;'), conf.count('proxy_pass http://127.0.0.1:8000;'))
        self.assertIn('Strict-Transport-Security', conf)
        self.assertIn('return 301 https://', conf)

    def test_package_contains_what_release_check_needs(self):
        packaging = (BASE / 'deploy/package_vm.py').read_text(encoding='utf-8')
        self.assertIn("'web/assets/*'", packaging)
        html = (BASE / 'web/index.html').read_text(encoding='utf-8')
        self.assertTrue(all((BASE / 'web' / ref).is_file() for ref in re.findall(r'(?:src|href)="/([^"?]+)', html)))


class AtomicWriteTests(unittest.TestCase):
    def test_write_follows_shared_link_target(self):
        import management
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        target = tmp / 'shared' / 'hosts.yaml'
        target.parent.mkdir()
        target.write_text('{}')
        link = tmp / 'release' / 'hosts.yaml'
        link.parent.mkdir()
        try:
            os.symlink(target, link)
        except OSError:
            self.skipTest('Lien symbolique : privilège requis')
        management.atomic_json(link, {'hosts': []})
        self.assertTrue(link.is_symlink(), 'le lien vers les données partagées est préservé')
        self.assertIn('hosts', target.read_text())


class ReleaseCheckTests(unittest.TestCase):
    def test_current_tree_passes_release_check(self):
        result = subprocess.run([sys.executable, str(BASE / 'deploy/preflight.py'), '--release-check'],
                                capture_output=True, text=True, timeout=300, cwd=BASE,
                                env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
        self.assertEqual(result.returncode, 0, result.stdout[-800:] + result.stderr[-800:])
        self.assertIn('Release valide', result.stdout)

    def test_syntax_check_writes_nothing_and_reports_errors(self):
        # py_compile(cfile=/dev/null) levait FileExistsError sous Linux : le contrôle
        # se fait désormais en mémoire, identique sur les deux systèmes.
        import preflight
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / 'ok.py').write_text('x = 1\n', encoding='utf-8')
        (tmp / 'ko.py').write_text('def f(:\n', encoding='utf-8')
        (tmp / 'nul.py').write_bytes(b'x = 1\x00\n')
        errors = preflight.syntax_errors(sorted(tmp.glob('*.py')))
        self.assertEqual([e.split(':')[0] for e in errors], ['ko.py', 'nul.py'])
        self.assertIn('ligne 1', errors[0])
        self.assertEqual(sorted(p.name for p in tmp.iterdir()), ['ko.py', 'nul.py', 'ok.py'], 'aucun .pyc écrit')
        self.assertNotIn('py_compile.compile', (BASE / 'deploy/preflight.py').read_text(encoding='utf-8'))

    def test_release_check_imports_app_on_a_database_copy(self):
        source = (BASE / 'deploy/preflight.py').read_text(encoding='utf-8')
        check = source[source.index('def release_check'):source.index('def main')]
        self.assertLess(check.index("os.environ['COCKPIT_DB'] = str(copie)"), check.index('import app'))
        self.assertIn("mode=ro", check)


if __name__ == '__main__':
    unittest.main()
