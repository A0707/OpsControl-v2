"""Script de lecture bornée (deploy/remote/infraops-read.sh) et règles sudoers associées."""
import re
from testing_tools import run_tool, shell_path
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
SCRIPT = BASE / 'deploy/remote/infraops-read.sh'
SUDOERS = BASE / 'deploy/remote/sudoers-infraops'


class ReaderRefusalTests(unittest.TestCase):
    """Refus vérifiables sans arborescence Apache : opération, taille, chemin hors périmètre."""

    def setUp(self):
        self.bash = shell_path(self)

    def run_reader(self, *args):
        return run_tool(self, [self.bash, str(SCRIPT), *args], kind='bash',
                        capture_output=True, text=True, timeout=20)

    def test_syntaxe(self):
        self.assertEqual(run_tool(self, [self.bash, '-n', str(SCRIPT)], kind='bash').returncode, 0)

    def test_operations_et_tailles_refusees(self):
        for args in (('cat', '/etc/passwd'), ('rm', '1', '/x'), ('head', '0', '/etc/passwd'),
                     ('head', '262145', '/etc/passwd'), ('tail', '-5', '/etc/passwd'),
                     ('tail', '16777217', '/etc/passwd'), ('tail', '123456789', '/etc/passwd'),
                     ('head', '1', '/etc/passwd', 'en-trop'), ('cert',)):
            with self.subTest(args=args):
                r = self.run_reader(*args)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(r.stdout, '', 'rien ne doit être lu')

    def test_chemins_hors_perimetre_refuses(self):
        # /etc/passwd existe (Linux, Git Bash) : refusé pour son chemin, pas pour son absence.
        for args in (('head', '100', '/etc/passwd'), ('tail', '100', '/etc/passwd'),
                     ('head', '100', '/etc/apache2/../passwd'), ('cert', '/etc/passwd')):
            with self.subTest(args=args):
                r = self.run_reader(*args)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(r.stdout, '')


class ScriptPolicyTests(unittest.TestCase):
    def test_fins_de_ligne_unix(self):
        for f in (SCRIPT, SUDOERS):
            self.assertNotIn(b'\r\n', f.read_bytes(), f.name)

    def test_perimetres(self):
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertIn('realpath -e', text, 'chemin réel vérifié avant lecture')
        self.assertIn('PRIVATE KEY', text, 'refus des fichiers de clé')
        self.assertIn('MAX_BYTES=262144', text)

    def test_limite_tail_compatible_avec_la_sonde_apache(self):
        # Audit CON-03 : la sonde demande 16 Mio d'access.log et 8 Mio d'error.log au lecteur borné.
        import re
        import apache_probe
        limite = int(re.search(r'MAX_TAIL_BYTES=(\d+)', SCRIPT.read_text(encoding='utf-8'))[1])
        self.assertGreaterEqual(limite, apache_probe.ACCESS_BYTES_PER_FILE)
        self.assertGreaterEqual(limite, apache_probe.ERROR_BYTES)

    def test_sudoers_sans_joker_dans_les_arguments(self):
        regles = ' '.join(l for l in SUDOERS.read_text(encoding='utf-8').splitlines() if not l.lstrip().startswith('#'))
        self.assertNotIn('*', regles, '« * » accepterait espaces et « .. » dans les arguments')
        for interdit in ('/bin/tail', '/bin/head', '/bin/cat', '/bin/openssl', 'ALL=(ALL)', 'NOPASSWD: ALL'):
            self.assertNotIn(interdit, regles)
        self.assertIn('/usr/local/sbin/infraops-read', regles)

    def test_sondes_ne_lisent_plus_en_direct(self):
        for name in ('waf_probe.py', 'apache_probe.py'):
            code = (BASE / name).read_text(encoding='utf-8')
            self.assertIsNone(re.search(r"'sudo', '-n', '(head|tail)'", code), name)
            self.assertIn('/usr/local/sbin/infraops-read', code)


if __name__ == '__main__':
    unittest.main()
