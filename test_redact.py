"""Masquage des secrets dans les preuves (audit_engine.redact) et champs SSH locaux retirés."""
import unittest

from audit_engine import redact
from payload_slim import slim, without_local_ssh


class RedactTests(unittest.TestCase):
    SECRETS = {
        'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def': 'eyJhbGciOiJIUzI1NiJ9',
        'curl -H "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==" https://x': 'dXNlcjpwYXNzd29yZDEyMw',
        '0 2 * * * mysqldump -uroot -pS3cretPwd base > /bak.sql': 'S3cretPwd',
        '/usr/bin/mysql -h db -u app -pAutreSecret -e "select 1"': 'AutreSecret',
        'outil --password Hunter2xx --verbose': 'Hunter2xx',
        'client --token abcdef123456': 'abcdef123456',
        'sshpass -p MonSecret ssh hote': 'MonSecret',
        'curl -u admin:Pa55word https://x': 'Pa55word',
        'curl --user admin:Pa55word https://x': 'Pa55word',
        'PGPASSWORD=abc123 psql': 'abc123',
        'https://compte:motdepasse@depot.example/x': 'motdepasse',
    }

    def test_secrets_masques(self):
        for texte, secret in self.SECRETS.items():
            with self.subTest(texte=texte):
                self.assertNotIn(secret, redact(texte))
                self.assertIn('[MASQUÉ]', redact(texte))

    def test_textes_ordinaires_inchanges(self):
        for texte in ('Basic configuration loaded', 'ps -p 1234 -o pid', 'sort -u fichier',
                      'ls --pass-through', 'mysql -p', 'Bearer court', 'systemctl status nginx'):
            with self.subTest(texte=texte):
                self.assertEqual(redact(texte), texte)


class LocalSshFieldsTests(unittest.TestCase):
    HOST = {'key': 'h', 'name': 'h', 'ip': '10.0.0.1', 'user': 'svc', 'port': 22,
            'key_path': 'C:/Users/x/.ssh/id_rsa', 'ssh_config': 'C:/Users/x/.ssh/config', 'ssh_host': 'alias'}

    def test_retires_des_listes_et_de_la_fiche(self):
        for vue in (slim(self.HOST), without_local_ssh(self.HOST)):
            for champ in ('key_path', 'ssh_config', 'ssh_host'):
                self.assertNotIn(champ, vue)
            self.assertEqual(vue['user'], 'svc')


if __name__ == '__main__':
    unittest.main()
