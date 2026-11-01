import contextlib
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
import waf_findings as wf
import waf_probe


class WafFindingsTests(unittest.TestCase):
    def test_expiry_boundaries(self):
        now=datetime(2026,9,13,tzinfo=timezone.utc)
        for days,expected in [(-1,'critical'),(0,'critical'),(7,'critical'),(8,'warning'),(30,'warning'),(31,'observed')]:
            cert={'not_before':(now-timedelta(days=300)).isoformat(),'not_after':(now+timedelta(days=days)).isoformat()}
            self.assertEqual(wf.expiry(cert,now)['severity'],expected)
        self.assertEqual(wf.expiry({},now)['severity'],'unknown')
        self.assertEqual(wf.expiry({'not_before':(now+timedelta(days=1)).isoformat(),'not_after':(now+timedelta(days=40)).isoformat()},now)['expiration_state'],'Pas encore valide')

    def test_command_validation_and_whitelist_scope(self):
        for ip in ('1.2.3.4;id','192.0.2.0/24','$(id)','fe80::1%eth0','999.1.1.1'):
            with self.assertRaises(ValueError):wf.command_plan(ip,'ban','10.77.0.131')
        result=wf.command_plan('2001:db8::1','whitelist','10.77.0.131')
        self.assertEqual(len(result['commands']),2)
        self.assertIn('addignoreip',result['commands'][0])
        self.assertIn('unbanip',result['commands'][1])
        self.assertFalse(result['executable'])
        self.assertIn('Non persistante',result['note'])
        self.assertEqual(result['execution_host'],'10.77.0.131')

    def test_findings_propagate_without_marking_stale_critical(self):
        cert={'path':'/etc/ssl/example.pem','not_before':'2020-01-01T00:00:00+00:00','not_after':'2021-01-01T00:00:00+00:00'}
        row={'status':'unknown','findings':[],'ip':'10.77.0.131','waf':{'sections':{'certificates':{'data':{'certificates':[cert]}}}}}
        wf.decorate(row)
        self.assertEqual(row['status'],'critical')
        self.assertTrue(any(f['id'].startswith('waf:tls:') for f in row['findings']))
        size=len(row['findings']);wf.decorate(row);self.assertEqual(len(row['findings']),size)
        row.update(stale=True,status='unknown');wf.decorate(row);self.assertEqual(row['status'],'unknown')

    def test_declared_certificate_is_not_presented_as_served(self):
        # Audit UI du 31/10 (fiche 11.2) : un fichier expiré n'est pas le certificat servi ;
        # la vérification SNI est fournie en texte à copier, jamais exécutée.
        cert={'path':'/etc/ssl/pay.pem','subject':'CN = pay.exemple.ma','not_before':'2020-01-01T00:00:00+00:00','not_after':'2021-01-01T00:00:00+00:00'}
        row={'status':'unknown','findings':[],'ip':'10.77.0.131','waf':{'sections':{'certificates':{'data':{'certificates':[cert]}}}}}
        wf.decorate(row)
        tls=next(f for f in row['findings'] if f['id'].startswith('waf:tls:'))
        self.assertTrue(tls['title'].startswith('Certificat déclaré (fichier)'))
        self.assertIn('certificat réellement servi : non mesuré',tls['evidence'])
        self.assertIn('-servername pay.exemple.ma',tls['check_command'])
        self.assertFalse(tls['executable'])
        self.assertIsNone(wf.server_name('O = Exemple'))

    def test_certificate_probe_reads_public_metadata_only(self):
        commands=[]
        def fake_glob(pattern):
            return ['/etc/apache2/sites-enabled/demo.conf'] if pattern=='/etc/apache2/sites-enabled/*' else []
        def run(args,**kwargs):
            commands.append(args)
            if args[-1]=='/etc/apache2/sites-enabled/demo.conf':
                out='SSLCertificateFile "/etc/ssl/demo cert.pem"\nSSLCertificateKeyFile /etc/ssl/private/secret.key\n'
            elif 'x509' in args:
                out='notBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Jan  1 00:00:00 2027 GMT\nsubject=CN=example.test\nissuer=CN=Issuer\nserial=123\nsha256 Fingerprint=AB:CD'
            else:return SimpleNamespace(returncode=1,stdout='',stderr='missing')
            return SimpleNamespace(returncode=0,stdout=out,stderr='')
        capture=io.StringIO()
        with patch.object(waf_probe.glob,'glob',side_effect=fake_glob),patch.object(waf_probe.subprocess,'run',side_effect=run),contextlib.redirect_stdout(capture):
            waf_probe.main()
        payload=json.loads(capture.getvalue())
        cert=payload['sections']['certificates']['data']['certificates'][0]
        self.assertEqual(cert['not_after'],'2027-01-01T00:00:00+00:00')
        self.assertEqual(cert['path'],'/etc/ssl/demo cert.pem')
        self.assertNotIn('/etc/ssl/private/secret.key',str(commands))
        self.assertNotIn('secret.key',json.dumps(payload))


if __name__=='__main__':unittest.main()
