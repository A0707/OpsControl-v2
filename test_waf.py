import contextlib
import io
import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import waf_probe
import waf_audit
import ssh


class WafTests(unittest.TestCase):
    def probe(self, invalid=False, denied=False):
        def fake_glob(pattern):
            if pattern.endswith('access.log'):return ['/var/log/apache2/access.log']
            if pattern.endswith('error.log'):return ['/var/log/apache2/error.log']
            return []
        def fake_run(args, **kwargs):
            out='';rc=0
            if denied:return SimpleNamespace(returncode=1,stdout='',stderr='denied')
            if 'systemctl' in args:out='LoadState=loaded\nActiveState=active\nSubState=running'
            elif '-M' in args:out=' security2_module (shared)'
            elif '-S' in args:out='*:443 example.test'
            elif 'status' in args:out='Currently banned: 1\nCurrently failed: 0\nTotal failed: 20\nTotal banned: 2\nBanned IP list: 2001:db8::1'
            elif 'get' in args:out='60'
            elif 'ss' in args:out='TCP: 8 (estab 2, closed 6)'
            elif 'cat' in args:out='100'
            elif 'iptables' in args:out='Chain INPUT (policy ACCEPT)\n12 40 DROP all -- * * 0/0 0/0'
            elif args[-1].endswith('access.log'):
                out='custom invalid log' if invalid else '192.0.2.1 - - [13/Sep/2026:12:00:00 +0000] "GET /login?token=PRIVATE HTTP/1.1" 503 10\n'
            elif args[-1].endswith('error.log'):
                out='[Sun Sep 13 12:00:00 2026] [client 192.0.2.1] ModSecurity: Access denied [id "942100"] Total Score: 9\n'
            return SimpleNamespace(returncode=rc,stdout=out,stderr='')
        capture=io.StringIO()
        with patch.object(waf_probe.glob,'glob',side_effect=fake_glob),patch.object(waf_probe.subprocess,'run',side_effect=fake_run),contextlib.redirect_stdout(capture):
            waf_probe.main()
        return json.loads(capture.getvalue())

    def test_samples_and_secrets(self):
        result=self.probe();s=result['sections']
        self.assertEqual(s['traffic']['data']['http_codes'],{'503':1})
        self.assertEqual(s['traffic']['data']['errors_5xx_pct'],100)
        self.assertEqual(s['modsecurity']['data']['rules'],[['942100',1]])
        self.assertEqual(s['fail2ban']['data']['banned_ips'],['2001:db8::1'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_denied_remains_unknown(self):
        s=self.probe(denied=True)['sections']
        self.assertEqual(s['fail2ban']['status'],'unknown')
        self.assertNotIn('data',s['maxretry'])
        self.assertEqual(s['traffic']['status'],'unknown')
        self.assertEqual(s['services']['status'],'unknown')

    def test_invalid_http_not_zero(self):
        self.assertEqual(self.probe(invalid=True)['sections']['traffic']['status'],'unknown')

    def test_no_ssh_no_probe(self):
        with patch.object(ssh,'run_operation') as runner:
            result=waf_audit.collect_waf({'ip':'10.77.0.131'},ssh.SSHConfig('test',''),{},'test')
        runner.assert_not_called();self.assertEqual(result['status'],'unknown')

    def test_payload_ne_peut_pas_imposer_horodatage_ni_statut(self):
        # Audit WAF-01 : la réponse distante ne doit ni rajeunir ni valider sa propre mesure.
        payload={'collected_at':'2099-01-01T00:00:00+00:00','status':'observed','coverage':{'measured':9,'total':9},
                 'sections':{'fail2ban':{'status':'unknown','data':{}}}}
        probe=ssh.RunResult(True,0,json.dumps(payload),'',1)
        with patch.object(ssh,'run_operation',return_value=probe),patch.object(waf_audit,'collect_apache',return_value={}):
            result=waf_audit.collect_waf({'ip':'10.77.0.131'},ssh.SSHConfig('test',''),{'ssh_user':'a','ssh_port':22},'test')
        self.assertNotEqual(result['collected_at'],'2099-01-01T00:00:00+00:00')
        self.assertEqual(result['status'],'unknown')
        self.assertEqual(result['coverage'],{'measured':0,'total':1})

    def test_fixed_operation(self):
        command=ssh.OPERATIONS['waf_detail']
        self.assertNotIn('StrictHostKeyChecking=no',command)
        self.assertNotIn('unbanip',command)
        self.assertNotIn('whois',command)


if __name__=='__main__':unittest.main()
