"""Critical latency, evidence clocks, concurrency and loss-of-source regressions."""
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, MagicMock, patch

from fastapi import FastAPI
import alert_center
import alert_policy
import critical_monitor
import management
from zabbix_inventory import problems, item_observed_at


class CriticalTests(unittest.TestCase):
    def test_fast_cycle_only_zabbix_honors_pause_and_does_not_overlap(self):
        context = SimpleNamespace(api_connections=lambda: [
            {'key': 'z', 'provider': 'Zabbix'}, {'key': 'p', 'provider': 'Proxmox'},
            {'key': 'missing', 'provider': 'Zabbix', 'auth_configured': False}],
            collect_api_connection=Mock(return_value={}))
        critical_monitor.install(context)
        with patch.object(critical_monitor.threading, 'Thread') as thread, \
             patch.object(critical_monitor, 'ThreadPoolExecutor') as pool:
            pool.return_value.__enter__.return_value.map.side_effect = lambda fn, keys: map(fn, keys)
            context.critical_tick(False, now=100)
            thread.assert_not_called()
            context.critical_tick(True, now=100)
            task = thread.call_args.kwargs
            self.assertEqual(task['args'], (['z'],))
            context.critical_tick(True, now=120)
            self.assertEqual(thread.call_count, 1)
            task['target'](*task['args'])
            context.collect_api_connection.assert_called_once_with('z')
            context.critical_tick(True, now=105)
            self.assertEqual(thread.call_count, 1)
            context.critical_tick(True, now=110)
            self.assertEqual(thread.call_count, 2)

    def test_item_clock_is_oldest_and_never_fetch_or_event_time(self):
        expected = datetime.fromtimestamp(100, timezone.utc).isoformat()
        self.assertEqual(item_observed_at([{'lastclock': '200'}, {'lastclock': '100'}]), expected)
        for items in (None, [], [{'lastclock': '0'}], [{'lastclock': '100'}, {}], [{'lastclock': 'bad'}]):
            self.assertIsNone(item_observed_at(items))
        pb = problems({'result': [{'triggerid': '1', 'lastchange': '50',
                                  'items': [{'lastclock': '100'}]}]})['problems'][0]
        self.assertEqual(pb['measurement_at'], expected)
        self.assertEqual(pb['last_change'], '50')

    def test_critical_carp_postgres_and_service_triggers(self):
        for text in ('CARP role changed to BACKUP', 'CARP split-brain',
                     'Inversion des rôles CARP', 'PostgreSQL service not running', 'nginx has stopped'):
            self.assertEqual(alert_policy.zabbix(text, 'critical')[0], 'critical', text)
        self.assertEqual(alert_policy.zabbix('Test trigger CARP role changed', 'critical')[0], 'info')

    def test_failed_or_old_poll_keeps_incident_but_removes_confirmation(self):
        now = datetime.now(timezone.utc)
        observed = now - timedelta(seconds=12)
        old_measure = now - timedelta(minutes=5)
        pb = {'description': 'PostgreSQL service not running', 'severity': 'critical',
              # Déclenchement récent : un trigger ouvert depuis 1970 serait « chronique »
              # (alert_center.CHRONIC_DAYS) et sortirait du compteur testé ici.
              'hosts': ['outside-inventory'], 'last_change': str(int(now.timestamp()) - 60),
              'measurement_at': old_measure.isoformat()}
        result = {'status': 'observed', 'collected_at': observed.isoformat(), 'inventory': {'problems': [pb]}}
        source = {'key': 'z', 'name': 'Zabbix', 'provider': 'Zabbix', 'last_result': result}
        context = SimpleNamespace(rows=lambda: [], api_connections=lambda: [source])
        alert = alert_center.build(context, now=now)['alerts'][0]
        self.assertTrue(alert['fresh'])
        self.assertEqual(alert['targets'][0]['measurement_at'], old_measure.isoformat())
        self.assertIsNone(alert['targets'][0]['host_key'])
        expired = alert_center.build(context, now=now+timedelta(seconds=20))
        self.assertEqual(expired['counts']['critical'], 0)
        self.assertEqual(expired['counts']['critical_stale'], 1)
        source.update(last_success_result=result,
                      last_result={'status': 'unknown', 'collected_at': now.isoformat(), 'error': 'Timeout'})
        failed = alert_center.build(context, now=now)
        critical = next(a for a in failed['alerts'] if a['severity'] == 'critical')
        self.assertFalse(critical['fresh'])
        self.assertEqual(critical['observed_at'], observed.isoformat())

    def test_manual_and_fast_collections_share_exclusion_and_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base/'data').mkdir()
            (base/'data/api-connections.json').write_text(json.dumps([
                {'key': 'one', 'name': 'One', 'url': 'https://example.test', 'provider': 'JSON', 'token_env': ''}]))
            context = SimpleNamespace(BASE=base, HOSTS=[])
            management.install(FastAPI(), context)
            entered, release = threading.Event(), threading.Event()
            response = MagicMock()
            response.__enter__.return_value.read.return_value = b'{}'
            def blocked(*args, **kwargs):
                entered.set()
                if not release.wait(3):
                    raise TimeoutError()
                return response
            opener = Mock()
            opener.open.side_effect = blocked
            with patch.object(management.urllib.request, 'build_opener', return_value=opener):
                worker = threading.Thread(target=context.collect_api_connection, args=('one',))
                worker.start()
                try:
                    self.assertTrue(entered.wait(2))
                    self.assertEqual(context.collect_api_connection('one'), {'status': 'busy'})
                    self.assertEqual(context.api_revision(), 0)
                finally:
                    release.set()
                    worker.join(4)
            self.assertFalse(worker.is_alive())
            self.assertEqual(context.api_revision(), 1)
            self.assertEqual(opener.open.call_count, 1)
