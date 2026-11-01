import json
import ssl
import unittest
import urllib.error
from management import collection_error
from proxmox_inventory import inventory, cluster_info


class ProxmoxTests(unittest.TestCase):
    def test_nodes_guests_and_migration(self):
        data=[{'type':'qemu','node':'pve02','vmid':101,'name':'web','status':'running','cpu':.25,'maxmem':4096},
              {'type':'node','node':'pve01','status':'online','cpu':.1},
              {'type':'node','node':'pve02','status':'online'},
              {'type':'lxc','node':'pve01','vmid':102,'name':'dns','status':'stopped'},
              {'type':'storage','node':'pve01','password':'SECRET'}]
        result=inventory({'data':data})
        self.assertEqual(result['nodes_count'],2)
        self.assertEqual(result['nodes'][0]['guests'][0]['vmid'],102)
        self.assertEqual(result['nodes'][1]['guests'][0]['cpu_pct'],25)
        self.assertIsNone(result['nodes'][1]['guests'][0]['memory_bytes'])
        self.assertEqual(result['counts']['qemu'],1)
        self.assertNotIn('SECRET',json.dumps(result))
        data[0]['node']='pve01'
        self.assertEqual(len(inventory({'data':data})['nodes'][0]['guests']),2)

    def test_missing_node_and_permissions(self):
        result=inventory({'data':[{'type':'qemu','node':'pve01','vmid':1,'status':'running'}]})
        self.assertFalse(result['nodes'][0]['reported'])
        self.assertEqual(result['nodes'][0]['status'],'unknown')
        self.assertTrue(inventory({'data':[]})['empty'])
        with self.assertRaises(ValueError):inventory({'data':{'version':'9'}})
        self.assertEqual(cluster_info({'data':[{'type':'cluster','name':'OVH','quorate':0}] }),{'name':'OVH','quorate':False})
        self.assertIsNone(cluster_info({'data':[{'type':'node','name':'pve01'}]}))

    def test_v2_storage_io_and_cluster_summary_remain_read_only_data(self):
        payload = {'data': [
            {'type': 'node', 'node': 'pve01', 'status': 'online', 'cpu': .2,
             'maxcpu': 16, 'mem': 40, 'maxmem': 100, 'disk': 10, 'maxdisk': 50},
            {'type': 'qemu', 'node': 'pve01', 'vmid': 101, 'name': 'api',
             'status': 'running', 'cpu': .1, 'maxcpu': 4, 'mem': 20, 'maxmem': 40,
             'disk': 30, 'maxdisk': 60, 'diskread': 7, 'diskwrite': 8,
             'netin': 9, 'netout': 10},
            {'type': 'storage', 'node': 'pve01', 'storage': 'local-lvm',
             'status': 'available', 'plugintype': 'lvmthin', 'shared': 0,
             'disk': 70, 'maxdisk': 100},
            {'type': 'storage', 'node': 'pve01', 'storage': 'pbs',
             'status': 'unavailable', 'plugintype': 'pbs', 'shared': 1,
             'disk': 5, 'maxdisk': 20, 'password': 'SECRET'},
        ]}
        result = inventory(payload)
        node = result['nodes'][0]
        guest = node['guests'][0]
        self.assertEqual(node['cpu_capacity'], 16)
        self.assertEqual(guest['network_out_bytes'], 10)
        self.assertEqual(guest['disk_used_bytes'], 30)
        self.assertEqual([x['name'] for x in node['storages']], ['local-lvm', 'pbs'])
        self.assertEqual(result['counts']['storage_unavailable'], 1)
        self.assertEqual(result['summary']['memory_bytes'], 40)
        self.assertEqual(result['summary']['storage_used_bytes'], 75)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_shared_storage_counted_once_and_vm_disk_zero_not_measured(self):
        # Audit UI du 31/10 (fiches 07.1 et 07.2).
        rows = [{'type': 'node', 'node': n, 'status': 'online'} for n in ('pve01', 'pve02', 'pve03')]
        rows += [{'type': 'storage', 'node': n, 'storage': 'ceph', 'status': 'available', 'shared': 1,
                  'disk': 40, 'maxdisk': 100} for n in ('pve01', 'pve02', 'pve03')]
        rows += [{'type': 'storage', 'node': n, 'storage': 'local', 'status': 'available', 'shared': 0,
                  'disk': 5, 'maxdisk': 10} for n in ('pve01', 'pve02')]
        rows += [{'type': 'qemu', 'node': 'pve01', 'vmid': 101, 'name': 'vm', 'status': 'running', 'disk': 0, 'maxdisk': 60},
                 {'type': 'lxc', 'node': 'pve01', 'vmid': 102, 'name': 'ct', 'status': 'running', 'disk': 0, 'maxdisk': 8}]
        result = inventory({'data': rows})
        self.assertEqual(result['summary']['storage_total_bytes'], 120)
        self.assertEqual(result['summary']['storage_used_bytes'], 50)
        self.assertEqual(result['summary']['storage_unique_count'], 3)
        guests = {g['type']: g for g in result['nodes'][0]['guests']}
        self.assertIsNone(guests['qemu']['disk_used_bytes'])
        self.assertEqual(guests['lxc']['disk_used_bytes'], 0)

    def test_error_types_hide_credentials(self):
        error=ssl.SSLCertVerificationError('SECRET')
        error.verify_code=20
        result=collection_error(urllib.error.URLError(error))
        self.assertEqual(result['error_kind'],'tls_certificate')
        self.assertNotIn('SECRET',json.dumps(result))
        for code in (401,403,404):
            result=collection_error(urllib.error.HTTPError('https://example.test',code,'SECRET',{},None))
            self.assertEqual(result['http_status'],code)
            self.assertNotIn('SECRET',json.dumps(result))
        self.assertEqual(collection_error(TimeoutError())['error_kind'],'timeout')
        self.assertEqual(collection_error(FileNotFoundError())['error_kind'],'ca_file')


if __name__=='__main__':unittest.main()
