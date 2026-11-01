"""Sonde stockage detaillee : decoupage, robustesse, et absence de faux sains."""
import unittest

import storage_probe as sp

SORTIE = """##MOUNTS
/ /dev/mapper/vg0-root ext4 rw,relatime
/mnt/partage nas01:/export/data nfs4 ro,relatime
##DF
Filesystem     Type 1024-blocks    Used Available Capacity Mounted on
/dev/mapper/vg0-root ext4 51475068 40182344   8674340      83% /
/dev/sda1      xfs      1038336  254160    784176      25% /boot
##INODES
Filesystem     Type   Inodes  IUsed   IFree IUse% Mounted on
/dev/mapper/vg0-root ext4 3276800 412033 2864767   13% /
/dev/sda1      xfs     524288    331    523957     1% /boot
##REMOTE
ALIVE|/mnt/partage|nas01:/export/data|nfs4|ro,relatime|4096 262144000 52428800
STALE|/mnt/archive|nas02:/export/archive|nfs4|rw,relatime|
##LVM
  vg0 root 53687091200 -wi-ao----
##ZFS
INDISPONIBLE
##SMART
sda|SMART overall-health self-assessment test result: PASSED
sdb|NON_ACCESSIBLE
##IO1
   8       0 sda 1000 0 20000 500 800 0 16000 400 0 100 900
##CPU1
cpu  1000 0 500 8000 200 0 0 0
##IO2
   8       0 sda 1100 0 22048 520 850 0 17024 420 0 105 950
##CPU2
cpu  1100 0 550 8700 260 0 0 0
##PROC
    PID COMMAND         %CPU %MEM
   1234 postgres         42.1  18.3
   5678 nginx             3.2   0.9
##PORTS
Netid State  Recv-Q Send-Q Local Address:Port
tcp   LISTEN 0      128    0.0.0.0:22
tcp   LISTEN 0      128    0.0.0.0:443
##FIREWALL
Status: active
##FAIL2BAN
Status
|- Number of jail: 2
##SSHFAIL
47
"""


class DecoupageTests(unittest.TestCase):
    def setUp(self):
        self.r = sp.parse(SORTIE)

    def test_filesystems_croisent_espace_et_inodes(self):
        racine = next(f for f in self.r['filesystems'] if f['mount'] == '/')
        self.assertEqual(racine['fstype'], 'ext4')
        self.assertEqual(racine['use_pct'], 83)
        self.assertEqual(racine['inodes_use_pct'], 13)
        self.assertEqual(racine['available_kb'], 8674340)
        self.assertEqual(racine['inodes_used'], 412033)
        self.assertEqual(racine['inodes_free'], 2864767)

    def test_partage_gele_signale_sans_bloquer(self):
        """Le cas qui fait tomber ce genre de collecteur : un montage mort."""
        partages = {p['mount']: p for p in self.r['remote_shares']}
        self.assertEqual(partages['/mnt/archive']['status'], 'stale')
        self.assertIsNone(partages['/mnt/archive']['use_pct'])
        self.assertEqual(partages['/mnt/partage']['status'], 'accessible')
        self.assertEqual(partages['/mnt/partage']['use_pct'], 80)

    def test_droits_effectifs_lus_dans_les_options(self):
        partages = {p['mount']: p for p in self.r['remote_shares']}
        self.assertEqual(partages['/mnt/partage']['access'], 'read-only')
        self.assertEqual(partages['/mnt/archive']['access'], 'read-write')

    def test_smart_inaccessible_n_est_pas_sain(self):
        """Sans root, smartctl echoue : cela ne doit jamais valoir « disque sain »."""
        smart = {d['device']: d for d in self.r['smart']}
        self.assertEqual(smart['sda']['status'], 'ok')
        self.assertEqual(smart['sdb']['status'], 'unknown')
        self.assertIn('root', smart['sdb']['detail'])

    def test_io_et_iowait_calcules_sur_l_intervalle(self):
        io = self.r['io']
        sda = next(d for d in io['devices'] if d['device'] == 'sda')
        self.assertEqual(sda['read_kbps'], 1024)   # 2048 secteurs / 2
        self.assertEqual(sda['write_kbps'], 512)
        # iowait = delta(iowait) / delta(total) = 60 / 910
        self.assertEqual(io['iowait_pct'], 6.6)

    def test_zfs_absent_reste_vide_et_non_inconnu(self):
        self.assertEqual(self.r['zfs'], [])
        self.assertEqual(self.r['lvm'][0]['vg'], 'vg0')

    def test_securite_locale(self):
        self.assertEqual(self.r['ssh_failed_24h'], 47)
        self.assertIn('active', self.r['firewall'])
        self.assertIn('jail', self.r['fail2ban'])

    def test_processus_les_plus_consommateurs(self):
        top = self.r['top_processes']
        self.assertEqual(top[0]['command'], 'postgres')
        self.assertEqual(top[0]['cpu_pct'], 42.1)


class RobustesseTests(unittest.TestCase):
    def test_sortie_vide_ne_leve_pas(self):
        r = sp.parse('')
        self.assertEqual(r['filesystems'], [])
        self.assertEqual(r['remote_shares'], [])
        self.assertIsNone(r['io']['iowait_pct'])
        self.assertIsNone(r['ssh_failed_24h'])

    def test_sortie_tronquee_ne_leve_pas(self):
        """Une session SSH coupee en plein milieu ne doit pas casser l'audit."""
        r = sp.parse(SORTIE[:len(SORTIE) // 3])
        self.assertIsInstance(r['filesystems'], list)
        self.assertIsNone(r['io']['iowait_pct'])

    def test_lignes_illisibles_ignorees_sans_bruit(self):
        r = sp.parse('##DF\nentete\nligne bancale\n##REMOTE\nnimporte quoi\n')
        self.assertEqual(r['filesystems'], [])
        self.assertEqual(r['remote_shares'], [])

    def test_la_commande_ne_touche_jamais_le_reseau_sans_timeout(self):
        """Toute commande visant un chemin distant doit etre bornee."""
        import re
        # findmnt lit /proc : sans danger. stat -f interroge le serveur distant.
        for appel in re.finditer(r'stat -f', sp.COMMAND):
            avant = sp.COMMAND[max(0, appel.start() - 24):appel.start()]
            self.assertIn('timeout', avant, 'un stat -f sans timeout peut geler la collecte')

    def test_la_commande_est_figee(self):
        """Aucune interpolation : le client ne choisit ni commande ni parametre."""
        self.assertNotIn('{', sp.COMMAND)
        self.assertNotIn('%s', sp.COMMAND)


if __name__ == '__main__':
    unittest.main()


class IntegrationAuditTests(unittest.TestCase):
    """Raccordement dans audit_engine : une seule operation SSH, findings actionnables."""

    def setUp(self):
        import audit_engine
        self.moteur = audit_engine
        self.appels = []

    def runner(self, sortie, ok=True, stderr=''):
        import ssh as ssh_mod

        def faux(ip, op, cfg, requester):
            self.appels.append(op)
            return ssh_mod.RunResult(ok, 0 if ok else None, sortie, stderr, 5)
        return faux

    def executer(self, sortie, **kw):
        checks, findings, result = [], [], {}
        self.moteur.storage_check({'ip': '192.0.2.1'}, None, result, checks, findings,
                                  self.runner(sortie, **kw), 'test')
        return result, checks, findings

    def test_une_seule_operation_ssh(self):
        """Le point de conception : huit familles de mesures, une connexion."""
        self.executer(SORTIE)
        self.assertEqual(self.appels, ['storage'])

    def test_partage_gele_produit_une_anomalie_critique(self):
        _, _, findings = self.executer(SORTIE)
        gel = [f for f in findings if f['id'].startswith('mount:')]
        self.assertEqual(len(gel), 1)
        self.assertEqual(gel[0]['severity'], 'critical')
        self.assertIn('/mnt/archive', gel[0]['title'])
        self.assertIn('umount -l', gel[0]['solution_command'])

    def test_partage_sain_ne_produit_aucune_anomalie(self):
        _, _, findings = self.executer(SORTIE)
        self.assertFalse([f for f in findings if '/mnt/partage' in f['id']])

    def test_smart_inaccessible_ne_produit_pas_d_anomalie(self):
        """Sans root on ne sait pas : ne pas alarmer sur une mesure absente."""
        _, _, findings = self.executer(SORTIE)
        self.assertFalse([f for f in findings if f['id'].startswith('smart:')])

    def test_echec_de_collecte_reste_inconnu(self):
        result, checks, findings = self.executer('', ok=False, stderr='timeout')
        self.assertEqual(checks[0]['status'], 'unknown')
        self.assertNotIn('storage', result)
        self.assertEqual(findings, [])

    def test_donnees_exposees_au_frontend(self):
        result, checks, _ = self.executer(SORTIE)
        self.assertEqual(checks[0]['status'], 'observed')
        self.assertIn('filesystems', result['storage'])
        self.assertIn('remote_shares', result['storage'])

class PrecisionSondeTests(unittest.TestCase):
    def test_timeout_et_erreur_sont_distingues(self):
        rows = sp.parse('##REMOTE\nTIMEOUT|/a|nas:/a|nfs4|rw|\nERROR|/b|nas:/b|nfs4|rw|\n')['remote_shares']
        self.assertEqual([p['error_kind'] for p in rows], ['timeout', 'probe_error'])
        self.assertEqual([p['status'] for p in rows], ['stale', 'unknown'])

    def test_lvm_decimales_thin_et_libre_vg(self):
        data = sp.parse('##LVM\n vg | thin | 53687091200.00 | Vwi-a-tz-- | pool | 83.12 |\n##VG\nvg 107374182400.00 53687091200.00\n')
        self.assertEqual(data['lvm'][0]['size_bytes'], 53687091200)
        self.assertEqual(data['lvm'][0]['pool'], 'pool')
        self.assertEqual(data['lvm'][0]['data_pct'], 83.12)
        self.assertIsNone(data['lvm'][0]['metadata_pct'])
        self.assertEqual(data['volume_groups'][0]['free_bytes'], 53687091200)

    def test_interruption_globale_explicite(self):
        self.assertFalse(sp.parse('##PROBESTATUS\n124\n')['collection_complete'])
        self.assertTrue(sp.parse('##PROBESTATUS\n0\n')['collection_complete'])
        self.assertIsNone(sp.parse('')['collection_complete'])
        self.assertTrue(sp.COMMAND.startswith('timeout -k 1 25 sh -c '))

class SortiePartielleTests(unittest.TestCase):
    def test_processus_tronque_et_non_fini_ignores_sans_perdre_le_stockage(self):
        data = sp.parse(SORTIE + '##PROC\nPID COMMAND %CPU %MEM\n1 worker 150 2\n2 coupe 1 -\n3 inconnu nan 2\n##PROBESTATUS\n124\n')
        self.assertEqual(data['filesystems'][0]['mount'], '/')
        self.assertEqual(data['top_processes'], [{'pid': 1, 'command': 'worker', 'cpu_pct': 150.0, 'mem_pct': 2.0}])
        self.assertFalse(data['collection_complete'])

    def test_verdict_smart_tronque_ne_devient_pas_une_panne(self):
        rows = sp.parse('##SMART\nsda|SMART overall-health self-assessment test result: PASS\nsdb|SMART Health Status: FAILED!\n')['smart']
        self.assertEqual([r['status'] for r in rows], ['unknown', 'failed'])
