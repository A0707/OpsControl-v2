import testing_env  # noqa: F401 — garde-fou réseau et données isolées (AGENTS.md)
import unittest
from unittest import mock

import export_proxmox_stockage as export

GIB = 1024 ** 3


class DisquesTests(unittest.TestCase):
    def test_disques_qemu_ignore_cdrom_et_signale_les_volumes_detaches(self):
        config = {
            'scsi0': 'ceph-remote:vm-101-disk-0,iothread=1,size=50G',
            'scsi1': 'myceph:vm-101-disk-1,size=1T',
            'ide2': 'local:iso/debian.iso,media=cdrom,size=600M',
            'ide0': 'none,media=cdrom',
            'efidisk0': 'myceph:vm-101-disk-2,efitype=4m,size=528K',
            'unused0': 'nfs-primary:101/vm-101-disk-3.qcow2',
            'net0': 'virtio=AA:BB,bridge=vmbr0,size=99G',
            'memory': 4096,
        }
        resultat = {d['cle']: d for d in export.disques(config, 'qemu')}
        self.assertEqual(set(resultat), {'scsi0', 'scsi1', 'efidisk0', 'unused0'})
        self.assertEqual(resultat['scsi0']['stockage'], 'ceph-remote')
        self.assertEqual(resultat['scsi0']['taille'], 50 * GIB)
        self.assertEqual(resultat['scsi1']['taille'], 1024 * GIB)
        self.assertEqual(resultat['efidisk0']['taille'], 528 * 1024)
        self.assertTrue(resultat['unused0']['detache'])
        self.assertIsNone(resultat['unused0']['taille'])

    def test_disques_lxc_ignore_les_montages_bind_de_l_hote(self):
        config = {'rootfs': 'myceph:vm-200-disk-0,size=8G',
                  'mp0': 'nfs-primary:200/vm-200-disk-1.raw,mp=/data,size=100G',
                  'mp1': '/mnt/hote,mp=/partage'}
        resultat = export.disques(config, 'lxc')
        self.assertEqual([(d['cle'], d['stockage']) for d in resultat],
                         [('mp0', 'nfs-primary'), ('rootfs', 'myceph')])


class DateCreationTests(unittest.TestCase):
    def test_ctime_lu_dans_meta_et_lot_signale(self):
        self.assertEqual(export.date_creation({'meta': 'creation-qemu=7.2.0,ctime=1704571377'}), 1704571377)
        self.assertIsNone(export.date_creation({'name': 'sans-meta'}))
        self.assertIsNone(export.date_creation(None))
        lot = [{'vmid': n, 'type': 'qemu', 'ctime': 1704571377 + n} for n in range(export.SEUIL_LOT)]
        seule = {'vmid': 900, 'type': 'qemu', 'ctime': 1654950000}
        ancienne = {'vmid': 901, 'type': 'qemu', 'ctime': None}
        conteneur = {'vmid': 902, 'type': 'lxc', 'ctime': None}
        fiabilite = export.fiabilite_dates(lot + [seule, ancienne, conteneur])
        self.assertTrue(fiabilite[0].startswith(f'Date commune à {export.SEUIL_LOT} VM'))
        self.assertEqual(fiabilite[900], 'Création sur ce cluster')
        self.assertIn('antérieure', fiabilite[901])
        self.assertIn('LXC', fiabilite[902])


class DateRetenueTests(unittest.TestCase):
    JOUR = 86400

    def test_croisement_proxmox_et_systeme(self):
        proxmox = 1704571377
        self.assertEqual(export.date_retenue(proxmox, proxmox + 3600)[1][:9], 'Confirmée')
        date, raison = export.date_retenue(proxmox, proxmox - 900 * self.JOUR)
        self.assertEqual(date, proxmox - 900 * self.JOUR)
        self.assertIn('migrée', raison)
        date, raison = export.date_retenue(proxmox, proxmox + 100 * self.JOUR)
        self.assertEqual(date, proxmox)
        self.assertIn('réinstallé', raison)
        self.assertEqual(export.date_retenue(None, 123456)[0], 123456)
        self.assertEqual(export.date_retenue(None, None), (None, 'Inconnue'))

    def test_rapprochement_par_vmid_puis_nom_court(self):
        installations = [{'vmid': 151, 'node': 'pve03', 'name': 'git01', 'installation': 1},
                         {'vmid': 999, 'node': 'pve01', 'name': 'web01', 'installation': 2}]
        self.assertEqual(export.installation_de({'vmid': 151, 'node': 'pve04', 'name': 'x'}, installations)['installation'], 1)
        self.assertEqual(export.installation_de({'vmid': 5, 'name': 'web01.host.exemple.ma'}, installations)['installation'], 2)
        self.assertIsNone(export.installation_de({'vmid': 6, 'name': 'autre'}, installations))


class SupportsTests(unittest.TestCase):
    def test_un_support_partage_est_compte_une_fois_et_le_local_additionne(self):
        ressources = [
            {'type': 'storage', 'storage': 'myceph', 'node': n, 'shared': 1, 'status': 'available',
             'plugintype': 'rbd', 'maxdisk': 1000, 'disk': 400} for n in ('pve1', 'pve2', 'pve3')
        ] + [
            {'type': 'storage', 'storage': 'local', 'node': 'pve1', 'shared': 0, 'status': 'available',
             'plugintype': 'dir', 'maxdisk': 100, 'disk': 10},
            {'type': 'storage', 'storage': 'local', 'node': 'pve2', 'shared': 0, 'status': 'available',
             'plugintype': 'dir', 'maxdisk': 200, 'disk': 50},
            {'type': 'storage', 'storage': 'local', 'node': 'pve3', 'shared': 0, 'status': 'unavailable',
             'plugintype': 'dir', 'maxdisk': 999, 'disk': 999},
            {'type': 'qemu', 'node': 'pve1', 'vmid': 100},
        ]
        resultat = {s['nom']: s for s in export.supports(ressources)}
        self.assertEqual((resultat['myceph']['total'], resultat['myceph']['utilise']), (1000, 400))
        self.assertEqual(sorted(resultat['myceph']['noeuds']), ['pve1', 'pve2', 'pve3'])
        # Un stockage indisponible n'a pas de mesure fiable : il n'entre pas au total.
        self.assertEqual((resultat['local']['total'], resultat['local']['utilise']), (300, 60))


class CollecteTests(unittest.TestCase):
    def test_collecte_en_get_seulement_et_tolere_une_config_illisible(self):
        client = mock.Mock()
        reponses = {
            '/cluster/resources': [
                {'type': 'qemu', 'node': 'pve1', 'vmid': 101, 'name': 'web'},
                {'type': 'lxc', 'node': 'pve1', 'vmid': 102, 'name': 'dns'},
                {'type': 'qemu', 'node': 'pve1', 'vmid': 900, 'name': 'modele', 'template': 1},
            ],
            '/nodes/pve1/qemu/101/config': {'scsi0': 'myceph:vm-101-disk-0,size=10G'},
        }

        def get(chemin):
            if chemin not in reponses:
                raise OSError('refusé')
            return reponses[chemin]

        client.get.side_effect = get
        _ressources, invites, erreurs = export.collecter(client)
        self.assertEqual([i['vmid'] for i in invites], [101, 102])
        self.assertEqual(invites[0]['disques'][0]['taille'], 10 * GIB)
        self.assertIsNone(invites[1]['disques'])
        self.assertEqual(erreurs, [(102, 'dns', 'OSError')])
        self.assertEqual({c.args[0] for c in client.get.call_args_list},
                         {'/cluster/resources', '/nodes/pve1/qemu/101/config', '/nodes/pve1/lxc/102/config'})


class ClientTests(unittest.TestCase):
    """Le client n'émet que des GET, sans proxy d'environnement, en HTTPS seulement."""

    def connexion(self, url='https://pve.example.test:8006'):
        return {'provider': 'Proxmox', 'url': url, 'token_env': 'INFRAOPS_PROXMOX_AUTH'}

    def test_get_https_sans_proxy(self):
        import os
        with mock.patch.dict(os.environ, {'INFRAOPS_PROXMOX_AUTH': 'x' * 40, 'HTTPS_PROXY': 'http://proxy.test:3128'}), \
                mock.patch('management.ssl_context_for', return_value=None):
            client = export.ClientProxmox(self.connexion())
        handlers = [type(h).__name__ for h in client.ouvreur.handlers]
        self.assertNotIn('ProxyHandler', handlers, 'aucun proxy d’environnement ne reçoit le jeton')
        reponse = mock.MagicMock()
        reponse.__enter__.return_value.read.return_value = b'{"data": []}'
        with mock.patch.object(client.ouvreur, 'open', return_value=reponse) as ouvert:
            self.assertEqual(client.get('/cluster/resources'), [])
        requete = ouvert.call_args.args[0]
        self.assertEqual(requete.get_method(), 'GET')
        self.assertIsNone(requete.data)

    def test_http_refuse(self):
        import os
        with mock.patch.dict(os.environ, {'INFRAOPS_PROXMOX_AUTH': 'x' * 40}), self.assertRaises(SystemExit):
            export.ClientProxmox(self.connexion('http://pve.example.test:8006'))


if __name__ == '__main__':
    unittest.main()
