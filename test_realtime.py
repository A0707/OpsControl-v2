"""Flux SSE : signale les changements sans jamais declencher de collecte."""
from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import asyncio
import json
import threading
import unittest
from types import SimpleNamespace

from fastapi import FastAPI
from starlette.requests import ClientDisconnect

import realtime


class FluxTests(unittest.TestCase):
    def setUp(self):
        self.context = SimpleNamespace(
            lock=threading.Lock(), net_lock=threading.Lock(),
            job={'running': False, 'completed': 0, 'total': 0, 'error': None},
            net_job={'running': False, 'completed': 0, 'total': 0},
            monitor={'interval': 0, 'next_at': None},
            api_sync_state=lambda: {'running': False, 'completed': 0, 'total': 0},
        )
        app = FastAPI()
        realtime.WATCH_SECONDS = 0.01
        realtime.install(app, self.context)
        self.endpoint = next(r.endpoint for r in all_routes(app) if getattr(r, 'path', '') == '/api/events')

    def lire(self, messages, deconnecte_apres=6):
        """Consomme le flux jusqu'a `deconnecte_apres` fragments."""
        recus = []
        etat = {'n': 0}

        async def is_disconnected():
            etat['n'] += 1
            return etat['n'] > deconnecte_apres

        requete = SimpleNamespace(is_disconnected=is_disconnected)

        async def run():
            reponse = await self.endpoint(requete)
            async for fragment in reponse.body_iterator:
                recus.append(fragment)
                if messages and len(recus) in messages:
                    messages[len(recus)]()
        asyncio.run(run())
        return recus

    def test_premier_message_immediat(self):
        """Le client doit savoir que le canal est ouvert sans attendre un changement."""
        recus = self.lire({}, deconnecte_apres=1)
        self.assertTrue(recus[0].startswith('event: ready'))

    def test_un_changement_produit_un_evenement(self):
        def demarre_collecte():
            self.context.job.update(running=True, completed=3, total=84)
        # Declenche apres le message `ready` : c'est le seul fragment garanti,
        # puisqu'un etat stable n'en produit aucun autre avant le maintien.
        recus = self.lire({1: demarre_collecte}, deconnecte_apres=5)
        etats = [m for m in recus if m.startswith('event: state')]
        self.assertTrue(etats, 'aucun evenement state emis apres le changement')
        charge = json.loads(etats[-1].split('data: ', 1)[1].strip())
        self.assertEqual(charge['ssh']['completed'], 3)
        self.assertEqual(charge['ssh']['total'], 84)

    def test_aucun_evenement_sans_changement(self):
        """Un etat stable ne doit produire que des commentaires de maintien."""
        recus = self.lire({}, deconnecte_apres=5)
        etats = [m for m in recus if m.startswith('event: state')]
        self.assertEqual(etats, [], 'le flux emet alors que rien n a change')

    def test_direct_source_commit_notifies_without_job_change(self):
        revision = [0]
        self.context.api_revision = lambda: revision[0]
        self.context.api_change = lambda: {'revision': revision[0], 'source': 'pve', 'provider': 'Proxmox'}
        messages = self.lire({1: lambda: revision.__setitem__(0, 1)})
        updates = [m for m in messages if m.startswith('event: state')]
        payload = json.loads(updates[-1].split('data: ', 1)[1])
        self.assertEqual(payload['api_revision'], 1)
        self.assertEqual(payload['api_change']['provider'], 'Proxmox')
        self.assertFalse(payload['ssh']['running'])

    def test_batch_completion_notifies_the_dashboard(self):
        batch = {'running': True, 'completed': 0, 'total': 1}
        self.context.batch_job = lambda: dict(batch)
        messages = self.lire({1: lambda: batch.update(running=False, completed=1)})
        updates = [m for m in messages if m.startswith('event: state')]
        payload = json.loads(updates[-1].split('data: ', 1)[1])
        self.assertEqual(payload['batch']['completed'], 1)
        self.assertFalse(payload['batch']['running'])

    def test_extension_absente_ne_coupe_pas_le_flux(self):
        """api_sync_state indisponible : on signale l'inconnue, on ne plante pas."""
        def casse():
            raise RuntimeError('extension non installee')
        self.context.api_sync_state = casse
        recus = self.lire({}, deconnecte_apres=2)
        self.assertTrue(recus[0].startswith('event: ready'))

    def test_le_flux_ne_declenche_aucune_collecte(self):
        """Garde-fou : observer l'etat ne doit jamais lancer de SSH ni d'API."""
        appels = []
        self.context.launch = lambda *a, **k: appels.append('ssh')
        self.context.launch_network = lambda *a, **k: appels.append('network')
        self.context.launch_api_sync = lambda *a, **k: appels.append('api')
        self.lire({}, deconnecte_apres=5)
        self.assertEqual(appels, [])


class PlafondTests(unittest.TestCase):
    """Plafonds de flux simultanés : par lecteur et au total, compteur toujours apparié."""

    def setUp(self):
        self.context = SimpleNamespace(
            lock=threading.Lock(), net_lock=threading.Lock(),
            job={'running': False, 'completed': 0, 'total': 0, 'error': None},
            net_job={'running': False, 'completed': 0, 'total': 0},
            monitor={'interval': 0, 'next_at': None},
            api_sync_state=lambda: {'running': False, 'completed': 0, 'total': 0},
        )
        app = FastAPI()
        realtime.WATCH_SECONDS = 0.01
        realtime.install(app, self.context)
        self.endpoint = next(r.endpoint for r in all_routes(app) if getattr(r, 'path', '') == '/api/events')
        self.limites = (realtime.MAX_STREAMS, realtime.MAX_PER_ACTOR)
        realtime._streams.clear()

    def tearDown(self):
        realtime.MAX_STREAMS, realtime.MAX_PER_ACTOR = self.limites
        realtime._streams.clear()

    def requete(self, user=None, host='10.0.0.1'):
        async def jamais_deconnecte():
            return False
        return SimpleNamespace(is_disconnected=jamais_deconnecte, client=SimpleNamespace(host=host),
                               state=SimpleNamespace(principal={'user': user}))

    def test_refus_503_au_dela_du_plafond_par_lecteur(self):
        realtime.MAX_PER_ACTOR = 1
        realtime._open('user:alice@example.org')
        reponse = asyncio.run(self.endpoint(self.requete('Alice@example.org')))
        self.assertEqual(reponse.status_code, 503)
        self.assertEqual(reponse.headers['retry-after'], str(realtime.RETRY_AFTER_SECONDS))
        # Un autre lecteur n'est pas concerné.
        autre = asyncio.run(self.endpoint(self.requete('bob@example.org')))
        self.assertNotEqual(getattr(autre, 'status_code', 200), 503)

    def test_refus_503_au_dela_du_plafond_global(self):
        realtime.MAX_STREAMS = 2
        realtime._open('client:10.0.0.8')
        realtime._open('client:10.0.0.9')
        reponse = asyncio.run(self.endpoint(self.requete(host='10.0.0.1')))
        self.assertEqual(reponse.status_code, 503)

    def test_compteur_libere_a_la_deconnexion(self):
        etat = {'n': 0}

        async def deconnecte():
            etat['n'] += 1
            return etat['n'] > 2

        requete = SimpleNamespace(is_disconnected=deconnecte, client=SimpleNamespace(host='10.0.0.2'),
                                  state=SimpleNamespace(principal={}))

        async def run():
            reponse = await self.endpoint(requete)
            async for _ in reponse.body_iterator:
                self.assertEqual(realtime._streams.get('client:10.0.0.2'), 1)
        asyncio.run(run())
        self.assertNotIn('client:10.0.0.2', realtime._streams)


class ConcurrentLimitTests(PlafondTests):
    """Audit A3 : plafonds tenus sous ouvertures concurrentes, place toujours rendue."""

    def ouvrir(self, requetes):
        async def run():
            reponses = await asyncio.gather(*(self.endpoint(r) for r in requetes))
            acceptees = [r for r in reponses if hasattr(r, 'body_iterator')]
            await asyncio.gather(*(r.body_iterator.__anext__() for r in acceptees))
            actifs = sum(realtime._streams.values())
            await asyncio.gather(*(r.body_iterator.aclose() for r in acceptees))
            return len(acceptees), actifs
        return asyncio.run(run())

    def test_cinquante_ouvertures_d_un_lecteur(self):
        acceptees, actifs = self.ouvrir([self.requete('alice@example.org') for _ in range(50)])
        self.assertEqual((acceptees, actifs), (realtime.MAX_PER_ACTOR, realtime.MAX_PER_ACTOR))
        self.assertEqual(realtime._streams, {})

    def test_plafond_global_sous_concurrence(self):
        realtime.MAX_STREAMS = 7
        acceptees, actifs = self.ouvrir([self.requete(f'u{i % 20}@example.org') for i in range(60)])
        self.assertEqual((acceptees, actifs), (7, 7))
        self.assertEqual(realtime._streams, {})

    def test_place_rendue_si_le_flux_ne_demarre_jamais(self):
        async def envoi_impossible(message):
            raise OSError('client parti')

        async def recevoir():
            return {'type': 'http.disconnect'}

        async def run():
            reponse = await self.endpoint(self.requete('alice@example.org'))
            self.assertEqual(realtime._streams, {'user:alice@example.org': 1})
            # Starlette traduit l'échec d'envoi en ClientDisconnect.
            with self.assertRaises(ClientDisconnect):
                await reponse({'type': 'http', 'asgi': {'spec_version': '2.4'}}, recevoir, envoi_impossible)
        asyncio.run(run())
        self.assertEqual(realtime._streams, {})

    def test_place_rendue_si_le_premier_etat_echoue(self):
        self.context.monitor = None  # dict(None) : le premier état lève une exception

        async def run():
            reponse = await self.endpoint(self.requete('alice@example.org'))
            with self.assertRaises(TypeError):
                await reponse.body_iterator.__anext__()
        asyncio.run(run())
        self.assertEqual(realtime._streams, {})


class EventLoopTests(FluxTests):
    """Audit BE-04 : un verrou tenu par une écriture ne gèle plus la boucle d'événements."""

    def test_verrou_occupe_ne_bloque_pas_les_autres_requetes(self):
        import time
        held, release = threading.Event(), threading.Event()

        def writer():
            with self.context.lock:      # écriture longue (YAML + SQLite) sous context.lock
                held.set()
                release.wait(2)
        threading.Thread(target=writer, daemon=True).start()
        held.wait(2)
        ticks = []

        async def heartbeat():
            # Autre requête servie pendant ce temps : la boucle doit continuer de tourner.
            for _ in range(10):
                ticks.append(time.monotonic())
                await asyncio.sleep(0.02)
            release.set()

        async def is_disconnected():
            return False

        async def run():
            reponse = await self.endpoint(SimpleNamespace(is_disconnected=is_disconnected))
            stream = reponse.body_iterator
            beat = asyncio.ensure_future(heartbeat())
            first = await asyncio.wait_for(stream.__anext__(), 5)   # snapshot() attend le verrou hors boucle
            received_at = time.monotonic()
            await beat
            await stream.aclose()
            return first, received_at
        first, received_at = asyncio.run(run())
        self.assertTrue(first.startswith('event: ready'))
        # Le verrou n'est libéré QUE par heartbeat : si snapshot() bloquait la boucle, aucun
        # battement ne précéderait le premier message (attente jusqu'au délai de 2 s).
        self.assertEqual(len([t for t in ticks if t < received_at]), 10)


if __name__ == '__main__':
    unittest.main()
