"""Coffre DPAPI : precedence, absence de fuite, robustesse."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import secret_store


class CoffreTests(unittest.TestCase):
    def test_variable_existante_jamais_ecrasee(self):
        """Le lanceur et les surcharges manuelles priment sur le coffre."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'INFRAOPS_TEST_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            with patch.dict(os.environ, {'INFRAOPS_TEST_AUTH': 'valeur-du-lanceur'}):
                charges = secret_store.charger(dossier)
                self.assertEqual(charges, [])
                self.assertEqual(os.environ['INFRAOPS_TEST_AUTH'], 'valeur-du-lanceur')

    def test_coffre_absent_n_est_pas_une_erreur(self):
        """Un poste sans coffre doit demarrer normalement."""
        self.assertEqual(secret_store.charger(Path(tempfile.gettempdir()) / 'coffre-inexistant-xyz'), [])

    def test_blob_illisible_ignore_sans_lever(self):
        """Un fichier corrompu ne doit pas empecher le demarrage."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'INFRAOPS_CASSE_AUTH.dpapi').write_text('pas du hexadecimal', encoding='utf-8')
            (Path(dossier) / 'INFRAOPS_VIDE_AUTH.dpapi').write_text('', encoding='utf-8')
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop('INFRAOPS_CASSE_AUTH', None)
                os.environ.pop('INFRAOPS_VIDE_AUTH', None)
                self.assertEqual(secret_store.charger(dossier), [])

    def test_ne_renvoie_que_des_noms(self):
        """Le retour alimente des journaux : aucune valeur ne doit en sortir."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'INFRAOPS_X_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            with patch.object(secret_store, '_dechiffrer', return_value='secret-tres-confidentiel'):
                os.environ.pop('INFRAOPS_X_AUTH', None)
                try:
                    charges = secret_store.charger(dossier)
                    self.assertEqual(charges, ['INFRAOPS_X_AUTH'])
                    self.assertNotIn('secret-tres-confidentiel', ' '.join(charges))
                finally:
                    os.environ.pop('INFRAOPS_X_AUTH', None)

    def test_valeur_vide_non_posee(self):
        """Une entree vide ne doit pas masquer l'absence reelle de secret."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'INFRAOPS_Y_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            with patch.object(secret_store, '_dechiffrer', return_value='   '):
                os.environ.pop('INFRAOPS_Y_AUTH', None)
                self.assertEqual(secret_store.charger(dossier), [])
                self.assertNotIn('INFRAOPS_Y_AUTH', os.environ)


@unittest.skipUnless(os.name == 'nt', 'Coffre DPAPI propre à Windows')
class CoffreInaccessibleTests(unittest.TestCase):
    """Un coffre refusé au compte courant ne doit jamais empêcher le démarrage."""

    def test_listage_refuse(self):
        with tempfile.TemporaryDirectory() as dossier, \
                patch.object(Path, 'glob', side_effect=PermissionError(13, 'Accès refusé')):
            self.assertEqual(secret_store.charger(dossier), [])
        self.assertFalse(secret_store.ETAT['disponible'])
        self.assertIn('PermissionError', secret_store.ETAT['raison'])

    def test_dossier_illisible(self):
        with patch.object(Path, 'is_dir', side_effect=OSError(5, 'Erreur E/S')):
            self.assertEqual(secret_store.charger(Path('C:/coffre-refuse')), [])
        self.assertIn('inaccessible', secret_store.ETAT['raison'])

    def test_fichier_refuse_n_empeche_pas_les_autres(self):
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'INFRAOPS_REFUS_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            (Path(dossier) / 'INFRAOPS_OK_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            lire = Path.read_text

            def lecture(self, *a, **k):
                if self.name.startswith('INFRAOPS_REFUS'):
                    raise PermissionError(13, 'Accès refusé')
                return lire(self, *a, **k)
            with patch.object(Path, 'read_text', lecture), \
                    patch.object(secret_store, '_dechiffrer', return_value='valeur-secrete-xyz'):
                for nom in ('INFRAOPS_REFUS_AUTH', 'INFRAOPS_OK_AUTH'):
                    os.environ.pop(nom, None)
                try:
                    self.assertEqual(secret_store.charger(dossier), ['INFRAOPS_OK_AUTH'])
                    self.assertNotIn('valeur-secrete-xyz', repr(secret_store.ETAT))
                finally:
                    os.environ.pop('INFRAOPS_OK_AUTH', None)

    def test_nom_de_variable_invalide_ignore(self):
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'path-invalide.dpapi').write_text('00ff', encoding='utf-8')
            with patch.object(secret_store, '_dechiffrer', return_value='x'):
                self.assertEqual(secret_store.charger(dossier), [])

    def test_import_application_avec_coffre_refuse(self):
        """app.py appelle charger() à l'import : un refus ne doit pas lever."""
        import subprocess
        import sys
        code = ('import pathlib, unittest.mock as m, secret_store\n'
                'with m.patch.object(pathlib.Path, "glob", side_effect=PermissionError(13, "refus")):\n'
                '    print(secret_store.charger(pathlib.Path(".")), secret_store.ETAT["disponible"])\n')
        sortie = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=60,
                                cwd=Path(__file__).resolve().parent)
        self.assertEqual(sortie.returncode, 0, sortie.stderr[-400:])
        self.assertEqual(sortie.stdout.strip(), '[] False')


if __name__ == '__main__':
    unittest.main()
