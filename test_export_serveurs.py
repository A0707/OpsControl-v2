"""Export Excel des serveurs : aucune valeur d'inventaire n'est sérialisée comme formule."""
import tempfile
import unittest
import zipfile
from pathlib import Path

import export_serveurs


class FormuleTests(unittest.TestCase):
    """Audit A6 : un nom ou un rôle commençant par « = » reste du texte."""

    def test_valeurs_texte_et_nombres_preserves(self):
        try:
            import openpyxl  # noqa: F401
        except ImportError:
            self.skipTest('openpyxl absent de cet environnement (requirements-tools.txt)')
        with tempfile.TemporaryDirectory() as dossier:
            chemin = Path(dossier) / 'serveurs.xlsx'
            ligne = {'Nom': '=1+1', 'Type de machine': 'VM QEMU', 'Rôle': '=HYPERLINK("http://x.test","a")',
                     'Environnement': '+cmd', 'VMID': 104}
            export_serveurs.ecrire(chemin, [ligne], False)
            from openpyxl import load_workbook
            classeur = load_workbook(chemin)
            try:
                feuille = classeur.active
                self.assertEqual([feuille.cell(row=2, column=n).data_type for n in (1, 3)], ['s', 's'])
                self.assertEqual(feuille['A2'].value, '=1+1')
                self.assertEqual((feuille['E2'].data_type, feuille['E2'].value), ('n', 104))
            finally:
                classeur.close()
            with zipfile.ZipFile(chemin) as archive:
                self.assertNotIn('<f>', archive.read('xl/worksheets/sheet1.xml').decode('utf-8'))


if __name__ == '__main__':
    unittest.main()
