"""Lot 5 : garde-fous d'architecture du frontend (analyse statique, sans navigateur).

- les fonctions de cycle de vie ne sont plus réaffectées en chaîne (abonnements) ;
- une seule minuterie périodique (poll() dans app.js) ;
- chaque appel POST du frontend correspond à une règle explicite d'access_policy ;
- chaque sélecteur de ROLE_CONTROLS désigne un contrôle qui existe encore ;
- chaque script référencé par index.html existe.
"""
import re
import unittest
from pathlib import Path

import access_policy

WEB = Path(__file__).parent / 'web'
SCRIPTS = {p: p.read_text(encoding='utf-8') for p in sorted(WEB.rglob('*.js')) if 'node_modules' not in p.parts}
CORE = ('render', 'navigation', 'load', 'detailView', 'overview', 'loadDaily', 'dailyMarkup', 'dailyGroupeMarkup',
        'openHost', 'navigate')


class LifecycleTests(unittest.TestCase):
    def test_core_functions_are_never_reassigned(self):
        pattern = re.compile(r'^\s*(?:window\.)?(' + '|'.join(CORE) + r')\s*=(?!=)', re.M)
        found = [f'{p.name}:{s[:m.start()].count(chr(10)) + 1} {m.group(1)}'
                 for p, s in SCRIPTS.items() for m in pattern.finditer(s)]
        self.assertEqual(found, [], 'réaffectation en chaîne : utiliser renderHooks, navigationHooks, pageRenderers…')

    def test_single_periodic_timer(self):
        found = [f'{p.relative_to(WEB)}:{s[:m.start()].count(chr(10)) + 1}'
                 for p, s in SCRIPTS.items() for m in re.finditer(r'(?<![.\w])setInterval\(', s)]
        self.assertEqual(found, ['app.js:' + str(SCRIPTS[WEB / 'app.js'][:SCRIPTS[WEB / 'app.js'].index('setInterval(')].count('\n') + 1)],
                         'minuterie hors du planificateur poll()')

    def test_polls_have_unique_names(self):
        names = [m.group(1) for s in SCRIPTS.values() for m in re.finditer(r"\bpoll\('([^']+)'", s)]
        self.assertGreaterEqual(len(names), 10)
        self.assertEqual(len(names), len(set(names)), 'deux tâches périodiques portent le même nom')


class AuthorizationContractTests(unittest.TestCase):
    def explicit(self, path):
        return any(re.fullmatch(rule, path) for rule, _, _ in access_policy.POST_RULES) or path in access_policy.WEBHOOKS

    def test_every_frontend_post_is_explicitly_classified(self):
        literals = set()
        for s in SCRIPTS.values():
            for m in re.finditer(r"\bpost\(\s*[`'\"](/api/[^`'\"$]*)", s):
                literals.add(m.group(1))
        self.assertGreaterEqual(len(literals), 20)
        unclassified = []
        for lit in sorted(literals):
            candidates = [lit] if not lit.endswith('/') else [lit + 'x' + tail for tail in ('', '/refresh', '/collect', '/delete')] + [lit + 'ack']
            if not any(self.explicit(c) for c in candidates):
                unclassified.append(lit)
        self.assertEqual(unclassified, [], 'POST sans règle explicite (repli « admin » silencieux)')

    def test_role_controls_target_existing_controls(self):
        app = SCRIPTS[WEB / 'app.js']
        block = app[app.index('const ROLE_CONTROLS=['):app.index('const ROLE_LABEL')]
        selectors = [sel.strip() for _, group in re.findall(r"\['(operator|admin)','([^']+)'\]", block) for sel in group.split(',')]
        self.assertGreaterEqual(len(selectors), 25)
        everything = '\n'.join(SCRIPTS.values()) + (WEB / 'index.html').read_text(encoding='utf-8')
        missing = []
        for sel in selectors:
            m = re.fullmatch(r'#([\w-]+)', sel) or re.fullmatch(r'\[([\w-]+)(?:="([\w-]+)")?\]', sel)
            if not m:
                missing.append(sel); continue
            if sel.startswith('#'):
                ok = re.search(r"""id=\\?["']""" + re.escape(m.group(1)) + r"""\\?["']|id === ['"]""" + re.escape(m.group(1)) + r"""['"]|b\.id===['"]""" + re.escape(m.group(1)), everything)
            elif m.group(2):
                ok = re.search(re.escape(m.group(1)) + r"""['"]?\s*[:=]\s*\\?['"]""" + re.escape(m.group(2)), everything) or \
                    re.search(r"""['"]""" + re.escape(m.group(2)) + r"""['"]\s*:""", everything)
            else:
                ok = m.group(1) in everything.replace(sel, '')
            if not ok:
                missing.append(sel)
        self.assertEqual(missing, [], 'sélecteur de droits sans contrôle correspondant')

    def test_viewer_gating_mirrors_backend_roles(self):
        # Un contrôle « opérateur » côté interface ne doit pas correspondre à une route « admin ».
        roles = {'/api/monitoring': 'admin', '/api/ssh-refresh': 'admin', '/api/refresh': 'operator',
                 '/api/incidents/ack': 'operator', '/api/inventory/apply': 'admin', '/api/connections/certificate': 'admin'}
        for path, role in roles.items():
            self.assertEqual(access_policy.classify('POST', path)[0], role, path)


class StaticAssetsTests(unittest.TestCase):
    def test_index_scripts_exist(self):
        html = (WEB / 'index.html').read_text(encoding='utf-8')
        for src in re.findall(r'src="/([^"?]+)', html):
            self.assertTrue((WEB / src).is_file(), src)
        app = SCRIPTS[WEB / 'app.js']
        lazy = re.findall(r"'/([\w/-]+\.js)\?v=\w+'", app)
        self.assertGreater(len(lazy), 10, 'modules paresseux versionnés attendus')
        for src in lazy:
            self.assertTrue((WEB / src).is_file(), 'module paresseux absent : ' + src)

    def test_versions_a_jour(self):
        # Versions = empreintes du contenu (deploy/assets_version.py) : aucune ne doit être périmée.
        import sys
        sys.path.insert(0, str(WEB.parent / 'deploy'))
        import assets_version
        self.assertEqual(assets_version.stale(WEB), [], 'lancer : python deploy/assets_version.py')


if __name__ == '__main__':
    unittest.main()
