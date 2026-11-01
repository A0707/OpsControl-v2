"""Routes HTTP du cœur d'OpsControl, regroupées par domaine (APIRouter).

Chaque module expose install(app, context) : il garde le contexte applicatif (le module app,
voir app_context.CONTRACT) et inclut son routeur. Les fonctions lisent le contexte à l'appel
(context.rows(), context.HOSTS…) : un remplacement dans app (tests, rechargement) est donc vu.

    fleet    vue globale, services et constats complets (réponses en cache)
    hosts    collecte SSH, fiche serveur, audits conservés, tendances
    network  sondes réseau
    system   intervalle d'actualisation, rapport d'inventaire, diagnostic SSH local
"""


def all_routes(app):
    """Routes effectives de l'application, y compris celles des routeurs inclus.

    Depuis FastAPI 0.13x, include_router() ajoute un objet _IncludedRouter dans app.routes au
    lieu d'y recopier les routes : tout code qui inspecte app.routes (contrôle de déploiement,
    test des rôles d'accès) doit passer par cette fonction pour ne rien manquer.
    """
    def walk(routes):
        for route in routes:
            original = getattr(route, 'original_router', None)
            if original is not None:
                yield from walk(original.routes)
            else:
                yield route
    return list(walk(app.routes))
