"""Synthèses partagées, invalidées par les écritures SQLite et à durée bornée."""

from functools import wraps
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from threading import Lock

from response_cache import ResponseCache


class WriteRevisions:
    """Suit les tables écrites, sans SQL supplémentaire ni modification du schéma."""

    def __init__(self):
        self.lock = Lock()
        self.versions = {}

    def revision(self, name):
        with self.lock:
            return self.versions.get(name, 0)

    @contextmanager
    def track(self, db):
        groups = set()
        before = db.total_changes

        def observe(action, table, column, database, trigger):
            if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
                if str(table).startswith('sec_') or table == 'registered_assets':
                    groups.update(('summary', 'recommendations'))
                elif table in ('states', 'settings'):
                    groups.add('recommendations')
            return sqlite3.SQLITE_OK

        db.set_authorizer(observe)
        try:
            # Le commit doit avoir réussi AVANT de publier les générations.
            yield
            if db.total_changes != before:
                with self.lock:
                    for group in groups:
                        self.versions[group] = self.versions.get(group, 0) + 1
        finally:
            db.set_authorizer(None)


class ReadModelCache:
    """Une connexion de lecture observe data_version sans retenir de transaction.

    La connexion doit rester la même pour comparer les générations SQLite. Elle
    n'exécute aucune collecte et se ferme lors de l'arrêt de l'application.
    """

    def __init__(self, database, *, clock=None, ttl=5.0, revisions=None):
        self.database = database
        self.revisions = revisions
        self.ttl = ttl
        self.cache = ResponseCache(**({'clock': clock} if clock else {}))
        self.lock = Lock()
        self.connection = None
        self.identity = None
        self.epoch = 0

    def generation(self, name=None):
        path = self.database()
        if path is None:
            return None
        path = Path(path).resolve()
        with self.lock:
            stat = path.stat()
            identity = (str(path), stat.st_dev, stat.st_ino)
            if self.connection is None or identity != self.identity:
                self._close()
                self.connection = sqlite3.connect(
                    path.as_uri() + '?mode=ro', uri=True, timeout=1,
                    check_same_thread=False,
                )
                self.connection.execute('PRAGMA query_only=ON')
                self.identity = identity
                self.epoch += 1
            revision = self.revisions(name) if self.revisions else None
            if revision is not None:
                return self.epoch, 'tracked', revision
            version = self.connection.execute('PRAGMA data_version').fetchone()[0]
            return self.epoch, 'sqlite', version

    def cached(self, name, revision):
        def decorate(build):
            @wraps(build)
            def read():
                generation = self.generation(name)
                # Les contextes sans fichier (tests, bases en mémoire) restent
                # utilisables sans conserver une synthèse impossible à invalider.
                if generation is None:
                    return build()
                return self.cache.get_object(
                    name, (generation, revision()), build, self.ttl,
                )
            return read
        return decorate

    def _close(self):
        if self.connection is not None:
            self.connection.close()
        self.connection = None
        self.identity = None
        self.cache.invalidate()

    def close(self):
        with self.lock:
            self._close()
