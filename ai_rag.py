"""Index local incrémental FTS5 : uniquement sources suivies et autorisées."""

from __future__ import annotations

import hashlib
import re
import sqlite3
import subprocess
import threading
from pathlib import Path

from ai_security import clean

EXCLUDED = {
    "release",
    "dist",
    "data",
    ".git",
    ".venv",
    ".graphify-packages",
    "graphify-out",
    "public-demo",
    "test_fixtures",
}


MANIFEST = "MANIFEST.sha256"


def tracked(root):
    """Fichiers suivis : index Git dans un dépôt, sinon manifeste de la release.

    Une release installée n'a ni .git ni forcément git : `git ls-files` y échouait et
    rendait recherche, documents et chat inutilisables (OC-AUDIT-017). Le manifeste,
    vérifié par release.py avant l'installation, liste exactement le code livré."""
    root = Path(root)
    if not (root / ".git").exists() and (root / MANIFEST).is_file():
        names = []
        for line in (root / MANIFEST).read_text(encoding="utf-8").splitlines():
            digest, sep, name = line.partition("  ")
            if sep and re.fullmatch(r"[0-9a-f]{64}", digest) and name:
                names.append(name)
        return names
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
        timeout=10,
    )
    return result.stdout.decode("utf-8").split("\0")


def permitted(name):
    p = Path(name)
    if p.is_absolute() or ".." in p.parts or EXCLUDED.intersection(p.parts):
        return False
    if p.suffix not in (".md", ".py", ".js") or p.name.startswith("test_"):
        return False
    # Les rapports d'exploitation et inventaires ne sont pas des documents publics.
    return (
        name in ("README.md", "AGENTS.md")
        or p.parts[0] in ("docs", "routers", "web")
        or len(p.parts) == 1
        and p.suffix == ".py"
    )


class Index:
    def __init__(self, root, db):
        self.root = Path(root).resolve()
        self.db = Path(db)
        self.lock = threading.Lock()

    def connect(self):
        self.db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db, timeout=5)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, stamp TEXT, digest TEXT)"
        )
        conn.execute(
            'CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(path UNINDEXED, line UNINDEXED, kind UNINDEXED, text, tokenize="unicode61 remove_diacritics 2")'
        )
        return conn

    def update(self):
        changed = 0
        with self.lock:
            conn = self.connect()
            try:
                with conn:
                    names = {n for n in tracked(self.root) if n and permitted(n)}
                    saved = {
                        p: (s, d) for p, s, d in conn.execute("SELECT path,stamp,digest FROM files")
                    }
                    for name in sorted(names):
                        path = self.root / name
                        # Aucun lien ne donne accès à un fichier extérieur ou exclu.
                        if (
                            path.is_symlink()
                            or path.resolve() != path.absolute()
                            or not path.is_file()
                        ):
                            names.discard(name)
                            continue
                        stat = path.stat()
                        if stat.st_size > 256_000:
                            names.discard(name)
                            continue
                        stamp = f"{stat.st_mtime_ns}:{stat.st_size}"
                        if name in saved and saved[name][0] == stamp:
                            continue
                        raw = path.read_bytes()
                        digest = hashlib.sha256(raw).hexdigest()
                        if name not in saved or saved[name][1] != digest:
                            conn.execute("DELETE FROM chunks WHERE path=?", (name,))
                            lines = raw.decode("utf-8", "replace").splitlines()
                            for i in range(0, len(lines), 18):
                                text = clean("\n".join(lines[i : i + 18]))[:1800]
                                conn.execute(
                                    "INSERT INTO chunks(path, line, kind, text) VALUES(?,?,?,?)",
                                    (name, i + 1, "docs" if name.endswith(".md") else "code", text),
                                )
                            changed += 1
                        conn.execute(
                            "INSERT OR REPLACE INTO files(path, stamp, digest) VALUES(?,?,?)", (name, stamp, digest)
                        )
                    for name in saved.keys() - names:
                        conn.execute("DELETE FROM chunks WHERE path=?", (name,))
                        conn.execute("DELETE FROM files WHERE path=?", (name,))
                        changed += 1
                return changed
            finally:
                conn.close()

    def search(self, query, code=False, limit=4):
        tokens = re.findall(r"\w{3,}", query, re.UNICODE)[:12]
        if not tokens:
            return []
        expression = " OR ".join('"' + word + '"' for word in tokens)
        conn = self.connect()
        try:
            rows = conn.execute(
                "SELECT path,line,text FROM chunks WHERE chunks MATCH ? AND (kind=? OR ?=1) ORDER BY bm25(chunks) LIMIT ?",
                (expression, "docs", int(code), max(1, min(limit, 8))),
            ).fetchall()
            # Revérifier la permission après indexation : pas de référence supprimée/retirée.
            return [
                {"path": p, "line": int(line), "text": clean(text)}
                for p, line, text in rows
                if permitted(p) and (self.root / p).is_file() and not (self.root / p).is_symlink()
            ]
        finally:
            conn.close()
