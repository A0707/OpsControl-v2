"""Versions des fichiers de l'interface (?v=…) calculées depuis leur contenu.

    python deploy/assets_version.py           # met à jour web/index.html et les chargements paresseux
    python deploy/assets_version.py --check   # contrôle seulement (deploy/ci.py) : code 1 si une version est périmée

Avant : chaque ?v=N s'incrémentait à la main. Un oubli laissait les navigateurs sur
l'ancienne version (constaté : waf-controls.js et services-full.js sans version). Ici, la
version est l'empreinte du contenu (8 caractères du SHA-256, fins de ligne normalisées :
même valeur sous Windows et sur la VM) : elle change si et seulement si le fichier change.

Ordre : références paresseuses (app.js, parc-next.js), imports ES de v2-ui.js et du
point d’entrée, puis index.html. Les dépendances sont réécrites avant leurs consommateurs.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / 'web'
# Scripts qui chargent d'autres fichiers à la demande : '/chemin.js?v=…'
LAZY_HOSTS = ('app.js', 'parc-next.js', 'v2-ui.js', 'frontend-bootstrap.js')
LAZY = re.compile(r"'/([\w/-]+\.(?:js|css))(?:\?v=[\w]+)?'")
# index.html : src="/x.js" ou href="/x.css", avec ou sans ?v=
INDEX = re.compile(r'((?:src|href)=")/([\w/-]+\.(?:js|css))(?:\?v=[\w]+)?(")')


def digest(path: Path) -> str:
    data = path.read_bytes().replace(b'\r\n', b'\n')
    return hashlib.sha256(data).hexdigest()[:8]


def _rewrite(text: str, pattern, build) -> str:
    return pattern.sub(build, text)


def update(web: Path = WEB) -> list[str]:
    """Réécrit les références ; renvoie les fichiers modifiés."""
    changed = []

    def write(path, new):
        old = path.read_bytes()
        newline = b'\r\n' if b'\r\n' in old else b'\n'
        data = new.replace('\r\n', '\n').encode('utf-8').replace(b'\n', newline)
        if data != old:
            path.write_bytes(data)
            changed.append(path.name)

    for name in LAZY_HOSTS:
        path = web / name
        text = path.read_text(encoding='utf-8')
        write(path, _rewrite(text, LAZY, lambda m: f"'/{m[1]}?v={digest(web / m[1])}'" if (web / m[1]).is_file() else m[0]))
    index = web / 'index.html'
    text = index.read_text(encoding='utf-8')
    write(index, _rewrite(text, INDEX, lambda m: f'{m[1]}/{m[2]}?v={digest(web / m[2])}{m[3]}' if (web / m[2]).is_file() else m[0]))
    return changed


def stale(web: Path = WEB) -> list[str]:
    """Références périmées, sans rien écrire."""
    out = []
    for name in LAZY_HOSTS:
        for m in re.finditer(r"'/([\w/-]+\.(?:js|css))(?:\?v=([\w]+))?'", (web / name).read_text(encoding='utf-8')):
            if (web / m[1]).is_file() and m[2] != digest(web / m[1]):
                out.append(f'{name} -> {m[1]}')
    text = (web / 'index.html').read_text(encoding='utf-8')
    for m in re.finditer(r'(?:src|href)="/([\w/-]+\.(?:js|css))(?:\?v=([\w]+))?"', text):
        if (web / m[1]).is_file() and m[2] != digest(web / m[1]):
            out.append(f'index.html -> {m[1]}')
    return out


def main(argv=None) -> int:
    a = argparse.ArgumentParser(description='Versions ?v= des fichiers web, depuis leur contenu.')
    a.add_argument('--check', action='store_true')
    args = a.parse_args(argv)
    if args.check:
        out = stale()
        for line in out:
            print('  PÉRIMÉ', line)
        print(f'  {len(out)} référence(s) périmée(s)' + (' : lancer python deploy/assets_version.py' if out else ''))
        return 1 if out else 0
    changed = update()
    print('Mis à jour :', ', '.join(changed) if changed else 'rien (déjà à jour)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
