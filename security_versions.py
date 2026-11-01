"""Comparaison de versions de paquets Debian (dpkg) et RPM, sans dépendance externe.

Pourquoi ce module : un serveur n'est déclaré vulnérable qu'en comparant la version
INSTALLÉE à la version CORRIGÉE publiée par la distribution POUR LA MÊME VERSION de la
distribution. Comparer des numéros « à l'œil » (3.0.11 < 3.0.15 donc vulnérable) est faux
dès qu'une distribution rétroporte un correctif : 3.0.11-1~deb12u2 peut être corrigé.

Les deux algorithmes reprennent exactement ceux de dpkg (verrevcmp, Debian Policy §5.6.12)
et de rpm (rpmvercmp), y compris « ~ » (avant tout, même la fin de chaîne) et « ^ » (rpm).
"""
from __future__ import annotations

import re
from functools import lru_cache

_DEBIAN = re.compile(r'^(?:(\d+):)?([A-Za-z0-9.+~:-]+?)(?:-([A-Za-z0-9.+~]+))?$')


def _order(char):
    """Poids d'un caractère non numérique selon dpkg : ~ < fin < lettres < autres."""
    if char == '~':
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _verrevcmp(left, right):
    i = j = 0
    while i < len(left) or j < len(right):
        first_diff = 0
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            lc = _order(left[i]) if i < len(left) else 0
            rc = _order(right[j]) if j < len(right) else 0
            if lc != rc:
                return lc - rc
            i += 1
            j += 1
        while i < len(left) and left[i] == '0':
            i += 1
        while j < len(right) and right[j] == '0':
            j += 1
        while i < len(left) and left[i].isdigit() and j < len(right) and right[j].isdigit():
            if not first_diff:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def parse_debian(version):
    """(époque, amont, révision) ; ValueError si la chaîne n'est pas une version dpkg."""
    text = str(version or '').strip()
    match = _DEBIAN.match(text)
    if not text or not match:
        raise ValueError(f'Version Debian invalide : {text[:60]!r}')
    epoch, upstream, revision = match.groups()
    return int(epoch or 0), upstream, revision or ''


def debian_compare(left, right):
    """-1, 0 ou 1, comme « dpkg --compare-versions »."""
    a, b = parse_debian(left), parse_debian(right)
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    for x, y in ((a[1], b[1]), (a[2], b[2])):
        result = _verrevcmp(x, y)
        if result:
            return -1 if result < 0 else 1
    return 0


def _rpm_segments(text):
    return re.findall(r'~|\^|[0-9]+|[A-Za-z]+', text)


def rpmvercmp(left, right):
    """Comparaison d'une composante (version ou release) selon rpmvercmp."""
    if left == right:
        return 0
    a, b = _rpm_segments(left), _rpm_segments(right)
    while a or b:
        x = a.pop(0) if a else None
        y = b.pop(0) if b else None
        if x == '~' or y == '~':
            if x != y:
                return -1 if x == '~' else 1
            continue
        if x == '^' or y == '^':
            if x is None:
                return -1
            if y is None:
                return 1
            if x != y:
                return -1 if x == '^' else 1
            continue
        if x is None:
            return -1
        if y is None:
            return 1
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        if x.isdigit():
            x, y = int(x), int(y)
        if x != y:
            return -1 if x < y else 1
    return 0


def parse_rpm(version):
    """(époque, version, release) depuis « [E:]V-R »."""
    text = str(version or '').strip()
    if not text or not re.fullmatch(r'(?:\d+:)?[A-Za-z0-9._+~^]+(?:-[A-Za-z0-9._+~^]+)?', text):
        raise ValueError(f'Version RPM invalide : {text[:60]!r}')
    epoch, _, rest = text.rpartition(':')
    value, _, release = rest.partition('-')
    return int(epoch or 0), value, release


def rpm_compare(left, right):
    a, b = parse_rpm(left), parse_rpm(right)
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    result = rpmvercmp(a[1], b[1])
    if result or not (a[2] and b[2]):
        return result
    return rpmvercmp(a[2], b[2])


def compare(manager, left, right):
    """Comparaison selon le gestionnaire de paquets ('dpkg' ou 'rpm')."""
    return debian_compare(left, right) if manager == 'dpkg' else rpm_compare(left, right)


@lru_cache(maxsize=4096)
def _older_cached(manager, installed, fixed):
    # La comparaison est pure : les mêmes paquets apparaissent dans des milliers
    # de CVE et sur plusieurs hôtes. La borne évite de retenir tout l'historique.
    return compare(manager, installed, fixed) < 0


def is_older(manager, installed, fixed):
    """True si `installed` < `fixed`, None si une version est illisible (jamais deviné)."""
    try:
        if all(isinstance(value, str) for value in (manager, installed, fixed)):
            return _older_cached(manager, installed, fixed)
        return compare(manager, installed, fixed) < 0
    except ValueError:
        return None


# --------------------------------------------------------------------------- versions amont
# Bulletins des éditeurs (NVD, avis PHP/WordPress) : versions AMONT (8.2.35), sans époque ni
# révision de distribution. rpmvercmp les ordonne correctement (segments numériques et
# alphabétiques, « ~ » avant tout).
UPSTREAM = re.compile(r'^[0-9][A-Za-z0-9._+~-]{0,60}$')


def upstream_of(manager, version):
    """Version amont d'un paquet de distribution : sans époque ni révision Debian/RPM.

    « 1:9.2p1-2+deb12u3 » -> « 9.2p1 » ; « 8.2.31-1~deb12u1 » -> « 8.2.31 ». Les suffixes de
    reconditionnement (+dfsg, ~ds) sont retirés : ils ne changent pas le code amont."""
    text = str(version or '').strip()
    if ':' in text:
        text = text.split(':', 1)[1]
    if manager in ('dpkg', 'rpm') and '-' in text:
        text = text.rsplit('-', 1)[0]
    text = re.split(r'[+~](?:dfsg|ds|repack|really)', text)[0]
    return text if UPSTREAM.fullmatch(text) else None


def upstream_compare(left, right):
    """Ordre des versions amont. Versions purement numériques : segments manquants à zéro,
    car les éditeurs écrivent « 7.1 » pour 7.1.0 (WordPress) et une plage « 7.1.0 - 7.1 »
    deviendrait sinon vide."""
    left, right = str(left), str(right)
    if re.fullmatch(r'\d+(\.\d+)*', left) and re.fullmatch(r'\d+(\.\d+)*', right):
        a, b = [int(x) for x in left.split('.')], [int(x) for x in right.split('.')]
        size = max(len(a), len(b))
        a, b = a + [0] * (size - len(a)), b + [0] * (size - len(b))
        return (a > b) - (a < b)
    return rpmvercmp(left, right)


def in_range(version, start=None, start_included=True, end=None, end_included=False):
    """True/False si `version` est dans la plage ; None si une borne est illisible."""
    if not UPSTREAM.fullmatch(str(version or '')):
        return None
    if start is not None:
        if not UPSTREAM.fullmatch(str(start)):
            return None
        c = upstream_compare(version, start)
        if c < 0 or (c == 0 and not start_included):
            return False
    if end is not None:
        if not UPSTREAM.fullmatch(str(end)):
            return None
        c = upstream_compare(version, end)
        if c > 0 or (c == 0 and not end_included):
            return False
    return True


def branch_in_range(branch, start=None, start_included=True, end=None, end_included=False):
    """Version connue à la branche seulement (tag Docker « 8.2 ») : 'all', 'some' ou 'none'.

    'all' : toute la branche est affectée (ex. 7.4 avec « < 8.2.35 ») ; 'some' : la conclusion
    dépend du correctif installé, donc potentielle ; 'none' : branche hors plage."""
    if not re.fullmatch(r'\d+(\.\d+)?', str(branch or '')):
        return None

    def head(value):
        return '.'.join(str(value).split('.')[:len(branch.split('.'))])
    if end is not None:
        if upstream_compare(head(end), branch) < 0 or (head(end) == branch and upstream_compare(end, branch) == 0 and not end_included):
            return 'none'
    if start is not None and upstream_compare(head(start), branch) > 0:
        return 'none'
    whole_start = start is None or upstream_compare(head(start), branch) < 0 or \
        all(p == '0' for p in str(start).split('.')[len(branch.split('.')):])
    whole_end = end is None or upstream_compare(head(end), branch) > 0
    return 'all' if whole_start and whole_end else 'some'
