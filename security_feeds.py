"""Sources de veille sécurité publiques, lues en HTTPS et normalisées.

Lecture seule, comme le reste d'OpsControl : chaque source est un GET HTTPS vérifié,
sans redirection, à taille bornée. Rien n'est envoyé aux sources, sauf la clé NVD
facultative (NVD_API_KEY, variable d'environnement du service, jamais enregistrée).

Sources et rôle :
    CISA KEV       CVE exploitées activement (priorisation, jamais une détection seule)
    NVD            score CVSS et description d'une CVE (enrichissement)
    CERT-FR        avis et alertes (veille ; CVE extraites du bulletin)
    Debian DSA/DLA correctifs publiés par release Debian : version corrigée exacte, donc
                   compatible avec les rétroportages (base de la détection Debian)
    FIRST EPSS     probabilité d'exploitation à 30 jours (priorisation)
    Avis PHP et WordPress (GitHub Security Advisories officiels de php/php-src et
                   WordPress/wordpress-develop) : CVE, gravité et plages de versions
    PHP, WordPress, Fortinet PSIRT, Proxmox : bulletins de veille (flux RSS/Atom)

Une URL se remplace ou se désactive (« off ») par INFRAOPS_SECURITY_FEED_<SOURCE>
(ex. miroir interne) : utile pour un serveur sans accès Internet direct.

Requêtes conditionnelles (If-None-Match / If-Modified-Since) : une source inchangée répond
304 sans corps, ce qui permet une synchronisation horaire sans retélécharger les listes.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET  # nosec B405 — DTD et entités refusées avant analyse (parse_xml)
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

CVE = re.compile(r'CVE-\d{4}-\d{4,7}')
USER_AGENT = 'OpsControl-veille/2 (lecture seule)'

# Nom de source -> (URL par défaut, taille maximale en octets, nature).
SOURCES = {
    'kev': ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            16 * 1048576, 'CISA KEV'),
    # CERT-FR a migré vers cert.cyber.gouv.fr : l'ancienne adresse répond 302, refusé ici.
    'certfr_avis': ('https://cert.cyber.gouv.fr/avis/feed/', 4 * 1048576, 'CERT-FR (avis)'),
    'certfr_alertes': ('https://cert.cyber.gouv.fr/alerte/feed/', 4 * 1048576, 'CERT-FR (alertes)'),
    'debian_dsa': ('https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list',
                   24 * 1048576, 'Debian Security Tracker (DSA)'),
    'debian_dla': ('https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list',
                   24 * 1048576, 'Debian Security Tracker (DLA)'),
    'php_advisories': ('https://api.github.com/repos/php/php-src/security-advisories?per_page=50&sort=published',
                       4 * 1048576, 'PHP (avis de sécurité officiels)'),
    'php': ('https://www.php.net/releases/feed.php', 4 * 1048576, 'PHP (versions publiées)'),
    'wordpress_advisories': ('https://api.github.com/repos/WordPress/wordpress-develop/security-advisories?per_page=50&sort=published',
                             4 * 1048576, 'WordPress (avis de sécurité officiels)'),
    'wordpress': ('https://wordpress.org/news/category/security/feed/', 4 * 1048576, 'WordPress (annonces de sécurité)'),
    'fortinet': ('https://filestore.fortinet.com/fortiguard/rss/ir.xml', 4 * 1048576, 'Fortinet PSIRT'),
    'proxmox': ('https://forum.proxmox.com/forums/announcements.7/index.rss', 4 * 1048576, 'Proxmox (annonces)'),
}
# Produit concerné par les avis structurés (plages de versions) d'une source.
ADVISORY_PRODUCTS = {'php_advisories': 'php', 'wordpress_advisories': 'wordpress'}
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
NVD_SEARCH = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EPSS_URL = 'https://api.first.org/data/v1/epss?cve='
CERTFR_JSON = re.compile(r'^https://(?:www\.cert\.ssi\.gouv\.fr|cert\.cyber\.gouv\.fr)/(avis|alerte)/'
                         r'(CERTFR-\d{4}-(?:AVI|ALE)-\d{3,5})/?$')


def certfr_json_url(link):
    """Version JSON d'un bulletin, sur l'adresse actuelle (l'ancienne redirige)."""
    match = CERTFR_JSON.match(link or '')
    return f'https://cert.cyber.gouv.fr/{match[1]}/{match[2]}/json/' if match else None
# Releases Debian suivies (les plus anciennes n'ont plus de correctif publié).
DEBIAN_RELEASES = ('stretch', 'buster', 'bullseye', 'bookworm', 'trixie', 'forky')


class FeedError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def source_url(name):
    """URL effective de la source, ou None si désactivée par variable d'environnement."""
    default = SOURCES[name][0]
    value = os.getenv('INFRAOPS_SECURITY_FEED_' + name.upper(), '').strip()
    if value.lower() in ('off', '0', 'false', 'non'):
        return None
    return value or default


class NotModified(Exception):
    """Réponse 304 : la source n'a pas changé depuis la dernière synchronisation."""


class Body(bytes):
    """Corps de réponse avec ses validateurs de cache (ETag, Last-Modified)."""
    etag = None
    last_modified = None


def fetch(url, limit, headers=None, timeout=30):
    """GET HTTPS vérifié, sans redirection, refusé au-delà de `limit` octets.

    Renvoie un Body (bytes + etag/last_modified) ; lève NotModified sur 304, FeedError sinon.
    HTTP 429 et 503 portent « limitation » dans le message : la source est alors espacée."""
    if urlsplit(url).scheme != 'https':
        raise FeedError('HTTPS requis pour une source de veille')
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': '*/*', **(headers or {})})
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(limit + 1)
            body = Body(raw)
            received = getattr(response, 'headers', None) or {}
            body.etag = (received.get('ETag') or '')[:200] or None
            body.last_modified = (received.get('Last-Modified') or '')[:100] or None
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            raise NotModified() from None
        if 300 <= exc.code < 400:
            raise FeedError(f'Redirection refusée (HTTP {exc.code}) : configurer l’URL finale') from None
        if exc.code in (403, 429, 503):
            raise FeedError(f'HTTP {exc.code} : limitation de débit de la source') from None
        raise FeedError(f'HTTP {exc.code}') from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, 'reason', exc)
        raise FeedError('Source injoignable : ' + type(reason).__name__) from None
    if len(body) > limit:
        raise FeedError('Réponse trop volumineuse')
    return body


def parse_xml(body):
    """XML sans DTD ni entité : ferme XXE et l'expansion d'entités (« billion laughs »)."""
    head = body[:4096].lower()
    if b'<!doctype' in head or b'<!entity' in body.lower():
        raise FeedError('Flux XML refusé : DTD ou entité déclarée')
    try:
        return ET.fromstring(body)  # nosec B314 — DTD/entités refusées ci-dessus, aucune résolution externe
    except ET.ParseError as exc:
        raise FeedError('Flux XML illisible') from exc


def _iso(value):
    """Date RSS (RFC 822) ou Atom (ISO 8601) en ISO UTC, sinon None."""
    text = str(value or '').strip()
    if not text:
        return None
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        try:
            moment = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except ValueError:
            return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def _text(node):
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', ''.join(node.itertext()) if node is not None else '')).strip()


def parse_feed(body, source):
    """RSS 2.0 ou Atom -> bulletins {id, title, url, published, summary, cves}."""
    root = parse_xml(body)
    items = []
    atom = '{http://www.w3.org/2005/Atom}'
    entries = root.findall('.//item') or root.findall('.//' + atom + 'entry')
    for entry in entries[:300]:
        def first(*names):
            for name in names:
                node = entry.find(name)
                if node is not None:
                    return node
            return None
        title = _text(first('title', atom + 'title'))[:300]
        link_node = first('link', atom + 'link')
        url = ''
        if link_node is not None:
            url = (link_node.get('href') or link_node.text or '').strip()
        summary = _text(first('description', atom + 'summary', atom + 'content'))[:2000]
        # Un élément sans enfant est « faux » en booléen : test explicite à None.
        date_node = first('pubDate', atom + 'published', atom + 'updated')
        published = _iso(date_node.text if date_node is not None else None)
        ident = (_text(first('guid', atom + 'id')) or url or title)[:300]
        if not title:
            continue
        cves = sorted(set(CVE.findall(title + ' ' + summary)))
        items.append({'id': ident, 'title': title, 'url': url if url.startswith('https://') else '',
                      'published': published, 'summary': summary, 'cves': cves, 'source': source})
    return items


def parse_kev(body):
    """Catalogue CISA KEV -> {cve: entrée}. Une CVE absente n'est PAS « non exploitée »."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise FeedError('Catalogue KEV illisible') from exc
    rows = data.get('vulnerabilities') if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise FeedError('Catalogue KEV inattendu')
    out = {}
    for row in rows:
        if not isinstance(row, dict) or not CVE.fullmatch(str(row.get('cveID', ''))):
            continue
        out[row['cveID']] = {
            'vendor': str(row.get('vendorProject') or '')[:120], 'product': str(row.get('product') or '')[:120],
            'name': str(row.get('vulnerabilityName') or '')[:300], 'added': str(row.get('dateAdded') or '')[:10],
            'due': str(row.get('dueDate') or '')[:10], 'action': str(row.get('requiredAction') or '')[:600],
            'ransomware': str(row.get('knownRansomwareCampaignUse') or '')[:20],
            'description': str(row.get('shortDescription') or '')[:1200],
        }
    return out


_DSA_HEAD = re.compile(r'^\[(\d{1,2} \w{3} \d{4})\] ((?:DSA|DLA)-\d+(?:-\d+)?) (\S+)(?: - (.*))?$')
_DSA_FIX = re.compile(r'^\s+\[(\w+)\] - (\S+) (\S+)')
_DSA_CVE = re.compile(r'^\s+\{([^}]*)\}')


def parse_debian_list(text):
    """Liste DSA/DLA du tracker Debian -> correctifs {advisory, release, package, fixed, cves, date}.

    `package` est le paquet SOURCE ; `fixed` la version corrigée publiée dans CETTE release.
    Les mentions <not-affected>, <unfixed>, <end-of-life>… ne donnent pas de version : ignorées."""
    out, current = [], None
    for line in text.splitlines():
        head = _DSA_HEAD.match(line)
        if head:
            try:
                date = datetime.strptime(head[1], '%d %b %Y').date().isoformat()
            except ValueError:
                date = None
            current = {'advisory': head[2], 'package': head[3], 'title': (head[4] or '')[:200], 'date': date, 'cves': []}
            continue
        if current is None:
            continue
        cves = _DSA_CVE.match(line)
        if cves:
            current['cves'] = sorted(set(CVE.findall(cves[1])))
            continue
        fix = _DSA_FIX.match(line)
        if fix and fix[1] in DEBIAN_RELEASES and not fix[3].startswith('<'):
            out.append({'advisory': current['advisory'], 'release': fix[1], 'package': fix[2], 'fixed': fix[3],
                        'cves': current['cves'], 'date': current['date'], 'title': current['title']})
    return out


_CPE = re.compile(r'^cpe:2\.3:([aoh]):([^:]+):([^:]+):([^:]*):')


def _cpe_match(match):
    """Critère NVD -> {part, vendor, product, version exacte, bornes} ; None si illisible."""
    parts = _CPE.match(str(match.get('criteria') or ''))
    if not parts:
        return None
    exact = parts[4] if parts[4] not in ('*', '-', '') else None
    start = match.get('versionStartIncluding') or match.get('versionStartExcluding')
    end = match.get('versionEndExcluding') or match.get('versionEndIncluding')
    return {'part': parts[1], 'vendor': parts[2].lower(), 'product': parts[3].lower(), 'exact': exact,
            'start': start, 'start_included': 'versionStartIncluding' in match,
            'end': end, 'end_included': 'versionEndIncluding' in match}


def _configurations(cve):
    """Configurations NVD normalisées : produits vulnérables et plateformes requises (AND).

    Exemple réel : CVE-2024-4577 = PHP < 8.1.29… ET Windows (plateforme non vulnérable) ;
    un serveur Linux n'est donc pas concerné. Ignorer cette condition produirait un faux positif."""
    out = []
    for config in cve.get('configurations') or []:
        vulnerable, platforms = [], []
        for node in config.get('nodes') or []:
            if node.get('negate'):
                continue
            for match in node.get('cpeMatch') or []:
                parsed = _cpe_match(match)
                if parsed:
                    (vulnerable if match.get('vulnerable') else platforms).append(parsed)
        if vulnerable:
            out.append({'vulnerable': vulnerable[:200],
                        'platforms': platforms[:50] if config.get('operator') == 'AND' else []})
    return out[:50]


def _nvd_record(cve):
    metrics = cve.get('metrics') or {}
    score, fallback = None, None
    # Score « Primary » de NVD d'abord, quelle que soit la version CVSS ; sinon le premier disponible.
    for key, version in (('cvssMetricV40', '4.0'), ('cvssMetricV31', '3.1'), ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0')):
        for row in metrics.get(key) or []:
            data = row.get('cvssData') or {}
            if not isinstance(data.get('baseScore'), (int, float)):
                continue
            item = {'cvss': float(data['baseScore']), 'vector': str(data.get('vectorString') or '')[:200], 'version': version,
                    'severity': str(data.get('baseSeverity') or row.get('baseSeverity') or '')[:20]}
            if row.get('type') == 'Primary' and score is None:
                score = item
            fallback = fallback or item
    score = score or fallback
    descriptions = cve.get('descriptions') or []
    text = next((d.get('value') for d in descriptions if d.get('lang') == 'fr'), None) or \
        next((d.get('value') for d in descriptions if d.get('lang') == 'en'), '')
    return {**(score or {'cvss': None, 'vector': None, 'version': None, 'severity': None}),
            'published': _iso(cve.get('published')), 'last_modified': _iso(cve.get('lastModified')),
            'status': str(cve.get('vulnStatus') or '')[:40] or None, 'description': str(text or '')[:2000],
            'configurations': _configurations(cve), 'kev_added': cve.get('cisaExploitAdd')}


def parse_nvd(body):
    """Réponse NVD 2.0 pour une CVE -> enregistrement normalisé, ou None si inconnue de NVD."""
    records = parse_nvd_page(body)['items']
    return records[0][1] if records else None


def parse_nvd_page(body):
    """Page NVD 2.0 (une CVE ou une recherche) -> {'items': [(cve, enregistrement)], 'total'}."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise FeedError('Réponse NVD illisible') from exc
    items = data.get('vulnerabilities') if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise FeedError('Réponse NVD inattendue')
    out = []
    for item in items:
        cve = (item or {}).get('cve') or {}
        if CVE.fullmatch(str(cve.get('id') or '')):
            out.append((cve['id'], _nvd_record(cve)))
    return {'items': out, 'total': data.get('totalResults', len(out)), 'start': data.get('startIndex', 0)}


def nvd_search_url(vendor, product, start, end, index=0, part='a'):
    """CVE modifiées pour un produit (CPE) dans une fenêtre, au format attendu par NVD."""
    fmt = '%Y-%m-%dT%H:%M:%S.000Z'
    return (f'{NVD_SEARCH}?virtualMatchString=cpe:2.3:{part}:{vendor}:{product}'
            f'&lastModStartDate={start.astimezone(timezone.utc).strftime(fmt)}'
            f'&lastModEndDate={end.astimezone(timezone.utc).strftime(fmt)}&resultsPerPage=500&startIndex={index}')


def parse_epss(body):
    """API FIRST EPSS -> {cve: {epss, percentile, date}}. Une CVE absente n'a PAS un score nul."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise FeedError('Réponse EPSS illisible') from exc
    rows = data.get('data') if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise FeedError('Réponse EPSS inattendue')
    out = {}
    for row in rows:
        try:
            epss, percentile = float(row['epss']), float(row['percentile'])
        except (KeyError, TypeError, ValueError):
            continue
        if CVE.fullmatch(str(row.get('cve') or '')) and 0 <= epss <= 1 and 0 <= percentile <= 1:
            out[row['cve']] = {'epss': epss, 'percentile': percentile, 'date': str(row.get('date') or '')[:10]}
    return out


_RANGE_PART = re.compile(r'^\s*(<=|>=|<|>|=)?\s*([0-9][A-Za-z0-9._+~-]*)\s*$')


def parse_range(text, patched=None):
    """Plage d'un avis GitHub (« < 8.2.35 », « 7.1.0 - 7.1.1 », « >= 8.3.0, < 8.3.36 »)
    -> {start, start_included, end, end_included, fixed}, ou None si illisible (jamais devinée)."""
    text = str(text or '').strip()
    out = {'start': None, 'start_included': True, 'end': None, 'end_included': False,
           'fixed': str(patched).split(',')[0].strip() or None if patched else None}
    dash = re.fullmatch(r'([0-9][A-Za-z0-9._+~-]*)\s+-\s+([0-9][A-Za-z0-9._+~-]*)', text)
    if dash:
        out.update(start=dash[1], end=dash[2], end_included=True)
        return out
    for part in text.split(','):
        match = _RANGE_PART.match(part)
        if not match:
            return None
        op, version = match[1] or '=', match[2]
        if op in ('<', '<='):
            out.update(end=version, end_included=op == '<=')
        elif op in ('>', '>='):
            out.update(start=version, start_included=op == '>=')
        else:
            out.update(start=version, end=version, end_included=True)
    return out if out['start'] or out['end'] else None


def _branch_bounds(ranges):
    """Bornes basses implicites des avis par branche.

    L'avis PHP publie « < 8.2.35 », « < 8.3.36 », « < 8.4.27 », « < 8.5.12 » : chaque borne
    vaut pour SA branche (8.4.0 ≤ v < 8.4.27), et seule la plus basse couvre aussi les
    branches plus anciennes (c'est la lecture de NVD pour ces CVE). Lues telles quelles,
    « < 8.4.27 » englobait PHP 8.3.36, pourtant corrigé : faux positif."""
    import security_versions
    open_ranges = [r for r in ranges if not r.get('start') and r.get('end') and re.match(r'\d+\.\d+', str(r['end']))]
    if len(open_ranges) < 2:
        return ranges
    lowest = min(open_ranges, key=lambda r: [int(x) for x in re.findall(r'\d+', str(r['end']))[:3]])
    for r in open_ranges:
        if r is not lowest:
            branch = re.match(r'(\d+\.\d+)', str(r['end']))[1]
            if not str(r['end']).startswith(branch + '.') or security_versions.upstream_compare(r['end'], branch + '.0') <= 0:
                continue
            r['start'], r['start_included'] = branch + '.0', True
    return ranges


def parse_ghsa(body, product):
    """Avis GitHub officiels d'un éditeur (php/php-src, WordPress/wordpress-develop).

    -> bulletins {id, title, url, published, summary, cves, severity, cvss, ranges}. Les plages
    viennent de l'éditeur ; un avis sans CVE reste listé, identifié par son GHSA."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise FeedError('Avis GitHub illisibles') from exc
    if not isinstance(data, list):
        raise FeedError('Réponse GitHub inattendue (limite de débit ?)')
    out = []
    for item in data[:200]:
        if not isinstance(item, dict) or not re.fullmatch(r'GHSA(-[a-z0-9]{4}){3}', str(item.get('ghsa_id') or '')):
            continue
        ranges = []
        for vuln in item.get('vulnerabilities') or []:
            parsed = parse_range(vuln.get('vulnerable_version_range'), vuln.get('patched_versions'))
            if parsed:
                ranges.append({**parsed, 'component': str((vuln.get('package') or {}).get('name') or '')[:80]})
        ranges = _branch_bounds(ranges)
        cve = item.get('cve_id') if CVE.fullmatch(str(item.get('cve_id') or '')) else None
        cvss = ((item.get('cvss_severities') or {}).get('cvss_v3') or {}).get('score') or (item.get('cvss') or {}).get('score')
        out.append({'id': item['ghsa_id'], 'title': str(item.get('summary') or item['ghsa_id'])[:300],
                    'url': str(item.get('html_url') or '') if str(item.get('html_url') or '').startswith('https://') else '',
                    'published': _iso(item.get('published_at')), 'updated': _iso(item.get('updated_at')),
                    'summary': re.sub(r'\s+', ' ', str(item.get('description') or ''))[:2000],
                    'cves': [cve] if cve else [], 'severity': str(item.get('severity') or '')[:20].lower() or None,
                    'cvss': float(cvss) if isinstance(cvss, (int, float)) and cvss > 0 else None,
                    'products': [product], 'ranges': ranges[:20], 'product': product})
    return out


def parse_certfr_json(body):
    """Bulletin CERT-FR (format JSON) -> CVE et produits concernés, lus défensivement."""
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise FeedError('Bulletin CERT-FR illisible') from exc
    cves = sorted(set(CVE.findall(json.dumps(data.get('cves', data) if isinstance(data, dict) else data))))
    products = []
    for item in (data.get('affected_systems') or []) if isinstance(data, dict) else []:
        if isinstance(item, dict):
            product = item.get('product') or {}
            vendor = str((product.get('vendor') or {}).get('name') or '')
            name = str(product.get('name') or '')
            # « N/A » : le CERT-FR décrit alors le produit dans le texte (« PHP versions antérieures à… »).
            label = vendor + ' ' + name if name and name != 'N/A' else vendor + ' — ' + str(item.get('description') or '')
            products.append(label.strip(' —')[:200])
    return {'cves': cves, 'products': [p for p in products if p][:40]}


def severity_of(cvss):
    """Gravité CVSS (échelle NVD) ; None quand la source ne fournit pas de score."""
    if cvss is None:
        return None
    return 'critical' if cvss >= 9 else 'high' if cvss >= 7 else 'medium' if cvss >= 4 else 'low' if cvss > 0 else 'none'
