"""Veille sécurité en ligne : synchronisation des sources publiques, côté serveur uniquement.

Le navigateur ne contacte jamais ces sources : seul le service OpsControl le fait, en GET
HTTPS vérifié (security_feeds.fetch). Pour chaque source :

- état persistant (sec_source_state) : opérationnelle / en erreur / désactivée, dernière
  tentative, dernier succès, erreurs consécutives, dernier message ;
- requêtes conditionnelles (ETag, Last-Modified) : une source inchangée répond 304 ;
- espacement après erreur (backoff exponentiel, plus long sur une limitation de débit) ;
- débit borné par domaine (Pacer) : NVD 5 requêtes / 30 s sans clé (règle publiée par NVD),
  50 avec clé ; GitHub et FIRST une requête par seconde ;
- déduplication : un bulletin est identifié par (source, identifiant) et mis à jour s'il
  est révisé ; une CVE n'a qu'un enregistrement, ses changements sont historisés.

Clés facultatives, lues dans l'environnement du service (coffre DPAPI sur le poste,
/etc/infraops/secrets.env sur la VM), jamais en base ni dans les réponses : NVD_API_KEY,
GITHUB_TOKEN.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit

import security_correlation as correlation
import security_feeds as feeds
from audit_engine import redact

BACKOFF_FIRST = 300          # 5 min après une première erreur, puis doublé
BACKOFF_MAX = 6 * 3600
NVD_WINDOW_FIRST_DAYS = 30   # première fenêtre de recherche par produit (NVD : 120 j au plus)
NVD_PAGES = 5


def now():
    return datetime.now(timezone.utc)


def iso(moment=None):
    return (moment or now()).isoformat()


class Pacer:
    """Intervalle minimal entre deux requêtes vers un même domaine."""

    def __init__(self, stop=None, sleep=None):
        self.last, self.stop, self.sleep = {}, stop, sleep

    def interval(self, url):
        host = urlsplit(url).hostname or ''
        if host.endswith('nvd.nist.gov'):
            return 0.7 if os.getenv('NVD_API_KEY', '').strip() else 6.5
        return 1.0 if host in ('api.github.com', 'api.first.org') else 0.0

    def wait(self, url):
        host = urlsplit(url).hostname or ''
        pause = self.interval(url) - (time.monotonic() - self.last.get(host, -1e9))
        if pause > 0:
            if self.sleep is not None:
                self.sleep(pause)
            elif self.stop is not None:
                if self.stop.wait(pause):
                    raise InterruptedError('Arrêt demandé')
            else:
                time.sleep(pause)
        self.last[host] = time.monotonic()


def headers_for(url):
    """En-têtes propres à une source ; les clés viennent de l'environnement du service."""
    host = urlsplit(url).hostname or ''
    out = {}
    if host == 'api.github.com':
        out = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if os.getenv('GITHUB_TOKEN', '').strip():
            out['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN'].strip()
    elif host.endswith('nvd.nist.gov') and os.getenv('NVD_API_KEY', '').strip():
        out['apiKey'] = os.environ['NVD_API_KEY'].strip()
    return out


# --------------------------------------------------------------------------- état des sources
def state(db, source):
    row = db.execute('SELECT last_attempt, last_success, status, failures, last_error, etag, last_modified, next_after, items '
                     'FROM sec_source_state WHERE source=?', (source,)).fetchone()
    names = ('last_attempt', 'last_success', 'status', 'failures', 'last_error', 'etag', 'last_modified', 'next_after', 'items')
    return dict(zip(names, row)) if row else {'failures': 0, 'status': 'never'}


def mark_ok(db, source, items=None, etag=None, last_modified=None, keep_validators=False):
    stamp = iso()
    previous = state(db, source)
    db.execute('INSERT OR REPLACE INTO sec_source_state(source, last_attempt, last_success, status, failures, last_error, etag, '
               'last_modified, next_after, items) VALUES(?,?,?,?,0,NULL,?,?,NULL,?)',
               (source, stamp, stamp, 'ok', previous.get('etag') if keep_validators else etag,
                previous.get('last_modified') if keep_validators else last_modified,
                items if items is not None else previous.get('items')))


def mark_failed(db, source, error):
    previous = state(db, source)
    failures = int(previous.get('failures') or 0) + 1
    delay = min(BACKOFF_FIRST * 2 ** (failures - 1), BACKOFF_MAX)
    if 'limitation' in str(error):
        delay = min(delay * 4, BACKOFF_MAX * 4)
    db.execute('INSERT OR REPLACE INTO sec_source_state(source, last_attempt, last_success, status, failures, last_error, etag, '
               'last_modified, next_after, items) VALUES(?,?,?,?,?,?,?,?,?,?)',
               (source, iso(), previous.get('last_success'), 'error', failures, redact(str(error))[:500], previous.get('etag'),
                previous.get('last_modified'), iso(now() + timedelta(seconds=delay)), previous.get('items')))
    return failures


def in_backoff(db, source):
    current = state(db, source)
    try:
        return current.get('status') == 'error' and datetime.fromisoformat(current['next_after']) > now()
    except (TypeError, ValueError, KeyError):
        return False


def record_sync(db, source, status, items=0, new=0, detail=None):
    db.execute('INSERT INTO sec_syncs(source, at, status, items, new_items, detail) VALUES(?,?,?,?,?,?)',
               (source, iso(), status, items, new, redact(str(detail))[:500] if detail else None))


# --------------------------------------------------------------------------- stockage
def store_advisories(db, items, source):
    """Insère ou met à jour (bulletin révisé) ; renvoie le nombre de NOUVEAUX bulletins."""
    new = 0
    stamp = iso()
    for item in items:
        digest = hashlib.sha256(json.dumps([item['title'], item.get('summary'), item.get('cves'), item.get('ranges'),
                                            item.get('severity')], sort_keys=True).encode()).hexdigest()[:16]
        values = (item['title'][:300], item.get('url') or '', item.get('published'), (item.get('summary') or '')[:2000],
                  json.dumps(item.get('cves') or []), json.dumps(item.get('products') or []), digest, item.get('severity'),
                  item.get('cvss'), json.dumps(item['ranges']) if item.get('ranges') else None, item.get('updated'))
        row = db.execute('SELECT digest FROM sec_advisories WHERE source=? AND id=?', (source, item['id'])).fetchone()
        if row is None:
            new += 1
            db.execute('INSERT INTO sec_advisories(title, url, published, summary, cves, products, digest, severity, cvss, ranges, '
                       'updated, source, id, first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                       values + (source, item['id'][:300], stamp))
        elif row[0] != digest:
            # Bulletin révisé : contenu mis à jour, date de première observation conservée.
            db.execute('UPDATE sec_advisories SET title=?, url=?, published=?, summary=?, cves=?, products=?, digest=?, severity=?, '
                       'cvss=?, ranges=?, updated=? WHERE source=? AND id=?', values + (source, item['id']))
    return new


NVD_FIELDS = ('cvss', 'severity', 'vector', 'cvss_version', 'description', 'published', 'nvd_config', 'nvd_status', 'nvd_modified')


def store_nvd(db, cve, record):
    """Enregistrement NVD d'une CVE ; chaque changement de score, statut ou configuration
    est historisé (sec_cve_changes) : « CVE mise à jour » visible dans la veille."""
    record = record or {}
    new = {'cvss': record.get('cvss'), 'severity': feeds.severity_of(record.get('cvss')), 'vector': record.get('vector'),
           'cvss_version': record.get('version'), 'description': record.get('description'), 'published': record.get('published'),
           'nvd_config': json.dumps(record.get('configurations') or []), 'nvd_status': record.get('status'),
           'nvd_modified': record.get('last_modified')}
    row = db.execute('SELECT ' + ', '.join(NVD_FIELDS) + ', nvd_at FROM sec_cve WHERE cve=?', (cve,)).fetchone()  # nosec B608 — colonnes fixes
    if row is not None and row[-1]:
        old = dict(zip(NVD_FIELDS, row))
        for field in ('cvss', 'nvd_status', 'nvd_config'):
            if old[field] != new[field] and not (field == 'nvd_config' and old[field] in (None, '[]') and new[field] == '[]'):
                shown = (lambda v: 'configurations modifiées' if field == 'nvd_config' else v)
                db.execute('INSERT INTO sec_cve_changes(cve, at, field, old, new) VALUES(?,?,?,?,?)',
                           (cve, iso(), field, None if old[field] is None else str(shown(old[field]))[:200],
                            None if new[field] is None else str(shown(new[field]))[:200]))
    db.execute('INSERT INTO sec_cve(cve, ' + ', '.join(NVD_FIELDS) + ', nvd_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) '  # nosec B608
               'ON CONFLICT(cve) DO UPDATE SET ' + ', '.join(f'{f}=excluded.{f}' for f in NVD_FIELDS) + ', nvd_at=excluded.nvd_at',
               (cve,) + tuple(new[f] for f in NVD_FIELDS) + (iso(),))


def _store_kev(db, entries):
    for cve, e in entries.items():
        db.execute('INSERT INTO sec_cve(cve, kev, kev_added, kev_due, kev_action, kev_ransomware) VALUES(?,1,?,?,?,?) '
                   'ON CONFLICT(cve) DO UPDATE SET kev=1, kev_added=excluded.kev_added, kev_due=excluded.kev_due, '
                   'kev_action=excluded.kev_action, kev_ransomware=excluded.kev_ransomware',
                   (cve, e['added'], e['due'], e['action'], e['ransomware']))
    # Une CVE retirée du catalogue n'est plus marquée exploitée.
    for (cve,) in db.execute('SELECT cve FROM sec_cve WHERE kev=1').fetchall():
        if cve not in entries:
            db.execute('UPDATE sec_cve SET kev=0 WHERE cve=?', (cve,))
    limit_day = (date.today() - timedelta(days=60)).isoformat()
    recent = [{'id': cve, 'title': f'{cve} — {e["vendor"]} {e["product"]} : {e["name"]}'.strip(),
               'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
               'published': e['added'] + 'T00:00:00+00:00' if e['added'] else None,
               'summary': e['description'] + (' Action requise : ' + e['action'] if e['action'] else ''),
               'cves': [cve], 'products': [f'{e["vendor"]} {e["product"]}'.strip()]}
              for cve, e in entries.items() if e['added'] >= limit_day]
    return store_advisories(db, recent, 'kev'), len(entries)


def _store_debian(db, name, body):
    fixes = feeds.parse_debian_list(body.decode('utf-8', 'replace'))
    if not fixes:
        raise feeds.FeedError('Liste Debian vide ou format inattendu')
    origin = 'DSA' if name == 'debian_dsa' else 'DLA'
    before = db.execute('SELECT count(*) FROM sec_fixes WHERE origin=?', (origin,)).fetchone()[0]
    db.executemany('INSERT OR REPLACE INTO sec_fixes(origin, advisory, release, package, fixed, cves, date, title) '
                   'VALUES(?,?,?,?,?,?,?,?)',
                   [(origin, f['advisory'], f['release'], f['package'], f['fixed'], json.dumps(f['cves']), f['date'], f['title'])
                    for f in fixes])
    return max(0, db.execute('SELECT count(*) FROM sec_fixes WHERE origin=?', (origin,)).fetchone()[0] - before), len(fixes)


# --------------------------------------------------------------------------- synchronisation
def sync(context, stop=None, fetch=None, force=False, pacer=None):
    """Synchronise toutes les sources ; chaque source échoue seule. `force` (action manuelle)
    ignore l'espacement après erreur, jamais le débit par domaine."""
    fetch = fetch or feeds.fetch
    pacer = pacer or Pacer(stop)
    report = []

    def get(url, limit, conditional=None):
        pacer.wait(url)
        headers = headers_for(url)
        if conditional:
            if conditional.get('etag'):
                headers['If-None-Match'] = conditional['etag']
            if conditional.get('last_modified'):
                headers['If-Modified-Since'] = conditional['last_modified']
        return fetch(url, limit, headers=headers or None)

    for name, (_, limit, label) in feeds.SOURCES.items():
        if stop is not None and stop.is_set():
            break
        url = feeds.source_url(name)
        with context.connect() as db:
            if url is None:
                db.execute("INSERT OR REPLACE INTO sec_source_state(source, status, failures) VALUES(?, 'disabled', 0)", (name,))
                report.append({'source': name, 'label': label, 'status': 'disabled'})
                continue
            if not force and in_backoff(db, name):
                report.append({'source': name, 'label': label, 'status': 'backoff', 'error': state(db, name).get('last_error')})
                continue
            previous = state(db, name)
        try:
            body = get(url, limit, previous)
        except feeds.NotModified:
            with context.connect() as db:
                mark_ok(db, name, keep_validators=True)
                record_sync(db, name, 'not_modified', previous.get('items') or 0, 0)
            report.append({'source': name, 'label': label, 'status': 'not_modified'})
            continue
        except InterruptedError:
            break
        except Exception as exc:  # noqa: BLE001 — une source en échec n'arrête pas les autres
            report.append(_failed(context, name, label, exc))
            continue
        try:
            with context.connect() as db:
                if name == 'kev':
                    new, count = _store_kev(db, feeds.parse_kev(body))
                elif name.startswith('debian_'):
                    new, count = _store_debian(db, name, body)
                elif name in feeds.ADVISORY_PRODUCTS:
                    items = feeds.parse_ghsa(body, feeds.ADVISORY_PRODUCTS[name])
                    new, count = store_advisories(db, items, name), len(items)
                else:
                    items = feeds.parse_feed(body, name)
                    new, count = store_advisories(db, items, name), len(items)
                mark_ok(db, name, count, getattr(body, 'etag', None), getattr(body, 'last_modified', None))
                record_sync(db, name, 'ok', count, new)
            report.append({'source': name, 'label': label, 'status': 'ok', 'items': count, 'new': new})
        except Exception as exc:  # noqa: BLE001 — réponse illisible : la source est en erreur
            report.append(_failed(context, name, label, exc))
    for step in (_certfr_details, _nvd_windows, _enrich_nvd, _enrich_epss):
        if stop is not None and stop.is_set():
            break
        try:
            result = step(context, get, force)
        except InterruptedError:
            break
        if result:
            report.append(result)
    return report


def _failed(context, name, label, exc):
    detail = str(exc) if isinstance(exc, feeds.FeedError) else type(exc).__name__
    with context.connect() as db:
        failures = mark_failed(db, name, detail)
        record_sync(db, name, 'failed', detail=detail)
    return {'source': name, 'label': label, 'status': 'failed', 'error': detail, 'failures': failures}


def _certfr_details(context, get, force):
    """CVE et produits des bulletins CERT-FR récents, depuis leur version JSON (20 au plus)."""
    with context.connect() as db:
        rows = db.execute("SELECT source, id, url FROM sec_advisories WHERE source LIKE 'certfr_%' AND cves='[]' "
                          'ORDER BY published DESC LIMIT 20').fetchall()
    done = 0
    for source, ident, url in rows:
        target = feeds.certfr_json_url(url)
        if not target:
            continue
        try:
            details = feeds.parse_certfr_json(get(target, 2 * 1048576))
        except InterruptedError:
            raise
        except Exception:  # noqa: BLE001 — le bulletin reste listé, sans CVE extraites
            continue
        with context.connect() as db:
            db.execute('UPDATE sec_advisories SET cves=?, products=? WHERE source=? AND id=?',
                       (json.dumps(details['cves'] or ['—']), json.dumps(details['products']), source, ident))
        done += 1
    return {'source': 'certfr_details', 'label': 'CERT-FR (détail des bulletins)', 'status': 'ok', 'items': done} if rows else None


def park_techs(context):
    """Technologies réellement présentes sur le parc (relevés SSH), pour cibler NVD."""
    techs = set()
    hosts = {h['key']: h for h in context.HOSTS}
    with context.connect() as db:
        for key, payload in db.execute('SELECT host_key, payload FROM sec_inventory'):
            techs |= {i['tech'] for i in correlation.instances(hosts.get(key, {'key': key}), json.loads(payload))}
    for host in context.HOSTS:
        techs |= {i['tech'] for i in correlation.instances(host, {}) if i['tech'] == 'fortios'}
    return techs


def _nvd_windows(context, get, force):
    """CVE NVD modifiées depuis la dernière fenêtre, pour chaque produit du parc (CPE)."""
    techs = park_techs(context)
    if not techs:
        return None
    total, errors = 0, []
    for tech in sorted(techs):
        for vendor, product in correlation.TECHS[tech]['cpe']:
            key = f'nvd:{vendor}:{product}'
            with context.connect() as db:
                if not force and in_backoff(db, key):
                    continue
                last = state(db, key).get('last_success')
            end = now()
            try:
                start = max(datetime.fromisoformat(last) - timedelta(minutes=5), end - timedelta(days=119))
            except (TypeError, ValueError):
                start = end - timedelta(days=NVD_WINDOW_FIRST_DAYS)
            part = 'o' if tech == 'fortios' else 'a'
            try:
                index, count = 0, 0
                for _ in range(NVD_PAGES):
                    page = feeds.parse_nvd_page(get(feeds.nvd_search_url(vendor, product, start, end, index, part), 16 * 1048576))
                    with context.connect() as db:
                        for cve, record in page['items']:
                            store_nvd(db, cve, record)
                    count += len(page['items'])
                    index += len(page['items'])
                    if not page['items'] or index >= (page['total'] or 0):
                        break
                with context.connect() as db:
                    mark_ok(db, key, count)
                total += count
            except InterruptedError:
                raise
            except Exception as exc:  # noqa: BLE001 — fenêtre retentée au passage suivant
                with context.connect() as db:
                    mark_failed(db, key, str(exc) if isinstance(exc, feeds.FeedError) else type(exc).__name__)
                errors.append(f'{vendor}:{product}')
    with context.connect() as db:
        record_sync(db, 'nvd_products', 'ok' if not errors else 'partial', total, 0,
                    ('échec : ' + ', '.join(errors)) if errors else None)
    return {'source': 'nvd_products', 'label': 'NVD (CVE par produit du parc)', 'status': 'ok' if not errors else 'partial',
            'items': total, 'error': ', '.join(errors) or None}


def _candidates(db, column, stale_hours, limit):
    """CVE à enrichir : vulnérabilités et correspondances actives, bulletins récents, KEV récentes."""
    since = iso(now() - timedelta(days=30))
    stale = iso(now() - timedelta(hours=stale_hours))
    cves = []
    for (cve,) in db.execute("SELECT cve FROM sec_vulns WHERE status IN ('open','validated','in_progress') "
                             "UNION SELECT cve FROM sec_matches WHERE status IN ('confirmed','potential')"):
        cves.append(cve)
    for (raw,) in db.execute('SELECT cves FROM sec_advisories WHERE first_seen >= ? OR COALESCE(updated, published) >= ?',
                             (since, since)):
        cves += [c for c in json.loads(raw) if feeds.CVE.fullmatch(c)]
    known = {r[0]: r[1] for r in db.execute(f'SELECT cve, {column} FROM sec_cve')}  # nosec B608 — colonne interne
    out = []
    for cve in dict.fromkeys(cves):
        stamp = known.get(cve)
        if stamp is None or stamp < stale:
            out.append(cve)
    return out[:limit]


def _enrich_nvd(context, get, force):
    """Enregistrement NVD des CVE citées (bulletins, parc) : score, configurations, statut."""
    limit = 200 if os.getenv('NVD_API_KEY', '').strip() else 40
    with context.connect() as db:
        cves = _candidates(db, 'nvd_at', 24 * 7, limit)
        if not force and in_backoff(db, 'nvd'):
            return {'source': 'nvd', 'label': 'NVD (CVE citées)', 'status': 'backoff', 'items': 0}
    done, failed = 0, 0
    for cve in cves:
        try:
            record = feeds.parse_nvd(get(feeds.NVD_URL + cve, 2 * 1048576))
        except InterruptedError:
            raise
        except Exception as exc:  # noqa: BLE001 — réessayé au passage suivant
            failed += 1
            if 'limitation' in str(exc):
                with context.connect() as db:
                    mark_failed(db, 'nvd', str(exc))
                break
            continue
        with context.connect() as db:
            if record is None:
                # Pas encore publiée par NVD : marquée vue pour ne pas la redemander à chaque passage.
                db.execute('INSERT INTO sec_cve(cve, nvd_at) VALUES(?,?) ON CONFLICT(cve) DO UPDATE SET nvd_at=excluded.nvd_at',
                           (cve, iso()))
            else:
                store_nvd(db, cve, record)
        done += 1
    with context.connect() as db:
        if cves:
            record_sync(db, 'nvd', 'ok' if not failed else 'partial', done, 0, f'{failed} échec(s)' if failed else None)
        if not failed:
            mark_ok(db, 'nvd', done)
    return {'source': 'nvd', 'label': 'NVD (CVE citées)', 'status': 'ok' if not failed else 'partial', 'items': done,
            'pending': len(cves) - done}


def _enrich_epss(context, get, force):
    """Scores FIRST EPSS par lots de 100 CVE, une fois par jour au plus."""
    with context.connect() as db:
        cves = _candidates(db, 'epss_at', 20, 1000)
        if not cves or (not force and in_backoff(db, 'epss')):
            return None
    found = 0
    try:
        for index in range(0, len(cves), 100):
            batch = cves[index:index + 100]
            scores = feeds.parse_epss(get(feeds.EPSS_URL + ','.join(batch), 1048576))
            with context.connect() as db:
                for cve in batch:
                    score = scores.get(cve)
                    # Absente d'EPSS (CVE trop récente) : aucun score, et surtout pas zéro.
                    db.execute('INSERT INTO sec_cve(cve, epss, epss_percentile, epss_date, epss_at) VALUES(?,?,?,?,?) '
                               'ON CONFLICT(cve) DO UPDATE SET epss=excluded.epss, epss_percentile=excluded.epss_percentile, '
                               'epss_date=excluded.epss_date, epss_at=excluded.epss_at',
                               (cve, score and score['epss'], score and score['percentile'], score and score['date'], iso()))
                found += len(scores)
        with context.connect() as db:
            mark_ok(db, 'epss', found)
            record_sync(db, 'epss', 'ok', found, 0)
        return {'source': 'epss', 'label': 'FIRST EPSS', 'status': 'ok', 'items': found}
    except InterruptedError:
        raise
    except Exception as exc:  # noqa: BLE001 — retenté au passage suivant
        detail = str(exc) if isinstance(exc, feeds.FeedError) else type(exc).__name__
        with context.connect() as db:
            mark_failed(db, 'epss', detail)
            record_sync(db, 'epss', 'failed', detail=detail)
        return {'source': 'epss', 'label': 'FIRST EPSS', 'status': 'failed', 'error': detail}


SOURCE_STATUS_LABELS = {'ok': 'Opérationnelle', 'error': 'En erreur', 'disabled': 'Désactivée', 'never': 'Jamais synchronisée'}


def sources_status(db):
    """État affichable de chaque source, y compris les étapes dérivées (NVD, EPSS)."""
    rows = {r[0]: r for r in db.execute('SELECT source, last_attempt, last_success, status, failures, last_error, next_after, items '
                                        'FROM sec_source_state')}
    out = []
    keys = list(feeds.SOURCES) + ['nvd', 'epss'] + sorted(k for k in rows if k.startswith('nvd:'))
    for key in keys:
        row = rows.get(key)
        label = feeds.SOURCES[key][2] if key in feeds.SOURCES else {'nvd': 'NVD (CVE citées)', 'epss': 'FIRST EPSS'}.get(
            key, 'NVD ' + key[4:].replace(':', ' / '))
        status = row[3] if row else ('disabled' if key in feeds.SOURCES and feeds.source_url(key) is None else 'never')
        out.append({'key': key, 'label': label, 'status': status, 'status_label': SOURCE_STATUS_LABELS.get(status, status),
                    'last_attempt': row[1] if row else None, 'last_success': row[2] if row else None,
                    'failures': row[4] if row else 0, 'error': row[5] if row else None, 'next_after': row[6] if row else None,
                    'items': row[7] if row else None, 'url': feeds.source_url(key) if key in feeds.SOURCES else None})
    return out
