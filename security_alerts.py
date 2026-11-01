"""Alertes de veille sécurité : règles, déduplication, centre d'alertes et e-mail.

Une notification n'est créée que pour ce qui touche le parc (CVE confirmée ou potentielle
sur au moins un serveur) et pour une raison explicite :

    kev        CVE listée par CISA KEV (exploitation active connue)
    critical   gravité critique (CVSS ≥ 9 ou avis « critical » de l'éditeur)
    exposed    serveur exposé à Internet concerné (WAF, site publié via le WAF, ou
               « exposure: internet » déclaré dans l'inventaire), gravité ≥ élevée
    fix        nouveau correctif publié (avis Debian ou de l'éditeur de moins de 7 jours)
    epss       probabilité d'exploitation élevée (FIRST EPSS ≥ seuil, 0,5 par défaut)
    bulletin   bulletin récent dont une CVE est ouverte sur le parc

Déduplication : une référence unique par (raison, CVE ou avis). Une notification déjà émise
ne revient (non lue, à renvoyer par e-mail) que si de nouveaux serveurs sont concernés ou si
son niveau monte. Les e-mails partent en un RÉSUMÉ par passage, au plus un toutes les
10 minutes, et seulement pour ce qui n'a pas déjà été envoyé.

E-mail : SMTP de l'entreprise, paramètres dans l'environnement du service (le mot de passe
dans le coffre, jamais en base) ; STARTTLS ou TLS implicite avec certificat vérifié.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import security_correlation as correlation

log = logging.getLogger('opscontrol.security')
LEVELS = {'info': 0, 'warning': 1, 'critical': 2}
KIND_LABELS = {'kev': 'Exploitée (CISA KEV)', 'critical': 'Critique et applicable', 'exposed': 'Service exposé à Internet',
               'fix': 'Nouveau correctif', 'epss': 'Risque d’exploitation élevé', 'bulletin': 'Bulletin concernant le parc',
               'cvss': 'Critique (CVSS)'}
MAIL_EVERY = 600


def now():
    return datetime.now(timezone.utc)


def iso(moment=None):
    return (moment or now()).isoformat()


def notify(db, ref, level, title, detail, hosts, cve=None, kind=None, priority=None):
    """Crée ou met à jour une notification ; renvoie True si elle est (re)devenue à traiter."""
    hosts = sorted(set(hosts))
    row = db.execute('SELECT hosts, level FROM sec_notifications WHERE ref=?', (ref,)).fetchone()
    if row is None:
        db.execute('INSERT INTO sec_notifications(ref, at, level, title, detail, hosts, cve, kind, priority) VALUES(?,?,?,?,?,?,?,?,?)',
                   (ref, iso(), level, title[:300], (detail or '')[:1000], json.dumps(hosts), cve, kind, priority))
        return True
    known = set(json.loads(row[0] or '[]'))
    escalated = LEVELS.get(level, 0) > LEVELS.get(row[1], 0)
    if set(hosts) <= known and not escalated:
        return False
    # Nouveau serveur concerné ou niveau plus grave : la notification redevient à traiter.
    db.execute('UPDATE sec_notifications SET hosts=?, at=?, level=?, title=?, detail=?, priority=?, read_at=NULL, read_by=NULL, '
               'emailed_at=NULL WHERE ref=?',
               (json.dumps(sorted(known | set(hosts))), iso(), level if escalated else row[1], title[:300], (detail or '')[:1000],
                priority, ref))
    return True


def exposure(rows):
    """Serveurs exposés à Internet, avec la raison : WAF, publication via le WAF, déclaration."""
    from published_sites import published_to
    from waf_audit import is_waf_host
    out = {}
    for host in rows:
        if is_waf_host(host):
            out[host['key']] = 'WAF (reverse proxy exposé)'
        elif str(host.get('exposure') or '').lower() in ('internet', 'dmz', 'public'):
            out[host['key']] = 'exposition déclarée dans l’inventaire'
        else:
            try:
                published = published_to(host, rows)
            except Exception:  # noqa: BLE001 — relevé des sites illisible : exposition inconnue, pas « non exposé »
                published = []
            if published:
                out[host['key']] = 'publié via ' + ', '.join(sorted({p['via']['name'] for p in published})[:3])
    return out


def applicable(db):
    """CVE applicables au parc : {cve: {'confirmed': {hôtes}, 'potential': {hôtes}, 'techs': {…}}}."""
    out = {}
    for cve, host, status, tech in db.execute("SELECT cve, host_key, status, tech FROM sec_matches WHERE status IN ('confirmed','potential')"):
        entry = out.setdefault(cve, {'confirmed': set(), 'potential': set(), 'techs': set()})
        entry[status].add(host)
        entry['techs'].add(tech)
    for cve, host in db.execute("SELECT cve, host_key FROM sec_vulns WHERE status IN ('open','validated','in_progress')"):
        entry = out.setdefault(cve, {'confirmed': set(), 'potential': set(), 'techs': set()})
        entry['confirmed'].add(host)
        entry['potential'].discard(host)
    return out


def cve_facts(db, cves):
    facts = {}
    for row in db.execute('SELECT cve, cvss, kev, epss, epss_percentile, description FROM sec_cve'):
        if row[0] in cves:
            facts[row[0]] = {'cvss': row[1], 'kev': bool(row[2]), 'epss': row[3], 'epss_percentile': row[4], 'description': row[5]}
    for source, cves_json, severity in db.execute("SELECT source, cves, severity FROM sec_advisories WHERE severity IS NOT NULL"):
        for cve in json.loads(cves_json):
            if cve in cves:
                entry = facts.setdefault(cve, {'cvss': None, 'kev': False, 'epss': None})
                order = list(correlation.SEVERITY_SCORE)
                if severity in order and (entry.get('severity') not in order or order.index(severity) < order.index(entry['severity'])):
                    entry['severity'] = severity
    return facts


def evaluate(db, context, exposed, epss_threshold=0.5):
    """Applique les règles ; renvoie le nombre de notifications créées ou réactivées."""
    names = {h['key']: h.get('name') or h['key'] for h in context.HOSTS}
    found = applicable(db)
    facts = cve_facts(db, set(found))
    changed = 0

    def label(hosts):
        shown = [names.get(h, h) for h in sorted(hosts)]
        return ', '.join(shown[:5]) + (f' … (+{len(shown) - 5})' if len(shown) > 5 else '')

    for cve, entry in found.items():
        f = facts.get(cve, {})
        hosts = entry['confirmed'] | entry['potential']
        state = f'{len(entry["confirmed"])} confirmé(s), {len(entry["potential"])} potentiel(s)'
        techs = ', '.join(correlation.TECHS.get(t, {}).get('label', t) for t in sorted(entry['techs'])) or 'paquets'
        critical = (f.get('cvss') or 0) >= 9 or f.get('severity') == 'critical'
        rank, _, why = correlation.priority({'cvss': f.get('cvss'), 'severity': f.get('severity'), 'kev': f.get('kev'),
                                             'epss': f.get('epss'), 'exposed': bool(hosts & set(exposed)),
                                             'status': 'confirmed' if entry['confirmed'] else 'potential'})
        if f.get('kev'):
            changed += notify(db, 'kev:' + cve, 'critical', f'{cve} exploitée activement (CISA KEV) — {techs}',
                              f'{state} : {label(hosts)}. Priorité {rank}.', hosts, cve, 'kev', rank)
        if critical:
            score = f'CVSS {f["cvss"]:.1f}' if f.get('cvss') is not None else 'gravité critique (éditeur)'
            changed += notify(db, 'crit:' + cve, 'critical' if entry['confirmed'] else 'warning',
                              f'{cve} critique ({score}) potentiellement applicable — {techs}',
                              f'{state} : {label(hosts)}. Priorité {rank} : {", ".join(why)}.', hosts, cve, 'critical', rank)
        exposed_hosts = hosts & set(exposed)
        if exposed_hosts and (critical or f.get('kev') or (f.get('cvss') or 0) >= 7):
            changed += notify(db, 'exposed:' + cve, 'critical', f'{cve} sur un service exposé à Internet — {techs}',
                              '; '.join(f'{names.get(h, h)} ({exposed[h]})' for h in sorted(exposed_hosts))[:900],
                              exposed_hosts, cve, 'exposed', rank)
        if f.get('epss') is not None and f['epss'] >= epss_threshold:
            changed += notify(db, 'epss:' + cve, 'warning',
                              f'{cve} : risque d’exploitation élevé (EPSS {f["epss"]:.0%}, centile {(f.get("epss_percentile") or 0):.0%})',
                              f'{state} : {label(hosts)}.', hosts, cve, 'epss', rank)
    changed += _new_fixes(db, found, label)
    # Date de PUBLICATION (à défaut, de première collecte) : au premier passage, tous les avis
    # sont « collectés aujourd'hui », et les avis de 2024 produisaient des alertes (constaté).
    since = iso(now() - timedelta(days=30))
    for source, ident, title, cves in db.execute(
            'SELECT source, id, title, cves FROM sec_advisories WHERE COALESCE(published, first_seen) >= ? AND source != ?',
            (since, 'kev')).fetchall():
        concerned = set().union(*[found[c]['confirmed'] | found[c]['potential'] for c in json.loads(cves) if c in found] or [set()])
        if concerned:
            import security_feeds
            changed += notify(db, f'adv:{source}:{ident}', 'warning', f'{security_feeds.SOURCES.get(source, ("", "", source))[2]} : {title}',
                              'CVE du bulletin applicable(s) sur le parc : ' + label(concerned), concerned, None, 'bulletin')
    return changed


def _new_fixes(db, found, label):
    """Correctif publié depuis moins de 7 jours pour une CVE applicable au parc."""
    changed = 0
    recent = (now() - timedelta(days=7)).date().isoformat()
    for advisory, release, package, fixed, cves, published in db.execute(
            'SELECT advisory, release, package, fixed, cves, date FROM sec_fixes WHERE date >= ?', (recent,)).fetchall():
        hosts = set().union(*[found[c]['confirmed'] | found[c]['potential'] for c in json.loads(cves) if c in found] or [set()])
        if hosts:
            changed += notify(db, f'fix:{advisory}:{release}', 'warning', f'Nouveau correctif {advisory} : {package} {fixed} ({release})',
                              f'Publié le {published}. Serveurs concernés : {label(hosts)}.', hosts, None, 'fix')
    since = (now() - timedelta(days=7)).isoformat()
    for source, ident, title, cves, ranges in db.execute(
            'SELECT source, id, title, cves, ranges FROM sec_advisories WHERE ranges IS NOT NULL AND COALESCE(updated, published) >= ?',
            (since,)).fetchall():
        hosts = set().union(*[found[c]['confirmed'] | found[c]['potential'] for c in json.loads(cves) if c in found] or [set()])
        fixes = sorted({r['fixed'] for r in json.loads(ranges) if r.get('fixed')})
        if hosts and fixes:
            changed += notify(db, f'fix:{ident}', 'warning', f'Nouveau correctif ({", ".join(json.loads(cves)) or ident}) : versions {", ".join(fixes)}',
                              f'{title}. Serveurs concernés : {label(hosts)}.', hosts, None, 'fix')
    return changed


def center_alerts(db, names):
    """Notifications critiques non lues, pour le centre d'alertes (mécanisme existant)."""
    out = []
    for ref, at, level, title, detail, hosts, cve, kind in db.execute(
            "SELECT ref, at, level, title, detail, hosts, cve, kind FROM sec_notifications WHERE read_at IS NULL "
            "AND level IN ('critical','warning') AND at >= ? ORDER BY at DESC LIMIT 100", (iso(now() - timedelta(days=30)),)):
        out.append({'ref': ref, 'at': at, 'level': level, 'title': title, 'detail': detail, 'cve': cve, 'kind': kind,
                    'hosts': [{'key': h, 'name': names.get(h, h)} for h in json.loads(hosts or '[]')]})
    return out


# --------------------------------------------------------------------------- e-mail
def mail_settings(context):
    """Paramètres SMTP (environnement) et destinataires (réglage, sinon environnement). Jamais renvoyés tels quels."""
    recipients = (context.read_setting('security_mail_to') or os.getenv('INFRAOPS_SECURITY_MAIL_TO', '')).replace(';', ',')
    return {
        'host': os.getenv('INFRAOPS_SMTP_HOST', '').strip(), 'port': int(os.getenv('INFRAOPS_SMTP_PORT', '587') or 587),
        'security': os.getenv('INFRAOPS_SMTP_SECURITY', 'starttls').strip().lower(),
        'user': os.getenv('INFRAOPS_SMTP_USER', '').strip(), 'password': os.getenv('INFRAOPS_SMTP_PASSWORD', ''),
        'sender': os.getenv('INFRAOPS_SMTP_FROM', '').strip(),
        'recipients': [r.strip() for r in recipients.split(',') if '@' in r.strip()][:20],
        'level': context.read_setting('security_mail_level') or 'critical',
    }


def mail_status(context):
    s = mail_settings(context)
    missing = [name for name, value in (('INFRAOPS_SMTP_HOST', s['host']), ('INFRAOPS_SMTP_FROM', s['sender']),
                                        ('destinataires', s['recipients'])) if not value]
    if s['security'] not in ('starttls', 'ssl'):
        missing.append('INFRAOPS_SMTP_SECURITY (starttls ou ssl)')
    return {'configured': not missing, 'missing': missing, 'recipients': s['recipients'], 'level': s['level'],
            'server': f'{s["host"]}:{s["port"]}' if s['host'] else None, 'security': s['security'],
            'authenticated': bool(s['user'])}


def send_mail(settings, subject, body, smtp=None):
    """Envoi SMTP vérifié (STARTTLS ou TLS implicite, certificat contrôlé)."""
    message = EmailMessage()
    message['Subject'], message['From'], message['To'] = subject, settings['sender'], ', '.join(settings['recipients'])
    message.set_content(body)
    tls = ssl.create_default_context()
    factory = smtp or (smtplib.SMTP_SSL if settings['security'] == 'ssl' else smtplib.SMTP)
    kwargs = {'timeout': 20}
    if settings['security'] == 'ssl':
        kwargs['context'] = tls
    with factory(settings['host'], settings['port'], **kwargs) as client:
        if settings['security'] == 'starttls':
            client.starttls(context=tls)
        if settings['user']:
            client.login(settings['user'], settings['password'])
        client.send_message(message)


def dispatch(context, smtp=None, force=False):
    """Résumé e-mail des notifications non encore envoyées (niveau ≥ réglage)."""
    status = mail_status(context)
    if not status['configured']:
        return {'status': 'not_configured', 'missing': status['missing']}
    last = context.read_setting('security_mail_last')
    try:
        if not force and last and (now() - datetime.fromisoformat(last)).total_seconds() < MAIL_EVERY:
            return {'status': 'throttled'}
    except ValueError:
        pass
    settings = mail_settings(context)
    minimum = LEVELS.get(settings['level'], 2)
    names = {h['key']: h.get('name') or h['key'] for h in context.HOSTS}
    with context.connect() as db:
        rows = [r for r in db.execute('SELECT id, level, title, detail, hosts, kind, priority FROM sec_notifications '
                                      'WHERE emailed_at IS NULL AND at >= ? ORDER BY at DESC LIMIT 200',
                                      (iso(now() - timedelta(days=7)),)) if LEVELS.get(r[1], 0) >= minimum]
    if not rows:
        return {'status': 'nothing'}
    critical = sum(r[1] == 'critical' for r in rows)
    lines = ['Veille sécurité OpsControl — alertes nouvelles ou mises à jour', '']
    for _, level, title, detail, hosts, kind, rank in rows[:50]:
        shown = [names.get(h, h) for h in json.loads(hosts or '[]')]
        lines += [f'[{"CRITIQUE" if level == "critical" else "MAJEUR" if level == "warning" else "INFO"}]'
                  f'{" " + rank if rank else ""} {title}',
                  f'  Raison : {KIND_LABELS.get(kind, kind or "—")}', f'  Serveurs : {", ".join(shown[:10]) or "—"}',
                  f'  {detail}' if detail else '', '']
    if len(rows) > 50:
        lines.append(f'… et {len(rows) - 50} autre(s) : voir OpsControl > Sécurité > Veille de sécurité.')
    lines += ['Procédures de correction et tickets GLPI : OpsControl > Sécurité.',
              'Aucune action n’a été exécutée sur les serveurs. Message automatique, ne pas répondre.']
    subject = f'[OpsControl] Veille sécurité : {len(rows)} alerte(s)' + (f', dont {critical} critique(s)' if critical else '')
    stamp = iso()
    try:
        send_mail(settings, subject, '\n'.join(line for line in lines if line is not None), smtp)
    except (OSError, smtplib.SMTPException) as exc:
        error = type(exc).__name__ + (f' {exc.smtp_code}' if getattr(exc, 'smtp_code', None) else '')
        log.warning('Résumé de veille non envoyé : %s', error)
        with context.connect() as db:
            db.executemany('UPDATE sec_notifications SET email_error=? WHERE id=?', [(error, r[0]) for r in rows])
            db.execute('INSERT INTO sec_syncs(source, at, status, items, new_items, detail) VALUES(?,?,?,?,?,?)',
                       ('mail', stamp, 'failed', len(rows), 0, error))
        return {'status': 'failed', 'error': error}
    with context.connect() as db:
        db.executemany('UPDATE sec_notifications SET emailed_at=?, email_error=NULL WHERE id=?', [(stamp, r[0]) for r in rows])
        db.execute('INSERT INTO sec_syncs(source, at, status, items, new_items, detail) VALUES(?,?,?,?,?,?)',
                   ('mail', stamp, 'ok', len(rows), 0, None))
    context.write_setting('security_mail_last', stamp)
    return {'status': 'sent', 'count': len(rows)}
