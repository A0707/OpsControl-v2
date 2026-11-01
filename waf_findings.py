"""Date-based TLS alerts, evidence-based WAF analysis, and command previews."""
import hashlib
import math
import re
import shlex
from datetime import datetime, timezone
from ipaddress import ip_address



def command_plan(address, action, execution_host):
    if '%' in address:
        raise ValueError('Adresse IPv4 ou IPv6 sans zone requise')
    parsed = ip_address(address)
    ip = str(parsed)
    execution_host = str(ip_address(execution_host))
    # Bannir le WAF lui-même, une adresse locale ou non routable coupe le service ou n'a aucun effet :
    # 127.0.0.1 figure dans les accès et les alertes ModSecurity des WAF (sondes, proxy local).
    if action in ('ban', 'remove_whitelist') and (ip == execution_host or parsed.is_loopback or parsed.is_unspecified
                                                  or parsed.is_multicast or parsed.is_link_local):
        raise ValueError('Adresse du WAF, locale ou non routable : aucun bannissement préparé. '
                         'Vérifier l’adresse réelle du client (mod_remoteip, en-tête X-Forwarded-For).')
    base = 'sudo fail2ban-client '
    jail = 'apache-modsecurity'
    target = shlex.quote(ip)
    plans = {
        'ban': ([f'{base}set {jail} banip {target}'], f'{base}set {jail} unbanip {target}',
                'Bannissement manuel dans ce jail. Vérifier que cette adresse ne correspond pas à votre accès, au bastion ou à un proxy partagé.'),
        'whitelist': ([f'{base}set {jail} addignoreip {target}', f'{base}set {jail} unbanip {target}'],
                      f'{base}set {jail} delignoreip {target}',
                      'Ajoute une exception Fail2ban active puis retire un éventuel ban existant. Ne désactive pas ModSecurity. Non persistante après rechargement/redémarrage : reporter l’IP dans la configuration du jail en conservant les exceptions existantes.'),
        'unban': ([f'{base}set {jail} unbanip {target}'], f'{base}set {jail} banip {target}',
                  'Retire le ban actuel ; l’IP peut être bannie à nouveau si elle récidive. Avant : lancer la '
                  'vérification de cette IP (motif du ban dans fail2ban.log). Une IP interne bannie de façon '
                  'répétée appelle plutôt une exception durable (liste blanche) après analyse.'),
        # Lecture seule : présence dans le jail, motif du ban, traces Apache/ModSecurity, règle pare-feu.
        'inspect': ([f'{base}get {jail} banip --with-time | grep -F -- {target}',
                     f'sudo zgrep -hF -- {target} /var/log/fail2ban.log* | tail -n 20',
                     f'sudo grep -hF -- {target} /var/log/apache2/error.log | grep -F ModSecurity | tail -n 20',
                     f'sudo grep -hF -- {target} /var/log/apache2/*access*log | tail -n 20',
                     f'sudo iptables -n -L f2b-{jail} | grep -F -- {target}   # ou : sudo nft list ruleset | grep -F -- {target}'],
                    '', 'Commandes de lecture uniquement. fail2ban.log donne le motif et l’heure du ban ; '
                        'la chaîne pare-feu dépend de la banaction (iptables ou nftables).'),
        'remove_whitelist': ([f'{base}set {jail} delignoreip {target}'], f'{base}set {jail} addignoreip {target}',
                             'Retire l’exception active de ce jail ; ne bannit pas immédiatement l’adresse.'),
    }
    if action not in plans:
        raise ValueError('Action inconnue')
    commands, undo, note = plans[action]
    if action == 'ban' and parsed.is_private:
        note = ('Adresse privée : probablement un serveur, un répartiteur ou un poste interne, pas un client Internet. '
                'Le bannir peut couper un service. ' + note)
    return {'ip': ip, 'action': action, 'commands': commands, 'undo': undo, 'note': note,
            'verify': [f'{base}status {jail} | grep -F -- {target}   # sortie vide : IP non bannie',
                       f'{base}get {jail} ignoreip'],
            'execution_host': execution_host, 'executable': False}


HTTP_5XX_MIN_REQUESTS = 50


def stable_id(value):
    """Identifiant de constat stable : l'ancien rang dans la liste (« tls:8 ») changeait dès qu'un
    certificat était ajouté ou retiré, et l'incident, son acquittement et son ticket passaient à un
    autre certificat. Empreinte courte du chemin (ou fichier:ligne), sans divulguer le chemin."""
    return hashlib.sha256(str(value).encode('utf-8')).hexdigest()[:12]


def server_name(subject):
    """CN du sujet OpenSSL (« CN = pay.exemple.ma » ou « /CN=… »), sinon None."""
    match = re.search(r'CN\s*=\s*([A-Za-z0-9*._-]+)', subject or '')
    return match.group(1) if match else None


def expiry(cert, now=None):
    now = now or datetime.now(timezone.utc)
    result = {**cert, 'severity': 'unknown', 'days_remaining': None, 'expiration_state': 'Non vérifié'}
    try:
        end = datetime.fromisoformat(cert['not_after'])
        start = datetime.fromisoformat(cert['not_before'])
        if end.tzinfo is None or start.tzinfo is None or end <= start:
            raise ValueError('Invalid validity interval')
        seconds = (end - now).total_seconds()
        result['days_remaining'] = math.floor(seconds / 86400)
        if seconds <= 0:
            result.update(severity='critical', expiration_state='Expiré')
        elif now < start:
            result.update(severity='critical', expiration_state='Pas encore valide')
        elif seconds <= 7 * 86400:
            result.update(severity='critical', expiration_state='Expire sous 7 jours')
        elif seconds <= 30 * 86400:
            result.update(severity='warning', expiration_state='Expire sous 30 jours')
        else:
            result.update(severity='observed', expiration_state='Échéance au-delà de 30 jours')
    except (KeyError, ValueError, TypeError):
        pass
    return result


def analyze(waf, host_ip, now=None):
    s = waf.get('sections', {})
    findings = []

    def add(key, title, severity, evidence, check, advice):
        findings.append({'id': 'waf:' + key, 'title': title, 'severity': severity, 'domain': 'WAF / TLS',
                         'evidence': evidence, 'check_command': check, 'solution_command': '# ' + advice,
                         'precaution': 'Vérifier la preuve et sa date avant intervention.', 'scope': 'Sur ' + host_ip,
                         'requires_adaptation': True, 'executable': False})

    for item in s.get('services', {}).get('data', []):
        if item.get('name') in ('apache2', 'fail2ban') and item.get('ActiveState') != 'active':
            state = item.get('ActiveState', 'unknown')
            add('service:' + item['name'], 'Service critique ' + item['name'] + ' non confirmé actif',
                'unknown' if state == 'unknown' else 'critical', 'État : ' + state,
                'systemctl status ' + item['name'], 'Examiner le journal du service et la configuration avant redémarrage.')
    if s.get('apache_modules', {}).get('data', {}).get('security_module_loaded') is False:
        add('module', 'ModSecurity absent de la liste des modules Apache', 'critical', 'apache2ctl -M ne liste pas security2/3_module.',
            'sudo apache2ctl -M', 'Vérifier le chargement du module dans la configuration utilisée.')
    for entry in s.get('engine', {}).get('data', {}).get('declarations', []):
        if entry.get('mode', '').lower() in ('off', 'detectiononly'):
            add('engine:' + stable_id(f"{entry.get('file')}:{entry.get('line')}"), 'Déclaration ModSecurity ' + entry['mode'], 'warning',
                f"{entry.get('file')}:{entry.get('line')} — portée effective à confirmer",
                'sudo apache2ctl -t', 'Vérifier les inclusions et la portée du vhost ; ne pas changer le mode sans examiner les faux positifs.')
    traffic = s.get('traffic', {}).get('data', {})
    # Pourcentage sans valeur sur un petit échantillon : 1 réponse 503 sur 2 lignes lues donnait 50 %
    # (échantillons de 2 requêtes observés sur prddcxwaf04). En dessous du minimum : contrôle incomplet.
    if (traffic.get('errors_5xx_pct') or 0) >= 5:
        enough = (traffic.get('requests') or 0) >= HTTP_5XX_MIN_REQUESTS
        add('http5xx', 'Réponses HTTP 5xx élevées dans l’échantillon' if enough else 'Réponses 5xx : échantillon trop faible pour conclure',
            'warning' if enough else 'unknown',
            str(traffic['errors_5xx_pct']) + '% sur ' + str(traffic.get('requests')) + ' requêtes échantillonnées'
            + ('.' if enough else f' (minimum {HTTP_5XX_MIN_REQUESTS}).'),
            'sudo journalctl -u apache2 --since "1 hour ago" --no-pager -n 80',
            'Corréler les erreurs Apache avec les applications amont ; les 5xx ne prouvent pas une attaque.')
    used, capacity = (s.get(k, {}).get('data') for k in ('conntrack', 'conntrack_max'))
    if isinstance(used, int) and isinstance(capacity, int) and capacity > 0 and used / capacity >= .8:
        add('conntrack', 'Table conntrack proche de sa capacité', 'critical' if used / capacity >= .95 else 'warning',
            f'{used} / {capacity} entrées', 'ss -s', 'Analyser les connexions et le trafic avant toute modification de limite.')

    # Santé Apache : évaluée à la collecte (apache_health.record) ; recalculée ici pour
    # les anciennes collectes, qui n'ont que la section sockets (CLOSE_WAIT seul).
    import apache_health
    health = waf.get('apache_health') or apache_health.evaluate(waf.get('apache'), s)
    findings.extend(health.get('findings', []))

    tls = s.get('certificates', {}).get('data', {})
    certificates = [expiry(cert, now) for cert in tls.get('certificates', [])]
    for cert in certificates:
        if cert['severity'] in ('critical', 'warning', 'unknown'):
            path = cert.get('path', '')
            # Fichier déclaré ≠ certificat servi (audit UI du 31/10, fiche 11.2) : la sonde lit
            # les fichiers référencés par Apache, pas le certificat présenté en SNI. Le constat le
            # dit, et la vérification du certificat servi est fournie en TEXTE à copier.
            name = server_name(cert.get('subject'))
            served = ('echo | openssl s_client -connect ' + shlex.quote(host_ip + ':443') + ' -servername ' +
                      shlex.quote(name) + ' 2>/dev/null | openssl x509 -noout -dates -subject') if name else None
            add('tls:' + stable_id(path), 'Certificat déclaré (fichier) : ' + cert['expiration_state'], cert['severity'],
                f"{path} — expiration : {cert.get('not_after', 'inconnue')} — jours restants : {cert['days_remaining']}"
                ' — certificat réellement servi : non mesuré',
                'sudo openssl x509 -in ' + shlex.quote(path) + ' -noout -dates -subject -issuer' + ('\n' + served if served else ''),
                'Vérifier si ce fichier est encore servi par un vhost actif (seconde commande : certificat présenté en SNI), puis son renouvellement.')
    if not certificates:
        add('tls:coverage', 'Aucun certificat SSL/TLS mesuré', 'unknown', 'Aucune date d’expiration disponible.',
            'sudo apache2ctl -S', 'Vérifier les déclarations SSLCertificateFile et les droits de lecture.')
    if tls.get('partial'):
        add('tls:partial', 'Couverture SSL/TLS partielle', 'unknown', 'Certains fichiers, inclusions ou certificats restent non résolus.',
            'sudo apache2ctl -S', 'Examiner la liste des sources inaccessibles et les limites de découverte.')
    for key, section in s.items():
        if section.get('status') == 'unknown':
            add('coverage:' + key, 'Contrôle WAF incomplet : ' + key, 'unknown', section.get('error', 'Preuve absente'),
                '', 'Vérifier les droits et la disponibilité de la source.')
    findings.sort(key=lambda f: {'critical': 0, 'warning': 1, 'unknown': 2}.get(f['severity'], 3))
    return certificates, findings


def decorate(row):
    if not row.get('waf'):
        return
    certs, findings = analyze(row['waf'], row['ip'])
    # Nouveau dict : row['waf'] vient de la charge mise en cache par rows(), partagée entre appels.
    row['waf'] = {**row['waf'], 'certificates': certs, 'analysis': findings}
    row['findings'] = [f for f in row.get('findings', []) if not f['id'].startswith('waf:')] + findings
    if not row.get('stale'):
        if any(f['severity'] == 'critical' for f in findings):
            row['status'] = 'critical'
        elif row['status'] not in ('critical', 'unreachable') and any(f['severity'] == 'warning' for f in findings):
            row['status'] = 'warning'
