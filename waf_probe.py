"""Fixed read-only remote probe. Sent by waf_audit via the SSH allowlist.

No external WHOIS lookup, no mutations, no arbitrary commands from the browser.
Only sanitized aggregates and selected event attributes leave the server.
"""
import collections
import datetime
import glob
import ipaddress
import json
import os
import posixpath
import re
import shlex
import ssl
import subprocess
import time


def main():
    started = time.monotonic()
    deadline = started + 70
    sections = {}

    def run(args, limit=800000):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Budget de collecte épuisé')
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=min(5, remaining), text=True, errors='replace')
        if p.returncode:
            raise RuntimeError('Commande refusée ou indisponible (code %s)' % p.returncode)
        if len(p.stdout) > limit:
            raise RuntimeError('Sortie trop volumineuse')
        return p.stdout

    # Lecture de fichiers : par le script borné s'il est installé (deploy/remote/infraops-read.sh),
    # que sudoers peut alors autoriser seul ; sinon, appel sudo historique (transition).
    reader = '/usr/local/sbin/infraops-read'
    bounded = os.path.isfile(reader)

    def read(op, size, path):
        return run(['sudo', '-n', reader, op, str(size), path] if bounded
                   else ['sudo', '-n', op, '-c', str(size), '--', path])

    def section(name, fn):
        try:
            sections[name] = {'status': 'observed', 'data': fn()}
        except Exception as e:
            sections[name] = {'status': 'unknown', 'error': str(e)[:180]}

    def integer(text):
        value = text.strip()
        if not re.fullmatch(r'-?\d+', value):
            raise ValueError('Valeur numérique absente')
        return int(value)

    def valid_ip(value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def services():
        result = []
        for unit in ('apache2', 'httpd', 'nginx', 'fail2ban', 'keepalived'):
            try:
                text = run(['systemctl', 'show', unit, '--no-pager',
                            '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState'])
                values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
                result.append({'name': unit, **values})
            except Exception:
                result.append({'name': unit, 'ActiveState': 'unknown'})
        if all(x.get('ActiveState') == 'unknown' for x in result):
            raise RuntimeError('État des services inaccessible')
        return result

    section('services', services)

    def modules():
        text = run(['sudo', '-n', 'apache2ctl', '-M'])
        return {'security_module_loaded': bool(re.search(r'\bsecurity[23]?_module\b', text)),
                'modules': re.findall(r'^\s*(\w+_module)\b', text, re.M)[:100]}

    section('apache_modules', modules)

    def vhosts():
        text = run(['sudo', '-n', 'apache2ctl', '-S'])
        return {'declarations': text.splitlines()[:80], 'scope': 'Déclarations Apache, disponibilité HTTP non testée'}

    section('vhosts', vhosts)

    def engine():
        paths = sorted({p for pattern in ('/etc/modsecurity/*.conf', '/etc/apache2/mods-enabled/*security*.conf', '/etc/apache2/sites-enabled/*') for p in glob.glob(pattern)})[:40]
        if not paths:
            raise RuntimeError('Aucune source de configuration découverte')
        declarations, unreadable = [], []
        for path in paths:
            try:
                text = read('head', 65536, path)
                for number, line in enumerate(text.splitlines(), 1):
                    match = re.match(r'^\s*SecRuleEngine\s+(On|Off|DetectionOnly)\s*(?:#.*)?$', line, re.I)
                    if match:
                        declarations.append({'file': path, 'line': number, 'mode': match[1]})
            except Exception:
                unreadable.append(path)
        return {'declarations': declarations, 'unreadable': unreadable,
                'scope': 'Déclarations dans les premiers 64 Ko de 40 fichiers maximum ; héritage et règles par vhost non résolus'}

    section('engine', engine)

    def certificates():
        paths = sorted({p for pattern in ('/etc/apache2/apache2.conf', '/etc/apache2/sites-enabled/*',
                                         '/etc/apache2/conf-enabled/*.conf', '/etc/apache2/mods-enabled/ssl.conf')
                        for p in glob.glob(pattern)})
        if not paths:
            raise RuntimeError('Aucune configuration Apache découverte')
        references, errors, unresolved = {}, [], []
        for path in paths[:192]:
            try:
                text = read('head', 131072, path)
                if len(text.encode('utf-8')) >= 131072:
                    unresolved.append({'source': path, 'reason': 'Configuration tronquée à 128 Ko'})
                for line in text.splitlines():
                    try:
                        tokens = shlex.split(line, comments=True)
                    except ValueError:
                        continue
                    if not tokens:
                        continue
                    if tokens[0].lower() == 'sslcertificatefile' and len(tokens) == 2:
                        value = tokens[1]
                        if any(x in value for x in ('$', '*', '?', '\n', '\r')) or ':' in value:
                            unresolved.append({'source': path, 'reason': 'Chemin de certificat dynamique non résolu'})
                            continue
                        value = posixpath.normpath(value if value.startswith('/') else '/etc/apache2/' + value)
                        references.setdefault(value, []).append(path)
                    elif tokens[0].lower() in ('include', 'includeoptional'):
                        unresolved.append({'source': path, 'reason': 'Inclusion non parcourue récursivement'})
            except Exception:
                errors.append(path)
        result = []
        for path, sources in list(references.items())[:96]:
            cert = {'path': path, 'sources': sources, 'status': 'unknown'}
            try:
                text = run(['sudo', '-n', reader, 'cert', path] if bounded else
                           ['sudo', '-n', 'openssl', 'x509', '-in', path, '-noout', '-startdate', '-enddate',
                            '-subject', '-issuer', '-serial', '-fingerprint', '-sha256'])
                values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
                cert.update(not_before=datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(values['notBefore']), datetime.timezone.utc).isoformat(),
                            not_after=datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(values['notAfter']), datetime.timezone.utc).isoformat(),
                            subject=values.get('subject'), issuer=values.get('issuer'), serial=values.get('serial'),
                            fingerprint=next((v for k, v in values.items() if 'fingerprint' in k.lower()), None), status='observed')
            except Exception:
                cert['error'] = 'Certificat inaccessible, invalide ou OpenSSL indisponible'
            result.append(cert)
        return {'certificates': result, 'configs_discovered': len(paths), 'configs_limit': 192, 'certificate_limit': 96,
                'unreadable': errors, 'unresolved': unresolved,
                'partial': bool(errors or unresolved) or len(paths) > 192 or len(references) > 96,
                'scope': 'Certificats fichiers déclarés dans Apache ; pas de test TLS distant, de chaîne de confiance ou de clé privée. Inclusions et conditions Apache non résolues.'}

    section('certificates', certificates)

    def jail():
        text = run(['sudo', '-n', 'fail2ban-client', 'status', 'apache-modsecurity'])
        result = {}
        for field, title in [('currently_banned', 'Currently banned'), ('total_banned', 'Total banned'),
                             ('currently_failed', 'Currently failed'), ('total_failed', 'Total failed')]:
            match = re.search(re.escape(title) + r':\s*(\d+)', text)
            result[field] = int(match[1]) if match else None
        match = re.search(r'Banned IP list:\s*([^\n]*)', text)
        result['banned_ips'] = [ip for value in match[1].split() if (ip := valid_ip(value))][:500] if match else []
        result['list_available'] = match is not None
        result['list_limit'] = 500
        banned.update(result['banned_ips'])
        return result

    # IP bannies, réutilisées plus bas pour rapprocher bans, accès Apache et alertes ModSecurity.
    banned = set()
    section('fail2ban', jail)

    def bantimes():
        """Date et durée de chaque ban (Fail2ban >= 0.11). Heure LOCALE du WAF, sans fuseau.

        Ligne attendue : « 192.0.2.1 \t2026-10-06 01:00:00 + 600 = 2026-10-06 01:10:00 »
        (durée -1 : ban permanent). Lecture seule ; refus ou version ancienne : section inconnue."""
        text = run(['sudo', '-n', 'fail2ban-client', 'get', 'apache-modsecurity', 'banip', '--with-time'])
        stamp = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        bans = {}
        for line in text.splitlines():
            m = re.match(r'\s*(\S+)\s+' + stamp + r'\s*\+\s*(-?\d+)\s*=\s*' + stamp, line)
            ip = valid_ip(m[1]) if m else None
            if ip and len(bans) < 500:
                bans[ip] = {'banned_at': m[2], 'duration_seconds': int(m[3]), 'expires_at': m[4]}
        if text.strip() and not bans:
            raise RuntimeError('Format de « banip --with-time » non reconnu')
        return {'bans': bans, 'clock': 'heure locale du WAF', 'limit': 500}

    section('bantimes', bantimes)
    def ignored():
        text = run(['sudo', '-n', 'fail2ban-client', 'get', 'apache-modsecurity', 'ignoreip'])
        import ipaddress
        addresses = []
        for token in re.findall(r'[0-9A-Fa-f:.]+(?:/\d+)?', text):
            if '.' not in token and ':' not in token:
                continue
            try:
                value = str(ipaddress.ip_network(token, strict=False)) if '/' in token else str(ipaddress.ip_address(token))
                if value not in addresses:
                    addresses.append(value)
            except ValueError:
                pass
        # Entrées de la liste (« |- valeur ») qui ne sont ni IP ni réseau : noms DNS, non
        # résolus ici. Comptées pour que le verdict signale une analyse partielle (WAF-05).
        listed = re.findall(r'^\s*[|`]-\s*(\S+)', text, re.M)
        unparsed = 0
        for entry in listed:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                unparsed += 1
        return {'addresses': addresses[:500], 'limit': 500, 'unparsed': unparsed,
                'scope': 'Exceptions IP/réseaux rapportées par Fail2ban ; les éventuels noms DNS ne sont pas analysés.'}
    section('ignoreip', ignored)
    for policy in ('maxretry', 'findtime', 'bantime'):
        section(policy, lambda policy=policy: integer(run(['sudo', '-n', 'fail2ban-client', 'get', 'apache-modsecurity', policy])))
    section('tcp', lambda: {'summary': run(['ss', '-s'])[:2000]})
    def endpoint(text):
        """'10.0.0.1:443', '[::ffff:10.0.0.1]:443', '*:80' -> (ip ou None, port ou None)."""
        host, _, port = text.rpartition(':')
        host = host.strip('[]').split('%', 1)[0]
        if host.lower().startswith('::ffff:') and '.' in host:
            host = host[7:]
        return valid_ip(host), int(port) if port.isdigit() else None

    # ss : 800 Ko ne couvraient que 10 000 à 13 000 sockets ; au-delà, toute la section échouait, précisément
    # lors d'un afflux de connexions. Plafond relevé et troncature signalée au lieu d'un comptage partiel muet.
    SS_BYTES, SS_LINES = 16000000, 200000
    truncated = []

    def socket_rows(text):
        """Lignes `ss -Htan[p]`, avec ou sans colonne d'état (absente si filtre d'état)."""
        lines = text.splitlines()
        if len(lines) > SS_LINES:
            truncated.append(len(lines))
        for line in lines[:SS_LINES]:
            parts = line.split()
            if len(parts) < 4:
                continue
            state = None if parts[0].isdigit() else parts.pop(0)
            if len(parts) < 4 or not (parts[0].isdigit() and parts[1].isdigit()):
                continue
            procs = re.findall(r'\("([^"]{1,40})",pid=(\d+)', ' '.join(parts[4:]))
            yield state, int(parts[0]), int(parts[1]), endpoint(parts[2]), endpoint(parts[3]), procs

    def sockets():
        states = collections.Counter()
        for state, *_ in socket_rows(run(['ss', '-Htan'], SS_BYTES)):
            states[state] += 1
        listening = {local[1] for _, _, _, local, _, _ in socket_rows(run(['ss', '-Htln'], SS_BYTES))}
        # Processus propriétaires : nécessite sudo pour les sockets d'Apache ; sinon comptage sans processus.
        try:
            text, with_process = run(['sudo', '-n', 'ss', '-Htanp', 'state', 'close-wait'], SS_BYTES), True
        except Exception:
            text, with_process = run(['ss', '-Htan', 'state', 'close-wait'], SS_BYTES), False
        by_local_port, by_upstream, by_client, by_process, by_pid = (collections.Counter() for _ in range(5))
        # Recv-Q = 1 en CLOSE_WAIT : seul le FIN du pair n'a pas été lu (connexion inactive).
        # Recv-Q > 1 : de vraies données restent non lues par le processus.
        recv_stuck = recv_bytes = fin_only = inbound = outbound = 0
        samples = []
        for _, recvq, sendq, local, peer, procs in socket_rows(text):
            direction = 'inbound' if local[1] in listening else 'outbound'
            if direction == 'inbound':
                inbound += 1
                by_local_port[local[1]] += 1
                if peer[0]:
                    by_client[peer[0]] += 1
            else:
                outbound += 1
                by_upstream['%s:%s' % (peer[0] or '?', peer[1] or '?')] += 1
            if recvq == 1:
                fin_only += 1
            elif recvq > 1:
                recv_stuck += 1
                recv_bytes += recvq - 1
            for name, pid in procs[:1]:
                by_process[name] += 1
                by_pid['%s:%s' % (name, pid)] += 1
            samples.append({'direction': direction, 'local_port': local[1], 'peer': peer[0], 'peer_port': peer[1],
                            'recv_q': recvq, 'send_q': sendq, 'process': procs[0][0] if procs else None,
                            'pid': int(procs[0][1]) if procs else None})
        samples.sort(key=lambda x: -x['recv_q'])
        try:
            apache_processes = len(run(['ps', '-C', 'apache2', '-o', 'pid=']).split())
        except Exception:
            apache_processes = None
        return {'states': dict(states), 'total': sum(states.values()),
                'close_wait_total': inbound + outbound, 'close_wait_inbound': inbound,
                'close_wait_outbound': outbound, 'recv_q_nonzero': recv_stuck, 'recv_q_bytes': recv_bytes, 'fin_unread': fin_only,
                'by_local_port': by_local_port.most_common(15), 'by_upstream': by_upstream.most_common(15),
                'by_client': by_client.most_common(15), 'by_process': by_process.most_common(10), 'by_pid': by_pid.most_common(10),
                'process_visible': with_process, 'apache_processes': apache_processes,
                'truncated': bool(truncated), 'lines_limit': SS_LINES,
                'listening_ports': sorted(p for p in listening if p)[:60], 'samples': samples[:40],
                'scope': 'Instantané ss au moment de la collecte ; l’âge d’une socket n’est pas exposé par ss. '
                         'Entrant = port local en écoute ; sortant = connexion ouverte par ce serveur (proxy, backend). '
                         + ('Processus lus via sudo -n ss -p.' if with_process else 'Processus non visibles : sudo -n ss refusé.')}

    section('sockets', sockets)
    section('conntrack', lambda: integer(run(['cat', '/proc/sys/net/netfilter/nf_conntrack_count'])))
    section('conntrack_max', lambda: integer(run(['cat', '/proc/sys/net/netfilter/nf_conntrack_max'])))

    def drops():
        text = run(['sudo', '-n', 'iptables', '-L', 'INPUT', '-nvx'])
        rules = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[0].isdigit() and parts[2] in ('DROP', 'REJECT'):
                rules.append({'target': parts[2], 'packets': int(parts[0])})
        return {'packets': sum(x['packets'] for x in rules), 'rules': len(rules),
                'scope': 'Compteurs des règles DROP/REJECT de INPUT uniquement ; ni débit ni total de tous les drops'}

    section('iptables', drops)

    def samples(patterns, limit):
        files = sorted({p for pattern in patterns for p in glob.glob(pattern)})
        if not files:
            raise RuntimeError('Aucun fichier découvert pour les chemins Apache configurés')
        records, sources, errors = [], [], []
        for path in files[:96]:
            try:
                # GNU tail -c bounds the bytes before selecting the last lines locally.
                text = read('tail', 131072, path)
                lines = text.splitlines()
                if len(text.encode('utf-8')) >= 131072:
                    lines = lines[1:]
                lines = lines[-limit:]
                records.extend((path, line[:16000]) for line in lines)
                sources.append({'path': path, 'lines': len(lines)})
            except Exception:
                errors.append(path)
        if not sources:
            raise RuntimeError('Logs découverts mais non accessibles')
        return records, {'sources': sources, 'unreadable': errors, 'files_discovered': len(files),
                         'file_limit': 96, 'lines_per_file': limit, 'bytes_per_file': 131072,
                         'partial': bool(errors) or len(files) > 96}

    def traffic():
        rows, scope = samples(['/var/log/apache2/access.log', '/var/log/apache2/*-access_log'], 200)
        codes, urls, ips, per_file = (collections.Counter() for _ in range(4))
        # Fenêtre propre à chaque fichier : 200 lignes couvrent une minute sur un vhost chargé et
        # plusieurs heures sur un vhost calme. Exposée pour ne pas lire l'échantillon comme continu.
        windows = {}
        banned_agents = {}
        times, rejected = [], 0
        for path, line in rows:
            match = re.match(r'^(\S+) .*?\[([^\]]+)\] "([A-Z]+) ([^" ]+)(?: HTTP/[^" ]+)?" ([1-5]\d\d)\b', line)
            if not match:
                rejected += 1
                continue
            address, timestamp, method, url, code = match.groups()
            codes[code] += 1
            # Paths only: no query strings, credentials, referers, cookies or bodies.
            urls[url.split('?', 1)[0].split('#', 1)[0][:160]] += 1
            ip = valid_ip(address)
            if ip:
                ips[ip] += 1
                if ip in banned:
                    # Format combined seulement : ne pas confondre référent et user-agent.
                    agent = re.match(r'\s+(?:\d+|-)\s+"[^"]*"\s+"([^"]*)"', line[match.end():])
                    if agent:
                        banned_agents.setdefault(ip, collections.Counter())[agent.group(1)[:200]] += 1
            per_file[path] += 1
            try:
                moment = datetime.datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
                times.append(moment)
                first, last = windows.get(path, (moment, moment))
                windows[path] = (min(first, moment), max(last, moment))
            except ValueError:
                pass
        count = sum(codes.values())
        if rows and not count:
            raise RuntimeError('Format HTTP non reconnu : adapter le parseur au LogFormat Apache')
        return {'http_codes': dict(codes), 'requests': count, 'unparsed_lines': rejected,
                'top_urls': urls.most_common(15), 'top_ips': ips.most_common(15),
                # Requêtes des IP bannies dans l'échantillon (toutes, pas seulement le top 15).
                'banned_requests': {ip: ips[ip] for ip in banned if ips[ip]},
                'banned_user_agents': {ip: agents.most_common(3) for ip, agents in banned_agents.items()},
                'by_file': per_file.most_common(), 'first_event': min(times).isoformat() if times else None,
                'last_event': max(times).isoformat() if times else None, 'scope': scope,
                'window_seconds': sorted(round((b - a).total_seconds()) for a, b in windows.values()),
                'errors_5xx_pct': round(100 * sum(n for code, n in codes.items() if code.startswith('5')) / count, 2) if count else None}

    section('traffic', traffic)

    def modsecurity():
        rows, scope = samples(['/var/log/apache2/error.log', '/var/log/apache2/*-error_log'], 500)
        rules, clients = collections.Counter(), collections.Counter()
        banned_rules = {}
        events, scores = [], []
        alerts = 0
        for path, line in rows:
            # Une alerte porte un identifiant de règle ou un refus ; les notices écrites à chaque
            # rechargement d'Apache (« ModSecurity for Apache/… configured », versions APR/PCRE)
            # étaient comptées comme des alertes.
            if 'ModSecurity' not in line or ('[id "' not in line and 'Access denied' not in line):
                continue
            alerts += 1
            ids = re.findall(r'\[id "(\d+)"\]', line)
            rules.update(ids)
            score = re.search(r'Total Score:\s*(\d+)', line)
            if score:
                scores.append(int(score[1]))
            match = re.search(r'\[client ([^\]]+)\]', line)
            # Apache 2.4 écrit « [client IP:port] », y compris en IPv6 sans crochets
            # (« 2001:db8::1:52345 ») : retirer d'abord le port, sinon l'IPv6 est perdue (port à 5
            # chiffres) ou fausse (port à 4 chiffres lu comme un dernier groupe hexadécimal).
            port = re.fullmatch(r'\[?(.+?)\]?:(\d{1,5})', match[1]) if match else None
            ip = (valid_ip(port[1]) if port else None) or (valid_ip(match[1]) if match else None)
            if ip:
                clients[ip] += 1
                if ip in banned:
                    banned_rules.setdefault(ip, collections.Counter()).update(ids or ['sans id'])
            events.append({'source': path, 'rules': ids, 'client': ip,
                           'timestamp_raw': line.split(']', 1)[0].lstrip('[')[:60] if line.startswith('[') else None,
                           'action': 'deny_reported' if 'Access denied' in line else 'alert',
                           'score': int(score[1]) if score else None})
        return {'alert_lines': alerts, 'rules': rules.most_common(15), 'clients': clients.most_common(15),
                # Lignes ModSecurity et 3 règles principales de chaque IP bannie (échantillon lu).
                'banned_alerts': {ip: {'lines': clients[ip], 'rules': c.most_common(3)} for ip, c in banned_rules.items()},
                'anomaly_max': max(scores) if scores else None, 'events': events[-60:], 'scope': scope,
                'note': 'Comptage de lignes, pas de requêtes uniques. Un code HTTP 403 ne prouve pas un blocage ModSecurity.'}

    section('modsecurity', modsecurity)
    print(json.dumps({'version': 1, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'duration_ms': round((time.monotonic() - started) * 1000), 'sections': sections}))


if __name__ == '__main__':
    main()
