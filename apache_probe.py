"""Sonde Apache « santé et saturation », envoyée par waf_audit via la liste blanche SSH.

LECTURE SEULE / ZÉRO IMPACT :
- aucune commande de service, de signal, de pare-feu ou d'écriture de fichier ;
- lectures de journaux bornées en octets (tail -c) et filtrées par date ;
- server-status lu sur 127.0.0.1 (timeout 3 s) ;
- backends : une connexion TCP puis une requête HEAD / par backend distinct,
  timeout 3 s, en parallèle limité ;
- budget global de 40 s : au-delà, les sections restantes sont marquées non mesurées.
Seuls des agrégats sortent du serveur : pas de paramètres d'URL, de cookies ni de corps.
"""
import collections
import concurrent.futures
import datetime
import glob
import http.client
import ipaddress
import json
import re
import shlex
import socket
import ssl
import subprocess
import os
import time
import urllib.error
import urllib.request

STARTED = time.monotonic()
DEADLINE = STARTED + 40
WINDOW_SECONDS = 600          # requêtes lentes, IP, URL, bots : 10 dernières minutes
PEAK_WINDOW_SECONDS = 3600    # pic de concurrence : 1 h, dans la limite des octets lus
SATURATION_WINDOW_SECONDS = 1800
ACCESS_BYTES_PER_FILE = 16 * 1024 * 1024
ACCESS_BYTES_TOTAL = 96 * 1024 * 1024
ERROR_BYTES = 8 * 1024 * 1024
# Journaux d'erreurs des vhosts (ErrorLog par site) : c'est là qu'Apache écrit les refus ModSecurity
# d'un site, pas dans error.log principal. Lecture bornée par fichier et au total.
VHOST_ERROR_GLOB = '/var/log/apache2/*-error_log'
VHOST_ERROR_FILES = 96
VHOST_ERROR_BYTES = 1024 * 1024
VHOST_ERROR_TOTAL = 32 * 1024 * 1024
MPM_DEFAULTS = {  # valeurs par défaut d'Apache 2.4 (event/worker), affichées comme telles
    'ServerLimit': 16, 'ThreadsPerChild': 25, 'MaxRequestWorkers': 400, 'MaxConnectionsPerChild': 0,
    'Timeout': 60, 'KeepAlive': 'On', 'KeepAliveTimeout': 5, 'MaxKeepAliveRequests': 100}
PREFORK_DEFAULTS = {'ServerLimit': 256, 'ThreadsPerChild': 1, 'MaxRequestWorkers': 256}
SATURATION_PATTERNS = [
    ('AH00484', re.compile(r'AH00484|server reached MaxRequestWorkers', re.I)),
    ('AH10159', re.compile(r'AH10159|within MinSpareThreads of MaxRequestWorkers', re.I)),
    ('AH03490', re.compile(r'AH03490|scoreboard is full', re.I)),
]
BOT_PATTERNS = [
    ('bingbot', r'bingbot'), ('meta-externalagent', r'meta-external'), ('Ahrefs', r'ahrefs'),
    ('MicroMessenger', r'micromessenger'),
    ('scanners', r'sqlmap|nikto|nmap|zgrab|masscan|nuclei|wpscan|dirbuster|gobuster|acunetix|nessus|openvas|python-requests|go-http-client|curl/|wget/|libwww'),
    ('international crawlers', r'googlebot|yandex|baiduspider|petalbot|semrush|mj12bot|dotbot|bytespider|gptbot|claudebot|amazonbot|applebot|sogou|seznam|dataforseo|bot\b|spider|crawler'),
]
BOT_REGEX = [(name, re.compile(p, re.I)) for name, p in BOT_PATTERNS]


def remaining():
    return DEADLINE - time.monotonic()


def run(args, limit=800000, timeout=5):
    if remaining() <= 1:
        raise RuntimeError('Budget de collecte épuisé')
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=min(timeout, remaining()), text=True, errors='replace')
    if p.returncode:
        raise RuntimeError('Commande refusée ou indisponible (code %s)' % p.returncode)
    if len(p.stdout) > limit:
        raise RuntimeError('Sortie trop volumineuse')
    return p.stdout


# Script de lecture bornée (deploy/remote/infraops-read.sh) : utilisé s'il est installé,
# sudoers peut alors n'autoriser que lui ; sinon, appel sudo historique (transition).
READER = '/usr/local/sbin/infraops-read'


def bounded_read(op, size, path):
    if os.path.isfile(READER):
        return ['sudo', '-n', READER, op, str(size), path]
    return ['sudo', '-n', op, '-c', str(size), '--', path]


def read_tail(path, max_bytes):
    text = run(bounded_read('tail', max_bytes, path), limit=max_bytes * 2 + 1024, timeout=8)
    truncated = len(text.encode('utf-8', 'replace')) >= max_bytes
    lines = text.splitlines()
    return (lines[1:] if truncated else lines), truncated


def read_config(path):
    return run(bounded_read('head', 262144, path))


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# --------------------------------------------------------------------------- server-status
def server_status():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request('http://127.0.0.1/server-status?auto', headers={'User-Agent': 'OpsControl-readonly'})
    try:
        with opener.open(request, timeout=3) as response:
            body = response.read(262144).decode('utf-8', 'replace')
    except urllib.error.HTTPError as exc:
        raise RuntimeError('server-status refusé (HTTP %s)' % exc.code)
    except Exception as exc:
        raise RuntimeError('server-status inaccessible : ' + type(exc).__name__)
    values = {}
    for line in body.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            values[key.strip()] = value.strip()
    if 'BusyWorkers' not in values:
        raise RuntimeError('Réponse server-status sans BusyWorkers (format non reconnu)')

    def number(name):
        try:
            v = float(values[name])
            return int(v) if v.is_integer() else v
        except (KeyError, ValueError):
            return None

    board = values.get('Scoreboard', '')
    fields = ['BusyWorkers', 'IdleWorkers', 'Processes', 'Stopping', 'ConnsTotal', 'ConnsAsyncWriting',
              'ConnsAsyncKeepAlive', 'ConnsAsyncClosing', 'ReqPerSec', 'DurationPerReq', 'BytesPerSec',
              'ServerUptimeSeconds', 'ParentServerConfigGeneration', 'ParentServerMPMGeneration', 'Total Accesses']
    result = {name: number(name) for name in fields}
    result['ServerUptime'] = values.get('ServerUptime')
    result['ServerMPM'] = values.get('ServerMPM')
    result['GracefulWorkers'] = board.count('G') if board else None
    result['scoreboard'] = {k: board.count(c) for k, c in (
        ('waiting', '_'), ('starting', 'S'), ('reading', 'R'), ('sending', 'W'), ('keepalive', 'K'),
        ('dns', 'D'), ('closing', 'C'), ('logging', 'L'), ('graceful', 'G'), ('idle_cleanup', 'I'),
        ('open_slot', '.'))} if board else None
    result['scoreboard_slots'] = len(board) if board else None
    result['extended'] = 'ReqPerSec' in values
    return result


# --------------------------------------------------------------------------- configuration
DIRECTIVES = ['ServerLimit', 'ThreadsPerChild', 'MaxRequestWorkers', 'MaxClients', 'MaxConnectionsPerChild',
              'MaxRequestsPerChild', 'Timeout', 'KeepAlive', 'KeepAliveTimeout', 'MaxKeepAliveRequests',
              'StartServers', 'MinSpareThreads', 'MaxSpareThreads', 'ProxyTimeout']


def configuration():
    mpm = next((m for m in ('event', 'worker', 'prefork') if glob.glob('/etc/apache2/mods-enabled/mpm_%s.load' % m)), None)
    files = ['/etc/apache2/apache2.conf'] + sorted(glob.glob('/etc/apache2/mods-enabled/mpm_*.conf')) + \
        sorted(glob.glob('/etc/apache2/conf-enabled/*.conf'))
    found, sources, unreadable = {}, {}, []
    for path in files:
        try:
            text = read_config(path)
        except Exception:
            unreadable.append(path)
            continue
        stack = []
        for line in text.splitlines():
            stripped = line.strip()
            block = re.match(r'<(/?)IfModule\s*([^>]*)>', stripped, re.I)
            if block:
                if block[1]:
                    stack = stack[:-1]
                else:
                    stack.append(block[2].strip().lower())
                continue
            # Directive dans un bloc d'un autre MPM : ignorée.
            if any(s.startswith('mpm_') and s != 'mpm_%s_module' % mpm for s in stack):
                continue
            match = re.match(r'^(\w+)\s+(\S+)', stripped)
            if match and match[1].lower() in [d.lower() for d in DIRECTIVES]:
                name = next(d for d in DIRECTIVES if d.lower() == match[1].lower())
                found[name] = match[2]
                sources[name] = path
    alias = {'MaxClients': 'MaxRequestWorkers', 'MaxRequestsPerChild': 'MaxConnectionsPerChild'}
    for old, new in alias.items():
        if old in found and new not in found:
            found[new], sources[new] = found[old], sources[old]
    defaults = {**MPM_DEFAULTS, **(PREFORK_DEFAULTS if mpm == 'prefork' else {})}
    values = {}
    for name in ('ServerLimit', 'ThreadsPerChild', 'MaxRequestWorkers', 'MaxConnectionsPerChild', 'Timeout',
                 'KeepAlive', 'KeepAliveTimeout', 'MaxKeepAliveRequests', 'StartServers', 'MinSpareThreads',
                 'MaxSpareThreads', 'ProxyTimeout'):
        raw = found.get(name)
        if raw is not None:
            value = int(raw) if raw.isdigit() else raw
            values[name] = {'value': value, 'source': sources[name]}
        elif name in defaults:
            values[name] = {'value': defaults[name], 'source': 'défaut Apache (non déclaré)'}
        else:
            values[name] = {'value': None, 'source': 'non déclaré'}
    limit, threads, maximum = (values[k]['value'] for k in ('ServerLimit', 'ThreadsPerChild', 'MaxRequestWorkers'))
    effective = maximum
    if all(isinstance(v, int) for v in (limit, threads, maximum)):
        effective = min(maximum, limit * threads)
    return {'mpm': mpm, 'directives': values, 'effective_max_workers': effective, 'unreadable': unreadable,
            'scope': 'Directives globales d’apache2.conf, mods-enabled/mpm_*.conf et conf-enabled ; '
                     'surcharges dans les vhosts et Include non résolus.'}


# --------------------------------------------------------------------------- journaux d'erreurs
def parse_error_time(line):
    match = re.match(r'^\[(\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\]', line)
    if not match:
        return None
    try:
        return datetime.datetime.strptime(match[1] + ' ' + match[2], '%a %b %d %H:%M:%S %Y')
    except ValueError:
        return None


def is_modsec_alert(line):
    """Alerte ModSecurity : identifiant de règle ou refus. Les notices écrites à chaque rechargement
    (« ModSecurity for Apache/… configured », versions APR/PCRE) ne sont pas des alertes (comme waf_probe)."""
    return 'ModSecurity' in line and ('[id "' in line or 'Access denied' in line)


def vhost_modsecurity(since):
    """Refus et alertes ModSecurity des journaux d'erreurs des vhosts sur la fenêtre, avec la couverture
    réellement obtenue : un journal illisible, non lu (budget) ou tronqué avant le début de la fenêtre
    rend le décompte minimal, et la page le dit."""
    files = sorted(glob.glob(VHOST_ERROR_GLOB))
    lines_seen = denied_total = read = 0
    by_file, unreadable, not_read, partial = {}, [], [], []
    budget = VHOST_ERROR_TOTAL
    for path in files[:VHOST_ERROR_FILES]:
        try:
            # Journal non modifié depuis le début de la fenêtre : aucune ligne récente, lecture inutile.
            if os.path.getmtime(path) < since.timestamp():
                continue
        except OSError:
            pass
        if budget < VHOST_ERROR_BYTES:
            not_read.append(path)
            continue
        try:
            lines, truncated = read_tail(path, VHOST_ERROR_BYTES)
        except Exception:
            unreadable.append(path)
            continue
        budget -= VHOST_ERROR_BYTES
        read += 1
        oldest, denied = None, 0
        for line in lines:
            at = parse_error_time(line)
            if at is None:
                continue
            oldest = oldest or at
            if at >= since and is_modsec_alert(line):
                lines_seen += 1
                denied += 'Access denied' in line
        if truncated and not (oldest and oldest <= since):
            partial.append(path)
        if denied:
            by_file[path] = denied
            denied_total += denied
    return lines_seen, denied_total, {
        'by_file': sorted(by_file.items(), key=lambda x: (-x[1], x[0]))[:10],
        'files_discovered': len(files), 'files_read': read, 'files_limit': VHOST_ERROR_FILES,
        'unreadable': unreadable[:20], 'not_read': not_read[:20], 'partial': partial[:20],
        'complete': not (unreadable or not_read or partial or len(files) > VHOST_ERROR_FILES)}


def saturation_events():
    now = datetime.datetime.now()
    since = now - datetime.timedelta(seconds=SATURATION_WINDOW_SECONDS)
    lines, truncated = read_tail('/var/log/apache2/error.log', ERROR_BYTES)
    counts = {code: 0 for code, _ in SATURATION_PATTERNS}
    last = {code: None for code, _ in SATURATION_PATTERNS}
    oldest = None
    modsec_denied = modsec_lines = 0
    for line in lines:
        at = parse_error_time(line)
        if at is None:
            continue
        oldest = oldest or at
        if at < since:
            continue
        for code, pattern in SATURATION_PATTERNS:
            if pattern.search(line):
                counts[code] += 1
                last[code] = at.isoformat()
        if is_modsec_alert(line):
            modsec_lines += 1
            modsec_denied += 'Access denied' in line
    covered = bool(oldest and oldest <= since) or not truncated
    vhost_lines, vhost_denied, vhosts = vhost_modsecurity(since)
    return {'window_seconds': SATURATION_WINDOW_SECONDS, 'counts': counts, 'last': last,
            'coverage_complete': covered, 'oldest_line': oldest.isoformat() if oldest else None,
            'modsecurity_lines': modsec_lines + vhost_lines, 'modsecurity_denied': modsec_denied + vhost_denied,
            'modsecurity_main_denied': modsec_denied, 'modsecurity_vhosts': vhosts,
            'scope': 'error.log principal (' + str(ERROR_BYTES // 1048576) + ' Mo au maximum) pour la saturation ; '
                     'refus ModSecurity : error.log et journaux d’erreurs des vhosts (' + str(VHOST_ERROR_BYTES // 1048576)
                     + ' Mo par fichier, ' + str(VHOST_ERROR_TOTAL // 1048576) + ' Mo au total). Fenêtre : '
                     + str(SATURATION_WINDOW_SECONDS // 60) + ' dernières minutes (heure locale du serveur).'}


# --------------------------------------------------------------------------- configuration des vhosts
def unquote(value):
    return value[1:-1].replace('\\"', '"') if len(value) >= 2 and value[0] == value[-1] == '"' else value


def vhosts():
    """Lit sites-enabled : ProxyPass / BalancerMember par vhost, et LogFormat / CustomLog."""
    files = sorted(glob.glob('/etc/apache2/sites-enabled/*'))[:192]
    formats, logs, backends, unreadable = {}, {}, {}, []
    for path in ['/etc/apache2/apache2.conf'] + sorted(glob.glob('/etc/apache2/conf-enabled/*.conf')) + files:
        try:
            text = read_config(path)
        except Exception:
            unreadable.append(path)
            continue
        vhost = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if re.match(r'<VirtualHost\b', stripped, re.I):
                vhost = {'names': [], 'file': path, 'formats': {}}
                continue
            if re.match(r'</VirtualHost', stripped, re.I):
                vhost = None
                continue
            # LogFormat / CustomLog : chaînes entre guillemets avec \" échappés, lues par regex.
            # Un LogFormat déclaré dans un VirtualHost ne vaut que pour ce vhost : sur le WAF,
            # un seul vhost redéfinit « combined » avec %D, les autres gardent le format global.
            fmt_match = re.match(r'^LogFormat\s+"((?:[^"\\]|\\.)*)"\s+(\S+)', stripped, re.I)
            if fmt_match:
                (vhost['formats'] if vhost is not None else formats)[fmt_match[2]] = fmt_match[1].replace('\\"', '"')
                continue
            log_match = re.match(r'^CustomLog\s+("?)([^"\s]+)\1\s+(?:"((?:[^"\\]|\\.)*)"|(\S+))', stripped, re.I)
            if log_match:
                if not log_match[2].startswith('|'):
                    target = log_match[2].replace('${APACHE_LOG_DIR}', '/var/log/apache2')
                    inline, nick = log_match[3], log_match[4]
                    local = vhost['formats'].get(nick) if vhost is not None and nick else None
                    logs[target] = (inline.replace('\\"', '"') if inline else local), nick or 'inline'
                continue
            try:
                tokens = shlex.split(stripped, posix=False)
            except ValueError:
                tokens = stripped.split()
            if not tokens:
                continue
            directive = tokens[0].lower()
            if vhost is not None and directive in ('servername', 'serveralias'):
                vhost['names'].extend(t for t in tokens[1:] if t not in vhost['names'])
            elif vhost is not None and directive in ('proxypass', 'proxypassmatch', 'balancermember'):
                url = next((t for t in tokens[1:] if re.match(r'^"?https?://', t, re.I)), None)
                if not url:
                    continue
                match = re.match(r'^(https?)://([^/:]+|\[[^\]]+\])(?::(\d+))?', unquote(url), re.I)
                if not match:
                    continue
                scheme, host, port = match[1].lower(), match[2].strip('[]'), int(match[3] or (443 if match[1].lower() == 'https' else 80))
                key = '%s://%s:%s' % (scheme, host, port)
                entry = backends.setdefault(key, {'scheme': scheme, 'host': host, 'port': port, 'vhosts': [], 'files': []})
                name = vhost['names'][0] if vhost['names'] else '(vhost sans ServerName)'
                if name not in entry['vhosts']:
                    entry['vhosts'].append(name)
                if path not in entry['files']:
                    entry['files'].append(path)
    # Un CustomLog peut précéder le LogFormat qu'il nomme : on résout une seconde fois.
    logs = {path: (spec if spec is not None else formats.get(nick), nick) for path, (spec, nick) in logs.items()}
    return {'formats': formats, 'logs': logs, 'backends': backends, 'unreadable': unreadable, 'files': len(files)}


# --------------------------------------------------------------------------- backends
def probe_backend(entry):
    started = time.monotonic()
    result = {'backend': '%s:%s' % (entry['host'], entry['port']), 'scheme': entry['scheme'],
              'vhosts': entry['vhosts'][:6], 'vhosts_total': len(entry['vhosts']),
              'tcp_ms': None, 'ttfb_ms': None, 'total_ms': None, 'http_status': None}
    try:
        address = socket.getaddrinfo(entry['host'], entry['port'], proto=socket.IPPROTO_TCP)[0][4]
    except Exception:
        return {**result, 'state': 'NETWORK DOWN', 'detail': 'Nom non résolu'}
    try:
        sock = socket.create_connection(address[:2], timeout=2)
        result['tcp_ms'] = round((time.monotonic() - started) * 1000, 1)
        sock.close()
    except ConnectionRefusedError:
        return {**result, 'state': 'TCP DOWN', 'detail': 'Connexion refusée (port fermé)'}
    except (socket.timeout, TimeoutError):
        return {**result, 'state': 'NETWORK DOWN', 'detail': 'Pas de réponse TCP en 2 s (route, filtrage ou hôte arrêté)'}
    except OSError as exc:
        return {**result, 'state': 'NETWORK DOWN', 'detail': 'Erreur réseau : ' + (exc.strerror or type(exc).__name__)}
    host_header = next((v for v in entry['vhosts'] if not v.startswith('(')), entry['host'])
    begin = time.monotonic()
    try:
        cls = http.client.HTTPSConnection if entry['scheme'] == 'https' else http.client.HTTPConnection
        kwargs = {'context': ssl.create_default_context()} if entry['scheme'] == 'https' else {}
        conn = cls(entry['host'], entry['port'], timeout=3, **kwargs)
        conn.request('HEAD', '/', headers={'Host': host_header, 'User-Agent': 'OpsControl-readonly-healthcheck',
                                           'Connection': 'close'})
        response = conn.getresponse()
        result['ttfb_ms'] = round((time.monotonic() - begin) * 1000, 1)
        response.read(0)
        conn.close()
        result['total_ms'] = round((time.monotonic() - begin) * 1000, 1)
        result['http_status'] = response.status
    except ssl.SSLError:
        return {**result, 'state': 'HTTP STATUS ERROR', 'detail': 'Erreur TLS vers le backend'}
    except (socket.timeout, TimeoutError):
        return {**result, 'state': 'HTTP SLOW', 'detail': 'TCP ouvert mais aucune réponse HTTP en 3 s'}
    except Exception as exc:
        return {**result, 'state': 'HTTP STATUS ERROR', 'detail': 'Réponse HTTP invalide : ' + type(exc).__name__}
    if result['http_status'] >= 500:
        return {**result, 'state': 'HTTP STATUS ERROR', 'detail': 'Code %s' % result['http_status']}
    if result['ttfb_ms'] >= 1000:
        return {**result, 'state': 'HTTP SLOW', 'detail': 'Premier octet après %.1f s' % (result['ttfb_ms'] / 1000)}
    # 404, 401, 302… sur « / » : le backend répond, ce n'est pas une panne.
    return {**result, 'state': 'HTTP RESPONDING', 'detail': 'Code %s' % result['http_status']}


def backends(config):
    entries = list(config['backends'].values())[:40]
    if not entries:
        raise RuntimeError('Aucun ProxyPass http(s) détecté dans sites-enabled')
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(probe_backend, e) for e in entries]
        for future, entry in zip(futures, entries):
            try:
                results.append(future.result(timeout=max(1, min(8, remaining()))))
            except Exception:
                results.append({'backend': '%s:%s' % (entry['host'], entry['port']), 'vhosts': entry['vhosts'][:6],
                                'state': 'NETWORK DOWN', 'detail': 'Test interrompu (budget de collecte)'})
    # Délai TCP sur un port alors qu'un autre port du même hôte répond : l'hôte est
    # joignable, c'est le port qui est filtré ou le service arrêté (TCP DOWN).
    reachable = {r['backend'].rsplit(':', 1)[0] for r in results if r.get('tcp_ms') is not None}
    for r in results:
        if r['state'] == 'NETWORK DOWN' and r['backend'].rsplit(':', 1)[0] in reachable:
            r['state'], r['detail'] = 'TCP DOWN', 'Aucune réponse TCP en 2 s sur ce port ; l’hôte répond sur un autre port (port filtré ou service arrêté)'
    order = {'NETWORK DOWN': 0, 'TCP DOWN': 1, 'HTTP STATUS ERROR': 2, 'HTTP SLOW': 3, 'HTTP RESPONDING': 4}
    results.sort(key=lambda r: (order.get(r['state'], 9), r['backend']))
    return {'backends': results, 'detected': len(config['backends']), 'limit': 40,
            'scope': 'ProxyPass / ProxyPassMatch / BalancerMember de sites-enabled. Test : connexion TCP (2 s) puis '
                     'une requête HEAD / avec le Host du vhost (3 s). Un 404 sur « / » compte comme réponse.'}


# --------------------------------------------------------------------------- journaux d'accès
TOKENS = {
    'h': r'(?P<ip>\S+)', 'a': r'(?P<ip2>\S+)', 'l': r'\S+', 'u': r'\S+', 't': r'\[(?P<time>[^\]]+)\]',
    'r': r'(?P<request>[^"]*)', 's': r'(?P<status>\d{3})', '>s': r'(?P<status>\d{3})', 'D': r'(?P<us>\d+)',
    'T': r'(?P<sec>\d+)', 'b': r'(?P<bytes>\d+|-)', 'B': r'(?P<bytes>\d+|-)', 'O': r'(?P<bytes>\d+|-)', 'I': r'\S+', 'S': r'\S+', 'v': r'\S+',
    'V': r'\S+', 'p': r'\S+', 'P': r'\S+', 'k': r'\S+', 'X': r'\S+', 'H': r'\S+', 'm': r'\S+', 'U': r'\S+',
    'q': r'\S*', 'L': r'\S+', 'R': r'\S+', 'f': r'\S+',
}


def format_regex(spec):
    """Transforme un LogFormat Apache en expression régulière ; None si %D ou %T absent."""
    if '%D' not in spec and '%T' not in spec and not re.search(r'%\{us\}T', spec):
        return None
    out, i, seen = '', 0, set()
    while i < len(spec):
        if spec[i] != '%':
            out += re.escape(spec[i])
            i += 1
            continue
        match = re.match(r'%[<>]?(?:\{([^}]*)\})?([a-zA-Z%]|>s)', spec[i:])
        if not match:
            out += re.escape(spec[i])
            i += 1
            continue
        arg, letter = match[1], match[2]
        i += len(match[0])
        if letter == '%':
            out += '%'
            continue
        if letter == 'i' and arg and arg.lower() == 'user-agent':
            out += r'(?P<ua>[^"]*)'
        elif letter == 'T' and arg in ('us', 'ms'):
            group = 'us' if arg == 'us' else 'ms'
            out += r'(?P<%s>\d+)' % group if group not in seen else r'\d+'
            seen.add(group)
        elif arg is not None and letter in ('i', 'o', 'e', 'n', 'C', 'x', 'c', 't'):
            out += r'[^"]*?' if letter != 't' else r'\[[^\]]*\]'
        else:
            pattern = TOKENS.get(('>s' if match[0].startswith('%>s') else letter), r'\S+')
            names = re.findall(r'\?P<(\w+)>', pattern)
            if any(n in seen for n in names):
                pattern = re.sub(r'\?P<\w+>', '?:', pattern)
            seen.update(names)
            out += pattern
    try:
        return re.compile('^' + out)
    except re.error:
        return None


def normalize_uri(request):
    parts = request.split(' ')
    path = parts[1] if len(parts) >= 2 else request
    path = path.split('?', 1)[0].split('#', 1)[0][:300]
    segments = []
    for segment in path.split('/'):
        if re.fullmatch(r'\d+', segment):
            segment = '{n}'
        elif re.fullmatch(r'[0-9a-fA-F-]{16,}', segment):
            segment = '{id}'
        elif segment.count('-') >= 2 or (len(segment) > 24 and '-' in segment):
            segment = segment.split('-', 1)[0] + '-*'
        segments.append(segment)
    return '/'.join(segments)[:160] or '/'


def bot_category(ua):
    for name, pattern in BOT_REGEX:
        if ua and pattern.search(ua):
            return name
    return None


def access_logs(config):
    now = datetime.datetime.now(datetime.timezone.utc)
    window_start = now - datetime.timedelta(seconds=WINDOW_SECONDS)
    peak_start = now - datetime.timedelta(seconds=PEAK_WINDOW_SECONDS)
    candidates = sorted({p for pattern in ('/var/log/apache2/*access*log', '/var/log/apache2/*access.log',
                                          '/var/log/apache2/access.log') for p in glob.glob(pattern)})[:120]
    if not candidates:
        raise RuntimeError('Aucun journal d’accès découvert')
    # Seuls les journaux modifiés pendant la fenêtre de pic sont lus.
    recent = []
    for path in candidates:
        try:
            info = os.stat(path)  # le répertoire est lisible : pas de sudo pour la date de modification
        except OSError:
            continue
        if info.st_mtime >= peak_start.timestamp():
            recent.append((info.st_size, path))
    recent.sort(reverse=True)
    excluded, analysed, truncated_files = [], [], []
    budget = ACCESS_BYTES_TOTAL
    total = slow1 = slow3 = slow5 = slow10 = 0
    sum_seconds = max_seconds = 0.0
    per_ip = {}
    per_uri = {}
    per_vhost = collections.Counter()
    starts = []
    statuses = collections.Counter()
    blocked_ua, blocked_ip, blocked_uri, bot_counts, bot_blocked = (collections.Counter() for _ in range(5))
    coverage_oldest = None
    formats_used = {}
    for size, path in recent:
        spec_nick = config['logs'].get(path)
        spec = spec_nick[0] if spec_nick else None
        regex = format_regex(spec) if spec else None
        if regex is None:
            excluded.append({'path': path, 'reason': 'Format sans %D / %T' if spec else 'Format non résolu dans la configuration'})
            continue
        if budget <= 0 or remaining() < 8:
            excluded.append({'path': path, 'reason': 'Budget de lecture atteint'})
            continue
        chunk = min(ACCESS_BYTES_PER_FILE, budget)
        try:
            lines, truncated = read_tail(path, chunk)
        except Exception:
            excluded.append({'path': path, 'reason': 'Lecture refusée'})
            continue
        budget -= min(chunk, size)
        if truncated:
            truncated_files.append(path)
        vhost = re.sub(r'(-|_)?access(_log|\.log|log)?$', '', path.rsplit('/', 1)[-1]) or 'défaut'
        parsed = 0
        for line in lines:
            match = regex.match(line)
            if not match:
                continue
            groups = match.groupdict()
            try:
                start = datetime.datetime.strptime(groups['time'], '%d/%b/%Y:%H:%M:%S %z')
            except (KeyError, TypeError, ValueError):
                continue
            if groups.get('us'):
                seconds = int(groups['us']) / 1e6
            elif groups.get('ms'):
                seconds = int(groups['ms']) / 1e3
            elif groups.get('sec'):
                seconds = float(groups['sec'])
            else:
                continue
            parsed += 1
            if coverage_oldest is None or start < coverage_oldest:
                coverage_oldest = start
            if start >= peak_start:
                starts.append((start.timestamp(), seconds))
            if start < window_start:
                continue
            total += 1
            per_vhost[vhost] += 1
            sum_seconds += seconds
            max_seconds = max(max_seconds, seconds)
            slow1 += seconds >= 1
            slow3 += seconds >= 3
            slow5 += seconds >= 5
            slow10 += seconds >= 10
            status = groups.get('status') or '???'
            statuses[status] += 1
            ip = valid_ip(groups.get('ip') or groups.get('ip2') or '') or 'inconnue'
            ua = (groups.get('ua') or '')[:160]
            category = bot_category(ua)
            item = per_ip.setdefault(ip, {'requests': 0, 'slow5': 0, 'slow10': 0, 'sum': 0.0, 'max': 0.0,
                                          'ua': collections.Counter(), 's403': 0, 's429': 0})
            item['requests'] += 1
            # Les octets ne sont mesurés que si le LogFormat déclaré comporte %b/%B/%O.
            if groups.get('bytes') is not None:
                item['bytes'] = item.get('bytes', 0) + (0 if groups['bytes'] == '-' else int(groups['bytes']))
            item['slow5'] += seconds >= 5
            item['slow10'] += seconds >= 10
            item['sum'] += seconds
            item['max'] = max(item['max'], seconds)
            if ua:
                item['ua'][ua] += 1
            uri = normalize_uri(groups.get('request') or '')
            entry = per_uri.setdefault(uri, {'requests': 0, 'sum': 0.0, 'max': 0.0, 'slow10': 0})
            entry['requests'] += 1
            entry['sum'] += seconds
            entry['max'] = max(entry['max'], seconds)
            entry['slow10'] += seconds >= 10
            if category:
                bot_counts[category] += 1
            if status in ('403', '429'):
                item['s' + status] += 1
                blocked_ua[ua or '(vide)'] += 1
                blocked_ip[ip] += 1
                blocked_uri[uri] += 1
                if category:
                    bot_blocked[category] += 1
        analysed.append({'path': path, 'parsed_lines': parsed, 'lines_read': len(lines), 'truncated': truncated,
                         'format': spec_nick[1] if spec_nick else None})
        formats_used[spec_nick[1] if spec_nick else '?'] = spec
        if len(per_ip) > 50000 or len(per_uri) > 50000:
            break
    if not analysed:
        raise RuntimeError('Aucun journal exploitable : %s' % ('; '.join('%s (%s)' % (e['path'].rsplit('/', 1)[-1], e['reason']) for e in excluded[:5]) or 'aucun journal récent'))

    def concurrency(since):
        events = collections.Counter()
        for begin, seconds in starts:
            if begin + seconds < since.timestamp():
                continue
            events[int(begin)] += 1
            events[int(begin + max(seconds, 0.001)) + 1] -= 1
        running = peak = 0
        peak_at = None
        for second in sorted(events):
            running += events[second]
            if running > peak and second >= int(since.timestamp()):
                peak, peak_at = running, second
        return peak, peak_at

    peak10, peak10_at = concurrency(window_start)
    peak60, peak60_at = concurrency(peak_start)
    last_minute = now - datetime.timedelta(seconds=60)
    current, _ = concurrency(last_minute)
    covered_seconds = (now - coverage_oldest).total_seconds() if coverage_oldest else 0

    def top_ips():
        rows = sorted(per_ip.items(), key=lambda kv: (-kv[1]['slow10'], -kv[1]['requests']))[:20]
        return [{'ip': ip, 'requests': v['requests'], 'slow5': v['slow5'], 'slow10': v['slow10'],
                 'avg': round(v['sum'] / v['requests'], 3), 'max': round(v['max'], 3),
                 'user_agent': v['ua'].most_common(1)[0][0] if v['ua'] else None,
                 'bot': bot_category(v['ua'].most_common(1)[0][0]) if v['ua'] else None,
                 's403': v['s403'], 's429': v['s429']} for ip, v in rows]

    def top_uris():
        rows = sorted(per_uri.items(), key=lambda kv: (-kv[1]['slow10'], -kv[1]['sum']))[:20]
        return [{'uri': uri, 'requests': v['requests'], 'avg': round(v['sum'] / v['requests'], 3),
                 'max': round(v['max'], 3), 'slow10': v['slow10']} for uri, v in rows]

    return {
        'window_seconds': WINDOW_SECONDS, 'total': total, 'slow1': slow1, 'slow3': slow3, 'slow5': slow5,
        'slow10': slow10, 'avg': round(sum_seconds / total, 3) if total else None,
        'max': round(max_seconds, 3) if total else None, 'rps': round(total / WINDOW_SECONDS, 2),
        'statuses': dict(statuses), 'top_ips': top_ips(), 'top_uris': top_uris(),
        'sample_response_bytes': dict(sorted(
            ((ip, value['bytes']) for ip, value in per_ip.items() if 'bytes' in value),
            key=lambda item: -item[1])[:200]),
        'top_vhosts': per_vhost.most_common(10),
        'concurrency': {'current': current, 'peak_10m': peak10, 'peak_10m_at': peak10_at,
                        'peak_1h': peak60, 'peak_1h_at': peak60_at,
                        'covered_minutes': round(min(covered_seconds, PEAK_WINDOW_SECONDS) / 60, 1)},
        'bots': {'s403': statuses.get('403', 0), 's429': statuses.get('429', 0),
                 'categories': bot_counts.most_common(), 'blocked_categories': bot_blocked.most_common(),
                 'top_user_agents': blocked_ua.most_common(8), 'top_ips': blocked_ip.most_common(8),
                 'top_uris': blocked_uri.most_common(8)},
        'files': analysed, 'excluded': excluded[:60], 'truncated': truncated_files, 'formats': formats_used,
        'scope': 'Journaux d’accès modifiés dans l’heure, format lu dans la configuration (LogFormat avec %D ou %T), '
                 + str(ACCESS_BYTES_PER_FILE // 1048576) + ' Mo par fichier et ' + str(ACCESS_BYTES_TOTAL // 1048576)
                 + ' Mo au total au maximum. Une requête est journalisée à sa fin : les requêtes encore en cours '
                 'ne sont pas comptées, la concurrence est donc un minimum.'}


def main():
    sections = {}

    def section(name, fn, *args):
        if remaining() <= 2:
            sections[name] = {'status': 'unknown', 'error': 'Budget de collecte épuisé avant cette section'}
            return None
        try:
            data = fn(*args)
            sections[name] = {'status': 'observed', 'data': data}
            return data
        except Exception as exc:
            sections[name] = {'status': 'unknown', 'error': str(exc)[:220]}
            return None

    section('status', server_status)
    section('config', configuration)
    section('saturation', saturation_events)
    try:
        config = vhosts()
    except Exception as exc:
        config = None
        sections['backends'] = sections['access'] = {'status': 'unknown', 'error': 'Configuration des vhosts illisible : ' + str(exc)[:160]}
    if config is not None:
        section('backends', backends, config)
        section('access', access_logs, config)
    print(json.dumps({'version': 1, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'duration_ms': round((time.monotonic() - STARTED) * 1000), 'sections': sections}))


if __name__ == '__main__':
    main()
