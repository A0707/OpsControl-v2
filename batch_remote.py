"""Read-only Linux scheduling probe. Executed through SSH's fixed allowlist.

Never executes a scheduled command. Never returns cron command arguments or
environment values. Python 3 is required on the remote host; no installation.
"""
import datetime
import glob
import hashlib
import json
import os
import posixpath
import re
import shlex
import subprocess
import time

LIMIT = 300


def command_metadata(command, depth=0, directory=None):
    """Extract executable/script paths only, never command arguments or contents."""
    empty = {'executable': None, 'script': None}
    if depth > 3:
        return empty
    try:
        tokens = shlex.split(command)
    except ValueError:
        return empty
    while tokens and re.match(r'^\w+=', tokens[0]):
        tokens.pop(0)
    if not tokens:
        return empty

    def path(value):
        if not value or len(value) > 512 or not re.fullmatch(r'[A-Za-z0-9_./+@-]+', value):
            return None
        if directory and value.startswith('./'):
            return posixpath.normpath(posixpath.join(directory, value))
        return value

    if tokens[0] == 'cd' and len(tokens) > 3 and tokens[2] in ('&&', ';'):
        return command_metadata(shlex.join(tokens[3:]) if hasattr(shlex, 'join') else
                                ' '.join(shlex.quote(t) for t in tokens[3:]), depth+1, path(tokens[1]))
    program = path(tokens[0])
    result = {'executable': program, 'script': None}
    base = posixpath.basename(program or '')
    if base == 'infraops-batch-report' and len(tokens) > 2:
        return command_metadata(' '.join(shlex.quote(t) for t in tokens[2:]), depth+1, directory)
    if base in ('sh', 'bash', 'dash', 'ksh', 'zsh'):
        if len(tokens) > 2 and tokens[1] == '-c':
            inner = command_metadata(tokens[2], depth+1, directory)
            result['script'] = inner['script']
        elif len(tokens) > 1 and not tokens[1].startswith('-'):
            result['script'] = path(tokens[1])
    elif re.fullmatch(r'(python[0-9.]*|perl|ruby|php|node)', base):
        if len(tokens) > 1 and not tokens[1].startswith('-'):
            result['script'] = path(tokens[1])
    elif base == 'java' and '-jar' in tokens[1:-1]:
        # Batchs Java du referentiel : le jar est le traitement, pas java.
        result['script'] = path(tokens[tokens.index('-jar') + 1])
    elif program and (program.startswith(('/', './', '../')) or
                      program.endswith(('.sh', '.py', '.pl', '.rb', '.php', '.js'))):
        result['script'] = program
    return result


def log_target(command, depth=0):
    """Fichier vers lequel une ligne cron redirige sa sortie : un chemin, pas un argument."""
    if depth > 3:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        if token == '-c' and index and index + 1 < len(tokens) and \
                posixpath.basename(tokens[index-1]) in ('sh', 'bash', 'dash', 'ksh'):
            inner = log_target(tokens[index+1], depth+1)
            if inner:
                return inner
        joined = re.match(r'^(?:1|&)?>>?(/[A-Za-z0-9_./+@-]+)$', token)
        if joined:
            target = joined.group(1)
        elif token in ('>', '>>', '1>', '1>>', '&>', '&>>') and index + 1 < len(tokens):
            target = tokens[index+1]
        else:
            continue
        if re.fullmatch(r'/[A-Za-z0-9_./+@-]{1,300}', target) and target != '/dev/null':
            return target
    return None


def cron_rows(text, source, owner, system=False, zone='Heure locale du serveur'):
    jobs = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            if line.startswith('CRON_TZ='):
                zone = line.split('=', 1)[1].strip().strip('"\'')[:80]
            continue
        count = (1 if line.startswith('@') else 5) + int(system)
        parts = line.split(None, count)
        if len(parts) != count + 1:
            continue
        schedule = ' '.join(parts[:count-int(system)])
        user = parts[count-1] if system else owner
        command = parts[-1]
        metadata = command_metadata(command)
        try:
            tokens = shlex.split(command)
            program = next((t for t in tokens if not re.match(r'^\w+=', t)), '')
            program = os.path.basename(program)
            if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,100}', program):
                program = 'Commande composée'
        except ValueError:
            program = 'Commande à vérifier sur le serveur'
        if metadata['script']:
            program = posixpath.basename(metadata['script'])
        jobs.append({'id': hashlib.sha256((source+':'+str(number)).encode()).hexdigest()[:20],
                     **metadata, 'log': log_target(command),
                     'kind': 'cron', 'name': program, 'source': source, 'line': number,
                     'owner': user[:100], 'schedule': schedule[:120], 'timezone': zone,
                     'state': 'scheduled', 'last_run': None, 'next_run': None,
                     'evidence': 'Planification déclarée ; exécution et résultat non mesurés.'})
    return jobs


BATCH_ROOT = '/var/batch'
BATCH_FILES = 2000
SCRIPT_EXT = ('.sh', '.py', '.jar', '.pl', '.php', '.ksh')
LOG_DIRS = ('log', 'logs', 'trace', 'traces')
LOG_NAME = re.compile(r'[.](log|out|err)([.][0-9]+|[.-][0-9]{4}-?[0-9]{2}-?[0-9]{2})?$')
PACKED = ('.gz', '.zip', '.bz2', '.xz', '.tar', '.tgz')
LOGS_PER_DIR = 4
LOGS_READ = 160
TAIL_BYTES = 65536
WRAPPER_DIR = '/var/lib/infraops-batch'


def batch_files(root=BATCH_ROOT, deadline=None):
    """Scripts et journaux presents sous /var/batch : chemin et date seulement.

    Les scripts disent si le lanceur du referentiel existe encore ; les journaux
    les plus recents de chaque dossier de batch sont lus ensuite (fin bornee).
    """
    found = {'root': root, 'readable': os.path.isdir(root) and os.access(root, os.R_OK | os.X_OK),
             'dirs': [], 'files': [], 'logs': [], 'truncated': False}
    if not found['readable']:
        return found
    logs, seen = {}, 0
    for current, dirs, files in os.walk(root):
        relative = os.path.relpath(current, root)
        parts = [] if relative == '.' else relative.split(os.sep)
        current = current.replace(os.sep, '/')
        if len(parts) == 1:
            found['dirs'].append(current)
        in_log = any(p.lower() in LOG_DIRS for p in parts)
        # Archives et temporaires : jamais le dernier passage.
        dirs[:] = sorted(d for d in dirs if len(parts) < 3 and
                         d.lower() not in ('archive', 'archives', 'tmp', 'old', 'backup'))
        for name in sorted(files):
            seen += 1
            full = posixpath.join(current, name)
            is_log = not name.endswith(PACKED) and bool(LOG_NAME.search(name) or in_log)
            if not is_log and (in_log or not name.endswith(SCRIPT_EXT)):
                continue
            try:
                info = os.stat(full)
            except OSError:
                continue
            if is_log and parts:
                folder = posixpath.join(root, parts[0])
                logs.setdefault(folder, []).append([full, int(info.st_mtime), info.st_size])
            elif not is_log and len(found['files']) < BATCH_FILES:
                found['files'].append([full, int(info.st_mtime)])
        if len(found['files']) >= BATCH_FILES or seen > 20000 or (deadline and time.monotonic() > deadline):
            found['truncated'] = True
            break
    for folder in sorted(logs):
        found['logs'].extend(sorted(logs[folder], key=lambda f: -f[1])[:LOGS_PER_DIR])
    return found


SECRET = re.compile(r'(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization|credentials?)"?\s*[:=]\s*)((?:bearer|basic)\s+\S+|\S+)')
BEARER = re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+')
URL_USER = re.compile(r'(//[^/\s:@]+):[^@\s/]+@')
LONG_TOKEN = re.compile(r'[A-Za-z0-9+/_-]{40,}={0,2}')
CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
ERROR = re.compile(r'\b(ERROR|FATAL|SEVERE|CRITICAL|ECHEC|Echec)\b|Exception\b|Caused by:|Traceback [(]most recent')
SUCCESS = re.compile(r'BUILD SUCCESS|\bSUCCESS\b|termin\S* avec succ|\bFin (du )?(batch|traitement)\b|\bCOMPLETED\b')
SPRING = re.compile(r'status: \[(COMPLETED|FAILED|STOPPED|ABANDONED|UNKNOWN)\]')


def mask(line):
    """Masque mots de passe, jetons et identifiants dans une ligne de journal."""
    line = CONTROL.sub(' ', line)
    line = SECRET.sub(lambda m: m.group(1) + '***', line)
    line = BEARER.sub(lambda m: m.group(1) + ' ***', line)
    line = URL_USER.sub(lambda m: m.group(1) + ':***@', line)
    line = LONG_TOKEN.sub('***', line)
    return line.strip()[:240]


def log_digest(path):
    """Fin d un journal : verdict du dernier passage et lignes qui l expliquent.

    Lecture seule et bornee (64 Kio de fin de fichier) ; seules quelques lignes
    masquees sortent du serveur, jamais le fichier.
    """
    digest = {'path': path, 'mtime': None, 'size': None, 'readable': False,
              'verdict': 'unknown', 'strength': None, 'errors': [], 'last_lines': []}
    try:
        info = os.stat(path)
        digest['mtime'], digest['size'] = int(info.st_mtime), info.st_size
        with open(path, 'rb') as handle:
            if info.st_size > TAIL_BYTES:
                handle.seek(info.st_size - TAIL_BYTES)
            data = handle.read(TAIL_BYTES)
    except OSError:
        return digest
    digest['readable'] = True
    lines = [line for line in data.decode('utf-8', 'replace').splitlines() if line.strip()]
    if info.st_size > TAIL_BYTES:
        lines = lines[1:]  # premiere ligne coupee par la lecture de fin
    spring = [m.group(1) for m in (SPRING.search(line) for line in lines) if m]
    errors = [i for i, line in enumerate(lines) if ERROR.search(line)]
    success = [i for i, line in enumerate(lines) if SUCCESS.search(line)]
    if spring:
        # Statut final Spring Batch : preuve forte du dernier passage.
        digest['verdict'] = 'success' if spring[-1] == 'COMPLETED' else 'failed'
        digest['strength'] = 'Statut Spring Batch ' + spring[-1]
    elif errors and (not success or errors[-1] > success[-1]):
        digest['verdict'], digest['strength'] = 'failed', 'Erreur apres le dernier marqueur de fin'
    elif success:
        digest['verdict'], digest['strength'] = 'success', 'Marqueur de fin sans erreur apres'
    digest['errors'] = [mask(lines[i]) for i in errors[-5:]]
    digest['last_lines'] = [mask(line) for line in lines[-3:]]
    return digest


def wrapper_runs(directory=WRAPPER_DIR):
    """Etats ecrits par infraops-batch-report : code retour, duree, fin de sortie."""
    runs = {'readable': os.path.isdir(directory) and os.access(directory, os.R_OK | os.X_OK), 'runs': []}
    if not runs['readable']:
        return runs
    for state in sorted(glob.glob(posixpath.join(directory, '*.state')))[:400]:
        name = os.path.basename(state)[:-6]
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}', name):
            continue
        values = {}
        try:
            with open(state, encoding='utf-8', errors='replace') as handle:
                for line in handle.read(4096).splitlines():
                    key, _, value = line.partition('=')
                    if key in ('started', 'finished', 'rc', 'duration') and re.fullmatch(r'-?[0-9]{1,12}', value):
                        values[key] = int(value)
        except OSError:
            continue
        tail = []
        try:
            with open(posixpath.join(directory, name + '.tail'), 'rb') as handle:
                text = handle.read(16384).decode('utf-8', 'replace')
            tail = [mask(line) for line in text.splitlines() if line.strip()][-40:]
        except OSError:
            tail = []
        runs['runs'].append(dict(values, name=name, tail=tail))
    return runs


def properties(text):
    return [dict(line.split('=', 1) for line in part.splitlines() if '=' in line)
            for part in text.strip().split('\n\n') if part.strip()]


def process_rows(text, zone):
    """Running scripts from ps, excluding process arguments from the result."""
    jobs = []
    for line in text.splitlines()[:2048]:
        fields = line.strip().split(None, 3)
        if len(fields) != 4 or not fields[0].isdigit() or not fields[2].isdigit():
            continue
        pid, owner, elapsed, command = fields
        metadata = command_metadata(command)
        script = metadata['script']
        if not script or not script.endswith(('.sh', '.py', '.pl', '.rb', '.php', '.js')):
            continue
        jobs.append({'id':'process:'+pid, 'kind':'process', 'name':posixpath.basename(script),
                     **metadata, 'pid':int(pid), 'elapsed_seconds':int(elapsed),
                     'source':'Processus observé', 'owner':owner[:100], 'timezone':zone,
                     'schedule':'Déclenchement non mesuré', 'state':'running',
                     'last_run':None, 'next_run':None,
                     'evidence':'PID '+pid+' · actif depuis '+elapsed+' secondes ; résultat final non mesuré.'})
    return jobs


def timer_rows(timers, services, zone):
    by_id = {s.get('Id'): s for s in services}
    jobs = []
    for timer in timers:
        name = timer.get('Id', '')
        if not name.endswith('.timer'):
            continue
        unit = timer.get('Unit') or name[:-6]+'.service'
        service = by_id.get(unit, {})
        active, sub = service.get('ActiveState'), service.get('SubState')
        ended = service.get('ExecMainExitTimestamp') or None
        outcome = service.get('Result')
        if active == 'failed' or (ended and outcome and outcome != 'success'):
            state = 'failed'
        elif active == 'activating' or (active == 'active' and sub in ('running', 'start')):
            state = 'running'
        elif ended and outcome == 'success':
            state = 'success'
        else:
            state = 'unknown'
        # systemctl show serializes ExecStart; discard arguments after extracting paths.
        executable = re.search(r'(?:^|[ {;])path=([^ ;}]+)', service.get('ExecStart', ''))
        metadata = command_metadata(executable.group(1)) if executable else {'executable': None, 'script': None}
        argv = re.search(r'argv\[\]=(.*?) ; ignore_errors=', service.get('ExecStart', ''))
        if argv:
            metadata['script'] = command_metadata(argv.group(1))['script']
        jobs.append({'id': name, 'kind': 'systemd', 'name': name, 'source': unit,
                     **metadata,
                     'owner': service.get('User') or 'root (systemd système)',
                     'schedule': timer.get('TimersCalendar') or timer.get('TimersMonotonic') or 'Expression non disponible',
                     'timezone': zone, 'state': state, 'timer_state': timer.get('ActiveState'),
                     'last_run': timer.get('LastTriggerUSec') or None,
                     'next_run': timer.get('NextElapseUSecRealtime') or None,
                     'exit_code': service.get('ExecMainStatus'),
                     'evidence': 'Dernier résultat du service : '+(outcome or 'non mesuré')})
    return jobs


def main():
    import pwd
    deadline = time.monotonic() + 18
    limitations, jobs, crontabs = [], [], []

    def read_command(args):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            return None
        try:
            # stdout/stderr=PIPE + universal_newlines plutôt que capture_output/text :
            # ceux-ci n’existent qu’à partir de Python 3.7, et CentOS 7 (prddcyjob02)
            # n’a que 3.6 — la sonde y plantait, d’où « Sonde indisponible ».
            # (Apostrophes typographiques exprès : une apostrophe droite dans ce
            # fichier casse les guillemets de la commande SSH.)
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                  errors='replace', timeout=min(3, remaining),
                                  env={**os.environ, 'LC_ALL':'C', 'SYSTEMD_COLORS':'0'})
        except (OSError, subprocess.TimeoutExpired):
            return None

    tz = read_command(['timedatectl', 'show', '-p', 'Timezone', '--value'])
    zone = tz.stdout.strip()[:80] if tz and tz.returncode == 0 else 'Heure locale du serveur (fuseau non lu)'
    user = pwd.getpwuid(os.getuid()).pw_name
    cron = read_command(['crontab', '-l'])
    if cron and cron.returncode == 0:
        jobs.extend(cron_rows(cron.stdout, 'crontab:'+user, user, zone=zone))
        crontabs.append(user)
    elif not cron or 'no crontab for' not in cron.stderr.lower():
        limitations.append('Crontab du compte non accessible ou outil absent')
    files = ['/etc/crontab'] + sorted(glob.glob('/etc/cron.d/*'))
    for filename in files[:128]:
        if not os.path.isfile(filename):
            continue
        try:
            with open(filename, encoding='utf-8', errors='replace') as handle:
                content = handle.read(262145)
            if len(content) > 262144:
                limitations.append('Fichier cron trop volumineux : '+filename)
                continue
            jobs.extend(cron_rows(content, filename, 'root', system=True, zone=zone))
        except OSError:
            limitations.append('Fichier cron non accessible : '+filename)
    spool = sorted(set(glob.glob('/var/spool/cron/*') + glob.glob('/var/spool/cron/crontabs/*')))
    for filename in spool[:128]:
        if not os.path.isfile(filename) or os.path.basename(filename) == user:
            continue
        try:
            with open(filename, encoding='utf-8', errors='replace') as handle:
                content = handle.read(262145)
            if len(content) > 262144:
                limitations.append('Crontab trop volumineuse : '+filename)
                continue
            jobs.extend(cron_rows(content, filename, os.path.basename(filename), zone=zone))
            crontabs.append(os.path.basename(filename))
        except OSError:
            limitations.append('Crontab non accessible : '+filename)
    for period in ('hourly', 'daily', 'weekly', 'monthly'):
        for filename in sorted(glob.glob('/etc/cron.'+period+'/*'))[:128]:
            if not os.path.isfile(filename) or not os.access(filename, os.X_OK):
                continue
            jobs.append({'id': hashlib.sha256(filename.encode()).hexdigest()[:20],
                         'kind': 'cron', 'name': os.path.basename(filename), 'script': filename,
                         'executable': filename, 'source': '/etc/cron.'+period,
                         'owner': 'Compte du lanceur cron/anacron non mesuré',
                         'schedule': period+' · horaire du lanceur non mesuré', 'timezone': zone,
                         'state': 'unknown', 'last_run': None, 'next_run': None,
                         'evidence': 'Script exécutable présent ; activation et exécution non mesurées.'})
    processes = read_command(['ps', '-eo', 'pid=,user=,etimes=,args='])
    if processes and processes.returncode == 0:
        # Running scripts take priority over the bounded scheduling history.
        jobs = process_rows(processes.stdout, zone) + jobs
        if len(processes.stdout.splitlines()) > 2048:
            limitations.append('Processus limités aux 2048 premières lignes')
    else:
        limitations.append('Scripts en cours non accessibles')
    limitations.append('Seules les crontabs et processus accessibles sont lus ; scripts non planifiés et inactifs et ordonnanceurs applicatifs non inspectés')
    listing = read_command(['systemctl','list-units','--type=timer','--all','--plain','--no-legend','--no-pager'])
    if listing and listing.returncode == 0:
        units = [line.split()[0] for line in listing.stdout.splitlines() if line.split() and re.fullmatch(r'[A-Za-z0-9_.@:-]+\.timer',line.split()[0])]
        if len(units)>64:
            limitations.append('Timers limités aux 64 premières unités chargées')
        units = units[:64]
        props = 'Id,Unit,ActiveState,LastTriggerUSec,NextElapseUSecRealtime,TimersCalendar,TimersMonotonic'
        timers = read_command(['systemctl','show','--no-pager','-p',props,'--']+units) if units else None
        if timers and timers.returncode == 0:
            parsed = properties(timers.stdout)
            service_units = [t.get('Unit') or t.get('Id','')[:-6]+'.service' for t in parsed]
            service_units = [u for u in service_units if re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service',u)]
            services = read_command(['systemctl','show','--no-pager','-p','Id,User,ActiveState,SubState,Result,ExecMainStatus,ExecMainExitTimestamp,ExecStart','--']+service_units) if service_units else None
            jobs.extend(timer_rows(parsed, properties(services.stdout) if services and services.returncode==0 else [], zone))
            if not services or services.returncode:
                limitations.append('Résultats des services associés non mesurés')
        elif units:
            limitations.append('Propriétés des timers non accessibles')
    else:
        limitations.append('Timers systemd non accessibles ou systemd absent')
    if len(files)>128 or len(spool)>128 or len(jobs)>LIMIT:
        limitations.append('Inventaire tronqué par les limites de collecte')
    # Journaux : les plus recents de chaque dossier de /var/batch, puis ceux
    # vers lesquels une ligne cron redirige la sortie.
    files = batch_files(deadline=deadline + 6)
    targets = [f[0] for f in files.get('logs', [])]
    targets += sorted({j['log'] for j in jobs if j.get('log')} - set(targets))[:64]
    logs = [log_digest(path) for path in targets[:LOGS_READ]]
    # Comptes dont la crontab a ete lue : sans root, une absence de planification
    # dans le referentiel reste non verifiable plutot que fausse.
    print(json.dumps({'collected_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'jobs':jobs[:LIMIT], 'limitations':limitations, 'timezone':zone,
                      'crontabs_read':sorted(set(crontabs)),
                      'batch_files':files, 'batch_logs':logs, 'batch_runs':wrapper_runs()}, ensure_ascii=True))


if __name__ == '__main__':
    main()
