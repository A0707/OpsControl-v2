"""Evidence-based read-only checks and non-executable remediation advice."""
import re, shlex
from dataclasses import replace
from datetime import datetime, timezone
import ssh

PROBES = {
 'identity': ('Système', 'uname -s; id; uname -r'),
 'inodes': ('Inodes', 'LC_ALL=C df -iP'),
 'network': ('Réseau et écoute', 'LC_ALL=C ss -lntu'),
 'timers': ('Planification système', 'LC_ALL=C systemctl list-timers --all --no-pager'),
 'cron_user': ('Crontab du compte connecté', 'crontab -l'),
 'clock': ('Synchronisation horaire', 'LC_ALL=C timedatectl show -p NTPSynchronized -p NTP'),
 'ssh_policy': ('Configuration SSH effective', '/usr/sbin/sshd -T'),
 'permissions': ('Permissions des comptes', "LC_ALL=C stat -c '%a %U %n' /etc/passwd /etc/shadow"),
 'errors': ('Erreurs des journaux', 'LC_ALL=C journalctl -p 3 --since "1 hour ago" -n 40 --no-pager -o short-iso'),
}
# Extends the shared SSH allowlist at import time (same pattern as waf_audit.py):
# anything reading ssh.OPERATIONS before this module is imported sees it incomplete.
ssh.OPERATIONS.update({k:v[1] for k,v in PROBES.items()})
# Sonde detaillee stockage/partages/securite : une seule operation SSH pour huit
# familles de mesures (voir storage_probe). Enregistree comme les autres, donc
# soumise a la meme allowlist.
import storage_probe
ssh.OPERATIONS['storage'] = storage_probe.COMMAND

def redact(value):
    text = str(value or '')
    text = re.sub(r'(?is)-----BEGIN .*?PRIVATE KEY-----.*?-----END .*?PRIVATE KEY-----', '[CLÉ MASQUÉE]', text)
    # Schémas d'en-tête : la valeur suit le MOT « Bearer »/« Basic », que la règle
    # « authorization: » ci-dessous masquait seul, en laissant le jeton lisible.
    text = re.sub(r'(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}', r'\1[MASQUÉ]', text)
    text = re.sub(r'(?i)\b(basic\s+)(?=[A-Za-z0-9+/]*[0-9+/=])[A-Za-z0-9+/]{12,}={0,2}', r'\1[MASQUÉ]', text)
    # Mots de passe en argument de commande (crontab, journaux, ps) : -pSECRET des clients
    # MySQL/MariaDB, --password SECRET, sshpass -p SECRET, curl -u compte:SECRET.
    text = re.sub(r'(?i)(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]*?\s-p)(?=[^\s-])\S+', r'\1[MASQUÉ]', text)
    text = re.sub(r'(?i)((?<![\w-])--?(?:password|passwd|pass|token|api-key|apikey|secret)\s+)(?!-)\S+', r'\1[MASQUÉ]', text)
    text = re.sub(r'(?i)(\bsshpass\s+(?:-\w\s+)*-p\s*)\S+', r'\1[MASQUÉ]', text)
    text = re.sub(r'(?i)((?:\s-u|--user)\s+[^\s:]+:)\S+', r'\1[MASQUÉ]', text)
    text = re.sub(r'(?i)((?:password|passwd|pwd|passphrase|mot[_ -]?de[_ -]?passe|token|jeton|secret|api[_-]?key|authorization)\s*[=:]\s*)[^\s,;]+', r'\1[MASQUÉ]', text)
    text = re.sub(r'(?i)(https?://)[^\s/@:]+:[^\s/@]+@', r'\1[MASQUÉ]@', text)
    return text[:12000] + ('\n[Sortie tronquée]' if len(text)>12000 else '')

def guide(check, fix, precaution, scope='Sur le serveur concerné', configurable=False):
    return {'check_command':check,'solution_command':fix,'precaution':precaution,'scope':scope,'requires_adaptation':configurable,'executable':False}

def finding(key,title,domain,severity,evidence,advice):
    return {'id':key,'title':title,'domain':domain,'severity':severity,'evidence':redact(evidence),**advice}

def generic_guide(op):
    return guide(ssh.OPERATIONS.get(op,''),'# Vérifier les droits et la disponibilité de cet outil avec l’administrateur.',
                 'Aucune correction universelle : confirmer la cause avant de modifier les droits.', configurable=True)

# Agents de sauvegarde reconnus, par unité systemd. La liste est volontairement
# explicite : deviner à partir d'un nom approchant produirait de faux positifs,
# et « peut-être sauvegardé » ne vaut pas mieux que « inconnu ».
BACKUP_AGENTS = {
    'bacula-fd.service': 'Bacula File Daemon',
    'bareos-fd.service': 'Bareos File Daemon',
    'borgmatic.service': 'Borgmatic',
    'restic.service': 'Restic',
    'duplicity.service': 'Duplicity',
    'rsnapshot.service': 'rsnapshot',
    'proxmox-backup-proxy.service': 'Proxmox Backup Server',
}
BACKUP_TIMERS = ('borgmatic.timer', 'restic.timer', 'duplicity.timer', 'rsnapshot.timer', 'bacula-fd.timer')
BACKUP_PRECAUTION = ("Un agent actif prouve qu'il tourne, jamais qu'une sauvegarde a réussi ni "
                     "qu'elle est restaurable. Seul un test de restauration le démontre.")


def backup_check(host, result, checks, findings):
    """Évalue la sauvegarde à partir des unités déjà collectées.

    Aucune commande SSH supplémentaire : `all_services` et le contrôle `timers`
    sont déjà dans le résultat. Trois états sont distingués, là où la version
    précédente renvoyait la même phrase sur tous les serveurs :

      - unités non lues      -> inconnu, et on le dit (ne rien conclure)
      - agent présent        -> observé (actif) ou anomalie (arrêté/en échec)
      - aucun agent          -> couverture à confirmer, jamais « pas sauvegardé » :
                                une sauvegarde au niveau hyperviseur (vzdump, PBS)
                                n'est pas visible depuis l'intérieur de la VM.
    """
    command = ssh.OPERATIONS['services']
    units = result.get('all_services')
    if not units:
        checks.append({'id': 'backups', 'title': 'Sauvegardes', 'status': 'unknown', 'command': command,
                       'executed': False, 'evidence': "Unités systemd non lues : la sauvegarde de ce serveur n'est pas évaluable."})
        findings.append(finding('backups', 'Sauvegardes : contrôle impossible', 'Couverture', 'unknown',
                                checks[-1]['evidence'],
                                guide(command, '# Rétablir la collecte SSH de ce serveur avant toute conclusion sur sa sauvegarde.',
                                      "Absence de mesure n'est pas absence de sauvegarde : ne rien déduire de ce contrôle.",
                                      configurable=True)))
        return

    states = {u.get('name'): u.get('status') for u in units if isinstance(u, dict)}
    found = [(BACKUP_AGENTS[name], name, state) for name, state in states.items() if name in BACKUP_AGENTS]
    timers_evidence = next((c.get('evidence', '') for c in checks if c.get('id') == 'timers'), '')
    scheduled = [t for t in BACKUP_TIMERS if t in timers_evidence]

    if not found:
        evidence = f'{len(states)} unités lues, aucun agent de sauvegarde reconnu'
        if scheduled:
            evidence += ' ; planification détectée : ' + ', '.join(scheduled)
        checks.append({'id': 'backups', 'title': 'Sauvegardes', 'status': 'unknown', 'command': command,
                       'executed': True, 'evidence': evidence})
        findings.append(finding('backups', 'Sauvegardes : aucun agent détecté sur ce serveur', 'Couverture', 'unknown',
                                evidence,
                                guide(command,
                                      '# Confirmer le mode de sauvegarde : agent local, ou sauvegarde au niveau hyperviseur (vzdump / Proxmox Backup Server).',
                                      "Une VM sauvegardée par son hyperviseur n'expose aucun agent : ce contrôle ne peut "
                                      "donc pas conclure seul. Rapprocher de l'inventaire Proxmox.",
                                      configurable=True)))
        return

    # Scheduled one-shot tools normally return to inactive between executions.
    # Their success is measured from job evidence, never from inactive alone.
    oneshot = {'borgmatic.service','restic.service','duplicity.service','rsnapshot.service'}
    inactive = [(label, name, state) for label, name, state in found
                if state != 'active' and not (name in oneshot and state == 'inactive')]
    names = ', '.join(f'{label} ({state})' for label, name, state in sorted(found))
    evidence = names + (' ; planification : ' + ', '.join(scheduled) if scheduled else '')
    if any(name in oneshot and state == 'inactive' for _,name,state in found):
        evidence += ' ; outil ponctuel inactif : résultat des exécutions non déduit de cet état'
    if inactive:
        checks.append({'id': 'backups', 'title': 'Sauvegardes', 'status': 'fail', 'command': command,
                       'executed': True, 'evidence': evidence})
        for label, name, state in inactive:
            severity = 'critical' if state == 'failed' else 'warning'
            findings.append(finding('backup:' + name, f'{label} : {state}', 'Sauvegardes', severity, evidence,
                                    guide(f'systemctl status --no-pager -- {name}; journalctl -u {name} -n 50 --no-pager',
                                          f'sudo systemctl start -- {name}',
                                          'Vérifier la cause avant de relancer : un agent arrêté volontairement pendant une '
                                          'maintenance ne doit pas être redémarré à l’aveugle. ' + BACKUP_PRECAUTION)))
        return

    checks.append({'id': 'backups', 'title': 'Sauvegardes', 'status': 'observed', 'command': command,
                   'executed': True, 'evidence': evidence})


def storage_check(host, cfg, result, checks, findings, runner, requester, connection_lost=False):
    """Relevé détaillé du stockage et des partages, en une seule opération SSH.

    Ne produit de finding que sur ce qui est actionnable : un partage distant
    gelé, un pool ZFS dégradé, un disque SMART en échec. Le reste alimente
    l'onglet « Audit détaillé » sans polluer la liste des problèmes.
    """
    command = ssh.OPERATIONS['storage']
    # La connexion a deja ete perdue pendant cet audit : insister couterait une
    # tentative SSH de plus sur un hote injoignable, pour rien. Meme regle que
    # la boucle PROBES ci-dessous.
    if connection_lost:
        checks.append({'id': 'storage', 'title': 'Stockage détaillé', 'status': 'unknown',
                       'command': command, 'executed': False,
                       'evidence': 'Non exécuté : connexion SSH perdue pendant cet audit'})
        return
    r = runner(host['ip'], 'storage', cfg, requester)
    if not r.ok or not r.stdout.strip():
        checks.append({'id': 'storage', 'title': 'Stockage détaillé', 'status': 'unknown',
                       'command': command, 'executed': True,
                       'evidence': redact(r.stderr) or 'Aucune sortie'})
        return
    import storage_probe
    data = storage_probe.parse(r.stdout)
    result['storage'] = data
    checks.append({'id': 'storage', 'title': 'Stockage détaillé', 'status': 'observed',
                   'command': command, 'executed': True,
                   'evidence': f"{len(data['filesystems'])} systèmes de fichiers, "
                               f"{len(data['remote_shares'])} partage(s) distant(s), "
                               f"{len(data['zfs'])} pool(s) ZFS"})

    # Un partage monté qui ne répond plus : l'application qui écrit dedans est
    # déjà bloquée. C'est la panne la plus coûteuse et la moins visible.
    for partage in data['remote_shares']:
        if partage['status'] == 'stale':
            findings.append(finding('mount:' + partage['mount'],
                                    'Partage distant injoignable : ' + partage['mount'],
                                    'Stockage', 'critical',
                                    f"{partage['source']} ({partage['fstype']}) ne répond pas",
                                    guide(f"timeout 5 stat -f {shlex.quote(partage['mount'])}; findmnt {shlex.quote(partage['mount'])}",
                                          '# Vérifier le serveur distant et le réseau avant tout remontage : '
                                          'un umount -l sur un montage utilisé peut faire perdre des écritures en cours.',
                                          'Un montage gelé bloque tout processus qui y accède. Identifier ces '
                                          'processus (lsof) avant d’intervenir.', configurable=True)))
    for pool in data['zfs']:
        if pool['health'] not in ('ONLINE', None):
            findings.append(finding('zfs:' + pool['pool'], f"Pool ZFS {pool['pool']} : {pool['health']}",
                                    'Stockage', 'critical', f"capacité {pool['capacity_pct']} %",
                                    guide(f"zpool status -v {shlex.quote(pool['pool'])}",
                                          '# Identifier le disque en défaut avant tout remplacement.',
                                          'Un pool dégradé fonctionne encore : ne pas se précipiter, '
                                          'mais ne pas attendre non plus.', configurable=True)))
    for disque in data['smart']:
        if disque['status'] == 'failed':
            findings.append(finding('smart:' + disque['device'], f"SMART en échec : {disque['device']}",
                                    'Matériel', 'critical', disque['detail'],
                                    guide(f"smartctl -a /dev/{disque['device']}",
                                          '# Planifier le remplacement du disque et vérifier les sauvegardes avant.',
                                          'Un verdict SMART en échec annonce une panne, il ne la constate pas '
                                          'toujours : les données sont encore lisibles, agir pendant qu’il est temps.')))


def enrich(host, cfg, result, runner=None, requester='local'):
    runner = runner or ssh.run_operation
    checks=[]; findings=[]
    result.update(checks=checks,findings=findings,audit_version=5)
    if not result.get('ssh_user'):
        # The diagnostic reproduces InfraOps' strict stores and bastion settings.
        # A bare ssh command can succeed using the user's permissive configuration.
        target=shlex.quote(host['ip'])
        command=f'python diagnostic_ssh.py {target}'
        key_error=any(a.get('error_kind')=='host_key' for a in result.get('attempts',[]))
        remedy=f'python register_host_key.py {target}' if key_error else command
        findings.append(finding('ssh','Connexion SSH indisponible','Connexion',result.get('status','unknown'), '\n'.join(result.get('issues',[])),
            guide(command, remedy, 'Comparer toute empreinte à une source de confiance avant enregistrement. Le diagnostic conserve la vérification stricte ; corriger compte, port ou route selon son résultat.', 'Dans le terminal du projet InfraOps, environnement Python activé', True)))
        checks.append({'id':'connection','title':'Connexion SSH','status':'unknown','evidence':'Aucun audit distant disponible','command':command})
        result['coverage']={'measured':0,'total':15}
        return result
    cfg=replace(cfg,user=result['ssh_user'],port=result['ssh_port'],target=host.get('ssh_host',''),key_path=host.get('key_path',cfg.key_path),config_path=host.get('ssh_config',cfg.config_path))
    for key,title,warn,crit in [('cpu','CPU',90,98),('ram','Mémoire',90,97),('disk_max','Disques',80,90)]:
        value=result.get(key)
        command=ssh.OPERATIONS['metrics' if key!='disk_max' else 'df']
        state='unknown' if value is None else 'fail' if value>=warn else 'pass'
        checks.append({'id':key,'title':title,'status':state,'evidence':str(value)+' %' if value is not None else 'Mesure indisponible','command':command})
        if state!='pass':
            fix='# Identifier la cause et préparer une intervention ciblée ; ne pas arrêter un processus sans validation.'
            verify='ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 15' if key=='cpu' else 'free -m; ps -eo pid,comm,%mem --sort=-%mem | head -n 15'
            if key=='disk_max':
                verify='df -hP; df -iP'
                fix='# Étendre le volume identifié ou appliquer une politique de rétention validée ; aucune purge automatique.'
            findings.append(finding(key,title+' : '+('mesure indisponible' if value is None else str(value)+' %'),'Ressources','unknown' if value is None else 'critical' if value>=crit else 'warning',checks[-1]['evidence'],guide(verify,fix,'Échantillon ponctuel. Confirmer la tendance et l’impact avant intervention.',configurable=True)))
    services=result.get('all_services',result.get('service_states',[]))
    failed=[s for s in services if s['status']=='failed' or (s.get('configured') and s['status']!='active')]
    checks.append({'id':'services','title':'Services systemd','status':'fail' if failed else 'pass' if services else 'unknown','evidence':f'{len(services)} unités observées ; {len(failed)} anomalies','command':ssh.OPERATIONS['services']})
    for s in failed:
        unit=s['name'] if s['name'].endswith('.service') else s['name']+'.service'
        if not re.fullmatch(r'[A-Za-z0-9_.@:-]+',unit):continue
        quote=shlex.quote(unit)
        unknown=s['status']=='unknown'
        findings.append(finding('service:'+unit,'Service '+unit+' : '+s['status'],'Services','unknown' if unknown else 'critical',s['status'],guide(
            f'systemctl status --no-pager -- {quote}; journalctl -u {quote} -n 50 --no-pager',
            '# Corriger le nom de l’unité dans hosts.yaml après vérification.' if unknown else f'sudo systemctl start -- {quote}',
            'Commande à exécuter manuellement après correction de la cause. Vérifier dépendances, maintenance et disponibilité ; ne pas lancer une unité intentionnellement arrêtée.',configurable=unknown)))
    connection_lost=False
    for op,(title,cmd) in PROBES.items():
        executed=not connection_lost
        r=runner(host['ip'],op,cfg,requester) if executed else ssh.RunResult(False,None,'','Non exécuté : connexion SSH perdue pendant cet audit',0,'network')
        if r.rc is None and r.error_kind in ('network','auth','host_key','local'):connection_lost=True
        output=redact(r.stdout); error=redact(r.stderr)
        partial=any(x in r.stderr.lower() for x in ['not seeing messages','permission denied','no journal files'])
        status='observed' if r.ok and output.strip() and not partial else 'unknown'
        if op=='cron_user' and 'no crontab for' in r.stderr.lower():
            status='observed'; output='Aucune crontab pour le compte connecté (autres comptes non audités)'
        if op in ('inodes','clock','ssh_policy','permissions') and status=='observed': status='pass'
        evidence=output or error or 'Aucune donnée accessible'
        check={'id':op,'title':title,'status':status,'command':cmd,'evidence':evidence,'error':error,'executed':executed}
        checks.append(check)
        if status=='unknown':
            findings.append(finding(op,title+' : contrôle incomplet','Couverture','unknown',evidence,generic_guide(op)))
            continue
        if op=='inodes':
            filesystems=ssh.parse_df(output)
            if not any(fs['use_pct'] is not None for fs in filesystems):check['status']='unknown'
            for fs in filesystems:
                if fs['use_pct'] is not None and fs['use_pct']>=80:
                    check['status']='fail'
                    findings.append(finding('inode:'+fs['mount'],'Inodes saturés : '+fs['mount'],'Stockage','critical' if fs['use_pct']>=90 else 'warning',f"{fs['use_pct']} %",guide(cmd,'# Identifier les petits fichiers et valider leur rétention avant toute suppression.','Aucune suppression automatique. Une extension dépend du système de fichiers.',configurable=True)))
        elif op=='clock':
            if 'NTPSynchronized=yes' not in output and 'NTPSynchronized=no' not in output:
                check['status']='unknown'
            elif 'NTPSynchronized=no' in output:
                check['status']='fail'
                findings.append(finding('ntp','Horloge non synchronisée','Système','warning',output,guide('timedatectl status','sudo timedatectl set-ntp true','Vérifier le service NTP prévu (chrony, timesyncd…), ses sources et les contraintes des applications.')))
        elif op=='ssh_policy':
            policy=dict(line.split(None,1) for line in output.splitlines() if len(line.split(None,1))==2)
            if not {'permitrootlogin','passwordauthentication'} <= policy.keys(): check['status']='unknown'
            for key in ['permitrootlogin','passwordauthentication']:
                if policy.get(key)=='yes':
                    check['status']='fail'
                    findings.append(finding(key,key+' activé','Sécurité','warning',key+' yes',guide('/usr/sbin/sshd -T', 'sudoedit /etc/ssh/sshd_config\nsudo /usr/sbin/sshd -t','Recommandation à valider selon votre politique. Garder une session de secours ; définir la valeur adaptée, tester les clés et les règles Match avant tout rechargement. Aucun rechargement automatique.',configurable=True)))
        elif op=='permissions':
            seen=set()
            for line in output.splitlines():
                parts=line.split()
                if len(parts)!=3:continue
                mode,owner,path=parts
                try: bits=int(mode,8)
                except ValueError:continue
                seen.add(path)
                unsafe=(owner!='root') or bool(bits & 0o022) or (path=='/etc/shadow' and bool(bits & 0o007))
                if unsafe:
                    check['status']='fail'
                    findings.append(finding('perms:'+path,'Permissions sensibles : '+path,'Sécurité','warning',line,guide(cmd,'# Rétablir propriétaire et permissions selon la distribution et sa politique de groupes.','Ne pas appliquer chmod à l’aveugle : les modes de shadow diffèrent selon la distribution.',configurable=True)))
            if seen!={'/etc/passwd','/etc/shadow'} and check['status']!='fail':check['status']='unknown'
        elif op=='errors' and '-- No entries --' not in output:
            check['status']='fail'
            findings.append(finding('journal','Erreurs dans la dernière heure','Journaux','warning',output,guide(cmd,'# Corriger le composant identifié dans le journal ; aucune commande générique fiable.','Échantillon de 40 lignes maximum, limité aux droits du compte. Les anciens messages ne prouvent pas un incident encore actif.',configurable=True)))
    for check in checks:
        if check['status']=='unknown' and not any(f['id']==check['id'] for f in findings):
            findings.append(finding(check['id'],check['title']+' : contrôle incomplet','Couverture','unknown',check['evidence'],generic_guide(check['id'])))
    storage_check(host, cfg, result, checks, findings, runner, requester, connection_lost)
    backup_check(host, result, checks, findings)
    if not host.get('services'):
        command = ssh.OPERATIONS['services']
        checks.append({'id':'critical_inventory','title':'Services critiques déclarés','status':'unknown','command':command,'executed':False,'evidence':'Liste services vide dans hosts.yaml'})
        findings.append(finding('critical_inventory','Services critiques déclarés : couverture à compléter','Couverture','unknown',checks[-1]['evidence'],guide(command,'# Renseigner la liste des services critiques de ce serveur dans le cockpit.','Une unité active ne prouve pas que le service rend le bon résultat.',configurable=True)))
    result['coverage']={'measured':sum(c['status']!='unknown' for c in checks),'total':len(checks)}
    rank={'critical':0,'warning':1,'unknown':2,'unreachable':0}
    findings.sort(key=lambda f:rank.get(f['severity'],2))
    result['status']='critical' if any(f['severity']=='critical' for f in findings) else 'warning' if any(f['severity']=='warning' for f in findings) else 'unknown' if any(c['status']=='unknown' for c in checks) else 'ok'
    result['issues']=[f['title'] for f in findings]
    result['collected_at']=datetime.now(timezone.utc).isoformat()
    return result
