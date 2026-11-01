// Evidence-first view of the Apache/ModSecurity probe derived from waf_monitor.py.
subtitles['WAF / HA']='Apache, ModSecurity et Fail2ban : mesures, événements et preuves de collecte.';
const wafNames={services:'Services système',bantimes:'Dates des bans Fail2ban',apache_modules:'Module ModSecurity',vhosts:'Virtual hosts Apache',engine:'Déclarations SecRuleEngine',fail2ban:'Jail apache-modsecurity',maxretry:'Seuil de tentatives',findtime:'Fenêtre de détection (s)',bantime:'Durée de ban (s)',tcp:'Connexions TCP',sockets:'Sockets TCP et CLOSE_WAIT',conntrack:'Conntrack utilisé',conntrack_max:'Capacité conntrack',iptables:'Compteurs INPUT',traffic:'Échantillon HTTP',modsecurity:'Alertes ModSecurity'};
const wafValue=v=>v==null?'Non mesuré':esc(v);
// Un état s'accompagne toujours d'un libellé : la couleur seule ne se lit ni en daltonisme ni à l'impression.
const wafUnmeasured=(text='Non mesuré')=>'<span class="badge unknown waf-unmeasured">● '+esc(text)+'</span>';
const wafStaleBadge=(text='MESURES ANCIENNES')=>'<span class="waf-stale-badge">'+esc(text)+'</span>';
// Filtre des IP bannies : web/waf-bans.js (analyse et commandes par IP).
let wafKey=null;
const wafDetails=new Map(),wafRequests=new Map();
function wafHosts(){return state.hosts.filter(h=>h.role==='WAF ModSecurity')}
function currentWafSummary(){
 const hosts=wafHosts();
 if(!hosts.length)return null;
 if(!hosts.some(h=>h.key===wafKey))wafKey=hosts[0].key;
 return hosts.find(h=>h.key===wafKey);
}
function currentWaf(){
 const summary=currentWafSummary();if(!summary)return null;
 const detail=wafDetails.get(summary.key);
 return detail&&detail.collected_at===summary.collected_at?detail:(summary.waf?summary:null);
}
async function loadWafDetail(summary){
 if(!summary||wafRequests.has(summary.key))return;
 const request=api('/api/hosts/'+encodeURIComponent(summary.key)).then(detail=>{
  wafDetails.set(summary.key,detail);
  if(page==='WAF / HA'&&!selected&&wafKey===summary.key)render();
 }).catch(e=>{const target=$('#content .waf-loading');if(target)target.textContent='Détail WAF indisponible : '+e.message}).finally(()=>wafRequests.delete(summary.key));
 wafRequests.set(summary.key,request);
}
function wafSelector(hosts){return '<div class="filters waf-selector-bar"><label>Serveur WAF <select id="waf-host-select">'+hosts.map(h=>'<option value="'+escAttr(h.key)+'" '+(h.key===wafKey?'selected':'')+'>'+esc(h.name)+' · '+esc(h.ip)+'</option>').join('')+'</select></label><span class="note">'+hosts.length+' WAF configuré(s) · preuves en lecture seule</span></div>'}
function wafEmpty(){return '<div class="panel empty">Aucun serveur avec le rôle exact « WAF ModSecurity » n’est configuré.<br>Attribuer ce rôle à un serveur (Serveurs → Modifier) pour activer cette page et sa collecte.</div>'}
// Keepalived inactif sur ce WAF : HA non mise en service, pas une panne (audit UI du 31/10,
// fiche 11.1). Aucune activation n'est proposée ; l'état attendu reste à confirmer.
function wafHaState(x){return x.name==='keepalived'&&x.ActiveState!=='active'?(x.ActiveState||'inconnu')+' · HA non mise en service':x.ActiveState}
function wafTable(headers,rows){return '<div class="table waf-table"><table><thead><tr>'+headers.map(x=>'<th>'+esc(x)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(x=>'<td>'+esc(x??'—')+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>'+(rows.length?'':'<p class="note">Aucune donnée dans la collecte disponible.</p>')}
// Limites de l'échantillon de journaux, à lire avant toute conclusion sur un pourcentage.
const WAF_MIN_SAMPLE=50;
const wafDuration=s=>s<120?s+' s':s<7200?Math.round(s/60)+' min':Math.round(s/3600)+' h';
function wafSampleNote(d){
 const sc=d.scope||{},win=d.window_seconds||[],out=[];
 if(win.length>1)out.push('Fenêtre propre à chaque journal : de '+wafDuration(win[0])+' à '+wafDuration(win[win.length-1])+' sur '+win.length+' fichiers. L’échantillon n’est pas une période continue.');
 if(d.requests!=null&&d.requests<WAF_MIN_SAMPLE)out.push('Échantillon de '+d.requests+' requête(s) : le pourcentage de 5xx n’est pas concluant (minimum '+WAF_MIN_SAMPLE+').');
 if(sc.partial)out.push('Échantillon partiel : '+(sc.unreadable||[]).length+' journal(aux) illisible(s)'+(sc.files_discovered>sc.file_limit?', '+sc.files_discovered+' découverts pour '+sc.file_limit+' lus':'')+'.');
 return out.length?'<p class="instruction">'+(sc.partial?wafUnmeasured('Partiel')+' ':'')+out.map(esc).join('<br>')+'</p>':'';
}
// Adresses locales ou privées : sonde, répartiteur ou proxy local, pas un client à bannir.
const wafIsLocal=ip=>/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|f[cd][0-9a-f]{2}:|fe80:)/i.test(String(ip));
function wafLocalNote(rows){
 const seen=[...new Set(rows.map(r=>r[0]).filter(wafIsLocal))];
 return seen.length?'<p class="instruction"><b>Adresses locales ou privées observées</b> : '+seen.slice(0,6).map(esc).join(', ')+'. Sonde, répartiteur ou proxy : ne pas les bannir. Si elles dominent, l’adresse réelle du client n’est pas journalisée (mod_remoteip).</p>':'';
}
// Sections de sonde qui alimentent chaque panneau : une section absente ou en échec est annoncée en tête
// du panneau, avec sa raison et la marche à suivre, au lieu d'un tableau vide ou de tirets muets.
const WAF_PANEL_SOURCES=[[/^Protection et services/,['services','apache_modules']],[/^Politique Fail2ban/,['fail2ban','maxretry','findtime','bantime']],
 [/^(Distribution HTTP|Chemins les plus demandés|Adresses observées)/,['traffic']],[/^(Règles|Événements) ModSecurity/,['modsecurity']],
 [/^Réseau L3\/L4/,['tcp','conntrack','conntrack_max','iptables']],[/^Certificats SSL/,['certificates']],[/^Liste blanche Fail2ban/,['ignoreip']]];
let wafCurrentSections=null;
function wafSourceState(title){
 const keys=(WAF_PANEL_SOURCES.find(([rule])=>rule.test(title))||[])[1];if(!keys||!wafCurrentSections)return '';
 const bad=keys.filter(k=>wafCurrentSections[k]?.status!=='observed');if(!bad.length)return '';
 return '<div class="instruction waf-source-state">'+bad.map(k=>{const sec=wafCurrentSections[k];return '<p>'+wafUnmeasured(sec?'Non mesuré':'Non collecté')+' '+esc(wafNames[k]||k)+' : '+esc(sec?.error||'section absente de cette collecte (sonde antérieure)')+'</p>'}).join('')+
  '<p>Actualiser le WAF ; si l’échec persiste, vérifier les droits sudo du compte de collecte (docs/SERVICE-ACCOUNT.md). Valeurs ci-dessous non concluantes.</p></div>';
}
function wafPanel(title,body){return '<section class="panel" data-waf-section="'+wafTopicForTitle(title)+'"><h2>'+title+'</h2>'+wafSourceState(title)+body+'</section>'}
function advancedWaf(h){
 const w=h.waf||{},s=w.sections||{},data=k=>s[k]?.data;
 wafCurrentSections=s;
 const jail=data('fail2ban')||{},traffic=data('traffic')||{},mod=data('modsecurity')||{};
 const cov=w.coverage,incomplete=cov&&Number(cov.measured)<Number(cov.total);
 // Mesures anciennes : bandeau en tête plutôt qu'une mention en fin de ligne, pour ne pas lire un état périmé comme actuel.
 let html='<section class="panel"><div class="panel-head"><div><h2>WAF ModSecurity · '+esc(h.ip)+'</h2><p>Apache · Fail2ban · HTTP · Réseau</p></div><button class="primary" data-audit-host="'+escAttr(h.key)+'" '+(state.job.running?'disabled aria-busy="true"':'')+'>'+(state.job.running?'<span class="waf-spinner" aria-hidden="true"></span>Collecte en cours…':'Actualiser le WAF')+'</button></div>'+(h.stale?'<p class="waf-stale-banner" role="status">'+wafStaleBadge()+'<span>La dernière collecte ne reflète pas forcément l’état actuel : actualiser le WAF avant toute conclusion.</span></p>':'')+'<p>'+esc(h.name)+' · '+esc(h.ip)+' · collecte : '+esc(stamp(w.collected_at))+'</p><p>Contrôles renseignés : '+(cov?esc(cov.measured)+' / '+esc(cov.total):'aucun')+' · '+wafValue(w.duration_ms)+' ms'+(!cov?' '+wafUnmeasured():incomplete?' <span class="badge warning">● Audit incomplet</span>':'')+'</p><div class="filters"><button data-edit-server="'+escAttr(h.key)+'">Services critiques</button><button data-host="'+escAttr(h.key)+'">Audit système et SSH</button><button data-export-waf>Exporter les preuves JSON</button></div>'+(w.error?'<p role="alert"><span class="badge critical">● Erreur de collecte</span> '+esc(w.error)+'</p>':'')+'<p class="note">Collecte en lecture seule via SSH. L’actualisation automatique du cockpit inclut ce WAF. Les règles CRS, le certificat réellement présenté en HTTPS, la VIP et le mode effectif par vhost restent à vérifier.</p></section>';
 html+='<div class="stats waf-stats">'+[['IPs bannies',jail.currently_banned,'Liste Fail2ban au moment de la collecte'],['Échecs Fail2ban cumulés',jail.total_failed,'Depuis le dernier démarrage de Fail2ban'],['Requêtes échantillonnées',traffic.requests,'Dernières lignes de chaque journal, pas un débit'],['Réponses 5xx (%)',traffic.errors_5xx_pct,traffic.requests!=null&&traffic.requests<WAF_MIN_SAMPLE?'Échantillon trop faible : non concluant':'Part de l’échantillon'],['Lignes d’alerte ModSecurity',mod.alert_lines,'Lignes de journal, pas des requêtes'],['Score anomalie max',mod.anomaly_max,'Dans les lignes lues']].map(([k,v,n])=>'<div class="card"><small>'+esc(k)+'</small><strong>'+wafValue(v)+'</strong><small class="waf-kpi-note">'+esc(n)+'</small></div>').join('')+'</div>';
 // Recommandations regroupées dans un seul panneau, distinct des constats (faits observés).
 if((w.recommendations||[]).length)html+=wafPanel('Recommandations',w.recommendations.map(t=>'<p class="instruction"><b>Recommandation · </b>'+esc(t)+'</p>').join(''));
 html+='<div class="waf-columns">'+wafPanel('Protection et services',wafTable(['Service','Chargement','État','Sous-état'],(data('services')||[]).map(x=>[x.name,x.LoadState,wafHaState(x),x.SubState]))+((data('services')||[]).some(x=>x.name==='keepalived')?'<p class="note">Keepalived n’est pas un service surveillé du WAF : son arrêt ne déclenche aucune alerte. La VIP et le rôle MASTER/BACKUP ne sont pas mesurés.</p>':'')+'<p>Module ModSecurity chargé : '+(data('apache_modules')?.security_module_loaded===true?'Oui':data('apache_modules')?.security_module_loaded===false?'Non':'Inconnu')+'</p>')+
 wafPanel('Politique Fail2ban',wafTable(['Contrôle','Valeur'],[['Maxretry',data('maxretry')],['Findtime (secondes)',data('findtime')],['Bantime (secondes)',data('bantime')],['Échecs actuels',jail.currently_failed],['Bans cumulés',jail.total_banned]])+'<p class="note">Valeurs lues sur apache-modsecurity. Les compteurs cumulés peuvent être remis à zéro au redémarrage.</p>')+'</div>';
 html+='<div class="waf-columns">'+wafPanel('Distribution HTTP',wafTable(['Code','Occurrences'],Object.entries(traffic.http_codes||{}))+'<p class="note">Échantillon : '+esc(traffic.first_event||'date inconnue')+' → '+esc(traffic.last_event||'date inconnue')+'. '+wafValue(traffic.unparsed_lines)+' lignes non reconnues. Aucun débit extrapolé.</p>'+wafSampleNote(traffic))+wafPanel('Règles ModSecurity',wafTable(['ID de règle','Lignes'],mod.rules||[])+'<p class="note">'+esc(mod.note||'Collecte requise')+'</p>'+wafSampleNote(mod))+'</div>';
 html+='<div class="waf-columns">'+wafPanel('Chemins les plus demandés',wafTable(['Chemin sans paramètres','Occurrences'],traffic.top_urls||[]))+wafPanel('Adresses observées dans les accès',wafTable(['IP','Occurrences'],traffic.top_ips||[])+'<p class="note">Une IP fréquente n’est pas nécessairement hostile. La configuration du proxy peut affecter l’adresse journalisée.</p>'+wafLocalNote([...(traffic.top_ips||[]),...(mod.clients||[])]))+'</div>';
 html+=wafBanMarkup(h.key);  // IP bannies analysées : waf-bans.js
 html+=wafPanel('Événements ModSecurity — 60 lignes reconnues, ordre de lecture',wafTable(['Horodatage du journal','Fichier','IP','Règles','Action rapportée','Score'],(mod.events||[]).map(e=>[e.timestamp_raw,e.source,e.client,e.rules.join(', '),e.action,e.score])));
 html+=wafPanel('Réseau L3/L4',wafTable(['Mesure','Valeur'],[['Conntrack',data('conntrack')],['Limite conntrack',data('conntrack_max')],['Paquets DROP/REJECT INPUT',data('iptables')?.packets]])+'<pre>'+esc(data('tcp')?.summary||'Non mesuré')+'</pre><p class="note">'+esc(data('iptables')?.scope||'Compteurs inconnus')+'</p><p class="note">Conntrack : connexions suivies par le pare-feu du noyau. Quand le nombre atteint la limite, le noyau rejette les nouvelles connexions (« nf_conntrack: table full » dans dmesg).</p>');
 html+=wafSockets(s.sockets,h);
 // Sondes attendues absentes de la collecte : listées plutôt qu'omises (une absence n'est pas un bon état).
 const missing=Object.keys(wafNames).filter(k=>!s[k]);
 html+=wafPanel('Déclarations et couverture',(Object.entries(s).map(([k,v])=>'<details><summary>'+badge(v.status)+' '+esc(wafNames[k]||k)+'</summary><pre>'+esc(JSON.stringify(v,null,2))+'</pre></details>').join('')||'<p>Aucune preuve collectée.</p>')+(missing.length?'<p class="waf-missing">'+wafUnmeasured('Non collecté')+' '+missing.map(k=>esc(wafNames[k])).join(' · ')+'</p>':''));
 html+=wafPanel('Historique des collectes', '<p class="note">Échantillons successifs susceptibles de se recouvrir ; ne pas sommer les requêtes ou alertes.</p><div id="waf-history">Chargement…</div>');
 return html;
}
// Analyse CLOSE_WAIT. CLOSE_WAIT = le pair a envoyé FIN, le noyau l'a acquitté, mais le
// processus local n'a pas encore fermé sa socket. Le noyau ne l'expire jamais seul : seule
// l'application peut la libérer. D'où la distinction entrant / sortant / processus.
const WAF_STATES=[['ESTAB','Établies'],['CLOSE-WAIT','CLOSE_WAIT'],['TIME-WAIT','TIME_WAIT'],['FIN-WAIT-1','FIN_WAIT_1'],['FIN-WAIT-2','FIN_WAIT_2'],['LAST-ACK','LAST_ACK'],['SYN-RECV','SYN_RECV'],['SYN-SENT','SYN_SENT'],['CLOSING','CLOSING'],['LISTEN','En écoute']];
function wafCloseWaitReading(c){
 const out=[],total=c.close_wait_total||0;
 if(!total)return ['Aucune socket en CLOSE_WAIT au moment de la collecte. Un instantané à zéro n’exclut pas des pics entre deux collectes.'];
 const outbound=c.close_wait_outbound||0,inbound=c.close_wait_inbound||0,top=(c.by_upstream||[])[0],port=(c.by_local_port||[])[0],proc=(c.by_process||[])[0];
 if(outbound>=inbound&&top)out.push('Majorité sortante ('+outbound+' / '+total+') : ce serveur est client, typiquement Apache mod_proxy vers un backend. La destination '+top[0]+' a fermé '+top[1]+' connexion(s) que le processus local n’a pas refermées : vérifier la réutilisation des connexions du proxy (keepalive, disablereuse, ttl) et que le timeout du backend est plus long que celui du proxy.');
 if(inbound>outbound&&port)out.push('Majorité entrante ('+inbound+' / '+total+') : des clients ont fermé leur connexion sur le port '+port[0]+' et Apache ne l’a pas encore refermée. À corréler avec BusyWorkers (bloc Apache Health) et les requêtes lentes avant toute conclusion sur l’état des workers.');
 if(c.fin_unread)out.push(c.fin_unread+' / '+total+' socket(s) n’ont en attente que le FIN du pair (Recv-Q = 1) : le processus ne lit plus ces connexions depuis que le pair les a fermées. Profil typique d’un pool de connexions inactives (mod_proxy) conservé plus longtemps que le délai d’inactivité du backend.');
 if(c.recv_q_nonzero)out.push(c.recv_q_nonzero+' socket(s) gardent de vraies données non lues (Recv-Q > 1, '+ui.bytes(c.recv_q_bytes)+') : le processus a cessé de lire en cours d’échange : à corréler avec BusyWorkers et les requêtes lentes.');
 const pid=(c.by_pid||[])[0];
 if(proc)out.push('Processus concerné : '+proc[0]+' ('+proc[1]+' sockets)'+(pid?', dont '+pid[1]+' tenues par '+pid[0].replace(':',' PID ')+(c.by_pid.length>1?' sur '+c.by_pid.length+' PID':'')+'.':'.'));
 else if(c.process_visible===false)out.push('Processus non visibles : sudo -n ss -p est refusé au compte de collecte. Le décompte ne suffit pas à désigner le processus en cause.');
 if(c.apache_processes!=null)out.push(c.apache_processes+' processus apache2 au moment de la collecte.');
 out.push('Le noyau n’expire pas le CLOSE_WAIT : il ne disparaît qu’à la fermeture par le processus (ou son redémarrage). Une valeur qui croît d’une collecte à l’autre indique une fuite ; une valeur faible et stable est souvent normale.');
 return out;
}
function wafCloseWaitTrend(history){
 const points=history.filter(x=>x.waf&&Number.isFinite(x.waf.close_wait)).map(x=>({ts:x.ts,v:x.waf.close_wait})).reverse();
 if(points.length<2)return '<p class="note">Tendance CLOSE_WAIT : au moins deux collectes mesurées sont nécessaires ('+points.length+' disponible). Aucune tendance n’est extrapolée.</p>';
 const first=points[0],last=points[points.length-1],delta=last.v-first.v;
 const rising=delta>0&&points.every((p,i)=>!i||p.v>=points[i-1].v);
 return '<p class="note">Tendance CLOSE_WAIT sur '+points.length+' collectes ('+esc(stamp(first.ts))+' → '+esc(stamp(last.ts))+') : '+first.v+' → '+last.v+' ('+(delta>0?'+':'')+delta+'). '+(rising?'Croissance continue : accumulation probable.':'Pas de croissance continue.')+'</p>';
}
function wafSockets(section,h){
 const title='Connexions TCP · analyse CLOSE_WAIT';
 if(!section)return wafPanel(title,'<p class="note">'+wafUnmeasured()+' Section non collectée par l’ancienne version de la sonde : cliquer « Actualiser le WAF » pour une nouvelle mesure.</p>');
 if(section.status!=='observed')return wafPanel(title,'<p class="instruction">'+wafUnmeasured()+' Mesure indisponible : '+esc(section.error||'erreur inconnue')+'. Actualiser le WAF ; si l’échec persiste, vérifier les droits du compte de collecte sur ss (docs/SERVICE-ACCOUNT.md).</p>');
 const c=section.data||{},st=c.states||{},stale=!!h.stale,total=c.close_wait_total;
 // Même échelle que la santé Apache (apache_health.CLOSE_WAIT_THRESHOLDS, calibrée sur l'historique).
 const [cwLow,cwMid,cwHigh]=h.waf?.apache_health?.close_wait?.thresholds||[200,300,1000];
 const tone=total>cwHigh?'critical':total>cwLow?'warning':'';
 const level=total==null?'Non mesuré':total>cwHigh?'Critique':total>cwMid?'Risque':total>cwLow?'Vigilance':'Dans les seuils';
 const kpis='<div class="v2-kpis waf-cw-kpis">'+ui.kpi('CLOSE_WAIT',total,(stale?'Mesure ancienne · '+level.toLowerCase()+' à la collecte':level)+' · seuils '+cwLow+' / '+cwMid+' / '+cwHigh,stale?'unknown':tone)+
  ui.kpi('Sortantes',c.close_wait_outbound,'Ce serveur est client (proxy, backend)')+ui.kpi('Entrantes',c.close_wait_inbound,'Sur un port en écoute')+
  ui.kpi('FIN non lu (inactives)',c.fin_unread??'Non mesuré','Recv-Q = 1 : le processus n’a plus lu la connexion')+ui.kpi('Données non lues',c.recv_q_nonzero,'Recv-Q > 1 · '+ui.bytes(c.recv_q_bytes),c.recv_q_nonzero?'warning':'')+
  ui.kpi('Établies',st['ESTAB']??0,'Sur '+(c.total??'—')+' sockets TCP')+ui.kpi('TIME_WAIT',st['TIME-WAIT']??0,'Fermées par ce serveur : normal')+'</div>';
 const known=WAF_STATES.filter(([k])=>st[k]!=null).map(([k,v])=>[v,st[k]]);
 const other=Object.entries(st).filter(([k])=>!WAF_STATES.some(([x])=>x===k));
 const reading=(c.truncated?'<p class="instruction">'+wafUnmeasured('Partiel')+' Sortie ss tronquée à '+esc(c.lines_limit)+' lignes : les décomptes sont des minimums.</p>':'')+'<div class="instruction"><b>Lecture de la mesure</b>'+wafCloseWaitReading(c).map(x=>'<p>'+esc(x)+'</p>').join('')+'</div>';
 const groups='<div class="waf-columns">'+wafPanel('Sortants · par destination',wafTable(['Destination IP:port','Sockets'],c.by_upstream||[])+'<p class="note">Backends ou services appelés par ce serveur, qui ont fermé la connexion.</p>')+
  wafPanel('Entrants · par port local',wafTable(['Port en écoute','Sockets'],c.by_local_port||[]))+'</div>'+
  '<div class="waf-columns">'+wafPanel('Par processus',c.process_visible?wafTable(['Processus','Sockets'],c.by_process||[])+wafTable(['Processus:PID','Sockets'],c.by_pid||[]):'<p class="note">Processus non visibles : le compte de collecte n’a pas le droit « sudo -n ss ». L’autoriser en lecture permet d’identifier le processus.</p>')+
  wafPanel('Entrants · par client',wafTable(['IP client','Sockets'],c.by_client||[])+'<p class="note">Adresse vue par ce serveur ; derrière un répartiteur, c’est celle du répartiteur.</p>')+'</div>';
 const samples=wafTable(['Sens','Port local','Pair','Port pair','Recv-Q','Send-Q','Processus (PID)'],(c.samples||[]).map(x=>[x.direction==='inbound'?'Entrant':'Sortant',x.local_port,x.peer,x.peer_port,x.recv_q,x.send_q,x.process?x.process+' ('+x.pid+')':'Non visible']));
 const commands='<div class="commands">'+command('Lister avec processus','sudo ss -tanp state close-wait')+
  command('Compter par destination',"ss -Htan state close-wait | awk '{print $4}' | sort | uniq -c | sort -rn | head")+
  command('Suivre l’évolution','watch -n 5 "ss -Htan state close-wait | wc -l"')+
  command('Configuration proxy Apache','sudo grep -RniE "ProxyPass|ProxyTimeout|KeepAlive|disablereuse|ttl=" /etc/apache2/')+'</div><p class="mini">Copie uniquement · aucune commande exécutée par la plateforme.</p>';
 return '<section class="panel waf-cw"><div class="panel-head"><div><h2>'+title+'</h2><p>'+esc(h.name)+' · '+stamp(h.waf?.collected_at)+(stale?' '+wafStaleBadge('MESURE ANCIENNE'):'')+'</p></div></div>'+kpis+reading+
  '<div class="waf-columns">'+wafPanel('Répartition des états TCP',wafTable(['État TCP','Sockets'],known.concat(other)))+wafPanel('Ports en écoute',wafTable(['Port'],(c.listening_ports||[]).map(p=>[p])))+'</div>'+groups+
  wafPanel('Échantillon CLOSE_WAIT — 40 sockets, Recv-Q décroissant',samples)+commands+'<p class="note">'+esc(c.scope||'')+'</p></section>';
}
// Page WAF en onglets : 25 sections (16 000 px) réparties par thème ; l'en-tête du WAF (serveur,
// collecte, audit) et le sélecteur restent visibles. Une section non reconnue reste dans la
// Synthèse : rien ne peut disparaître. Le contenu complet est toujours construit (preuves,
// filtres et dialogues inchangés) ; seul l'onglet actif est affiché.
const WAF_TABS=[['summary','Vue d’ensemble','État, compteurs et constats à examiner'],['apache','Apache et backends','Charge, latences et saturation'],['traffic','Trafic et ModSecurity','HTTP, règles et événements observés'],['actions','IP et Fail2ban','Bans, liste blanche et commandes à copier'],['tls','Certificats TLS','Certificats déclarés et dates d’expiration'],['network','Réseau et TCP','Sockets, CLOSE_WAIT et conntrack'],['evidence','Preuves et historique','Couverture des sondes et observations conservées']];
const WAF_TAB_RULES=[
 ['evidence',/^(Déclarations et couverture|Historique des collectes|Apache Incident History)/],
 ['apache',/^(Apache Health|Backend CLOSE_WAIT|Backend Proxy Health|Requêtes lentes|URL les plus lentes|Top IP|Concurrence estimée)/],
 ['traffic',/^(Bot \/ WAF Activity|Distribution HTTP|Chemins les plus demandés|Adresses observées|Événements ModSecurity|Règles ModSecurity)/],
 ['network',/^(Réseau L3\/L4|Connexions TCP)/],
 ['actions',/^(Actions IP|IP bannies|Liste blanche Fail2ban|Politique Fail2ban)/],
 ['tls',/^Certificats SSL/]];
// Ordre des blocs dans chaque onglet : sélecteur CSS (bloc sans titre) ou motif du titre h2.
// Vue d'ensemble : compteurs, santé Apache, constats, recommandations puis état des services.
const WAF_TAB_ORDER={
 summary:['.waf-stats','.apx-cards,.apx-cards-missing','.apx-message',/^Constats WAF/,/^Recommandations/,/^Protection et services/],
 apache:[/^Apache Health/,/^Requêtes lentes/,/^Concurrence estimée/,/^Backend Proxy Health/,/^Backend CLOSE_WAIT/,/^Top IP/,/^URL les plus lentes/],
 traffic:[/^Distribution HTTP/,/^Règles ModSecurity/,/^Événements ModSecurity/,/^Bot \/ WAF Activity/,/^Chemins les plus demandés/,/^Adresses observées/],
 actions:[/^IP bannies/,/^Politique Fail2ban/,/^Liste blanche Fail2ban/],
 network:[/^Connexions TCP/,/^Réseau L3\/L4/],
 evidence:[/^Déclarations et couverture/,/^Historique des collectes/,/^Apache Incident History/]};
function wafBlockRank(el){
 const order=WAF_TAB_ORDER[el.dataset.wafTab]||[],title=(el.querySelector('h2')?.textContent||'').trim();
 const at=order.findIndex(m=>typeof m==='string'?el.matches(m):m.test(title));
 return at<0?order.length:at;
}
let wafTab='summary';
function wafTopicForTitle(title){for(const [tab,rule] of WAF_TAB_RULES)if(rule.test(title))return tab;return 'summary'}
function wafSectionTab(el){
 if(el.dataset.wafSection)return el.dataset.wafSection;
 const title=(el.querySelector('h2')?.textContent||'').trim();
 return wafTopicForTitle(title);
}
function wafOrganizeTabs(){
 const content=$('#content');
 const header=content.querySelector(':scope > section.panel');
 if(!header||header.classList.contains('waf-loading'))return;
 header.classList.add('waf-hero');
 // Les anciennes colonnes pouvaient réunir deux thèmes différents. Déplacer les
 // panneaux entiers conserve leurs preuves, filtres et gestionnaires d'événements.
 content.querySelectorAll(':scope > .waf-columns').forEach(row=>row.replaceWith(...row.children));
 const blocks=[...content.children].filter(el=>el!==header&&!el.matches('.filters,.page-guide,.waf-tabs'));
 const counts={};
 for(const el of blocks){const tab=wafSectionTab(el);el.dataset.wafTab=tab;counts[tab]=(counts[tab]||0)+1}
 // Ordre de lecture par onglet : état puis détail. Tri stable, les blocs non listés gardent leur ordre en fin.
 blocks.sort((a,b)=>wafBlockRank(a)-wafBlockRank(b));
 if(!WAF_TABS.some(([k])=>k===wafTab))wafTab='summary';
 const shell=document.createElement('div');shell.className='waf-workspace';
 shell.innerHTML='<nav class="waf-topic-nav" role="tablist" aria-orientation="vertical" aria-label="Thèmes de l’analyse WAF">'+WAF_TABS.map(([k,label,description])=>
  '<button type="button" role="tab" id="waf-tab-'+k+'" aria-controls="waf-panel-'+k+'" aria-selected="'+(wafTab===k)+'" tabindex="'+(wafTab===k?0:-1)+'" data-waf-tab-button="'+k+'"><span>'+esc(label)+'</span><small>'+esc(description)+'</small><span class="waf-panel-count">'+(counts[k]||0)+' panneau(x)</span></button>').join('')+'</nav><div class="waf-topic-panels"></div>';
 header.after(shell);
 const panels=shell.querySelector('.waf-topic-panels');
 for(const [key,label,description] of WAF_TABS){
  const panel=document.createElement('section');panel.id='waf-panel-'+key;panel.dataset.wafPanel=key;
  panel.setAttribute('role','tabpanel');panel.setAttribute('aria-labelledby','waf-tab-'+key);panel.tabIndex=0;
  panel.innerHTML='<div class="waf-topic-heading"><h2>'+esc(label)+'</h2><p>'+esc(description)+'</p></div><div class="waf-topic-body"></div>';
  const body=panel.querySelector('.waf-topic-body');
  blocks.filter(el=>el.dataset.wafTab===key).forEach(el=>body.append(el));
  if(!body.children.length)body.innerHTML='<div class="panel console-empty">'+wafUnmeasured()+'<strong>Aucune preuve disponible pour ce thème</strong><p>Une section non collectée ne permet pas de conclure au bon état du WAF.</p></div>';
  panels.append(panel);
 }
 const translations={'Apache Health':'Santé Apache','Backend CLOSE_WAIT':'CLOSE_WAIT des backends','Backend Proxy Health':'Santé des backends proxy','Bot / WAF Activity':'Robots et activité WAF','Apache Incident History':'Historique des incidents Apache'};
 // Traduction par préfixe : « Bot / WAF Activity · 10 dernières minutes » garde sa précision de fenêtre.
 shell.querySelectorAll('.waf-topic-body h2').forEach(el=>{const t=el.textContent.trim(),k=Object.keys(translations).find(x=>t===x||t.startsWith(x+' '));if(k)el.textContent=translations[k]+t.slice(k.length)});
 wafShowTab();
}
// Tableau qui défile : atteignable au clavier et nommé (WCAG « scrollable-region-focusable »). Mesuré
// à l'affichage de l'onglet, seul moment où les dimensions sont connues.
function wafFocusableScroll(root){root.querySelectorAll('.waf-table').forEach(box=>{if(box.scrollHeight>box.clientHeight+1||box.scrollWidth>box.clientWidth+1){box.tabIndex=0;box.setAttribute('role','region');box.setAttribute('aria-label',(box.closest('section.panel')?.querySelector('h2')?.textContent||'Tableau').trim()+' · tableau défilant')}})}
function wafShowTab(){
 const content=$('#content');
 content.querySelectorAll('[data-waf-panel]').forEach(el=>{el.hidden=el.dataset.wafPanel!==wafTab});
 const shown=content.querySelector('[data-waf-panel]:not([hidden])');if(shown)wafFocusableScroll(shown);
 content.querySelectorAll('[data-waf-tab-button]').forEach(b=>{const on=b.dataset.wafTabButton===wafTab;b.classList.toggle('active',on);b.setAttribute('aria-selected',String(on));b.tabIndex=on?0:-1});
 if(wafTab==='evidence'&&typeof apxLoadHistory==='function')apxLoadHistory();
}
$('#content').addEventListener('click',e=>{
 const b=e.target.closest('[data-waf-tab-button]');if(!b)return;
 wafTab=b.dataset.wafTabButton;wafShowTab();b.focus({preventScroll:true});
});
$('#content').addEventListener('keydown',e=>{
 const b=e.target.closest('[data-waf-tab-button]');if(!b||!['ArrowRight','ArrowLeft','ArrowDown','ArrowUp','Home','End'].includes(e.key))return;
 const tabs=[...$('#content').querySelectorAll('[data-waf-tab-button]')],at=tabs.indexOf(b);
 const next=e.key==='Home'?0:e.key==='End'?tabs.length-1:(at+(['ArrowRight','ArrowDown'].includes(e.key)?1:-1)+tabs.length)%tabs.length;
 e.preventDefault();wafTab=tabs[next].dataset.wafTabButton;wafShowTab();tabs[next].focus({preventScroll:true});
});
// Tableaux : tri des colonnes numériques, filtre texte et « charger plus » par 50 lignes, appliqués
// dans le navigateur aux lignes déjà rendues (aucune requête). L'état de chaque tableau survit au
// rendu suivant (rafraîchissement temps réel) pour ne pas effacer une saisie en cours. Le tableau
// des IP bannies garde ses propres filtre et pagination (waf-bans.js) : il ne reçoit que les libellés.
const WAF_TABLE_PAGE=50,WAF_FILTER_MIN=8,wafTableState=new Map();
function wafCellNumber(text){const t=text.replace(/[\s  ]/g,'').replace(/(%|ms|s)$/,'').replace(',','.');return /^-?\d+(\.\d+)?$/.test(t)?Number(t):null}
function wafTableKey(table){const panel=table.closest('section.panel');return wafKey+'|'+(panel?.querySelector('h2')?.textContent||'').trim()+'#'+[...(panel||document).querySelectorAll('.waf-table table')].indexOf(table)}
function wafEnhanceTables(root){
 root.querySelectorAll('.waf-table table').forEach(table=>{
  const heads=[...(table.tHead?.rows[0]?.cells||[])],body=table.tBodies[0];
  if(!heads.length||!body||table.dataset.wafEnhanced)return;
  table.dataset.wafEnhanced='1';
  const rows=[...body.rows];
  // Libellé de colonne répété dans chaque cellule : lecture en cartes sous 768 px (CSS).
  rows.forEach(r=>[...r.cells].forEach((td,i)=>{if(heads[i])td.dataset.label=heads[i].textContent.trim()}));
  if(table.closest('#waf-ban-analysis'))return;
  const key=wafTableKey(table);table.dataset.wafKey=key;table.wafRows=rows;
  heads.forEach((th,i)=>{
   const values=rows.map(r=>(r.cells[i]?.textContent||'').trim()).filter(t=>t&&!['—','N/A','Non mesuré','Non visible'].includes(t));
   if(values.length<2||!values.every(t=>wafCellNumber(t)!=null))return;
   th.setAttribute('aria-sort','none');
   th.innerHTML='<button type="button" class="waf-sort" data-waf-sort="'+i+'" title="Trier cette colonne">'+esc(th.textContent)+'<span aria-hidden="true"> ↕</span></button>';
  });
  const box=table.closest('.waf-table');
  if(rows.length>=WAF_FILTER_MIN)box.insertAdjacentHTML('beforebegin','<div class="waf-table-tools"><label>Filtrer <input type="search" maxlength="80" data-waf-filter="'+escAttr(key)+'" placeholder="IP, chemin, règle…"></label><span class="mini" data-waf-count></span></div>');
  if(rows.length>WAF_TABLE_PAGE)box.insertAdjacentHTML('afterend','<div class="waf-table-more"><button type="button" data-waf-more>Afficher '+WAF_TABLE_PAGE+' lignes de plus</button></div>');
  const saved=wafTableState.get(key);if(saved?.q){const input=box.previousElementSibling?.querySelector('[data-waf-filter]');if(input)input.value=saved.q}
  wafApplyTable(table);
 });
}
function wafApplyTable(table){
 const key=table.dataset.wafKey,st=wafTableState.get(key)||{q:'',col:null,dir:'desc',limit:WAF_TABLE_PAGE},box=table.closest('.waf-table');
 wafTableState.set(key,st);
 let rows=[...table.wafRows];
 if(st.col!=null){
  const val=r=>wafCellNumber((r.cells[st.col]?.textContent||'').trim());
  // Valeurs non mesurées toujours en fin de liste, quel que soit le sens du tri.
  rows.sort((a,b)=>{const x=val(a),y=val(b);if(x==null||y==null)return (x==null)-(y==null);return st.dir==='asc'?x-y:y-x});
 }
 const q=st.q.toLowerCase();let shown=0,matched=0;
 for(const r of rows){const match=!q||r.textContent.toLowerCase().includes(q);if(match)matched++;r.hidden=!match||matched>st.limit;if(!r.hidden)shown++;table.tBodies[0].append(r)}
 table.querySelectorAll('th[aria-sort]').forEach(th=>{const i=[...th.parentNode.cells].indexOf(th);th.setAttribute('aria-sort',i===st.col?(st.dir==='asc'?'ascending':'descending'):'none')});
 const count=box.previousElementSibling?.querySelector('[data-waf-count]');
 if(count)count.textContent=shown+' ligne(s) affichée(s) sur '+matched+(q?' correspondante(s) · '+table.wafRows.length+' au total':'');
 const more=box.nextElementSibling?.matches('.waf-table-more')?box.nextElementSibling:null;
 if(more)more.hidden=matched<=st.limit;
}
$('#content').addEventListener('click',e=>{
 const sort=e.target.closest('[data-waf-sort]'),more=e.target.closest('[data-waf-more]');
 if(sort){const table=sort.closest('table'),st=wafTableState.get(table.dataset.wafKey),col=Number(sort.dataset.wafSort);st.dir=st.col===col&&st.dir==='desc'?'asc':'desc';st.col=col;wafApplyTable(table);return}
 if(more){const table=more.closest('.waf-table-more').previousElementSibling.querySelector('table');wafTableState.get(table.dataset.wafKey).limit+=WAF_TABLE_PAGE;wafApplyTable(table)}
});
$('#content').addEventListener('input',e=>{
 const input=e.target.closest('[data-waf-filter]');if(!input)return;
 const table=input.closest('.waf-table-tools').nextElementSibling.querySelector('table'),st=wafTableState.get(table.dataset.wafKey);
 st.q=input.value.trim();st.limit=WAF_TABLE_PAGE;wafApplyTable(table);
});
// Collecte ancienne : chaque pastille d'état Apache est grisée et préfixée « Ancien » ; un OK d'hier ne vaut
// pas un OK actuel. L'historique (#apx-history), daté ligne à ligne, est chargé plus tard et n'est pas concerné.
function wafMarkStale(root){
 root.querySelectorAll('.apx-pill').forEach(p=>{p.className=p.className.replace(/\blvl-\S+/,'lvl-unknown');p.textContent='Ancien · '+p.textContent});
 root.querySelectorAll('.apx-card,.apx-message').forEach(c=>{c.className=c.className.replace(/\blvl-\S+/,'lvl-unknown')});
}
pageRenderers['WAF / HA']=function(){
 const hosts=wafHosts();
 const summary=currentWafSummary();
 if(!summary){$('#content').innerHTML=wafEmpty();return}
 const h=currentWaf();
 if(!h){$('#content').innerHTML=wafSelector(hosts)+'<section class="panel waf-loading" role="status" aria-busy="true"><span class="waf-spinner" aria-hidden="true"></span>Chargement des preuves WAF…</section>';loadWafDetail(summary);return}
 const focused=document.activeElement?.dataset?.wafFilter;
 $('#content').innerHTML=wafSelector(hosts)+advancedWaf(h);
 wafOrganizeTabs();
 const target=$('#waf-history');
 if(target)target.innerHTML=wafTable(['Collecte','IPs bannies','Requêtes (échantillon)','5xx (%)','Alertes (lignes)','CLOSE_WAIT','dont sortantes','ESTAB'],(h.history||[]).filter(x=>x.waf).map(x=>[stamp(x.ts),x.waf.banned,x.waf.requests,x.waf.errors_5xx_pct,x.waf.alerts,x.waf.close_wait??'Non mesuré',x.waf.close_wait_outbound??'—',x.waf.established??'—']))+wafCloseWaitTrend(h.history||[]);
 wafEnhanceTables($('#content'));
 if(h.stale)wafMarkStale($('#content'));
 const shown=$('#content [data-waf-panel]:not([hidden])');if(shown)wafFocusableScroll(shown);
 if(focused){const input=[...$('#content').querySelectorAll('[data-waf-filter]')].find(x=>x.dataset.wafFilter===focused);if(input){input.focus({preventScroll:true});input.setSelectionRange(input.value.length,input.value.length)}}
};
$('#content').addEventListener('change',e=>{
 if(e.target.id!=='waf-host-select')return;
 wafKey=e.target.value;render();
});
$('#content').addEventListener('click',e=>{
 if(!e.target.closest('[data-export-waf]'))return;
 const h=currentWaf();if(!h)return;
 const url=URL.createObjectURL(new Blob([JSON.stringify({server:h.name,ip:h.ip,stale:h.stale,...h.waf},null,2)],{type:'application/json'}));
 const link=document.createElement('a');link.href=url;link.download='waf-audit-'+h.key+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
