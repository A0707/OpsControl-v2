// WAF · Apache santé & saturation (sonde apache_probe.py, évaluation apache_health.py).
// Affichage uniquement : aucune commande n'est exécutée depuis l'interface ; les
// commandes proposées sont à copier. Toute valeur absente s'affiche « N/A ».
const APX_LEVEL_LABEL={ok:'OK',yellow:'Vigilance',orange:'Risque',red:'Critique',critical:'APACHE SATURATION',unknown:'N/A',info:'Information'};
// Seuils CLOSE_WAIT calculés côté serveur (apache_health.CLOSE_WAIT_THRESHOLDS) ; repli pour une ancienne collecte.
const apxCwThresholds=health=>health?.close_wait?.thresholds||[200,300,1000];
const APX_BACKEND_TONE={'HTTP RESPONDING':'ok','HTTP SLOW':'orange','HTTP STATUS ERROR':'red','TCP DOWN':'red','NETWORK DOWN':'red'};
let apxHistoryHours=24;
const apxNa=v=>v==null||v===''?'N/A':v;
const apxNum=(v,d=1)=>v==null||!Number.isFinite(Number(v))?'N/A':Number(v).toLocaleString('fr-FR',{maximumFractionDigits:d});
const apxSec=v=>v==null?'N/A':apxNum(v,2)+' s';
const apxMs=v=>v==null?'N/A':apxNum(v,0)+' ms';
function apxPill(level,text){return '<span class="apx-pill lvl-'+esc(level||'unknown')+'">'+esc(text||APX_LEVEL_LABEL[level]||'N/A')+'</span>'}
function apxSection(sections,name){const s=(sections||{})[name];return s&&s.status==='observed'?s.data||{}:null}
function apxError(sections,name){const s=(sections||{})[name];return !s?'Non collecté par cette version de la sonde : actualiser le WAF.':s.status==='observed'?null:(s.error||'Mesure indisponible')}
function apxUnavailable(title,error,extra=''){return wafPanel(title,'<p class="instruction">'+wafUnmeasured()+' '+esc(error)+'</p>'+extra)}

function apxCards(health){
 if(!health)return '<p class="note apx-cards-missing">'+wafUnmeasured()+' Santé Apache : aucune collecte de la sonde Apache.</p>';
 return '<div class="apx-cards">'+health.cards.map(c=>'<div class="apx-card lvl-'+esc(c.level)+'"><span>'+esc(c.title)+'</span><strong>'+esc(c.value)+'</strong>'+apxPill(c.level)+'<small>'+esc(c.note||'')+'</small></div>').join('')+'</div>';
}
function apxMessage(health){
 if(!health)return '';
 const tone=health.overall,missing=Object.entries(health.errors||{});
 return '<section class="panel apx-message lvl-'+esc(tone)+'"><div class="panel-head"><h2>'+(tone==='critical'?'APACHE SATURATION':'Diagnostic Apache')+'</h2>'+apxPill(tone)+'</div>'+
  (missing.length?'<p class="instruction">'+wafUnmeasured()+' Non mesuré : '+missing.map(([k,e])=>esc(k)+' ('+esc(e)+')').join(' · ')+'. L’état global ne peut pas être « OK » tant que ces mesures manquent.</p>':'')+
  health.summary.map(l=>'<p>'+esc(l)+'</p>').join('')+
  (health.diagnostics.length?'<div class="apx-diags">'+health.diagnostics.map(d=>'<div class="apx-diag lvl-'+(d.level==='critical'?'red':'yellow')+'"><b>Cas '+esc(d.case)+' · '+esc(d.text)+'</b><small>'+esc(d.detail)+'</small></div>').join('')+'</div>':'')+
  (health.workers?.last_saturation?'<p class="apx-sat">Dernière occurrence de saturation dans error.log : <b>'+esc(health.workers.last_saturation)+'</b> (heure du serveur)</p>':'')+
  '<p class="note">Corrélation indicative : « likely » et « may contribute » signalent une hypothèse à vérifier, seule la présence d’AH00484/AH03490 confirme une saturation. Évaluation : '+esc(stamp(health.evaluated_at))+'.</p></section>';
}

// Refus ModSecurity par journal d'erreurs : un site écrit ses refus dans son propre ErrorLog, pas dans
// error.log principal. Couverture réelle affichée : journal illisible, non lu ou tronqué = décompte minimal.
function apxModsecVhosts(sat){
 const v=sat.modsecurity_vhosts;
 if(!v)return '<p class="instruction">'+wafUnmeasured()+' Refus ModSecurity des vhosts : non collectés par cette version de la sonde. Actualiser le WAF.</p>';
 const gaps=[[v.unreadable,'illisible(s)'],[v.not_read,'non lu(s) faute de budget'],[v.partial,'tronqué(s) avant le début de la fenêtre']].filter(([l])=>l?.length).map(([l,t])=>l.length+' '+t);
 return '<p class="note">Refus ModSecurity sur '+(sat.window_seconds/60)+' min : <b>'+esc(apxNa(sat.modsecurity_denied))+'</b>, dont '+esc(apxNa(sat.modsecurity_main_denied))+' dans error.log principal. '+
  esc(v.files_read)+' journal(aux) de vhost lu(s) sur '+esc(v.files_discovered)+' ; les journaux non modifiés depuis le début de la fenêtre sont ignorés.</p>'+
  (gaps.length?'<p class="instruction">'+wafUnmeasured('Partiel')+' Journaux '+esc(gaps.join(', '))+' : décompte minimal. Vérifier les droits de lecture de /var/log/apache2 (docs/SERVICE-ACCOUNT.md).</p>':'')+
  (v.by_file?.length?wafTable(['Journal d’erreurs du vhost','Refus ModSecurity (30 min)'],v.by_file.map(([p,n])=>[String(p).split('/').pop(),n])):'');
}
function apxHealth(sections,health){
 const st=apxSection(sections,'status'),cfg=apxSection(sections,'config');
 const d=cfg?.directives||{},v=k=>d[k]?.value,src=k=>d[k]?.source;
 const w=health?.workers||{};
 const statusBlock=st?wafTable(['Métrique server-status','Valeur'],[
  ['BusyWorkers',apxNa(st.BusyWorkers)],['IdleWorkers',apxNa(st.IdleWorkers)],['GracefulWorkers',apxNa(st.GracefulWorkers)],
  ['Processes',apxNa(st.Processes)],['Stopping',apxNa(st.Stopping)],['ConnsTotal',apxNa(st.ConnsTotal)],
  ['ConnsAsyncKeepAlive',apxNa(st.ConnsAsyncKeepAlive)],['ConnsAsyncClosing',apxNa(st.ConnsAsyncClosing)],
  ['ReqPerSec (moyenne depuis le démarrage)',apxNum(st.ReqPerSec,2)],['DurationPerReq (ms, moyenne)',apxNum(st.DurationPerReq,1)],
  ['ServerUptime',apxNa(st.ServerUptime)],['ParentServerConfigGeneration',apxNa(st.ParentServerConfigGeneration)],
  ['ParentServerMPMGeneration',apxNa(st.ParentServerMPMGeneration)]]):
  '<p class="instruction">'+wafUnmeasured()+' server-status : '+esc(apxError(sections,'status'))+'</p>'+command('Activer server-status en local (à appliquer manuellement)','<Location "/server-status">\n    SetHandler server-status\n    Require local\n</Location>\n# ExtendedStatus On pour ReqPerSec / DurationPerReq\n# puis : sudo apache2ctl configtest (le rechargement reste une décision manuelle)');
 const configBlock=cfg?wafTable(['Directive','Valeur','Source'],['ServerLimit','ThreadsPerChild','MaxRequestWorkers','MaxConnectionsPerChild','Timeout','KeepAlive','KeepAliveTimeout','MaxKeepAliveRequests','ProxyTimeout'].map(k=>[k,apxNa(v(k)),apxNa(src(k))]))+
  '<p class="note">MPM : '+esc(apxNa(cfg.mpm))+' · capacité effective = min(MaxRequestWorkers, ServerLimit × ThreadsPerChild) = <b>'+esc(apxNa(cfg.effective_max_workers))+'</b>. '+esc(cfg.scope||'')+'</p>':
  '<p class="instruction">'+wafUnmeasured()+' Configuration : '+esc(apxError(sections,'config'))+'</p>';
 const started=st&&v('ThreadsPerChild')&&st.Processes!=null?st.Processes*v('ThreadsPerChild'):null;
 const gauge=ui.gauge('Worker utilization',w.utilization,{thresholds:[75,90],detail:(w.busy??'N/A')+' / '+(w.max??'N/A')+' workers (BusyWorkers / MaxRequestWorkers)'});
 const note='<p class="note">IdleWorkers ne représente que les threads des processus démarrés'+(started!=null?' ('+started+' slots démarrés sur '+esc(apxNa(cfg?.effective_max_workers))+')':'')+' : Apache peut encore démarrer des processus jusqu’à ServerLimit. Seuils : vert < 60 %, jaune ≥ 60 %, orange ≥ 75 %, rouge ≥ 90 %, APACHE SATURATION si BusyWorkers ≥ MaxRequestWorkers ou message AH00484 / AH10159 / AH03490 récent.</p>';
 const sat=apxSection(sections,'saturation');
 const satBlock=sat?wafTable(['Message error.log ('+(sat.window_seconds/60)+' dernières min)','Occurrences','Dernière occurrence'],[['AH00484 · server reached MaxRequestWorkers',sat.counts.AH00484,apxNa(sat.last.AH00484)],['AH10159 · proche de MaxRequestWorkers',sat.counts.AH10159,apxNa(sat.last.AH10159)],['AH03490 · scoreboard is full',sat.counts.AH03490,apxNa(sat.last.AH03490)]])+'<p class="note">'+esc(sat.scope)+(sat.coverage_complete?'':' Couverture partielle : les octets lus ne remontent pas jusqu’au début de la fenêtre.')+'</p>'+apxModsecVhosts(sat):'<p class="instruction">'+wafUnmeasured()+' Journal d’erreurs : '+esc(apxError(sections,'saturation'))+'</p>';
 return '<section class="panel apx-health"><div class="panel-head"><h2>Apache Health & Saturation</h2>'+apxPill(w.level)+'</div>'+gauge+note+
  '<div class="waf-columns">'+wafPanel('server-status (127.0.0.1)',statusBlock)+wafPanel('Configuration Apache',configBlock)+'</div>'+wafPanel('Événements de saturation',satBlock)+'</section>';
}

function apxCloseWait(wafSections,health){
 const s=(wafSections||{}).sockets;
 if(!s||s.status!=='observed')return apxUnavailable('Backend CLOSE_WAIT',s?.error||'Section sockets non collectée');
 const c=s.data||{},cw=health?.close_wait||{},w=health?.workers||{};
 const others=(c.by_upstream||[]).slice(5).reduce((n,[,x])=>n+x,0);
 const upstream=(c.by_upstream||[]).slice(0,5).map(([k,n])=>[k,n]).concat(others?[['autres',others]]:[]);
 const [cwLow,cwMid,cwHigh]=apxCwThresholds(health);
 const reading=cw.value==null?'N/A':cw.value>cwLow&&(w.utilization??0)>=75?'Connexions backend CLOSE_WAIT persistantes avec une charge des workers élevée ('+w.utilization+' %) : alerte haute.':
  cw.value>cwLow?'Connexions backend CLOSE_WAIT persistantes ; charge des workers '+(w.utilization!=null?'faible ('+w.utilization+' %)':'non mesurée')+' : avertissement, pas de saturation constatée.':'CLOSE_WAIT dans la plage observée en fonctionnement normal.';
 return '<section class="panel apx-cw"><div class="panel-head"><h2>Backend CLOSE_WAIT</h2>'+apxPill(cw.level,cw.value==null?'N/A':cw.value+' · '+(APX_LEVEL_LABEL[cw.level]||'N/A'))+'</div>'+
  '<div class="apx-cards apx-cards-3">'+[['Total CLOSE_WAIT Apache',apxNa(cw.value),cw.level],['Évolution depuis la collecte précédente',cw.delta==null?'N/A':(cw.delta>0?'+':'')+cw.delta,cw.delta==null?'unknown':cw.delta>0?'yellow':'ok'],['BusyWorkers',w.busy==null?'N/A':w.busy+' / '+(w.max??'N/A'),w.level]].map(([t,v,l])=>'<div class="apx-card lvl-'+esc(l||'unknown')+'"><span>'+esc(t)+'</span><strong>'+esc(v)+'</strong>'+apxPill(l||'unknown')+'</div>').join('')+'</div>'+
  '<p>'+esc(reading)+'</p><div class="waf-columns">'+wafPanel('Par backend IP:port',wafTable(['Backend','CLOSE_WAIT'],upstream))+wafPanel('Top PID Apache',c.process_visible?wafTable(['PID','CLOSE_WAIT'],(c.by_pid||[]).map(([k,n])=>['PID '+String(k).split(':').pop(),n])):'<p class="note">N/A · processus non visibles (sudo -n ss refusé).</p>')+'</div>'+
  '<p class="note">Seuils : vert ≤ '+cwLow+', jaune > '+cwLow+', orange > '+cwMid+', rouge > '+cwHigh+' (calibrés sur l’historique, docs/WAF-SEUILS.md). Un CLOSE_WAIT indique que le backend a fermé la connexion et qu’Apache ne l’a pas encore refermée ; il ne prouve pas à lui seul l’état des workers, d’où la corrélation avec BusyWorkers.</p></section>';
}

function apxBackends(sections,health){
 const b=apxSection(sections,'backends'),chronic=new Set(health?.backends?.chronic_list||[]);
 if(!b)return apxUnavailable('Backend Proxy Health',apxError(sections,'backends'));
 const rows=b.backends||[];
 return '<section class="panel"><div class="panel-head"><h2>Backend Proxy Health</h2><span class="mini">'+rows.length+' backend(s) testé(s) sur '+esc(b.detected)+' détecté(s)</span></div>'+
  '<div class="table waf-table"><table><thead><tr>'+['État','Backend','Vhost(s)','TCP connect','TTFB','Total','HTTP','Détail'].map(x=>'<th>'+x+'</th>').join('')+'</tr></thead><tbody>'+
  rows.map(r=>'<tr><td>'+apxPill(chronic.has(r.backend)?'yellow':APX_BACKEND_TONE[r.state]||'unknown',r.state+(chronic.has(r.backend)?' · chronique > 24 h':''))+'</td><td class="ip">'+esc(r.scheme==='https'?'https://':'')+esc(r.backend)+'</td><td>'+esc((r.vhosts||[]).join(', '))+(r.vhosts_total>(r.vhosts||[]).length?' <small>+'+(r.vhosts_total-r.vhosts.length)+'</small>':'')+'</td><td>'+apxMs(r.tcp_ms)+'</td><td>'+apxMs(r.ttfb_ms)+'</td><td>'+apxMs(r.total_ms)+'</td><td>'+esc(apxNa(r.http_status))+'</td><td>'+esc(r.detail||'')+'</td></tr>').join('')+'</tbody></table></div>'+
  '<p class="note">'+esc(b.scope||'')+' HTTP SLOW : premier octet après 1 s ou aucune réponse en 3 s.'+(chronic.size?' Chronique : injoignable depuis plus de 24 h, souvent un vhost abandonné ; à retirer de la configuration ou à réparer, il ne relève plus l’état global au-delà de « Vigilance ».':'')+'</p></section>';
}

function apxSlow(sections,health){
 const a=apxSection(sections,'access');
 if(!a)return apxUnavailable('Requêtes lentes',apxError(sections,'access'),'<p class="note">Cette analyse exige la durée de requête (%D) dans le LogFormat des journaux concernés.</p>');
 const sl=health?.slow||{};
 const pct=n=>a.total?' ('+apxNum(n/a.total*100,1)+' %)':'';
 return '<section class="panel"><div class="panel-head"><h2>Requêtes lentes · 10 dernières minutes</h2>'+apxPill(sl.level)+'</div>'+
  '<div class="apx-cards apx-cards-8">'+[['Total',a.total],['≥ 1 s',a.slow1+pct(a.slow1)],['≥ 3 s',a.slow3+pct(a.slow3)],['≥ 5 s',a.slow5+pct(a.slow5)],['≥ 10 s',a.slow10+pct(a.slow10)],['Moyenne',apxSec(a.avg)],['Maximum',apxSec(a.max)],['Req/s (10 min)',apxNum(a.rps,2)]].map(([t,v])=>'<div class="apx-card"><span>'+esc(t)+'</span><strong>'+esc(v)+'</strong></div>').join('')+'</div>'+
  '<p class="note">Seuils sur la moyenne : vert < 1 s, jaune 1-3 s, orange 3-5 s, rouge > 5 s ; critique si les requêtes ≥ 10 s dépassent 10 % du trafic. '+esc(a.scope)+'</p>'+
  (a.excluded?.length?'<details><summary>'+a.excluded.length+' journal(aux) non analysé(s)</summary>'+wafTable(['Journal','Raison'],a.excluded.map(e=>[e.path,e.reason]))+'</details>':'')+
  (a.top_vhosts?.length?'<details><summary>Répartition par journal (vhost)</summary>'+wafTable(['Journal','Requêtes (10 min)'],a.top_vhosts)+'</details>':'')+'</section>';
}

// Libellés neutres : aucune IP n'est qualifiée d'attaque.
function apxIpLabel(ip,row,a,banned){
 if(banned.has(ip))return 'Blocked';
 if(row.s429)return 'Rate-limited';
 if(row.bot)return 'Crawler suspected';
 if(a.total&&row.requests>=Math.max(100,a.total*0.05))return 'High traffic';
 return 'Normal';
}
function apxTopIps(sections,wafSections){
 const a=apxSection(sections,'access');if(!a)return apxUnavailable('Top IP - requêtes lentes',apxError(sections,'access'));
 const banned=new Set(wafSections?.fail2ban?.data?.banned_ips||[]);
 return wafPanel('Top IP - requêtes lentes','<div class="table waf-table"><table><thead><tr>'+['IP','Requêtes','Lentes > 5 s','Lentes > 10 s','Durée moyenne','Durée max','User-Agent principal','Profil'].map(x=>'<th>'+x+'</th>').join('')+'</tr></thead><tbody>'+
  (a.top_ips||[]).map(r=>'<tr><td class="ip">'+esc(r.ip)+'</td><td>'+esc(r.requests)+'</td><td>'+esc(r.slow5)+'</td><td>'+esc(r.slow10)+'</td><td>'+apxSec(r.avg)+'</td><td>'+apxSec(r.max)+'</td><td class="apx-ua">'+esc(apxNa(r.user_agent))+'</td><td>'+esc(apxIpLabel(r.ip,r,a,banned))+'</td></tr>').join('')+'</tbody></table></div>'+
  '<p class="note">Profils descriptifs (Normal, High traffic, Crawler suspected, Rate-limited, Blocked) : aucune IP n’est qualifiée d’attaque automatiquement. Derrière un répartiteur, l’IP journalisée peut être la sienne.</p>');
}
function apxTopUris(sections){
 const a=apxSection(sections,'access');if(!a)return apxUnavailable('URL les plus lentes',apxError(sections,'access'));
 return wafPanel('URL les plus lentes',wafTable(['URI (normalisée, sans paramètres)','Requêtes','Durée moyenne','Durée max','Requêtes > 10 s'],(a.top_uris||[]).map(r=>[r.uri,r.requests,apxSec(r.avg),apxSec(r.max),r.slow10]))+
  '<p class="note">Segments variables regroupés : nombres → {n}, identifiants → {id}, « societe-xxx-yyy » → « societe-* ».</p>');
}
function apxConcurrency(sections,health){
 const a=apxSection(sections,'access');
 if(!a)return apxUnavailable('Concurrence estimée',apxError(sections,'access'));
 const c=a.concurrency||{},max=health?.workers?.max;
 const ratio=v=>v==null||!max?null:v/max*100;
 return wafPanel('Concurrence estimée','<div class="v2-gauge-grid">'+
  ui.gauge('Current estimated concurrency',ratio(c.current),{thresholds:[75,90],detail:apxNa(c.current)+' / '+apxNa(max)+' · pic de la dernière minute'})+
  ui.gauge('Peak concurrency 10 min',ratio(c.peak_10m),{thresholds:[75,90],detail:apxNa(c.peak_10m)+' / '+apxNa(max)+(c.peak_10m_at?' · '+new Date(c.peak_10m_at*1000).toLocaleTimeString('fr-FR'):'')})+
  ui.gauge('Peak concurrency 1 h',ratio(c.peak_1h),{thresholds:[75,90],detail:apxNa(c.peak_1h)+' / '+apxNa(max)+' · '+apxNum(c.covered_minutes,0)+' min couvertes'})+'</div>'+
  '<p class="note">Estimation par chevauchement des intervalles [début (%t), début + %D] des requêtes journalisées. Les requêtes encore en cours ne sont pas journalisées : c’est un minimum, comparé à MaxRequestWorkers.</p>');
}
function apxBots(sections){
 const a=apxSection(sections,'access'),sat=apxSection(sections,'saturation');
 if(!a)return apxUnavailable('Bot / WAF Activity · 10 dernières minutes',apxError(sections,'access'));
 const b=a.bots||{};
 return '<section class="panel"><div class="panel-head"><h2>Bot / WAF Activity · 10 dernières minutes</h2></div>'+
  '<div class="apx-cards apx-cards-3">'+[['Requêtes bloquées (HTTP 403)',b.s403],['Requêtes limitées (HTTP 429)',b.s429],['Refus ModSecurity (30 min, error.log et vhosts'+(sat?.modsecurity_vhosts&&!sat.modsecurity_vhosts.complete?', minimum':'')+')',apxNa(sat?.modsecurity_denied)]].map(([t,v])=>'<div class="apx-card"><span>'+esc(t)+'</span><strong>'+esc(apxNa(v))+'</strong></div>').join('')+'</div>'+
  '<div class="waf-columns">'+wafPanel('Catégories de robots (tout le trafic)',wafTable(['Catégorie','Requêtes'],b.categories||[]))+wafPanel('Catégories parmi les 403/429',wafTable(['Catégorie','Requêtes'],b.blocked_categories||[]))+'</div>'+
  '<div class="waf-columns">'+wafPanel('Top User-Agent (403/429)',wafTable(['User-Agent','Requêtes'],b.top_user_agents||[]))+wafPanel('Top source IP (403/429)',wafTable(['IP','Requêtes'],b.top_ips||[]))+'</div>'+
  wafPanel('Top URI (403/429)',wafTable(['URI','Requêtes'],b.top_uris||[]))+
  '<p class="note">Un robot actif n’est jamais présenté comme cause d’une saturation : le comparer aux requêtes lentes et à la concurrence. Catégories par motif de User-Agent, déclaratif et falsifiable.</p></section>';
}
function apxHistoryShell(h){
 return '<section class="panel"><div class="panel-head"><h2>Apache Incident History</h2><label>Période <select id="apx-history-hours">'+[[1,'1 h'],[6,'6 h'],[24,'24 h'],[168,'7 jours']].map(([v,l])=>'<option value="'+v+'" '+(v===apxHistoryHours?'selected':'')+'>'+l+'</option>').join('')+'</select></label></div><div id="apx-history" data-key="'+escAttr(h.key)+'">Chargement…</div><p class="note">Un échantillon par collecte WAF, conservé 7 jours dans la base locale d’OpsControl : compteurs, top IP et top URL sans paramètres. Les lignes en rouge sont les collectes en saturation, pour comparer avant / pendant / après.</p></section>';
}
async function apxLoadHistory(){
 const target=$('#apx-history');if(!target)return;
 if(target.closest('[hidden]'))return;
 try{
  const data=await api('/api/waf/'+encodeURIComponent(target.dataset.key)+'/apache-history?hours='+apxHistoryHours);
  if(!target.isConnected)return;
  const s=data.samples||[];
  target.innerHTML=s.length?'<div class="table waf-table"><table><thead><tr>'+['Collecte','État','BusyWorkers','Max','CLOSE_WAIT','Req/s (10 min)','Lentes ≥5s / ≥10s','Moyenne','Latence backend max','Top IP','Top URI','AH00484','AH03490'].map(x=>'<th>'+x+'</th>').join('')+'</tr></thead><tbody>'+
   s.map(x=>'<tr class="lvl-row-'+esc(x.level)+'"><td>'+esc(stamp(x.ts))+'</td><td>'+apxPill(x.level)+'</td><td>'+esc(apxNa(x.busy))+'</td><td>'+esc(apxNa(x.max_workers))+'</td><td>'+esc(apxNa(x.close_wait))+'</td><td>'+apxNum(x.rps,2)+'</td><td>'+esc(apxNa(x.slow5))+' / '+esc(apxNa(x.slow10))+'</td><td>'+apxSec(x.avg)+'</td><td>'+apxMs(x.backend_max_ttfb_ms)+'</td><td class="ip">'+esc(apxNa(x.top_ip))+'</td><td>'+esc(apxNa(x.top_uri))+'</td><td>'+(x.ah00484?'Oui':'Non')+'</td><td>'+(x.ah03490?'Oui':'Non')+'</td></tr>').join('')+'</tbody></table></div>':'<p class="note">Aucun échantillon sur cette période : l’historique commence avec la première collecte de la sonde Apache.</p>';
  wafEnhanceTables(target);
 }catch(e){if(target.isConnected)target.textContent='Historique N/A · '+e.message}
}
$('#content').addEventListener('change',e=>{if(e.target.id!=='apx-history-hours')return;apxHistoryHours=Number(e.target.value)||24;apxLoadHistory()});

const advancedWafBeforeApache=advancedWaf;
advancedWaf=function(h){
 let html=advancedWafBeforeApache(h);
 const w=h.waf||{},apache=w.apache||{},sections=apache.sections||{},health=w.apache_health||null;
 const top=apxCards(health)+apxMessage(health)+(apache.error?'<p class="instruction">Sonde Apache : '+esc(apache.error)+'</p>':'');
 const marker='<div class="stats waf-stats">';
 html=html.includes(marker)?html.replace(marker,top+marker):top+html;
 const blocks=apxHealth(sections,health)+apxCloseWait(w.sections,health)+apxBackends(sections,health)+apxSlow(sections,health)+
  '<div class="waf-columns">'+apxTopIps(sections,w.sections)+apxTopUris(sections)+'</div>'+apxConcurrency(sections,health)+apxBots(sections)+apxHistoryShell(h);
 const after='<div class="waf-columns">';
 const at=html.indexOf(after,html.indexOf(marker));
 html=at>=0?html.slice(0,at)+blocks+html.slice(at):html+blocks;
 return html;
};
