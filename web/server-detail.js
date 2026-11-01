// Per-host monitoring overview. Each duration retains its source and time basis.
const serverAlertFilters=new Map();
function alertDuration(seconds){
 if(seconds==null||!Number.isFinite(seconds))return 'Non mesurée';
 const minutes=Math.floor(seconds/60),hours=Math.floor(minutes/60),days=Math.floor(hours/24);
 return days?days+' j '+hours%24+' h':hours?hours+' h '+minutes%60+' min':minutes?minutes+' min':'Moins d’une minute';
}
function serverAlertRows(host){
 const filter=serverAlertFilters.get(host.key)||{query:'',source:'',severity:''};
 const all=host.alerts?.items||[];
 const matches=all.filter(a=>(!filter.source||a.source===filter.source)&&(!filter.severity||a.severity===filter.severity)&&
  (!filter.query||(a.title+' '+(a.evidence||'')).toLowerCase().includes(filter.query.toLowerCase())));
 return '<p role="status">'+matches.length+' alerte(s) correspondant aux filtres · '+Math.min(50,matches.length)+' affichée(s)</p>'+
  '<div class="table"><table><caption>Alertes de '+esc(host.name)+' · dates affichées dans le fuseau du navigateur</caption><thead><tr>'+['Gravité / source','Problème','Depuis / base de temps','Durée','Dernière observation'].map(s=>'<th scope="col">'+s+'</th>').join('')+'</tr></thead><tbody>'+
  matches.slice(0,50).map(a=>'<tr><td>'+badge(a.severity)+'<p>'+esc(a.source)+'</p></td><td><strong>'+esc(a.title)+'</strong>'+(a.evidence?'<details><summary>Preuve / détail</summary><pre>'+esc(a.evidence)+'</pre></details>':'')+'</td><td>'+stamp(a.started_at)+'<p class="note">'+esc(a.time_basis)+'</p></td><td>'+alertDuration(a.duration_seconds)+(a.fresh?'':'<p class="note">À la dernière observation</p>')+'</td><td>'+stamp(a.observed_at)+'<p class="badge '+(a.fresh?'observed':'unknown')+'">'+(a.fresh?'Observation récente':'À reconfirmer')+'</p></td></tr>').join('')+'</tbody></table></div>'+
  (matches.length?'':'<p>Aucune alerte dans cette sélection. Une source absente ou un contrôle incomplet ne prouve pas que le serveur est sain.</p>');
}
// Faits système (Synthèse) : chacun porte sa source ; « Non mesuré » plutôt qu'une valeur supposée.
function serverFacts(host){
 const counts=host.alerts?.counts||{};
 const net=host.network_evidence||{};
 return '<section class="panel server-facts-panel"><h2>Identité et accès</h2><dl class="server-facts">'+[['Système (SSH)',host.os||'Non mesuré'],['Uptime (SSH)',host.uptime||'Non mesuré'],['Accès SSH observé',host.ssh_user?host.ssh_user+':'+host.ssh_port:'Non établi'],['Disponibilité réseau (ping)',net.fresh?(net.ping===true?'Ping réussi':net.ping===false?'Sans réponse':'Non mesuré'):'Ancienne ou non mesurée'],['Dernier audit SSH',stamp(host.collected_at)],['Alertes à reconfirmer',counts.old??0]].map(([label,value])=>'<div><dt>'+esc(label)+'</dt><dd>'+esc(value)+'</dd></div>').join('')+'</dl></section>';
}
// Alertes de toutes les sources pour ce serveur (onglet Incidents), avec filtres.
function serverMonitoring(host){
 const counts=host.alerts?.counts||{};
 const filter=serverAlertFilters.get(host.key)||{query:'',source:'',severity:''};
 const sources=[...new Set((host.alerts?.items||[]).map(a=>a.source))];
 // Repliées sous les incidents du journal (web/host-incidents.js) : même anomalie vue par chaque source.
 return '<details class="panel server-monitoring"><summary><b>Détail par source</b> · alertes brutes de chaque outil ('+(counts.total??0)+') — une même anomalie peut y figurer plusieurs fois</summary><div class="panel-head"><div><h2>Supervision de ce serveur</h2><p>Alertes de toutes les sources, avec leur ancienneté</p></div><span class="badge unknown">'+(counts.total??0)+' alerte(s) documentée(s)</span></div>'+
 '<p class="note">'+esc(host.alerts?.scope||'Chronologie non disponible : recharger la fiche après mise à jour du serveur OpsControl.')+'</p><div class="filters server-alert-filters"><label>Rechercher<input id="server-alert-query" type="search" value="'+escAttr(filter.query)+'" placeholder="Disque, service, agent…"></label><label>Source<select id="server-alert-source"><option value="">Toutes</option>'+sources.map(s=>'<option '+(filter.source===s?'selected':'')+' value="'+escAttr(s)+'">'+esc(s)+'</option>').join('')+'</select></label><label>Gravité<select id="server-alert-severity">'+[['','Toutes'],['critical','Critique'],['warning','Avertissement'],['unreachable','Injoignable'],['unknown','Information / non classée']].map(([v,label])=>'<option value="'+v+'" '+(v===filter.severity?'selected':'')+'>'+label+'</option>').join('')+'</select></label></div><div id="server-alert-results">'+serverAlertRows(host)+'</div></details>';
}
hostSection('summary',30,serverFacts);
hostSection('incidents',10,serverMonitoring);
function updateServerAlertFilter(event){
 const field={'server-alert-query':'query','server-alert-source':'source','server-alert-severity':'severity'}[event.target.id];
 if(!field||!hostDetail)return;
 const filter=serverAlertFilters.get(hostDetail.key)||{query:'',source:'',severity:''};
 filter[field]=event.target.value;serverAlertFilters.set(hostDetail.key,filter);
 const target=document.getElementById('server-alert-results');if(target)target.innerHTML=serverAlertRows(hostDetail);
}
document.getElementById('content').addEventListener('input',updateServerAlertFilter);
document.getElementById('content').addEventListener('change',updateServerAlertFilter);
// Applications qui tournent sur le serveur (opération SSH `apps`, lecture seule, sans sudo).
// Un relevé absent ou en échec n'est jamais présenté comme « aucune application ».
const hostAppsFilters=new Map();
function hostAppsFilter(){const key=hostDetail?.key||'';if(!hostAppsFilters.has(key))hostAppsFilters.set(key,{q:'',c:''});return hostAppsFilters.get(key);}
function appDate(seconds){return Number.isFinite(seconds)&&seconds>0?new Date(seconds*1000).toLocaleDateString('fr-FR'):'—'}
function serverApplications(h){
 const a=h.applications;
 if(!a)return '<section class="panel"><h2>Applications</h2><p class="empty">Relevé pas encore effectué : lancer l’audit de ce serveur.</p></section>';
 const head='<div class="panel-head"><div><h2>Applications qui tournent</h2><p class="mini">'+freshnessMarkup(a.collected_at,'Relevé des applications',900)+'</p></div></div>';
 if(a.status!=='observed')return '<section class="panel">'+head+'<p role="alert" class="form-error">'+esc(a.error||'Relevé indisponible.')+'</p><p class="note">L’absence de relevé ne prouve pas l’absence d’application.</p></section>';
 // Les sites ont leur propre tableau (lien, DNS, application) ; ils ne sont pas répétés plus bas.
 const sitesTable=Array.isArray(a.sites);
 const elements=(a.elements||[]).filter(e=>!(sitesTable&&e.categorie==='Site web')),categories=[...new Set(elements.map(e=>e.categorie))].sort();
 const facts=[['Système',a.os||'Non mesuré'],['Installation du système',a.installation?appDate(a.installation)+' ('+a.installation_source+')':'Non mesurée'],
  ['Docker',a.docker||'Non mesuré'],['Ports TCP en écoute',(a.ports||[]).join(', ')||'Aucun relevé'],['Dossiers applicatifs',(a.dossiers||[]).join(', ')||'Aucun'],
  // Relevés antérieurs aux paquets : « non relevé », jamais « aucun paquet ».
  ['Noyau',a.noyau||'Non relevé'],['Paquets clés',Array.isArray(a.paquets)?(a.paquets.map(p=>p.nom+' '+p.version).join(', ')||'Aucun de la liste'):'Non relevé : relancer l’audit']];
 return '<section class="panel host-applications">'+head+
  '<dl class="server-facts">'+facts.map(([k,v])=>'<dt>'+esc(k)+'</dt><dd>'+esc(v)+'</dd>').join('')+'</dl>'+
  (sitesTable?serverSites(a.sites):'')+
  '<div class="filters"><label>Rechercher<input id="host-apps-search" type="search" maxlength="80" placeholder="Nom, catégorie, détail…" value="'+escAttr(hostAppsFilter().q)+'"></label>'+
  '<label>Catégorie<select id="host-apps-category"><option value="">Toutes ('+elements.length+')</option>'+
  categories.map(c=>'<option value="'+escAttr(c)+'"'+(c===hostAppsFilter().c?' selected':'')+'>'+esc(c)+' ('+elements.filter(e=>e.categorie===c).length+')</option>').join('')+'</select></label></div>'+
  (elements.length?'<div class="table"><table><caption>'+elements.length+' élément(s) relevé(s) sur '+esc(h.name)+'</caption><thead><tr><th>Catégorie</th><th>Nom</th><th>Source</th><th>État</th><th>Détail</th><th>Date</th></tr></thead><tbody>'+
   elements.map(e=>'<tr'+(appHidden(e)?' hidden':'')+' data-app-category="'+escAttr(e.categorie)+'" data-app-text="'+escAttr([e.categorie,e.nom,e.source,e.etat,e.detail].join(' ').toLowerCase())+'"><td>'+esc(e.categorie)+'</td><td><strong>'+esc(e.nom)+'</strong></td><td>'+esc(e.source)+'</td><td>'+esc(e.etat||'—')+'</td><td class="wrap">'+esc(e.detail||'—')+'</td><td>'+appDate(e.date)+(e.date?'<small>'+esc(e.nature_date)+'</small>':'')+'</td></tr>').join('')+'</tbody></table></div>'
   :'<p class="empty">Aucune application reconnue dans ce relevé.</p>')+
  '<p class="note">Relevé sans droits root : un port n’indique pas son processus, et Docker peut être refusé (« Accès refusé (droits) »). Les lignes de commande complètes ne sont jamais relevées : elles peuvent contenir des secrets.</p></section>';
}
// Sites web déclarés (Apache/Nginx) : lien, portée DNS vue depuis OpsControl et application
// qui sert chaque site (cible du proxy). Lien seulement si l'URL a la forme attendue.
const SITE_DNS={interne:['info','DNS interne'],en_ligne:['warning','En ligne (IP publique)'],non_resolu:['unknown','Non résolu']};
function siteLink(s){
 return /^https?:\/\/[A-Za-z0-9.-]+\/$/.test(s.url||'')
  ?'<a href="'+escAttr(s.url)+'" target="_blank" rel="noopener noreferrer">'+esc(s.nom)+'</a>':esc(s.nom);
}
function serverSites(sites){
 if(!sites.length)return '<h3>Sites web</h3><p class="empty">Aucun site Apache ou Nginx déclaré sur ce serveur.</p>';
 return '<h3>Sites web ('+sites.length+')</h3><div class="table"><table class="host-sites"><thead><tr><th>Site</th><th>DNS</th><th>Application qui le sert</th><th>Serveur web · configuration</th></tr></thead><tbody>'+
  sites.map(s=>{
   const [tone,label]=SITE_DNS[s.dns?.statut]||['unknown','DNS non mesuré'];
   const apps=(s.cibles||[]).map(c=>'<li><code>'+esc(c.chemin)+'</code> → <strong>'+esc(c.application)+'</strong>'+
    (c.serveur?' · <button class="link" data-host="'+escAttr(c.serveur.key)+'">'+esc(c.serveur.name)+'</button>':'')+'<small>'+esc(c.cible)+(c.repartiteur?' · répartiteur '+esc(c.repartiteur):'')+'</small></li>');
   const roots=(s.racines||[]).map(r=>'<li>Fichiers statiques : <code>'+esc(r)+'</code></li>');
   return '<tr><td>'+siteLink(s)+(s.https?'':'<small>HTTP sans TLS</small>')+'</td>'+
    '<td><span class="badge '+tone+'">● '+esc(label)+'</span><small>'+esc((s.dns?.adresses||[]).join(', '))+'</small></td>'+
    '<td>'+((apps.length||roots.length)?'<ul class="plain">'+apps.join('')+roots.join('')+'</ul>':'Non déterminée (ni proxy ni racine relevés)')+'</td>'+
    '<td>'+esc(s.serveur_web)+'<small>'+esc((s.fichiers||[]).join(', '))+'</small></td></tr>';
  }).join('')+'</tbody></table></div>'+
  '<p class="note">DNS vu depuis OpsControl : « interne » = adresses privées seulement ; « en ligne » = au moins une adresse publique. Aucune connexion n’est faite au site.</p>';
}
// Enregistrements (noms DNS) déclarés sur le WAF et publiés vers CE serveur, avec le port visé
// et l'application qui y écoute d'après le relevé de ce serveur.
function serverPublished(h){
 const list=h.published_sites||[];
 if(!list.length)return '<section class="panel host-published"><h2>Enregistrements publiés vers ce serveur</h2><p class="empty">Aucun site d’un WAF ou d’un répartiteur relevé ne renvoie vers ce serveur. Un WAF jamais audité, ou sans relevé des applications, ne peut pas être pris en compte.</p></section>';
 return '<section class="panel host-published"><h2>Enregistrements publiés vers ce serveur ('+list.length+')</h2>'+
  '<div class="table"><table class="host-sites"><thead><tr><th>Enregistrement</th><th>DNS</th><th>Publié par</th><th>Port · chemin</th><th>Application sur ce serveur</th></tr></thead><tbody>'+
  list.map(p=>{
   const [tone,label]=SITE_DNS[p.dns?.statut]||['unknown','DNS non mesuré'];
   return '<tr><td>'+siteLink({nom:p.site,url:p.url})+(p.https?'':'<small>HTTP sans TLS</small>')+'</td>'+
    '<td><span class="badge '+tone+'">● '+esc(label)+'</span><small>'+esc((p.dns?.adresses||[]).join(', '))+'</small></td>'+
    '<td><button class="link" data-host="'+escAttr(p.via.key)+'">'+esc(p.via.name)+'</button><small>relevé '+esc(stamp(p.releve_le))+'</small></td>'+
    '<td><strong>'+esc(p.port)+'</strong><small>'+esc(p.chemin)+' → '+esc(p.chemin_cible)+(p.repartiteur?' · répartiteur '+esc(p.repartiteur):'')+'</small></td>'+
    '<td>'+esc(p.application)+'</td></tr>';
  }).join('')+'</tbody></table></div><p class="note">Rapprochement par IP ou nom de ce serveur dans les cibles de proxy du WAF ; l’application est déduite du port d’après le relevé de ce serveur.</p></section>';
}
// Filtre conservé entre deux rafraîchissements de la fiche (polling, SSE).
function appHidden(e){
 const q=hostAppsFilter().q.trim().toLowerCase();
 return !!(q&&![e.categorie,e.nom,e.source,e.etat,e.detail].join(' ').toLowerCase().includes(q))||!!(hostAppsFilter().c&&e.categorie!==hostAppsFilter().c);
}
function filterServerApplications(){
 hostAppsFilter().q=document.getElementById('host-apps-search')?.value||'';hostAppsFilter().c=document.getElementById('host-apps-category')?.value||'';
 const q=hostAppsFilter().q.trim().toLowerCase(),c=hostAppsFilter().c;
 document.querySelectorAll('.host-applications tr[data-app-text]').forEach(r=>{r.hidden=!!(q&&!r.dataset.appText.includes(q))||!!(c&&r.dataset.appCategory!==c)});
}
document.addEventListener('input',e=>{if(e.target.id==='host-apps-search'||e.target.id==='host-apps-category')filterServerApplications()});
document.addEventListener('change',e=>{if(e.target.id==='host-apps-category')filterServerApplications()});
