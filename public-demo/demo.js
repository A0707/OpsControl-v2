'use strict';
// Handwritten fictional inventory. Documentation-only IP ranges; no collectors.
const hosts = [
  {name:'web-01',ip:'192.0.2.11',role:'Serveur web',env:'Production',status:'ok',cpu:24,ram:48,source:'Proxmox',services:'Nginx · Application'},
  {name:'web-02',ip:'192.0.2.12',role:'Serveur web',env:'Production',status:'ok',cpu:31,ram:52,source:'Proxmox',services:'Nginx · Application'},
  {name:'db-01',ip:'192.0.2.21',role:'Base de données',env:'Production',status:'warning',cpu:46,ram:87,source:'Zabbix',services:'PostgreSQL · Réplication'},
  {name:'db-02',ip:'192.0.2.22',role:'Base de données',env:'Production',status:'ok',cpu:18,ram:43,source:'Zabbix',services:'PostgreSQL · Réplication'},
  {name:'edge-01',ip:'192.0.2.31',role:'Passerelle WAF',env:'Production',status:'ok',cpu:12,ram:32,source:'Wazuh',services:'ModSecurity · Fail2ban'},
  {name:'backup-01',ip:'192.0.2.41',role:'Sauvegardes',env:'Production',status:'warning',cpu:34,ram:55,source:'Backup',services:'Bacula Director · Storage'},
  {name:'batch-01',ip:'192.0.2.51',role:'Traitements planifiés',env:'Production',status:'critical',cpu:null,ram:null,source:'Zabbix',services:'Planificateur · Worker'},
  {name:'monitor-01',ip:'192.0.2.61',role:'Supervision',env:'Production',status:'ok',cpu:19,ram:46,source:'Zabbix',services:'Zabbix · Agent'},
  {name:'security-01',ip:'192.0.2.62',role:'Sécurité',env:'Production',status:'ok',cpu:28,ram:61,source:'Wazuh',services:'Wazuh Manager · Indexer'},
  {name:'logs-01',ip:'192.0.2.63',role:'Centralisation des logs',env:'Production',status:'ok',cpu:36,ram:64,source:'Elastic',services:'Elasticsearch · Kibana'},
  {name:'app-staging',ip:'198.51.100.11',role:'Recette applicative',env:'Recette',status:'ok',cpu:8,ram:26,source:'Proxmox',services:'Nginx · Application'},
  {name:'lab-01',ip:'198.51.100.21',role:'Laboratoire',env:'Test',status:'ok',cpu:6,ram:22,source:'Proxmox',services:'Docker · Agent'}
];
const incidents = [
  {host:'batch-01',status:'critical',title:'Serveur injoignable',detail:'Le scénario simule une perte de réponse réseau et SSH.',source:'Zabbix · Network',time:'09:42'},
  {host:'db-01',status:'warning',title:'Mémoire utilisée : 87 %',detail:'Le seuil de vigilance du scénario est fixé à 85 %.',source:'Zabbix',time:'09:35'},
  {host:'backup-01',status:'warning',title:'Une sauvegarde à relancer',detail:'Le job de sauvegarde de batch-01 a échoué dans ce scénario.',source:'Backup',time:'09:20'}
];
const sources = [
  ['Z','Zabbix','Supervision des hôtes, métriques système et incidents.','8 hôtes du scénario'],
  ['P','Proxmox','Inventaire des machines virtuelles et des conteneurs.','4 machines du scénario'],
  ['W','Wazuh','Visibilité sur les agents et les événements de sécurité.','2 agents du scénario'],
  ['E','Elastic','Santé du cluster et centralisation des journaux.','1 cluster fictif'],
  ['B','Backup','Suivi des jobs, résultats et durées de sauvegarde.','12 jobs du scénario'],
  ['N','Network','Disponibilité réseau et observations de connectivité.','12 cibles fictives'],
  ['S','SSH Audit','Consultation des services et preuves d’audit système.','11 audits fictifs']
];
const labels = {ok:'Opérationnel',warning:'À surveiller',critical:'Indisponible'};
const pages = {
  overview:['Vue globale','Votre infrastructure, vos priorités, une seule console.'],
  servers:['Parc serveurs','Explorez les serveurs et ouvrez leurs fiches de démonstration.'],
  security:['Sécurité & alertes','Les incidents à traiter et les observations du scénario.'],
  backups:['Sauvegardes','Résultats simulés des derniers jobs de sauvegarde.'],
  network:['Réseau','Disponibilité et latence du parc de démonstration.'],
  sources:['Intégrations','Les sources représentées dans OpsControl. Toutes les données ci-dessous sont simulées.']
};
let view='overview', query='', filter='all', simulation=0;
const $=s=>document.querySelector(s);
const escapeHTML=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge=(status,text=labels[status])=>`<span class="badge ${status==='ok'?'good':status}">${escapeHTML(text)}</span>`;
const stat=(label,value,note,tone='')=>`<article class="stat"><div class="stat-label">${label}</div><strong class="${tone}">${value}</strong><small>${note}</small></article>`;
const metric=value=>value===null?'<span title="Aucune mesure disponible">—</span>':`<progress max="100" value="${value}" aria-label="${value} pour cent"></progress>${value} %`;
const hostLink=h=>`<button class="server-link" data-host="${h.name}">${h.name}</button><small>${h.role}</small>`;
const incidentMarkup=()=>incidents.map(i=>`<article class="incident"><span class="incident-symbol ${i.status}" aria-hidden="true">${i.status==='critical'?'!':'△'}</span><div><h3>${i.title}</h3><p><b>${i.host}</b> · ${i.detail}</p><small>${i.source} · ${i.time} dans le scénario · ${i.status==='critical'?'Critique':'Avertissement'}</small></div></article>`).join('');
function table(items,compact=false){
  return `<div class="table-wrap"><table><thead><tr><th scope="col">SERVEUR</th><th scope="col">ÉTAT</th><th scope="col">CPU</th><th scope="col">MÉMOIRE</th>${compact?'':'<th scope="col">ENVIRONNEMENT</th><th scope="col">ADRESSE IP</th>'}</tr></thead><tbody>${items.map(h=>`<tr><td>${hostLink(h)}</td><td>${badge(h.status)}</td><td>${metric(h.cpu)}</td><td>${metric(h.ram)}</td>${compact?'':`<td>${h.env}</td><td>${h.ip}</td>`}</tr>`).join('')||'<tr><td colspan="6" class="empty">Aucun serveur ne correspond à votre recherche.</td></tr>'}</tbody></table></div>`;
}
function overview(){
  const available=hosts.filter(h=>h.status!=='critical').length;
  return `<div class="stats">${stat('SERVEURS SUPERVISÉS',hosts.length,'3 environnements fictifs')}${stat('SERVEURS JOIGNABLES',`${available}<small> / ${hosts.length}</small>`,'Disponibilité instantanée simulée','good')}${stat('ALERTES ACTIVES',incidents.length,'1 critique · 2 avertissements','warning')}${stat('SAUVEGARDES RÉUSSIES','11<small> / 12</small>','Dernière exécution du scénario','good')}</div>
  <div class="grid"><section class="panel"><div class="panel-head"><h2>Activité de l’infrastructure</h2><small>CPU moyen · Historique fictif</small></div><div class="panel-body"><div class="chart-key"><span class="dot"></span>Charge CPU · 6 dernières heures simulées</div><svg class="chart" viewBox="0 0 600 160" role="img" aria-label="Courbe illustrative de charge CPU entre 20 et 45 pour cent"><path class="chart-grid" d="M0 20H600 M0 65H600 M0 110H600 M0 155H600"/><path class="chart-fill" d="M0 125 L25 119 L50 122 L75 101 L100 109 L125 96 L150 111 L175 92 L200 86 L225 106 L250 92 L275 66 L300 71 L325 91 L350 83 L375 100 L400 70 L425 59 L450 80 L475 68 L500 90 L525 76 L550 87 L575 69 L600 79 L600 160 L0 160Z"/><path class="chart-line" d="M0 125 L25 119 L50 122 L75 101 L100 109 L125 96 L150 111 L175 92 L200 86 L225 106 L250 92 L275 66 L300 71 L325 91 L350 83 L375 100 L400 70 L425 59 L450 80 L475 68 L500 90 L525 76 L550 87 L575 69 L600 79"/></svg><div class="chart-labels"><span>04:00</span><span>05:00</span><span>06:00</span><span>07:00</span><span>08:00</span><span>09:00</span><span>10:00</span></div></div></section>
  <section class="panel"><div class="panel-head"><h2>Disponibilité du parc</h2><small>Instantané fictif</small></div><div class="health"><div class="ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle cx="50" cy="50" r="44"/><circle cx="50" cy="50" r="44"/></svg><strong>92<span>%</span></strong></div><div class="legend"><span><b class="good">9</b> Opérationnels</span><span><b class="warning">2</b> À surveiller</span><span><b class="critical">1</b> Indisponible</span></div></div><div class="health-note">11 serveurs joignables sur 12 · arrondi à 92 %</div></section></div>
  <div class="grid"><section class="panel"><div class="panel-head"><h2>Parc serveurs</h2><button class="text-button" data-view="servers">Voir les 12 serveurs →</button></div>${table(hosts.slice(0,5),true)}<div class="table-foot"><span>5 serveurs sur 12</span><span>Cliquez sur un serveur pour sa fiche</span></div></section><section class="panel"><div class="panel-head"><h2>Points d’attention</h2><small>3 alertes simulées</small></div>${incidentMarkup()}</section></div>`;
}
function serverRows(){
  const matches=hosts.filter(h=>(filter==='all'||h.status===filter)&&[h.name,h.ip,h.role,h.env].some(v=>v.toLocaleLowerCase('fr').includes(query.toLocaleLowerCase('fr'))));
  $('#server-results').innerHTML=`${table(matches)}<div class="table-foot" role="status">${matches.length} serveur(s) sur ${hosts.length} · données fictives</div>`;
}
function render(){
  $('#page-title').textContent=pages[view][0];$('#breadcrumb').textContent=pages[view][0];$('#page-description').textContent=pages[view][1];
  document.querySelectorAll('nav [data-view]').forEach(b=>{if(b.dataset.view===view)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
  let html='';
  if(view==='overview') html=overview();
  if(view==='servers') html=`<div class="filters"><label>Rechercher <input id="search" type="search" placeholder="Nom, rôle ou adresse IP" value="${escapeHTML(query)}"></label><label>État <select id="status-filter"><option value="all">Tous les états</option>${Object.entries(labels).map(([key,value])=>`<option value="${key}" ${key===filter?'selected':''}>${value}</option>`).join('')}</select></label></div><section class="panel" id="server-results"></section>`;
  if(view==='security') html=`<div class="stats">${stat('INCIDENT CRITIQUE',1,'Perte de disponibilité','critical')}${stat('AVERTISSEMENTS',2,'Mémoire · Sauvegarde','warning')}${stat('AGENTS WAZUH',2,'Agents fictifs présents','good')}${stat('WAF',1,'Passerelle du scénario','good')}</div><section class="panel"><div class="panel-head"><h2>Incidents du scénario</h2><small>Données de démonstration</small></div>${incidentMarkup()}</section><div class="demo-note">Les alertes illustrent le regroupement de plusieurs sources. Aucun blocage, scan ou changement de règle n’est exécuté.</div>`;
  if(view==='backups') html=`<div class="stats">${stat('JOBS',12,'Une sauvegarde par serveur')}${stat('RÉUSSIS',11,'Résultats fictifs','good')}${stat('EN ÉCHEC',1,'batch-01 indisponible','critical')}${stat('RESTAURATION','—','Aucun test de restauration effectué')}</div><section class="panel"><div class="panel-head"><h2>Derniers jobs de sauvegarde</h2><small>Historique fictif · 09:00</small></div><div class="table-wrap"><table><thead><tr><th scope="col">CLIENT</th><th scope="col">JOB</th><th scope="col">RÉSULTAT</th><th scope="col">DURÉE</th><th scope="col">VOLUME</th></tr></thead><tbody>${hosts.map((h,i)=>`<tr><td>${hostLink(h)}</td><td>backup-${h.name}</td><td>${badge(h.status==='critical'?'critical':'ok',h.status==='critical'?'Échec':'Réussi')}</td><td>${h.status==='critical'?'—':`${8+i*2} min`}</td><td>${h.status==='critical'?'—':`${12+i*3} Go`}</td></tr>`).join('')}</tbody></table></div><div class="table-foot">Un job réussi ne certifie pas la restaurabilité des données.</div></section>`;
  if(view==='network') html=`<div class="stats">${stat('CIBLES',12,'Adresses de documentation')}${stat('JOIGNABLES',11,'Observations simulées','good')}${stat('INDISPONIBLE',1,'batch-01','critical')}${stat('COLLECTE RÉELLE','Aucune','Aucun accès aux adresses affichées')}</div><section class="panel"><div class="panel-head"><h2>Connectivité du parc</h2><small>Mesures entièrement fictives</small></div><div class="table-wrap"><table><thead><tr><th scope="col">SERVEUR</th><th scope="col">ADRESSE IP</th><th scope="col">RÉSEAU</th><th scope="col">LATENCE</th><th scope="col">SSH</th></tr></thead><tbody>${hosts.map((h,i)=>`<tr><td>${hostLink(h)}</td><td>${h.ip}</td><td>${badge(h.status==='critical'?'critical':'ok',h.status==='critical'?'Sans réponse':'Joignable')}</td><td>${h.status==='critical'?'—':`${2+i%5} ms`}</td><td>${h.status==='critical'?'Non mesuré':'Audit simulé'}</td></tr>`).join('')}</tbody></table></div></section>`;
  if(view==='sources') html=`<div class="cards">${sources.map(([icon,name,detail,count])=>`<article class="panel source"><div class="source-icon" aria-hidden="true">${icon}</div><h2>${name}</h2><p>${detail}</p><span class="badge">Source simulée</span><p>${count}</p></article>`).join('')}</div>`;
  $('#content').innerHTML=html;
  if(view==='servers')serverRows();
}
function showHost(name){
  const h=hosts.find(item=>item.name===name);if(!h)return;
  $('#dialog-title').textContent=h.name;
  $('#dialog-content').innerHTML=`<dl class="detail-grid"><div><dt>Rôle</dt><dd>${h.role}</dd></div><div><dt>État simulé</dt><dd>${badge(h.status)}</dd></div><div><dt>Adresse de documentation</dt><dd>${h.ip}</dd></div><div><dt>Environnement</dt><dd>${h.env}</dd></div><div><dt>CPU</dt><dd>${metric(h.cpu)}</dd></div><div><dt>Mémoire</dt><dd>${metric(h.ram)}</dd></div><div><dt>Source principale</dt><dd>${h.source}</dd></div><div><dt>Services documentés</dt><dd>${h.services}</dd></div></dl><div class="demo-note">Fiche fictive. Aucun accès SSH ni appel API vers ce serveur.</div>`;
  $('#server-dialog').showModal();
}
document.addEventListener('click',event=>{
  const nav=event.target.closest('[data-view]');if(nav){view=nav.dataset.view;render();$('#content').focus();}
  const host=event.target.closest('[data-host]');if(host)showHost(host.dataset.host);
});
document.addEventListener('input',event=>{if(event.target.id==='search'){query=event.target.value;serverRows();}});
document.addEventListener('change',event=>{if(event.target.id==='status-filter'){filter=event.target.value;serverRows();}});
$('#close-dialog').addEventListener('click',()=>$('#server-dialog').close());
$('#refresh').addEventListener('click',()=>{
  simulation++;hosts.forEach((h,i)=>{if(h.status==='ok')h.cpu=6+(i*7+simulation*3)%40;});
  render();$('#snapshot').textContent=`Simulation ${simulation} · ${new Date().toLocaleTimeString('fr-FR')}`;
});
function setTheme(theme){document.documentElement.dataset.theme=theme;$('#theme').setAttribute('aria-label',theme==='dark'?'Activer le thème clair':'Activer le thème sombre');}
try{setTheme(localStorage.getItem('opscontrol-demo-theme')==='light'?'light':'dark');}catch{setTheme('dark');}
$('#theme').addEventListener('click',()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';setTheme(theme);try{localStorage.setItem('opscontrol-demo-theme',theme);}catch{}});
render();
