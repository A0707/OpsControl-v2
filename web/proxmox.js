subtitles.Proxmox='Pilotage visuel des clusters, nœuds, VM, conteneurs et stockages — collecte API en lecture seule.';
let proxmoxSources=[],proxmoxQuery='',proxmoxMode='overview',proxmoxStatus='',proxmoxType='';
// Filtres V2 : état et type d'invité, combinés à la recherche texte.
const pveGuestFilter=g=>(!proxmoxStatus||g.status===proxmoxStatus)&&(!proxmoxType||g.type===proxmoxType);
const proxmoxExpanded=new Map();

function pveSize(bytes){
 if(bytes==null||!Number.isFinite(Number(bytes)))return 'Non mesuré';
 const units=['o','Kio','Mio','Gio','Tio','Pio'];let value=Number(bytes),index=0;
 while(value>=1024&&index<units.length-1){value/=1024;index++}
 return value.toLocaleString('fr-FR',{maximumFractionDigits:index<3?0:1})+' '+units[index];
}
// Disponible = joignable ; le risque de remplissage est un signal distinct (fiche 07.3).
function pveCapacity(ratio){return ratio==null||ratio<75?'':'<span class="badge '+(ratio>=90?'critical':'warning')+'">'+(ratio>=90?'Presque plein':'Capacité à surveiller')+' · '+ratio.toLocaleString('fr-FR',{maximumFractionDigits:1})+' %</span>'}
function pveRatio(value,total){return value==null||!total?null:Math.max(0,Math.min(100,Number(value)/Number(total)*100))}
function pveDuration(seconds){
 if(seconds==null)return 'Non mesuré';
 const days=Math.floor(seconds/86400),hours=Math.floor(seconds%86400/3600);
 return days?days+' j '+hours+' h':hours+' h';
}
function pveStatus(status,stale){
 const names={online:'En ligne',offline:'Hors ligne',running:'Démarrée',stopped:'Arrêtée',available:'Disponible',unavailable:'Indisponible',unknown:'Inconnu'};
 const classes={online:'ok',offline:'critical',running:'active',stopped:'inactive',available:'ok',unavailable:'critical',unknown:'unknown'};
 return '<span class="badge '+(stale?'unknown':classes[status]||'unknown')+'">'+(stale?'Ancien · ':'')+esc(names[status]||'Inconnu')+'</span>';
}
// Largeur par classe quantifiée (v2.css) : la CSP style-src 'self' bloquait l'ancien style en ligne
// et laissait toutes les jauges vides en production. Piste .oc-gauge (premium.css) : le niveau
// porte la couleur, mêmes seuils que le reste de l'interface (75 / 90 %).
function pveGauge(label,value,detail,tone='blue'){
 const measured=value!=null&&Number.isFinite(Number(value)),bounded=measured?Math.max(0,Math.min(100,Number(value))):0;
 const severity=bounded>=90?'critical':bounded>=75?'warning':tone,level=!measured?'none':bounded>=90?'crit':bounded>=75?'warn':'ok';
 return '<div class="pve-gauge '+severity+'"><div class="pve-gauge-head"><span>'+esc(label)+'</span><strong>'+(measured?bounded.toLocaleString('fr-FR',{maximumFractionDigits:1})+' %':'—')+'</strong></div><div class="pve-gauge-track oc-gauge" data-level="'+level+'" role="img" aria-label="'+escAttr(label)+' '+(measured?bounded+' %':'non mesuré')+'"><i class="v2-w'+Math.round(bounded)+'"></i></div><small>'+esc(detail||'Donnée non visible')+'</small></div>';
}
// Capacité unique (audit UI du 31/10, fiche 07.1) : un stockage partagé visible sur plusieurs
// nœuds n'est compté qu'une fois, comme côté serveur (proxmox_inventory).
function pveUniqueStorages(nodes){const seen=new Map();for(const n of nodes)for(const s of n.storages||[]){const id=s.shared?s.name+'\u0000':s.name+'\u0000'+n.name;if(!seen.has(id))seen.set(id,s)}return [...seen.values()]}
function pveSummary(inv){
 const nodes=inv.nodes||[],guests=nodes.flatMap(n=>n.guests||[]),storages=nodes.flatMap(n=>n.storages||[]),reported=inv.summary||{};
 const sum=(items,key)=>{const values=items.map(x=>x[key]).filter(v=>v!=null&&Number.isFinite(Number(v)));return values.length?values.reduce((a,b)=>a+Number(b),0):null};
 const cpu=reported.cpu_pct??(()=>{const values=nodes.map(n=>n.cpu_pct).filter(v=>v!=null);return values.length?values.reduce((a,b)=>a+b,0)/values.length:null})();
 const memory=reported.memory_bytes??sum(nodes,'memory_bytes'),memoryTotal=reported.memory_total_bytes??sum(nodes,'memory_total_bytes');
 const unique=pveUniqueStorages(nodes),deduped=reported.storage_unique_count!=null,storage=deduped?reported.storage_used_bytes:sum(unique,'used_bytes'),storageTotal=deduped?reported.storage_total_bytes:sum(unique,'total_bytes');
 return {cpu,memory,memoryTotal,storage,storageTotal,
  networkIn:reported.network_in_bytes??sum(guests,'network_in_bytes'),networkOut:reported.network_out_bytes??sum(guests,'network_out_bytes'),
  online:reported.nodes_online??nodes.filter(n=>n.status==='online').length};
}
function pveHero(inv,stale){
 const s=pveSummary(inv),counts=inv.counts||{},totalGuests=(counts.qemu||0)+(counts.lxc||0);
 return '<div class="pve-hero">'
  +'<div class="pve-hero-title"><div><span class="eyebrow">PROXMOX VE · V2</span><h3>'+s.online+' / '+inv.nodes_count+' nœuds en ligne</h3><p>'+totalGuests+' VM & LXC visibles · '+(counts.running||0)+' démarrés · '+(counts.stopped||0)+' arrêtés</p></div><div class="pve-live"><i></i>'+(stale?'Données à actualiser':'État observé')+'</div></div>'
  +'<div class="pve-gauges">'
  +pveGauge('CPU cluster',s.cpu,'Moyenne des nœuds visibles')
  +pveGauge('Mémoire',pveRatio(s.memory,s.memoryTotal),pveSize(s.memory)+' / '+pveSize(s.memoryTotal),'violet')
  +pveGauge('Stockage (capacité unique)',pveRatio(s.storage,s.storageTotal),pveSize(s.storage)+' / '+pveSize(s.storageTotal),'cyan')
  +'<div class="pve-traffic"><span>Trafic cumulé des invités</span><div><b>↓ '+pveSize(s.networkIn)+'</b><b>↑ '+pveSize(s.networkOut)+'</b></div><small>Compteurs fournis par Proxmox, pas un débit instantané.</small></div>'
  +'</div></div>';
}
function pveGuestTable(guests,stale,compact=false){
 const headings=compact?['VMID','Nom','Type','État','CPU','Mémoire','Disque']:['VMID','Nom','Nœud','Type','État','CPU','Mémoire','Disque','E/S disque','Réseau','Uptime','Pool'];
 return '<div class="table pve-table"><table><thead><tr>'+headings.map(x=>'<th>'+x+'</th>').join('')+'</tr></thead><tbody>'+guests.map(g=>{
  const cells=['<td>'+esc(g.vmid)+'</td>','<td><b>'+esc(g.name)+'</b></td>',...(compact?[]:['<td>'+esc(g.node)+'</td>']),'<td>'+esc(g.type==='qemu'?'VM QEMU':'CT LXC')+'</td>','<td>'+pveStatus(g.status,stale)+'</td>','<td>'+pct(g.cpu_pct)+(g.cpu_capacity?' / '+esc(g.cpu_capacity)+' vCPU':'')+'</td>','<td>'+pveSize(g.memory_bytes)+'<small>'+pveSize(g.memory_total_bytes)+' alloués</small></td>','<td>'+(!g.disk_used_bytes&&g.type==='qemu'?'<span class="mini" title="Proxmox ne lit pas le système de fichiers d’une VM QEMU">Non fourni par Proxmox</span>':pveSize(g.disk_used_bytes))+'<small>'+pveSize(g.disk_capacity_bytes)+' alloués</small></td>'];
  if(!compact)cells.push('<td>↓ '+pveSize(g.disk_read_bytes)+'<small>↑ '+pveSize(g.disk_write_bytes)+'</small></td>','<td>↓ '+pveSize(g.network_in_bytes)+'<small>↑ '+pveSize(g.network_out_bytes)+'</small></td>','<td>'+pveDuration(g.uptime_seconds)+'</td>','<td>'+esc(g.pool||'—')+'</td>');
  return '<tr>'+cells.join('')+'</tr>';
 }).join('')+'</tbody></table></div>';
}
// Nœuds repliés par défaut (6 nœuds dépliés faisaient 4 500 px ; la liste complète des VM est dans
// l'onglet « VM & LXC »). Ouverts d'office : nœud à surveiller (hors ligne, mesures absentes ou
// anciennes), recherche active, ou choix de l'opérateur (mémorisé hors recherche).
function pveNodeNeedsAttention(n,stale){return stale||n.status!=='online'||n.reported===false}
function pveNodeOpen(id,n,stale,query){return query?true:proxmoxExpanded.has(id)?proxmoxExpanded.get(id):pveNodeNeedsAttention(n,stale)}
function pveNodeMeta(n){
 const g=n.guests||[],up=g.filter(x=>x.status==='running').length,down=g.filter(x=>x.status==='stopped').length;
 const ram=pveRatio(n.memory_bytes,n.memory_total_bytes),val=v=>v==null?'—':Math.round(v)+' %';
 return '<span class="pve-node-meta">CPU '+val(n.cpu_pct)+' · RAM '+val(ram)+' · '+up+' démarrée(s)'+(down?' · '+down+' arrêtée(s)':'')+'</span>';
}
// Mémorise les nœuds ouverts/fermés par l'opérateur, jamais l'ouverture forcée par une recherche.
let pveNodesQuery='';
function pveRememberNodes(){if(!pveNodesQuery)document.querySelectorAll('[data-pve-node]').forEach(n=>proxmoxExpanded.set(n.dataset.pveNode,n.open))}
function pveNodes(inv,stale,query){
 pveNodesQuery=query;
 let matches=0,html='';
 for(const n of inv.nodes||[]){
  const matchGroup=(n.name+' '+(n.storages||[]).map(s=>s.name).join(' ')).toLowerCase().includes(query);
  const guests=(n.guests||[]).filter(g=>pveGuestFilter(g)&&(!query||matchGroup||(g.name+' '+g.vmid+' '+g.type+' '+(g.pool||'')).toLowerCase().includes(query)));
  if(query&&!matchGroup&&!guests.length)continue;matches++;
  const id=(inv._connectionKey||'')+'|'+n.name,ram=pveRatio(n.memory_bytes,n.memory_total_bytes),disk=pveRatio(n.disk_bytes,n.disk_total_bytes);
  html+='<details class="panel pve-node" data-pve-node="'+escAttr(id)+'" '+(pveNodeOpen(id,n,stale,query)?'open':'')+'><summary><span><b>'+esc(n.name)+'</b> '+pveStatus(n.status,stale)+'</span>'+pveNodeMeta(n)+'<span>'+n.guests.length+' VM / CT · '+pveDuration(n.uptime_seconds)+'</span></summary>'
   +'<div class="pve-node-grid">'+pveGauge('CPU',n.cpu_pct,(n.cpu_capacity||'—')+' cœurs visibles')+pveGauge('RAM',ram,pveSize(n.memory_bytes)+' / '+pveSize(n.memory_total_bytes),'violet')+pveGauge('Disque système',disk,pveSize(n.disk_bytes)+' / '+pveSize(n.disk_total_bytes),'cyan')+'</div>'
   +(n.reported?'':'<p class="note">Nœud déduit de l’affectation des VM ; ses mesures ne sont pas visibles.</p>')
   +pveGuestTable(guests,stale,true)+(guests.length?'':'<p class="empty">Aucune VM visible sur ce nœud pour ces critères.</p>')+'</details>';
 }
 return html||(query?'<div class="panel empty">Aucun nœud ou invité ne correspond à la recherche.</div>':'');
}
function pveGuests(inv,stale,query){
 const guests=(inv.nodes||[]).flatMap(n=>(n.guests||[]).map(g=>({...g,node:n.name}))).filter(g=>pveGuestFilter(g)&&(!query||(g.name+' '+g.vmid+' '+g.type+' '+g.node+' '+(g.pool||'')+' '+(inv.cluster?.name||'')).toLowerCase().includes(query)));
 return '<section class="panel"><div class="panel-head"><h3>Machines virtuelles & conteneurs</h3><span class="mini">'+guests.length+' résultat(s)</span></div>'+pveGuestTable(guests,stale,false)+(guests.length?'':'<div class="empty">Aucun invité visible pour ces critères.</div>')+'</section>';
}
function pveStorages(inv,stale,query){
 const rows=(inv.nodes||[]).flatMap(n=>(n.storages||[]).map(s=>({...s,node:n.name}))).filter(s=>!query||(s.name+' '+s.node+' '+(s.type||'')).toLowerCase().includes(query));
 if(!rows.length)return '<section class="panel empty">Aucun stockage visible. Le jeton peut ne pas avoir le droit Audit sur les stockages.</section>';
 return '<div class="pve-storage-grid">'+rows.map(s=>{const used=pveRatio(s.used_bytes,s.total_bytes),free=s.total_bytes==null||s.used_bytes==null?null:s.total_bytes-s.used_bytes;return '<article class="panel pve-storage"><div class="panel-head"><div><h3>'+esc(s.name)+'</h3><p>'+esc(s.node)+' · '+esc(s.type||'type non mesuré')+'</p></div>'+pveStatus(s.status,stale)+pveCapacity(used)+'</div>'+pveGauge('Occupation',used,pveSize(s.used_bytes)+' / '+pveSize(s.total_bytes),'cyan')+'<div class="pve-storage-meta"><span>'+(s.shared===true?'Partagé':s.shared===false?'Local':'Portée inconnue')+'</span><span>'+pveSize(free)+' disponibles</span></div></article>'}).join('')+'</div>';
}
function proxmoxMarkup(){
 const query=proxmoxQuery.trim().toLowerCase();
 return proxmoxSources.map(c=>{
  const r=sourceResult(c),inv=r.inventory,stale=!sourceFresh(r);
  let html='<section class="panel pve-cluster-head"><div class="panel-head"><div><span class="eyebrow">CLUSTER</span><h2>'+esc(inv?.cluster?.name||c.name)+'</h2><p>Source : '+esc(c.name)+' · collecte '+stamp(r.collected_at)+'</p></div><button class="primary" data-pve-collect="'+escAttr(c.key)+'">↻ Collecter</button></div>'+sourceStatus(c);
  if(r.error)html+='<p role="alert" class="instruction">'+esc(r.error)+'</p>';
  if(!inv)return html+'<p>Aucun inventaire API disponible. Vérifier la connexion puis collecter <code>/api2/json/cluster/resources</code>.</p><button data-go="Connexions API">Configurer la connexion</button></section>';
  inv._connectionKey=c.key;
  html+=(r.warning?'<p class="instruction">'+esc(r.warning)+'</p>':'')+(inv.cluster?'<p class="pve-quorum">Quorum : <b>'+(inv.cluster.quorate===true?'actif':inv.cluster.quorate===false?'inactif':'non mesuré')+'</b></p>':'')+'</section>';
  html+=pveHero(inv,stale);
  if(proxmoxMode==='storage')html+=pveStorages(inv,stale,query);
  else if(proxmoxMode==='guests')html+=pveGuests(inv,stale,query);
  else html+=pveNodes(inv,stale,query);
  return html;
 }).join('')||'<section class="panel"><h2>Aucune connexion Proxmox configurée</h2><p>Ajouter une connexion vers <code>/api2/json/cluster/resources</code>.</p><button data-go="Connexions API">Ajouter une connexion API</button></section>';
}
async function loadProxmox(){
 const target=$('#pve-data');if(!target)return;
 try{const sources=await api(sourceUrl('Proxmox'));if(!target.isConnected)return;proxmoxSources=sources.filter(c=>c.provider==='Proxmox');const signature=JSON.stringify(proxmoxSources)+String(proxmoxSources.map(c=>sourceFresh(sourceResult(c))));if(target.dataset.signature!==signature){target.dataset.signature=signature;target.innerHTML=proxmoxMarkup();}}
 catch(e){if(target.isConnected)target.textContent=e.message}
}
pageRenderers.Proxmox=function(){
 pveRememberNodes();
 $('#content').innerHTML='<section class="panel pve-toolbar"><div><span class="eyebrow">CENTRE DE VIRTUALISATION</span><h2>Infrastructure Proxmox</h2><p>Vue inspirée d’un cockpit Proxmox, alimentée uniquement par des appels API de lecture.</p></div><button data-go="Connexions API">Connexions API</button><div class="tabs pve-tabs" role="group" aria-label="Vues Proxmox">'+[['overview','Vue globale'],['guests','VM & LXC'],['storage','Stockage']].map(([key,label])=>'<button data-pve-mode="'+key+'" aria-pressed="'+(proxmoxMode===key)+'" class="'+(proxmoxMode===key?'active':'')+'">'+label+'</button>').join('')+'</div><div class="pve-search"><label>Rechercher <input id="pve-search" value="'+escAttr(proxmoxQuery)+'" placeholder="Cluster, nœud, VMID, nom, pool, stockage…"></label><label>État <select id="pve-status"><option value="">Tous</option><option value="running" '+(proxmoxStatus==='running'?'selected':'')+'>Démarrés</option><option value="stopped" '+(proxmoxStatus==='stopped'?'selected':'')+'>Arrêtés</option><option value="unknown" '+(proxmoxStatus==='unknown'?'selected':'')+'>Inconnus</option></select></label><label>Type <select id="pve-type"><option value="">VM et LXC</option><option value="qemu" '+(proxmoxType==='qemu'?'selected':'')+'>VM QEMU</option><option value="lxc" '+(proxmoxType==='lxc'?'selected':'')+'>Conteneurs LXC</option></select></label></div><p class="note">Mesures exposées par <code>/cluster/resources</code>. Les droits Audit du jeton déterminent le périmètre visible ; une absence n’est jamais interprétée comme un état sain.</p></section><div id="pve-data">Chargement de l’inventaire API…</div>';
 loadProxmox();
};
$('#content').addEventListener('change',e=>{if(e.target.id!=='pve-status'&&e.target.id!=='pve-type')return;pveRememberNodes();if(e.target.id==='pve-status')proxmoxStatus=e.target.value;else proxmoxType=e.target.value;$('#pve-data').innerHTML=proxmoxMarkup()});
$('#content').addEventListener('input',e=>{if(e.target.id!=='pve-search')return;proxmoxQuery=e.target.value;const total=proxmoxSources.reduce((n,c)=>n+(sourceResult(c).inventory?.nodes||[]).reduce((m,node)=>m+(node.guests||[]).length,0),0);deferLargeRender('pve-search',total>100,()=>{pveRememberNodes();const target=$('#pve-data');if(target)target.innerHTML=proxmoxMarkup()})});
$('#content').addEventListener('click',async e=>{
 const mode=e.target.closest('[data-pve-mode]');if(mode){proxmoxMode=mode.dataset.pveMode;render();return}
 const b=e.target.closest('[data-pve-collect]');if(!b)return;b.disabled=true;b.textContent='Collecte…';
 try{await post('/api/connections/'+encodeURIComponent(b.dataset.pveCollect)+'/collect');await loadProxmox()}catch(error){$('#error').textContent=error.message}finally{b.disabled=false;b.textContent='↻ Collecter'}
});
sourceLoaders['Proxmox']=loadProxmox;
