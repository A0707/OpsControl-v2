// Présentation des preuves de stockage ; aucune collecte pendant la navigation.
const storageChoices = new Map();
const storageLabels = {ok:'Mesuré', critical:'Critique', warning:'Alerte', preventive:'Préventif', unknown:'Non mesuré', info:'Technique', accessible:'Accessible', stale:'Injoignable', failed:'En échec'};
function storageBadge(level, stale=false) {
  const safe = Object.hasOwn(storageLabels, level) ? level : 'unknown';
  const tone = {accessible:'ok',stale:'critical',failed:'critical'}[safe]||safe;
  return '<span class="badge '+(stale?'unknown':tone)+'">'+(stale?'Ancien · ':'')+esc(storageLabels[safe])+'</span>';
}
function storageSize(kb) {
  if (kb==null || !Number.isFinite(Number(kb)) || Number(kb)<0) return 'Non mesuré';
  const units=['Kio','Mio','Gio','Tio','Pio']; let n=Number(kb), i=0;
  while(n>=1024 && i<units.length-1){n/=1024;i++;}
  return n.toLocaleString('fr-FR',{maximumFractionDigits:1})+' '+units[i];
}
function storageCount(n){return n==null?'Non mesuré':Number(n).toLocaleString('fr-FR');}
function storagePct(n){return n==null?'Non mesuré':esc(n)+' %';}
function storageGauge(pct, level, stale=false) {
  if(pct==null)return '<span class="mini">Non mesuré</span>';
  const cls=!stale&&['critical','warning'].includes(level)?level:'';
  return '<div class="metric'+(stale?' stale':'')+'"><span>'+storagePct(pct)+'</span><div class="meter '+cls+'" role="img" aria-label="Occupation '+escAttr(pct)+' %"><i data-fill="'+escAttr(pct)+'"></i></div></div>';
}
function storageTable(headers, rows) {
  return '<div class="table"><table><thead><tr>'+headers.map(h=>'<th scope="col">'+esc(h)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(c=>'<td>'+(c==null?'—':c)+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>'+(rows.length?'':'<p class="note">Non renseigné par ce relevé : absence ou collecte indisponible à vérifier dans les preuves.</p>');
}
function storageAssessment(host) {
  // Ancien relevé : les seuils restent exclusivement évalués par le serveur.
  return host.storage_assessment || {volumes:((host.storage||{}).filesystems||[]).map(v=>({...v,severity:'unknown',capacity_severity:'unknown',inode_severity:'unknown',reasons:['Évaluation non disponible : actualiser les données de la fiche.']})),fresh:false,history:[],collected_at:(host.storage||{}).collected_at||host.collected_at};
}
function storageChoice(host){if(!storageChoices.has(host.key))storageChoices.set(host.key,{section:'volumes',query:'',mount:''});return storageChoices.get(host.key);}
function storageVolume(v, fresh) {
  return '<article class="storage-volume"><div class="panel-head"><h3>'+esc(v.mount)+'</h3>'+storageBadge(v.severity,!fresh)+'</div><p class="mini storage-identity">'+esc(v.device||'Périphérique non identifié')+' · '+esc(v.fstype||'Type inconnu')+(v.remote?' · Distant':'')+'</p><div class="storage-measures"><div><h4>Capacité</h4>'+storageGauge(v.use_pct,v.capacity_severity,!fresh)+'<p><b>'+esc(storageSize(v.available_kb))+'</b> disponibles</p><p class="mini">Utilisé : '+esc(storageSize(v.used_kb))+' · Total : '+esc(storageSize(v.total_kb))+'</p></div><div><h4>Inodes</h4>'+storageGauge(v.inodes_use_pct,v.inode_severity,!fresh)+'<p><b>'+esc(storageCount(v.inodes_free))+'</b> libres</p><p class="mini">Utilisés : '+esc(storageCount(v.inodes_used))+' · Total : '+esc(storageCount(v.inodes_total))+'</p></div></div>'+(v.reasons||[]).map(r=>'<p class="note">'+esc(r)+'</p>').join('')+'<button data-storage-history="'+escAttr(v.mount)+'">Historique de ce volume</button></article>';
}
function storageVolumes(host) {
  const a=storageAssessment(host),q=storageChoice(host).query.toLocaleLowerCase('fr-FR');
  const matches=(a.volumes||[]).filter(v=>[v.mount,v.device,v.fstype].join(' ').toLocaleLowerCase('fr-FR').includes(q));
  const useful=matches.filter(v=>!v.technical),technical=matches.filter(v=>v.technical);
  return '<div class="storage-volume-grid">'+useful.map(v=>storageVolume(v,a.fresh)).join('')+'</div>'+(technical.length?'<details class="storage-technical"><summary>Volumes techniques ('+technical.length+') · exclus du maximum utile</summary><div class="storage-volume-grid">'+technical.map(v=>storageVolume(v,a.fresh)).join('')+'</div></details>':'')+(matches.length?'':'<p class="empty">Aucun volume renseigné pour ce filtre.</p>');
}
function storageShares(host) {
  const d=host.storage||{},a=storageAssessment(host);
  return '<h3>Partages consommés par ce serveur</h3>'+storageTable(['Montage','Source / type','Accessibilité observée','Options configurées','Occupation / disponible'],(d.remote_shares||[]).map(v=>[esc(v.mount),esc(v.source)+'<small>'+esc(v.fstype)+'</small>',storageBadge(v.status,!a.fresh)+(v.error_kind?'<small>'+esc({timeout:'Délai de sonde dépassé',probe_error:'Échec de sonde : cause non établie',unavailable:'Ancien constat sans cause précise'}[v.error_kind]||v.error_kind)+'</small>':''),v.access==='read-only'?'ro · lecture seule':'rw · lecture / écriture',storagePct(v.use_pct)+' / '+esc(storageSize(v.available_kb))]))+'<p class="note">ro/rw décrit le montage. Les droits effectifs de l’application et une écriture fonctionnelle ne sont pas testés. Un délai dépassé ne prouve pas la cause de la panne.</p><h3>Partages déclarés sur ce serveur</h3>'+storageTable(['Protocole','Chemin','Clients autorisés / nom du partage','Volume porteur'],(d.exports||[]).map(v=>[esc(v.protocol),esc(v.path),esc(v.clients||v.name||'Non renseigné'),esc(v.filesystem||'Non rapproché')]))+'<p class="note">Déclarations NFS/Samba : les clients autorisés ne sont pas des sessions actives. '+(d.exports==null?'Ancienne sonde ou section non collectée.':'La configuration et le service réellement actif peuvent différer.')+'</p>';
}
function storageTopology(host) {
  const d=host.storage||{};
  return '<h3>Groupes LVM</h3>'+storageTable(['VG','Taille','Libre'],(d.volume_groups||[]).map(v=>[esc(v.name),esc(storageSize(v.size_bytes==null?null:v.size_bytes/1024)),esc(storageSize(v.free_bytes==null?null:v.free_bytes/1024))]))+'<h3>Volumes LVM et thin pools</h3>'+storageTable(['VG / LV','Taille','Pool','Data %','Metadata %','Attributs'],(d.lvm||[]).map(v=>[esc(v.vg)+' / '+esc(v.lv),esc(storageSize(v.size_bytes==null?null:v.size_bytes/1024)),esc(v.pool||'Non renseigné'),storagePct(v.data_pct),storagePct(v.metadata_pct),esc(v.attr)]))+'<h3>Pools ZFS</h3>'+storageTable(['Pool','État déclaré','Occupation','Fragmentation'],(d.zfs||[]).map(v=>[esc(v.pool),esc(v.health),storagePct(v.capacity_pct),storagePct(v.fragmentation_pct)]))+'<h3>Montages observés</h3>'+storageTable(['Montage','Périphérique','Système de fichiers'],(storageAssessment(host).volumes||[]).map(v=>[esc(v.mount),esc(v.device),esc(v.fstype)]))+'<p class="note">Inventaire observé : les liens LV → disque physique, les datasets et snapshots ZFS, RAID et multipath ne sont pas collectés. Un disque de VM ne prouve pas la santé du stockage de son hyperviseur.</p>';
}
function storageHealth(host) {
  const d=host.storage||{},io=d.io||{},a=storageAssessment(host);
  return '<h3>Santé physique (SMART)</h3>'+storageTable(['Disque','État','Preuve / limite'],(d.smart||[]).map(v=>[esc(v.device),storageBadge(v.status,!a.fresh),esc(v.detail)]))+'<p class="note">SMART absent ou inaccessible ne signifie pas disque sain. Le relevé ne couvre pas les contrôleurs RAID et le stockage physique derrière une VM.</p><h3>Entrées / sorties</h3><p>iowait CPU : <b>'+storagePct(io.iowait_pct)+'</b></p>'+storageTable(['Périphérique','Lecture (Kio/s)','Écriture (Kio/s)'],(io.devices||[]).map(v=>[esc(v.device),esc(storageCount(v.read_kbps)),esc(storageCount(v.write_kbps))]))+'<p class="note">Échantillon d’environ une seconde, sans addition entre couches. Les latences, IOPS, files d’attente et tendances I/O ne sont pas mesurées.</p>';
}
function storageHistoryChart(points, field, total, label) {
  const known=points.filter(p=>p[field]!=null);
  if(!known.length)return '<p class="note">'+esc(label)+' : aucune mesure.</p>';
  let paths=[],part=[],prev=null;
  points.forEach((p,i)=>{
    if(prev && (p[total]!==prev[total] || p[field]==null || prev[field]==null)){if(part.length)paths.push(part);part=[];}
    if(p[field]!=null)part.push((20+i*560/Math.max(1,points.length-1)).toFixed(1)+','+(120-p[field]).toFixed(1));
    prev=p;
  });if(part.length)paths.push(part);
  return '<figure class="storage-history-chart"><figcaption>'+esc(label)+' · 0–100 %</figcaption><svg viewBox="0 0 600 150" role="img" aria-label="'+escAttr(label)+' : '+known.length+' mesures, détails dans le tableau"><path class="storage-chart-axis" d="M20 20V120H580"/>'+paths.map(p=>p.length>1?'<polyline points="'+p.join(' ')+'"/>':'<circle cx="'+p[0].split(',')[0]+'" cy="'+p[0].split(',')[1]+'" r="3"/>').join('')+'</svg></figure>';
}
function storageHistory(host) {
  const a=storageAssessment(host),choice=storageChoice(host),hist=a.history||[];
  const identities=new Map();[...(a.volumes||[]),...hist].filter(v=>!v.technical).forEach(v=>identities.set(JSON.stringify([v.mount,v.device]),v));
  const options=[...identities.entries()];let chosen=options.find(([,v])=>v.mount===choice.mount)?.[0]||options[0]?.[0]||'';
  if(choice.identity && identities.has(choice.identity))chosen=choice.identity;
  const volume=identities.get(chosen),observed=hist.filter(v=>v.mount===volume?.mount&&v.device===volume?.device);
  const points=volume?(a.history_timestamps||observed.map(v=>v.at)).map(at=>observed.find(v=>v.at===at)||{at,use_pct:null,inodes_use_pct:null,total_kb:null,inodes_total:null}):[];
  return '<h3>Historique par volume</h3><label>Volume <select id="storage-history-mount">'+options.map(([key,v])=>'<option value="'+escAttr(key)+'" '+(key===chosen?'selected':'')+'>'+esc(v.mount)+' · '+esc(v.device)+'</option>').join('')+'</select></label><p class="note">'+esc(a.history_scope||'Les 20 derniers audits conservés ; aucun historique par volume disponible.')+' Les espacements du graphique représentent les audits successifs. Pas de prévision sans série suffisante.</p><div class="storage-measures">'+storageHistoryChart(points,'use_pct','total_kb','Capacité utilisée')+storageHistoryChart(points,'inodes_use_pct','inodes_total','Inodes utilisés')+'</div>'+storageTable(['Audit SSH','Capacité utilisée','Disponible','Total','Inodes utilisés','Inodes libres'],[...points].reverse().map(v=>[esc(stamp(v.at)),storagePct(v.use_pct),esc(storageSize(v.available_kb)),esc(storageSize(v.total_kb)),storagePct(v.inodes_use_pct),esc(storageCount(v.inodes_free))]));
}
function storageView(host) {
  const a=storageAssessment(host),choice=storageChoice(host),sections=[['volumes','Volumes & inodes'],['shares','Partages'],['topology','Topologie'],['health','Santé & I/O'],['history','Historique']];
  const views={volumes:()=>'<label class="storage-search">Filtrer les volumes <input id="storage-query" maxlength="120" value="'+escAttr(choice.query)+'" placeholder="Montage, périphérique ou type"></label><div id="storage-volume-list">'+storageVolumes(host)+'</div>',shares:()=>storageShares(host),topology:()=>storageTopology(host),health:()=>storageHealth(host),history:()=>storageHistory(host)};
  return '<section class="panel storage-detail">'+(host.storage?.collection_complete===false?'<p role="status" class="instruction">Collecte interrompue : sections incomplètes. Consulter les preuves avant de conclure.</p>':'')+'<div class="panel-head"><h2>Stockage de ce serveur</h2>'+storageBadge(a.fresh?'ok':'unknown',!a.fresh)+'</div><p>Relevé SSH : '+esc(stamp(a.collected_at))+' · '+(a.fresh?'Dernières mesures collectées.':'Anciennes mesures ou relevé absent : état actuel non confirmé.')+'</p><p class="note">'+esc(a.scope||'Une donnée manquante ne prouve pas un état sain.')+' L’actualisation des API ne renouvelle pas les mesures SSH.</p><div class="storage-nav" role="group" aria-label="Vues du stockage">'+sections.map(([key,label])=>'<button data-storage-section="'+key+'" aria-pressed="'+(choice.section===key)+'">'+label+'</button>').join('')+'</div><div class="storage-view">'+views[choice.section]()+'</div><p class="storage-proof"><button data-goto-tab="audit">Voir les preuves et limites de collecte</button></p></section>';
}
function storageApplyGauges(){document.querySelectorAll('#content .meter i[data-fill]').forEach(el=>el.style.setProperty('width',Math.max(0,Math.min(100,Number(el.dataset.fill)||0))+'%'));}
function storageSelected(){return selected&&hostDetail?.key===selected?hostDetail:null;}
// Le filtre ne reconstruit que la liste : le focus et la saisie restent stables.
document.getElementById('content').addEventListener('input',event=>{
  if(event.target.id!=='storage-query')return;const host=storageSelected();if(!host)return;
  storageChoice(host).query=event.target.value.slice(0,120);document.getElementById('storage-volume-list').innerHTML=storageVolumes(host);storageApplyGauges();
});
document.getElementById('content').addEventListener('change',event=>{
  if(event.target.id!=='storage-history-mount')return;const host=storageSelected();if(!host)return;
  storageChoice(host).identity=event.target.value;render();
});
document.getElementById('content').addEventListener('click',event=>{
  const target=event.target.closest('[data-storage-section],[data-storage-history]');if(!target)return;const host=storageSelected();if(!host)return;
  const choice=storageChoice(host);choice.section=target.dataset.storageSection||'history';if(target.hasAttribute('data-storage-history')){choice.mount=target.dataset.storageHistory;choice.identity='';}render();
  document.querySelector('[data-storage-section="'+choice.section+'"]')?.focus();
});
hostSection('storage',10,storageView);
detailRenderers.storage=storageView;
hostSection('performance',30,host=>'<section class="panel"><h2>Processus les plus consommateurs</h2>'+storageTable(['PID','Commande','CPU','Mémoire'],((host.storage||{}).top_processes||[]).map(p=>[esc(p.pid),esc(p.command),storagePct(p.cpu_pct),storagePct(p.mem_pct)]))+'<p class="note">Instantané de l’audit SSH : '+esc(stamp((host.storage||{}).collected_at||host.collected_at))+'.</p></section>');
hostSection('security',20,host=>{const d=host.storage||{};return '<section class="panel"><h2>Sécurité locale</h2>'+storageTable(['Contrôle','Relevé'],[['Pare-feu',esc(d.firewall||'Non mesuré')],['Fail2ban',esc(d.fail2ban||'Non mesuré')],['Échecs SSH (24 h)',esc(storageCount(d.ssh_failed_24h))],['Ports en écoute',esc(storageCount(d.listening_ports))]])+'<p class="note">Instantané de l’audit SSH : '+esc(stamp(d.collected_at||host.collected_at))+'.</p></section>';});
detailAfterRenderers.push(()=>{if(selected&&detailTab==='storage')storageApplyGauges();});
