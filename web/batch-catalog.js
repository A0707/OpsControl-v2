// Référentiel des batchs métier (data/batch_catalog.yaml) rapproché des observations.
// Vues « Référentiel », « Écarts » et « Non référencés » de la page Batch / Planification.
// Lecture seule : aucune action sur les serveurs, seulement des constats datés.
const catalogLabels={failed:'Échec',drift:'Écart',running:'En cours',ok:'Conforme',unknown:'À confirmer',stopped:'Arrêté comme prévu'};
const catalogColors={failed:'critical',drift:'warning',running:'observed',ok:'ok',unknown:'unknown',stopped:'unknown'};
const catalogRank={failed:0,drift:1,running:2,unknown:3,ok:4,stopped:5};
const catalogLevel={critical:'critical',warning:'warning',info:'unknown'};
const catalogViews=['catalog','runs','gaps','unreferenced'];

// Vue « Exécutions » : un batch par ligne, début, fin, durée, résultat et incident.
// Un échec ou un passage quotidien manqué ouvre un incident (source Batch du
// journal des incidents), résolu au passage réussi suivant.
function catalogDuration(s){if(s==null)return '—';s=Number(s);return s<60?s+' s':s<3600?Math.floor(s/60)+' min '+(s%60)+' s':Math.floor(s/3600)+' h '+Math.floor(s%3600/60)+' min';}
function catalogRuns(entries){
 const at=e=>(e.outcome&&(e.outcome.started_at||e.outcome.finished_at||e.outcome.at))||0;
 const rows=entries.slice().sort((a,b)=>Number(!!b.outcome)-Number(!!a.outcome)||at(b)-at(a)||a.nom.localeCompare(b.nom,'fr'));
 return '<div class="table"><table><caption class="note">Heures du serveur batch. Début inconnu quand seul le journal est lu (il ne date que sa dernière écriture).</caption><thead><tr>'+['Batch','Serveur','Début d’exécution','Fin','Durée','Résultat','Cause','Incident'].map(x=>'<th scope="col">'+x+'</th>').join('')+'</tr></thead><tbody>'+rows.map(e=>{
  const o=e.outcome||{},missed=e.findings.some(f=>f.text.includes('lancement manqué')),incident=o.verdict==='failed'||missed;
  return '<tr data-batch-run="'+escAttr(e.id)+'"><td><b>'+esc(e.nom)+'</b><small>'+esc(e.horaire?'Attendu : '+e.horaire:'Horaire non renseigné')+'</small></td><td>'+(e.host_key?'<button class="link" data-host="'+escAttr(e.host_key)+'">'+esc(e.host_name)+'</button>':esc(e.host_name))+'</td>'+
   '<td>'+esc(o.started_at?catalogEpoch(o.started_at):e.outcome?'Non mesuré':'—')+'</td><td>'+esc(o.verdict==='running'?'En cours':o.finished_at?catalogEpoch(o.finished_at):'—')+'</td><td>'+esc(catalogDuration(o.duration))+'</td>'+
   '<td>'+(e.outcome?'<span class="badge '+outcomeColors[o.verdict]+'">'+esc(outcomeLabels[o.verdict]||'Inconnu')+'</span><small>'+esc(o.source)+'</small>':'<span class="badge unknown">Non mesuré</span>')+'</td>'+
   '<td class="batch-wrap">'+(o.verdict==='failed'?'<small class="batch-cause">'+esc(o.reason)+'</small>':missed?'<small>'+esc(e.findings.find(f=>f.text.includes('lancement manqué')).text)+'</small>':'')+'</td>'+
   '<td>'+(incident?'<span class="badge '+(o.verdict==='failed'?'critical':'warning')+'">Incident ouvert</span><button class="link" data-go="Incidents">Voir les incidents</button>':'—')+'</td></tr>';
 }).join('')+'</tbody></table></div>';
}

function catalogEpoch(s){return s?new Date(s*1000).toLocaleString('fr-FR'):'Non mesuré';}
// Résultat du dernier passage et sa cause : enveloppe (code + fin de sortie
// d'erreur), Zabbix (code), ou journal du batch (verdict déduit, moins sûr).
const outcomeLabels={success:'Réussi',failed:'Échec',running:'En cours',unknown:'Inconnu'};
const outcomeColors={success:'ok',failed:'critical',running:'observed',unknown:'unknown'};
function catalogLines(lines){return lines&&lines.length?'<pre class="batch-lines">'+lines.map(esc).join('\n')+'</pre>':'';}
function catalogResult(e){
 const o=e.outcome,l=e.log;
 const running=e.running.length?'<small>Processus en cours : PID '+esc(e.running[0].pid)+' · depuis '+esc(e.running[0].elapsed_seconds)+' s</small>':'';
 if(!o)return '<span class="badge unknown">Non mesuré</span>'+running+'<small>'+(l?'Journal illisible':'Ni journal lisible ni enveloppe infraops-batch-report')+'</small>';
 const why='<details><summary>Pourquoi</summary><p>'+esc(o.reason)+'</p>'+catalogLines(o.lines)+
  (l?'<p class="batch-wrap">Journal : '+esc(l.path)+(l.mtime?' · modifié le '+esc(catalogEpoch(l.mtime)):'')+'</p><p class="note">'+esc(l.why||'')+(o.source==='Journal du batch'?' · verdict déduit du contenu ('+esc(l.strength||'aucun marqueur reconnu')+')':'')+'</p>':'')+
  '<p class="note">Lignes masquées (mots de passe, jetons) ; extrait borné, jamais le fichier complet.</p></details>';
 return '<span class="badge '+outcomeColors[o.verdict]+'">'+esc(outcomeLabels[o.verdict]||'Inconnu')+'</span>'+
  '<small>'+esc(o.source)+'</small>'+(o.at?'<small>'+esc(o.verdict==='running'?'Début : ':'Fin : ')+esc(catalogEpoch(o.at))+(o.duration!=null?' · '+esc(o.duration)+' s':'')+'</small>':'')+
  (o.verdict==='failed'?'<small class="batch-cause">'+esc(o.reason)+'</small>':'')+running+why;
}
function catalogScripts(e){
 const presence=e.script_present===true?'<span class="badge ok">Présent</span>'+(e.script_mtime?'<small>Modifié le '+esc(catalogEpoch(e.script_mtime))+'</small>':''):e.script_present===false?'<span class="badge warning">Introuvable</span>':'';
 return (e.scripts.length?e.scripts.map(s=>'<small class="batch-wrap">'+esc(s)+'</small>').join(''):'<small>Script non renseigné</small>')+presence+
  (e.properties||e.envoi_mail?'<details><summary>Configuration</summary>'+(e.properties?'<p class="batch-wrap">'+esc(e.properties)+'</p>':'')+(e.envoi_mail?'<p>Envoi de mail : '+esc(e.envoi_mail)+'</p>':'')+'</details>':'');
}
function catalogSchedule(e){
 const obs=e.observed_schedules.map(c=>'<small>Cron : '+esc(c.schedule)+' · '+esc(c.owner||'compte non mesuré')+'</small>').join('');
 const cls=e.planning==='Concordant'?'ok':e.planning==='Différent'?'warning':'unknown';
 return esc(e.horaire||'Non renseigné')+obs+'<small><span class="badge '+cls+'">'+esc(e.planning)+'</span></small>';
}
function catalogReference(e){
 const dates=[e.mise_en_production&&'MEP '+e.mise_en_production,e.migration&&'Migration '+e.migration].filter(Boolean).join(' · ');
 return esc(e.statut||'Statut non renseigné')+(e.attendu==='arrete'?'<small><span class="badge warning">Arrêt demandé</span></small>':'')+(e.validation?'<small>Validation : '+esc(e.validation)+'</small>':'')+(dates?'<small>'+esc(dates)+'</small>':'')+(e.criticite!=null?'<small>Criticité : '+esc(e.criticite)+'</small>':'')+(e.commentaire?'<small class="batch-wrap">'+esc(e.commentaire)+'</small>':'');
}
function catalogTable(entries){
 return '<div class="table"><table><caption class="note">Attendu : référentiel. Observé : inventaire SSH et résultats Zabbix, datés. Aucun batch ne peut être lancé ni arrêté depuis cette page.</caption><thead><tr>'+['Batch','Serveur','Script et configuration','Horaire attendu / observé','Dernier résultat','Référentiel','Constats'].map(x=>'<th scope="col">'+x+'</th>').join('')+'</tr></thead><tbody>'+entries.map(e=>'<tr data-batch-entry="'+escAttr(e.id)+'"><td><b>'+esc(e.nom)+'</b><small>Responsable : '+esc(e.responsable||'non renseigné')+'</small>'+(e.langage?'<small>'+esc(e.langage)+'</small>':'')+'</td><td>'+(e.host_key?'<button class="link" data-host="'+escAttr(e.host_key)+'">'+esc(e.host_name)+'</button><small class="ip">'+esc(e.serveur)+'</small>':esc(e.host_name))+(e.collected_at?'<small>Relevé '+stamp(e.collected_at)+'</small>':'')+'</td><td>'+catalogScripts(e)+'</td><td class="batch-wrap">'+catalogSchedule(e)+'</td><td>'+catalogResult(e)+'</td><td>'+catalogReference(e)+'</td><td><span class="badge '+catalogColors[e.state]+'">'+esc(catalogLabels[e.state])+'</span>'+(e.findings.length?'<ul class="batch-findings">'+e.findings.map(f=>'<li><span class="badge '+catalogLevel[f.level]+'">'+esc({critical:'Grave',warning:'Écart',info:'À compléter'}[f.level])+'</span> '+esc(f.text)+'</li>').join('')+'</ul>':'')+'</td></tr>').join('')+'</tbody></table></div>';
}
function catalogUnreferenced(rows){
 if(!rows.length)return '<p>Aucun batch de /var/batch observé hors référentiel. Une crontab non lue peut en cacher : vérifier la couverture.</p>';
 return '<div class="table"><table><thead><tr>'+['Traitement','Serveur','Type','Planification / compte'].map(x=>'<th scope="col">'+x+'</th>').join('')+'</tr></thead><tbody>'+rows.map(r=>'<tr><td><b>'+esc(r.name)+'</b>'+(r.script?'<small class="batch-wrap">'+esc(r.script)+'</small>':'')+'</td><td>'+(r.host_key?'<button class="link" data-host="'+escAttr(r.host_key)+'">'+esc(r.host_name)+'</button>':esc(r.host_name))+'</td><td>'+esc(r.kind==='zabbix'?'Résultat Zabbix':r.kind)+'</td><td>'+esc(r.schedule||'—')+'<small>'+esc(r.owner||'')+'</small></td></tr>').join('')+'</tbody></table></div>';
}
function renderBatchCatalog(target){
 const c=batchData.catalog||{},counts=c.counts||{},card=(label,value,note)=>'<div class="workload-card"><span>'+label+'</span><strong>'+value+'</strong><small>'+note+'</small></div>';
 if(!c.available){
  $('#batch-summary').innerHTML='';
  target.innerHTML='<section class="panel"><h3>Référentiel des batchs indisponible</h3><p>'+esc(c.error||'Référentiel non chargé.')+'</p><p class="note">Le référentiel reste hors Git (data/batch_catalog.yaml). L’inventaire relevé reste consultable dans les autres vues.</p></section>';
  return;
 }
 const q=batchSearch.toLowerCase();
 const entries=(c.entries||[]).filter(e=>(!batchHost||e.host_key===batchHost)&&(!q||[e.nom,e.responsable,e.serveur,e.host_name,e.scripts.join(' '),e.horaire,e.commentaire,e.statut].join(' ').toLowerCase().includes(q)));
 const unref=(c.unreferenced||[]).filter(r=>(!batchHost||r.host_key===batchHost)&&(!q||[r.name,r.script,r.host_name].join(' ').toLowerCase().includes(q)));
 $('#batch-summary').innerHTML=card('Batchs référencés',counts.total||0,(counts.stopped||0)+' arrêtés comme prévu')+card('Échecs et écarts',(counts.failed||0)+(counts.drift||0),'Dernier passage en échec, script absent, horaire différent…')+card('Résultat mesuré',(counts.measured||0)+' / '+(counts.total||0),'Enveloppe, Zabbix ou journal lisible')+card('Planification non vérifiable',counts.unverifiable||0,'Crontab root non lue par le compte d’audit')+card('Non référencés',(c.unreferenced||[]).length,'Batchs observés absents du référentiel');
 let body;
 if(batchView==='unreferenced')body=catalogUnreferenced(unref);
 else if(batchView==='runs')body='<p role="status">'+entries.filter(e=>e.outcome).length+' batch(s) avec un passage mesuré sur '+entries.length+'</p>'+(entries.length?catalogRuns(entries):'<p>Aucun batch ne correspond à la recherche.</p>');
 else{
  const rows=(batchView==='gaps'?entries.filter(e=>e.findings.some(f=>f.level!=='info')||e.state==='failed'):entries).slice().sort((a,b)=>(catalogRank[a.state]??9)-(catalogRank[b.state]??9)||a.nom.localeCompare(b.nom,'fr'));
  body='<p role="status">'+rows.length+' batch(s) sur '+(c.entries||[]).length+' du référentiel</p>'+(rows.length?catalogTable(rows):'<p>'+(batchView==='gaps'?'Aucun écart mesuré pour cette sélection. Un batch « à confirmer » n’est pas pour autant conforme.':'Aucun batch ne correspond à la recherche.')+'</p>');
 }
 const servers=(c.servers||[]).map(s=>esc(s.name)+' : '+(s.collected_at?'relevé '+stamp(s.collected_at):'non collecté')+' · crontabs lues : '+esc(s.crontabs_read?s.crontabs_read.join(', ')||'aucune':'non mesuré')+' · scripts vérifiés : '+(s.files_checked?'oui':'non')+' · journaux lus : '+esc(s.logs_read??0)+' · passages enveloppés : '+esc(s.runs_count??0)).join('<br>');
 target.innerHTML='<section class="panel">'+body+(counts.unverifiable?'<p class="note">Les batchs de /var/batch sont planifiés dans la crontab de root (et de batchuser) : sans lecture root, leur planification ne peut être ni confirmée ni infirmée. Voir deploy/batch-setup.md pour une lecture restreinte et l’enveloppe infraops-batch-report (résultat de chaque passage).</p>':'')+'<details><summary>Couverture des serveurs batch</summary><p>'+(servers||'Aucun serveur du référentiel dans l’inventaire.')+'</p><p class="note">Source : '+esc(c.source||'')+'</p></details></section>';
}
