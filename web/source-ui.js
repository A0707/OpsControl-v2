// Shared source status: collection success and freshness are separate facts.
function sourceResult(connection){
  const last=connection.last_result||{};
  if(last.status==='observed'||!connection.last_success_result)return last;
  // Preserve the observation date; failure never turns old data green.
  return {...connection.last_success_result,status:'unknown',error:last.error,
    last_attempt_at:last.collected_at,retained:true};
}
function sourceFresh(result){
  const age=Date.now()-Date.parse(result.collected_at);
  return result.status==='observed' && Number.isFinite(age) && age>=0 && age<=900000;
}
function sourceStatus(connection){
  const r=sourceResult(connection);
  const auth=connection.auth_configured===false?'Identifiants absents : rechargez cette source dans le lanceur.':'';
  const freshness=sourceFresh(r)?'Données récentes':'Données anciennes, absentes ou collecte en échec';
  return '<div class="source-state" role="status"><span class="badge '+(sourceFresh(r)?'observed':'unknown')+'">'+freshness+'</span><span>'+freshnessMarkup(r.collected_at,'Lecture API',connection.provider==='Zabbix'?30:120)+'</span>'+(r.retained?'<p class="instruction">Dernières données conservées. Tentative en échec : '+esc(stamp(r.last_attempt_at))+'.</p>':'')+(auth?'<p class="instruction">'+esc(auth)+'</p>':'')+'</div>';
}
function linkedServer(names){
  const values=new Set(names.filter(Boolean).map(x=>String(x).toLowerCase().replace(/\.$/,'')));
  const matches=(state?.hosts||[]).filter(h=>[h.key,h.name,h.fqdn,h.ip].some(v=>v&&values.has(String(v).toLowerCase().replace(/\.$/,''))));
  return matches.length===1?'<button class="link" data-host="'+escAttr(matches[0].key)+'">'+esc(matches[0].name)+' · détail serveur</button>':(matches.length?'Association ambiguë':'Non rapproché');
}

// Host details retain source identities instead of mixing API and SSH health.
// Lot 4 : sections enregistrées par onglet (plus d'enveloppe de detailView, plus de
// sections ajoutées sous tous les onglets).
// Avertissements de validité des preuves : visibles quel que soit l'onglet.
hostNotices.push(host=>{
 const attempt=host.last_attempt;
 return (attempt?'<section class="host-notice" role="status"><h2>Dernière tentative SSH en échec</h2><p>'+stamp(attempt.collected_at)+' · Les mesures affichées restent celles du '+stamp(host.collected_at)+'.</p>'+(attempt.issues||[]).map(issue=>'<p>'+esc(issue)+'</p>').join('')+'</section>':'')+
  (host.configuration_changed?'<section class="host-notice" role="status"><h2>Configuration modifiée depuis cet audit</h2><p>Les anciennes mesures sont conservées. Un nouvel audit est nécessaire pour valider la configuration actuelle.</p></section>':'');
});
// Performances : mesures de la VM vues par l'hyperviseur, jamais substituées aux mesures SSH.
hostSection('performance',20,host=>{
 const linked=state?.hosts.find(h=>h.key===host.key);
 const guests=host.proxmox_matches||linked?.proxmox_matches||[];
 if(guests.length===1){
   const g=guests[0];
   return '<section class="panel server-secondary"><h2>Mesures API Proxmox de ce serveur</h2><p>'+esc(g.cluster)+' / '+esc(g.node)+' · VM '+esc(g.vmid)+' · '+esc(g.status)+' · '+stamp(g.collected_at)+' · '+(g.fresh?'Récent':'Ancien ou collecte en échec')+'</p><div class="stats">'+[
     ['CPU VM',pct(g.cpu_pct)],['RAM utilisée / allouée',ui.bytes(g.memory_bytes)+' / '+ui.bytes(g.memory_total_bytes)],['Capacité disque allouée',ui.bytes(g.disk_capacity_bytes)]
   ].map(([label,value])=>'<div class="card"><small>'+esc(label)+'</small><strong>'+esc(value)+'</strong></div>').join('')+'</div><p class="note">Source : hyperviseur Proxmox. La capacité allouée ne mesure pas le remplissage des disques dans le serveur. Les contrôles système nécessitent un audit SSH.</p></section>';
 }
 if(guests.length>1)return '<section class="panel server-secondary"><h2>Mesures API Proxmox</h2><p>Plusieurs VM correspondent à ce serveur : association à vérifier.</p></section>';
 return '<section class="panel server-secondary"><h2>Mesures API Proxmox</h2><p>Aucune VM associée sans ambiguïté : aucune mesure d’hyperviseur n’est affichée.</p></section>';
});
// Audit : état de l'audit enregistré, preuves brutes par source et rattachements.
hostSection('audit',10,host=>'<section class="panel server-secondary"><h2>Audit SSH enregistré</h2><p>'+esc(host.audit_recorded?'Conservé ; actualisation manuelle disponible.':'Audit initial à réaliser ou couverture non mesurée.')+' · '+stamp(host.collected_at)+'</p><p>Les données SSH décrivent cette date, pas nécessairement l’état actuel.</p><p>'+esc((host.audit_versions||[]).length)+' version(s) conservée(s).</p></section>');
hostSection('audit',40,host=>'<section class="panel server-secondary"><h2>Données API de ce serveur</h2>'+(host.source_details||[]).map(s=>{
   const e=s.evidence||{};
   let content='<p>'+esc(s.scope)+'</p>';
   if(e.agent)content+='<p>Agent Wazuh : '+esc(e.agent.name)+' · '+esc(e.agent.status)+' · version '+esc(e.agent.version||'Non mesurée')+'</p>';
   if(e.host)content+='<p>Zabbix : '+esc(e.host.status)+' · '+esc(e.problems_measured===false?'Non mesuré':(e.problems||[]).length)+' problème(s)</p>'+(e.problems_scope?'<p>'+esc(e.problems_scope)+'</p>':'')+(e.problems||[]).map(p=>'<p>'+esc(p.description)+'</p>').join('');
   if(e.recent_jobs)content+='<p>'+esc(e.jobs_count)+' jobs distincts associés. Dernier passage des dix plus récents :</p>'+e.recent_jobs.map(j=>'<p>'+esc(j.name)+' · '+esc(j.status_label)+' · '+esc(j.endtime||'Fin non mesurée')+'</p>').join('');
   return '<article><h3>'+esc(s.provider)+'</h3><p>'+stamp(s.collected_at)+' · '+(s.fresh?'Récent':'Ancien ou collecte en échec')+'</p>'+content+(s.error?'<p>'+esc(s.error)+'</p>':'')+'</article>';
 }).join('')+'<p class="note">Une source absente ici est non rapprochée ou non mesurée. Wazuh décrit ici l’agent ; les événements de sécurité ne sont pas collectés. La santé globale Elastic ne prouve pas la réception des logs de ce serveur.</p></section>');
hostSection('audit',60,host=>{
 const linked=state?.hosts.find(h=>h.key===host.key);
 if(!linked)return '';
 return '<section class="panel server-secondary"><h2>Rattachements de ce serveur</h2><p>Périmètre actif : '+esc(linked.active_scope?'Inclus':linked.scope_reason)+'</p><p>Sources associées : '+esc((linked.source_links||[]).map(s=>s.provider+(s.fresh?'':' · ancien')).join(', ')||'Aucune association documentée')+'</p><p class="note">L’état de chaque source, avec sa date, figure dans la Synthèse (rapprochement des sources).</p></section>';
});
