subtitles.Synchronisation='Inventaire rapproché, fraîcheur des sources et collecte API, SSH et réseau.';
pageRenderers.Synchronisation=function(){
 $('#content').innerHTML='<section class="panel"><div class="panel-head"><h2>Synchroniser l’infrastructure</h2><button id="sync-all" class="primary">Collecter API + SSH + réseau</button></div><p>Actualisation : API et réseau périodiques ; SSH initial uniquement pour les serveurs sans audit enregistré. Ce bouton relance volontairement tous les audits. Les accès SSH utilisent la configuration et les empreintes déjà vérifiées.</p></section><div id="sync-data">Chargement…</div>';
 loadSync();
};
// Une réponse partielle (champ retiré par l'allègement, serveur d'une autre version) ne doit
// ni lever d'exception ni passer pour une liste vide : « Non fourni » le dit explicitement.
const syncList=v=>Array.isArray(v)?v:null;
async function loadSync(){
 const target=$('#sync-data');if(!target)return;
 try{
  const d=await api('/api/sync');if(!target.isConnected)return;
  const job=d.job||{},sources=syncList(d.sources),assets=syncList(d.assets),guests=syncList(d.unmatched_guests),missing=syncList(d.missing_providers);
  const row=h=>{const pm=syncList(h.proxmox_matches);return '<tr><td>'+esc(h.name)+'<br><span class="ip">'+esc(h.ip)+'</span></td><td>'+(pm?pm.map(g=>esc(g.cluster+' / '+g.node+' / '+g.vmid)).join('<br>')||'Non rapproché':'Non fourni')+(h.association==='ambiguous'?'<br>Association ambiguë':'')+'</td><td>'+(pm?pm.map(g=>esc(g.status)+(g.fresh?'':' · Ancien')).join('<br>'):'Non fourni')+'</td><td>'+badge(h.status)+'<br>'+stamp(h.collected_at)+'</td><td>'+esc(h.active_scope?'VM démarrée · ping réussi':h.scope_reason)+'<br>'+stamp(h.network_evidence?.collected_at)+'</td><td>'+esc((h.source_links||[]).map(s=>s.provider+(s.fresh?'':' · ancien')).join(', ')||'Non rapproché')+'</td><td><button data-host="'+escAttr(h.key)+'">Détails et SSH</button></td></tr>'};
  target.innerHTML='<section class="panel"><h2>Sources</h2><p>'+esc('SSH : '+(d.ssh_job?.running?'en cours':'au repos')+' · Réseau : '+(d.network_job?.running?'en cours':'au repos'))+'</p><p>'+(job.running?'Collecte API en cours : ':'Dernier lot API : ')+(job.total==null?'Non fourni':esc(job.completed+' / '+job.total))+'</p>'+(sources?sources.map(s=>'<p><b>'+esc(s.name)+'</b> · '+esc(s.provider)+' · '+stamp(s.collected_at)+' · '+(s.fresh?'Récent':'À actualiser')+(s.error?' · '+esc(s.error):'')+'</p>').join(''):'<p>Sources : non fournies par le serveur.</p>')+'<p>À raccorder : '+esc(missing?missing.join(', ')||'Aucune source manquante':'Non fourni')+'</p>'+(syncList(job.errors)||[]).map(e=>'<p role="alert">'+esc(e.key)+' : '+esc(e.error)+'</p>').join('')+'</section><section class="panel"><h2>Serveurs et VM associés</h2><p>Rapprochement par nom exact ou couple nœud / VMID documenté. Les associations sont à confirmer ; aucune adresse SSH n’est inventée.</p><div class="table"><table><thead><tr><th>Serveur / IP SSH</th><th>Cluster / nœud / VMID</th><th>État API</th><th>Audit SSH / WAF</th><th>Ping / périmètre actif</th><th>Sources associées</th><th>Accès</th></tr></thead><tbody>'+(assets?assets.map(row).join(''):'<tr><td colspan="7">Liste des serveurs non fournie par le serveur.</td></tr>')+'</tbody></table></div></section><section class="panel"><h2>VM à rapprocher ('+(guests?guests.length:'non fourni')+')</h2>'+(guests||[]).map(g=>'<p>'+esc(g.cluster+' / '+g.node+' / '+g.vmid+' · '+g.name+' — '+g.reason)+'</p>').join('')+'</section>';
 }catch(e){if(!target.isConnected)return;const p=document.createElement('p');p.setAttribute('role','alert');p.textContent='Synchronisation indisponible : '+e.message;target.replaceChildren(p)}
}
$('#content').addEventListener('click',async e=>{
 if(!e.target.closest('#sync-all'))return;
 const b=e.target.closest('button');b.disabled=true;
 try{await post('/api/sync');await loadSync()}catch(e){$('#error').textContent=e.message}finally{b.disabled=false}
});
sourceLoaders.Synchronisation=loadSync;
poll('synchronisation',5000,loadSync,{when:()=>page==='Synchronisation'&&!selected});
