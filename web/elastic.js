// Cluster-level facts: no inference about individual indices or recoverability.
subtitles.Elasticsearch='Santé du cluster et allocation des shards, avec date et source de chaque collecte.';
let elasticSources=[];
function elasticMarkup(){
 return elasticSources.map(c=>{
  const r=sourceResult(c), v=r.indicators||{}, fresh=sourceFresh(r);
  const health={green:['ok','Vert — primaires et réplicas alloués'],yellow:['warning','Jaune — des réplicas ne sont pas alloués'],red:['critical','Rouge — des primaires ne sont pas alloués']}[v.cluster_status];
  const metrics=[['Nœuds',v.number_of_nodes],['Nœuds de données',v.number_of_data_nodes],['Shards actifs',v.active_shards],['Shards non alloués',v.unassigned_shards],['Shards actifs (%)',v.active_shards_percent_as_number==null?null:Math.round(v.active_shards_percent_as_number*100)/100]];
  return '<section class="panel"><div class="panel-head"><h2>'+esc(c.name)+'</h2><button data-elastic-collect="'+escAttr(c.key)+'" '+(c.auth_configured===false?'disabled':'')+'>Collecter ce cluster</button></div><p>'+esc(c.url)+'</p>'+sourceStatus(c)+(r.error?'<p role="alert">'+esc(r.error)+'</p>':'')+'<p class="badge '+(fresh&&health?health[0]:'unknown')+'">'+esc(health?health[1]:'Santé non mesurée')+(fresh?'':' · état non actuel')+'</p><div class="stats">'+metrics.map(([label,value])=>'<div class="card"><small>'+esc(label)+'</small><strong>'+esc(value??'Non mesuré')+'</strong></div>').join('')+'</div><p class="note">Le nombre de shards non alloués ne donne pas le nombre de serveurs ou d’index sans sauvegarde. La cause nécessite un diagnostic d’allocation.</p><details><summary>Diagnostic à consulter dans Kibana Dev Tools (lecture seule)</summary><pre>GET _cluster/allocation/explain\nGET _cat/allocation?v</pre></details></section>';
 }).join('')||'<section class="panel"><h2>Aucune connexion Elasticsearch</h2><button data-go="Connexions API">Configurer une source</button></section>';
}
async function loadElastic(){
 const target=$('#elastic-data'); if(!target)return;
 try{const sources=await api(sourceUrl('Elasticsearch'));if(!target.isConnected)return;elasticSources=sources.filter(c=>c.provider==='Elasticsearch');const signature=JSON.stringify(elasticSources)+String(elasticSources.map(c=>sourceFresh(sourceResult(c))));if(target.dataset.signature!==signature){target.dataset.signature=signature;target.innerHTML=elasticMarkup();}}
 catch(e){if(target.isConnected)target.textContent=e.message;}
}
pageRenderers.Elasticsearch=function(){$('#content').innerHTML='<div id="elastic-data" aria-live="polite">Chargement…</div>';loadElastic();};
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('[data-elastic-collect]');if(!b)return;
 b.disabled=true;
 try{await post('/api/connections/'+encodeURIComponent(b.dataset.elasticCollect)+'/collect');await loadElastic();}
 catch(error){$('#error').textContent=error.message;}
 finally{if(b.isConnected)b.disabled=false;}
});

// Enregistrement aupres du socle : app.js n'a pas a connaitre ce module.
sourceLoaders['Elasticsearch']=loadElastic;
