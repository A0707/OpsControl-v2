// Services du parc : pagination serveur et filtres conservés entre rafraîchissements.
const SVC_PAGE=100;
let svcStatus='failed',svcQuery='',svcFreshness='all',svcOffset=0;
let svcData=null,svcKey='',svcLoadedAt=0,svcLoading=false,svcError='';
function svcParams(){const all=state?.hosts||[],shown=list(),p=new URLSearchParams({status:svcStatus,offset:String(svcOffset),limit:String(SVC_PAGE),freshness:svcFreshness});if(svcQuery)p.set('q',svcQuery);if(shown.length!==all.length)p.set('hosts',shown.map(h=>h.key).join(','));return p.toString();}
async function svcLoad(key){
 if(svcLoading)return;svcLoading=true;svcError='';
 try{const data=await api('/api/services/units?'+key);if(!data||!Array.isArray(data.items))throw Error('Réponse des unités incomplète ou invalide.');svcData=data;svcKey=key;svcLoadedAt=Date.now();}
 catch(error){svcError=error.message;svcKey=key;svcData=null;svcLoadedAt=Date.now();}
 finally{svcLoading=false;if(page==='Services'&&!selected)render();}
}
// Attendu / observé et provenance du niveau (audit UI du 31/10, fiche 04.1) : la colonne
// « Critique : Oui/Non » ne disait ni pourquoi une unité compte, ni si son absence est normale.
const SVC_READINGS={expected_down:'Attendu sur ce serveur, non actif',accessory_failed:'Hors inventaire : service accessoire ou à déclarer',missing_check:'Déclaré, état non relevé : contrôle manquant'};
const SVC_LEVELS={critical:['Critique','critical'],warning:['Visibilité','warning'],preventive:['Maintenance','unknown']};
function svcLevel(u){const [label,tone]=SVC_LEVELS[u.level]||['Non qualifié','unknown'];return '<span class="badge '+tone+'">'+esc(label)+'</span>'+(u.level_source?'<small>'+esc(u.level_source)+'</small>':'');}
function svcCard(label,value,note){return '<div class="workload-card"><span>'+esc(label)+'</span><strong>'+esc(value??'Non mesuré')+'</strong><small>'+esc(note)+'</small></div>';}
serviceView=function(){
 const shown=list();if(!shown.length)return '<section class="panel"><h2>Services observés</h2>'+toolbar()+'<p class="empty">Aucun serveur pour ces critères. Les unités des autres serveurs ne sont pas chargées.</p></section>';
 const key=svcParams();if(key!==svcKey||Date.now()-svcLoadedAt>60000)svcLoad(key);
 const hosts=Object.fromEntries((state?.hosts||[]).map(h=>[h.key,h])),d=svcData&&svcKey===key?svcData:null,s=d?.summary||{};
 if(d&&d.offset&&d.offset>=d.total){svcOffset=0;svcLoad(svcParams());}
 const choices=[['failed','En échec'],['critical','Critiques déclarés'],['active','Actives'],['inactive','Inactives'],['unknown','Non mesurées'],['all','Toutes les unités']];
 const head='<div class="panel-head"><div><h2>Services observés</h2><p>Unités systemd du parc · état système et couverture de collecte</p></div><span class="mini">'+(d?d.total+' unité(s) sélectionnée(s)':'Chargement…')+'</span></div>'+toolbar()+'<div class="workload-cards">'+svcCard('Échecs récents',s.failed_recent,'Une ancienne panne reste à reconfirmer')+svcCard('Attendus non actifs',s.expected_down,'Déclarés pour le serveur, pas actifs')+svcCard('Hors inventaire en échec',s.accessory_failed,'Service accessoire ou à déclarer')+svcCard('Critiques déclarés',s.configured,'Criticité définie dans l’inventaire')+svcCard('Observations anciennes',s.stale,'État actuel non confirmé')+svcCard('Serveurs sans unités',s.unmeasured_hosts,'Absence de relevé, pas absence de service')+'</div><div class="storage-nav" role="group" aria-label="Filtres des unités">'+choices.map(([value,label])=>'<button data-svc-status="'+value+'" aria-pressed="'+(svcStatus===value)+'">'+label+'</button>').join('')+'</div><div class="workload-filters"><label>Rechercher une unité<input id="svc-q" type="search" maxlength="120" placeholder="nginx, cron…" value="'+escAttr(svcQuery)+'"></label><label>Fraîcheur<select id="svc-freshness">'+[['all','Toutes les observations'],['recent','Récentes uniquement'],['stale','Anciennes ou non datées']].map(([v,label])=>'<option value="'+v+'" '+(svcFreshness===v?'selected':'')+'>'+label+'</option>').join('')+'</select></label></div><p class="note">« active » ne prouve pas le fonctionnement HTTP, SQL ou métier ; active/exited peut être normal pour un oneshot. Les unités inactives non critiques peuvent être volontairement arrêtées. Les compteurs suivent les serveurs, la recherche et la fraîcheur sélectionnés, avant le filtre d’état.</p>';
 if(!d)return '<section class="panel workload-global">'+head+'<p role="status">'+esc(svcError||'Chargement des unités…')+'</p></section>';
 const rows=d.items.map(u=>{const h=hosts[u.host_key]||{key:u.host_key,name:u.host_key},recent=u.fresh===true;return '<tr><td><button class="link" data-host="'+escAttr(h.key)+'">'+esc(h.name)+'</button></td><td><strong>'+esc(u.name)+'</strong></td><td>'+badge(recent?u.status:'unknown')+(!recent?'<small>Ancien état : '+esc(u.status)+'</small>':'')+(SVC_READINGS[u.reading]?'<small>'+esc(SVC_READINGS[u.reading])+'</small>':'')+'</td><td>'+esc(u.substate||'Non mesuré')+'</td><td>'+svcLevel(u)+'</td><td>'+freshnessMarkup(u.collected_at||h.collected_at,'Mesures SSH',900)+'</td><td><button data-svc-host="'+escAttr(h.key)+'">Unités et preuves</button></td></tr>';}).join('');
 const fin=Math.min(d.offset+d.items.length,d.total),pages=d.total>SVC_PAGE?'<div class="workload-pages"><button data-svc-page="-1" '+(!d.offset?'disabled':'')+'>← Précédentes</button><span>'+(d.total?d.offset+1:0)+'–'+fin+' / '+d.total+'</span><button data-svc-page="1" '+(fin>=d.total?'disabled':'')+'>Suivantes →</button></div>':'';
 return '<section class="panel workload-global">'+head+(rows?'<div class="table"><table><caption>Unités observées : ouvrir la fiche pour les preuves et les applications</caption><thead><tr>'+['Serveur','Unité','État observé','Sous-état','Criticité','Collecte','Détail'].map(label=>'<th scope="col">'+label+'</th>').join('')+'</tr></thead><tbody>'+rows+'</tbody></table></div>'+pages:'<p class="empty">Aucune unité pour ces critères. Vérifier aussi les serveurs sans relevé.</p>')+'</section>';
};
document.addEventListener('click',event=>{
 const status=event.target.closest('[data-svc-status]');if(status){svcStatus=status.dataset.svcStatus;svcOffset=0;render();return;}
 const pageButton=event.target.closest('[data-svc-page]');if(pageButton&&svcData){svcOffset=Math.max(0,svcOffset+Number(pageButton.dataset.svcPage)*SVC_PAGE);render();return;}
 const hostButton=event.target.closest('[data-svc-host]');if(hostButton){const key=hostButton.dataset.svcHost;workloadChoice({key}).view='units';openHost(key).then(()=>{if(hostDetail?.key===key){detailTab='services';render();}});}
});
document.addEventListener('change',event=>{if(event.target.id==='svc-q')svcQuery=event.target.value.trim();else if(event.target.id==='svc-freshness')svcFreshness=event.target.value;else return;svcOffset=0;render();});
