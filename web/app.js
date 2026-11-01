const $=s=>document.querySelector(s);
// Sections <details> ouvertes, retrouvées après rafraîchissement par une identité STABLE
// (data-k, sinon le titre, chiffres neutralisés car les âges relatifs changent) et non plus
// par position : une section insérée avant décalait l'ouverture sur la mauvaise.
const detailsId=d=>d.dataset.k||(d.querySelector(':scope>summary')?.textContent||'').replace(/\d+/g,'#').trim();
const openDetails=root=>new Set(root?[...root.querySelectorAll('details')].filter(d=>d.open).map(detailsId):[]);
const restoreDetails=(root,ids)=>root?.querySelectorAll('details').forEach(d=>{if(ids.has(detailsId(d)))d.open=true});
// Vocabulaire UNIQUE des niveaux : un même code porte le même mot et la même couleur sur
// toutes les pages (« warning » s'affichait À surveiller, Majeur, Dégradé ou Avertissement).
// rank : ordre de tri, du plus grave au plus rassurant.
const sevLabel=(code,plural)=>SEVERITY[code]?SEVERITY[code][plural?'plural':'label']:code;
// Notifications navigateur : registre COMMUN à la voie rapide (critical.js) et au centre
// d'alertes (alerts.js). Un serveur hors service déclenchait deux notifications coup sur coup ;
// un serveur déjà signalé n'est plus renotifié par l'autre module pendant 10 min.
const NOTIFIED_HOSTS=new Map(),NOTIFY_HOST_TTL=600000;
const notifiedRecently=names=>names.some(n=>n&&Date.now()-(NOTIFIED_HOSTS.get(String(n).toLowerCase())||0)<NOTIFY_HOST_TTL);
const markNotified=names=>names.forEach(n=>{if(n)NOTIFIED_HOSTS.set(String(n).toLowerCase(),Date.now())});
const labels={ok:SEVERITY.ok.label,critical:SEVERITY.critical.label,warning:SEVERITY.warning.label,unreachable:SEVERITY.unreachable.label,unknown:SEVERITY.unknown.label,pass:'Concluant',fail:'Anomalie',observed:'Observé',active:'Actif',failed:'Échec',inactive:'Inactif'};
const badge=s=>'<span class="badge '+(Object.hasOwn(labels,s)?s:'unknown')+'">● '+esc(labels[s]||s)+'</span>';
const stamp=v=>v?new Date(v).toLocaleString('fr-FR'):'Jamais collecté';
const pct=v=>v==null?'—':esc(v)+' %';
// Identité de l'opérateur (/api/whoami), renseignée par v2.js ; null = pas encore connue.
let operatorIdentity=null;
// ---------------------------------------------------------------------------
// Cycle de vie (lot 5). render, navigation et load gardent leur identité : les modules
// s'abonnent (renderHooks…) ou déclarent une page (pageRenderers) au lieu de réaffecter
// ces fonctions en chaîne. Une extension en échec n'empêche pas les suivantes ; son
// erreur reste visible (erreur non interceptée, relevée par les tests).
// ---------------------------------------------------------------------------
const beforeRenderHooks=[],renderHooks=[],navigationHooks=[],loadHooks=[];
// Constats d'audit affichés par lots (la page complète dépassait 40 000 px pour 65 constats).
const PROBLEMS_PAGE=20;let problemsShown=PROBLEMS_PAGE;
// Accueil : fourni par daily.js (synthèse quotidienne) ; overview() reste le repli sans ce module.
let homeView=null;
function runHooks(hooks){for(const hook of hooks){try{hook()}catch(error){setTimeout(()=>{throw error})}}}
// Les droits s'appliquent après TOUS les abonnés : un module qui ajoute un bouton dans son
// rappel (ex. manage.js) est couvert sans attendre l'observateur (course constatée au lot 6).
// Titre de document et route par écran (audit transversal du 01/11) : l'onglet, l'historique et
// les lecteurs d'écran gardaient « OpsControl V2 — Centre d'exploitation » sur toutes les pages.
function syncDocument(){const home=page==='Vue globale'&&!selected;document.documentElement.dataset.route=home?'home':'page';if(state)document.documentElement.dataset.shellReady='1';const host=selected&&(state?.hosts||[]).find(h=>h.key===selected);documentTitle=(selected?(host?.name||selected)+' — Fiche serveur':page)+' — OpsControl';applyDocumentTitle()}
// Nombre d'alertes interrompantes (alerts.js) en préfixe, comme avant, devant le titre de l'écran.
let documentTitle=document.title,alertTitleCount=0;
function applyDocumentTitle(){const title=(alertTitleCount?'('+alertTitleCount+') ':'')+documentTitle;if(document.title!==title)document.title=title}
function render(){runHooks(beforeRenderHooks);renderView();runHooks(renderHooks);applyRoleGates();syncDocument()}
function navigation(){navigationView();runHooks(navigationHooks)}
async function load(){await loadView();for(const hook of loadHooks){try{await hook()}catch(error){setTimeout(()=>{throw error})}}}
// Minuteries : un seul intervalle d'une seconde pilote toutes les tâches périodiques.
// Onglet masqué : seules les tâches marquées hidden continuent (au rythme hiddenMs) ;
// au retour, les tâches dues partent aussitôt. Une tâche lente ne se chevauche jamais.
let frontendStarted=false;
const polls=new Map();
function poll(name,ms,task,{hidden=false,hiddenMs=ms,when=null}={}){polls.set(name,{ms,task,hidden,hiddenMs,when,last:Date.now(),running:false,runs:0})}
function pollTick(force=false){
 if(!frontendStarted)return;
 const now=Date.now();
 for(const [name,p] of polls){
  if(p.running||(document.hidden&&!p.hidden))continue;
  if(!force&&now-p.last<(document.hidden?p.hiddenMs:p.ms)-50)continue;
  if(p.when&&!p.when())continue;
  p.last=now;p.runs++;
  let result;try{result=p.task()}catch(error){setTimeout(()=>{throw error});continue}
  if(result&&typeof result.then==='function'){p.running=true;result.catch(error=>setTimeout(()=>{throw error})).finally(()=>{p.running=false})}
 }
}
function pollStatus(){return [...polls].map(([name,p])=>({name,ms:p.ms,hidden:p.hidden,hiddenMs:p.hiddenMs,runs:p.runs,running:p.running}))}
setInterval(()=>pollTick(false),1000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)pollTick(false)});
// Droits : les actions hors du rôle de la session sont désactivées et expliquées. Le
// serveur reste seul juge (access_policy.py, mêmes règles) ; ceci évite des clics voués au refus.
const ROLE_CONTROLS=[
 ['operator','#refresh,[data-audit-host],[data-net-host],[data-net-refresh],[data-refresh-availability],[data-alert-ack],[data-alert-unack],[data-inc-action],[data-inc-sync],[data-inc-maintenance-new],[data-inc-maintenance-delete],[data-waf-command],[data-waf-ban-cmd],[data-test-connection],[data-test-server-params],[data-bulk-test],#sync-all,#batch-refresh,[data-daily-audit],[data-pve-collect],[data-zbx-collect],[data-wazuh-collect],[data-elastic-collect],[data-bacula-collect],[data-collect-api],[data-action="refresh-all"],[data-action="audit"]'],
 ['admin','#interval,#ssh-interval,[data-action="interval"],[data-add-server],[data-edit-server],[data-bulk-open],[data-hostkeys-open],[data-discovery-open],[data-disc-scan],[data-disc-add],[data-hostkeys-scan],[data-hostkeys-accept],[data-delete-server],[data-add-api],[data-edit-api],[data-delete-api],[data-check-cert],[data-inv-appliquer]']
];
const ROLE_LABEL={operator:'opérateur',admin:'administrateur'};
function roleAllows(required){const id=operatorIdentity;if(!id||!id.role)return true;return required==='admin'?!!id.can_admin:!!(id.can_operate||id.can_admin)}
// Nom accessible des dialogues (audit FE-07) : le premier titre affiché, recalculé à chaque ouverture
// et à chaque contenu ; un nom fixe sinon. v2.js nomme le sien lui-même.
const DIALOG_NAMES={'alert-ack-dialog':'Prise en charge d’une alerte','host-access-dialog':'Accès SSH','incident-dialog':'Action sur un incident','maintenance-dialog':'Fenêtre de maintenance','management-dialog':'Gestion des serveurs','waf-command-dialog':'Commande WAF'};
new MutationObserver(records=>{for(const r of records){const d=r.target.closest?.('dialog');if(d&&d.open&&DIALOG_NAMES[d.id]){const h=d.querySelector('h2,h3,legend');d.setAttribute('aria-label',(h&&h.textContent.trim())||DIALOG_NAMES[d.id])}}}).observe(document.body,{subtree:true,childList:true,attributes:true,attributeFilter:['open']});
function applyRoleGates(root=document){
 if(!operatorIdentity?.role)return;
 document.documentElement.dataset.role=operatorIdentity.role;
 // Mention du menu selon le rôle réel (audit UI du 31/10, fiche 12.3) : « lecture seule » était
 // affiché à un administrateur qui peut modifier les connexions. Le parc reste en lecture seule.
 const note=document.querySelector('.side-note div');
 // Écrire seulement si le texte change : applyRoleGates est relancée par un MutationObserver,
 // une réécriture systématique bouclerait.
 const wanted=({admin:'<b>Administration d’OpsControl</b><small>Parc supervisé en lecture seule · actions auditées</small>',operator:'<b>Lecture et collectes</b><small>Parc supervisé en lecture seule · actions auditées</small>'})[operatorIdentity.role]||'<b>Accès en lecture seule</b><small>Consultation · aucune action</small>';
 if(note&&note.innerHTML!==wanted)note.innerHTML=wanted;
 for(const [required,selector] of ROLE_CONTROLS){
  if(roleAllows(required))continue;
  for(const el of root.querySelectorAll(selector)){
   if(el.dataset.roleLocked){el.disabled=true;continue;}
   el.dataset.roleLocked=required;el.disabled=true;el.setAttribute('aria-disabled','true');
   el.title='Réservé au rôle « '+ROLE_LABEL[required]+' » : votre session est en lecture.';
  }
 }
}
// Les vues partielles se redessinent hors de render : regrouper leurs droits en microtâche,
// sans attendre une image dont l’arrivée dépend du démarrage ou de l’onglet visible.
let roleGateFrame=0;
new MutationObserver(()=>{if(roleGateFrame||!operatorIdentity?.role||roleAllows('admin'))return;roleGateFrame=1;queueMicrotask(()=>{roleGateFrame=0;applyRoleGates()})}).observe(document.documentElement,{childList:true,subtree:true});
// Un module qui réactive un bouton après son action ne lève pas le verrou de rôle.
document.addEventListener('click',e=>{const locked=e.target.closest('[data-role-locked]');if(locked){e.preventDefault();e.stopImmediatePropagation();toast(locked.title)}},true);
let state=null,page='Vue globale',selected=null,hostDetail=null,detailTab='summary',filters={q:'',status:'',environment:'',role:''},mode='incidents',renderId=0,loading=false,netState=null;
function toast(text){$('#toast').textContent=text;setTimeout(()=>$('#toast').textContent='',2800)}
let lastHostSnapshot='', lastDetailSnapshot='', lastSourceRefresh=0,lastLoadAt=0,pendingLoadTimer=null,overviewDirty=false;
const pageFilters=new Map();
// The clock is not a new observation. Keep the investigation mounted on polling.
function detailSignature(result){
 const alerts=result.alerts;
 return JSON.stringify({...result,alerts:alerts?{...alerts,generated_at:undefined,
  items:(alerts.items||[]).map(({duration_seconds,duration_until,...evidence})=>evidence)}:alerts});
}
function restoreDetailFocus(id,start,end){
 const el=id&&document.getElementById(id);if(!el)return;
 el.focus({preventScroll:true});
 if(start!=null&&typeof el.setSelectionRange==='function')el.setSelectionRange(start,end??start);
}
function backupBadge(h){
 const b=h.backup_summary;
 if(!b?.matched)return '<span class="badge unknown">Aucun job associé</span>';
 const texts={ok:'Derniers jobs réussis',critical:'Dernier passage en erreur',warning:'Avertissement',running:'Job en cours',pending:'Job en attente',unknown:'Résultat non mesuré'};
 const color=b.fresh?({ok:'ok',critical:'critical',warning:'warning',running:'active'}[b.severity]||'unknown'):'unknown';
 return '<button class="link" data-host="'+escAttr(h.key)+'"><span class="badge '+color+'">'+esc(texts[b.severity]||texts.unknown)+'</span></button><small>'+esc(b.jobs_count)+' job(s) · '+(b.fresh?'Collecte récente':'À reconfirmer')+'</small><small>'+stamp(b.collected_at)+'</small>';
}

// Chaque page adossée à une source API y inscrit son chargeur : la couche de
// base déclare l'emplacement, les modules le remplissent. L'inverse — app.js
// citant loadWazuh(), loadZabbix()… — rendait le socle dépendant de fichiers
// chargés après lui.
const sourceLoaders={};
// Point d'extension pour migrer une page vers un rendu incrémental. Si aucun
// renderer n'est inscrit, le HTML historique reste le repli automatique.
const pageRenderers={};
// Extensions de fiche serveur. Les modules lourds ajoutent un onglet et son
// renderer sans envelopper detailView/render, ce qui les rend chargeables à la
// demande avant l'ouverture de la première fiche.
const detailTabs=[];
const detailRenderers={};
const detailAfterRenderers=[];
const detailTransformers=[];
// Décorateurs des cartes de connexions, enregistrés notamment par la couche V2.
const connectionDecorators=[];
// Les vues riches restent hors du chemin critique. Elles s'enregistrent dans
// pageRenderers à leur premier affichage, sans modifier la chaîne globale de
// render après l'installation de la couche V2.
const lazyPageScripts={
 Proxmox:'/proxmox.js?v=18584c0a',
 Elasticsearch:'/elastic.js?v=1f1a90a3',
 Wazuh:'/wazuh.js?v=c937c22d',
 Zabbix:'/zabbix.js?v=24bab87f',
 Partages:'/shares.js?v=12a079c6',
 Synchronisation:'/sync.js?v=84fd4beb',
 'Compléter l’inventaire':'/inventory-completion.js?v=7a17a0a9',
 'Connexions API':['/connections.js?v=9fa3f7d1','/api-help.js?v=9ad6d3c0','/connections-v2.js?v=c90a4e84'],
 'Santé d’OpsControl':'/self-monitor.js?v=dce41ff6',
 Sources:'/sources-center.js?v=df0e11f6',
 'Sécurité':'/security.js?v=78621037'
};
const lazyDetailScripts={storage:'/storage.js?v=539569b6',v2:'/v2-detail.js?v=9b99330a'};
const lazyPageLoads=new Map();
function ensurePageModule(name){
 const sources=[].concat(lazyPageScripts[name]||[]);
 if(!sources.length||pageRenderers[name])return Promise.resolve();
 if(lazyPageLoads.has(name))return lazyPageLoads.get(name);
 const load=src=>new Promise((resolve,reject)=>{
  const script=document.createElement('script');script.src=src;script.async=false;script.dataset.lazyPage=name;
  script.onload=resolve;script.onerror=()=>reject(Error('Impossible de charger le module '+name+'.'));
  document.head.appendChild(script);
 });
 const pending=sources.reduce((chain,src)=>chain.then(()=>load(src)),Promise.resolve())
  .then(()=>{if(!pageRenderers[name])throw Error('Le module '+name+' ne s’est pas enregistré.')})
  .catch(error=>{lazyPageLoads.delete(name);throw error});
 lazyPageLoads.set(name,pending);return pending;
}
let lazyDetailLoad=null;
function ensureDetailModules(){
 if(Object.keys(lazyDetailScripts).every(key=>detailRenderers[key]))return Promise.resolve();
 if(lazyDetailLoad)return lazyDetailLoad;
 lazyDetailLoad=Promise.all(Object.entries(lazyDetailScripts).filter(([key])=>!detailRenderers[key]).map(([key,src])=>new Promise((resolve,reject)=>{
  const script=document.createElement('script');script.src=src;script.async=true;script.dataset.lazyDetail=key;
  script.onload=()=>((key==='v2'&&detailRenderers.observability)||detailRenderers[key])?resolve():reject(Error('Le module de détail '+key+' ne s’est pas enregistré.'));
  script.onerror=()=>reject(Error('Impossible de charger le module de détail '+key+'.'));document.head.appendChild(script);
 }))).catch(error=>{lazyDetailLoad=null;throw error});
 return lazyDetailLoad;
}
const sourceUrl=provider=>'/api/connections?provider='+encodeURIComponent(provider);
const deferredRenders=new Map();
function deferLargeRender(key,large,paint,delay=180){
 const prior=deferredRenders.get(key);if(prior)clearTimeout(prior);
 if(!large){deferredRenders.delete(key);paint();return}
 deferredRenders.set(key,setTimeout(()=>{deferredRenders.delete(key);paint()},delay));
}
function paintRuntime(){
 if(!state)return;
 const sansSecret=state.missing_auth||[];
 $('#error').textContent=state.job?.error||(sansSecret.length
  ?'Identifiants absents pour '+sansSecret.length+' source'+(sansSecret.length>1?'s':'')+' ('+sansSecret.join(', ')+') : aucune collecte API ne peut aboutir. Arrêter ce serveur et le relancer avec LANCER-INFRAOPS.ps1 en saisissant les secrets.'
  :'');
 const jobs=state.jobs||{ssh:state.job};
 document.querySelectorAll('[data-audit-host]').forEach(button=>button.disabled=Boolean(state.job?.running));
 $('#refresh').disabled=Object.values(jobs).some(j=>j?.running);
 if(state.monitoring)$('#interval').value=String(state.monitoring.interval);
 const running=Object.entries(jobs).filter(([,j])=>j?.running);
 $('#progress').textContent=running.map(([name,j])=>name.toUpperCase()+' : '+(j.completed||0)+' / '+(j.total||0)).join(' · ');
}
function applyRealtimeState(update){
 if(!state||!update)return;
 const jobs={...(state.jobs||{})};
 for(const name of ['ssh','network','api','batch'])if(update[name])jobs[name]={...(jobs[name]||{}),...update[name]};
 state.jobs=jobs;
 if(update.ssh)state.job=jobs.ssh;
 if(update.monitoring)state.monitoring={...state.monitoring,...update.monitoring};
 paintRuntime();
}
function scheduleLoad(delay=0){
 clearTimeout(pendingLoadTimer);
 pendingLoadTimer=setTimeout(()=>{pendingLoadTimer=null;load()},delay);
}
async function loadView(){
 // On ne sollicite pas le serveur ni les 84 hôtes pour un onglet que personne
 // ne regarde. Le rattrapage est assuré par l'écouteur visibilitychange plus bas ;
 // sans lui, ouvrir OpsControl dans un onglet d'arrière-plan laissait l'interface
 // vide jusqu'à la prochaine minuterie, soit 30 secondes.
 if(loading||document.hidden)return;
 loading=true;
 try{
  const data=await api('/api/overview');
  const snapshot=JSON.stringify(data.hosts);
  const changed=snapshot!==lastHostSnapshot;
  const initial=!state;
   state=data;lastHostSnapshot=snapshot;lastLoadAt=Date.now();overviewDirty=false;
  // Un secret manquant rend TOUTES les collectes d'une source impossibles. On le
  // dit une fois, globalement et en nommant la manoeuvre : sans ça, l'opérateur
  // ne voit que cinq échecs distincts sans cause commune apparente.
   paintRuntime();
  if(selected){
   const key=selected, result=await api('/api/hosts/'+encodeURIComponent(key));
   if(selected!==key)return;
   const signature=detailSignature(result);
   hostDetail=result;
   // Premier état reçu : rendu obligatoire (fiche ouverte par lien direct avant l'arrivée du parc).
   if(initial||signature!==lastDetailSnapshot){lastDetailSnapshot=signature;render();}
  }else{
   // sourceLoaders est un point d'extension rempli par chaque module de page
   // (voir plus bas sa déclaration) : app.js n'a plus à connaître leurs noms.
   // Keep the source page and its controls mounted while SSH jobs progress.
   if(!initial&&sourceLoaders[page]){
    if(Date.now()-lastSourceRefresh>30000){lastSourceRefresh=Date.now();await sourceLoaders[page]();}
   }else if(initial||changed)render();
  }
 }catch(e){$('#error').textContent=e.message}finally{loading=false}
}
$('#refresh').onclick=async()=>{try{await post(page==='Synchronisation'?'/api/sync':'/api/refresh');await load();if(page==='Synchronisation'&&sourceLoaders.Synchronisation)await sourceLoaders.Synchronisation()}catch(e){$('#error').textContent=e.message}};
$('#interval').onchange=async e=>{try{await post('/api/monitoring',{interval:Number(e.target.value)});await load()}catch(error){$('#error').textContent=error.message}};
function navigate(p){
 if(page===p&&!selected&&!lazyPageScripts[p])return;
 pageFilters.set(page,{...filters});page=p;selected=null;hostDetail=null;filters={...(pageFilters.get(p)||{q:'',status:'',environment:'',role:''})};
 if(lazyPageScripts[p]&&!pageRenderers[p]){
  $('#title').textContent=p;$('#breadcrumb').textContent=p;$('#subtitle').textContent=subtitles[p]||'';navigation();
  $('#content').innerHTML='<div class="panel empty" role="status">Chargement de la vue '+esc(p)+'…</div>';
  ensurePageModule(p).then(()=>{if(page===p&&!selected)render()}).catch(error=>{if(page===p&&!selected)$('#content').innerHTML='<div class="panel empty" role="alert">'+esc(error.message)+' <button data-retry-page="'+escAttr(p)+'">Réessayer</button></div>'});
 }else render();
 window.scrollTo(0,0);if(overviewDirty)scheduleLoad();
}
$('#nav').onclick=e=>{const b=e.target.closest('[data-page]');if(b)navigate(b.dataset.page)};
// Mesures SSH « récentes » : même seuil que le serveur (audit_retention, 900 s). Audit UI du 31/10,
// fiche 05.1 : avec 30 s, une mesure de quelques minutes s'affichait « À actualiser ».
const SSH_FRESH_SECONDS=900;
// Couverture : un audit partiel est dit partiel, avec les contrôles non observés (fiche 05.1).
function coverage(h){const c=h.coverage||{measured:0,total:15},missing=h.coverage_missing||[],partial=c.measured>0&&c.measured<c.total;return '<span'+(missing.length?' title="'+escAttr('Non observés : '+missing.join(', '))+'"':'')+'>'+(h.stale?'Obsolète · ':'')+esc(c.measured)+' / '+esc(c.total)+(partial?' · partiel':'')+'</span>'+(partial&&missing.length?'<small>Absents : '+esc(missing.slice(0,2).join(', '))+(missing.length>2?' +'+(missing.length-2):'')+'</small>':'')}
function incidents(hosts,includeUnknown=false){return hosts.flatMap(h=>(h.findings||[]).filter(f=>includeUnknown?f.severity==='unknown':f.severity!=='unknown').map(f=>({h,f}))).sort((a,b)=>({critical:0,unreachable:0,warning:1,unknown:2}[a.f.severity]??2)-({critical:0,unreachable:0,warning:1,unknown:2}[b.f.severity]??2))}
// Confirmation sur le bouton lui-même : le toast peut être hors champ quand le bloc est en bas de page.
function copyConfirm(b){b.dataset.copyLabel??=b.textContent;b.textContent='Copié ✓';b.classList.add('is-copied');clearTimeout(b.copyTimer);b.copyTimer=setTimeout(()=>{b.textContent=b.dataset.copyLabel;b.classList.remove('is-copied')},2000)}
function command(label,text){return '<div class="command"><div class="panel-head"><b>'+esc(label)+'</b><button data-copy="'+escAttr(text||'')+'">Copier</button></div><pre>'+esc(text||'Commande à définir après diagnostic')+'</pre></div>'}
// Constat compact (≈ 1 ligne au lieu de ~500 px) : gravité, domaine, titre, serveur, date de l'audit visibles ;
// preuve, portée, commandes à copier et précautions repliées. Ouverture mémorisée (la page se redessine
// à chaque mise à jour). Rappel « copie uniquement » toujours visible.
const issueOpen=new Set();
function issue(h,f){const key=h.key+'|'+(f.id||f.title);return '<article class="panel issue compact '+esc(f.severity)+'"><header><div>'+badge(f.severity)+' <span class="mini">'+esc(f.domain)+'</span><h3>'+esc(f.title)+'</h3><button class="link" data-host="'+escAttr(h.key)+'">'+esc(h.name)+' · '+esc(h.ip)+'</button></div><span class="mini">Audit SSH · '+stamp(h.collected_at)+(h.stale?' · <b class="text-critical">PREUVE OBSOLÈTE</b>':'')+'</span></header><details class="issue-more" data-issue-key="'+escAttr(key)+'"'+(issueOpen.has(key)?' open':'')+'><summary>Preuve, commandes à copier et précautions <span class="mini">· copie uniquement, aucune commande exécutée par la plateforme</span></summary><div class="evidence">'+esc(f.evidence)+'</div><p class="note">'+esc(f.scope)+'</p><div class="commands">'+command('1. Vérifier',f.check_command)+command(f.requires_adaptation?'2. Préparer la correction':'2. Correction proposée',f.solution_command)+'</div><p class="note">'+esc(f.precaution)+'</p><p class="mini issue-copy-only">Copie uniquement · aucune commande de correction exécutée par la plateforme.</p></details></article>'}
document.addEventListener('toggle',e=>{const d=e.target;if(!(d instanceof HTMLDetailsElement)||!d.dataset.issueKey)return;if(d.open)issueOpen.add(d.dataset.issueKey);else issueOpen.delete(d.dataset.issueKey)},true);
function checks(h){return (h.checks||[]).map(c=>'<details class="panel"><summary>'+badge(c.status)+' '+esc(c.title)+'</summary><p class="note">Commande de contrôle en lecture seule</p><pre>'+esc(c.command)+'</pre><p>Preuve</p><pre>'+esc(c.evidence)+'</pre>'+(c.error?'<p>'+esc(c.error)+'</p>':'')+'</details>').join('')||'<div class="empty">Lancer un audit pour afficher les contrôles et leurs preuves.</div>'}
// Audit age and coverage are different from current server availability.
const STALE_REASONS={age:'Mesure de plus de 15 min',attempt_failed:'Dernière tentative en échec',configuration_changed:'Configuration modifiée depuis l’audit'};
function hostAuditBadge(h){
 const measured=(h.coverage?.measured||0)>0;
 if(!measured)return '<span class="badge unknown">● Audit non mesuré</span>';
 if(h.stale&&measured)return '<span class="badge unknown">● Audit ancien</span><small>'+esc(STALE_REASONS[h.stale_reason]||'Mesure à actualiser')+' · dernier audit : '+esc(labels[h.audit_status||h.last_status]||'État non mesuré')+'</small>';
 if(h.status==='unknown')return '<span class="badge unknown">● '+(measured?'Audit partiel':'Audit non mesuré')+'</span>';
 return badge(h.status);
}
// Fiche serveur en onglets (lot 4). Seul l'onglet actif est construit : chaque module
// enregistre ses sections (hostSection) au lieu d'injecter du HTML autour des onglets.
// Les anciennes clés d'onglet restent acceptées (liens, état mémorisé, modules tiers).
const HOST_TABS=[['summary','Synthèse'],['incidents','Incidents'],['storage','Stockage'],['performance','Performances'],['services','Services & applications'],['network','Réseau & accès'],['backup','Sauvegardes'],['security','Sécurité']];
const HOST_TAB_ALIASES={problems:'incidents',checks:'audit',inventory:'audit',history:'audit',observability:'performance',applications:'services'};
const hostSections={},hostNotices=[],hostTabCounts={};
function hostSection(tab,order,renderSection){tab=hostTabKey(tab);(hostSections[tab]=hostSections[tab]||[]).push({order,render:renderSection});hostSections[tab].sort((a,b)=>a.order-b.order)}
function hostTabKey(tab){return HOST_TAB_ALIASES[tab]||tab}
function hostTabList(){return [...HOST_TABS,...detailTabs.filter(([k])=>!HOST_TAB_ALIASES[k]&&!HOST_TABS.some(([t])=>t===k))]}
function detailView(h){
 detailTab=hostTabKey(detailTab);
 if(detailTab!=='audit'&&!hostTabList().some(([k])=>k===detailTab))detailTab='summary';
 let html='<div class="panel host-header"><div class="detail-banner"><div><button data-go="Serveurs">← Serveurs</button><h2>'+esc(h.name)+' '+hostAuditBadge(h)+'</h2><p>'+esc(h.ip)+' · '+esc(h.environment)+' · '+esc(h.role)+'</p><p>SSH : '+esc(h.ssh_user)+' · port '+esc(h.ssh_port)+' · '+(h.collected_at?freshnessMarkup(h.collected_at,'Mesures SSH',SSH_FRESH_SECONDS):'<span class="mini">Première collecte en attente</span>')+'</p></div><div><button class="primary" data-audit-host="'+escAttr(h.key)+'" '+(state.job.running?'disabled':'')+'>↻ Auditer ce serveur</button><button data-export>Exporter l’audit JSON</button></div></div>'+(h.stale?'<p class="instruction">Mesures obsolètes. Refaire les vérifications avant toute correction.</p>':'')+hostNotices.map(n=>n(h)).join('')+'</div>';
 html+='<div class="host-evidence-actions"><button id="host-tab-audit" data-goto-tab="audit" aria-controls="host-tabpanel" aria-expanded="'+(detailTab==='audit')+'">Preuves et historique</button>'+(detailTab==='audit'?'<button data-goto-tab="summary">← Revenir à la synthèse</button>':'')+'</div>';
 html+='<div class="tabs host-tabs" role="tablist" aria-label="Sections de la fiche serveur">'+hostTabList().map(([k,v])=>{const n=hostTabCounts[k]?hostTabCounts[k](h):0;return '<button role="tab" id="host-tab-'+k+'" aria-controls="host-tabpanel" aria-selected="'+(detailTab===k)+'" tabindex="'+(detailTab===k||(detailTab==='audit'&&k==='summary')?0:-1)+'" class="'+(detailTab===k?'active':'')+'" data-tab="'+k+'">'+esc(v)+(n?'<span class="tab-count">'+n+'</span>':'')+'</button>'}).join('')+'</div>';
 let body=(hostSections[detailTab]||[]).map(s=>s.render(h)).join('');
 if(!hostSections[detailTab]&&detailRenderers[detailTab])body=detailRenderers[detailTab](h);
 html+='<div id="host-tabpanel" role="'+(detailTab==='audit'?'region':'tabpanel')+'" aria-labelledby="host-tab-'+detailTab+'">'+(body||'<div class="panel empty">Aucune donnée pour cette section.</div>')+'</div>';
 return detailTransformers.reduce((markup,transform)=>transform(markup,h),html);
}
// Sections de base (données de l'audit SSH).
hostSection('summary',10,h=>'<section class="panel host-measures"><div class="detail-grid">'+[['CPU',pct(h.cpu)],['RAM',pct(h.ram)],['Disque max',pct(h.disk_max)]].map(([k,v])=>'<div class="card">'+k+'<strong>'+v+'</strong></div>').join('')+'</div><p class="note">Couverture : '+coverage(h)+' contrôles renseignés. Cela ne constitue pas une certification de sécurité.</p></section>');
hostSection('incidents',20,h=>'<details class="host-findings"><summary class="section-title">Constats de l’audit SSH et commandes à copier ('+(h.findings||[]).length+')</summary>'+((h.findings||[]).map(f=>issue(h,f)).join('')||'<div class="panel empty">'+esc((h.issues||[]).join(' · ')||'Aucune anomalie sur les contrôles accessibles.')+'</div>')+'</details>');
hostSection('audit',20,h=>'<h2 class="section-title">Audit détaillé</h2>'+checks(h)+'<details class="panel"><summary>Tentatives de connexion SSH</summary><pre>'+esc(JSON.stringify(h.attempts||[],null,2))+'</pre></details>');
hostSection('audit',30,h=>'<div class="panel"><h2>20 derniers audits — résumés</h2>'+(h.history||[]).map(x=>'<div class="row">'+badge(x.status)+'<div>'+stamp(x.ts)+'<p>'+esc((x.issues||[]).join(' · '))+'</p></div></div>').join('')+'</div>');
hostSection('audit',50,h=>'<div class="panel"><h2>Informations documentaires</h2><p>Nœud : '+esc(h.node)+' · VMID : '+esc(h.vmid)+'</p><p>'+esc((h.inventory_warnings||[]).join(' · '))+'</p><p class="note">Informations historiques du classeur ; aucun état live déduit.</p><pre>'+esc(JSON.stringify(h.documented||{},null,2))+'</pre><h3>Sources</h3><pre>'+esc((h.inventory_sources||[]).join('\n'))+'</pre></div>');
// Onglets au clavier (motif WAI-ARIA) : flèches, Début et Fin activent l'onglet voisin.
$('#content').addEventListener('keydown',e=>{
 const tab=e.target.closest('.host-tabs [role=tab]');if(!tab||!['ArrowRight','ArrowLeft','Home','End'].includes(e.key))return;
 const keys=hostTabList().map(([k])=>k),at=keys.indexOf(tab.dataset.tab);
 const next=e.key==='Home'?0:e.key==='End'?keys.length-1:(at+(e.key==='ArrowRight'?1:-1)+keys.length)%keys.length;
 e.preventDefault();detailTab=keys[next];render();document.getElementById('host-tab-'+detailTab)?.focus({preventScroll:true});
});
// Compteur de l'onglet Incidents : alertes récentes à traiter et constats SSH mesurés.
hostTabCounts.incidents=h=>(h.alerts?.items||[]).filter(a=>a.fresh&&['critical','warning','unreachable'].includes(a.severity)).length+(h.stale?0:(h.findings||[]).filter(f=>['critical','warning'].includes(f.severity)).length);
// Libellés propres à chaque mesure (audit UI du 31/10, fiche 08.1) : un même Oui/Non servait au
// ping, au port et à la clé ; un ping sans réponse (ICMP filtré) passait pour une panne.
function netPing(v){return v===true?'<span class="badge ok">● Répond</span>':v===false?'<span class="badge warning" title="ICMP peut être filtré : ne prouve pas un arrêt">● Sans réponse</span>':'<span class="badge unknown">● Non mesuré</span>'}
function netPort(p){const why={refused:['Refusé','critical','Connexion refusée : service arrêté ou port fermé'],timeout:['Délai dépassé','warning','Aucune réponse : filtrage réseau ou hôte muet'],unreachable:['Injoignable','critical','Route ou hôte injoignable']}[p.failure]||['Fermé ou filtré','critical','Cause non relevée par cette collecte'];return '<span class="badge '+(p.ok===true?'ok':p.ok===false?why[1]:'unknown')+'"'+(p.ok===false?' title="'+escAttr(why[2])+'"':'')+'>● '+esc(p.port)+' '+(p.ok===true?'ouvert'+(p.latency_ms!=null?' · '+esc(p.latency_ms)+' ms':''):p.ok===false?why[0].toLowerCase():'non mesuré')+'</span>'}
function netKey(v){return v===true?'<span class="badge ok">● Connue</span>':v===false?'<span class="badge warning" title="Absente de known_hosts : aucune connexion SSH tant qu’elle n’est pas vérifiée">● Inconnue</span>':'<span class="badge unknown">● Non vérifiée</span>'}
function netBadge(v){return v===true?'<span class="badge ok">● Oui</span>':v===false?'<span class="badge critical">● Non</span>':'<span class="badge unknown">● Inconnu</span>'}
async function renderNetwork(id){
 const target=$('#net');if(!target)return;
 try{netState=await api('/api/network');if(id!==renderId)return;
 const p=$('#netprogress');if(p)p.textContent=netState.job.running?'Vérification en cours : '+netState.job.completed+' / '+netState.job.total+' serveurs':'';
 document.querySelectorAll('[data-net-refresh]').forEach(b=>b.disabled=netState.job.running);
 target.innerHTML='<div class="table"><table><thead><tr>'+['Serveur','IP','Ping','Ports TCP','Clé hôte SSH','Dernière vérification',''].map(v=>'<th>'+v+'</th>').join('')+'</tr></thead><tbody>'+netState.hosts.map(h=>'<tr><td class="ident">'+esc(h.name)+'</td><td class="ip">'+esc(h.ip)+'</td><td>'+netPing(h.ping)+'</td><td>'+((h.ports||[]).map(netPort).join(' ')||'—')+'</td><td>'+netKey(h.ssh_key_known)+'</td><td>'+stamp(h.collected_at)+'</td><td><button data-net-host="'+escAttr(h.key)+'" '+(netState.job.running?'disabled':'')+'>Vérifier</button></td></tr>').join('')+'</tbody></table></div>'+(netState.hosts.length?'':'<div class="empty">Aucun serveur.</div>')
 }catch(e){if(id===renderId)target.textContent=e.message}
}
async function renderExtra(id){
 const target=$('#extra');if(!target)return;
 try{const data=await api(page==='Connexion'?'/api/runtime':'/api/inventory-report');if(id!==renderId)return;
 if(page!=='Connexion'&&data.available===false){target.innerHTML='<h2>Rapprochement de l’inventaire</h2><p>'+esc(data.policy)+'</p>';return;}
 target.innerHTML=page==='Connexion'?runtimeView(data):'<h2>Rapprochement de l’inventaire</h2><p>'+esc(data.policy)+'</p><p>'+esc(data.hosts)+' serveurs · '+data.conflicts.length+' écarts IP · '+data.excluded.length+' entrées exclues ou à confirmer.</p><details><summary>Écarts entre feuilles</summary><pre>'+esc(data.conflicts.map(c=>c.host+' : '+c.retained_ip+' retenue / '+c.other_ip+' ('+c.source+')').join('\n'))+'</pre></details><details><summary>Entrées non retenues</summary><pre>'+esc(JSON.stringify(data.excluded,null,2))+'</pre></details>'
 }catch(e){if(id===renderId)target.textContent=e.message}
}
$('#content').addEventListener('input',e=>{if(e.target.id==='search'&&!e.target.dataset.action){filters.q=e.target.value;deferLargeRender('fleet-search',(state?.hosts?.length||0)>100,render)}});
$('#content').addEventListener('change',e=>{if(e.target.dataset.filter){filters[e.target.dataset.filter]=e.target.value;render()}});
// Zones hors #content (bandeau d'alertes #alert-strip, serveurs critiques #t0-zone) :
// leurs boutons data-go / data-host n'avaient aucun gestionnaire et restaient inertes.
// #v2-ops et les dialogues gèrent déjà leurs propres clics.
document.addEventListener('click',e=>{
 const b=e.target.closest('button[data-go],button[data-host]');
 if(!b||b.dataset.action||b.closest('#content,#v2-ops,dialog'))return;
 if(b.dataset.go)navigate(b.dataset.go);else openHost(b.dataset.host,b);
});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 try{
 if(b.dataset.go)navigate(b.dataset.go);
  if(b.dataset.retryPage)navigate(b.dataset.retryPage);
 if(b.dataset.host&&!b.dataset.action)await openHost(b.dataset.host,b)
 if(b.dataset.tab||b.dataset.gotoTab){detailTab=hostTabKey(b.dataset.tab||b.dataset.gotoTab);render();document.getElementById('host-tab-'+detailTab)?.focus({preventScroll:true})}
 if(b.dataset.mode){mode=b.dataset.mode;render()}
 if(b.dataset.auditHost){await post('/api/hosts/'+encodeURIComponent(b.dataset.auditHost)+'/refresh');await load()}
 if(b.hasAttribute('data-net-refresh')){await post('/api/network/refresh');await renderNetwork(renderId)}
 if(b.dataset.netHost){await post('/api/network/hosts/'+encodeURIComponent(b.dataset.netHost)+'/refresh');await renderNetwork(renderId)}
 if(b.hasAttribute('data-copy')){await navigator.clipboard.writeText(b.dataset.copy);toast('Commande copiée · aucune exécution');copyConfirm(b)}
 if(b.hasAttribute('data-export')){const blob=new Blob([JSON.stringify(hostDetail,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='audit-'+hostDetail.key+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 }catch(error){$('#error').textContent=error.message}finally{if(b.isConnected)b.disabled=false}
});
// Un seul ordonnanceur de secours. Avec SSE actif, une vérification lente suffit ;
// sans SSE, on garde 5 s pendant un job et 30 s au repos.
poll('etat-du-parc',5000,()=>{const running=Object.values(state?.jobs||{ssh:state?.job}).some(j=>j?.running);const connected=typeof realtimeConnected!=='undefined'&&realtimeConnected;const cadence=connected?60000:(running?5000:30000);if(Date.now()-lastLoadAt>=cadence)scheduleLoad()});
poll('reseau-en-cours',2000,()=>renderNetwork(renderId),{when:()=>page==='Réseau'&&netState?.job?.running});


// Interface additions; collection and SSH stay in the existing backend.
const iconPaths={overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',server:'M4 3h16v7H4z M4 14h16v7H4z M7 6h1 M7 17h1',alert:'M12 3 2 21h20z M12 9v5 M12 17v1',service:'M3 12h4l3-8 4 16 3-8h4',audit:'M6 3h12v18H6z M9 8h6 M9 12h6 M9 16h4',network:'M9 3h6v5H9z M3 16h6v5H3z M15 16h6v5h-6z M12 8v4 M6 16v-4h12v4',backup:'M4 6c0-4 16-4 16 0v12c0 4-16 4-16 0z M4 6c0 4 16 4 16 0 M4 12c0 4 16 4 16 0',shield:'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z M8 12l3 3 5-6',inventory:'M4 4h16v16H4z M4 9h16 M9 9v11',key:'M14 4a5 5 0 1 1-3 9l-7 7H2v-3l7-7a5 5 0 0 1 5-6z'};
const icon=k=>'<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="'+iconPaths[k]+'"/></svg>';
const navGroups=[['EXPLOITATION',[['Vue globale','overview'],['Serveurs','server'],['Problèmes','alert'],['Services','service'],['Audit','audit']]],['INFRASTRUCTURE',[['Réseau','network'],['Sauvegardes','backup'],['Proxmox','server'],['Partages','backup'],['WAF / HA','shield'],['Wazuh','shield'],['Zabbix','alert'],['Elasticsearch','server'],['Sécurité','shield']]],['CONFIGURATION',[['Synchronisation','network'],['Inventaire','inventory'],['Compléter l’inventaire','inventory'],['Connexions API','network'],['Connexion','key'],['Santé d’OpsControl','overview'],['Sources','network']]]];
function navigationView(){
 const signature=JSON.stringify(navGroups);
 const nav=$('#nav');
 if(nav.dataset.structure!==signature){
  nav.innerHTML=navGroups.map(([title,items])=>'<div class="nav-section">'+title+'</div>'+items.map(([p,i])=>'<button data-page="'+p+'">'+icon(i)+p+'<span class="nav-count"></span></button>').join('')).join('');
  nav.dataset.structure=signature;
 const mobile=$('#mobile-nav');if(mobile)mobile.innerHTML=navGroups.map(([title,items])=>'<optgroup label="'+title+'">'+items.map(([p])=>'<option value="'+p+'">'+p+'</option>').join('')+'</optgroup>').join('');
 }
 if($('#mobile-nav'))$('#mobile-nav').value=page;
 for(const button of nav.querySelectorAll('[data-page]')){
  const target=button.dataset.page;
  button.classList.toggle('active',target===page);
  if(target===page)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
  const count=button.querySelector('.nav-count');
  count.textContent=state&&target==='Serveurs'?onlineHosts().length:state&&target==='Problèmes'?incidents(state.hosts).filter(x=>!x.h.stale).length:'';
 }
}
let sortKey='status',sortDir=1;
const rank={critical:0,unreachable:1,warning:2,unknown:3,ok:4};
const subtitles={'Vue globale':'L’état de votre parc. Les priorités de votre journée.',Serveurs:'Parc enregistré durablement. Disponibilité actualisée ; audit SSH initial conservé.',Problèmes:'Des anomalies documentées, des preuves et des commandes à préparer.',Services:'Les unités observées et les services déclarés critiques.',Audit:'La couverture des contrôles et leurs preuves, serveur par serveur.',Réseau:'Disponibilité, ports et empreintes SSH : comprendre les accès bloqués.',Sauvegardes:'Informations documentaires et couverture des sauvegardes.',Proxmox:'Pilotage visuel des clusters, nœuds, VM, conteneurs et stockages — collecte API en lecture seule.',Partages:'Dossiers partagés NFS et Samba : occupation, accessibilité depuis chaque client, exports déclarés.',Wazuh:'Manager Wazuh : démons, agents déclarés et version, collectés par API.',Zabbix:'Hôtes supervisés et anomalies actives, collectés par l’API JSON-RPC.',Elasticsearch:'Santé du cluster et allocation des shards, avec date et source de chaque collecte.',Synchronisation:'Inventaire rapproché, fraîcheur des sources et collecte API, SSH et réseau.','Compléter l’inventaire':'Rôles, environnements et services critiques proposés à partir des preuves collectées.','Connexions API':'Sources de collecte HTTPS : Proxmox, Wazuh, Elasticsearch et Bacula.','WAF / HA':'Périmètre WAF et haute disponibilité à partir de l’inventaire.',Sécurité:'Les anomalies de sécurité observées par l’audit SSH.',Inventaire:'Votre parc consolidé et les écarts entre les sources.',Connexion:'Le contexte SSH utilisé par cette instance du cockpit.'};
function relative(v){if(!v)return 'Jamais';const m=Math.max(0,Math.floor((Date.now()-new Date(v).getTime())/60000));return m<1?'À l’instant':m<60?'Il y a '+m+' min':m<1440?'Il y a '+Math.floor(m/60)+' h':'Il y a '+Math.floor(m/1440)+' j'}
const bucket5=n=>Math.max(0,Math.min(100,Math.round(n/5)*5));
function metric(v,stale=false,k='cpu'){if(v==null||!Number.isFinite(Number(v)))return '<span class="mini">Non mesuré</span>';const n=Math.max(0,Math.min(100,Number(v)));const limits=k==='disk_max'?[80,90]:k==='ram'?[90,97]:[90,98];const state=n>=limits[1]?'critical':n>=limits[0]?'warning':'normal';const stateLabel={critical:'Seuil critique dépassé',warning:'Seuil d’alerte dépassé',normal:'Dans les limites normales'}[state];return '<div class="metric '+(stale?'stale':'')+'" title="'+(stale?'Dernière mesure ancienne':'Dernière mesure')+'"><span class="metric-label">'+pct(v)+'</span><div class="meter '+(state==='normal'?'':state)+'" role="img" aria-label="'+stateLabel+'"><i class="w'+bucket5(n)+'"></i></div></div>'}
// Parc géré = serveur enregistré ou en ligne confirmé ; le reste de l'inventaire consolidé
// (découvertes, entrées sans preuve) est « hors parc géré ». Audit UI du 31/10, fiches 01.1 et 14.1.
function managed(h){return h.registered===true||h.active_scope===true}
function onlineHosts(){return (state?.hosts||[]).filter(managed)}
function scopeLine(){const total=(state?.hosts||[]).length,m=onlineHosts().length;return m+' serveur'+(m>1?'s':'')+' du parc géré sur '+total+' entrée'+(total>1?'s':'')+' de l’inventaire consolidé · '+(total-m)+' hors parc géré (découvertes ou sans preuve d’enregistrement)'}
async function openHost(key,control){
 selected=key;detailTab='summary';if(control)control.disabled=true;
 try{const [result]=await Promise.all([api('/api/hosts/'+encodeURIComponent(key)),ensureDetailModules()]);if(selected!==key)return;hostDetail=result;lastDetailSnapshot=detailSignature(result);render();window.scrollTo(0,0)}
 catch(error){$('#error').textContent=error.message}
 finally{if(control?.isConnected)control.disabled=false}
}
function list(){return state.hosts.filter(h=>(!['Serveurs','Vue globale'].includes(page)||managed(h))&&(!filters.scope||(filters.scope==='managed')===managed(h))&&(!filters.q||(h.name+' '+h.ip).toLowerCase().includes(filters.q.toLowerCase()))&&['status','environment','role'].every(k=>!filters[k]||h[k]===filters[k])).sort((a,b)=>{let av=sortKey==='status'?rank[a.status]:a[sortKey],bv=sortKey==='status'?rank[b.status]:b[sortKey];if(av==null)return bv==null?0:1;if(bv==null)return -1;return (typeof av==='number'?av-bv:String(av).localeCompare(String(bv),'fr'))*sortDir||a.name.localeCompare(b.name)})}
function availabilityMessage(){
 const reasons=state?.availability?.exclusions||{};
 if(onlineHosts().length)return '';
 return '<section class="instruction" role="status"><b>Aucun serveur confirmé en ligne pour le moment</b><p>La liste attend un état Proxmox démarré et un ping récent. Une collecte API seule ne suffisait pas à renouveler le ping.</p>'+Object.entries(reasons).map(([reason,count])=>'<p>'+esc(count)+' · '+esc(reason)+'</p>').join('')+'<button data-refresh-availability>Actualiser Proxmox et ping</button></section>';
}
function toolbar(){return (['Serveurs','Vue globale'].includes(page)?availabilityMessage()+'<p class="note">'+esc(scopeLine())+' · Un arrêt ou un ping en échec ne retire pas un serveur du parc. <button class="link" data-go="Inventaire">Tout l’inventaire</button> · <button class="link" data-go="Synchronisation">Voir les exclusions</button></p>':'')+(['Audit','Inventaire'].includes(page)?'<p class="note scope-note">'+esc(scopeLine())+'</p>':'')+'<div class="filters"><input id="search" aria-label="Rechercher hostname ou IP" placeholder="⌕  Rechercher un hostname ou une adresse IP…" value="'+escAttr(filters.q)+'">'+['status','environment','role'].map(k=>'<select data-filter="'+k+'" aria-label="'+({status:'État',environment:'Environnement',role:'Rôle'}[k])+'"><option value="">'+({status:'Tous les états',environment:'Environnements',role:'Tous les rôles'}[k])+'</option>'+[...new Set(state.hosts.map(h=>h[k]))].filter(v=>v!=null).sort().map(v=>'<option '+(v===filters[k]?'selected ':'')+'value="'+escAttr(v)+'">'+esc(labels[v]||v)+'</option>').join('')+'</select>').join('')+(['Audit','Inventaire'].includes(page)?'<select data-filter="scope" aria-label="Périmètre"><option value="">Tout l’inventaire</option><option value="managed"'+(filters.scope==='managed'?' selected':'')+'>Parc géré</option><option value="other"'+(filters.scope==='other'?' selected':'')+'>Hors parc géré</option></select>':'')+(Object.values(filters).some(Boolean)?'<button class="filter-reset" data-reset>Effacer</button>':'')+'</div>'}
function table(hosts){const cols=[['Serveur','name'],['IP','ip'],['Rôle / env.','role'],['État','status'],['CPU','cpu'],['RAM','ram'],['Disque max','disk_max'],['Services',''],['Sauvegarde',''],['Audit',''],['Collecte','collected_at']];return '<div class="table"><table><thead><tr>'+cols.map(([title,k])=>'<th '+(k===sortKey?'aria-sort="'+(sortDir===1?'ascending':'descending')+'"':'')+'>'+(k?'<button class="sort-button" data-sort="'+k+'">'+title+(sortKey===k?(sortDir===1?' ↑':' ↓'):' ↕')+'</button>':title)+'</th>').join('')+'</tr></thead><tbody>'+hosts.map(h=>{const sv=h.all_services||h.service_states||[],failed=sv.filter(s=>s.status==='failed').length;return '<tr><td><button class="link" data-host="'+escAttr(h.key)+'">'+esc(h.name)+'</button><small>'+esc(h.active_scope?'En ligne confirmé':h.scope_reason||h.node||'Disponibilité non mesurée')+'</small>'+(managed(h)?'':'<small class="scope-tag">'+esc(h.discovered_from?'Découvert · hors parc géré':'Hors parc géré')+'</small>')+'</td><td class="ip">'+esc(h.ip)+'</td><td>'+esc(h.role)+'<small>'+esc(h.environment)+'</small></td><td>'+hostAuditBadge(h)+(h.status_reason?'<small class="status-reason">Cause : '+esc(h.status_reason)+'</small>':'')+'</td>'+['cpu','ram','disk_max'].map(k=>'<td>'+metric(h[k],h.stale,k)+'</td>').join('')+'<td>'+(h.stale?'<span class="mini">À actualiser</span>':failed?'<span class="badge critical">'+failed+' en échec</span>':(h.services||[]).length?'<span class="mini">Voir les contrôles</span>':'<span class="mini">À configurer</span>')+'</td><td>'+backupBadge(h)+'</td><td class="mini">'+coverage(h)+'</td><td title="'+escAttr(stamp(h.collected_at))+'">'+(h.collected_at?freshnessMarkup(h.collected_at,'Mesures SSH',SSH_FRESH_SECONDS):'<span class="mini">Première collecte en attente</span>')+(h.last_attempt?.collected_at?'<small>Dernière tentative : '+esc(stamp(h.last_attempt.collected_at))+' · échec</small>':'')+'</td></tr>'}).join('')+'</tbody></table></div>'+(hosts.length?'<div class="table-foot"><span>'+hosts.length+' serveur'+(hosts.length>1?'s':'')+' affiché'+(hosts.length>1?'s':'')+'</span><span>Cliquer sur un hostname pour ouvrir son audit</span></div>':'<div class="empty">Aucun serveur pour ces critères.</div>')}
function brief(hosts){const all=incidents(hosts).filter(x=>!x.h.stale).sort((a,b)=>((a.f.id==='ssh')-(b.f.id==='ssh'))),old=all.length===0,visible=old?incidents(hosts).filter(x=>x.h.stale):all;return '<section class="panel priority-list"><div class="panel-head"><h2>À traiter maintenant <span class="state-count">'+all.length+'</span></h2><button data-go="Problèmes">Tous les problèmes →</button></div>'+(old&&visible.length?'<p class="note">Derniers problèmes connus · preuves anciennes à actualiser</p>':'')+visible.slice(0,4).map(({h,f})=>'<div class="row">'+(old?'<span class="badge unknown">Ancien</span>':badge(f.severity))+'<div><button class="link" data-host="'+escAttr(h.key)+'">'+esc(h.name)+'</button><p>'+esc(f.title)+'</p></div><button data-host="'+escAttr(h.key)+'">Diagnostic ↗</button></div>').join('')+(visible.length?'':'<div class="empty"><span class="empty-symbol">◎</span>Aucune anomalie récente disponible.<br>Actualisez les audits pour connaître l’état du parc.</div>')+'</section>'}
function health(hosts=state.hosts){const total=hosts.length,recent=hosts.filter(h=>h.collected_at&&!h.stale),observed=recent.filter(h=>h.cpu!=null),ok=recent.filter(h=>h.status==='ok').length,score=recent.length&&total?Math.round(ok/total*100):null,blocked=recent.filter(h=>h.cpu==null).length;return '<section class="panel health-panel"><div class="panel-head"><h2>Santé & couverture</h2></div><div class="health-body"><div class="health-ring hv'+bucket5(score||0)+'"><strong>'+(score==null?'—':score+'%')+'</strong></div><div><b>Parc confirmé OK</b><p>'+ok+' / '+total+' serveurs</p><p>Sur les contrôles disponibles</p></div></div><div><div class="health-line"><span>Mesures récentes</span><b>'+observed.length+' / '+total+'</b></div><div class="health-line"><span>Accès sans mesures</span><b>'+blocked+'</b></div><div class="health-line"><span>Anciens ou jamais collectés</span><b>'+(total-recent.length)+'</b></div></div><div class="health-note">Les états inconnus ne sont pas considérés comme OK.<br><button data-go="Audit">Consulter la couverture →</button></div></section>'}
function overview(){const hosts=onlineHosts(),counts={};for(const h of hosts)counts[h.status]=(counts[h.status]||0)+1;return '<div class="stats">'+[['Serveurs',hosts.length,'','VM démarrées · ping réussi'],['OK',counts.ok||0,'ok','Contrôles concluants'],['Critiques',counts.critical||0,'critical','Incidents ou accès refusés'],['À surveiller',counts.warning||0,'warning','Seuils et anomalies'],['Injoignables',counts.unreachable||0,'unreachable','Collecte impossible'],['Incomplets',counts.unknown||0,'unknown','À vérifier ou actualiser']].map(([n,v,c,s])=>'<button class="card stat-card '+c+'" data-status="'+c+'"><span class="stat-dot"></span>'+n+'<strong>'+v+'</strong><small>'+s+'</small></button>').join('')+'</div><div class="overview-grid">'+brief(hosts)+health(hosts)+'</div>'}
function serviceView(){const hs=list(),units=hs.flatMap(h=>(h.all_services||[]).map(s=>({h,s}))).sort((a,b)=>(a.s.status==='failed'?-1:1)-(b.s.status==='failed'?-1:1));return '<div class="panel"><div class="panel-head"><h2>Services observés</h2><span class="mini">'+units.length+' unités</span></div>'+toolbar()+'<div class="service-summary"><span>'+units.filter(x=>x.s.status==='failed'&&!x.h.stale).length+' échecs récents</span><span>'+hs.filter(h=>!(h.services||[]).length).length+' listes critiques à configurer</span></div><div class="table"><table><thead><tr><th>Serveur</th><th>Unité</th><th>État observé</th><th>Déclarée critique</th><th>Collecte</th></tr></thead><tbody>'+units.map(({h,s})=>'<tr><td><button class="link" data-host="'+escAttr(h.key)+'">'+esc(h.name)+'</button></td><td>'+esc(s.name)+'</td><td>'+badge(h.stale?'unknown':s.status)+(h.stale?'<small>Ancien état : '+esc(s.status)+'</small>':'')+'</td><td>'+(s.configured?'Oui':'Non')+'</td><td>'+(h.collected_at?freshnessMarkup(h.collected_at,'Mesures SSH',SSH_FRESH_SECONDS):'<span class="mini">Première collecte en attente</span>')+'</td></tr>').join('')+'</tbody></table></div>'+(units.length?'':'<div class="empty">Aucune unité disponible. Actualisez l’infrastructure.</div>')+'</div>'}
function backups(){return '<div class="panel"><div class="panel-head"><h2>Sauvegardes</h2><span class="badge unknown">Proxmox Backup Server non raccordé</span></div><p class="note">Les chemins ci-dessous proviennent de l’inventaire. Ils ne prouvent ni l’exécution ni la réussite d’une sauvegarde.</p>'+toolbar()+'<div class="table"><table><thead><tr><th>Serveur</th><th>État réel</th><th>Chemins documentés</th><th>Rétention documentée</th></tr></thead><tbody>'+list().map(h=>'<tr><td><button class="link" data-host="'+escAttr(h.key)+'">'+esc(h.name)+'</button></td><td>'+badge('unknown')+'</td><td>'+esc(h.documented?.backup?.paths||'Non renseignés')+'</td><td>'+esc(h.documented?.backup?.retention||'Non renseignée')+'</td></tr>').join('')+'</tbody></table></div></div>'}
function security(){const findings=incidents(list()).filter(({f})=>/sécurité|security|permissions|ssh_policy/i.test(f.domain+' '+f.id));return '<div class="panel"><div class="panel-head"><h2>Contrôles de sécurité SSH</h2><span class="badge unknown">Source : audit SSH</span></div><p>Cette vue présente les anomalies accessibles au compte SSH. Les contrôles non accessibles sont détaillés dans chaque audit. Wazuh n’alimente pas cette vue : ses agents figurent dans Sources → Wazuh, ses vulnérabilités dans le tableau de bord Sécurité.</p>'+toolbar()+'</div>'+findings.map(({h,f})=>issue(h,f)).join('')+(findings.length?'':'<div class="panel empty">Aucune anomalie de sécurité disponible sur ce périmètre. Cela ne vaut pas validation de conformité.</div>')}
function runtimeView(data){return '<h2>Contexte de connexion</h2><p class="note">'+esc(data.hint)+'</p><div class="runtime-grid">'+[['Transport',data.transport],['Client SSH',data.ssh_client_found?'Trouvé':'Introuvable'],['Clé privée',(data.key_name||'—')+(data.key_exists?' · présente':' · absente')+(data.key_permissions&&data.key_exists?' · droits '+data.key_permissions:'')],['Configuration SSH',(data.config_name||'—')+(data.config_exists?' · présente':' · absente')+(data.config_permissions&&data.config_exists?' · droits '+data.config_permissions:'')],['Empreintes connues',data.known_hosts_exists?'known_hosts présent':'known_hosts absent'],['Contrôle des clés hôtes',data.host_key_checking||'Non renseigné'],['Collectes simultanées',data.workers],['Journal d’audit',data.audit_log_name]].map(([k,v])=>'<div class="runtime-item"><small>'+k+'</small><b>'+esc(v)+'</b></div>').join('')+'</div><p class="instruction">Les empreintes SSH sont vérifiées manuellement. Les comptes et ports utilisés sont visibles dans les tentatives de chaque serveur.</p><details><summary>Informations techniques</summary><pre>'+esc(JSON.stringify(data,null,2))+'</pre></details>'}
// Sans état, on affiche explicitement l'attente plutôt que de sortir en laissant
// le DOM de la page précédente : sinon « Sécurité » affichait le contenu de
// « Proxmox », dernier module à avoir peint. Mesuré : 4 pages sur 17 concernées.
function renderView(){if(!state){$('#title').textContent=page;$('#breadcrumb').textContent=page;$('#subtitle').textContent=subtitles[page]||'';navigation();$('#content').innerHTML='<div class="panel empty">Chargement de l’état du parc…</div>';return}const id=++renderId,focus=document.activeElement?.id,position=document.activeElement?.selectionStart,selectionEnd=document.activeElement?.selectionEnd;const expanded=openDetails($('#content'));$('#title').textContent=selected?hostDetail?.name||'Serveur':page;$('#breadcrumb').textContent=selected?'Serveurs / '+(hostDetail?.name||'Chargement'):page;$('#subtitle').textContent=selected?'Mesures, services et preuves : comprendre avant d’intervenir.':subtitles[page]||'';navigation();if(!selected&&pageRenderers[page]){pageRenderers[page]();return}let html='';
 if(selected&&hostDetail){$('#content').innerHTML=detailView(hostDetail);restoreDetails($('#content'),expanded);restoreDetailFocus(focus,position,selectionEnd);detailAfterRenderers.forEach(fn=>fn(hostDetail));return}
 if(page==='Vue globale')html=homeView?homeView():overview();
 if(['Serveurs','Audit','Inventaire'].includes(page))html+='<div class="panel"><div class="panel-head"><h2>'+(page==='Audit'?'Couverture par serveur':'Parc serveurs')+' <span class="state-count">'+(['Serveurs','Vue globale'].includes(page)?onlineHosts().length:state.hosts.length)+'</span></h2><span class="mini">'+list().length+' résultat'+(list().length>1?'s':'')+'</span></div>'+toolbar()+table(list())+'</div>';
 if(page==='Problèmes'){const data=incidents(list(),mode==='coverage');html='<div class="panel">'+toolbar()+'<div class="tabs"><button data-mode="incidents" class="'+(mode==='incidents'?'active':'')+'">Anomalies observées</button><button data-mode="coverage" class="'+(mode==='coverage'?'active':'')+'">Contrôles incomplets</button></div><p class="note">Commandes à copier. Les corrections sont à examiner et à exécuter manuellement après diagnostic.</p></div>'+data.slice(0,problemsShown).map(({h,f})=>issue(h,f)).join('')+(data.length>problemsShown?'<div class="panel more-row"><button data-problems-more>Afficher '+Math.min(PROBLEMS_PAGE,data.length-problemsShown)+' constats de plus ('+(data.length-problemsShown)+' restants)</button><span class="note">'+problemsShown+' sur '+data.length+' affichés</span></div>':'')+(data.length?'':'<div class="panel empty">Aucun résultat. Consultez Audit pour les contrôles absents.</div>')}
 if(page==='Réseau')html='<div class="panel"><div class="panel-head"><h2>Disponibilité réseau et SSH</h2><button data-net-refresh>↻ Vérifier le réseau</button></div><p class="note">Ping, ports TCP et présence des empreintes connues, mesurés depuis le poste OpsControl. Aucun ajout automatique de clé. Un ping sans réponse ne prouve pas un arrêt (ICMP souvent filtré) ; une clé modifiée est signalée à la connexion SSH, pas ici.</p><span id="netprogress" class="mini"></span><div id="net">Chargement…</div></div>';
 if(page==='Services')html=serviceView();if(page==='Sauvegardes')html=backups();if(page==='Sécurité')html=security();
 if(page==='Connexion'||page==='Inventaire')html+='<section class="panel" id="extra">Chargement…</section>';
 $('#content').innerHTML=html;renderExtra(id);renderNetwork(id);if(focus==='search'){$('#search')?.focus();$('#search')?.setSelectionRange(position,position)}
}
navigationHooks.push(()=>{if(page!=='Problèmes')problemsShown=PROBLEMS_PAGE});
$('#content').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;if(b.hasAttribute('data-problems-more')){problemsShown+=PROBLEMS_PAGE;render();return}if(b.hasAttribute('data-mode'))problemsShown=PROBLEMS_PAGE;if(b.hasAttribute('data-status')){navigate('Serveurs');filters={q:'',status:b.dataset.status,environment:'',role:''};render()}if(b.hasAttribute('data-reset')){filters={q:'',status:'',environment:'',role:''};render()}if(b.dataset.sort){sortDir=sortKey===b.dataset.sort?-sortDir:1;sortKey=b.dataset.sort;render()}});
function applyTheme(theme){document.documentElement.dataset.theme=theme;$('#theme').setAttribute('aria-label','Activer le thème '+(theme==='dark'?'clair':'sombre'))}
// Thème : choix enregistré de l'opérateur, sinon préférence du système (sombre par défaut si inconnue).
const systemTheme=()=>window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
let savedTheme=null;try{savedTheme=localStorage.getItem('infraops-theme')}catch{}
applyTheme(savedTheme||systemTheme());
if(!savedTheme&&window.matchMedia)matchMedia('(prefers-color-scheme: light)').addEventListener?.('change',()=>{let s=null;try{s=localStorage.getItem('infraops-theme')}catch{}if(!s)applyTheme(systemTheme())});
$('#theme').onclick=()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';applyTheme(theme);try{localStorage.setItem('infraops-theme',theme)}catch{}};

// Rattrapage immediat quand l'onglet redevient visible : la garde document.hidden
// de load() protege le serveur, cet ecouteur evite qu'elle laisse l'interface vide.
document.addEventListener('visibilitychange',()=>{if(!document.hidden)scheduleLoad()});
// Le point d’entrée ES démarre les données après l’inscription de toutes les extensions.
function startApplication(){if(frontendStarted)return;frontendStarted=true;navigation();load();}



$('#mobile-nav').addEventListener('change',e=>navigate(e.target.value));

$('#content').addEventListener('click',async e=>{const b=e.target.closest('[data-refresh-availability]');if(!b)return;b.disabled=true;try{await post('/api/availability/refresh');await load();}catch(error){$('#error').textContent=error.message;}finally{if(b.isConnected)b.disabled=false;}});
