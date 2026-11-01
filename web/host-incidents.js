// Fiche serveur, onglet Incidents : les incidents RÉELS du journal (incident_center),
// une ligne par cause et par source, sans les doublons des alertes brutes ni des constats.
// Actions : prise en charge (même dialogue que le journal) et ticket GLPI (web/itsm.js).
// Les alertes brutes et les constats d'audit restent consultables, repliés plus bas.
const hostIncidentCache = new Map();
const HOST_INC_STATES = {open: 'Ouvert', reopened: 'Rouvert', acknowledged: 'Pris en charge', investigating: 'En investigation',
  suppressed: 'Masqué', resolved: 'Résolu'};
const HOST_INC_ACTIVE = ['open', 'reopened', 'acknowledged', 'investigating'];

function hostIncidentItems() {
  return [...hostIncidentCache.values()].flatMap(c => c.items || []);
}

// Noms du serveur dans les sources (hôte Zabbix rapproché par IP, FQDN) : un incident Zabbix
// porte le nom Zabbix, pas la clé d'inventaire.
function hostIncidentAliases(h) {
  const names = (h?.source_details || []).flatMap(s => [s.evidence?.host?.host, s.evidence?.host?.name]).concat(h?.fqdn ? [h.fqdn] : []);
  return [...new Set(names.filter(Boolean).map(String))].slice(0, 10);
}

async function hostIncidentsLoad(key, force = false) {
  const cached = hostIncidentCache.get(key);
  if (cached && (cached.loading || (!force && Date.now() - cached.at < 30000))) return;
  hostIncidentCache.set(key, {...(cached || {}), loading: true});
  const aliases = hostDetail?.key === key ? hostIncidentAliases(hostDetail) : [];
  try {
    const data = await api('/api/incidents?host=' + encodeURIComponent(key) + '&chronic=include&limit=200' +
      (aliases.length ? '&alias=' + encodeURIComponent(aliases.join(',')) : ''));
    hostIncidentCache.set(key, {items: data.items || [], at: Date.now(), error: ''});
  } catch (error) {
    hostIncidentCache.set(key, {items: cached?.items || [], at: Date.now(), error: error.message});
  }
  // Toujours sur cette fiche et cet onglet : on réaffiche avec les données reçues.
  if (selected === key && detailTab === 'incidents') render();
}

// Gravités du journal (politique OpsControl), libellées comme sur la page Alertes.
const HOST_INC_SEVERITIES = {critical: 'Critique', warning: 'Majeur', preventive: 'Préventif', info: 'Information'};
function hostIncidentRow(i) {
  const open = ['open', 'reopened'].includes(i.state);
  return '<tr><td><span class="badge ' + escAttr(i.severity) + '">' + esc(HOST_INC_SEVERITIES[i.severity] || i.severity) + '</span><p>' + esc(i.source) + '</p></td>' +
    '<td><strong>' + esc(i.title) + '</strong>' + (i.target && i.target_key !== selected ? '<p class="note">' + esc(i.target) + '</p>' : '') +
    (i.evidence ? '<details><summary>Preuve</summary><pre>' + esc(i.evidence) + '</pre></details>' : '') + '</td>' +
    '<td>' + incEventDate(i) + '<small>Dernière preuve : ' + exactTimeMarkup(i.observed_at) + '</small>' + (i.chronic ? '<p class="badge unknown">Chronique</p>' : '') + '</td>' +
    '<td>' + esc(HOST_INC_STATES[i.state] || i.state) + (i.owner ? '<p class="note">' + esc(i.owner) + (i.owner_authenticated ? '' : ' (déclaratif)') + '</p>' : '') +
    (typeof itsmBadge === 'function' ? '<p>' + itsmBadge('incident', i.id) + '</p>' : '') + '</td>' +
    '<td class="host-inc-actions">' + (open && roleAllows('operator') ? '<button data-host-inc-action="ack" data-inc-id="' + escAttr(i.id) + '">Prendre en charge</button>' : '') +
    (roleAllows('admin') && i.state !== 'resolved' ? '<button data-itsm-origin="incident" data-itsm-id="' + escAttr(i.id) + '" data-itsm-host="' + escAttr(selected || '') + '" title="Créer ou consulter le ticket GLPI de cet incident">Ticket GLPI</button>' : '') + '</td></tr>';
}

function hostIncidentsSection(h) {
  const cached = hostIncidentCache.get(h.key);
  if (!cached || (!cached.at && !cached.error)) {
    hostIncidentsLoad(h.key);
    return '<section class="panel host-incidents"><h2>Incidents de ce serveur</h2><p>Chargement du journal d’incidents…</p></section>';
  }
  if (Date.now() - cached.at > 30000) hostIncidentsLoad(h.key);
  const active = cached.items.filter(i => HOST_INC_ACTIVE.includes(i.state));
  const masked = cached.items.length - active.length;
  return '<section class="panel host-incidents"><div class="panel-head"><div><h2>Incidents de ce serveur</h2>' +
    '<p>Journal d’incidents : une ligne par cause et par source, prise en charge et ticket GLPI.</p></div>' +
    '<span class="badge ' + (active.some(i => i.severity === 'critical') ? 'critical' : active.length ? 'warning' : 'ok') + '">' + active.length + ' actif(s)</span></div>' +
    (cached.error ? '<p role="alert" class="form-error">' + esc(cached.error) + ' Dernière liste conservée.</p>' : '') +
    (active.length ? '<div class="table"><table><caption>Incidents actifs de ' + esc(h.name) + '</caption><thead><tr>' +
      ['Gravité / source', 'Incident', 'Occurrence et preuve', 'État', 'Actions'].map(s => '<th scope="col">' + s + '</th>').join('') + '</tr></thead><tbody>' +
      active.map(hostIncidentRow).join('') + '</tbody></table></div>'
      : '<p class="empty">Aucun incident actif dans le journal pour ce serveur. Une source absente ne prouve pas que le serveur est sain : voir le détail par source ci-dessous.</p>') +
    (masked ? '<p class="note">' + masked + ' incident(s) supprimé(s) temporairement, non listé(s) : voir le journal Incidents.</p>' : '') +
    '</section>';
}
hostSection('incidents', 5, hostIncidentsSection);
// Compteur de l'onglet : incidents actifs du journal dès qu'ils sont connus (plus de double comptage
// alertes + constats) ; avant chargement, l'ancien calcul reste affiché.
const hostIncidentFallbackCount = hostTabCounts.incidents;
hostTabCounts.incidents = h => {
  const cached = hostIncidentCache.get(h.key);
  return cached?.at ? cached.items.filter(i => HOST_INC_ACTIVE.includes(i.state)).length : (hostIncidentFallbackCount ? hostIncidentFallbackCount(h) : 0);
};

document.addEventListener('click', e => {
  const b = e.target.closest('[data-host-inc-action]');
  if (b) incOpenDialog(b.dataset.hostIncAction, b.dataset.incId);
});
// Après une prise en charge (ou fermeture du dialogue), la fiche relit le journal.
incDialog.addEventListener('close', () => { if (selected && hostIncidentCache.has(selected)) hostIncidentsLoad(selected, true); });
itsmDialog.addEventListener('close', () => { if (selected && hostIncidentCache.has(selected)) hostIncidentsLoad(selected, true); });

// Les CVE gardent leur propre identité et leur validation : elles ne deviennent pas
// des incidents d'exploitation par simple copie dans le journal.
const hostSecurityCache = new Map();
async function hostSecurityLoad(key, offset=0, force=false) {
  const prior=hostSecurityCache.get(key);
  if(prior?.loading || (!force && prior?.offset===offset && Date.now()-prior.at<30000))return;
  hostSecurityCache.set(key,{...prior,loading:true});
  try {
    const [data,signals]=await Promise.all([api('/api/security/vulns?host='+encodeURIComponent(key)+'&status=active&limit=10&offset='+offset+'&projection=list'),
      api('/api/security/notifications?host='+encodeURIComponent(key)+'&limit=5').catch(error=>({items:[],error:error.message}))]);
    hostSecurityCache.set(key,{...data,signals:signals.items||[],signalsError:signals.error,offset,at:Date.now(),loading:false});
  } catch(error) {hostSecurityCache.set(key,{...prior,offset,at:Date.now(),loading:false,error:error.message});}
  if(selected===key && detailTab==='incidents')render();
}
function hostSecuritySection(h) {
  const data=hostSecurityCache.get(h.key);
  if(!data){hostSecurityLoad(h.key);return '<section class="panel host-security"><h2>Alertes de sécurité</h2><p role="status">Lecture des vulnérabilités enregistrées…</p></section>';}
  if(!data.loading&&Date.now()-data.at>30000)hostSecurityLoad(h.key,data.offset||0);
  const titles={open:'À vérifier',validated:'Validée',in_progress:'Correction planifiée'};
  const severities={critical:'Critique',high:'Élevée',medium:'Moyenne',low:'Faible',none:'Aucune'};
  const rows=(data.items||[]).map(v=>'<tr><td>'+ui.pill(severities[v.severity]||'Non évaluée',v.severity==='critical'?'critical':v.severity==='high'?'warning':'unknown')+
    (v.kev?' '+ui.pill('Exploitée · KEV','critical'):'')+'</td><td><strong>'+esc(v.cve)+'</strong><small>'+esc(v.package)+'</small></td>'+
    '<td>'+esc(v.installed||'Non mesurée')+' → '+esc(v.fixed||'Correctif non publié')+'</td><td>'+esc((v.sources||[]).join(' · '))+'<small>'+esc(stamp(v.last_seen))+'</small></td>'+
    '<td>'+ui.pill(titles[v.status]||v.status,v.status==='open'?'unknown':'info')+'<small>'+esc(v.confidence||'Confiance non renseignée')+'</small>'+
    (typeof itsmBadge==='function'?itsmBadge('vulnerability',v.id,true):'')+'</td><td>'+
    '<button data-host-sec-review="'+escAttr(v.id)+'" data-host-sec-key="'+escAttr(h.key)+'">'+(roleAllows('admin')?'Examiner / ticket GLPI':'Voir les preuves')+'</button></td></tr>').join('');
  const offset=data.offset||0,total=data.total||0;
  const signals=(data.signals||[]).filter(s=>['critical','warning'].includes(s.level)).map(s=>'<article class="console-security-signal">'+
    '<div>'+ui.pill(s.level==='critical'?'Critique':'Majeur',s.level)+' <strong>'+esc(s.title)+'</strong><p>'+esc(s.detail||'')+'</p>'+
    '<small>Veille sécurité · '+esc(stamp(s.at))+' · Applicabilité à vérifier</small>'+
    (typeof itsmBadge==='function'?itsmBadge('security_alert',s.id+'|'+h.key,true):'')+'</div>'+
    (roleAllows('admin')?'<button data-itsm-origin="security_alert" data-itsm-id="'+escAttr(s.id)+'" data-itsm-host="'+escAttr(h.key)+'">Préparer un ticket de vérification</button>':'')+'</article>').join('');
  return '<section class="panel host-security"><div class="panel-head"><div><span class="console-eyebrow">SÉCURITÉ DU SERVEUR</span><h2>Alertes de sécurité</h2>'+
    '<p>CVE détectées dans les preuves enregistrées · validation humaine avant transmission à GLPI.</p></div>'+
    '<button data-host-sec-refresh="'+escAttr(h.key)+'">Actualiser la liste</button></div>'+
    (data.error?'<p class="form-error" role="alert">Liste non actualisée : '+esc(data.error)+'. Les dernières données disponibles sont conservées.</p>':'')+
    (data.signalsError?'<p class="note" role="status">Les signaux de veille n’ont pas pu être relus : '+esc(data.signalsError)+'</p>':'')+
    (signals?'<h3>Derniers signaux de veille</h3><p class="note">Cinq notifications récentes au plus. Un signal potentiel ne constitue pas une vulnérabilité confirmée.</p>'+signals:'')+
    '<h3 class="console-section-title">Vulnérabilités détectées</h3>'+
    (rows?'<div class="table"><table><caption>'+total+' vulnérabilité(s) active(s) pour '+esc(h.name)+'</caption><thead><tr>'+
      ['Gravité','CVE / composant','Version → cible','Source / observation','Validation / ticket','Action'].map(x=>'<th scope="col">'+x+'</th>').join('')+'</tr></thead><tbody>'+rows+'</tbody></table></div>'+
      '<nav class="console-pagination" aria-label="Pagination des alertes de sécurité"><span>'+ (offset+1)+'–'+Math.min(offset+10,total)+' sur '+total+'</span>'+
      '<button data-host-sec-page="'+Math.max(0,offset-10)+'" '+(!offset?'disabled':'')+'>Précédent</button><button data-host-sec-page="'+(offset+10)+'" '+(offset+10>=total?'disabled':'')+'>Suivant</button></nav>':
      !data.error?'<div class="console-empty"><strong>Aucune vulnérabilité active enregistrée</strong><p>Une analyse absente, ancienne ou incomplète ne permet pas de conclure à un serveur sain. Consultez la couverture dans l’onglet Sécurité.</p></div>':'')+'</section>';
}
hostSection('incidents',6,hostSecuritySection);

const hostSecurityDialog=document.createElement('dialog');
hostSecurityDialog.id='host-security-dialog';
hostSecurityDialog.setAttribute('aria-label','Vulnérabilité et ticket GLPI');
document.body.append(hostSecurityDialog);
let hostSecurityReview=null,hostSecurityRequest=0;
async function hostSecurityOpen(id,key) {
  const request=++hostSecurityRequest;
  hostSecurityDialog.innerHTML='<div class="panel-head"><h2>Vulnérabilité et ticket GLPI</h2><button data-host-sec-close>Fermer</button></div><p role="status">Chargement des preuves…</p>';
  hostSecurityDialog.showModal();
  try {
    const v=await api('/api/security/vulns/'+encodeURIComponent(id));
    if(request!==hostSecurityRequest || !hostSecurityDialog.open)return;
    if(v.host_key!==key)throw new Error('La preuve reçue ne correspond pas au serveur sélectionné.');
    hostSecurityReview={v,key};
    const needsValidation=v.status==='open',canTicket=roleAllows('admin')&&['open','validated','in_progress'].includes(v.status);
    hostSecurityDialog.innerHTML='<form id="host-sec-review-form"><div class="panel-head"><div><span class="console-eyebrow">PREUVE → VALIDATION → TICKET</span><h2>'+esc(v.cve)+' · '+esc(v.host_name||key)+'</h2></div><button type="button" data-host-sec-close>Fermer</button></div>'+
      '<p>'+esc(v.description||'Description non fournie par la source.')+'</p><dl class="console-facts">'+
      [['Composant',v.package],['Version relevée',v.installed],['Version corrigée',v.fixed],['Confiance',v.confidence],['Sources',(v.sources||[]).join(' · ')],['Dernière observation',stamp(v.last_seen)]].map(([k,val])=>'<div><dt>'+esc(k)+'</dt><dd>'+esc(val||'Non renseignée')+'</dd></div>').join('')+'</dl>'+
      '<details open><summary>Preuves disponibles</summary><pre>'+esc(JSON.stringify(v.evidence||{},null,2))+'</pre></details>'+
      (canTicket?'<p class="instruction">'+(needsValidation?'Vérifiez l’applicabilité et les éventuels correctifs rétroportés avant de valider. ':'Cette vulnérabilité a déjà été validée. ')+
        'Le dossier reprend le serveur, la CVE, les versions et le plan de correction. Le ticket externe sera prévisualisé avant confirmation.</p>'+
        (needsValidation?'<label><input type="checkbox" name="verified" required> J’ai vérifié les preuves et confirme l’applicabilité sur ce serveur.</label>':'')+
        '<label>Note de qualification<textarea name="note" maxlength="2000" placeholder="Vérifications, impact et contexte"></textarea></label>'+
        (!operatorIdentity?.authenticated?'<label>Votre nom (déclaratif)<input name="by" maxlength="120" required value="'+escAttr(itsmDeclaredName())+'"></label>':'')+
        '<button type="submit" class="primary">'+(needsValidation?'Valider et préparer le ticket':'Préparer / consulter le ticket GLPI')+'</button>':
        '<p class="note">'+(!roleAllows('admin')?'La préparation du ticket est réservée aux administrateurs.':'Cette vulnérabilité n’est plus active. Consultez son historique dans Sécurité.')+'</p>')+
      '<p role="alert" class="form-error"></p></form>';
  }catch(error){if(request===hostSecurityRequest&&hostSecurityDialog.open)hostSecurityDialog.innerHTML='<h2>Preuves indisponibles</h2><p role="alert">'+esc(error.message)+'</p><button data-host-sec-close>Fermer</button>';}
}
document.addEventListener('click',e=>{
  const review=e.target.closest('[data-host-sec-review]');
  if(review)hostSecurityOpen(review.dataset.hostSecReview,review.dataset.hostSecKey);
  const refresh=e.target.closest('[data-host-sec-refresh]');
  if(refresh)hostSecurityLoad(refresh.dataset.hostSecRefresh,0,true);
  const pager=e.target.closest('[data-host-sec-page]');
  if(pager&&!pager.disabled&&selected)hostSecurityLoad(selected,Number(pager.dataset.hostSecPage),true);
});
hostSecurityDialog.addEventListener('click',e=>{if(e.target.closest('[data-host-sec-close]')){hostSecurityRequest++;hostSecurityDialog.close();}});
hostSecurityDialog.addEventListener('submit',async e=>{
  e.preventDefault();
  if(!hostSecurityReview||!roleAllows('admin'))return;
  const {v,key}=hostSecurityReview,form=e.target,button=form.querySelector('[type=submit]');
  if(button.disabled||!form.reportValidity())return;
  button.disabled=true;
  try{
    const values=Object.fromEntries(new FormData(form));
    if(v.status==='open'){
      if(!form.elements.verified?.checked)throw new Error('La vérification des preuves est requise.');
      await post('/api/security/vulns/action',{id:v.id,action:'validate',note:values.note||'',by:values.by||''});
      v.status='validated';
    }
    if(values.by)itsmRememberName(values.by);
    hostSecurityDialog.close();
    hostSecurityLoad(key,0,true);
    await itsmStart('vulnerability',v.id,key);
  }catch(error){form.querySelector('.form-error').textContent=error.message;}
  finally{button.disabled=false;}
});
