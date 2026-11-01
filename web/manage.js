// Inventory forms live outside the polling area so refreshes never erase edits.
subtitles['Connexions API']='Sources de collecte HTTPS : Proxmox, Wazuh, Elasticsearch et Bacula.';
const modal=document.createElement('dialog');
modal.id='management-dialog';
document.body.append(modal);
function field(label,name,value='',extra=''){
 return '<label>'+label+'<input name="'+name+'" value="'+escAttr(value)+'" '+extra+'></label>';
}
// Création et modification sont distinctes (audit A2) : en création, un identifiant
// déjà utilisé est refusé par le serveur ; en modification, la révision lue ici détecte
// un changement concurrent. Le port absent reste hérité du profil SSH (audit A3).
let serverForm=null;
async function openServer(key){
 let h={key:'srv-'+[...crypto.getRandomValues(new Uint8Array(8))].map(n=>n.toString(16).padStart(2,'0')).join(''),name:'',ip:'',role:'',environment:'PROD',services:[]},effective,revision=null,collecting=false;
 try{
  const data=key?await api('/api/manage/hosts/'+encodeURIComponent(key)):await api('/api/manage/ssh-profile');
  if(key){h=data.host;revision=data.revision}
  effective=data.effective;collecting=data.collecting;
 }catch(error){toast(error.message);return}
 serverForm={key:key||'',revision,profile:effective.profile,original:h,step:0};
 const inherit=!h.port,profilePorts=effective.profile.ports.join(', ')||'22';
 modal.innerHTML='<form id="server-form" novalidate><div class="panel-head"><h2>'+(key?'Modifier '+esc(h.name):'Ajouter un serveur')+'</h2><button type="button" data-close>Fermer</button></div><p>Configuration locale du suivi. L’empreinte SSH reste à vérifier avant la première collecte.</p>'+
 (collecting?'<p class="note" role="status">Collecte en cours : l’enregistrement reste possible. Le lot en cours garde les paramètres précédents ; les nouveaux s’appliquent au lot suivant.</p>':'')+
 '<div class="edit-grid">'+
 field('Identifiant unique','key',h.key,'required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,79}" maxlength="80" '+(key?'readonly':''))+
 field('Nom du serveur','name',h.name,'required maxlength="120"')+field('Adresse IP (IPv4 ou IPv6, pas de nom DNS)','ip',h.ip,'required maxlength="64"')+
 field('Rôle','role',h.role,'maxlength="80"')+field('Environnement','environment',h.environment,'maxlength="80"')+
 '<label>Importance<select name="criticality"><option value="standard">Standard</option><option value="critical" '+(h.criticality==='critical'?'selected':'')+'>Critique</option></select></label>'+
 field('Compte SSH (vide : profil SSH)','user',h.user||'','maxlength="64" pattern="[A-Za-z_][A-Za-z0-9_.-]{0,63}"')+
 '<label>Port SSH<select name="port_mode"><option value="inherit" '+(inherit?'selected':'')+'>Hériter du profil SSH ('+esc(profilePorts)+')</option><option value="custom" '+(inherit?'':'selected')+'>Port spécifique</option></select></label>'+
 field('Port spécifique','port',h.port||'','type="number" min="1" max="65535" '+(inherit?'disabled':'required'))+
 '</div><p class="note" id="server-effective" aria-live="polite"></p><label>Services critiques — un nom d’unité par ligne<textarea name="services" rows="5">'+esc((h.services||[]).join('\n'))+'</textarea></label><p class="note">ModSecurity : renseigner nginx ou apache2/httpd selon le serveur installé. Ajouter keepalived seulement si utilisé. ModSecurity est un module, pas nécessairement un service systemd.</p><label><input type="checkbox" name="collect_enabled" '+(h.collect_enabled===false?'':'checked')+'> Collecte SSH activée</label><button type="button" data-test-server-params>Tester avec ces paramètres</button><section id="server-test-results" aria-live="polite"></section><p class="form-error" role="alert"></p><div class="panel-head"><button class="primary" type="submit">'+(key?'Enregistrer les modifications':'Ajouter ce serveur')+'</button>'+(key?'<button type="button" data-delete-server="'+escAttr(key)+'">Supprimer du suivi</button>':'')+'</div></form>';
 showEffective(modal.querySelector('#server-form'));
 installServerWizard(modal.querySelector('#server-form'));
 modal.showModal();
}
const SERVER_DRAFT='opscontrol-server-draft-v1';
const SERVER_STEPS=[['Identité',['key','name','ip','role','environment']],['Accès SSH',['user','port_mode','port']],['Contrôles',['criticality','services','collect_enabled']],['Récapitulatif',[]]];
// Les champs restent dans le même formulaire : revenir à une étape ne perd ni saisie ni diagnostic.
function installServerWizard(form){
 const grid=form.querySelector('.edit-grid'),footer=form.querySelector('.panel-head:last-child');
 const note=form.elements.services.closest('label').nextElementSibling;
 const nav=document.createElement('ol');nav.className='server-steps';nav.setAttribute('aria-label','Étapes de configuration');
 nav.innerHTML=SERVER_STEPS.map(([label],i)=>'<li><button type="button" data-server-step="'+i+'"><span>'+(i+1)+'</span> '+label+'</button></li>').join('');
 grid.before(nav);
 SERVER_STEPS.forEach(([title,names],i)=>{
  const panel=document.createElement('section');panel.className='server-step';panel.dataset.step=i;panel.setAttribute('aria-labelledby','server-step-title-'+i);
  panel.innerHTML='<h3 id="server-step-title-'+i+'" tabindex="-1">'+(i+1)+'. '+title+'</h3><div class="edit-grid"></div>';
  const fields=panel.querySelector('.edit-grid');
  for(const name of names)fields.append(form.elements[name].closest('label'));
  if(i===0)panel.insertAdjacentHTML('beforeend','<p class="note">Identifiant technique généré : modifiable avant création, stable ensuite. Le nom peut être modifié ultérieurement.</p>');
  if(i===1){panel.append(form.querySelector('#server-effective'),form.querySelector('[data-test-server-params]'),form.querySelector('#server-test-results'));panel.insertAdjacentHTML('beforeend','<p class="note">Profil SSH en lecture seule. Aucun test ne part sans votre action ; aucun secret n’est saisi dans ce formulaire.</p>')}
  if(i===2)panel.append(note);
  if(i===3)panel.insertAdjacentHTML('beforeend','<div id="server-review"></div><p class="note">L’enregistrement ne lance aucun audit ni aucune commande corrective sur le serveur.</p>');
  footer.before(panel);
 });
 grid.remove();
 footer.classList.add('server-wizard-actions');
 footer.insertAdjacentHTML('afterbegin','<button type="button" data-server-back>Précédent</button><button class="primary" type="button" data-server-next>Suivant</button>'+(!serverForm.key?'<button type="button" data-server-draft>Garder le brouillon</button>':''));
 if(!serverForm.key&&readServerDraft())nav.insertAdjacentHTML('beforebegin','<div class="instruction" data-draft-banner>Brouillon disponible dans cet onglet. <button type="button" data-server-resume>Reprendre le brouillon</button><button type="button" data-server-discard>Écarter le brouillon</button></div>');
 setServerStep(form,0,false);
}
function reviewServer(form){
 const values=serverValues(form),old=serverForm.original;
 const rows=[['Identifiant',values.key],['Nom',values.name],['Adresse IP',values.ip],['Environnement',values.environment||'À renseigner'],['Rôle',values.role||'À renseigner'],['Compte SSH',values.user||serverForm.profile.users.join(', ')+' (profil SSH)'],['Port SSH',values.port??serverForm.profile.ports.join(', ')+' (profil SSH)'],['Importance',values.criticality==='critical'?'Critique':'Standard'],['Collecte SSH',values.collect_enabled?'Activée':'Désactivée'],['Services critiques',values.services.join(', ')||'Aucun service déclaré']];
 const changes=Object.keys(values).filter(k=>!['mode','revision'].includes(k)&&JSON.stringify(values[k]??null)!==JSON.stringify(old[k]??(k==='collect_enabled'?true:k==='services'?[]:k==='user'?'':null)));
 const names={key:'identifiant',name:'nom',ip:'adresse IP',role:'rôle',environment:'environnement',criticality:'importance',user:'compte SSH',port:'port SSH',services:'services critiques',collect_enabled:'collecte SSH'};
 form.querySelector('#server-review').innerHTML='<dl class="server-review-grid">'+rows.map(([label,value])=>'<div><dt>'+label+'</dt><dd>'+esc(value)+'</dd></div>').join('')+'</dl><p class="instruction">'+(serverForm.key?(changes.length?'Champs modifiés : '+esc(changes.map(k=>names[k]).join(', ')):'Aucune modification des champs affichés.'):'Nouveau serveur : visible dès l’enregistrement, avec première collecte en attente. L’empreinte SSH n’est pas approuvée automatiquement.')+'</p>';
}
function setServerStep(form,index,focus=true){
 serverForm.step=index;
 form.querySelectorAll('.server-step').forEach(panel=>{panel.hidden=Number(panel.dataset.step)!==index});
 form.querySelectorAll('[data-server-step]').forEach(button=>{if(Number(button.dataset.serverStep)===index)button.setAttribute('aria-current','step');else button.removeAttribute('aria-current')});
 form.querySelector('[data-server-back]').hidden=index===0;
 form.querySelector('[data-server-next]').hidden=index===3;
 form.querySelector('[type=submit]').hidden=index!==3;
 if(index===3)reviewServer(form);
 if(focus)form.querySelector('#server-step-title-'+index)?.focus();
}
function navigateServerStep(form,index){
 clearFieldErrors(form);
 for(let i=serverForm.step;i<index;i++){
  const errors=localErrors(form,SERVER_STEPS[i][1]);
  if(Object.keys(errors).length){setServerStep(form,i,false);showFieldErrors(form,errors);form.querySelector('.form-error').textContent='Compléter les champs signalés avant de continuer.';return}
 }
 setServerStep(form,index);
}
function readServerDraft(){
 try{const raw=sessionStorage.getItem(SERVER_DRAFT);if(!raw||raw.length>32768)return null;const draft=JSON.parse(raw),age=Date.now()-draft.at;return draft.version===1&&draft.values&&typeof draft.values==='object'&&Number.isFinite(draft.at)&&age>=0&&age<86400000?draft:null}catch{return null}
}
function saveServerDraft(form){
 const values={};
 for(const [,names]of SERVER_STEPS)for(const name of names){const field=form.elements[name];values[name]=field.type==='checkbox'?field.checked:field.value}
 try{const raw=JSON.stringify({version:1,at:Date.now(),values});if(raw.length>32768)throw Error('size');sessionStorage.setItem(SERVER_DRAFT,raw)}catch{form.querySelector('.form-error').textContent='Brouillon indisponible dans cet onglet ou saisie trop volumineuse. La saisie reste dans le formulaire.';return}
 modal.close();toast('Brouillon conservé dans cet onglet (24 h maximum). Aucun serveur enregistré.');
}
function resumeServerDraft(form){
 const draft=readServerDraft();if(!draft)return;
 for(const [,names]of SERVER_STEPS)for(const name of names){const field=form.elements[name],value=draft.values[name];if(field.type==='checkbox')field.checked=value===true;else if(typeof value==='string')field.value=value}
 const port=form.elements.port,custom=form.elements.port_mode.value==='custom';port.disabled=!custom;port.required=custom;
 form.querySelector('[data-draft-banner]')?.remove();clearFieldErrors(form);showEffective(form);setServerStep(form,0);
}
// Paramètres SSH réellement utilisés et leur origine, recalculés à chaque saisie.
function showEffective(form){
 const target=form?.querySelector('#server-effective');if(!target||!serverForm)return;
 const user=form.elements.user.value.trim(),custom=form.elements.port_mode.value==='custom',port=form.elements.port.value.trim();
 const users=user?user+' (serveur)':(serverForm.profile.users.join(', ')||'—')+' (profil SSH)';
 const ports=custom?(port||'à renseigner')+' (serveur)':(serverForm.profile.ports.join(', ')||'22')+' (profil SSH)';
 target.textContent='Paramètres effectifs · compte : '+users+' · port : '+ports;
}
function clearFieldErrors(form){
 form.querySelectorAll('.field-error').forEach(e=>e.remove());
 form.querySelectorAll('[aria-invalid]').forEach(e=>{e.removeAttribute('aria-invalid');e.removeAttribute('aria-describedby')});
 form.querySelector('.form-error').textContent='';
}
// Erreur affichée sous le champ concerné ; les valeurs saisies restent en place.
function showFieldErrors(form,fields){
 let first=null;
 for(const [name,message] of Object.entries(fields||{})){
  const input=form.elements[name];if(!input?.closest)continue;
  const step=SERVER_STEPS.findIndex(([,names])=>names.includes(name));if(!first&&step>=0)setServerStep(form,step,false);
  const id='error-'+name;input.setAttribute('aria-invalid','true');input.setAttribute('aria-describedby',id);
  input.closest('label').insertAdjacentHTML('beforeend','<small class="field-error" id="'+id+'">'+esc(message)+'</small>');
  first=first||input;
 }
 first?.focus();return Boolean(first);
}
function serverValues(form){
 const v=name=>form.elements[name].value.trim();
 const values={key:v('key'),name:v('name'),ip:v('ip'),role:v('role'),environment:v('environment'),criticality:form.elements.criticality.value,user:v('user'),
  port:form.elements.port_mode.value==='custom'?Number(v('port')):null,
  services:form.elements.services.value.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean),collect_enabled:form.elements.collect_enabled.checked,
  mode:serverForm?.key?'update':'create'};
 if(serverForm?.revision)values.revision=serverForm.revision;
 return values;
}
// Contrôle local avant envoi (espaces retirés, comme le serveur) : message sous le champ.
function localErrors(form,names=['key','name','ip','user','port']){
 const fields={};
 for(const name of names){const input=form.elements[name];if(input.disabled||input.type==='checkbox')continue;const before=input.value;input.value=before.trim();if(!input.checkValidity())fields[name]=input.validationMessage;input.value=before}
 return fields;
}
async function testServerParams(button){
 const form=button.closest('form'),target=form.querySelector('#server-test-results');
 for(const name of ['ip','user','port'])if(!form.elements[name].disabled&&!form.elements[name].reportValidity())return;
 // Port hérité : le test vise le premier port du profil, comme la première tentative de collecte.
 const custom=form.elements.port_mode.value==='custom';
 const params={ip:form.elements.ip.value.trim(),user:form.elements.user.value.trim(),port:Number(custom?form.elements.port.value:(serverForm?.profile.ports[0]||22))};
 target.textContent='Test de '+params.ip+':'+params.port+' en cours…';button.disabled=true;
 try{
  const result=await post('/api/hosts/test-params',params);
  if(target.isConnected)target.innerHTML='<h3>Résultat des paramètres testés</h3>'+hostTestMarkup(result);
 }catch(error){if(target.isConnected)target.textContent=error.message}
 finally{if(button.isConnected)button.disabled=false}
}
renderHooks.push(function(){
 if(!state)return;
 if(selected&&hostDetail){
  const banner=$('.detail-banner');
  banner?.insertAdjacentHTML('beforeend','<button data-edit-server="'+escAttr(selected)+'">Modifier le serveur et ses services critiques</button>');
 }else if(page==='Serveurs'){
  $('#content').insertAdjacentHTML('afterbegin','<div class="panel-head"><p>Gérer le parc et les services critiques surveillés.</p><button class="primary" data-add-server>＋ Ajouter un serveur</button></div>');
 }
});
modal.addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 const form=b.closest('#server-form');
 if(form&&b.hasAttribute('data-server-step'))navigateServerStep(form,Number(b.dataset.serverStep));
 if(form&&b.hasAttribute('data-server-next'))navigateServerStep(form,Math.min(3,serverForm.step+1));
 if(form&&b.hasAttribute('data-server-back'))navigateServerStep(form,Math.max(0,serverForm.step-1));
 if(form&&b.hasAttribute('data-server-draft'))saveServerDraft(form);
 if(form&&b.hasAttribute('data-server-resume'))resumeServerDraft(form);
 if(form&&b.hasAttribute('data-server-discard')){try{sessionStorage.removeItem(SERVER_DRAFT)}catch{}form.querySelector('[data-draft-banner]')?.remove()}
 if(b.hasAttribute('data-close'))modal.close();
 if(b.hasAttribute('data-test-server-params'))testServerParams(b);
 if(b.dataset.openExisting)openServer(b.dataset.openExisting);
 if(b.dataset.deleteServer&&confirm('Retirer ce serveur du suivi et supprimer son historique local ?')){
  try{const result=await post('/api/manage/hosts/'+encodeURIComponent(b.dataset.deleteServer)+'/delete');modal.close();selected=null;hostDetail=null;await load();toast(result.message||'Serveur retiré du suivi')}catch(e){modal.querySelector('.form-error').textContent=e.message}
 }
});
modal.addEventListener('input',e=>{const form=e.target.closest('#server-form');if(form)showEffective(form)});
modal.addEventListener('keydown',e=>{
 const form=e.target.closest('#server-form');
 if(form&&e.key==='Enter'&&e.target.matches('input')&&serverForm.step<3){e.preventDefault();navigateServerStep(form,serverForm.step+1)}
});
modal.addEventListener('change',e=>{
 if(e.target.name!=='port_mode')return;
 const form=e.target.form,port=form.elements.port,custom=e.target.value==='custom';
 port.disabled=!custom;port.required=custom;if(custom&&!port.value)port.value=serverForm?.profile.ports[0]||22;showEffective(form);
});
modal.addEventListener('submit',async e=>{
 e.preventDefault();const form=e.target;
 if(form.id!=='server-form')return;
 if(serverForm.step<3){navigateServerStep(form,serverForm.step+1);return}
 const button=form.querySelector('[type=submit]');
 if(button?.disabled)return;
 clearFieldErrors(form);
 if(showFieldErrors(form,localErrors(form)))return;
 if(button)button.disabled=true;
 const values=serverValues(form);
 try{
  const result=await post('/api/manage/hosts',values);
  if(values.mode==='create')try{sessionStorage.removeItem(SERVER_DRAFT)}catch{}
  modal.close();await load();toast(result.message||'Configuration enregistrée');
 }catch(error){
  if(!form.isConnected)return;
  const message=form.querySelector('.form-error');
  message.textContent=showFieldErrors(form,error.fields)?'Saisie à corriger : voir les champs signalés.':error.message;
  // Identifiant déjà utilisé : lien vers le serveur existant plutôt qu'un écrasement.
  if(error.status===409&&values.mode==='create'&&state.hosts.some(h=>h.key===values.key))
   message.insertAdjacentHTML('beforeend',' <button type="button" class="link" data-open-existing="'+escAttr(values.key)+'">Ouvrir le serveur existant</button>');
 }finally{if(button?.isConnected)button.disabled=false}
});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-add-server'))openServer();
 if(b.dataset.editServer)openServer(b.dataset.editServer);
});
