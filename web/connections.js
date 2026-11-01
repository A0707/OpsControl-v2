// Gestion des sources API, chargée uniquement à l'ouverture de Connexions API.
const providerHints={Proxmox:'/api2/json/cluster/resources',Wazuh:'/manager/status',Zabbix:'/api_jsonrpc.php',Elasticsearch:'/_cluster/health',Bacula:'Chemin de lecture selon votre édition de Bacula',JSON:'Chemin de votre endpoint JSON'};
const authHints={Proxmox:'Format attendu : PVEAPIToken=USER@REALM!TOKENID=SECRET',Wazuh:'Format attendu : utilisateur:mot_de_passe — un jeton JWT est ré-obtenu automatiquement à chaque collecte, jamais à coller ici',Zabbix:'Format attendu : le jeton API seul (Administration → API tokens). Requêtes JSON-RPC de lecture uniquement.',Elasticsearch:'Format attendu : ApiKey CLE_ENCODEE',Bacula:'Format selon votre édition de l’API Bacula',JSON:'Valeur complète de l’en-tête Authorization'};
let connectionItems=[];

function openConnection(item={}){
 modal.innerHTML='<form id="connection-form"><div class="panel-head"><h2>Connexion API</h2><button type="button" data-close>Fermer</button></div><div class="edit-grid">'+field('Identifiant','key',item.key||'','required '+(item.key?'readonly':''))+field('Nom','name',item.name||'','required')+'<label>Produit<select name="provider">'+Object.keys(providerHints).map(p=>'<option '+(item.provider===p?'selected':'')+'>'+p+'</option>').join('')+'</select></label><label>Serveur associé<select name="host_key"><option value="">Source globale</option>'+state.hosts.map(h=>'<option value="'+escAttr(h.key)+'" '+(h.key===item.host_key?'selected':'')+'>'+esc(h.name)+'</option>').join('')+'</select></label></div>'+field('URL HTTPS complète de lecture','url',item.url||'','required type="url"')+field('Variable d’environnement contenant les identifiants','token_env',item.token_env||'','placeholder="INFRAOPS_PROXMOX_AUTH"')+'<p id="auth-hint" class="note"></p><label>Certificat CA (chemin .pem local, ou contenu PEM de l’autorité vérifiée — vide : autorités reconnues du système)<textarea name="ca_bundle" rows="3" placeholder="C:\\chemin\\vers\\proxmox-ca.pem">'+esc(item.ca_bundle||'')+'</textarea></label><div class="filters"><button type="button" data-check-cert>Vérifier le certificat du serveur</button><span id="cert-status" class="mini">'+(item.ca_bundle?.startsWith('-----BEGIN')?'Certificat PEM renseigné':'')+'</span></div><div id="cert-result"></div><p class="note">Le lanceur mémorise les identifiants chiffrés avec votre compte Windows et les charge automatiquement. Aucun secret dans ce formulaire ni dans le fichier de connexions. Certificat TLS vérifié ; requêtes GET uniquement.</p><p id="provider-hint"></p><p class="form-error" role="alert"></p><button class="primary" type="submit">Enregistrer la connexion</button></form>';
 const select=modal.querySelector('[name=provider]');
 const hint=()=>{modal.querySelector('#provider-hint').textContent='Endpoint : '+providerHints[select.value];modal.querySelector('#auth-hint').textContent=authHints[select.value]};
 select.onchange=hint;hint();modal.showModal();
}

async function connectionView(){
 const target=$('#connections-list');if(!target)return;
 try{
  connectionItems=await api('/api/connections?compact=1');if(!target.isConnected)return;
  target.innerHTML=connectionItems.map(c=>'<article class="panel"><div class="panel-head"><h2>'+esc(c.name)+'</h2>'+badge(c.last_result?.status||'unknown')+'</div><p>Identifiants ('+esc(c.token_env||'—')+') dans cette instance : '+(c.auth_configured===true?'Disponibles':c.auth_configured===false?'Absents — lancez LANCER-INFRAOPS.ps1 pour charger les identifiants mémorisés':'Non vérifié')+'</p><p>'+esc(c.provider)+' · '+esc(c.url)+'</p><p>Dernière collecte : '+stamp(c.last_result?.collected_at)+'</p><pre>'+esc(JSON.stringify(c.last_result||{message:'Aucune collecte effectuée'},null,2))+'</pre><div class="filters"><button data-collect-api="'+escAttr(c.key)+'">Collecter</button><button data-edit-api="'+escAttr(c.key)+'">Modifier</button><button data-delete-api="'+escAttr(c.key)+'">Supprimer</button></div></article>').join('')||'<div class="panel empty">Ajoutez une source avec son URL de lecture. Aucun produit n’est encore raccordé.</div>';
  connectionDecorators.forEach(decorate=>decorate(target,connectionItems));
 }catch(e){target.textContent=e.message}
}

pageRenderers['Connexions API']=function(){
 $('#content').innerHTML=(typeof apiHelp==='function'?apiHelp():'')+'<section class="panel"><div class="panel-head"><h2>Sources de données</h2><button class="primary" data-add-api>＋ Ajouter une connexion</button></div><p>Collecte manuelle JSON et indicateurs disponibles. Une réponse API reçue ne prouve pas la conformité du produit.</p><p>Proxmox · Wazuh · Zabbix · Elasticsearch · Bacula</p></section><div id="connections-list">Chargement…</div>';
 connectionView();
};

modal.addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-check-cert')){
  const result=modal.querySelector('#cert-result');b.disabled=true;result.innerHTML='Vérification…';
  try{const cert=await post('/api/connections/certificate',{url:modal.querySelector('[name=url]').value});result.innerHTML='<p class="note">Empreinte SHA-256 : <code>'+esc(cert.sha256_fingerprint)+'</code>'+(cert.subject_cn?'<br>Sujet : '+esc(cert.subject_cn):'')+(cert.issuer_cn?' · Émetteur : '+esc(cert.issuer_cn):'')+(cert.not_after?'<br>Valide jusqu’au '+esc(cert.not_after):'')+'<br>Comparez cette empreinte à celle affichée par le produit avant de continuer.</p>'+(cert.usable_anchor?'<button type="button" class="primary" data-pin-cert>Épingler ce certificat après vérification</button>':'<p>Ce certificat ne permet pas à lui seul de valider la connexion.</p>');result.dataset.pem=cert.pem}catch(err){result.textContent=err.message}finally{b.disabled=false}
 }
 if(b.hasAttribute('data-pin-cert')){const result=modal.querySelector('#cert-result');modal.querySelector('[name=ca_bundle]').value=result.dataset.pem;modal.querySelector('#cert-status').textContent='Certificat PEM renseigné';result.innerHTML=''}
});
modal.addEventListener('submit',async e=>{
 if(e.target.id!=='connection-form')return;e.preventDefault();const form=e.target,button=form.querySelector('[type=submit]');button.disabled=true;
 // Relecture de la vue elle-même : load() ne redessine que si le parc change, la carte
 // ajoutée ou modifiée restait donc invisible jusqu'à une autre navigation (OC-AUDIT-021).
 try{await post('/api/connections',Object.fromEntries(new FormData(form)));modal.close();await connectionView();toast('Configuration enregistrée')}catch(error){form.querySelector('.form-error').textContent=error.message}finally{if(button.isConnected)button.disabled=false}
});
$('#content').addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-add-api'))openConnection();if(b.dataset.editApi)openConnection(connectionItems.find(c=>c.key===b.dataset.editApi));
 try{if(b.dataset.collectApi){b.disabled=true;b.textContent='Collecte…';await post('/api/connections/'+encodeURIComponent(b.dataset.collectApi)+'/collect');await connectionView()}if(b.dataset.deleteApi&&confirm('Supprimer cette connexion API ?')){await post('/api/connections/'+encodeURIComponent(b.dataset.deleteApi)+'/delete');await connectionView()}}catch(error){$('#error').textContent=error.message}finally{if(b.isConnected)b.disabled=false}
});
