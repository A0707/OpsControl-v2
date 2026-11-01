const wafCommandDialog=document.createElement('dialog');
wafCommandDialog.id='waf-command-dialog';
document.body.append(wafCommandDialog);
wafCommandDialog.addEventListener('input',()=>{const target=wafCommandDialog.querySelector('#waf-command-result');if(target)target.innerHTML=''});
function openWafCommand(hostKey){
 const h=state.hosts.find(x=>x.key===hostKey);
 wafCommandDialog.innerHTML='<form id="waf-command-form"><div class="panel-head"><h2>Commande IP · Fail2ban</h2><button type="button" data-close-command>Fermer</button></div><p>Sur '+(h?esc(h.name)+' · '+esc(h.ip):'ce serveur')+' · jail apache-modsecurity</p><input type="hidden" name="host_key" value="'+escAttr(hostKey)+'"><label>Adresse IPv4 ou IPv6<input name="ip" required maxlength="64" placeholder="Ex. 192.0.2.15"></label><label>Action<select name="action"><option value="ban">Bannir cette IP</option><option value="whitelist">Ajouter en liste blanche Fail2ban</option><option value="inspect">Vérifier cette IP (lecture seule)</option><option value="unban">Retirer le ban actuel</option><option value="remove_whitelist">Retirer de la liste blanche</option></select></label><p>Préparation et copie uniquement. Les commandes s’exécutent manuellement sur le WAF.</p><button class="primary" type="submit">Préparer la commande</button><p id="waf-command-error" role="alert"></p><section id="waf-command-result"></section></form>';
 wafCommandDialog.showModal();
}
wafCommandDialog.addEventListener('submit',async e=>{
 e.preventDefault();const form=e.target,button=form.querySelector('[type=submit]');button.disabled=true;
 const target=form.querySelector('#waf-command-result');target.innerHTML='';form.querySelector('#waf-command-error').textContent='';
 try{
  const plan=await post('/api/waf/commands',Object.fromEntries(new FormData(form)));
  target.innerHTML='<p class="instruction">'+esc(plan.note)+'</p>'+command('À exécuter manuellement sur '+plan.execution_host,plan.commands.join('\n'))+command('Vérifier après intervention',plan.verify.join('\n'))+(plan.undo?command('Commande inverse de l’action principale',plan.undo):'');
 }catch(error){form.querySelector('#waf-command-error').textContent=error.message}finally{button.disabled=false}
});
wafCommandDialog.addEventListener('click',async e=>{
 const b=e.target.closest('button');if(!b)return;
 if(b.hasAttribute('data-close-command'))wafCommandDialog.close();
 if(b.hasAttribute('data-copy')){
  e.preventDefault();
  try{await navigator.clipboard.writeText(b.dataset.copy);toast('Commande copiée · aucune exécution');copyConfirm(b)}catch(e){wafCommandDialog.querySelector('#waf-command-error').textContent='Copie indisponible : sélectionner le texte de la commande.'}
 }
});
// Copy controls generated inside a form must not submit it.
new MutationObserver(()=>wafCommandDialog.querySelectorAll('[data-copy]').forEach(b=>b.type='button')).observe(wafCommandDialog,{childList:true,subtree:true});
$('#content').addEventListener('click',e=>{const b=e.target.closest('[data-waf-command]');if(b)openWafCommand(b.dataset.wafCommand)});

function wafAlerts(h){
 const w=h.waf||{},certs=w.certificates||[],findings=w.analysis||[];
 const critical=findings.filter(f=>f.severity==='critical').length;
 const warnings=findings.filter(f=>f.severity==='warning').length;
 let html=wafPanel('Constats WAF à examiner','<div class="panel-head"><p>'+critical+' alerte(s) critique(s) · '+warnings+' avertissement(s) · '+findings.filter(f=>f.severity==='unknown').length+' contrôle(s) incomplet(s)'+(h.stale?' · PREUVES ANCIENNES':'')+'</p><button class="primary" data-waf-command="'+escAttr(h.key)+'">Préparer ban / liste blanche</button></div><p class="note">Une forte fréquence d’accès ou une alerte ModSecurity ne suffit pas à conclure qu’une IP doit être bannie.</p>'+findings.map(f=>'<details class="waf-finding"><summary>'+badge(h.stale?'unknown':f.severity)+' '+esc(f.title)+'</summary><p><b>Constat · </b>'+esc(f.evidence)+'</p>'+(f.solution_command?'<p><b>Recommandation · </b>'+esc(f.solution_command.replace(/^# /,''))+'</p>':'')+(f.check_command?command('Commande de diagnostic',f.check_command):'')+'</details>').join('')+(findings.length?'':'<p>Aucune anomalie issue des contrôles disponibles. Les sources non collectées restent à vérifier.</p>'));
 // Tous les certificats déclarés, du plus proche de l'expiration au plus lointain. L'ancien filtre sur
 // les certificats joker (CN=*.…) masquait 5 certificats sur 12, dont un certificat expiré en production.
 const allCerts=certs.map(c=>({...c,cn:(c.subject||'').match(/\bCN\s*=\s*([^,/]+)/i)?.[1]?.trim()})).sort((a,b)=>{const av=Date.parse(a.not_after),bv=Date.parse(b.not_after);return (Number.isFinite(av)?av:Infinity)-(Number.isFinite(bv)?bv:Infinity)});
 html+=wafPanel('Certificats SSL/TLS · expiration',wafTable(['État','Nom (CN)','Jours restants','Date d’expiration','Fichier'],allCerts.map(c=>[c.expiration_state||'Non vérifié',c.cn||'Non lu',c.days_remaining,c.not_after?new Date(c.not_after).toLocaleDateString('fr-FR',{timeZone:'UTC'}):'Non mesurée',c.path]))+'<p class="note">'+allCerts.length+' certificat(s) déclaré(s) dans Apache, dont '+allCerts.filter(c=>c.cn?.startsWith('*.')).length+' joker. Date lue dans le fichier : le certificat réellement présenté par le vhost reste à vérifier.</p>'+(h.stale?'<p class="note">Dernière collecte ancienne : actualiser le WAF.</p>':''));
 html+=wafPanel('Liste blanche Fail2ban observée',wafTable(['IP / réseau ignoré'],(w.sections?.ignoreip?.data?.addresses||[]).map(ip=>[ip]))+'<p class="note">'+esc(w.sections?.ignoreip?.data?.scope||'Aucune lecture disponible. Actualiser le WAF.')+'</p>');
 return html;
}
const advancedWafBeforeControls=advancedWaf;
advancedWaf=function(h){
 const html=advancedWafBeforeControls(h);
 const point=html.indexOf('<div class="stats');
 return point<0?html+wafAlerts(h):html.slice(0,point)+wafAlerts(h)+html.slice(point);
};
wafNames.certificates='Certificats SSL/TLS déclarés';wafNames.ignoreip='Liste blanche Fail2ban';
