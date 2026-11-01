// Présentation V2 des résultats API, différée avec la page Connexions API.
function v2ConnectionSummary(c) {
 const r=sourceResult(c),ind=r.indicators||{};
 const facts=Object.entries(ind).filter(([,value])=>['number','string','boolean'].includes(typeof value)).slice(0,8)
  .map(([key,value])=>'<div><dt>'+esc(key.replace(/_/g,' '))+'</dt><dd>'+esc(typeof value==='number'?ui.fmt(value):value)+'</dd></div>').join('');
 return '<div class="v2-conn-summary">'+sourceStatus(c)+
  (r.error?'<p role="alert" class="form-error">'+esc(r.error)+'</p>':'')+
  (r.warning?'<p class="instruction">'+esc(r.warning)+'</p>':'')+
  (facts?'<dl class="v2-facts">'+facts+'</dl>':'<p class="note">Aucun indicateur collecté.</p>')+
  (r.summary?'<p class="note">Réponse reçue : '+esc(r.summary.entries)+' entrée(s), '+ui.bytes(r.summary.bytes)+'. Corps brut jamais conservé ni affiché.</p>':'')+
  (r.inventory?.scope?'<p class="note">Périmètre : '+esc(r.inventory.scope)+'</p>':'')+'</div>';
}
connectionDecorators.push((list,items)=>{
 list.querySelectorAll('article.panel').forEach((card,index)=>{
  const connection=items[index],raw=card.querySelector('pre');
  if(connection&&raw)raw.outerHTML=v2ConnectionSummary(connection);
 });
});
