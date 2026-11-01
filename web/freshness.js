// Age advances locally; a page refresh never becomes a new observation.
// Un fuseau explicite rend les dates comparables entre postes d'exploitation.
const exactTimeFormat = new Intl.DateTimeFormat('fr-FR', {timeZone:'Africa/Casablanca',
  day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZoneName:'shortOffset'});
function exactTimeMarkup(value) {
  // Sans décalage dans la preuve, le fuseau du navigateur inventerait une heure.
  const ms=value && /(?:Z|[+-]\d{2}:?\d{2})$/i.test(String(value)) ? Date.parse(value) : NaN;
  if(!Number.isFinite(ms))return '<span class="exact-time unknown">Date inconnue</span>';
  const iso=new Date(ms).toISOString();
  return '<time class="exact-time" datetime="'+escAttr(iso)+'" title="Africa/Casablanca · '+escAttr(iso)+'">'+esc(exactTimeFormat.format(ms))+'</time>';
}
function ageSeconds(value, now=Date.now()) {
  if (!value) return null;
  const ms=Date.parse(value);
  return Number.isFinite(ms) ? Math.floor((now-ms)/1000) : null;
}
function ageText(value, now=Date.now()) {
  const age=ageSeconds(value,now);
  if(age===null)return 'Date inconnue';
  if(age<0)return 'Horloge à vérifier';
  if(age<60)return 'il y a '+age+' s';
  if(age<3600)return 'il y a '+Math.floor(age/60)+' min '+age%60+' s';
  if(age<86400)return 'il y a '+Math.floor(age/3600)+' h';
  return 'il y a '+Math.floor(age/86400)+' j';
}
function freshnessMarkup(value, label='Mesure', budget=30) {
  const age=ageSeconds(value), old=age===null||age<0||age>budget;
  return '<time class="data-age'+(old?' overdue':'')+'" data-observed-at="'+escAttr(value||'')+
    '" data-age-label="'+escAttr(label)+'" data-age-budget="'+budget+'" title="'+escAttr(stamp(value))+'">'+
    esc(label+' : '+ageText(value)+(old?' · À actualiser':''))+'</time>';
}
function updateAges() {
  if(document.hidden)return;
  document.querySelectorAll('[data-observed-at]').forEach(el=>{
    const value=el.dataset.observedAt, age=ageSeconds(value);
    const old=age===null||age<0||age>Number(el.dataset.ageBudget);
    el.textContent=el.dataset.ageLabel+' : '+ageText(value)+(old?' · À actualiser':'');
    el.classList.toggle('overdue',old);
  });
}
poll('ages-des-preuves',1000,updateAges);
document.addEventListener('visibilitychange',updateAges);
