// Utilitaires ES sans DOM ni requête au chargement.
export const esc=v=>String(v??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Dans un attribut, une valeur absente reste vide : esc(null) donnait « — », d'où data-host="—"
// et l'ouverture silencieusement ratée d'une fiche sans clé.
export const escAttr=v=>v==null?'':esc(v);

export const SEVERITY={
 critical:{label:'Critique',plural:'Critiques',tone:'critical',rank:0},
 unreachable:{label:'Injoignable',plural:'Injoignables',tone:'critical',rank:1},
 warning:{label:'Majeur',plural:'Majeurs',tone:'warning',rank:2},
 preventive:{label:'Préventif',plural:'Préventifs',tone:'info',rank:3},
 unknown:{label:'Inconnu',plural:'Inconnus',tone:'unknown',rank:4},
 stale:{label:'Ancien',plural:'Anciens',tone:'unknown',rank:5},
 info:{label:'Information',plural:'Informations',tone:'unknown',rank:6},
 ok:{label:'OK',plural:'OK',tone:'ok',rank:7}};

const inFlightGets=new Map();
// Refus de la politique d'accès (401/403/429) et erreurs serveur : message lisible + référence.
// Erreurs de validation (422) : un message par champ, en français, au lieu du JSON
// brut de Pydantic ; error.fields permet de l'afficher sous le bon champ (audit A6).
const FIELD_MESSAGES={missing:'champ obligatoire',string_pattern_mismatch:'format invalide',string_too_long:'trop long',string_too_short:'obligatoire',greater_than_equal:'valeur trop petite',less_than_equal:'valeur trop grande',int_parsing:'nombre entier attendu',literal_error:'valeur non proposée',extra_forbidden:'champ non accepté'};
export function fieldErrors(detail){
 const fields={};
 for(const item of Array.isArray(detail)?detail:[]){
  const loc=(item?.loc||[]).filter(p=>p!=='body'),name=String(loc[0]??'');
  const message=FIELD_MESSAGES[item?.type]||String(item?.msg||'valeur invalide').replace(/^Value error, /,'');
  if(name&&!fields[name])fields[name]=message;
 }
 return fields;
}
async function apiError(r){
 let detail='',fields={};try{const body=await r.json();fields=fieldErrors(body.detail);detail=typeof body.detail==='string'?body.detail:Object.keys(fields).length?Object.entries(fields).map(([k,v])=>k+' : '+v).join(' · '):JSON.stringify(body.detail);if(body.request_id&&r.status>=500)detail+=' (référence '+body.request_id+')'}catch{detail=r.statusText}
 const prefix={401:'Accès non authentifié',403:'Action non autorisée',422:'Saisie à corriger',429:'Trop de demandes'}[r.status]||('Erreur '+r.status);
 const error=Error(prefix+' : '+detail);error.status=r.status;error.fields=fields;error.detail=detail;return error;
}
// Délais par défaut : une requête suspendue (VPN coupé, proxy figé) ne doit pas laisser
// l'écran « en chargement » indéfiniment (audit FE-02). Une collecte API peut enchaîner
// plusieurs appels de 10 s côté serveur, d'où un délai plus long pour les écritures.
export const TIMEOUTS={GET:30000,WRITE:120000};
function withTimeout(options,ms){
 const timer=AbortSignal.timeout(ms);
 const signal=options?.signal?(AbortSignal.any?AbortSignal.any([options.signal,timer]):options.signal):timer;
 return {...options,signal};
}
// Erreurs réseau du navigateur (« Failed to fetch », en anglais) traduites en message utile.
function networkError(error,ms){
 if(error?.name==='TimeoutError')return Object.assign(Error('Délai dépassé ('+Math.round(ms/1000)+' s) : serveur OpsControl lent ou injoignable.'),{status:0,timeout:true});
 if(error?.name==='AbortError')return error;
 if(error instanceof TypeError)return Object.assign(Error('Serveur OpsControl injoignable : vérifier le réseau ou le VPN.'),{status:0});
 return error;
}
async function send(url,options,ms){
 let r;
 try{r=await fetch(url,withTimeout(options,ms))}catch(error){throw networkError(error,ms)}
 if(!r.ok)throw await apiError(r);
 return r.json();
}
// Lectures conditionnelles (ETag / 304). Les vues interrogées toutes les 5 à 10 s (alertes 75 Ko,
// parc 137 Ko) étaient retéléchargées même inchangées. Le serveur répond 304 sans corps ; le texte
// conservé est relu (JSON.parse) pour qu'une vue qui modifie l'objet reçu n'altère pas la copie.
const knownBodies=new Map(),KNOWN_MAX=40;
async function sendGet(url,options,ms){
 const known=knownBodies.get(url);
 const headers=known?{...(options?.headers||{}),'If-None-Match':known.etag}:options?.headers;
 let r;
 try{r=await fetch(url,withTimeout({...options,headers},ms))}catch(error){throw networkError(error,ms)}
 if(r.status===304&&known){
  // Même contenu : seul l'horodatage de construction a changé, il est appliqué à la copie.
  const data=JSON.parse(known.text),at=r.headers.get('X-Generated-At');
  if(at&&data&&typeof data==='object'&&'generated_at' in data)data.generated_at=at;
  return data;
 }
 if(!r.ok)throw await apiError(r);
 const text=await r.text(),etag=r.headers.get('ETag');
 knownBodies.delete(url);
 if(etag){knownBodies.set(url,{etag,text});if(knownBodies.size>KNOWN_MAX)knownBodies.delete(knownBodies.keys().next().value)}
 return JSON.parse(text);
}
async function api(url,options){
 const method=String(options?.method||'GET').toUpperCase();
 if(method!=='GET')return send(url,options,TIMEOUTS.WRITE);
 // Un appel avec son propre signal n'est jamais partagé : sinon l'annulation de l'un
 // annulait l'autre, ou un appel sans délai héritait d'un délai qui n'était pas le sien.
 if(options?.signal)return sendGet(url,options,TIMEOUTS.GET);
 if(inFlightGets.has(url))return inFlightGets.get(url);
 const request=sendGet(url,options,TIMEOUTS.GET).finally(()=>inFlightGets.delete(url));
 inFlightGets.set(url,request);return request;
}
async function post(url,body){return api(url,{method:'POST',headers:{'X-Cockpit-Request':'1','Content-Type':'application/json'},body:JSON.stringify(body||{})})}

export { api, post };
