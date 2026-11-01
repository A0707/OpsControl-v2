// Lot 5 : cycle de vie du frontend. (1) Droits : selon le rôle de la session, les actions
// interdites sont désactivées et expliquées, y compris dans les vues redessinées hors de render ;
// aucun POST ne part. (2) Minuteries : onglet caché, seules les tâches autorisées tournent, au
// rythme réduit ; au retour, rattrapage immédiat. (3) render garde son identité. Fixture synthétique.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const now=()=>new Date().toISOString();
async function open(browser,role,{clock=false}={}){
 const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[],posts=[],gets=[];
 page.on('pageerror',e=>errors.push(e.message));
 if(clock)await page.clock.install();
 await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}}});
 const host={key:'web01',name:'web01',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',services:[],findings:[],checks:[],coverage:{measured:10,total:15},collected_at:now(),alerts:{counts:{},items:[]}};
 const alert={id:'a1',source:'SSH',severity:'critical',title:'Service en échec',fresh:true,observed_at:now(),count:1,targets:[{name:'web01',host_key:'web01'}]};
 const who={viewer:{role:'viewer',can_operate:false,can_admin:false},operator:{role:'operator',can_operate:true,can_admin:false},admin:{role:'admin',can_operate:true,can_admin:true}}[role];
 await page.route('http://cycle.test/**',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(req.method()!=='GET'){posts.push(url.pathname);return route.fulfill({status:403,json:{detail:'refusé'}});}
  gets.push(url.pathname);
  if(url.pathname==='/api/whoami')return route.fulfill({json:{mode:'proxy',authenticated:true,user:role+'@ex.test',label:role+'@ex.test',...who}});
  if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[host],counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
  if(url.pathname==='/api/hosts/web01')return route.fulfill({json:{...host,history:[]}});
  if(url.pathname==='/api/alerts')return route.fulfill({json:{alerts:[alert],counts:{critical:1,warning:0,preventive:0,info:0,info_stale:0},levels:[{key:'critical',label:'Critique',delay:'Immédiat'}],policy:[],sources:[],scope:'x'}});
  if(url.pathname==='/api/incidents/maintenance')return route.fulfill({json:{items:[],active:0}});
  if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
  const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
  if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
  return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
 });
 await page.goto('http://cycle.test/');
 if(clock)await page.clock.runFor(3000);
 await page.waitForFunction(()=>typeof state!=='undefined'&&state&&operatorIdentity&&operatorIdentity.role);
 return {page,errors,posts,gets};
}
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const renderRef=[];
  for(const role of ['viewer','operator','admin']){
   const {page,errors,posts}=await open(browser,role);
   await page.evaluate(()=>render());
   const locked=sel=>page.locator(sel).first().evaluate(e=>!!e.dataset.roleLocked&&e.disabled);
   // Barre de contrôle : collecte (opérateur) et intervalle (administrateur).
   assert.equal(await locked('#refresh'),role==='viewer','#refresh pour '+role);
   assert.equal(await locked('#interval'),role!=='admin','#interval pour '+role);
   if(role==='viewer')assert.match(await page.locator('#refresh').getAttribute('title'),/Réservé au rôle « opérateur »/);
   // Fiche serveur : audit (opérateur), modification (administrateur).
   await page.evaluate(()=>openHost('web01'));await page.locator('.host-tabs').waitFor();
   assert.equal(await locked('[data-audit-host]'),role==='viewer');
   assert.equal(await locked('[data-edit-server]'),role!=='admin');
   // Vue redessinée hors de render (alertes) : l'observateur applique les mêmes droits.
   await page.evaluate(()=>{selected=null;hostDetail=null;navigate('Alertes')});
   await page.locator('#alert-data [data-alert-ack]').first().waitFor();
   await page.evaluate(()=>alertPaint(true));
   await page.waitForTimeout(100);
   assert.equal(await locked('#alert-data [data-alert-ack]'),role==='viewer','prise en charge (vue partielle) pour '+role);
   if(role==='viewer'){
    // Un module qui réactive le bouton ne lève pas le verrou : le clic est bloqué, rien ne part.
    await page.evaluate(()=>{const b=document.querySelector('#refresh');b.disabled=false;b.click()});
    await page.waitForTimeout(200);
    assert.deepEqual(posts,[],'aucun POST pour un lecteur');
    assert.equal(await page.locator('html').getAttribute('data-role'),'viewer');
   }
   renderRef.push(await page.evaluate(()=>render.toString().slice(0,60)));
   assert.deepEqual(errors,[]);
   await page.close();
  }
  assert.ok(renderRef.every(r=>r.includes('runHooks(beforeRenderHooks)')),'render reste le répartiteur du cycle de vie');
  // Minuteries : horloge simulée ; on compte les lectures /api/alerts.
  const {page,errors,gets}=await open(browser,'admin',{clock:true});
  const count=()=>gets.filter(p=>p==='/api/alerts').length;
  const run=async seconds=>{for(let i=0;i<seconds;i++){await page.clock.runFor(1000);await page.waitForTimeout(5)}};
  let before=count();await run(60);const visible=count()-before;
  assert.ok(visible>=5&&visible<=7,'onglet visible : une lecture toutes les 10 s ('+visible+'/min)');
  await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});document.dispatchEvent(new Event('visibilitychange'))});
  const ticksBefore=await page.evaluate(()=>pollStatus().find(p=>p.name==='ages-des-preuves').runs);
  before=count();await run(120);const hidden=count()-before;
  assert.ok(hidden>=3&&hidden<=5,'onglet caché : une lecture toutes les 30 s ('+hidden+' en 2 min)');
  assert.equal(await page.evaluate(()=>pollStatus().find(p=>p.name==='ages-des-preuves').runs),ticksBefore,'affichage non rafraîchi onglet caché');
  // Retour au premier plan : les tâches dues partent aussitôt.
  await page.evaluate(()=>{Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});document.dispatchEvent(new Event('visibilitychange'))});
  await page.waitForTimeout(50);
  assert.ok(await page.evaluate(()=>pollStatus().find(p=>p.name==='ages-des-preuves').runs)>ticksBefore,'rattrapage au retour');
  const names=await page.evaluate(()=>pollStatus().map(p=>p.name));
  for(const n of ['alertes','etat-du-parc','barre-d-etat','serveurs-critiques-vue'])assert.ok(names.includes(n),'tâche déclarée : '+n);
  assert.deepEqual(errors,[]);
  await page.close();
  console.log('PASS: cycle de vie — droits par rôle (y compris vues partielles, aucun POST lecteur), minuteries réduites onglet caché et rattrapage, render stable');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
