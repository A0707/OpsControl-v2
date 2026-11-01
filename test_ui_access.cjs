// Lot 1 : boutons hors #content actifs, refus 403/429 lisibles, rôle affiché. Fixture synthétique.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[],gets=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}}});
  const now=new Date().toISOString();
  const host={key:'web01',name:'web01',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',services:[],findings:[],checks:[],coverage:{measured:10,total:15},collected_at:now};
  await page.route('http://access.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(req.method()==='POST'){
    if(url.pathname==='/api/refresh'||url.pathname==='/api/daily/refresh')return route.fulfill({status:429,headers:{'Retry-After':'42'},json:{detail:'Collecte complète déjà demandée : réessayer dans 42 s.',request_id:'abc12345abc12345'}});
    return route.fulfill({status:403,json:{detail:'Rôle « opérateur » requis pour cette action.',request_id:'abc12345abc12345'}});
   }
   gets.push(url.pathname);
   if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[host],counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
   if(url.pathname==='/api/hosts/web01')return route.fulfill({json:{...host,history:[],alerts:{items:[],counts:{}}}});
   if(url.pathname==='/api/whoami')return route.fulfill({json:{mode:'proxy',authenticated:true,user:'lecteur@example.test',role:'viewer',can_operate:false,can_admin:false,label:'lecteur@example.test'}});
   if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://access.test/');
  await page.waitForFunction(()=>typeof state!=='undefined'&&state);
  // Boutons de zones hors #content (bandeau d'alertes, serveurs critiques) : navigation et fiche serveur.
  await page.evaluate(()=>{
   const zone=document.createElement('section');zone.id='t0-zone';
   zone.innerHTML='<button class="park-cell" data-host="web01">web01</button><button data-go="Incidents">Incidents</button>';
   document.getElementById('content').before(zone);
  });
  await page.locator('#t0-zone [data-go="Incidents"]').click();
  await page.waitForFunction(()=>document.getElementById('title').textContent==='Incidents');
  await page.locator('#t0-zone [data-host="web01"]').click();
  await page.waitForFunction(()=>typeof selected!=='undefined'&&selected==='web01');
  assert.ok(gets.includes('/api/hosts/web01'),'fiche serveur chargée depuis une zone hors #content');
  // Refus de la politique d'accès : message lisible, pas de JSON brut.
  const forbidden=await page.evaluate(async()=>{try{await post('/api/incidents/ack',{id:'x'});return ''}catch(e){return e.message}});
  assert.equal(forbidden,'Action non autorisée : Rôle « opérateur » requis pour cette action.');
  const limited=await page.evaluate(async()=>{try{await post('/api/refresh');return ''}catch(e){return e.message+'|'+e.status}});
  assert.equal(limited,'Trop de demandes : Collecte complète déjà demandée : réessayer dans 42 s.|429');
  // Identité et rôle affichés.
  await page.locator('.local-label').filter({hasText:'lecteur@example.test'}).waitFor();
  // Audit UI du 31/10 (fiche 12.3) : mention du menu fidèle au rôle ; « Modifier » réservé à l'admin.
  assert.match(await page.locator('.side-note').innerText(),/Accès en lecture seule/);
  const edit=await page.evaluate(()=>{const b=document.createElement('button');b.dataset.editApi='x';document.getElementById('content').append(b);applyRoleGates();return b.disabled});
  assert.equal(edit,true,'Modifier une connexion : réservé au rôle administrateur');
  assert.deepEqual(errors,[]);
  console.log('PASS: boutons hors #content actifs, refus 403/429 lisibles, identité proxy affichée');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
