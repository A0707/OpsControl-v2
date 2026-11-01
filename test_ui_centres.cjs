// Lot 3 : centres Incidents et Sources. Menu allégé sans perte de page, onglets accessibles
// (44 px, clavier, aria-current), lien profond, recherche, sources absentes jamais « OK »,
// accueil sans doublon de fraîcheur et détails qui ne se referment plus. Fixture synthétique.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const now=new Date().toISOString(),old=new Date(Date.now()-2*86400e3).toISOString();
  const host={key:'web01',name:'web01',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',services:[],findings:[],checks:[],coverage:{measured:10,total:15},collected_at:now};
  const health={generated_at:now,ready:true,not_ready_reasons:[],opscontrol:{uptime_seconds:60,database:{status:'ok',journal_mode:'wal'},database_size:{bytes:1},scheduler:{healthy:true,last:now},sse:{clients:0,total_since_start:0},tunnel:{}},
   collectors:[{kind:'api',key:'Zabbix:z',label:'Lectures API',runs:2,success:2,failure:0,last_duration_ms:900,state:'ok'}],jobs:{},errors:[],scope:'x',
   sources:[{key:'z',name:'Zabbix prod',provider:'Zabbix',reachable:true,last_attempt:now,last_success:now,fresh:true,error:null,credentials_loaded:true},
    {key:'w',name:'Wazuh manager',provider:'Wazuh',reachable:false,last_attempt:now,last_success:old,fresh:false,error:'Délai dépassé <script>x()</script>',credentials_loaded:true},
    {key:'b',name:'Bacula',provider:'Bacula',reachable:null,last_attempt:null,last_success:null,fresh:false,error:null,credentials_loaded:false}],
   freshness:{hosts:1,ssh_fresh:1,ssh_measured:1,network_fresh:0,api_fresh:1,api_total:3,budget_seconds:900}};
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   const mobile=viewport.width<500,page=await browser.newPage({viewport}),errors=[],posts=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}}});
   await page.route('http://centres.test/**',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(req.method()!=='GET'){posts.push(url.pathname);return route.fulfill({status:403,json:{detail:'lecture seule'}});}
    if(url.pathname==='/api/self-monitoring')return route.fulfill({json:health});
    if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[host],counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
    if(url.pathname==='/api/incidents')return route.fulfill({json:{items:[],total:0,counts:{},active_by_severity:{},sources:[],sync:{at:null},policy:''}});
    if(url.pathname==='/api/incidents/suppressions')return route.fulfill({json:{items:[]}});
    if(url.pathname==='/api/incidents/maintenance')return route.fulfill({json:{items:[],active:0}});
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
    const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
    if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
    return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
   });
   // Lien profond vers une vue sœur : la page s'ouvre avec les onglets de son centre.
   await page.goto('http://centres.test/#/Alertes');
   await page.waitForFunction(()=>typeof state!=='undefined'&&state&&page==='Alertes');
   const navPages=await page.evaluate(()=>[...document.querySelectorAll('#nav [data-page]')].map(b=>b.dataset.page));
   for(const gone of ['Alertes','Problèmes','Zabbix','Wazuh','Elasticsearch','Connexions API','Synchronisation'])
    assert.ok(!navPages.includes(gone),'entrée de menu redondante : '+gone);
   assert.ok(navPages.length<=18,'menu allégé, Assistant IA compris ('+navPages.length+' entrées)');
   await page.locator('#v2-hub-tabs').waitFor();
   assert.deepEqual(await page.locator('#v2-hub-tabs button').allInnerTexts(),['Journal','Alertes en direct','Constats d’audit','ITSM / GLPI','Passation']);
   assert.equal(await page.locator('#v2-hub-tabs [aria-current="page"]').getAttribute('data-go'),'Alertes');
   assert.equal(await page.locator('#breadcrumb').textContent(),'Incidents / Alertes en direct');
   if(mobile)assert.equal(await page.locator('#mobile-nav').inputValue(),'Incidents','sélecteur mobile sur le centre');
   else assert.equal(await page.locator('#nav [data-page="Incidents"]').getAttribute('aria-current'),'page','entrée du centre active');
   const heights=await page.$$eval('#v2-hub-tabs button',bs=>bs.map(b=>b.getBoundingClientRect().height));
   assert.ok(heights.every(h=>h>=44),'cibles ≥ 44 px : '+heights);
   // Clavier : l'onglet Journal s'active au clavier et garde le focus après le rendu.
   await page.locator('#v2-hub-tabs [data-go="Incidents"]').focus();
   await page.keyboard.press('Enter');
   await page.waitForFunction(()=>page==='Incidents');
   assert.equal(await page.evaluate(()=>document.activeElement?.dataset.go),'Incidents','focus conservé sur l’onglet');
   // Journal jamais rapproché : aucun compteur « 0 » vert, message explicite.
   await page.getByText('Journal pas encore rapproché').waitFor();
   assert.equal(await page.locator('.inc-kpis').count(),0);
   // Onglet Constats d'audit (ancienne page Problèmes), sans perte de fonction.
   await page.locator('#v2-hub-tabs [data-go="Problèmes"]').click();
   await page.waitForFunction(()=>page==='Problèmes');
   assert.ok(await page.locator('#content [data-mode="coverage"]').count()>=1,'onglet couverture conservé');
   // Recherche rapide : les vues sœurs restent trouvables, rattachées à leur centre.
   if(!mobile){
    await page.keyboard.press('Control+k');
    await page.locator('#v2-command-search').fill('wazuh');
    assert.match(await page.locator('#v2-command-dialog [data-v2-page="Wazuh"] small').innerText(),/Sources › Wazuh/);
    await page.keyboard.press('Escape');
   }
   // Centre Sources : réseau, SSH et API distincts ; absence et échec jamais « OK ».
   if(mobile)await page.locator('#mobile-nav').selectOption('Sources');
   else await page.locator('#nav [data-page="Sources"]').click();
   await page.locator('.sc-grid').first().waitFor();
   const card=k=>page.locator('[data-source-key="'+k+'"]');
   assert.match(await card('z').innerText(),/Lecture réussie[\s\S]*Récente/);
   const w=await card('w').innerText();assert.match(w,/Dernière lecture en échec/);assert.match(w,/Ancienne/);assert.doesNotMatch(w,/Récente/);
   assert.equal(await card('w').locator('script').count(),0,'erreur échappée');
   const b=await card('b').innerText();assert.match(b,/Jamais interrogée/);assert.match(b,/Aucune donnée/);assert.match(b,/Absents dans cette instance/);assert.doesNotMatch(b,/Lecture réussie|Récente/);
   assert.equal(await card('b').evaluate(e=>e.classList.contains('ok')),false);
   assert.match(await page.locator('.sc-kpis').innerText(),/0 \/ 1/,'sonde réseau absente : 0/1, pas OK');
   assert.equal(await page.locator('#v2-hub-tabs [aria-current="page"]').getAttribute('data-go'),'Sources');
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
   assert.ok(overflow<=1,'pas de défilement horizontal ('+overflow+' px)');
   await page.screenshot({path:path.join(__dirname,'data','v2-captures','lot3-sources-'+(mobile?'mobile':'desktop')+'.png'),fullPage:true});
   // Accueil : les détails ouverts par l'opérateur survivent au rafraîchissement.
   if(mobile)await page.locator('#mobile-nav').selectOption('Vue globale');
   else await page.locator('#nav [data-page="Vue globale"]').click();
   await page.locator('[data-v2-home-details] > summary').click();
   await page.waitForTimeout(1200);
   await page.evaluate(()=>{state={...state};v2RefreshOps()});
   assert.equal(await page.locator('[data-v2-home-details]').evaluate(d=>d.open),true,'détails toujours ouverts');
   assert.equal(await page.locator('#v2-hub-tabs').isVisible(),false,'pas d’onglets hors centre');
   assert.equal(await page.locator('.critical-sources [data-observed-at]').count(),0,'âges des sources non répétés dans les incidents critiques');
   assert.deepEqual(posts,[],'aucune écriture déclenchée par la navigation');
   assert.deepEqual(errors,[]);
   await page.close();
  }
  console.log('PASS: centres Incidents et Sources — menu allégé sans perte, onglets 44 px/clavier, absence jamais OK, accueil sans doublon');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
