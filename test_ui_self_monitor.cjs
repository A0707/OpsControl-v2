// Lot 2 : page « Santé d’OpsControl ». Quatre niveaux distincts ; une source jamais
// interrogée ou en échec n'est jamais affichée disponible ; aucune erreur JS ; mobile sans
// défilement horizontal ; chargée à la demande (absente du chemin critique). Fixture synthétique.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const now=new Date().toISOString(),old=new Date(Date.now()-3*86400e3).toISOString();
  const health={generated_at:now,ready:true,not_ready_reasons:[],
   opscontrol:{status:'ok',uptime_seconds:7300,started_at:now,database:{status:'ok',journal_mode:'wal'},database_size:{bytes:52428800,files:{db:50000000,'-wal':2428800}},
    scheduler:{last:now,lag_seconds:0,healthy:true},single_instance:true,sse:{clients:2,total_since_start:9},tunnel:{required:true,open:false}},
   collectors:[{kind:'api',key:'Zabbix:z',label:'Lectures API',runs:4,success:4,failure:0,consecutive_failures:0,running:false,last_finished:now,last_success:now,last_duration_ms:1840,last_items:null,last_error:null,state:'ok'},
    {kind:'api',key:'Wazuh:w',label:'Lectures API',runs:3,success:0,failure:3,consecutive_failures:3,running:false,last_finished:now,last_success:null,last_duration_ms:30010,last_items:null,last_error:'Délai dépassé',state:'failing'}],
   jobs:{ssh:{running:false,completed:3,total:3,error:null},network:{running:true,completed:1,total:4,error:null}},
   sources:[{key:'z',name:'Zabbix',provider:'Zabbix',reachable:true,last_success:now,fresh:true,error:null,credentials_loaded:true},
    {key:'w',name:'Wazuh',provider:'Wazuh',reachable:false,last_success:old,fresh:false,error:'Délai dépassé',credentials_loaded:true},
    {key:'b',name:'Bacula',provider:'Bacula',reachable:null,last_success:null,fresh:false,error:null,credentials_loaded:false}],
   freshness:{hosts:10,ssh_fresh:4,ssh_measured:9,network_fresh:10,api_fresh:1,api_total:3,budget_seconds:900},
   errors:[{at:now,source:'api',message:'Lectures API · Wazuh:w : Délai dépassé'}],scope:'Mesures internes du processus.'};
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   const page=await browser.newPage({viewport}),errors=[],requested=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}}});
   await page.route('http://health.test/**',async route=>{
    const url=new URL(route.request().url());requested.push(url.pathname);
    if(route.request().method()!=='GET')return route.fulfill({status:405,json:{detail:'interdit'}});
    if(url.pathname==='/api/self-monitoring')return route.fulfill({json:health});
    if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[],counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
    const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
    if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
    return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
   });
   await page.goto('http://health.test/');
   await page.waitForFunction(()=>typeof state!=='undefined'&&state);
   assert.ok(!requested.includes('/self-monitor.js'),'module chargé à la demande seulement');
   // Desktop : entrée réelle de la navigation ; mobile : sélecteur de page (même identifiant).
   if(viewport.width>=500)await page.locator('#nav button[data-page="Santé d’OpsControl"]').click();
   else await page.locator('#mobile-nav').selectOption('Santé d’OpsControl');
   await page.locator('.sm-levels').waitFor();
   const levels=await page.locator('.sm-level').allInnerTexts();
   assert.equal(levels.length,4,'quatre niveaux distincts');
   assert.match(levels[0],/Disponible/);
   assert.match(levels[1],/1 en échec/);
   assert.match(levels[2],/1 indisponible/);
   // Audit UI du 31/10 : Web Vitals de la session, mesurés localement, jamais transmis.
   await page.getByText("Rendu dans ce navigateur").waitFor();
   assert.match(await page.locator("#content").innerText(),/Aucune donnée n’est transmise/);
   assert.match(levels[3],/33 %/,'fraîcheur : le plus bas des trois ratios');
   const rows=await page.locator('[data-sm="sources"] tbody tr').allInnerTexts();
   const bacula=rows.find(r=>r.includes('Bacula')),wazuh=rows.find(r=>r.includes('Wazuh'));
   assert.match(bacula,/Jamais interrogée/);assert.doesNotMatch(bacula,/Disponible|Récente/);
   assert.match(wazuh,/Indisponible/);assert.match(wazuh,/Ancienne/);
   assert.match(await page.locator('.sm-facts').innerText(),/Fermé/,'tunnel requis et fermé signalé');
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
   if(viewport.width<500){
    // Les tableaux défilent dans leur conteneur ; la page elle-même ne déborde pas.
    assert.ok(overflow<=1,'pas de défilement horizontal de page en mobile ('+overflow+' px)');
    const small=await page.$$eval('.sm-level small,.sm-facts',els=>els.map(e=>parseFloat(getComputedStyle(e).fontSize)).filter(s=>s<12));
    assert.deepEqual(small,[],'texte lisible (≥ 12 px)');
   }
   assert.deepEqual(errors,[]);
   await page.screenshot({path:path.join(__dirname,'data','v2-captures','lot2-sante-'+(viewport.width<500?'mobile':'desktop')+'.png'),fullPage:true});
   await page.close();
  }
  console.log('PASS: Santé d’OpsControl — 4 niveaux, sources absentes/en échec jamais OK, mobile sans débordement');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
