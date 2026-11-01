// Phase 4.2 : DOM incrémental et notifications critiques anti-spam.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const OUT=path.join(__dirname,'data','v2-captures');fs.mkdirSync(OUT,{recursive:true});
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1280,height:850}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{
   window.EventSource=class extends EventTarget{constructor(){super()}close(){}};
   window.Notification=class {static permission='granted';static requestPermission=async()=> 'granted';constructor(title,options){this.title=title;this.options=options;localStorage.setItem('test.notification.count',String(Number(localStorage.getItem('test.notification.count')||0)+1));}};
  });
  const now=Date.now(),iso=ms=>new Date(ms).toISOString();
  const alert={id:'SSH:service:postfix:critical',source:'SSH',severity:'critical',severity_label:'Critique',source_severity:'critical',title:'Postfix arrêté',evidence:'inactive',rule:'Service critique',delay:'Immédiat',fresh:true,chronic:false,count:1,max_age_seconds:900,observed_at:iso(now-1000),targets:[{name:'web01',host_key:'web01',detail:'postfix.service',observed_at:iso(now-1000),started_at:iso(now-60000)}]};
  const alerts={generated_at:iso(now),alerts:[alert],counts:{critical:1,critical_stale:0,warning:0,warning_stale:0,preventive:0,preventive_stale:0,info:0,info_stale:0},levels:[{key:'critical',label:'Critique',delay:'Immédiat'},{key:'warning',label:'Majeur',delay:'4 h'},{key:'preventive',label:'Préventif',delay:'Planifié'},{key:'info',label:'Information',delay:'Information'}],policy:[],scope:'Fixture Phase 4.2',sources:[{name:'SSH',provider:'SSH',fresh:true,collected_at:iso(now-1000),max_age_seconds:900}]};
  let maintenance=[{id:4,name:'Patch web01',starts_at:iso(now-60000),ends_at:iso(now+3600000),source:'SSH',target:'web01',active:true,actor:'Ops'},
   {id:5,name:'Maintenance hôte',starts_at:iso(now-60000),ends_at:iso(now+3600000),source:'',target:'web01',active:true,actor:'Ops'}];
  await page.route('http://alerts-phase42.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());let data;
   if(url.pathname==='/api/alerts')data=alerts;
   else if(url.pathname==='/api/incidents/maintenance')data={items:maintenance,active:maintenance.length};
   else if(url.pathname==='/api/overview')data={hosts:[],counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}};
   else if(url.pathname==='/api/tier0')data={hosts:[],sources:[],webhook:{count:0}};
   else if(url.pathname==='/api/daily')data={counts:{},priorities:[],sources:[],attention:[],batches:{}};
   else if(url.pathname==='/api/whoami')data={mode:'local',authenticated:false,user:null,label:'Session locale'};
   else if(url.pathname.startsWith('/api/'))data={};
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://alerts-phase42.test/#/Alertes');
  await page.locator('#alert-list .alert-item').waitFor();
  await page.getByText('Maintenance · Patch web01',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>notificationInMaintenance('Tier0',['web01'])),true,'transition Tier 0 non couverte par une maintenance hôte');
  await page.screenshot({path:path.join(OUT,'phase42-alerts-maintenance-dark.png'),fullPage:true});
  assert.equal(await page.evaluate(()=>Number(localStorage.getItem('test.notification.count')||0)),0,'notification émise pendant une maintenance');
  const reused=await page.evaluate(async()=>{const item=document.querySelector('#alert-list .alert-item');item.__phase42=true;await loadAlerts();return item===document.querySelector('#alert-list .alert-item')&&document.querySelector('#alert-list .alert-item').__phase42===true});
  assert.equal(reused,true,'alerte reconstruite malgré des données inchangées');
  await page.locator('#alert-search').fill('Post');
  await page.locator('#alert-search').evaluate(e=>e.setSelectionRange(1,3));
  await page.evaluate(()=>loadAlerts());
  assert.deepEqual(await page.locator('#alert-search').evaluate(e=>({same:e===document.activeElement,selection:[e.selectionStart,e.selectionEnd]})),{same:true,selection:[1,3]});
  maintenance=[];
  await page.evaluate(async()=>{await loadAlertMaintenance(true);await loadAlerts()});
  assert.equal(await page.evaluate(()=>Number(localStorage.getItem('test.notification.count')||0)),1,'nouvelle alerte non notifiée après la maintenance');
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>Number(localStorage.getItem('test.notification.count')||0)),1,'notification dupliquée au polling suivant');
  await page.reload();
  await page.locator('#alert-list .alert-item').waitFor();
  assert.equal(await page.evaluate(()=>Number(localStorage.getItem('test.notification.count')||0)),1,'notification dupliquée après rechargement');
  assert.deepEqual(errors,[]);
  console.log('PASS: Phase 4.2 alertes incrémentales, maintenance silencieuse, focus stable et notifications persistantes anti-spam');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
