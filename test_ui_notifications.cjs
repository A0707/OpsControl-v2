const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
// Notifications des incidents critiques pour l'application installée (Edge) : bouton permanent,
// notification de test, notification persistante, pastille sur l'icône, manifeste.
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{
   window.testClockOffset=0;const realNow=Date.now.bind(Date);Date.now=()=>realNow()+window.testClockOffset;
   window.EventSource=class extends EventTarget{constructor(){super();setTimeout(()=>this.dispatchEvent(new Event('ready')),0)}close(){}};
   window.sent=[];window.badges=[];
   window.Notification=class{static permission='default';
    static async requestPermission(){Notification.permission='granted';return 'granted'}
    constructor(title,options){this.title=title;this.options=options;window.sent.push({title,options})}};
   navigator.setAppBadge=async n=>{window.badges.push(n)};
   navigator.clearAppBadge=async()=>{window.badges.push(0)};
  });
  let alerts=[];
  await page.route('http://infraops.test/**',async route=>{
   const u=new URL(route.request().url());let data;
   if(u.pathname==='/api/alerts')data={alerts,generated_at:new Date().toISOString(),counts:{},levels:[],policy:[],sources:[]};
   else if(u.pathname==='/api/overview')data={hosts:[],job:{running:false},monitoring:{interval:60}};
   else if(u.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
   const type=file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':'text/html';
   return route.fulfill({body:fs.readFileSync(file),contentType:type});
  });
  await page.goto('http://infraops.test/');
  const manifest=await page.evaluate(async()=>(await fetch(document.querySelector('link[rel=manifest]').href)).json());
  assert.equal(manifest.short_name,'OpsControl');
  assert.equal(manifest.display,'standalone');

  const bouton=page.locator('.top-actions [data-notify-control]');
  await bouton.waitFor();
  assert.match(await bouton.innerText(),/Activer les alertes/);
  await bouton.click();
  await page.waitForFunction(()=>/Alertes actives/.test(document.querySelector('[data-notify-control]').textContent));
  await bouton.click();
  await page.waitForFunction(()=>window.sent.some(n=>n.title==='OpsControl : notification de test'));

  // Nouvel incident critique récent : notification persistante et pastille sur l'icône.
  const now=new Date().toISOString();
  const old=new Date(Date.now()-2*86400000).toISOString();
  alerts=[{id:'SSH:old:critical',source:'SSH',severity:'critical',fresh:true,observed_at:now,count:1,
    targets:[{name:'old01',host_key:'old01',observed_at:now,started_at:old}]}];
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),0,'preuve fraîche ne rend pas une ancienne panne nouvelle');
  alerts[0].targets[0].started_at=null;
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),0,'début inconnu : aucune notification déduite de la date de collecte');
  alerts[0].targets[0].started_at=new Date(Date.now()-16*60000).toISOString();
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),0,'occurrence de 16 min silencieuse malgré une preuve fraîche');
  alerts[0].targets[0].started_at=now;alerts[0].notification_events=[];
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),0,'liste de candidats vide du serveur respectée');
  alerts=[{id:'Zabbix:db:critical',source:'Zabbix',severity:'critical',severity_label:'Critique',title:'PostgreSQL service not running',
   fresh:true,observed_at:now,max_age_seconds:900,count:1,delay:'Intervention immédiate',chronic:false,ack:null,
   targets:[{name:'pg01',host_key:'pg01',observed_at:now,started_at:now}]}];
  await page.evaluate(()=>loadAlerts());
  await page.waitForFunction(()=>window.sent.some(n=>/alerte\(s\) critique/.test(n.title)));
  const critique=await page.evaluate(()=>window.sent.find(n=>/alerte\(s\) critique/.test(n.title)));
  assert.equal(critique.options.requireInteraction,true);
  assert.match(critique.options.body,/PostgreSQL service not running/);
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),1,'même occurrence non renvoyée');
  await page.waitForFunction(()=>window.badges.at(-1)===1);
  // Même nombre de cibles : un autre serveur est un nouvel événement.
  const baseMs=Date.parse(now),later=minutes=>new Date(baseMs+minutes*60000).toISOString();
  await page.evaluate(()=>window.testClockOffset=6*60000);
  Object.assign(alerts[0],{observed_at:later(6),targets:[{name:'pg02',host_key:'pg02',observed_at:later(6),started_at:later(6)}]});
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),2,'nouvelle cible à nombre égal notifiée');
  assert.match(await page.evaluate(()=>window.sent.at(-1).options.body),/pg02/);
  assert.doesNotMatch(await page.evaluate(()=>window.sent.at(-1).options.body),/pg01/,'la notification ne cite que les cibles récentes');
  // Même serveur : une réapparition possède une autre signature, la preuve seule non.
  await page.evaluate(()=>window.testClockOffset=17*60000);
  alerts[0].observed_at=later(17);alerts[0].targets[0].observed_at=later(17);alerts[0].targets[0].started_at=later(17);
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),3);
  await page.evaluate(()=>window.testClockOffset=33*60000);
  alerts[0].observed_at=later(33);alerts[0].targets[0].observed_at=later(33);
  await page.evaluate(()=>loadAlerts());
  assert.equal(await page.evaluate(()=>window.sent.filter(n=>/alerte\(s\) critique/.test(n.title)).length),3,'ancienne occurrence jamais renvoyée avec une nouvelle preuve');
  assert.equal(await page.evaluate(()=>alertNew().length),0);
  await page.evaluate(()=>window.testClockOffset=0);
  alerts=[];
  await page.evaluate(()=>loadAlerts());
  await page.waitForFunction(()=>window.badges.at(-1)===0);
  // La voie rapide doit suivre la décision du journal, même lorsque la sonde vient de tomber.
  await page.evaluate(()=>{localStorage.removeItem(ALERT_NOTIFIED_KEY);window.sent=[];});
  for(const state of ['acknowledged','investigating','suppressed','resolved']){
   const at=new Date().toISOString();
   alerts=[{id:'Sonde directe:down:critical',source:'Sonde directe',severity:'critical',fresh:true,
    observed_at:at,count:1,title:'Serveur hors service',state_counts:{[state]:1},notification_events:[],
    targets:[{name:'probe-policy',host_key:'probe-policy',started_at:at,observed_at:at,state}]}];
   await page.evaluate(at=>{
    t0Previous['probe-policy']='up';t0Data={hosts:[{key:'probe-policy',name:'probe-policy',ip:'192.0.2.42',
     probe:{status:'down',down_since:at,checked_at:at}}]};t0Notify();
   },at);
   await page.waitForFunction(()=>!alertLoading);
   assert.equal(await page.evaluate(()=>window.sent.length),0,'voie rapide silencieuse pour '+state);
  }
  const probeAt=new Date().toISOString();
  alerts[0].notification_events=[{id:'Sonde directe|probe-policy|down',at:probeAt,name:'probe-policy',
   host_key:'probe-policy',observed_at:probeAt,max_age_seconds:30}];
  alerts[0].state_counts={open:1};alerts[0].observed_at=probeAt;
  await page.evaluate(at=>{t0Previous['probe-policy']='up';t0Data.hosts[0].probe={status:'down',down_since:at,checked_at:at};t0Notify();},probeAt);
  await page.waitForFunction(()=>window.sent.length===1);
  assert.match(await page.evaluate(()=>window.sent[0].options.body),/probe-policy/);
  alerts=[];await page.evaluate(()=>loadAlerts());
  await page.setViewportSize({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');
  await page.setViewportSize({width:1440,height:1000});
  await page.evaluate(()=>{document.getElementById('toast').textContent=''});
  await page.locator('.topbar').screenshot({path:'data/notifications-verified.png'});
  assert.deepEqual(errors,[]);
  console.log('PASS: manifest, top bar control, permission, test notification, persistent critical notification, app badge');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
