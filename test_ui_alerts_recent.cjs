const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
// Page Alertes : plus récentes d'abord (date de début), 7 derniers jours par défaut,
// alerte sans date de début jamais masquée, lien « toutes les dates ».
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{
   window.EventSource=class extends EventTarget{constructor(){super();setTimeout(()=>this.dispatchEvent(new Event('ready')),0)}close(){}};
  });
  const now=Date.now(),iso=ms=>new Date(ms).toISOString(),jour=86400000;
  const alerte=(id,severity,label,debut)=>({id,source:'Zabbix',severity,severity_label:label,title:'Alerte '+id,
   fresh:true,observed_at:iso(now),max_age_seconds:900,count:1,delay:'',chronic:false,ack:null,
   targets:[{name:'srv-'+id,observed_at:iso(now),...(debut?{started_at:iso(debut)}:{})}]});
  const alerts=[alerte('a2j','critical','Critique',now-2*jour),alerte('a1h','preventive','Préventif',now-3600000),
   alerte('a10j','critical','Critique',now-10*jour),alerte('sansdate','warning','Majeur',null),
   alerte('a5j','warning','Majeur',now-5*jour)];
  // Le début calculé sur toutes les cibles prime sur l'échantillon affiché.
  Object.assign(alerts[0],{started_at:iso(now-3*jour),started_at_complete:false,count:30,truncated:true});
  await page.route('http://infraops.test/**',async route=>{
   const u=new URL(route.request().url());let data;
   if(u.pathname==='/api/alerts')data={alerts,generated_at:iso(now),counts:{critical:2,warning:2,preventive:1,info:0,info_stale:0},
    levels:[{key:'critical',label:'Critique',delay:''},{key:'warning',label:'Majeur',delay:''},{key:'preventive',label:'Préventif',delay:''}],
    policy:[],sources:[],scope:''};
   else if(u.pathname==='/api/overview')data={hosts:[],job:{running:false},monitoring:{interval:60}};
   else if(u.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
   const type=file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':'text/html';
   return route.fulfill({body:fs.readFileSync(file),contentType:type});
  });
  await page.goto('http://infraops.test/');
  await page.evaluate(async()=>{await loadAlerts();navigate('Alertes')});
  await page.locator('#alert-list .alert-item').first().waitFor();
  const ordre=()=>page.$$eval('#alert-list .alert-item',n=>n.map(x=>x.dataset.alertKey));
  assert.deepEqual(await ordre(),['a1h','a2j','a5j','sansdate'],'7 jours par défaut, plus récentes d’abord');
  assert.equal(await page.inputValue('#alert-period'),'7');
  assert.equal(await page.locator('#alert-list .alert-exact-dates').count(),4);
  assert.match(await page.locator('#alert-list [data-alert-key="a1h"] .alert-exact-dates').innerText(),/\d{2}\/\d{2}\/\d{4}.*\d{2}:\d{2}:\d{2}.*UTC/);
  assert.match(await page.locator('#alert-list [data-alert-key="sansdate"] .alert-exact-dates').innerText(),/Début déclaré : Non mesuré/);
  assert.equal(await page.locator('#alert-list [data-alert-key="a2j"] [data-since]').getAttribute('data-since'),iso(now-3*jour));
  assert.match(await page.locator('#alert-list [data-alert-key="a2j"] .alert-exact-dates').innerText(),/certaines cibles sans date de début/);
  assert.match(await page.innerText('#alert-order'),/1 alerte\(s\) commencée\(s\) il y a plus de 7 jours masquée/);
  await page.click('[data-alert-all-dates]');
  await page.waitForFunction(()=>document.querySelectorAll('#alert-list .alert-item').length===5);
  assert.deepEqual(await ordre(),['a1h','a2j','a5j','a10j','sansdate']);
  assert.equal(await page.inputValue('#alert-period'),'');
  await page.selectOption('#alert-period','7');
  await page.waitForFunction(()=>document.querySelectorAll('#alert-list .alert-item').length===4);
  // La gravité reste visible sur chaque alerte.
  assert.match(await page.innerText('#alert-list [data-alert-key="a2j"] .badge'),/Critique/);
  await page.setViewportSize({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');
  assert.deepEqual(errors,[]);
  console.log('PASS: alerts sorted most recent first, 7-day default period, undated alerts kept, all dates link');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
