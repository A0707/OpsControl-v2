const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  const start=Date.now(),iso=ms=>new Date(ms).toISOString();
  await page.clock.install({time:new Date(start)});
  await page.addInitScript(()=>{
   window.EventSource=class extends EventTarget {
    constructor(){super();window.testEvents=this;setTimeout(()=>this.dispatchEvent(new Event('ready')),0);}
    close(){}
   };
  });
  let alerts=[],failed=false,calls=0;
  const incident=(id,title,at)=>({id,title,source:'Zabbix',severity:'critical',severity_label:'Critique',
   fresh:true,observed_at:at,max_age_seconds:30,count:1,delay:'Intervention immédiate',
   targets:[{name:id==='carp'?'Firewall secondaire':'PostgreSQL production',host_key:null,
    observed_at:at,measurement_at:iso(start-300000),started_at:iso(start-60000)}]});
  const host={key:'db',name:'PostgreSQL production',ip:'192.0.2.8',registered:true,active_scope:true,
   status:'unknown',stale:true,collected_at:iso(start-300000),cpu:45,ram:30,disk_max:80,
   services:[],findings:[],checks:[]};
  await page.route('http://infraops.test/**',async route=>{
   const u=new URL(route.request().url());let data;
   if(u.pathname==='/api/ssh/host-keys')data={hosts:[]};
   else if(u.pathname==='/api/overview')data={hosts:[host],job:{running:false},monitoring:{interval:60}};
   else if(u.pathname==='/api/alerts'){
    calls++;
    if(failed)return route.fulfill({status:503,body:'Unavailable'});
    data={alerts,generated_at:iso(start),counts:{critical:alerts.length},levels:[],policy:[],
     sources:[{name:'Zabbix',provider:'Zabbix',collected_at:alerts[0]?.observed_at||iso(start),max_age_seconds:30}]};
   }else if(u.pathname==='/api/daily')data={generated_at:iso(start),
    counts:{registered:1,inventory:1,online:1,audit_missing:0,critical_total:2,critical_recent:2,api_fresh:1,api_total:1},
    policy:'Données de validation simulées.',priorities:[],sources:[],attention:[],batches:{counts:{},fresh_hosts:0,hosts_total:1}};
   else if(u.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://infraops.test/');
  await page.locator('#home-critical .empty').waitFor();
  alerts=[incident('carp','CARP role changed to BACKUP',iso(start-12000)),
          incident('db','PostgreSQL service not running',iso(start-12000))];
  const before=calls;
  await page.evaluate(()=>window.testEvents.dispatchEvent(new Event('state')));
  await page.getByRole('heading',{name:'CARP role changed to BACKUP',exact:true}).waitFor();
  assert(calls>before,'SSE must reload incidents immediately');
  assert.match(await page.locator('#home-critical').innerText(),/Lecture Zabbix : il y a 1\d s/);
  assert.match(await page.locator('#home-critical').innerText(),/Item le plus ancien : il y a 5 min/);
  await page.locator('[data-alert-seen]').first().click();
  assert(await page.locator('#alert-strip').isHidden());
  assert(await page.getByRole('heading',{name:'PostgreSQL service not running',exact:true}).isVisible());
  // Passing time alone must expire evidence, never reset it to the browser fetch time.
  await page.clock.fastForward(21000);
  await page.locator('#home-critical .critical-old').waitFor();
  assert.match(await page.locator('#home-critical').innerText(),/0 cause\(s\) récente\(s\)/);
  assert.match(await page.locator('#home-critical').innerText(),/2 cause\(s\) critique\(s\) ancienne\(s\)/);
  const now=await page.evaluate(()=>Date.now());
  alerts=alerts.map(a=>({...a,observed_at:iso(now),targets:a.targets.map(t=>({...t,observed_at:iso(now)}))}));
  await page.evaluate(()=>window.testEvents.dispatchEvent(new Event('ready')));
  await page.waitForFunction(()=>document.querySelector('#home-critical .state-count')?.textContent.startsWith('2'));
  failed=true;
  await page.evaluate(()=>window.testEvents.dispatchEvent(new Event('state')));
  await page.locator('#home-critical [role="alert"]').waitFor();
  assert.match(await page.locator('#home-critical').innerText(),/Derniers incidents conservés/);
  assert.match(await page.locator('#home-critical').innerText(),/0 cause\(s\) récente\(s\)/);
  failed=false;
  await page.evaluate(()=>loadAlerts());
  await page.waitForFunction(()=>document.querySelector('#home-critical .state-count')?.textContent.startsWith('2'));
  await page.screenshot({path:'data/critical-home-verified.png',fullPage:false});
  await page.setViewportSize({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');
  await page.screenshot({path:'data/critical-mobile-verified.png',fullPage:false});
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#nav [data-page="Serveurs"]').click();
  await page.getByText(/Mesures SSH : il y a 5 min/).waitFor();
  assert.deepEqual(errors,[]);
  console.log('PASS: SSE critical incidents, seen alerts retained on home, genuine measurement age, expiration, failed feed, reconnect, mobile, SSH age');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
