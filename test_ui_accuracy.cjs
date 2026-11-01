const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try {
  const page=await browser.newPage({viewport:{width:1440,height:900}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  let tick=0;
  const now=new Date().toISOString();
  const host={key:'web',name:'Serveur web',ip:'192.0.2.10',registered:true,active_scope:true,
   status:'unknown',stale:true,services:[],findings:[],checks:[],history:[],
   backup_summary:{matched:true,severity:'critical',fresh:false,jobs_count:2,collected_at:now},
   alerts:{counts:{total:1,old:0},items:[{id:'z:1',source:'Zabbix',severity:'critical',title:'Disque plein',fresh:true,observed_at:now,started_at:now,time_basis:'Zabbix'}]}};
  await page.route('http://infraops.test/**',async route=>{
   const u=new URL(route.request().url());let data;
   if(u.pathname==='/api/overview')data={hosts:[host],job:{running:false},monitoring:{interval:0}};
   else if(u.pathname==='/api/hosts/web')data={...host,alerts:{...host.alerts,generated_at:String(++tick),items:host.alerts.items.map(a=>({...a,duration_seconds:tick,duration_until:String(tick)}))}};
   else if(u.pathname==='/api/alerts')data={alerts:[],counts:{},sources:[],levels:[],policy:[]};
   else if(u.pathname==='/api/daily')data={counts:{},priorities:[],sources:[],attention:[],batches:{}};
   else if(u.pathname==='/api/ssh/host-keys')data={hosts:[]};
   else if(u.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const f=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
   return route.fulfill({body:fs.readFileSync(f),contentType:f.endsWith('.js')?'text/javascript':f.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://infraops.test/');
  await page.locator('#nav [data-page="Serveurs"]').click();
  await page.locator('#search').fill('web');
  await page.getByText('Dernier passage en erreur',{exact:true}).waitFor();
  await page.getByText('2 job(s) · À reconfirmer',{exact:true}).waitFor();
  await page.locator('#nav [data-page="Inventaire"]').click();
  assert.equal(await page.locator('#search').inputValue(),'');
  await page.locator('#nav [data-page="Serveurs"]').click();
  assert.equal(await page.locator('#search').inputValue(),'web');
  await page.locator('#content [data-host="web"]').first().click();
  await page.locator('[data-tab="incidents"]').click();
  // Alertes brutes par source repliées sous les incidents du journal (e748b59).
  await page.locator('.server-monitoring > summary').click();
  await page.locator('#server-alert-query').fill('Disque');
  const stable=await page.evaluate(async()=>{
   const el=document.getElementById('server-alert-query');el.setSelectionRange(1,4);
   await load();await load();
   return {same:el===document.getElementById('server-alert-query'),focus:el===document.activeElement,selection:[el.selectionStart,el.selectionEnd]};
  });
  assert.deepEqual(stable,{same:true,focus:true,selection:[1,4]});
  host.alerts.items[0].title='Disque critique actualisé';
  await page.evaluate(()=>load());
  assert.equal(await page.locator('#server-alert-query').inputValue(),'Disque');
  assert.deepEqual(await page.locator('#server-alert-query').evaluate(el=>({focus:el===document.activeElement,selection:[el.selectionStart,el.selectionEnd]})),{focus:true,selection:[1,4]});
  // Lot 4 : l'alerte figure aussi dans la chronologie du même onglet ; on vérifie le tableau des alertes.
  await page.locator('#server-alert-results').getByText('Disque critique actualisé',{exact:true}).waitFor();
  await page.locator('#content [data-go="Serveurs"]').first().click();
  assert.equal(await page.locator('#search').inputValue(),'web');
  assert.deepEqual(errors,[]);
  console.log('PASS: source-backed backups, filters preserved, polling stable, real updates retain input focus and selection');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
