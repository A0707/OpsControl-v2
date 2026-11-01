// Phase 4.5: V2 shell/dashboard are eager, server detail is lazy and registry-based.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');

(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1360,height:900}}),errors=[],requests=[];
  page.on('pageerror',error=>errors.push(error.message));page.on('request',request=>requests.push(new URL(request.url()).pathname));
  const now=new Date().toISOString();
  const host={key:'a',name:'srv-a',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',role:'Web',environment:'PROD',cpu:12,ram:34,disk_max:56,collected_at:now,services:[],all_services:[],findings:[],checks:[],history:[],coverage:{measured:1,total:1},source_details:[],proxmox_matches:[],backup_summary:{matched:false},alerts:{counts:{total:0},items:[]},network_evidence:{ping:true,fresh:true,collected_at:now}};
  await page.route('http://phase45.test/**',async route=>{
   const url=new URL(route.request().url());let data;
   if(url.pathname==='/api/overview')data={hosts:[host],counts:{ok:1},job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/hosts/a')data=host;
   else if(url.pathname==='/api/hosts/a/observability')data={samples:1,points:[{cpu:12,ram:34,disk:56}],changes:[],trends:{cpu:{last:12,samples:1},ram:{last:34,samples:1},disk:{last:56,samples:1}},scope:'Fixture historique'};
   else if(url.pathname==='/api/network')data={hosts:[{key:'a',ping:true,ssh_key_known:true,ports:[],collected_at:now}],job:{running:false}};
   else if(url.pathname==='/api/v2/cockpit')data={sources:[],missing_providers:[],counts:{},attention:[]};
   else if(url.pathname==='/api/alerts')data={alerts:[],counts:{},sources:[],levels:[],policy:[]};
   else if(url.pathname==='/api/daily')data={counts:{},priorities:[],sources:[],attention:[],batches:{}};
   else if(url.pathname.startsWith('/api/'))data={hosts:[],sources:[],assets:[],job:{running:false},missing_providers:[]};
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://phase45.test/');await page.locator('.top-actions [data-v2-command]').waitFor();
  assert.ok(requests.includes('/v2.js')&&requests.includes('/v2-dashboard.js'));
  assert.equal(requests.includes('/v2-detail.js'),false,'server detail must stay outside startup');
  await page.evaluate(()=>{window.__phase45Render=render;window.__phase45Detail=detailView});
  await page.locator('#nav [data-page="Serveurs"]').click();await page.locator('#content [data-host="a"]:visible').first().click();
  await page.locator('script[data-lazy-detail="v2"]').waitFor({state:'attached'});await page.locator('[data-tab="performance"]').waitFor();
  // Lot 4 : la provenance des sources ouvre la fiche (Synthèse) ; la supervision détaillée
  // est dans l'onglet Incidents ; un onglet inactif n'est pas construit.
  assert.equal(await page.locator('.v2-host-sources').count(),1,'source provenance must open the server page');
  assert.equal(await page.locator('.server-monitoring').count(),0,'inactive tab must not be rendered');
  await page.locator('[data-tab="incidents"]').click();await page.locator('.server-monitoring').waitFor();
  assert.equal(await page.locator('.v2-host-sources').count(),0);
  await page.locator('[data-tab="performance"]').click();await page.getByRole('heading',{name:'Tendances sur 7 jours'}).waitFor();
  assert.equal(await page.evaluate(()=>render===window.__phase45Render&&detailView===window.__phase45Detail),true,'lazy detail must not replace global dispatchers');
  await page.locator('#nav [data-page="Serveurs"]').click();await page.locator('#content [data-host="a"]:visible').first().click();
  assert.equal(requests.filter(file=>file==='/v2-detail.js').length,1);
  assert.deepEqual(errors,[]);console.log('PASS: Phase 4.5 V2 shell/dashboard split and lazy wrapper-free server detail');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
