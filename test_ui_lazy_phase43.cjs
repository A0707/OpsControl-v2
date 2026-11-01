// Phase 4.3: the source views must stay outside the startup path and load once.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');

(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1280,height:800}}),errors=[],requests=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>requests.push(new URL(request.url()).pathname));
  await page.route('http://phase43.test/**',async route=>{
   const url=new URL(route.request().url());let data;
   if(url.pathname==='/api/overview')data={hosts:[],counts:{},job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/connections')data=[];
   else if(url.pathname==='/api/shares')data={shares:[],counts:{},thresholds:{preventive:75,warning:85,critical:95},scope:'Fixture'};
   else if(url.pathname==='/api/alerts')data={alerts:[],counts:{},sources:[],levels:[],policy:[]};
   else if(url.pathname==='/api/daily')data={counts:{},priorities:[],sources:[],attention:[],batches:{}};
   else if(url.pathname.startsWith('/api/'))data={hosts:[],sources:[],assets:[],job:{running:false},missing_providers:[]};
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://phase43.test/');
  await page.locator('#nav [data-page="Proxmox"]').waitFor();
  const lazy=['/proxmox.js','/elastic.js','/wazuh.js','/zabbix.js','/shares.js'];
  assert.deepEqual(lazy.filter(file=>requests.includes(file)),[],'no source view should load at startup');
  await page.evaluate(()=>{window.__phase43Render=render});
  for(const name of ['Proxmox','Elasticsearch','Wazuh','Zabbix','Partages']){
   await (async()=>{const hub=await page.evaluate(p=>v2HubOf(p),name);if(hub&&hub!==name){await page.locator('#nav [data-page="'+hub+'"]').click();await page.locator('#v2-hub-tabs [data-go="'+name+'"]').click();}else await page.locator('#nav [data-page="'+name+'"]').click();})(); // lot 3 : onglets du centre Sources
   await page.locator('script[data-lazy-page="'+name+'"]').waitFor({state:'attached'});
   await page.waitForFunction(pageName=>Boolean(pageRenderers[pageName]),name);
   await page.locator('#nav [data-page="Vue globale"]').click();
   await (async()=>{const hub=await page.evaluate(p=>v2HubOf(p),name);if(hub&&hub!==name){await page.locator('#nav [data-page="'+hub+'"]').click();await page.locator('#v2-hub-tabs [data-go="'+name+'"]').click();}else await page.locator('#nav [data-page="'+name+'"]').click();})(); // lot 3 : onglets du centre Sources
  }
  assert.equal(await page.evaluate(()=>render===window.__phase43Render),true,'lazy views must not wrap global render');
  for(const file of lazy)assert.equal(requests.filter(item=>item===file).length,1,file+' should load once');
  assert.deepEqual(errors,[]);
  console.log('PASS: Phase 4.3 lazy source views, single fetch and stable render dispatcher');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
