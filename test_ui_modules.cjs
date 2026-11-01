const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage(),errors=[],requests=[];let coalesced=0;
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
  await page.route('http://modules.test/**',async route=>{
   const request=route.request(),url=new URL(request.url());requests.push({path:url.pathname,method:request.method(),headers:request.headers(),body:request.postData()});
   if(url.pathname==='/api/coalesce'){coalesced++;await new Promise(r=>setTimeout(r,40));return route.fulfill({json:{ok:true}});}
   if(url.pathname==='/api/forbidden')return route.fulfill({status:403,json:{detail:'Refus simulé'}});
   if(url.pathname==='/api/action')return route.fulfill({json:{ok:true}});
   if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[],counts:{},job:{running:false},jobs:{},monitoring:{interval:0}}});
   if(url.pathname==='/api/whoami')return route.fulfill({json:{role:'viewer',can_admin:false,can_operate:false}});
   if(url.pathname==='/api/ssh/host-keys')return route.fulfill({json:{hosts:[]}});
   if(url.pathname==='/api/daily')return route.fulfill({json:{counts:{},priorities:[],sources:[],attention:[],batches:{}}});
   if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
   // La latence du point d’entrée ne doit pas laisser partir les scripts classiques avant le pont.
   if(url.pathname==='/frontend-bootstrap.js')await new Promise(r=>setTimeout(r,100));
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://modules.test/');
  await page.waitForFunction(()=>typeof state!=='undefined'&&state&&frontendStarted);
  assert.equal(requests.filter(r=>r.method!=='GET').length,0,'imports et démarrage : GET uniquement');
  const result=await page.evaluate(async()=>{
   const source=await fetch('/frontend-bootstrap.js').then(r=>r.text());
   const utilsUrl=source.match(/from '(\/frontend-utils\.js[^']*)'/)[1];
   const uiUrl=source.match(/from '(\/v2-ui\.js[^']*)'/)[1];
   const utils=await import(utilsUrl),components=await import(uiUrl);
   const created=components.createUi({freshnessMarkup:()=>'<time>fixture</time>'});
   await Promise.all([utils.api('/api/coalesce'),api('/api/coalesce')]);
   let forbidden;try{await utils.api('/api/forbidden')}catch(error){forbidden={status:error.status,message:error.message}}
   await utils.post('/api/action',{label:'fixture'});
   return {same:utils.esc===esc&&utils.api===api&&utils.SEVERITY===SEVERITY,escaped:utils.esc('<img>'),empty:utils.escAttr(null),gauge:created.gauge('Valeur',null),fresh:created.fresh(null),forbidden};
  });
  assert.equal(result.same,true);assert.equal(result.escaped,'&lt;img&gt;');assert.equal(result.empty,'');
  assert.match(result.gauge,/Non mesuré/);assert.equal(result.fresh,'<time>fixture</time>');
  assert.equal(result.forbidden.status,403);assert.match(result.forbidden.message,/Action non autorisée/);
  assert.equal(coalesced,1,'un seul GET entre import ES et consommateur classique');
  const action=requests.find(r=>r.path==='/api/action');assert.equal(action.headers['x-cockpit-request'],'1');assert.equal(JSON.parse(action.body).label,'fixture');
  assert.deepEqual(errors,[]);console.log('PASS: real ES imports, delayed startup, shared bridge/cache, escaping, errors and explicit POST headers');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
