// Phase 4.4: operational pages and detailed storage load only when requested.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');

(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1280,height:850}}),errors=[],requests=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>requests.push(new URL(request.url()).pathname));
  const host={key:'a',name:'srv-a',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',role:'Web',environment:'PROD',services:[],all_services:[],findings:[],checks:[],history:[],coverage:{measured:1,total:1},storage:{collected_at:new Date().toISOString(),remote_shares:[],filesystems:[],zfs:[],lvm:[],smart:[],io:{devices:[]},top_processes:[],scope:'Fixture stockage'}};
  await page.route('http://phase44.test/**',async route=>{
   const url=new URL(route.request().url());let data;
   if(url.pathname==='/api/overview')data={hosts:[host],counts:{ok:1},job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/hosts/a')data=host;
   else if(url.pathname==='/api/sync')data={ssh_job:{running:false},network_job:{running:false},job:{running:false,completed:0,total:0,errors:[]},sources:[],missing_providers:[],assets:[],unmatched_guests:[]};
   else if(url.pathname==='/api/inventory/suggestions')data={counts:{hosts:1,role_missing:0,role_proposed:0,services_declared:0,services_proposed:0},suggestions:[],conventions:{codes:{}},scope:'Fixture inventaire'};
   else if(url.pathname==='/api/connections')data=[];
   else if(url.pathname==='/api/manage/ssh-profile')data={effective:{profile:{users:['audit'],ports:[22]},users:['audit'],user_origin:'profil',ports:[22],port_origin:'profil'},collecting:false};
   else if(url.pathname==='/api/alerts')data={alerts:[],counts:{},sources:[],levels:[],policy:[]};
   else if(url.pathname==='/api/daily')data={counts:{},priorities:[],sources:[],attention:[],batches:{}};
   else if(url.pathname.startsWith('/api/'))data={hosts:[],sources:[],assets:[],job:{running:false},missing_providers:[]};
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://phase44.test/');
  await page.locator('#nav [data-page="Sources"]').waitFor();
  const lazy=['/storage.js','/sync.js','/inventory-completion.js','/connections.js','/api-help.js','/connections-v2.js'];
  assert.deepEqual(lazy.filter(file=>requests.includes(file)),[],'Phase 4.4 modules must not load at startup');
  await page.evaluate(()=>{window.__phase44Render=render;window.__phase44Detail=detailView});

  // Host management remains immediately available after the API forms split.
  await page.locator('#nav [data-page="Serveurs"]').click();await page.locator('[data-add-server]').click();
  await page.locator('#server-form').waitFor();await page.locator('#management-dialog [data-close]').click();

  await page.locator('#nav [data-page="Sources"]').click();await page.locator('#v2-hub-tabs [data-go="Synchronisation"]').click();await page.locator('#sync-data').waitFor();
  await page.locator('#nav [data-page="Compléter l’inventaire"]').click();await page.locator('#inv-data').waitFor();
  await page.locator('#nav [data-page="Sources"]').click();await page.locator('#v2-hub-tabs [data-go="Connexions API"]').click();await page.getByText('Comment ajouter une API ? Guide pas à pas',{exact:true}).waitFor();
  await page.locator('[data-add-api]').click();await page.locator('#connection-form').waitFor();await page.locator('#management-dialog [data-close]').click();
  await page.locator('#nav [data-page="Serveurs"]').click();await page.locator('[data-host="a"]').first().click();
  await page.locator('[data-tab="storage"]').click();await page.getByRole('heading',{name:'Stockage de ce serveur'}).waitFor();

  assert.equal(await page.evaluate(()=>render===window.__phase44Render&&detailView===window.__phase44Detail),true,'lazy modules must keep global dispatchers stable');
  for(const file of lazy)assert.equal(requests.filter(item=>item===file).length,1,file+' should load once');
  assert.deepEqual(errors,[]);
  console.log('PASS: Phase 4.4 pages and storage detail are lazy, single-fetch and wrapper-free');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
