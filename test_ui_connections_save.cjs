// OC-AUDIT-021 : après « Enregistrer la connexion », la carte apparaît (ou change) aussitôt,
// même quand le parc (/api/overview) ne change pas. Données simulées, aucune instance réelle.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');

(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1280,height:850}}),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  const host={key:'a',name:'srv-a',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',role:'Web',environment:'PROD',services:[],all_services:[],findings:[],checks:[],history:[],coverage:{measured:1,total:1}};
  const saved=[];let posts=0;
  await page.route('http://connections-save.test/**',async route=>{
   const request=route.request(),url=new URL(request.url());let data;
   if(url.pathname==='/api/overview')data={hosts:[host],counts:{ok:1},job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/connections'&&request.method()==='POST'){
    posts++;const body=request.postDataJSON();const i=saved.findIndex(c=>c.key===body.key);
    const item={...body,host_key:body.host_key||null};if(i<0)saved.push(item);else saved[i]=item;data=item;
   }
   else if(url.pathname==='/api/connections')data=saved;
   else if(url.pathname.startsWith('/api/'))data={hosts:[],sources:[],assets:[],job:{running:false},missing_providers:[]};
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://connections-save.test/');
  await page.locator('#nav [data-page="Sources"]').click();
  await page.locator('#v2-hub-tabs [data-go="Connexions API"]').click();
  await page.getByText('Ajoutez une source avec son URL de lecture',{exact:false}).waitFor();

  const fill=async(values)=>{
   await page.locator('#connection-form').waitFor();
   for(const [name,value] of Object.entries(values))await page.locator('#connection-form [name="'+name+'"]').fill(value);
   await page.locator('#connection-form [type=submit]').click();
  };
  await page.locator('[data-add-api]').click();
  await fill({key:'es',name:'Cluster Elastic',url:'https://es.example.test/_cluster/health'});
  await page.locator('#connections-list h2',{hasText:'Cluster Elastic'}).waitFor({timeout:3000});

  await page.locator('[data-edit-api="es"]').click();
  await fill({name:'Cluster Elastic renommé'});
  await page.locator('#connections-list h2',{hasText:'Cluster Elastic renommé'}).waitFor({timeout:3000});
  assert.equal(posts,2);
  assert.equal(await page.locator('#connections-list article').count(),1);
  assert.deepEqual(errors,[]);
  console.log('OK : carte Connexions API rafraîchie après enregistrement, parc inchangé');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exit(1)});
