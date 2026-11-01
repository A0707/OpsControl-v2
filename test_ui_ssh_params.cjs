const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],posts=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
  const hosts=Array.from({length:11},(_,i)=>({key:'demo'+i,name:i===1?'<img src=x onerror=alert(1)>':'Démo '+i,ip:'192.0.2.'+(10+i),role:'Web',environment:'DEMO',services:[],status:'unknown',user:'audit',port:22,findings:[],checks:[]}));
  const diagnostic=(h,ok=true)=>({key:h.key,name:h.name,ip:h.ip,ok,cause:ok?null:'auth',summary:ok?'Lecture uptime réussie':'Compte refusé',steps:[{step:'Empreinte',ok:true,detail:'Clé vérifiée'}],attempts:[{user:h.user,port:h.port,ok,duration_ms:1,detail:ok?'up 3 days':'Authentification refusée'}]});
  await page.route('http://ssh-params.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());let data;
   if(req.method()==='POST'){
    const body=req.postDataJSON();posts.push({path:url.pathname,body});
    if(url.pathname==='/api/hosts/test-params')return route.fulfill({json:{...diagnostic({...body,name:'Paramètres non enregistrés'}),saved:false}});
    const key=url.pathname.split('/')[3],host=hosts.find(h=>h.key===key);
    return route.fulfill({json:diagnostic(host,key!=='demo5')});
   }
   if(url.pathname==='/api/overview')data={hosts,job:{running:false},jobs:{},monitoring:{interval:0}};
   // Formulaire : configuration enregistrée (port explicite 22) et profil SSH hérité.
   else if(url.pathname.startsWith('/api/manage/hosts/')){const h=hosts.find(h=>h.key===url.pathname.split('/')[4]);data={host:h,revision:'0123456789abcdef',...({effective:{profile:{users:['audit'],ports:[22]},users:['audit'],user_origin:'profil',ports:[22],port_origin:'profil'},collecting:false}),effective:{profile:{users:['audit'],ports:[22]},users:[h.user],user_origin:'serveur',ports:[h.port],port_origin:'serveur'}}}
   else if(url.pathname==='/api/whoami')data={role:'admin',mode:'local',can_admin:true,can_operate:true};
   else if(url.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://ssh-params.test/');
  await page.waitForFunction(()=>state?.hosts?.length===11);
  await page.evaluate(()=>openServer('demo0'));
  await page.locator('#server-form [name=ip]').fill('192.0.2.90');
  await page.locator('#server-form [data-server-next]').click();
  await page.locator('#server-form [name=user]').fill('audit_demo');
  await page.locator('#server-form [name=port]').fill('2222');
  await page.getByRole('button',{name:'Tester avec ces paramètres',exact:true}).click();
  await page.getByRole('heading',{name:'Résultat des paramètres testés'}).waitFor();
  assert.deepEqual(posts[0],{path:'/api/hosts/test-params',body:{ip:'192.0.2.90',user:'audit_demo',port:2222}});
  assert.equal(await page.locator('#server-form [name=ip]').inputValue(),'192.0.2.90');
  assert.equal(await page.evaluate(()=>state.hosts[0].ip),'192.0.2.10');
  await page.evaluate(()=>{modal.close();bulkOpen()});
  await page.locator('[data-bulk-all="1"]').click();
  await page.locator('[data-bulk-test]').click();
  await page.getByText('Cocher de 1 à 10 serveurs pour ce test.').waitFor();
  assert.equal(posts.length,1);
  await page.locator('[data-bulk-pick][value=demo10]').uncheck();
  await page.locator('[data-bulk-test]').click();
  await page.getByText('Tests terminés · aucun paramètre enregistré.').waitFor();
  assert.equal(await page.locator('#bulk-test-results details').count(),10);
  assert.equal(posts.length,11);
  assert.equal(posts.filter(p=>p.path.includes('/manage/')).length,0);
  assert.equal(await page.locator('#bulk-test-results img').count(),0);
  assert.deepEqual(errors,[]);
  console.log('PASS: unsaved values, unchanged form/inventory, maximum 10, per-server results and escaping');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
