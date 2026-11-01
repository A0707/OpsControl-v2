const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const now=new Date().toISOString(),old=new Date(Date.now()-86400e3).toISOString();
  const units=[{name:'nginx.service',status:'failed',substate:'failed',configured:true},{name:'oneshot.service',status:'active',substate:'exited',configured:true},{name:'off.service',status:'inactive',substate:'dead'},{name:'<img src=x onerror=alert(1)>',status:'unknown'},...Array.from({length:55},(_,i)=>({name:'worker-'+i,status:'active',substate:'running'}))];
  const jobs=[['cron','scheduled','Planification sans résultat',true],['systemd','success','Succès observé',true],['systemd','failed','Échec récent',true],['process','running','En cours',true],['bacula','failed','Échec ancien',false]].map(([kind,state,name,fresh],i)=>({id:String(i),name,kind,state,fresh,source:'fixture',host_key:'web',host_name:'Web',collected_at:fresh?now:old,exit_code:state==='success'?0:null,script:'/opt/job.sh',owner:'app',timezone:'UTC',schedule:'0 2 * * *',evidence:'Observation synthétique'}));
  const web={key:'web',name:'Web',registered:true,active_scope:true,ip:'192.0.2.1',status:'critical',collected_at:now,services:['nginx','oneshot'],all_services:units,batches:jobs,batch_coverage:{fresh:true,collected_at:now,limitations:['Comptes privés non mesurés']},checks:[],findings:[],history:[],applications:{status:'observed',collected_at:now,elements:[{nom:'app',categorie:'Application',source:'Fixture',etat:'Observée'}]},published_sites:[]};
  const oldHost={...web,key:'old',name:'Ancien',ip:'192.0.2.2',stale:true,collected_at:old,all_services:[{name:'old.service',status:'failed'}],batches:[]},missing={key:'missing',name:'Sans relevé',registered:true,ip:'192.0.2.3',status:'unknown',services:[],all_services:[]};
  const hosts=[web,oldHost,missing];
  for(const width of [1440,390]){
   const page=await browser.newPage({viewport:{width,height:950}}),errors=[],posts=[],serviceCalls=[];page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
   await page.route('**/*',route=>route.abort());
   await page.route('http://workloads.test/**',async route=>{
    const req=route.request(),u=new URL(req.url());if(req.method()!=='GET'){posts.push(u.pathname);return route.fulfill({status:403,json:{detail:'Lecture seule'}});}
    if(u.pathname==='/api/overview')return route.fulfill({json:{hosts,counts:{},job:{running:false},jobs:{},monitoring:{interval:0},availability:{sources:[]}}});
    if(u.pathname.startsWith('/api/hosts/')&&!u.pathname.endsWith('/observability'))return route.fulfill({json:hosts.find(h=>h.key===u.pathname.split('/').pop())});
    if(u.pathname==='/api/batches')return route.fulfill({json:{jobs,coverage:hosts.map(h=>({host_key:h.key,name:h.name,collected_at:h.collected_at,fresh:!h.stale&&!!h.collected_at,limitations:['Limite synthétique']})),job:{running:false}}});
    if(u.pathname==='/api/services/units'){
     serviceCalls.push(u.search);const status=u.searchParams.get('status'),q=u.searchParams.get('q')||'',freshness=u.searchParams.get('freshness'),wanted=u.searchParams.get('hosts')?.split(',');
     let all=hosts.filter(h=>!wanted||wanted.includes(h.key)).flatMap(h=>(h.all_services||[]).map(s=>({...s,host_key:h.key,collected_at:h.collected_at,fresh:!h.stale&&!!h.collected_at}))).filter(s=>(!q||s.name.toLowerCase().includes(q.toLowerCase()))&&(freshness==='all'||freshness==='recent'&&s.fresh||freshness==='stale'&&!s.fresh));
     const summary={failed_recent:all.filter(s=>s.fresh&&s.status==='failed').length,configured:all.filter(s=>s.configured).length,stale:all.filter(s=>!s.fresh).length,unmeasured_hosts:1};
     const filtered=all.filter(s=>status==='all'||status==='critical'&&s.configured||s.status===status),offset=Number(u.searchParams.get('offset')||0);
     return route.fulfill({json:{items:filtered.slice(offset,offset+100),total:filtered.length,offset,limit:100,summary}});
    }
    if(u.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
    const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);return fs.existsSync(file)?route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'"}}):route.fulfill({status:404,body:''});
   });
   await page.goto('http://workloads.test/');await page.waitForFunction(()=>state);await page.evaluate(()=>openHost('web'));await page.locator('[data-tab="services"]').click();
   await page.getByRole('heading',{name:'Services et traitements de ce serveur',exact:true}).waitFor();assert.equal(await page.locator('[data-workload-view]').count(),9,'5 vues et 4 cartes');
   assert.match(await page.locator('#workload-body').innerText(),/active\/exited/);assert.equal(await page.locator('.host-applications').count(),0,'vue inactive non construite');
   await page.locator('.workload-nav [data-workload-view="units"]').click();assert.equal(await page.locator('#workload-body tbody tr').count(),50);assert.equal(await page.locator('#workload-body img').count(),0);
   await page.locator('[data-workload-page="1"]').click();assert.equal(await page.locator('#workload-body tbody tr').count(),9);
   await page.locator('#workload-query').fill('oneshot');assert.equal(await page.locator('#workload-body tbody tr').count(),1);assert.match(await page.locator('#workload-body').innerText(),/exited/);assert.equal(await page.locator('#workload-query').evaluate(e=>e===document.activeElement),true);
   await page.evaluate(()=>render());assert.equal(await page.locator('#workload-query').inputValue(),'oneshot');
   await page.locator('.workload-nav [data-workload-view="batches"]').click();assert.equal(await page.locator('#workload-query').inputValue(),'','recherche indépendante par vue');
   assert.match(await page.locator('#workload-body').innerText(),/Planifié · résultat inconnu/);const success=page.locator('#workload-body tbody tr').filter({hasText:'Succès observé'});await success.getByText('Preuves et exécution',{exact:true}).click();assert.match(await success.innerText(),/Code retour : 0/);
   await page.locator('#workload-kind').selectOption('cron');assert.equal(await page.locator('#workload-body tbody tr').count(),1);
   await page.locator('.workload-nav [data-workload-view="applications"]').click();await page.locator('.host-applications').waitFor();await page.locator('.workload-nav [data-workload-view="published"]').click();await page.locator('.host-published').waitFor();
   await page.locator('.workload-nav [data-workload-view="units"]').click();assert.equal(await page.locator('#workload-query').inputValue(),'oneshot');
   await page.evaluate(()=>navigate('Services'));await page.locator('[data-svc-status="active"]').waitFor();await page.locator('[data-svc-status="active"]').click();await page.getByText('oneshot.service',{exact:true}).waitFor();assert.match(await page.locator('.workload-global').innerText(),/exited/);
   // Audit UI du 31/10 (fiche 04.1) : colonne « Criticité » avec provenance, plus de « Critique : Oui/Non ».
   assert.ok((await page.locator("#content thead").innerText()).includes("CRITICITÉ")||(await page.locator("#content thead").innerText()).includes("Criticité"));
   await page.locator('#svc-q').fill('oneshot');await page.locator('#svc-q').press('Tab');await page.waitForFunction(()=>document.querySelectorAll('.workload-global tbody tr').length===1);
   await page.locator('[data-svc-status="critical"]').click();await page.getByText('oneshot.service',{exact:true}).waitFor();await page.locator('[data-svc-host="web"]').click();await page.locator('.workload-nav').waitFor();assert.equal(await page.locator('.workload-nav [data-workload-view="units"]').getAttribute('aria-pressed'),'true');
   await page.evaluate(()=>navigate('Services'));await page.locator('#search').fill('ne-correspond-a-rien');const before=serviceCalls.length;await page.getByText('Aucun serveur pour ces critères.',{exact:false}).waitFor();await page.evaluate(()=>render());assert.equal(serviceCalls.length,before,'périmètre vide ne charge pas tout le parc');
   await page.evaluate(()=>{filters={q:'',status:'',environment:'',role:''};navigate('Batch / Planification')});await page.getByText('Référentiel des batchs indisponible').waitFor();await page.locator('[data-batch-view="jobs"]').click();await page.locator('#batch-results tbody tr').first().waitFor();
   await page.locator('[data-batch-view="priorities"]').click();assert.equal(await page.locator('#batch-results tbody tr').count(),1);assert.match(await page.locator('#batch-results').innerText(),/Échec récent/);assert.doesNotMatch(await page.locator('#batch-results').innerText(),/Échec ancien/);
   await page.locator('[data-batch-view="scheduled"]').click();assert.equal(await page.locator('#batch-results tbody tr').count(),1);assert.match(await page.locator('#batch-results').innerText(),/résultat inconnu/);
   await page.locator('[data-batch-view="running"]').click();assert.equal(await page.locator('#batch-results tbody tr').count(),1);
   await page.locator('[data-batch-view="coverage"]').click();assert.equal(await page.locator('#batch-results').isVisible(),false);assert.equal(await page.locator('#batch-servers tbody tr').count(),3);
   await page.locator('#batch-servers [data-batch-host="web"]').click();assert.equal(await page.locator('#batch-host').inputValue(),'web');assert.equal(await page.locator('[data-batch-view="jobs"]').getAttribute('aria-pressed'),'true');
   await page.locator('#batch-freshness').selectOption('stale');assert.equal(await page.locator('#batch-results tbody tr').count(),1);assert.match(await page.locator('#batch-results').innerText(),/Observation ancienne/);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'aucun débordement');fs.mkdirSync(path.join(__dirname,'data','v2-captures'),{recursive:true});await page.screenshot({path:path.join(__dirname,'data','v2-captures','workloads-'+width+'.png'),fullPage:true});
   assert.deepEqual(posts,[]);assert.deepEqual(errors,[]);await page.close();
  }
  console.log('PASS: vues services et batchs, sous-état, zéro, recherches indépendantes, pagination, fraîcheur, périmètre vide, mobile, CSP, sans POST');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
