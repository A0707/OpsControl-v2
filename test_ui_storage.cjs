// Parc intégralement simulé : navigation sans collecte, volumes distincts et lacunes visibles.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const now=new Date().toISOString(),dates=[-3,-2,-1,0].map(d=>new Date(Date.now()+d*86400e3).toISOString());
  const volume=(mount,device,extra={})=>({mount,device,fstype:'ext4',use_pct:40,total_kb:10485760,available_kb:6291456,used_kb:4194304,inodes_use_pct:20,inodes_total:1000,inodes_used:200,inodes_free:800,severity:'ok',capacity_severity:'ok',inode_severity:'ok',reasons:[],...extra});
  const root=volume('/','/dev/sda1'),data=volume('/data','/dev/sdb1',{inodes_use_pct:100,inodes_free:0,inodes_used:1000,severity:'critical',inode_severity:'critical',reasons:['100 % des inodes utilisés']}),snap=volume('/snap/core/1','/dev/loop0',{use_pct:100,technical:true,severity:'info'}),trap=volume('/<img src=x onerror=alert(1)>','/dev/sdc1');
  const host={key:'storage01',name:'storage01',registered:true,ip:'192.0.2.1',status:'critical',services:[],all_services:[{name:'worker.service',status:'active',substate:'exited',configured:true}],collected_at:now,history:[],checks:[],findings:[],audit_versions:[],
   storage:{collected_at:now,collection_complete:false,filesystems:[root,data,snap,trap],remote_shares:[{mount:'/nas',source:'nas:/share',fstype:'nfs4',status:'unknown',error_kind:'probe_error',access:'read-write'}],exports:[{protocol:'NFS',path:'/data',clients:'192.0.2.2(ro)',filesystem:'/data'}],lvm:[{vg:'vg0',lv:'thin',pool:'pool0',data_pct:90,metadata_pct:98}],volume_groups:[{name:'vg0',size_bytes:10737418240,free_bytes:0}],smart:[{device:'sda',status:'unknown',detail:'Non accessible'}]},
   storage_assessment:{fresh:true,collected_at:now,volumes:[data,root,trap,snap],capacity:root,history_timestamps:dates,history:[volume('/','/dev/sda1',{at:dates[0],use_pct:10}),volume('/','/dev/sda1',{at:dates[2],use_pct:30}),volume('/','/dev/sda1',{at:dates[3],use_pct:40}),volume('/data','/dev/sdb1',{at:dates[0],use_pct:70}),volume('/data','/dev/sdb1',{at:dates[1],use_pct:80}),volume('/data','/dev/sdb1',{at:dates[2],use_pct:90,total_kb:20971520}),volume('/data','/dev/sdb1',{at:dates[3],use_pct:95,total_kb:20971520})]}};
  for(const width of [1440,390,320]){
   const page=await browser.newPage({viewport:{width,height:900}}),errors=[],posts=[];page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
   await page.route('**/*',route=>route.abort());
   await page.route('http://storage.test/**',async route=>{
    const req=route.request(),url=new URL(req.url());if(req.method()!=='GET'){posts.push(url.pathname);return route.fulfill({status:403,body:''});}
    if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[host],counts:{},job:{running:false},jobs:{},monitoring:{interval:0},availability:{sources:[]}}});
    if(url.pathname==='/api/hosts/storage01')return route.fulfill({json:host});
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Source non simulée'}});
    const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
    return fs.existsSync(file)?route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}}):route.fulfill({status:404,body:''});
   });
   await page.goto('http://storage.test/');await page.waitForFunction(()=>state);await page.evaluate(()=>openHost('storage01'));await page.locator('.host-tabs').waitFor();
   assert.equal(await page.locator('.host-tabs [role=tab]').count(),8);
   assert.match(await page.locator('.host-capacity-summary').innerText(),/\/.*40 %/s);
   await page.locator('[data-tab="storage"]').click();
   const panel=page.locator('.storage-detail');await panel.waitFor();
   assert.match(await panel.innerText(),/Collecte interrompue/);
   assert.equal(await panel.locator('img').count(),0,'montage échappé');
   assert.match(await panel.locator('.storage-volume').first().innerText(),/100 % des inodes utilisés/);
   assert.match(await panel.locator('.storage-volume').first().innerText(),/0 libres/);
   assert.equal(await panel.locator('.storage-technical').getAttribute('open'),null);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),'volumes sans débordement');
   fs.mkdirSync(path.join(__dirname,'data','v2-captures'),{recursive:true});await page.screenshot({path:path.join(__dirname,'data','v2-captures','storage-volumes-'+width+'.png'),fullPage:true});
   await page.locator('#storage-query').fill('/data');assert.equal(await panel.locator('.storage-volume').count(),1);
   await page.evaluate(()=>render());assert.equal(await page.locator('#storage-query').inputValue(),'/data');
   await page.locator('[data-storage-history="/data"]').click();
   assert.equal(await page.locator('#storage-history-mount').inputValue(),JSON.stringify(['/data','/dev/sdb1']));
   assert.equal(await panel.locator('.storage-history-chart').first().locator('polyline').count(),2,'extension interrompt la courbe');
   await page.locator('#storage-history-mount').selectOption(JSON.stringify(['/','/dev/sda1']));
   assert.equal(await panel.locator('.storage-history-chart').first().locator('polyline').count(),1,'lacune non reliée');
   assert.equal(await panel.locator('.storage-history-chart').first().locator('circle').count(),1);
   await page.locator('[data-storage-section="shares"]').click();assert.match(await panel.innerText(),/Échec de sonde : cause non établie/);assert.match(await panel.innerText(),/clients autorisés ne sont pas des sessions actives/);
   await page.locator('[data-storage-section="topology"]').click();assert.match(await panel.innerText(),/pool0/);assert.match(await panel.innerText(),/98 %/);
   await page.locator('[data-storage-section="health"]').click();assert.match(await panel.innerText(),/Non mesuré/);assert.match(await panel.innerText(),/latences, IOPS/);
   await page.locator('[data-tab="services"]').click();await page.locator('.workload-nav [data-workload-view="units"]').click();assert.match(await page.locator('#host-tabpanel').innerText(),/active.*exited/s);assert.match(await page.locator('#host-tabpanel').innerText(),/ne prouve pas/);
   await page.locator('[data-tab="storage"]').click();assert.equal(await page.locator('[data-storage-section="health"]').getAttribute('aria-pressed'),'true');
   await page.evaluate(()=>{hostDetail.storage_assessment.fresh=false;render()});assert.match(await panel.innerText(),/Anciennes mesures/);
   await page.locator('.storage-proof button').click();assert.equal(await page.locator('#host-tab-audit').getAttribute('aria-expanded'),'true');
   assert.equal(await page.locator('.host-tabs [tabindex="0"]').count(),1,'onglets toujours accessibles depuis les preuves');
   await page.locator('[data-tab="storage"]').click();
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);assert.ok(overflow<=1,'mobile sans débordement : '+overflow+' px');
   fs.mkdirSync(path.join(__dirname,'data','v2-captures'),{recursive:true});await page.screenshot({path:path.join(__dirname,'data','v2-captures','storage-'+width+'.png'),fullPage:true});
   assert.deepEqual(posts,[],'aucune collecte pendant la navigation');assert.deepEqual(errors,[]);await page.close();
  }
  console.log('PASS: stockage par volume, inodes, partages, LVM, lacunes, extension, ancienneté, preuves, mobile et CSP');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
