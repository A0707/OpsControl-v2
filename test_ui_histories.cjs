const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],posts=[];
  page.on('pageerror',e=>errors.push(e.message));
  // Actions à effet (ajout, maintenance) : confirmation demandée puis acceptée (audit FE-08).
  const confirmations=[];page.on('dialog',d=>{confirmations.push(d.message());d.accept();});
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
  const at=new Date().toISOString(), host={key:'demo',name:'Démo',ip:'192.0.2.1',status:'unknown',services:[],checks:[],findings:[]};
  const item={ip:'192.0.2.2',ports:[22],ssh_port:22,ping:true,ttl:64,type:'Linux',os:'Test',dns:'<img src=x onerror=alert(1)>',status:'new_ssh',proxmox_matches:[],proxmox_proposal:{name:'VM proposée',node:'node-test',source:'Cluster fictif',fresh:true}};
  const discovery={job:{running:false},at,range:'192.0.2.0/29',items:[item],counts:{inventory:0,new_ssh:1,new:0},inventory_missing:[host]};
  const history={scope:'Comparaison de scans terminés de même plage.',scans:[{id:2,range:'192.0.2.0/29',at,duration_s:1,status:'completed',hosts_count:1,changes:{appeared:['192.0.2.2'],disappeared:['192.0.2.1'],ports_changed:[{ip:'192.0.2.3',before:[22],after:[22,443]}]}}]};
  await page.route('http://histories.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());let data;
   if(req.method()==='POST'){posts.push({path:url.pathname,body:req.postDataJSON()});return route.fulfill({json:{added:[],note:'Simulation'}});}
   if(url.pathname==='/api/overview')data={hosts:[host],job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/whoami')data={role:'admin',mode:'local',authenticated:false,can_admin:true,can_operate:true};
   else if(url.pathname==='/api/discovery')data=discovery;
   else if(url.pathname==='/api/discovery/history')data=history;
   else if(url.pathname==='/api/ssh/host-keys')data={hosts:[]};
   else if(url.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://histories.test/');
  await page.evaluate(()=>discoveryOpen());
  await page.getByText('Machines de l’inventaire non observées dans cette plage').waitFor();
  await page.getByText('Proxmox proposé : VM proposée · nœud node-test · Cluster fictif').waitFor();
  assert.equal(await page.locator('#disc-result img').count(),0);
  await page.getByRole('tab',{name:'Historique',exact:true}).click();
  await page.getByText('1 apparues · 1 non observées · 1 changements de ports').click();
  assert.ok((await page.locator('#disc-history-panel').textContent()).includes('22, 443'));
  assert.equal(posts.length,0,'aucun scan automatique');
  await page.getByRole('tab',{name:'Historique',exact:true}).focus();
  await page.keyboard.press('ArrowLeft');
  await page.locator('#disc-use-pve').check();
  await page.locator('[data-disc-pick]').check();
  await page.locator('[data-disc-add]').click();
  await page.getByText('0 serveur(s) ajouté(s). Simulation').waitFor();
  assert.equal(posts[0].body.use_proxmox_names,true);
  await page.evaluate(()=>hostAccessDialog.close());
  const row={ip:'93.184.216.34',verdict:'verify',kind:'publique',network:'93.184.216.0/24',network_bans:3,modsec_rules:[],reasons:['Test'],requests:100,first_observed:at,last_observed:at,current_observed_since:at,reban_count:2,location:{status:'observed',country:'=1+2',city:'Ville test',asn:'AS-test'}};
  await page.evaluate(data=>{wafBanKey='waf-demo';wafBanData=data;document.querySelector('#content').innerHTML='<section id="waf-ban-analysis" data-key="waf-demo"></section>';wafBanPaint();},{rows:[row],summary:{listed:1,currently_banned:1,incoherent:0,verify:1,keep:0,campaigns:[]},coverage:{activity_known:true},collected_at:at,recommendations:[{network:'93.184.216.0/24',text:'Limiter le débit du robot déclaré',rule:'Quota par user-agent'}],top_traffic:[{ip:row.ip,requests:100,location:row.location}]});
  await page.getByText('2 rebannissement(s) observé(s)',{exact:false}).waitFor();
  const download=page.waitForEvent('download');await page.locator('[data-waf-ban-export]').click();
  const file=await download;await file.saveAs('data/waf-analysis-export-test.csv');
  const csv=fs.readFileSync('data/waf-analysis-export-test.csv','utf8');assert.ok(csv.includes("'=1+2"));assert.ok(csv.includes('93.184.216.34'));
  assert(confirmations.length>0,'action à effet sans confirmation');
  assert.deepEqual(errors,[]);console.log('PASS: discovery history, missing inventory, explicit Proxmox choice, no automatic scan, ban chronology, CSV and formula protection');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
