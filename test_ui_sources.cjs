const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'); const path=require('node:path');const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
 const page=await browser.newPage({viewport:{width:1440,height:900}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const now=new Date().toISOString();
 const hosts=[{key:'a',name:'Actif',ip:'192.0.2.1',status:'unknown',active_scope:true,services:[],findings:[],checks:[]},{key:'b',name:'Arrete',ip:'192.0.2.2',status:'unknown',active_scope:false,services:[],findings:[],checks:[]}];
 const sources=[{key:'es',name:'Elastic test',provider:'Elasticsearch',url:'https://example.test',auth_configured:false,last_result:{status:'observed',collected_at:now,indicators:{cluster_status:'yellow',number_of_nodes:3,unassigned_shards:950}}},{key:'w',name:'Wazuh test',provider:'Wazuh',last_result:{status:'observed',collected_at:now,inventory:{counts:{running:1,stopped:1},daemons_count:2,daemons:[{name:'wazuh-apid',status:'running'},{name:'wazuh-maild',status:'stopped'}]}}},{key:'z',name:'Zabbix test',provider:'Zabbix',last_result:{status:'observed',collected_at:now,inventory:{counts:{monitored:1},hosts:[{name:'Actif',host:'a',status:'monitored',addresses:['192.0.2.1']}],problems:[{severity:'critical',severity_label:'Haute',description:'Disque plein',hosts:['a']},{severity:'warning',severity_label:'Moyenne',description:'Charge',hosts:['a']}]}}}];
 await page.route('http://infraops.test/**',async route=>{
 const url=new URL(route.request().url());let data;
 if(url.pathname==='/api/overview')data={hosts,counts:{unknown:2},job:{running:false},monitoring:{interval:0}};
 else if(url.pathname==='/api/connections')data=sources;
 else if(url.pathname==='/api/alerts')data={alerts:[],counts:{},sources:[],levels:[],policy:[]};
 else if(url.pathname==='/api/daily')data={counts:{},priorities:[],sources:[],attention:[],batches:{}};
 else if(url.pathname==='/api/hosts/a'){await new Promise(r=>setTimeout(r,250));data={...hosts[0],history:[]};}
 else if(url.pathname.startsWith('/api/'))data={hosts:[],job:{running:false,errors:[]},sources:[],assets:[],unmatched_guests:[],missing_providers:[]};
 if(data)return route.fulfill({json:data});
 const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
 return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
 });
 await page.goto('http://infraops.test/');
 const auditLabels=await page.evaluate(()=>[
  hostAuditBadge({status:'unknown',stale:true,coverage:{measured:13},audit_status:'critical'}),
  hostAuditBadge({status:'unknown',coverage:{measured:13}}),
  hostAuditBadge({status:'unknown',coverage:{measured:0}}),
  hostAuditBadge({status:'critical',coverage:{measured:13}})]);
 assert.ok(auditLabels[0].includes('Audit ancien')&&/dernier audit : Critique/i.test(auditLabels[0]));
 // Audit UI du 31/10 (fiche 05.1) : cause de « ancien », audit partiel nommé, seuil de 15 min.
 const lot3=await page.evaluate(()=>({
  attempt:hostAuditBadge({status:'unknown',stale:true,stale_reason:'attempt_failed',coverage:{measured:13},audit_status:'ok'}),
  partial:coverage({coverage:{measured:13,total:15},coverage_missing:['Pare-feu','Mises à jour']}),
  complete:coverage({coverage:{measured:15,total:15},coverage_missing:[]}),
  recent:freshnessMarkup(new Date(Date.now()-5*60000).toISOString(),'Mesures SSH',SSH_FRESH_SECONDS)}));
 assert.ok(lot3.attempt.includes('Dernière tentative en échec'));
 assert.ok(lot3.partial.includes('13 / 15 · partiel')&&lot3.partial.includes('Absents : Pare-feu, Mises à jour'));
 assert.ok(!lot3.complete.includes('partiel'));
 assert.ok(!lot3.recent.includes('À actualiser'),'mesure de 5 min : récente');
 assert.ok(auditLabels[1].includes('Audit partiel'));
 assert.ok(auditLabels[2].includes('Audit non mesuré'));
 assert.ok(auditLabels[3].includes('Critique')&&!auditLabels[3].includes('Audit ancien'));

 await page.locator('#nav [data-page="Serveurs"]').click();
 await page.getByText('1 serveur du parc géré sur 2 entrées',{exact:false}).first().waitFor();
 assert.equal(await page.locator('#content tbody tr').count(),1);
 await page.locator('#nav [data-page="Inventaire"]').click();assert.equal(await page.locator('#content tbody tr').count(),2);
 // Périmètre explicite (fiches 01.1 et 14.1) : l'entrée hors parc géré est nommée et filtrable.
 await page.getByText('1 serveur du parc géré sur 2 entrées de l’inventaire consolidé',{exact:false}).waitFor();
 assert.equal(await page.locator('#content .scope-tag').count(),1);
 await page.locator('#content select[data-filter="scope"]').selectOption('other');
 assert.equal(await page.locator('#content tbody tr').count(),1);
 await page.locator('#content [data-reset]').click();
 assert.equal(await page.locator('#content tbody tr').count(),2);
 await page.locator('#nav [data-page="Serveurs"]').click();
 const stable=await page.evaluate(async()=>{const row=document.querySelector('#content tbody tr'),menu=document.querySelector('#nav [data-page="Serveurs"]');await load();await load();return {row:row===document.querySelector('#content tbody tr'),menu:menu===document.querySelector('#nav [data-page="Serveurs"]')};});assert.deepEqual(stable,{row:true,menu:true});
 await page.locator('#content [data-host="a"]').first().click();
 await page.locator('#nav [data-page="Sources"]').click();await page.locator('#v2-hub-tabs [data-go="Elasticsearch"]').click();await page.getByText('950',{exact:true}).waitFor();await page.getByText(/Identifiants absents/).waitFor();await page.waitForTimeout(300);assert.equal(await page.evaluate(()=>page),'Elasticsearch');assert.equal(await page.locator('#elastic-data').count(),1);
 await page.locator('#v2-hub-tabs [data-go="Wazuh"]').click();await page.getByText('wazuh-maild',{exact:true}).waitFor();assert.equal(await page.locator('#wazuh-data td .critical').count(),0);assert.equal(await page.evaluate(async()=>{const row=document.querySelector('#wazuh-data tbody tr');await loadWazuh();return row===document.querySelector('#wazuh-data tbody tr');}),true);
 await page.locator('#wazuh-search').fill('apid');assert.equal(await page.locator('#wazuh-data tbody tr').count(),1);
 await page.locator('#nav [data-page="Sources"]').click();await page.locator('#v2-hub-tabs [data-go="Zabbix"]').click();await page.getByText('Disque plein',{exact:true}).waitFor();await page.locator('#zbx-level').selectOption('critical');assert.equal(await page.getByText('Charge',{exact:true}).count(),0);await page.getByText('Actif · détail serveur',{exact:true}).waitFor();
 await page.locator('#zbx-search').fill('Disque');await page.evaluate(()=>render());assert.equal(await page.locator('#zbx-search').inputValue(),'Disque');assert.equal(await page.locator('#zbx-search').evaluate(e=>e===document.activeElement),true);
 await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
 await page.locator('#mobile-nav').selectOption('Serveurs');assert.equal(await page.locator('#content tbody tr').count(),1);assert.equal(await page.locator('#nav').isVisible(),false);
 await page.evaluate(()=>{state.hosts.forEach(h=>{h.active_scope=false;});state.availability={exclusions:{'Ping ancien ou non mesuré pour cette IP':2}};render();});await page.getByText('Aucun serveur confirmé en ligne pour le moment',{exact:true}).waitFor();await page.getByText('2 · Ping ancien ou non mesuré pour cette IP',{exact:true}).waitFor();
 await page.evaluate(()=>{state.hosts[1].registered=true;render();});assert.equal(await page.locator('#content tbody tr').count(),1);await page.getByText('Arrete',{exact:true}).waitFor();
 // A failed API attempt keeps the previous inventory, even when that inventory
 // is only seconds old; it must still be labelled non-current.
 sources.push({key:'p',name:'PVE test',provider:'Proxmox',last_result:{status:'observed',collected_at:now,inventory:{counts:{qemu:1,lxc:0,running:1,stopped:0},nodes_count:1,nodes:[{name:'pve01',status:'online',guests:[{vmid:100,name:'VM conservée',status:'running',type:'qemu'}]}]}}});
 sources.push({key:'b',name:'Bacula test',provider:'Bacula',last_result:{status:'observed',collected_at:now,inventory:{jobs_count:1,counts:{ok:1},jobs:[{name:'Backup conservé',severity:'ok',status_label:'Terminé'}]}}});
 for(const source of sources){source.last_success_result=source.last_result;source.last_result={status:'unknown',collected_at:now,error:'Connexion interrompue <script>bad()</script>'};}
 await page.setViewportSize({width:1440,height:900});
 for(const [name,target,value] of [['Elasticsearch','#elastic-data','950'],['Wazuh','#wazuh-data','wazuh-apid'],['Zabbix','#zbx-data','Disque plein'],['Proxmox','#pve-data','VM conservée'],['Sauvegardes','#bacula-data','Backup conservé']]){
  // Lot 3 : Zabbix, Wazuh et Elasticsearch sont des onglets du centre Sources.
  const hub=await page.evaluate(p=>v2HubOf(p),name);
  if(hub&&hub!==name){await page.locator('#nav [data-page="'+hub+'"]').click();await page.locator('#v2-hub-tabs [data-go="'+name+'"]').click();}
  else await page.locator('#nav [data-page="'+name+'"]').click();
  if(name==='Sauvegardes')await page.locator(target+' details summary').click();
  await page.locator(target).getByText(value,{exact:true}).waitFor();
  await page.locator(target).getByText(/Dernières données conservées/).waitFor();
  assert.equal(await page.locator(target+' .source-state .observed').count(),0);
  assert.equal(await page.locator(target+' script').count(),0);
 }
 Object.assign(hosts[0],{audit_recorded:true,audit_retained:true,stale:true,cpu:12,ram:35,collected_at:now,coverage:{measured:13,total:16},last_attempt:{collected_at:now,issues:['Clé SSH à vérifier']},proxmox_matches:[{cluster:'PVE',node:'pve01',vmid:100,status:'running',collected_at:now,fresh:true,cpu_pct:4,memory_bytes:1073741824,memory_total_bytes:2147483648,disk_capacity_bytes:10737418240}]});
 await page.locator('#nav [data-page="Inventaire"]').click();
 await page.locator('#content [data-host="a"]').first().click();
 await page.getByRole('heading',{name:'Dernière tentative SSH en échec'}).waitFor();
 await page.locator('[data-tab="performance"]').click();
 await page.getByRole('heading',{name:'Dernière tentative SSH en échec'}).waitFor();
 await page.getByRole('heading',{name:'Mesures API Proxmox de ce serveur'}).waitFor();
 await page.getByText('Clé SSH à vérifier',{exact:true}).waitFor();
 await page.evaluate(()=>{hostDetail.alerts={counts:{total:2,old:1},items:[{id:'z:1',source:'Zabbix',severity:'critical',title:'Disque saturé',duration_seconds:90000,started_at:'2026-09-17T09:00:00Z',observed_at:'2026-09-18T10:00:00Z',fresh:true,time_basis:'Dernier changement du trigger Zabbix',evidence:'<script>bad()</script>'},{id:'s:1',source:'SSH',severity:'warning',title:'Horloge non synchronisée',duration_seconds:0,fresh:false,time_basis:'Première observation conservée'}]};render();});
 await page.locator('[data-tab="incidents"]').click();
 // Alertes brutes par source repliées sous les incidents du journal (e748b59).
 await page.locator('.server-monitoring > summary').click();
 await page.getByRole('heading',{name:'Supervision de ce serveur'}).waitFor();
 await page.locator('#server-alert-results').getByText('1 j 1 h',{exact:true}).waitFor();
 assert.equal(await page.locator('#server-alert-results script').count(),0);
 await page.locator('#server-alert-source').selectOption('SSH');
 assert.equal(await page.locator('#server-alert-results tbody tr').count(),1);
 await page.locator('#server-alert-source').selectOption('');
 await page.locator('#server-alert-query').fill('saturé');
 assert.equal(await page.locator('#server-alert-results tbody tr').count(),1);
 assert.equal(await page.locator('#server-alert-query').evaluate(e=>e===document.activeElement),true);
 await page.locator('#server-alert-severity').selectOption('warning');
 assert.equal(await page.locator('#server-alert-results tbody tr').count(),0);

 await page.setViewportSize({width:390,height:844});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
 assert.deepEqual(errors,[]);console.log('PASS: navigation, focus, mobile, retained inventories for all five APIs, retained SSH and distinct Proxmox metrics');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
