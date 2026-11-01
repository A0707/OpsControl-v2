// Audit SUP-04/05/06/07/09/10 : aucun vert ni « 0 » rassurant quand la preuve manque.
// Données simulées par interception (infraops.test) : aucune instance réelle, aucun réseau.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{
   window.EventSource=class extends EventTarget{constructor(){super();}close(){}};
  });
  await page.route('http://infraops.test/**',async route=>{
   const u=new URL(route.request().url());
   if(u.pathname==='/api/overview')return route.fulfill({json:{hosts:[],job:{running:false},monitoring:{interval:0}}});
   if(u.pathname==='/api/ssh/host-keys')return route.fulfill({json:{hosts:[]}});
   if(u.pathname.startsWith('/api/'))return route.fulfill({json:[]});
   const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://infraops.test/');
  await page.waitForFunction(()=>typeof homeCriticalMarkup==='function'&&typeof v2IntegrationTone==='function'&&typeof t0Tile==='function');

  const result=await page.evaluate(()=>{
   const now=new Date().toISOString(),old=new Date(Date.now()-10*60000).toISOString();
   const home=sources=>{alertData={alerts:[],sources,counts:{},levels:[]};alertFeedError=null;return homeCriticalMarkup();};
   const tone=(provider,detail)=>v2IntegrationTone({provider,fresh:true,detail});
   const tile=(status,checked_at)=>t0Tile({key:'db',name:'db',ip:'192.0.2.8',probe:{status,checked_at}},true);
   return {
    homeNone:home([]), homeLate:home([{name:'ZABBIX',provider:'Zabbix',fresh:false}]),
    homeFresh:home([{name:'ZABBIX',provider:'Zabbix',fresh:true}]),
    proxmoxEmpty:tone('Proxmox',{capacity:{},counts:{}}),
    proxmoxNodeDown:tone('Proxmox',{quorate:true,nodes_count:3,capacity:{nodes_online:2},counts:{}}),
    proxmoxOk:tone('Proxmox',{quorate:true,nodes_count:3,capacity:{nodes_online:3},counts:{}}),
    baculaEmpty:tone('Bacula',{latest_counts:{ok:null,critical:null,warning:null}}),
    baculaUnknownJob:tone('Bacula',{latest_counts:{ok:4,critical:0,warning:0,unknown:1}}),
    baculaOk:tone('Bacula',{latest_counts:{ok:4,critical:0,warning:0,unknown:0}}),
    wazuhEmpty:tone('Wazuh',{daemons:{running:null},agents:null}),
    wazuhOk:tone('Wazuh',{daemons:{running:12,failed:0,stopped:0},agents:{total:3,states:{}}}),
    tileFresh:tile('up',now), tileStale:tile('up',old), tileDownStale:tile('down',old),
   };
  });
  assert(!result.homeNone.includes('is-clear'),'aucune source : jamais « rien à signaler » en vert');
  assert(!result.homeLate.includes('is-clear'),'source en retard : jamais vert');
  assert.match(result.homeLate,/absence n’est pas confirmée/);
  assert(result.homeFresh.includes('is-clear'),'sources récentes et aucun incident : vert légitime');
  assert.deepEqual([result.proxmoxEmpty,result.proxmoxNodeDown,result.proxmoxOk],['unknown','warning','ok']);
  assert.deepEqual([result.baculaEmpty,result.baculaUnknownJob,result.baculaOk],['unknown','warning','ok']);
  assert.deepEqual([result.wazuhEmpty,result.wazuhOk],['unknown','ok']);
  assert.match(result.tileFresh,/status-up/);
  assert.match(result.tileStale,/status-unknown/);
  assert.match(result.tileStale,/Mesure périmée/);
  assert.match(result.tileDownStale,/status-down/,'une panne n’est jamais masquée par l’âge');

  // Carte « Sources à jour » sans aucune source déclarée : ton neutre (SUP-05).
  const card=await page.evaluate(()=>{
   alertData={alerts:[],sources:[],counts:{critical:0,warning:0,preventive:0,info:0,critical_stale:0,warning_stale:0,preventive_stale:0,info_stale:0},levels:[],policy:[],scope:''};
   const box=document.createElement('div');box.innerHTML=alertMarkup();
   const c=[...box.querySelectorAll('.stat-card')].find(e=>e.textContent.includes('Sources à jour'));
   return {cls:c.className,text:c.textContent};
  });
  assert(!/\bok\b/.test(card.cls),'0/0 source : jamais « ok »');
  assert.match(card.text,/Aucune source API déclarée/);

  // Tuile devenue périmée sans nouvelle peinture : la minuterie la déclasse (SUP-06).
  const ticked=await page.evaluate(()=>{
   const old=new Date(Date.now()-10*60000).toISOString(),box=document.createElement('div');
   box.innerHTML='<button class="t0-pill status-up" data-probe-at="'+old+'"><span class="t0-label">Opérationnel</span></button>';
   document.body.appendChild(box);t0Tick();
   const el=box.firstChild,out={cls:el.className,text:el.textContent};box.remove();return out;
  });
  assert.match(ticked.cls,/status-unknown/);
  assert.equal(ticked.text,'Mesure périmée');

  // Rapprochement d'incidents en échec : « 0 ouvert » n'est pas vert (SUP-09).
  const inc=await page.evaluate(()=>{
   incData={counts:{open:0,reopened:0},active_by_severity:{},items:[],total:0,sources:[],sync:{at:new Date().toISOString(),error:'OperationalError : database is locked'}};
   const box=document.createElement('div');box.innerHTML=incMarkup();
   return [...box.querySelectorAll(".v2-kpi")].slice(0,3).map(e=>e.className+' '+e.textContent).join(' | ');
  });
  assert(!/\bok\b/.test(inc.split(' | ')[0]),'KPI « Ouverts » jamais vert après un échec : '+inc);
  assert.match(inc,/Dernier rapprochement en échec/);

  // Audit SUP-17 : flux d'alertes en échec → message visible, aucune carte « Sources à jour » verte.
  const feed=await page.evaluate(()=>{
   alertData={alerts:[],sources:[{name:'ZABBIX',provider:'Zabbix',fresh:true}],counts:{critical:0,warning:0,preventive:0,info:0,critical_stale:0,warning_stale:0,preventive_stale:0,info_stale:0},levels:[],policy:[],scope:''};
   alertFeedError='Flux d’incidents indisponible.';
   const box=document.createElement('div');box.innerHTML=alertMarkup();
   const card=[...box.querySelectorAll('.stat-card')].find(e=>e.textContent.includes('Sources à jour'));
   const out={alert:!!box.querySelector('[role="alert"]'),cls:card.className,text:card.textContent};
   alertData=null;out.first=alertMarkup();alertFeedError='';
   return out;
  });
  assert(feed.alert,'erreur de flux affichée');
  assert(!/\bok\b/.test(feed.cls),'sources jamais « ok » quand le flux est en échec');
  assert.match(feed.text,/à reconfirmer/);
  assert.match(feed.first,/role="alert"/,'premier chargement en échec : pas de « Chargement… » sans fin');
  // Audit SUP-19 : Bacula en retard de sauvegarde ou non mesuré → jamais vert.
  const bacula=await page.evaluate(()=>[
   v2IntegrationTone({provider:'Bacula',fresh:true,detail:{latest_counts:{ok:4,critical:0,warning:0,unknown:0},overdue_count:1}}),
   v2IntegrationTone({provider:'Bacula',fresh:true,detail:{latest_counts:{ok:4,critical:0,warning:0,unknown:0},overdue_count:null}}),
   v2IntegrationTone({provider:'Bacula',fresh:true,detail:{latest_counts:{ok:4,critical:0,warning:0,unknown:0},overdue_count:0}})]);
  assert.deepEqual(bacula,['warning','unknown','ok']);

  assert.deepEqual(errors,[]);
  console.log('PASS: no reassuring green without fresh evidence (home, sources card, integrations, stale tiles, failed incident sync)');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
