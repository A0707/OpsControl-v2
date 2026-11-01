// OpsControl V2 — parcours complet sur une fixture ENTIÈREMENT SYNTHÉTIQUE.
// Aucune requête ne quitte le navigateur : toutes les routes sont simulées ici.
// Adresses de documentation uniquement (RFC 5737). Produit les captures V2.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const OUT=path.join(__dirname,'data','v2-captures');fs.mkdirSync(OUT,{recursive:true});
const SECRET='SECRET-NE-DOIT-PAS-APPARAITRE-7f3a';

(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage(),errors=[],mutations=[];let observabilityRequests=0;
  page.on('pageerror',e=>errors.push(e.message+' @ '+String(e.stack||'').split(/\n/)[1]));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super();setTimeout(()=>this.dispatchEvent(new Event('ready')),0)}close(){}}});
  const now=Date.now(),iso=ms=>new Date(ms).toISOString(),fresh=iso(now-60000),old=iso(now-3*86400000);
  const base={registered:true,active_scope:true,services:[],findings:[],checks:[],service_states:[],coverage:{measured:15,total:15},network_evidence:{ping:true,fresh:true,collected_at:fresh},proxmox_matches:[],source_links:[],backup_summary:{matched:false,jobs_count:0,severity:'unknown',fresh:false}};
  const hosts=[
   {...base,key:'web01',name:'web01',ip:'192.0.2.10',role:'Web',environment:'PROD',status:'ok',cpu:12,ram:41,disk_max:55,collected_at:fresh,
    backup_summary:{matched:true,jobs_count:2,severity:'ok',fresh:true,collected_at:fresh,last_success:'2026-09-28 01:00:00'}},
   {...base,key:'db01',name:'db01',ip:'192.0.2.11',role:'Base de données',environment:'PROD',status:'critical',cpu:71,ram:93,disk_max:94,collected_at:fresh,criticality:'critical',
    proxmox_matches:[{cluster:'DEMO',node:'pve-a',vmid:102,status:'running',fresh:true,collected_at:fresh,cpu_pct:20,memory_bytes:1<<30,memory_total_bytes:2<<30,disk_capacity_bytes:8<<30}],
    findings:[{id:'disk',domain:'Stockage',severity:'critical',title:'Disque à 94 %',evidence:'/var 94 %',scope:'df',check_command:'df -h',solution_command:'',precaution:''}]},
   {...base,key:'app01',name:'app01',ip:'192.0.2.12',role:'Applicatif',environment:'REC',status:'warning',cpu:35,ram:62,disk_max:82,collected_at:fresh},
   {...base,key:'fw01',name:'fw01',ip:'192.0.2.13',role:'Pare-feu',environment:'PROD',status:'unreachable',cpu:null,ram:null,disk_max:null,collected_at:fresh,network_evidence:{ping:false,fresh:true,collected_at:fresh},coverage:{measured:0,total:15}},
   {...base,key:'old01',name:'old01',ip:'192.0.2.14',role:'Web',environment:'PROD',status:'ok',stale:true,cpu:10,ram:20,disk_max:30,collected_at:old,network_evidence:{ping:null,fresh:false,collected_at:old}},
   {...base,key:'new01',name:'new01',ip:'192.0.2.15',role:'À renseigner',environment:'PROD',status:'unknown',cpu:null,ram:null,disk_max:null,collected_at:null,coverage:{measured:0,total:15},network_evidence:{}}
  ];
  const sources=[{key:'pve',name:'Cluster DEMO',provider:'Proxmox',collected_at:fresh,fresh:true,status:'observed',error:null,auth_configured:true},
   {key:'zbx',name:'Zabbix DEMO',provider:'Zabbix',collected_at:fresh,fresh:true,status:'observed',error:null,auth_configured:true},
   {key:'waz',name:'Wazuh DEMO',provider:'Wazuh',collected_at:fresh,fresh:true,status:'observed',error:null,auth_configured:true},
   {key:'es',name:'Elastic DEMO',provider:'Elasticsearch',collected_at:old,fresh:false,status:'unknown',error:'Délai de connexion dépassé.',auth_configured:true}];
  const overview={hosts,counts:{},job:{running:false},jobs:{ssh:{running:false},network:{running:false},api:{running:false}},monitoring:{interval:300},missing_auth:[],availability:{exclusions:{},sources}};
  const cockpit={version:'2.0',sources:[
   {key:'pve',name:'Cluster DEMO',provider:'Proxmox',status:'observed',fresh:true,collected_at:fresh,has_data:true,detail:{quorate:true,nodes_count:2,counts:{running:3,stopped:1,storage_unavailable:0},capacity:{nodes_online:2,cpu_pct:18,memory_bytes:60,memory_total_bytes:100,storage_used_bytes:40,storage_total_bytes:100}}},
   {key:'zbx',name:'Zabbix DEMO',provider:'Zabbix',status:'observed',fresh:true,collected_at:fresh,has_data:true,detail:{counts:{monitored:5,unmonitored:1},problem_counts:{critical:1,warning:2,unknown:0},problems_measured:true}},
   {key:'waz',name:'Wazuh DEMO',provider:'Wazuh',status:'observed',fresh:true,collected_at:fresh,has_data:true,detail:{daemons:{running:10,stopped:2,failed:0},agents:{total:6,states:{active:4,disconnected:1,never_connected:1}},manager_version:'v4.x'}},
   {key:'es',name:'Elastic DEMO',provider:'Elasticsearch',status:'retained',fresh:false,collected_at:old,error:'Délai de connexion dépassé.',has_data:true,detail:{cluster_status:'green',number_of_nodes:3,unassigned_shards:0}}],
   missing_providers:['Bacula']};
  const vm=(vmid,name,status,node,type='qemu')=>({vmid,name,type,status,node,cpu_pct:status==='running'?20:0,memory_bytes:1<<30,memory_total_bytes:2<<30,disk_used_bytes:1<<30,disk_capacity_bytes:8<<30,pool:'demo-pool'});
  const inv={nodes_count:2,counts:{qemu:3,lxc:1,running:3,stopped:1,storage:1},summary:{nodes_online:2,cpu_pct:18,memory_bytes:60,memory_total_bytes:100,storage_used_bytes:40,storage_total_bytes:100},cluster:{name:'DEMO',quorate:true},scope:'Fixture synthétique',
   nodes:[{name:'pve-a',status:'online',reported:true,cpu_pct:22,cpu_capacity:16,memory_bytes:30,memory_total_bytes:50,guests:[vm(101,'web01','running','pve-a'),vm(102,'db01','running','pve-a')],storages:[{name:'local-lvm',status:'available',type:'lvmthin',shared:false,used_bytes:40,total_bytes:100}]},
          {name:'pve-b',status:'online',reported:true,cpu_pct:14,cpu_capacity:16,memory_bytes:30,memory_total_bytes:50,guests:[vm(103,'app01','running','pve-b'),vm(104,'ct-old','stopped','pve-b','lxc')],storages:[]}]};
  const connections=[{key:'pve',name:'Cluster DEMO',provider:'Proxmox',url:'https://pve.example.test:8006/api2/json/cluster/resources',token_env:'INFRAOPS_PROXMOX_AUTH',auth_configured:true,
    last_result:{status:'observed',collected_at:fresh,inventory:inv,indicators:{resources:9,running:3,stopped:1},summary:{type:'dict',entries:1,bytes:4096},password:SECRET}}];
  const daily={generated_at:fresh,counts:{inventory:6,registered:6,online:5,audit_recorded:4,audit_missing:2,critical_recent:1,critical_total:1,critical_stale:0,api_fresh:3,api_total:4},policy:'Fixture.',
   priorities:[{host_key:'db01',host_name:'db01',title:'Disque à 94 %',severity:'critical',collected_at:fresh,stale:false},{host_key:'old01',host_name:'old01',title:'Ancienne alerte',severity:'warning',collected_at:old,stale:true}],
   sources:[],attention:[],batches:{counts:{},fresh_failures:0,fresh_hosts:0,hosts_total:6}};
  const detail=key=>({...hosts.find(h=>h.key===key),history:[],attempts:[],alerts:{items:[],counts:{total:0}},
   source_details:[{provider:'Wazuh',key:'waz',collected_at:fresh,fresh:true,evidence:{agent:{name:key,status:'active',version:'v4.x'}},scope:'serveur'},
                   {provider:'Zabbix',key:'zbx',collected_at:fresh,fresh:true,evidence:{host:{status:'monitored'},problems_measured:true,problems:[]},scope:'serveur'}]});
  const network={job:{running:false,completed:0,total:0},hosts:hosts.map(h=>({key:h.key,name:h.name,ip:h.ip,ping:h.network_evidence.ping??null,ports:[{port:22,ok:h.status!=='unreachable'}],ssh_key_known:true,collected_at:h.network_evidence.collected_at||null}))};
  const observability={samples:4,range_days:7,scope:'Fixture : audits SSH conservés.',
   points:[{at:old,status:'ok',cpu:20,ram:42,disk:68},{at:fresh,status:'critical',cpu:31,ram:48,disk:94}],
   trends:{cpu:{first:20,last:31,delta:11,direction:'up',samples:2},ram:{first:42,last:48,delta:6,direction:'up',samples:2},disk:{first:68,last:94,delta:26,direction:'up',samples:2}},
   changes:[{at:fresh,kind:'threshold',type:'changes',source:'Audit SSH',title:'Disque : seuil ok → critical',severity:'critical',evidence:'68 % → 94 %'}]};
  const shapes={'/api/overview':overview,'/api/v2/cockpit':cockpit,'/api/connections':connections,'/api/daily':daily,'/api/network':network,'/api/findings':{},
   '/api/alerts':{alerts:[],counts:{},sources:[],levels:[],policy:[]},'/api/tier0':{hosts:[],sources:[]},'/api/ssh-refresh':{interval:0},
   '/api/services':{},'/api/services/units':{items:[],total:0,failed_total:0,offset:0,limit:100,status:'failed'},'/api/batches':{jobs:[],coverage:[],job:{running:false}},'/api/sync':{assets:[],sources:[],unmatched_guests:[],missing_providers:[],job:{completed:0,total:0,errors:[]}},
   '/api/shares':{shares:[],clients:[],hosts:[]},'/api/runtime':{hint:'Fixture',transport:'openssh'},'/api/inventory-report':{policy:'Fixture',hosts:6,conflicts:[],excluded:[]},
   '/api/inventory/suggestions':{suggestions:[],counts:{}}};
  await page.route('http://opscontrol-v2.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(req.method()!=='GET'){mutations.push(req.method()+' '+url.pathname);return route.fulfill({json:{}})}
   if(/^\/api\/hosts\/[^/]+\/observability$/.test(url.pathname)){observabilityRequests++;return route.fulfill({json:observability});}
   if(url.pathname.startsWith('/api/hosts/'))return route.fulfill({json:detail(decodeURIComponent(url.pathname.split('/').pop()))});
   if(url.pathname.startsWith('/api/'))return shapes[url.pathname]!==undefined?route.fulfill({json:shapes[url.pathname]}):route.fulfill({status:404,json:{detail:'Non simulé'}});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',
    headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'"}});
  });
  const shot=async name=>{await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(OUT,name),fullPage:true})};
  const noHScroll=async label=>assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Défilement horizontal : '+label);

  await page.goto('http://opscontrol-v2.test/');
  // 1. Navigation par domaines : cinq domaines, pages existantes toutes présentes.
  const sections=await page.locator('#nav .nav-section').allTextContents();
  assert.deepEqual(sections,['PILOTAGE','PARC','INFRASTRUCTURE','SUPERVISION & SÉCURITÉ','DONNÉES & CONFIGURATION']);
  // Lot 3 : les vues sœurs d'un centre quittent le menu mais restent accessibles (onglets,
  // recherche, adresse #/…). Aucune page ne doit disparaître : menu ∪ centres.
  const pages=await page.evaluate(()=>[...document.querySelectorAll('#nav [data-page]')].map(x=>x.dataset.page).concat(v2HubMembers()));
  assert.ok((await page.locator('#nav [data-page]').count())<=18,'menu allégé : 18 entrées au plus avec Assistant IA');
  for(const p of ['Vue globale','Alertes','Problèmes','Serveurs','Services','Audit','Batch / Planification','Proxmox','Réseau','Sauvegardes','Partages','WAF / HA','Zabbix','Wazuh','Elasticsearch','Sécurité','Synchronisation','Inventaire','Compléter l’inventaire','Connexions API','Connexion'])
   assert.ok(pages.includes(p),'Page absente : '+p);
  assert.ok(pages.includes('Assistant IA'),'Page Assistant IA absente');

  // 2. Centre d'exploitation : quatre KPI et priorités visibles ; détail à la demande.
  await page.locator('#v2-ops .v2-command-kpis .v2-kpi').first().waitFor();
  assert.equal(await page.locator('#v2-ops .v2-command-kpis .v2-kpi').count(),4);
  assert.equal((await page.locator('#progress').textContent()).trim(),'','Les collectes au repos sont répétées dans la barre de contrôle');
  assert.equal(await page.locator('#t0-zone .park').isVisible(),false,'Le résumé du parc est affiché deux fois en mode standard');
  await page.getByRole('heading',{name:'À traiter maintenant'}).first().waitFor();
  assert.equal(await page.locator('[data-v2-home-details]').evaluate(d=>d.open),false);
  await page.locator('[data-v2-home-details] summary').click();
  await page.locator('#v2-ops .v2-fleet').waitFor();
  const legend=Object.fromEntries(await page.locator('#v2-ops .v2-fleet .v2-legend-item').evaluateAll(l=>l.map(x=>[x.querySelector('span').textContent,Number(x.querySelector('b').textContent)])));
  assert.deepEqual(legend,{OK:1,Critiques:1,'Majeurs':1,Injoignables:1,Inconnus:0,'Anciens / jamais audités':2});
  await page.locator('#v2-ops .v2-integration').filter({hasText:'Bacula'}).getByText('Non raccordé').waitFor();
  await page.locator('#v2-ops .v2-integration').filter({hasText:'Elasticsearch'}).getByText('Échec · données conservées').waitFor();
  assert.match(await page.locator('#v2-status').textContent(),/Sources API 3\/4 récentes/);
  // Régression lazy : la fiche serveur doit fonctionner avant que la page
  // Proxmox ait chargé son module et ses helpers privés.
  assert.equal(await page.evaluate(()=>typeof pveSize),'undefined');
  await page.evaluate(()=>navigate('Serveurs'));
  await page.locator('#next-parc .n-table').waitFor();
  await page.locator('#content [data-host="db01"]').first().click();
  await page.locator('.v2-source-matrix').waitFor();
  // Lot 4 : les mesures de l'hyperviseur sont dans l'onglet Performances.
  await page.locator('[data-tab="performance"]').click();
  assert.match(await page.locator('#content').innerText(),/RAM utilisée \/ allouée[\s\S]*Gio/);
  // L'onglet Performances a chargé l'historique : on repart d'un état vierge pour vérifier plus bas le chargement paresseux.
  await page.evaluate(()=>v2ObsCache.clear());observabilityRequests=0;
  await page.evaluate(()=>{selected=null;hostDetail=null;navigate('Vue globale')});
  await page.locator('#v2-ops .v2-command-kpis').waitFor();
  await page.locator('.v2-home-journal > summary').click();
  await page.getByText('Preuve ancienne',{exact:true}).first().waitFor();
  await page.locator('[data-v2-home-details] summary').click();
  await page.locator('.v2-home-journal > summary').click();
  await shot('v2-home-desktop-dark.png');

  // 3. Outils opérateur légers : compact, favoris, palette et mode NOC.
  await page.locator('[data-v2-density]').click();
  assert.equal(await page.locator('html').getAttribute('data-density'),'compact');
  assert.equal(JSON.parse(await page.evaluate(()=>localStorage.getItem('opscontrol-v2-prefs'))).density,'compact');
  await page.locator('[data-v2-nav]').click();
  await page.locator('#v2-nav-dialog [data-v2-favorite="Proxmox"]').click();
  assert.ok(JSON.parse(await page.evaluate(()=>localStorage.getItem('opscontrol-v2-prefs'))).favorites.includes('Proxmox'));
  await page.locator('#v2-nav-dialog').evaluate(d=>d.close());
  await page.keyboard.press('Control+K');
  await page.locator('#v2-command-search').fill('Proxmox');
  await page.locator('#v2-command-dialog [data-v2-page="Proxmox"]').click();
  assert.equal(await page.locator('#title').textContent(),'Proxmox');
  await page.evaluate(()=>navigate('Vue globale'));
  await page.locator('[data-v2-noc]').click();
  assert.equal(await page.locator('html').getAttribute('data-display'),'noc');
  assert.equal(await page.locator('.sidebar').isVisible(),false);
  assert.equal(await page.locator('#t0-zone .park').isVisible(),true,'La mosaïque détaillée doit rester disponible en mode NOC');
  await shot('v2-home-noc-dark.png');
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('html').getAttribute('data-display'),'standard');
  await page.locator('[data-v2-density]').click();

  // 4. Chaque page s'affiche sans erreur JavaScript et sans défilement horizontal.
  for(const p of pages){
   const hub=await page.evaluate(p=>v2HubOf(p),p);
   if(hub&&hub!==p){await page.locator('#nav [data-page="'+hub+'"]').click();await page.locator('#v2-hub-tabs [data-go="'+p+'"]').click();}
   else await page.locator('#nav [data-page="'+p+'"]').click();
   await page.waitForTimeout(120);assert.equal(await page.locator('#title').textContent(),p);
  }
  assert.deepEqual(errors,[],'Erreurs JS pendant la navigation');

  // 5. Filtres et page mémorisés : l'URL porte la page, la recherche survit au rechargement.
  await page.locator('#nav [data-page="Serveurs"]').click();
  await page.locator('#next-parc .n-table').waitFor();
  assert.equal(await page.locator('#next-parc').count(),1,'Vue Parc optimisée non montée');
  assert.equal(await page.locator('#content > .panel .table').count(),0,'Ancien tableau encore rendu');
  assert.equal(await page.getByText('Gérer le parc et les services critiques surveillés.').count(),1,'Actions de gestion dupliquées');
  assert.equal(await page.getByText('Repères pour exploiter cette page').count(),1,'Guide de page dupliqué');
  assert.equal(await page.getByText('Hyperviseur non renseigné',{exact:true}).count(),0,'Information absente répétée dans le tableau');
  await page.locator('#search').fill('db');
  assert.equal(await page.locator('#content tbody tr').count(),1);
  assert.equal(new URL(page.url()).hash,'#/Serveurs');
  await page.reload();
  await page.locator('#search').waitFor();
  assert.equal(await page.locator('#search').inputValue(),'db');
  assert.equal(await page.locator('#title').textContent(),'Serveurs');
  // Le polling ne vole ni le focus ni la saisie.
  await page.locator('#search').focus();
  const reused=await page.evaluate(()=>{const row=document.querySelector('#content tbody tr');row.__phase4Marker=true;state.hosts[0].cpu=13;render();return row===document.querySelector('#content tbody tr')&&document.querySelector('#content tbody tr').__phase4Marker===true});
  assert.equal(reused,true,'Ligne serveur reconstruite au lieu d’être réconciliée');
  await page.evaluate(()=>{lastHostSnapshot='';return load()});
  assert.equal(await page.locator('#search').evaluate(e=>e===document.activeElement),true);
  await page.locator('#search').fill('');
  await shot('v2-servers-desktop-dark.png');

  // 6. Fiche serveur : jauges, rapprochement des sources, onglets V2.
  await page.locator('#content [data-host="db01"]').first().click();
  await page.locator('.v2-source-matrix tbody tr').first().waitFor();
  assert.equal(await page.locator('.v2-source-matrix tbody tr').count(),6);
  assert.equal(await page.locator('.v2-host-gauges .v2-gauge').count(),2);
  assert.equal(observabilityRequests,0,'Historique chargé avant ouverture de la chronologie');
  assert.ok((await page.locator('.v2-host-gauges .v2-track i').first().evaluate(i=>i.getBoundingClientRect().width))>0,'Jauge vide : CSP ?');
  await page.locator('[data-tab="performance"]').click();
  await page.locator('.v2-observability').waitFor();
  assert.equal(observabilityRequests,1,'Historique non chargé paresseusement');
  assert.equal(await page.locator('.v2-trend-card').count(),2);
  assert.ok((await page.locator('.v2-chart-line').first().getAttribute('points')).length>3,'Courbe de tendance vide');
  // La chronologie unifiée vit dans l'onglet Incidents ; même historique, aucune requête de plus.
  await page.locator('[data-tab="incidents"]').click();
  await page.getByText('Disque : seuil ok → critical').waitFor();
  assert.equal(observabilityRequests,1,'Historique rechargé en changeant d’onglet');
  await shot('v2-observability-desktop-dark.png');
  for(const [tab,text] of [['network','Réseau et accès SSH'],['backup','Sauvegardes observées'],['security','Sécurité observable']]){
   await page.locator('[data-tab="'+tab+'"]').click();await page.getByRole('heading',{name:text}).waitFor();
  }
  await shot('v2-server-desktop-dark.png');
  // Un serveur jamais mesuré n'affiche aucune valeur inventée.
  await page.locator('#content .detail-banner [data-go="Serveurs"]').click();
  await page.locator('#content [data-host="new01"]').first().click();
  await page.locator('.v2-host-gauges').waitFor();
  assert.equal(await page.locator('.v2-host-gauges .sev-none').count(),3);

  // 7. Proxmox : jauges remplies malgré la CSP, filtres état/type.
  await page.evaluate(()=>{selected=null;hostDetail=null;navigate('Proxmox')});
  await page.locator('.pve-hero').waitFor();
  assert.ok((await page.locator('.pve-gauge-track i').nth(1).evaluate(i=>i.getBoundingClientRect().width))>0,'Jauge Proxmox vide');
  await page.locator('[data-pve-mode="guests"]').click();
  await page.locator('#pve-status').selectOption('stopped');
  assert.equal(await page.locator('.pve-table tbody tr').count(),1);
  await page.locator('#pve-search').fill('demo-pool');
  assert.equal(await page.locator('.pve-table tbody tr').count(),1);
  await page.locator('#pve-status').selectOption('');
  assert.equal(await page.locator('.pve-table tbody tr').count(),4);
  await shot('v2-proxmox-desktop-dark.png');

  // 8. Connexions API : résumé normalisé, aucun corps JSON ni champ secret affiché.
  await page.locator('#nav [data-page="Sources"]').click();await page.locator('#v2-hub-tabs [data-go="Connexions API"]').click();
  await page.locator('.v2-conn-summary').waitFor();
  assert.equal(await page.locator('#connections-list pre').count(),0);
  assert.ok(!(await page.content()).includes(SECRET),'Secret présent dans le HTML');

  // 9. Thème clair.
  await page.evaluate(()=>applyTheme('light'));
  await page.evaluate(()=>navigate('Vue globale'));
  await page.locator('#v2-ops .v2-command-kpis').waitFor();
  const bg=await page.evaluate(()=>getComputedStyle(document.body).backgroundColor);
  assert.notEqual(bg,'rgb(11, 14, 19)');
  await shot('v2-home-desktop-light.png');
  await page.evaluate(()=>applyTheme('dark'));

  // 10. Mobile : pas de défilement horizontal, navigation par liste.
  await page.setViewportSize({width:390,height:844});
  await noHScroll('accueil');await shot('v2-home-mobile-dark.png');
  await page.locator('#mobile-nav').selectOption('Proxmox');await page.locator('.pve-hero').waitFor();await noHScroll('proxmox');await shot('v2-proxmox-mobile-dark.png');
  await page.locator('#mobile-nav').selectOption('Serveurs');await page.locator('#next-parc .n-table').waitFor();await noHScroll('parc serveurs');await shot('v2-servers-mobile-dark.png');
  await page.locator('#content [data-host="db01"]').first().click();await page.locator('.v2-source-matrix').waitFor();
  await noHScroll('fiche serveur');await shot('v2-server-mobile-dark.png');
  await page.locator('[data-tab="performance"]').click();await page.locator('.v2-observability').waitFor();await noHScroll('chronologie');await shot('v2-observability-mobile-dark.png');
  await page.evaluate(()=>applyTheme('light'));await page.evaluate(()=>{selected=null;hostDetail=null;navigate('Vue globale')});await page.locator('#v2-ops .v2-command-kpis').waitFor();
  await noHScroll('accueil clair');await shot('v2-home-mobile-light.png');
  await page.keyboard.press('Tab');
  assert.notEqual(await page.evaluate(()=>document.activeElement.tagName),'BODY');

  // 11. Lecture seule : la navigation n'a émis aucune requête de mutation.
  assert.deepEqual(mutations,[],'Requêtes non-GET émises : '+mutations.join(', '));
  assert.deepEqual(errors,[]);
  console.log('PASS: V2 accueil opérateur, compact/NOC, palette, favoris, navigation, sources, fiche serveur, Proxmox, filtres, thèmes, mobile, lecture seule');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
