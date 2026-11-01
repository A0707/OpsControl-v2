// Lot 4 : fiche serveur en huit onglets (Applications ajouté le 10/10). Onglets visibles dès l'ouverture, seul l'onglet actif
// est construit, aucune section perdue ni dupliquée, clavier (flèches/Début/Fin), anciennes clés
// acceptées, avertissements de validité sur chaque onglet, serveur jamais audité sans valeur
// inventée, mobile 44 px sans débordement. Fixture synthétique, lecture seule.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const now=new Date().toISOString(),old=new Date(Date.now()-86400e3).toISOString();
  const base={registered:true,active_scope:true,services:[],environment:'PROD',role:'Web'};
  const web={...base,key:'web01',name:'web01',ip:'192.0.2.10',status:'warning',cpu:41,ram:63,disk_max:88,collected_at:now,coverage:{measured:12,total:15},
   ssh_user:'audit',ssh_port:22,os:'Debian 12',uptime:'12 jours',audit_recorded:true,audit_versions:[{},{}],
   last_attempt:{collected_at:now,issues:['Délai SSH dépassé']},
   findings:[{id:'disk',domain:'stockage',severity:'warning',title:'Disque /var à 88 %',evidence:'df -h',commands:{diagnose:'df -h /var'}}],
   checks:[{id:'c1',status:'pass',title:'Contrôle des services'}],history:[{ts:now,status:'warning',issues:['Disque']}],
   all_services:[{name:'nginx.service',status:'active',configured:true}],batches:[{name:'logrotate',state:'ok',last_run:now}],
   batch_coverage:{limitations:['Cron et timers systemd uniquement']},
   alerts:{counts:{total:2,old:1},scope:'Alertes rapprochées par nom et IP.',items:[
    {id:'z1',source:'Zabbix',severity:'critical',title:'Charge élevée',observed_at:now,started_at:old,fresh:true,duration_seconds:3600,time_basis:'Début Zabbix'},
    {id:'s1',source:'SSH',severity:'warning',title:'Disque /var à 88 %',observed_at:old,fresh:false,time_basis:'Audit'}]},
   source_details:[{provider:'Zabbix',fresh:true,collected_at:now,scope:'Hôte Zabbix associé par nom',evidence:{host:{status:'monitored'},problems_measured:true,problems:[{description:'Charge élevée'}]}}],
   proxmox_matches:[{cluster:'PVE',node:'pve01',vmid:101,status:'running',fresh:true,collected_at:now,cpu_pct:12,memory_bytes:2e9,memory_total_bytes:4e9,disk_capacity_bytes:5e10}],
   network_evidence:{fresh:true,ping:true,collected_at:now},backup_summary:{matched:false},
   storage:{collected_at:now,filesystems:[]},documented:{owner:'Équipe web'},inventory_sources:['classeur.xlsx'],
   published_sites:[{site:'portail.exemple.ma',url:'https://portail.exemple.ma/',https:true,dns:{statut:'en_ligne',adresses:['203.0.113.9']},
    chemin:'/',port:3000,chemin_cible:'/',via:{key:'new01',name:'new01'},releve_le:now,application:'Conteneur Docker portail'}],
   applications:{status:'observed',collected_at:now,os:'Debian 12',docker:'1 conteneur(s)',ports:['22','443','8080'],dossiers:['/opt/app'],
    installation:1700000000,installation_source:'Paquet basesystem (rpm)',
    sites:[{nom:'app.exemple.local',url:'https://app.exemple.local/',https:true,serveur_web:'Apache',fichiers:['/etc/apache2/sites-enabled/app.conf'],
      cibles:[{chemin:'/',cible:'127.0.0.1:3000/',application:'Conteneur Docker web'}],racines:[],dns:{statut:'interne',adresses:['10.0.0.5']}},
     {nom:'piege',url:'javascript:alert(1)',https:false,serveur_web:'Nginx',fichiers:['/etc/nginx/x'],cibles:[],racines:['/var/www'],dns:{statut:'en_ligne',adresses:['8.8.8.8']}}],
    elements:[
     {categorie:'Serveur web',source:'Service systemd',nom:'nginx',detail:'',etat:'Démarré',date:1700000000,nature_date:'Installation'},
     {categorie:'Conteneur',source:'Docker',nom:'<img src=x onerror=alert(1)>',detail:'image app:1',etat:'Up 2 days',date:null,nature_date:''},
     {categorie:'Processus applicatif',source:'Java',nom:'-jar /opt/app/app.jar',detail:'',etat:'',date:1700000000,nature_date:'Dernier déploiement du fichier'}]}};
  const fresh={...base,key:'new01',name:'new01',ip:'192.0.2.20',status:'unknown',collected_at:null,coverage:{measured:0,total:15},findings:[],checks:[],history:[],alerts:{counts:{},items:[]}};
  const hosts=[web,fresh];
  for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   const mobile=viewport.width<500,page=await browser.newPage({viewport}),errors=[],posts=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}}});
   let obsRequests=0;
   await page.route('http://tabs.test/**',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(req.method()!=='GET'){posts.push(url.pathname);return route.fulfill({status:403,json:{detail:'lecture seule'}});}
    if(url.pathname==='/api/overview')return route.fulfill({json:{hosts,counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
    const m=url.pathname.match(/^\/api\/hosts\/([^/]+)(\/observability)?$/);
    if(m&&m[2]){obsRequests++;return route.fulfill({json:{samples:2,scope:'Audits conservés',points:[{cpu:30,ram:60,disk:80},{cpu:41,ram:63,disk:88}],trends:{},changes:[{at:now,title:'Disque : seuil ok → warning',severity:'warning'}]}});}
    if(m)return route.fulfill({json:hosts.find(h=>h.key===decodeURIComponent(m[1]))});
    if(url.pathname==='/api/network')return route.fulfill({json:{hosts:[{key:'web01',collected_at:now,ping:true,ssh_key_known:true,ports:[{port:22,ok:true}]}]}});
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
    const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
    if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
    return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
   });
   await page.goto('http://tabs.test/');
   await page.waitForFunction(()=>typeof state!=='undefined'&&state);
   await page.evaluate(()=>openHost('web01'));
   await page.locator('.host-tabs').waitFor();
   // Sept onglets, visibles sans défiler (ils étaient à 2 090 px sur desktop).
   assert.deepEqual(await page.locator('.host-tabs [role=tab]').allInnerTexts().then(t=>t.map(x=>x.replace(/\d+$/,'').trim())),
    ['Synthèse','Incidents','Stockage','Performances','Services & applications','Réseau & accès','Sauvegardes','Sécurité']);
   const top=await page.locator('.host-tabs').evaluate(e=>e.getBoundingClientRect().top+scrollY);
   assert.ok(top<(mobile?844*1.2:900),'onglets visibles dès l’ouverture ('+Math.round(top)+' px)');
   const heights=await page.$$eval('.host-tabs [role=tab]',bs=>bs.map(b=>b.getBoundingClientRect().height));
   assert.ok(heights.every(h=>h>=44),'cibles ≥ 44 px : '+heights);
   assert.equal(await page.locator('[data-tab="incidents"] .tab-count').innerText(),'2','alerte récente + constat SSH mesuré');
   // Synthèse seule construite.
   const has=sel=>page.locator('#host-tabpanel '+sel).count();
   assert.equal(await has('.v2-source-matrix'),1);
   assert.equal(await has('.v2-host-gauges'),1);
   assert.equal(await has('.server-facts-panel'),1);
   assert.match(await page.locator('.v2-host-priorities').innerText(),/Charge élevée/);
   assert.doesNotMatch(await page.locator('.v2-host-priorities').innerText(),/Disque \/var/,'alerte ancienne absente des priorités');
   for(const sel of ['.server-monitoring','.v2-observability','.host-findings','.server-secondary'])assert.equal(await has(sel),0,'onglet inactif construit : '+sel);
   const domSummary=await page.locator('#host-tabpanel *').count();
   // Chaque onglet : ses sections, et l'avertissement de validité reste visible.
   const expect={incidents:['Incidents de ce serveur','Supervision de ce serveur','Chronologie unifiée'],
    storage:['Stockage de ce serveur'],performance:['Tendances sur 7 jours','Mesures API Proxmox de ce serveur','Processus les plus consommateurs'],
    services:['Services et traitements de ce serveur'],network:['Réseau et accès SSH'],backup:['Sauvegardes observées'],security:['Sécurité observable'],
    audit:['Audit SSH enregistré','Audit détaillé','20 derniers audits — résumés','Données API de ce serveur','Informations documentaires','Rattachements de ce serveur']};
   const seen=new Map();
   for(const [tab,headings] of Object.entries(expect)){
    await page.locator(tab==='audit'?'#host-tab-audit':'.host-tabs [data-tab="'+tab+'"]').click();
    // Depuis e748b59, alertes brutes par source et constats SSH sont repliés sous les incidents du journal.
    if(tab==='incidents'){
     assert.equal(await page.locator('#host-tabpanel .server-monitoring').evaluate(d=>d.open),false,'alertes brutes repliées par défaut');
     await page.locator('#host-tabpanel .server-monitoring > summary').click();
     await page.locator('#host-tabpanel .host-findings > summary').getByText(/^Constats de l’audit SSH et commandes à copier \(\d+\)$/).waitFor();
    }
    for(const h of headings)await page.locator('#host-tabpanel').getByRole('heading',{name:h,exact:true}).first().waitFor();
    if(tab==='audit')assert.equal(await page.locator('#host-tab-audit').getAttribute('aria-expanded'),'true');
    else assert.equal(await page.locator('[role=tab][aria-selected=true]').getAttribute('data-tab'),tab);
    assert.equal(await page.getByRole('heading',{name:'Dernière tentative SSH en échec'}).count(),1,'avertissement présent une fois sur '+tab);
    assert.equal(await has('.v2-source-matrix'),0,'rapprochement des sources rendu hors Synthèse');
    for(const h of await page.locator('#host-tabpanel h2').allInnerTexts())seen.set(h,(seen.get(h)||0)+1);
   }
   assert.deepEqual([...seen].filter(([,n])=>n>1),[],'section rendue dans deux onglets');
   assert.equal(obsRequests,1,'historique chargé une seule fois pour Incidents et Performances');
   // Onglet Applications : relevé affiché, données serveur échappées, filtre conservé.
   await page.locator('.host-tabs [data-tab="services"]').click();
   await page.locator('[data-workload-view="applications"]').click();
   assert.equal(await page.locator('.host-applications tr[data-app-text]').count(),3);
   assert.equal(await page.locator('.host-applications img').count(),0,'nom de conteneur échappé');
   assert.match(await page.locator('.host-applications').innerText(),/22, 443, 8080/);
   // Sites web : lien seulement pour une URL http(s) valide, DNS interne / en ligne, application liée.
   const links=await page.$$eval('.host-applications .host-sites a',as=>as.map(a=>[a.getAttribute('href'),a.rel,a.target]));
   assert.deepEqual(links,[['https://app.exemple.local/','noopener noreferrer','_blank']],'aucun lien javascript:');
   const sitesText=await page.locator('.host-applications .host-sites').innerText();
   // Enregistrements publiés vers ce serveur par le WAF : port, application, lien vers le WAF.
   await page.locator('[data-workload-view="published"]').click();
   const published=await page.locator('.host-published').innerText();
   assert.match(published,/portail\.exemple\.ma/);assert.match(published,/3000/);assert.match(published,/Conteneur Docker portail/);
   assert.match(sitesText,/DNS interne/);assert.match(sitesText,/En ligne \(IP publique\)/);assert.match(sitesText,/Conteneur Docker web/);
   await page.locator('[data-workload-view="applications"]').click();
   await page.locator('#host-apps-search').fill('nginx');
   assert.equal(await page.locator('.host-applications tr[data-app-text]:not([hidden])').count(),1);
   await page.evaluate(()=>render());
   assert.equal(await page.locator('.host-applications tr[data-app-text]:not([hidden])').count(),1,'filtre conservé après rafraîchissement');
   await page.locator('#host-apps-search').fill('');
   await page.locator('#host-apps-category').selectOption('Conteneur');
   assert.equal(await page.locator('.host-applications tr[data-app-text]:not([hidden])').count(),1);
   await page.locator('#host-apps-category').selectOption('');
   await page.locator('[data-workload-view="published"]').click();
   await page.locator('.host-published [data-host="new01"]').click();
   await page.waitForFunction(()=>selected==='new01');
   await page.evaluate(()=>openHost('web01'));await page.locator('.host-tabs').waitFor();
   await page.locator('.host-tabs [data-tab="services"]').click();
   assert.ok(domSummary<2000,'Synthèse légère ('+domSummary+' nœuds)');
   // Clavier : flèches, Début, Fin ; le focus suit l'onglet activé.
   await page.locator('.host-tabs [data-tab="security"]').focus();
   await page.keyboard.press('ArrowRight');
   assert.equal(await page.evaluate(()=>[detailTab,document.activeElement?.dataset.tab]).then(v=>v.join()),'summary,summary','flèche droite en boucle');
   await page.keyboard.press('End');
   assert.equal(await page.evaluate(()=>document.activeElement?.dataset.tab),'security');
   await page.keyboard.press('ArrowLeft');
   assert.equal(await page.evaluate(()=>detailTab),'backup');
   // Ancienne clé : redirigée vers son nouvel onglet.
   await page.evaluate(()=>{detailTab='observability';render()});
   assert.equal(await page.locator('[role=tab][aria-selected=true]').getAttribute('data-tab'),'performance');
   // Lien « Tous les incidents » de la Synthèse.
   await page.locator('.host-tabs [data-tab="summary"]').click();
   await page.locator('[data-goto-tab="incidents"]').click();
   assert.equal(await page.evaluate(()=>detailTab),'incidents');
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth-document.documentElement.clientWidth);
   assert.ok(overflow<=1,'pas de défilement horizontal ('+overflow+' px)');
   await page.locator('.host-tabs [data-tab="summary"]').click();
   await page.screenshot({path:path.join(__dirname,'data','v2-captures','lot4-fiche-'+(mobile?'mobile':'desktop')+'.png'),fullPage:true});
   // Serveur jamais audité : aucune valeur inventée, absence expliquée.
   await page.evaluate(()=>openHost('new01'));
   await page.locator('.v2-host-gauges').waitFor();
   assert.equal(await page.locator('.v2-host-gauges .sev-none').count(),3);
   assert.match(await page.locator('.v2-host-priorities').innerText(),/Audit SSH ancien ou absent : ce n’est pas une preuve de bon état/);
   await page.locator('.host-tabs [data-tab="services"]').click();
   await page.locator('[data-workload-view="applications"]').click();
   assert.match(await page.locator('#host-tabpanel').innerText(),/Relevé pas encore effectué/,'jamais « aucune application » sans relevé');
   await page.locator('.host-tabs [data-tab="summary"]').click();
   assert.equal(await page.locator('[data-tab="incidents"] .tab-count').count(),0);
   assert.deepEqual(posts,[],'aucune écriture');
   assert.deepEqual(errors,[]);
   await page.close();
  }
  console.log('PASS: fiche serveur — 8 onglets visibles, applications relevées et échappées, onglet actif seul construit, sans perte ni doublon, clavier, alias, jamais audité sans valeur inventée, mobile');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
