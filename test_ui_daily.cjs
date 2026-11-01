const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 const now=new Date().toISOString();
 const host={key:'web',name:'Serveur web',ip:'192.0.2.10',registered:true,active_scope:true,status:'unknown',services:[],checks:[],findings:[],batches:[],audit_recorded:true,coverage:{measured:12,total:16}};
 const jobs=Array.from({length:61},(_,i)=>({id:String(i),name:i===0?'<script>secret</script>':'Traitement '+i,kind:i%2?'cron':'systemd',script:i===0?'/opt/<script>secret</script>':'/opt/job-'+i+'.sh',source:'/etc/cron.d/application',host_key:'web',host_name:'Serveur web',state:i%2?'scheduled':'failed',fresh:true,schedule:'15 2 * * *',timezone:'Africa/Casablanca',last_run:null,next_run:null,collected_at:now,owner:'app',evidence:'Résultat non mesuré'}));
 host.batches=jobs;
 // Référentiel des batchs (batch-catalog.js) : un conforme, un écart, un échec, un hors inventaire.
 const fiche=(id,nom,state,extra)=>({id,nom,responsable:'Équipe',langage:'',serveur:'192.0.2.10',host_key:'web',host_name:'Serveur web',collected_at:now,scripts:['/var/batch/'+id+'/run.sh'],script_present:true,script_mtime:1700000000,properties:'',envoi_mail:'',observed_schedules:[{schedule:'30 2 * * *',owner:'root'}],horaire:'02:30',planning:'Concordant',expected_times:'02:30',running:[],last_result:null,outcome:null,log:null,statut:'En prod',attendu:'actif',validation:'Oui',mise_en_production:'',migration:'',criticite:null,commentaire:'',state,findings:[],...extra});
 const catalog={available:true,source:'batch_catalog.yaml',counts:{total:4,failed:1,drift:1,ok:1,unknown:1,stopped:0,unverifiable:1},
  entries:[fiche('batch_ok','Import factures','ok'),fiche('batch_drift','<img src=x onerror=alert(1)>','drift',{planning:'Différent',findings:[{level:'warning',text:'Horaire observé 03:00 ≠ attendu 02:30'}]}),
   fiche('batch_ko','Export banque','failed',{last_result:{state:'failed',rc:2,finished_at:1700000000,duration_s:12},outcome:{source:'Enveloppe (fin de sortie d’erreur)',verdict:'failed',at:1700000000,started_at:1699999988,finished_at:1700000000,rc:2,duration:12,reason:'Code retour 2 — ERROR SFTP refusé',lines:['INFO début','ERROR <img src=x onerror=alert(2)> password=***']},log:{path:'/var/batch/batch_ko/log/run.log',mtime:1700000000,why:'Journal au nom du script',strength:null,readable:true},findings:[{level:'critical',text:'Dernier passage en échec (code 2)'}]}),
   fiche('swarm','Revue de presse','unknown',{serveur:'SWARM',host_key:null,host_name:'SWARM',scripts:[],script_present:null,observed_schedules:[],planning:'Non mesuré',findings:[{level:'info',text:'Hors inventaire SSH (SWARM) : rapprochement impossible'}]})],
  unreferenced:[{name:'nouveau.sh',script:'/var/batch/batch_nouveau/nouveau.sh',kind:'cron',schedule:'0 4 * * *',owner:'root',host_key:'web',host_name:'Serveur web'}],
  servers:[{name:'Serveur web',collected_at:now,crontabs_read:['root'],files_checked:true}]};
 const daily={generated_at:now,counts:{inventory:84,registered:50,online:48,audit_recorded:15,audit_missing:69,critical_recent:3,api_fresh:4,api_total:5},policy:'Audits conservés et sources actualisées.',priorities:[{host_key:'web',host_name:'Serveur web',title:'Disque à 94 %',severity:'critical',collected_at:now,stale:false},{host_key:'web',host_name:'Serveur web',title:'Ancienne alerte à confirmer',severity:'warning',collected_at:now,stale:true}],sources:[{name:'Cluster Proxmox',provider:'Proxmox',fresh:true,collected_at:now},{name:'Elastic logs',provider:'Elasticsearch',fresh:true,collected_at:now,indicators:{cluster_status:'yellow',unassigned_shards:950}},{name:'Wazuh manager',provider:'Wazuh',fresh:true,collected_at:now},{name:'Zabbix',provider:'Zabbix',fresh:true,collected_at:now},{name:'Bacula',provider:'Bacula',fresh:false,collected_at:now,error:'Tunnel indisponible'}],attention:[{key:'web',name:'Serveur web',ip:'192.0.2.10',issues:['Clé SSH non vérifiée']}],batches:{counts:{running:2,scheduled:30},fresh_failures:4,fresh_hosts:15,hosts_total:84}};
 await page.route('http://infraops.test/**',async route=>{
  const url=new URL(route.request().url());let data;
  if(url.pathname==='/api/overview')data={hosts:[host],job:{running:false},monitoring:{interval:300},jobs:{ssh:{running:false},batch:{running:false}}};
  else if(url.pathname==='/api/daily')data=daily;
  else if(url.pathname==='/api/batches')data={jobs,coverage:[{host_key:'web',name:'Serveur web',ip:'192.0.2.10',fresh:true,limitations:['Autres comptes non audités']},{host_key:'empty',name:'Serveur non collecté',ip:'192.0.2.20',fresh:false,limitations:['Inventaire non collecté']}],job:{running:false},catalog};
  else if(url.pathname==='/api/hosts/web')data=host;
  else if(url.pathname.startsWith('/api/'))data=[];
  if(data!==undefined)return route.fulfill({json:data});
  const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
  return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
 });
 await page.goto('http://infraops.test/');
 await page.locator('.v2-home-journal > summary').click();
 await page.getByRole('heading',{name:'Priorités du jour'}).waitFor();
 await page.getByText('Preuve ancienne',{exact:true}).waitFor();
 await page.screenshot({path:'data/daily-preview.png',fullPage:true});
 await page.locator('#nav [data-page="Batch / Planification"]').click();
 await page.locator('#batch-results tbody tr').first().waitFor();
 // Ouverture sur le référentiel : échecs puis écarts en tête, filtres de l'inventaire masqués.
 assert.equal(await page.locator('#batch-results tbody tr').count(),4);
 assert.equal(await page.locator('#batch-results tbody tr').first().getAttribute('data-batch-entry'),'batch_ko');
 assert.equal(await page.locator('#batch-kind').isVisible(),false);
 assert.equal(await page.locator('#batch-results img').count(),0);
 const ko=page.locator('[data-batch-entry="batch_ko"]');
 assert.ok((await ko.locator('.batch-cause').textContent()).includes('ERROR SFTP refusé'));
 await ko.getByText('Pourquoi',{exact:true}).click();
 assert.ok((await ko.locator('.batch-lines').textContent()).includes('<img src=x onerror=alert(2)>'));
 assert.ok((await page.locator('#batch-summary').textContent()).includes('Résultat mesuré'));
 assert.ok((await page.locator('#batch-summary').textContent()).includes('Planification non vérifiable'));
 await page.locator('#batch-search').fill('banque');
 assert.equal(await page.locator('#batch-results tbody tr').count(),1);
 await page.locator('#batch-search').fill('');
 await page.locator('[data-batch-view="runs"]').click();
 const run=page.locator('[data-batch-run="batch_ko"]');
 assert.equal(await page.locator('#batch-results tbody tr').first().getAttribute('data-batch-run'),'batch_ko');
 assert.ok((await run.textContent()).includes('Incident ouvert'));
 assert.ok((await run.textContent()).includes('12 s'));
 assert.equal(await page.locator('[data-batch-run="batch_ok"] .badge').first().textContent(),'Non mesuré');
 await page.locator('[data-batch-view="gaps"]').click();
 assert.equal(await page.locator('#batch-results tbody tr').count(),2);
 await page.locator('[data-batch-view="unreferenced"]').click();
 assert.ok((await page.locator('#batch-results').textContent()).includes('/var/batch/batch_nouveau/nouveau.sh'));
 await page.locator('[data-batch-view="jobs"]').click();
 assert.equal(await page.locator('#batch-kind').isVisible(),true);
 assert.equal(await page.locator('#batch-results tbody tr').count(),50);
 await page.locator('[data-batch-view="coverage"]').click();
 assert.equal(await page.locator('#batch-servers tbody tr').count(),2);
 await page.locator('[data-batch-view="jobs"]').click();
 await page.locator('#batch-host').selectOption('empty');
 assert.equal(await page.locator('#batch-results tbody tr').count(),0);
 await page.locator('[data-batch-view="coverage"]').click();
 await page.locator('#batch-servers [data-batch-host="web"]').click();
 assert.equal(await page.locator('#batch-host').inputValue(),'web');
 assert.equal(await page.locator('#batch-results tbody tr').count(),50);
 assert.equal(await page.locator('#batch-results script').count(),0);
 assert.ok((await page.locator('#batch-results').textContent()).includes('Script : /opt/<script>secret</script>'));
 await page.getByRole('button',{name:'Suivant',exact:true}).click();
 assert.equal(await page.locator('#batch-results tbody tr').count(),11);
 await page.locator('#batch-kind').selectOption('cron');
 assert.equal(await page.locator('#batch-results tbody tr').count(),30);
 await page.locator('#batch-search').fill('Traitement 1');
 assert.equal(await page.locator('#batch-results tbody tr').count(),6);
 assert.equal(await page.locator('#batch-search').evaluate(e=>e===document.activeElement),true);
 await page.evaluate(()=>loadBatches());
 assert.equal(await page.locator('#batch-search').inputValue(),'Traitement 1');
 assert.equal(await page.locator('#batch-search').evaluate(e=>e===document.activeElement),true);
 await page.locator('#batch-kind').selectOption('');
 await page.locator('#batch-search').fill('/opt/job-60.sh');
 assert.equal(await page.locator('#batch-results tbody tr').count(),1);
 await page.locator('#batch-results tbody [data-host="web"]').click();
 await page.locator('.host-tabs [data-tab="services"]').click();
 await page.locator('.workload-nav [data-workload-view="batches"]').click();
 const tasks=page.locator('section').filter({has:page.getByRole('heading',{name:'Tâches de ce serveur',exact:true})});
 assert.equal(await tasks.locator('tbody tr').count(),50);
 await page.locator('[data-workload-page="1"]').click();
 assert.equal(await tasks.locator('tbody tr').count(),11);
 assert.equal(await tasks.locator('script').count(),0);
 await page.screenshot({path:'data/batch-preview.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 await page.locator('#mobile-nav').selectOption('Vue globale');
 await page.locator('.v2-home-journal > summary').click();
 await page.getByRole('heading',{name:'Priorités du jour'}).waitFor();
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 await page.keyboard.press('Tab');
 assert.notEqual(await page.evaluate(()=>document.activeElement.tagName),'BODY');
 assert.deepEqual(errors,[]);
 console.log('PASS: daily summary, old evidence, escaped batch names, pagination, filters, stable focus, mobile and keyboard');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
