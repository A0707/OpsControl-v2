// Centre d'incidents : fixture synthétique, aucune requête ne quitte le navigateur.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const OUT=path.join(__dirname,'data','v2-captures');fs.mkdirSync(OUT,{recursive:true});
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900},timezoneId:'Asia/Tokyo'}),errors=[],posts=[],queries=[];
  page.on('pageerror',e=>errors.push(e.message));
  // Actions à effet (ajout, maintenance) : confirmation demandée puis acceptée (audit FE-08).
  const confirmations=[];page.on('dialog',d=>{confirmations.push(d.message());d.accept();});
  page.on('console',m=>{if(m.type()==='error'&&!/404|503/.test(m.text()))errors.push(m.text())});
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}}});
  const now=Date.now(),iso=ms=>new Date(ms).toISOString();
  const base={source:'SSH',target_key:'web01',severity_max:'critical',first_observed_at:null,reopen_count:0,chronic:false,rule:'Services',fresh:true,confirmation_blocked:false,owner:null,note:null,ack_until:null,investigation_at:null,suppressed_until:null,resolved_at:null,since_basis:'journal',maintenance:null};
  let items=[
   {...base,id:'SSH|web01|service:postfix.service',target:'web01',type:'service:postfix.service',title:'Service postfix.service en échec',state:'open',severity:'critical',opened_at:iso(now-3600000),since:iso(now-3600000),last_seen_at:iso(now-30000),observed_at:iso(now-60000),duration_seconds:3600,evidence:'postfix.service failed',link:{host_key:'web01'}},
   {...base,id:'Zabbix|db01|Disk full',source:'Zabbix',target_key:null,target:'db01.example.test',type:'Disk full',title:'Disque plein',state:'reopened',reopen_count:2,severity:'warning',severity_max:'critical',opened_at:iso(now-3600000),first_observed_at:iso(now-86400000*2),since:iso(now-86400000*2),since_basis:'source',last_seen_at:iso(now-20000),observed_at:iso(now-20000),duration_seconds:172800,evidence:'/var 97 %',link:{page:'Zabbix'},confirmation_blocked:true,confirmation_blocked_reason:'ZABBIX : Délai dépassé'},
   {...base,id:'SSH|app01|disk',target_key:'app01',target:'app01',type:'disk',title:'Disque à 91 %',state:'acknowledged',severity:'warning',opened_at:iso(now-5400000),since:iso(now-5400000),last_seen_at:iso(now-40000),observed_at:iso(now-40000),duration_seconds:5400,owner:'Operator',owner_authenticated:false,note:'purge prévue',ack_until:iso(now+86400000),link:{host_key:'app01'}}];
  const suppressed={...base,id:'Wazuh|global|agents',source:'Wazuh',target:'global',target_key:null,type:'agents',title:'Agents déconnectés',state:'suppressed',severity:'warning',opened_at:iso(now-86400000),since:iso(now-86400000),last_seen_at:iso(now),observed_at:iso(now),duration_seconds:86400,owner:'jdoe@example.test',owner_authenticated:true,note:'maintenance',suppressed_until:null,link:{page:'Wazuh'}};
  let maintenance=[],failIncidentRead=false;
  const hosts=[{key:'web01',name:'web01',ip:'192.0.2.10',registered:true,active_scope:true,status:'critical',services:[],findings:[],checks:[],coverage:{measured:10,total:15},collected_at:iso(now-60000)}];
  await page.route('http://incidents.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(req.method()==='POST'){posts.push({path:url.pathname,body:req.postDataJSON()});
    if(url.pathname==='/api/incidents/ack'){const i=items.find(x=>x.id===req.postDataJSON().id);Object.assign(i,{state:'acknowledged',owner:req.postDataJSON().by,owner_authenticated:false,ack_until:iso(now+7*86400000)});}
    if(url.pathname==='/api/incidents/investigate'){const i=items.find(x=>x.id===req.postDataJSON().id);Object.assign(i,{state:'investigating',owner:req.postDataJSON().by,owner_authenticated:false,investigation_at:iso(now),ack_until:iso(now+86400000)});}
    if(url.pathname==='/api/incidents/maintenance'){const b=req.postDataJSON(),w={...b,id:17,actor:b.by,actor_authenticated:false,created_at:iso(now),active:true};maintenance=[w];items=items.map(i=>({...i,maintenance:i.source===b.source&&i.target===b.target?w:null}));return route.fulfill({json:w});}
    if(url.pathname==='/api/incidents/maintenance/delete'){maintenance=[];items=items.map(i=>({...i,maintenance:null}));return route.fulfill({json:{id:req.postDataJSON().id,deleted:true}});}
    return route.fulfill({json:{}});}
   if(url.pathname==='/api/incidents'){queries.push(Object.fromEntries(url.searchParams));
    if(failIncidentRead)return route.fulfill({status:503,json:{detail:'Collecte temporairement indisponible'}});
    const st=url.searchParams.get('state'),q=(url.searchParams.get('q')||'').toLowerCase();
    let list=items.filter(i=>(st==='active'||st==='all'||i.state===st)&&(!q||(i.title+i.target).toLowerCase().includes(q)));
    const recency=i=>now-Date.parse(i.event_at||i.reopened_at||i.since||i.opened_at)<=86400000?'recent':'old';
    const recency_counts={recent:list.filter(i=>recency(i)==='recent').length,old:list.filter(i=>recency(i)==='old').length,unknown:0};
    const age=url.searchParams.get('age')||'all';if(age!=='all')list=list.filter(i=>recency(i)===age);
    const counts={open:0,reopened:0,acknowledged:0,investigating:0,suppressed:1,resolved:4};items.forEach(i=>counts[i.state]++);
    const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||20);
    return route.fulfill({json:{items:list.slice(offset,offset+limit),total:list.length,limit,offset,age,recency_counts,order:url.searchParams.get('order'),counts,active_by_severity:{critical:1,warning:2},sources:['SSH','Wazuh','Zabbix'],chronic_active:47,maintenance_active:maintenance.filter(w=>w.active).length,sync:{at:iso(now-5000),stats:{},error:null},policy:'Résolution seulement sur collecte complète.'}});}
   if(url.pathname==='/api/incidents/suppressions')return route.fulfill({json:{items:[suppressed]}});
   if(url.pathname==='/api/incidents/maintenance')return route.fulfill({json:{items:maintenance,active:maintenance.filter(w=>w.active).length,policy:'La maintenance réduit le bruit sans masquer les preuves.'}});
   if(url.pathname==='/api/incidents/events')return route.fulfill({json:{id:url.searchParams.get('id'),events:[{at:iso(now-1000),kind:'reopened',detail:{severity:'warning'}},{at:iso(now-3600000),kind:'resolution_blocked',detail:{reason:'ZABBIX : Délai dépassé'}},{at:iso(now-86400000*2),kind:'opened',detail:{severity:'critical'}}]}});
   if(url.pathname==='/api/overview')return route.fulfill({json:{hosts,counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
   if(url.pathname==='/api/whoami')return route.fulfill({json:{mode:'local',authenticated:false,user:null,label:'Session locale · non authentifiée'}});
   if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://incidents.test/#/Incidents');
  await page.locator('.inc-row').first().waitFor();
  assert.equal(await page.locator('#nav [data-page="Incidents"]').count(),1);
  assert.equal(await page.locator('.inc-row').count(),3);
  await page.locator('[data-inc-age=recent]').click();
  await page.waitForFunction(()=>document.querySelectorAll('.inc-row').length===2);
  assert.equal(queries.at(-1).age,'recent');
  assert.equal(await page.locator('#inc-age-recent').getAttribute('aria-pressed'),'true');
  await page.locator('[data-inc-age=old]').click();
  await page.waitForFunction(()=>document.querySelectorAll('.inc-row').length===1);
  assert.match(await page.locator('.inc-row').innerText(),/Ancien/);
  assert.match(await page.locator('.inc-row').innerText(),/Réapparu/,'ancienneté et état restent distincts');
  await page.locator('[data-inc-age=all]').click();
  await page.waitForFunction(()=>document.querySelectorAll('.inc-row').length===3);
  assert.equal(queries.at(-1).order,'recent','tri chronologique demandé au serveur avant pagination');
  assert.match(await page.locator('.inc-row .inc-when time[datetime]').first().innerText(),/\d{2}\/\d{2}\/\d{4}.*\d{2}:\d{2}:\d{2}.*UTC/);
  assert.match(await page.evaluate(()=>exactTimeMarkup('2026-10-27T09:12:34Z')),/09:12:34.*UTC/,'fuseau Casablanca explicite, même depuis un navigateur à Tokyo');
  assert.match(await page.evaluate(()=>exactTimeMarkup('2026-05-01T09:12:34Z')),/10:12:34.*UTC\+1/,'ancien décalage de Casablanca respecté selon la date');
  assert.match(await page.evaluate(()=>exactTimeMarkup('2026-03-01T09:12:34Z')),/09:12:34.*UTC/,'le décalage historique de Casablanca est respecté');
  assert.match(await page.evaluate(()=>exactTimeMarkup('<script>danger</script>')),/Date inconnue/);
  assert.match(await page.evaluate(()=>exactTimeMarkup('2026-10-27T09:12:34')),/Date inconnue/,'une preuve sans fuseau ne reçoit pas une heure inventée');
  await page.locator('#inc-order').selectOption('observed');
  await page.waitForFunction(()=>incData?.order==='observed');
  assert.equal(queries.at(-1).order,'observed');
  assert.equal(queries.at(-1).offset,'0');
  // Une dernière page devenue vide revient automatiquement à une page existante.
  await page.evaluate(async()=>{incFilters.offset=40;await loadIncidents(false)});
  assert.equal(queries.at(-1).offset,'0');
  assert.equal(await page.locator('.inc-row').count(),3);
  // Une panne de lecture conserve les preuves avec un avertissement explicite.
  failIncidentRead=true;
  await page.evaluate(()=>loadIncidents(false));
  await page.locator('#inc-feed-status').getByRole('alert').waitFor();
  assert.equal(await page.locator('.inc-row').count(),3,'dernière liste conservée en cas de panne');
  failIncidentRead=false;
  await page.evaluate(()=>loadIncidents(false));
  assert.equal(await page.locator('#inc-feed-status [role=alert]').count(),0);
  // Source en panne : la résolution impossible est visible, jamais présentée comme résolue.
  await page.getByText('Résolution impossible : ZABBIX : Délai dépassé').waitFor();
  await page.getByText('(déclaratif)').first().waitFor();
  await page.locator('#inc-suppressions').getByText('Permanente').waitFor();
  // Début déclaré par la source distingué du début du suivi.
  await page.getByText(/Début déclaré par la source/).first().waitFor();
  await page.getByText(/Premier suivi OpsControl/).first().waitFor();
  // Filtres envoyés au serveur (pagination côté serveur) et focus conservé pendant le rafraîchissement.
  await page.locator('#inc-search').fill('postfix');
  await page.waitForFunction(()=>document.querySelectorAll('.inc-row').length===1);
  assert.equal(queries.at(-1).q,'postfix');
  assert.equal(await page.locator('#inc-search').evaluate(e=>e===document.activeElement),true);
  await page.evaluate(()=>loadIncidents(false));
  await page.waitForTimeout(150);
  assert.equal(await page.locator('#inc-search').evaluate(e=>e===document.activeElement),true,'focus perdu au rafraîchissement');
  assert.equal(await page.locator('#inc-search').inputValue(),'postfix');
  await page.locator('#inc-search').fill('');
  await page.waitForFunction(()=>document.querySelectorAll('.inc-row').length===3);
  const rowReused=await page.evaluate(async()=>{const row=document.querySelector('.inc-row');row.__phase42=true;await loadIncidents(false);return row===document.querySelector('.inc-row')&&document.querySelector('.inc-row').__phase42===true});
  assert.equal(rowReused,true,'ligne incident reconstruite malgré des données inchangées');
  // Historique à la demande, conservé ouvert au rafraîchissement.
  await page.locator('[data-inc-toggle="Zabbix|db01|Disk full"]').click();
  await page.locator('.inc-timeline').getByText('Réapparition').waitFor();
  await page.evaluate(()=>loadIncidents(false));
  await page.waitForTimeout(150);
  assert.equal(await page.locator('.inc-timeline').count(),1,'détail ouvert conservé');
  await page.screenshot({path:path.join(OUT,'phase2-incidents-desktop-dark.png'),fullPage:true});
  // Prise en charge 7 jours en mode local : nom déclaratif requis.
  await page.locator('[data-inc-action="ack"][data-inc-id="SSH|web01|service:postfix.service"]').click();
  await page.locator('#incident-form select[name=duration]').selectOption('7d');
  await page.locator('#incident-form input[name=by]').fill('Operator');
  await page.locator('#incident-form input[name=note]').fill('ticket INC-42');
  await page.locator('#incident-form [type=submit]').click();
  await page.waitForFunction(()=>!document.getElementById('incident-dialog').open);
  assert.deepEqual(posts.at(-1),{path:'/api/incidents/ack',body:{id:'SSH|web01|service:postfix.service',note:'ticket INC-42',by:'Operator',duration:'7d'}});
  // L'investigation est un état explicite, attribué et limité dans le temps.
  await page.locator('[data-inc-action="investigate"][data-inc-id="SSH|web01|service:postfix.service"]').click();
  await page.locator('#incident-form input[name=note]').fill('analyse des journaux');
  await page.locator('#incident-form [type=submit]').click();
  await page.waitForFunction(()=>!document.getElementById('incident-dialog').open);
  assert.deepEqual(posts.at(-1),{path:'/api/incidents/investigate',body:{id:'SSH|web01|service:postfix.service',note:'analyse des journaux',by:'Operator',duration:'24h'}});
  await page.getByText('En investigation').first().waitFor();
  // Audit UI du 31/10 (fiche 02.2) : « Masquer » exige un motif ; rien n'est envoyé sans lui.
  const before=posts.length;
  await page.locator('[data-inc-action="suppress"]').first().click();
  await page.locator('#incident-dialog h2').filter({hasText:'Masquer'}).waitFor();
  assert.equal(await page.locator('#incident-form input[name=note]').getAttribute('required'),'');
  await page.locator('#incident-form [type=submit]').click();
  assert.equal(posts.length,before,'masquage sans motif : aucun envoi');
  await page.locator('#incident-dialog [data-inc-close]').click();
  // Vues enregistrées (fiche 02.1) : « Sans responsable » interroge le serveur avec le bon filtre.
  const unowned=page.waitForRequest(r=>r.url().includes('/api/incidents?')&&r.url().includes('owner=__none__'));
  await page.locator('#inc-view').selectOption('unowned');
  await unowned;
  await page.locator('#inc-view').selectOption('');
  // Fenêtre planifiée : visible sur l'incident, preuves conservées, puis annulation locale.
  await page.locator('[data-inc-maintenance-new]').click();
  await page.locator('#maintenance-form input[name=name]').fill('Patch production');
  await page.locator('#maintenance-form select[name=source]').selectOption('SSH');
  await page.locator('#maintenance-form input[name=target]').fill('web01');
  await page.locator('#maintenance-form input[name=note]').fill('CHG-42');
  await page.locator('#maintenance-form [type=submit]').click();
  await page.waitForFunction(()=>!document.getElementById('maintenance-dialog').open);
  assert.equal(posts.at(-1).path,'/api/incidents/maintenance');
  assert.equal(posts.at(-1).body.by,'Operator');
  assert.equal(posts.at(-1).body.target,'web01');
  await page.locator('#inc-maintenance').getByText('Patch production').waitFor();
  await page.locator('.inc-maintenance').getByText(/Maintenance · Patch production/).waitFor();
  await page.screenshot({path:path.join(OUT,'phase3-incidents-maintenance-dark.png'),fullPage:true});
  await page.locator('[data-inc-maintenance-delete="17"]').click();
  await page.waitForFunction(()=>!document.querySelector('[data-inc-maintenance-delete="17"]'));
  assert.equal(posts.at(-1).path,'/api/incidents/maintenance/delete');
  // Réactivation depuis la liste des suppressions actives.
  await page.locator('#inc-suppressions [data-inc-action="reactivate"]').click();
  await page.locator('#incident-form [type=submit]').click();
  await page.waitForFunction(()=>!document.getElementById('incident-dialog').open);
  assert.equal(posts.at(-1).path,'/api/incidents/reactivate');
  assert.equal(posts.at(-1).body.duration,undefined);
  // Cibles hors inventaire : pas de lien inventé vers une fiche.
  assert.equal(await page.locator('.inc-row [data-host="db01.example.test"]').count(),0);
  // Thème clair, mobile.
  await page.evaluate(()=>applyTheme('light'));
  await page.screenshot({path:path.join(OUT,'phase2-incidents-desktop-light.png'),fullPage:false});
  await page.evaluate(()=>applyTheme('dark'));
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'défilement horizontal mobile');
  await page.screenshot({path:path.join(OUT,'phase2-incidents-mobile-dark.png'),fullPage:true});
  // Toutes les écritures sont locales à OpsControl.
  assert.ok(posts.every(p=>p.path.startsWith('/api/incidents/')),JSON.stringify(posts));
  assert.deepEqual(errors,[]);
  console.log('PASS: incidents persistants, résolution bloquée visible, début source/suivi, filtres serveur, focus et détail conservés, ack 7 j, réactivation, thèmes, mobile');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
