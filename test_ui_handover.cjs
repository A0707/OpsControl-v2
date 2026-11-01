// Passation : fixture synthétique, aucune requête ne quitte le navigateur.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const OUT=path.join(__dirname,'data','v2-captures');fs.mkdirSync(OUT,{recursive:true});
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const context=await browser.newContext({viewport:{width:1440,height:900},acceptDownloads:true});
  const page=await context.newPage(),errors=[],queries=[],writes=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('console',m=>{if(m.type()==='error'&&!/404/.test(m.text()))errors.push(m.text())});
  await page.addInitScript(()=>{
   window.EventSource=class extends EventTarget{constructor(){super()}close(){}};
   // Presse-papiers simulé : on vérifie le texte copié sans dépendre des permissions du navigateur.
   window.__copied=[];
   Object.defineProperty(navigator,'clipboard',{value:{writeText:async t=>{window.__copied.push(t)}},configurable:true});
  });
  const now=Date.now(),iso=ms=>new Date(ms).toISOString();
  const inc={source:'SSH',target:'web01',host_key:'web01',chronic:false,owner:null,owner_authenticated:false};
  const report=hours=>({generated_at:iso(now),period:{start:iso(now-hours*3600000),end:iso(now),hours},thresholds:{unowned_hours:24,expiring_hours:12},
   counts:{new:1,resolved:1,taken:2,unowned:1,expiring:1,tickets:1,tickets_pending:1},by_actor:{Operator:1,jdoe:1},chronic_unowned:2,
   sync:{at:iso(now-30000),error:null},
   new:[{...inc,id:'N',title:'Disque plein',source:'Zabbix',target:'db01.example.test',host_key:null,severity:'warning',state:'acknowledged',at:iso(now-7200000),reopened:false}],
   resolved:[{...inc,id:'R',title:'Service postfix en échec',severity:'critical',state:'resolved',at:iso(now-3600000),reappeared:false}],
   taken:[{...inc,id:'N',title:'Disque plein',severity:'warning',state:'acknowledged',at:iso(now-3600000),action:'ack',actor:'Operator',actor_authenticated:false,duration:'24h',note:'purge prévue'},
    {...inc,id:'C',title:'Charge élevée',severity:'critical',state:'investigating',at:iso(now-72000000),action:'investigation_started',actor:'jdoe',actor_authenticated:true,duration:'24h',note:null}],
   unowned:[{...inc,id:'A',title:'Sauvegarde absente',severity:'critical',state:'open',since:iso(now-30*3600000),age_seconds:30*3600,expired_owner:null}],
   expiring:[{...inc,id:'C',title:'Charge élevée',severity:'critical',state:'investigating',owner:'jdoe',owner_authenticated:true,until:iso(now+4*3600000),note:null}],
   tickets:[{reference:'OC-1A2B3C4D',kind:'Ticket',glpi_id:1234,status:'linked',glpi_status:'2',title:'Disque plein',target:'db01',source:'Zabbix',severity:'warning',owner:'Operator',owner_authenticated:false,origin:'incident',taken_at:iso(now-7000000),created_at:iso(now-6900000)}],
   tickets_pending:[{reference:'OC-9F8E7D6C',kind:'Ticket',glpi_id:null,status:'failed',glpi_status:null,title:'Service arrêté',target:'app01',source:'SSH',severity:'critical',owner:'Operator',owner_authenticated:false,origin:'incident',taken_at:iso(now-600000),created_at:null}],
   scope:'Journal d’incidents et dossiers ITSM d’OpsControl uniquement ; aucune collecte relancée.',
   text:'Passation OpsControl — '+hours+' h\nÀ TRAITER\n• Sans responsable depuis plus de 24 h (1)'});
  const hosts=[{key:'web01',name:'web01',ip:'192.0.2.10',registered:true,active_scope:true,status:'ok',services:[],findings:[],checks:[],coverage:{measured:10,total:15},collected_at:iso(now-60000)}];
  await page.route('http://handover.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(req.method()!=='GET')writes.push(url.pathname);
   if(url.pathname==='/api/handover'){
    queries.push(Object.fromEntries(url.searchParams));
    const hours=Number(url.searchParams.get('hours'));
    if(url.searchParams.get('format')==='csv')return route.fulfill({body:'﻿rubrique;date\r\n',contentType:'text/csv; charset=utf-8',headers:{'Content-Disposition':'attachment; filename="passation-test.csv"'}});
    return route.fulfill({json:report(hours)});
   }
   if(url.pathname==='/api/overview')return route.fulfill({json:{hosts,counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
   if(url.pathname==='/api/whoami')return route.fulfill({json:{mode:'local',authenticated:false,user:null,label:'Session locale · non authentifiée'}});
   if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
  });
  await page.goto('http://handover.test/#/Passation');
  await page.locator('[data-ho-section="unowned"] tbody tr').first().waitFor();
  // Onglet du centre Incidents (menu V2 plafonné) : l'entrée Incidents reste active.
  assert.equal(await page.locator('#nav [data-page="Incidents"].active').count(),1);
  assert.equal(await page.locator('#nav [data-page="Passation"]').count(),0);
  assert.equal(await page.locator('#v2-hub-tabs [data-go="Passation"].active').count(),1);
  assert.equal(queries[0].hours,'24');
  // À traiter puis ce qui a changé ; qui fait quoi visible, nom déclaratif signalé.
  for(const key of ['unowned','expiring','tickets_pending','new','resolved','taken','tickets'])
   assert.equal(await page.locator('[data-ho-section="'+key+'"]').count(),1,key);
  await page.locator('[data-ho-section="taken"]').getByText('(déclaratif)').first().waitFor();
  await page.locator('[data-ho-section="tickets"]').getByText('1234').waitFor();
  await page.getByText('2 anomalie(s) chronique(s)').waitFor();
  await page.getByText('Operator 1 · jdoe 1').waitFor();
  await page.screenshot({path:path.join(OUT,'handover-desktop-dark.png'),fullPage:true});
  // Copier le texte : le texte construit par le serveur, tel quel.
  await page.locator('[data-ho-copy]').click();
  await page.waitForFunction(()=>window.__copied.length===1);
  assert.match(await page.evaluate(()=>window.__copied[0]),/^Passation OpsControl — 24 h/);
  // Changement de période : nouvelle lecture serveur.
  await page.locator('#ho-hours').selectOption('8');
  await page.waitForFunction(()=>document.querySelector('#ho-text')?.textContent.includes('— 8 h'));
  assert.equal(queries.at(-1).hours,'8');
  // Export CSV : fichier produit par le serveur pour la période choisie.
  const [download]=await Promise.all([page.waitForEvent('download'),page.locator('[data-ho-csv]').click()]);
  assert.equal(download.suggestedFilename(),'passation-test.csv');
  assert.deepEqual(queries.at(-1),{hours:'8',format:'csv'});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(OUT,'handover-mobile-dark.png'),fullPage:true});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),true,'défilement horizontal en mobile');
  // Lecture seule : aucune écriture envoyée.
  assert.deepEqual(writes,[]);
  assert.deepEqual(errors,[]);
  console.log('PASS: passation (onglet du centre Incidents, à traiter / ce qui a changé, qui fait quoi, copie du texte, période, export CSV, mobile, lecture seule)');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
