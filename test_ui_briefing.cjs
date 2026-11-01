const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
// Bilan à l'ouverture : affiché à la première consultation, mis à jour pendant le contrôle de
// démarrage, non répété dans la même session, réouvrable, et discret quand tout est sain.
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const start=Date.now(),iso=ms=>new Date(ms).toISOString();
  const critique={key:'critical',title:'Incidents critiques en cours',severity:'critical',count:1,page:'Alertes',note:null,
   items:[{id:'Zabbix:pg:critical',source:'Zabbix',title:'PostgreSQL service not running',detail:'pg01',count:1,observed_at:iso(start-8000),host_key:'pg01'}]};
  const aveugle={key:'blind',title:'Angles morts de la détection',severity:'unverified',count:1,page:'Sources',note:null,
   items:[{title:'Source Bacula périmée',detail:'Dernière lecture trop ancienne : ses alertes sont à reconfirmer.',page:'Sources'}]};
  const bilan=(level,checking,sections)=>({generated_at:iso(start),level,checking,startup:{status:checking?'running':'done'},
   headline:{critical:'Problème critique en cours : intervention immédiate',ok:'Aucun problème critique : sources récentes et collecte saine'}[level],
   sections,counts:{critical:sections.some(s=>s.key==='critical')?1:0,reconfirm:0,acknowledged:1,maintenance:0,chronic:3},
   scope:'Bilan relu dans les collectes enregistrées.'});
  async function open(state){
   const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],posts=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.clock.install({time:new Date(start)});
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super();setTimeout(()=>this.dispatchEvent(new Event('ready')),0)}close(){}}});
   await page.route('http://infraops.test/**',async route=>{
    const u=new URL(route.request().url());let data;
    if(route.request().method()==='POST'){posts.push(u.pathname);return route.fulfill({status:202,json:{api:{running:true}}});}
    if(u.pathname==='/api/briefing')data=state.briefing;
    else if(u.pathname==='/api/overview')data={hosts:[],job:{running:false},monitoring:{interval:60}};
    else if(u.pathname==='/api/alerts')data={alerts:[],generated_at:iso(start),counts:{},levels:[],policy:[],sources:[]};
    else if(u.pathname.startsWith('/api/'))data=[];
    if(data!==undefined)return route.fulfill({json:data});
    const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
    return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
   });
   await page.goto('http://infraops.test/');
   return {page,errors,posts};
  }

  const state={briefing:bilan('critical',true,[critique,aveugle])};
  const {page,errors,posts}=await open(state);
  const dialog=page.locator('#briefing-dialog');
  await dialog.getByRole('heading',{name:'Bilan à l’ouverture'}).waitFor();
  const texte=await dialog.innerText();
  assert.match(texte,/Problème critique en cours/);
  assert.match(texte,/PostgreSQL service not running/);
  assert.match(texte,/Contrôle de démarrage en cours/);
  assert.match(texte,/Source Bacula périmée/);
  assert.match(texte,/1 critique\(s\) prise\(s\) en charge/);
  // Fin du contrôle de démarrage : le bilan se met à jour sans action.
  state.briefing=bilan('critical',false,[critique]);
  await page.clock.fastForward(4500);
  await page.waitForFunction(()=>!document.querySelector('#briefing-dialog .briefing-checking'));
  assert.doesNotMatch(await dialog.innerText(),/Source Bacula périmée/);
  await dialog.getByRole('button',{name:'Revérifier maintenant'}).click();
  await page.waitForFunction(()=>document.querySelector('#briefing-dialog .briefing-checking'));
  assert.deepEqual(posts,['/api/availability/refresh']);
  await page.setViewportSize({width:390,height:844});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');
  await page.screenshot({path:'data/briefing-mobile-verified.png'});
  await page.setViewportSize({width:1440,height:1000});
  await page.screenshot({path:'data/briefing-verified.png'});
  await dialog.getByRole('button',{name:'J’ai pris connaissance'}).click();
  assert(!(await page.evaluate(()=>document.getElementById('briefing-dialog').open)));
  // Même session : pas de nouvelle interruption au rechargement ; réouverture à la demande.
  await page.reload();
  await page.locator('[data-briefing-open]').waitFor();
  await page.clock.fastForward(1000);
  assert(!(await page.evaluate(()=>document.getElementById('briefing-dialog').open)),'shown twice in one session');
  await page.locator('[data-briefing-open]').click();
  await dialog.getByRole('heading',{name:'Bilan à l’ouverture'}).waitFor();
  await dialog.getByRole('button',{name:'Fiche ↗'}).waitFor();
  assert.deepEqual(errors,[]);
  await page.close();

  // Nouvelle session, tout est sain : un simple message, aucune fenêtre bloquante.
  const sain=await open({briefing:bilan('ok',false,[])});
  await sain.page.waitForFunction(()=>/Bilan : Aucun problème critique/.test(document.getElementById('toast')?.textContent||''));
  assert(!(await sain.page.evaluate(()=>document.getElementById('briefing-dialog').open)));
  assert.deepEqual(sain.errors,[]);
  console.log('PASS: briefing on opening, startup check refresh, recheck, once per session, reopen, mobile, healthy toast');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
