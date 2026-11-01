// Audit FE-02/FE-04 : délais du client API, erreurs réseau traduites, signal non partagé,
// démarrage en mode dégradé si un module manque. Données simulées, aucune instance réelle.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1280,height:900}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{constructor(){super();}close(){}};});
  let hits=0;
  await page.route('http://infraops.test/**',async route=>{
   const u=new URL(route.request().url());
   if(u.pathname==='/api/hang')return;                       // jamais de réponse
   if(u.pathname==='/api/down')return route.abort('connectionrefused');
   if(u.pathname==='/api/count'){hits++;await new Promise(r=>setTimeout(r,150));return route.fulfill({json:{n:hits}});}
   if(u.pathname==='/api/overview')return route.fulfill({json:{hosts:[],job:{running:false},monitoring:{interval:0}}});
   if(u.pathname.startsWith('/api/'))return route.fulfill({json:[]});
   if(u.pathname==='/waf-apache.js')return route.fulfill({status:404,body:'absent'});   // module manquant
   const file=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://infraops.test/');
  // FE-04 : un module absent n'empêche pas le démarrage, et l'écart reste affiché.
  await page.waitForFunction(()=>typeof startApplication==='function'&&document.getElementById('frontend-degraded'));
  assert.match(await page.locator('#frontend-degraded').innerText(),/waf-apache\.js/);
  assert(await page.locator('#nav [data-page]').count()>5,'navigation construite malgré le module manquant');

  const result=await page.evaluate(async()=>{
   const m=await import('/frontend-utils.js');
   m.TIMEOUTS.GET=300;
   const out={};
   try{await m.api('/api/hang')}catch(e){out.hang=e.message}
   try{await m.api('/api/down')}catch(e){out.down=e.message}
   // Deux appels identiques sans signal : partagés ; avec signal : jamais partagés.
   await Promise.all([m.api('/api/count'),m.api('/api/count')]);
   out.shared=(await m.api('/api/count')).n;
   const controller=new AbortController();
   const own=m.api('/api/count',{signal:controller.signal});
   const plain=m.api('/api/count');
   controller.abort();
   try{await own}catch(e){out.aborted=e.name}
   out.plain=(await plain).n>0;
   return out;
  });
  assert.match(result.hang,/Délai dépassé/);
  assert.match(result.down,/Serveur OpsControl injoignable/);
  assert.equal(result.shared,2,'deux appels simultanés identiques = une seule requête');
  assert.equal(result.aborted,'AbortError');
  assert.equal(result.plain,true,'l’annulation d’un appel signé n’annule pas l’appel partagé');
  // Audit FE-07 : chaque dialogue ouvert porte un nom accessible (son titre, sinon un nom fixe).
  const names=await page.evaluate(async()=>{
   const out={};
   hostAccessDialog.innerHTML='<h2>Empreintes SSH à confirmer</h2>';hostAccessDialog.showModal();
   await new Promise(r=>setTimeout(r,0));out.titled=hostAccessDialog.getAttribute('aria-label');hostAccessDialog.close();
   alertAckDialog.innerHTML='<p>sans titre</p>';alertAckDialog.showModal();
   await new Promise(r=>setTimeout(r,0));out.fixed=alertAckDialog.getAttribute('aria-label');alertAckDialog.close();
   return out;
  });
  assert.equal(names.titled,'Empreintes SSH à confirmer');
  assert.equal(names.fixed,'Prise en charge d’une alerte');
  assert.deepEqual(errors,[]);
  console.log('PASS: API timeout, translated network errors, signal never shared, degraded start with banner, named dialogs');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
