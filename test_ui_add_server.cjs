// Parcours complet d'ajout d'un serveur (audit lot 7), sur données simulées : création,
// persistance et présence dans Serveurs après rechargement, conflit d'identifiant, erreur
// de saisie sous le champ, double clic, port hérité du profil SSH, collecte en cours.
// Aucun contact avec le parc : toutes les requêtes sont servies par page.route.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],posts=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
  // Inventaire simulé côté « serveur » : survit aux rechargements de la page.
  const inventory=[{key:'web01',name:'Web 01',ip:'192.0.2.10',role:'Web',environment:'PROD',services:[],admin_enrolled_at:'2026-10-01T00:00:00Z'}];
  let collecting=false,revision=1,failSave=false;
  const profile={profile:{users:['audit'],ports:[3300]}};
  const effective=h=>({...profile,users:h.user?[h.user]:['audit'],user_origin:h.user?'serveur':'profil',ports:h.port?[h.port]:[3300],port_origin:h.port?'serveur':'profil'});
  const row=h=>({...h,status:'unknown',registered:Boolean(h.admin_enrolled_at),collected_at:null,findings:[],checks:[],issues:['Audit initial requis']});
  await page.route('http://add-server.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());let data;
   if(req.method()==='POST'&&url.pathname==='/api/manage/hosts'){
    const body=req.postDataJSON();posts.push(body);
    await new Promise(r=>setTimeout(r,150));  // laisse le temps d'un second clic
    if(failSave)return route.fulfill({status:503,json:{detail:'Indisponibilité simulée : réessayer'}});
    if(!/^\d+\.\d+\.\d+\.\d+$/.test(body.ip))return route.fulfill({status:422,json:{detail:[{type:'value_error',loc:['body','ip'],msg:'Value error, Adresse IP attendue (IPv4 ou IPv6) ; un nom DNS n’est pas accepté dans ce champ'}]}});
    const prior=inventory.find(h=>h.key===body.key);
    if(body.mode==='create'&&prior)return route.fulfill({status:409,json:{detail:'Identifiant « '+body.key+' » déjà utilisé par '+prior.name+' ('+prior.ip+').'}});
    if(body.mode==='update'&&body.revision!=='r'+revision)return route.fulfill({status:409,json:{detail:'Configuration modifiée entre-temps'}});
    const {mode,revision:_r,...fields}=body,item={...prior,...fields};
    if(item.port==null)delete item.port;if(!item.user)delete item.user;
    if(!prior){item.admin_enrolled_at='2026-10-25T10:00:00Z';inventory.push(item)}else inventory[inventory.indexOf(prior)]=item;
    revision++;
    return route.fulfill({json:{...item,saved:true,applies:collecting?'next_batch':'now',sync_pending:false,
     message:collecting?'Configuration enregistrée. Collecte en cours avec les paramètres précédents : les nouveaux s’appliquent au prochain lot.':'Configuration enregistrée.'}});
   }
   if(url.pathname==='/api/manage/ssh-profile')data={effective:effective({}),collecting};
   else if(url.pathname.startsWith('/api/manage/hosts/')){
    const h=inventory.find(h=>h.key===decodeURIComponent(url.pathname.split('/')[4]));
    data={host:h,revision:'r'+revision,effective:effective(h),collecting};
   }
   else if(url.pathname==='/api/overview')data={hosts:inventory.map(row),job:{running:collecting},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/whoami')data={role:'admin',mode:'local',can_admin:true,can_operate:true};
   else if(url.pathname==='/api/ssh/host-keys')data={hosts:[]};
   else if(url.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  const toasts=[];
  await page.exposeFunction('recordToast',t=>toasts.push(t));
  // Observateur réinstallé à chaque chargement : le test recharge la page.
  await page.addInitScript(()=>document.addEventListener('DOMContentLoaded',()=>new MutationObserver(()=>{const t=document.querySelector('#toast')?.textContent;if(t)recordToast(t)}).observe(document.querySelector('#toast'),{childList:true,characterData:true,subtree:true})));
  await page.goto('http://add-server.test/');
  await page.waitForFunction(()=>state?.hosts?.length===1);
  await page.locator('#nav [data-page="Serveurs"]').first().click();
  await page.locator('[data-add-server]').click();
  const form=page.locator('#server-form');
  await form.waitFor();
  const step=async index=>{await form.locator('[data-server-step="'+index+'"]').click()};
  const review=()=>step(3);
  assert.match(await form.locator('[name=key]').inputValue(),/^srv-[0-9a-f]{16}$/);
  assert.equal(await form.getByRole('button',{name:'Ajouter ce serveur'}).isVisible(),false);
  // Brouillon partiel conservé dans l'onglet, puis repris après rechargement : zéro POST.
  await form.locator('[name=name]').fill('Brouillon <img src=x onerror=alert(1)>');
  await form.locator('[name=ip]').fill('192.0.2.20');
  const draftKey=await form.locator('[name=key]').inputValue();
  await form.getByRole('button',{name:'Garder le brouillon',exact:true}).click();
  assert.equal(posts.length,0);
  await page.reload();
  await page.waitForFunction(()=>state?.hosts?.length===1);
  await page.locator('#nav [data-page="Serveurs"]').first().click();
  await page.locator('[data-add-server]').click();
  await form.getByRole('button',{name:'Reprendre le brouillon',exact:true}).click();
  assert.equal(await form.locator('[name=key]').inputValue(),draftKey);
  assert.equal(await form.locator('[name=name]').inputValue(),'Brouillon <img src=x onerror=alert(1)>');
  await form.locator('[name=name]').press('Enter');
  await form.locator('[data-step="1"]').waitFor({state:'visible'});
  assert.equal(posts.length,0,'Entrée avance dans l’assistant sans enregistrer');
  // Port hérité par défaut, valeur effective et origine affichées.
  assert.equal(await form.locator('[name=port_mode]').inputValue(),'inherit');
  assert.equal(await form.locator('[name=port]').isDisabled(),true);
  await page.getByText('port : 3300 (profil SSH)').waitFor();
  await review();
  assert.equal(await form.locator('#server-review img').count(),0);
  assert.ok((await form.locator('#server-review').textContent()).includes('<img src=x onerror=alert(1)>'));
  await step(0);

  // 1. Nom DNS dans le champ IP : erreur sous le champ, saisie conservée.
  await form.locator('[name=key]').fill('app02');
  await form.locator('[name=name]').fill('Application 02');
  await form.locator('[name=ip]').fill('app02.example.test');
  await review();
  assert.equal(await form.locator('#server-review img').count(),0);
  await form.getByRole('button',{name:'Ajouter ce serveur'}).click();
  await form.locator('#error-ip').waitFor();
  assert.match(await form.locator('#error-ip').textContent(),/nom DNS/);
  assert.equal(await form.locator('[name=ip]').getAttribute('aria-invalid'),'true');
  assert.equal(await form.locator('[name=name]').inputValue(),'Application 02');
  assert.doesNotMatch(await form.locator('.form-error').textContent(),/[{[]"/,'pas de JSON brut');

  // 2. Correction (espaces retirés) et double clic : une seule requête, un seul serveur.
  await form.locator('[name=ip]').fill(' 192.0.2.20 ');
  await review();
  posts.length=0;
  await form.getByRole('button',{name:'Ajouter ce serveur'}).dblclick();
  await page.waitForFunction(()=>!document.querySelector('#management-dialog').open);
  assert.equal(posts.length,1,'double clic : une seule requête');
  assert.deepEqual({ip:posts[0].ip,mode:posts[0].mode,port:posts[0].port},{ip:'192.0.2.20',mode:'create',port:null});
  assert.equal(inventory.filter(h=>h.key==='app02').length,1);
  assert.equal(await page.evaluate(()=>sessionStorage.getItem(SERVER_DRAFT)),null,'brouillon effacé après succès');
  assert.equal('port' in inventory.find(h=>h.key==='app02'),false,'port hérité, pas de 22 imposé');

  // 3. Présent dans Serveurs, avant et après rechargement, avec son état explicite.
  await page.locator('#content').getByText('Application 02').first().waitFor();
  await page.reload();
  await page.waitForFunction(()=>state?.hosts?.length===2);
  await page.locator('#nav [data-page="Serveurs"]').first().click();
  await page.locator('#content').getByText('Application 02').first().waitFor();
  assert.equal(await page.evaluate(()=>onlineHosts().some(h=>h.key==='app02')),true);
  await page.locator('#content').getByText('Première collecte en attente').first().waitFor();

  // 4. Identifiant déjà utilisé en création : conflit lisible, aucun écrasement.
  await page.locator('[data-add-server]').click();
  await form.waitFor();
  await form.locator('[name=key]').fill('web01');
  await form.locator('[name=name]').fill('Autre');
  await form.locator('[name=ip]').fill('192.0.2.30');
  await review();
  await form.getByRole('button',{name:'Ajouter ce serveur'}).click();
  await form.getByText('déjà utilisé par Web 01').waitFor();
  assert.equal(inventory.find(h=>h.key==='web01').name,'Web 01');
  await form.getByRole('button',{name:'Ouvrir le serveur existant'}).click();
  await page.getByRole('heading',{name:'Modifier Web 01'}).waitFor();

  // 5. Modification pendant une collecte : acceptée, port hérité préservé, message clair.
  collecting=true;
  await page.locator('#management-dialog [data-close]').click();
  await page.evaluate(()=>openServer('web01'));
  await page.getByText('Collecte en cours : l’enregistrement reste possible').waitFor();
  await form.locator('[name=name]').fill('Web 01 renommé');
  await review();
  await form.getByRole('button',{name:'Enregistrer les modifications'}).click();
  await page.waitForFunction(()=>!document.querySelector('#management-dialog').open);
  const update=posts.at(-1);
  assert.deepEqual({mode:update.mode,port:update.port,revision:Boolean(update.revision)},{mode:'update',port:null,revision:true});
  await page.waitForFunction(()=>/prochain lot/.test(document.querySelector('#toast')?.textContent||''),null,{timeout:5000}).catch(()=>{});
  assert.ok(toasts.some(t=>/prochain lot/.test(t)),'message « prochain lot » affiché');
  assert.equal('port' in inventory.find(h=>h.key==='web01'),false);

  // 6. Port spécifique choisi explicitement : envoyé tel quel.
  await page.evaluate(()=>openServer('web01'));
  await step(1);
  await form.locator('[name=port_mode]').selectOption('custom');
  await form.locator('[name=port]').fill('2222');
  await page.getByText('port : 2222 (serveur)').waitFor();
  await review();
  await form.getByRole('button',{name:'Enregistrer les modifications'}).click();
  await page.waitForFunction(()=>!document.querySelector('#management-dialog').open);
  assert.equal(posts.at(-1).port,2222);

  // 7. Erreur serveur : récapitulatif et saisie conservés, nouvelle tentative explicite.
  await page.evaluate(()=>openServer('web01'));
  await form.locator('[name=name]').fill('Web 01 après reprise');
  await review();failSave=true;
  await form.getByRole('button',{name:'Enregistrer les modifications'}).click();
  await form.locator('.form-error').getByText('Indisponibilité simulée : réessayer',{exact:false}).waitFor();
  assert.equal(await form.locator('[name=name]').inputValue(),'Web 01 après reprise');
  assert.equal(await form.locator('[data-step="3"]').isVisible(),true);
  failSave=false;
  await form.getByRole('button',{name:'Enregistrer les modifications'}).click();
  await page.waitForFunction(()=>!document.querySelector('#management-dialog').open);
  assert.equal(inventory.find(h=>h.key==='web01').name,'Web 01 après reprise');
  // 8. Petit écran : pas de débordement du dialogue ou des panneaux de récapitulatif.
  await page.setViewportSize({width:390,height:844});
  await page.evaluate(()=>openServer('web01'));
  await review();
  assert.equal(await page.locator('#management-dialog').evaluate(e=>e.scrollWidth<=e.clientWidth+2),true);
  assert.deepEqual(errors,[]);
  console.log('PASS: guided add flow — draft, keyboard, review, field error, double click, inherited port, persistence, conflicts, save during collection, retry and mobile');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
