// Parcours serveur → preuves → validation → dossier → prévisualisation → ticket, simulé.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),posts=[],errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}};sessionStorage.setItem('opscontrol.briefing.dismissed','1');});
  const now=new Date().toISOString();
  const host={key:'web01',name:'Serveur Web',ip:'192.0.2.10',registered:true,active_scope:true,status:'critical',stale:false,collected_at:now,
   services:[],findings:[],checks:[],history:[],coverage:{measured:10,total:15},alerts:{items:[],counts:{}},environment:'PROD'};
  const vuln={id:'a'.repeat(20),host_key:'web01',host_name:host.name,cve:'CVE-2026-1234',package:'openssl',installed:'3.0.1',fixed:'3.0.2',
   confidence:'à vérifier',status:'open',sources:['debian'],severity:'critical',cvss:9.8,kev:true,last_seen:now,first_seen:now,
   evidence:{source:'Avis Debian',reason:'Version à vérifier <img src=x onerror=alert(1)>',binaries:['openssl']},description:'Preuve de test <script>alert(1)</script>'};
  let fail=false,viewer=false;
  const dossier={id:'case-test',origin:'vulnerability',origin_id:vuln.id,kind:'Ticket',reference:'OC-TEST',owner:'Opérateur',owner_auth:'local',
   taken_at:now,status:'pending',snapshot:{title:vuln.cve,source:'Debian',severity:'critical',state:'Validée'},events:[]};
  await page.route('http://console-security.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());
   if(req.method()==='POST'){
    const body=req.postDataJSON();posts.push({path:url.pathname,body});
    if(url.pathname==='/api/security/vulns/action'){assert.equal(body.action,'validate');vuln.status='validated';return route.fulfill({json:vuln});}
    if(url.pathname==='/api/itsm/take'){dossier.origin=body.origin;return route.fulfill({json:dossier});}
    if(url.pathname==='/api/itsm/preview')return route.fulfill({json:{preview_hash:'test-preview',observer_id:7,payload:{name:'Incident CVE',content:'<p>Serveur Web — CVE-2026-1234</p>',entities_id:0,_users_id_requester:1}}});
    if(url.pathname==='/api/itsm/create'){assert.equal(body.confirmed,true);assert.equal(body.preview_hash,'test-preview');dossier.status='linked';dossier.remote_id=123;dossier.url='https://glpi.example.test/ticket/123';return route.fulfill({json:dossier});}
    return route.fulfill({status:403,json:{detail:'Action non simulée'}});
   }
   if(url.pathname==='/api/whoami')return route.fulfill({json:{mode:'local',role:viewer?'viewer':'admin',can_admin:!viewer,can_operate:!viewer,authenticated:false,user:null}});
   if(url.pathname==='/api/overview')return route.fulfill({json:{hosts:[host],counts:{critical:1},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
   if(url.pathname==='/api/hosts/web01')return route.fulfill({json:host});
   if(url.pathname==='/api/hosts/web01/observability')return route.fulfill({json:{samples:0,points:[],changes:[],trends:{}}});
   if(url.pathname==='/api/incidents')return route.fulfill({json:{items:[],total:0,counts:{}}});
   if(url.pathname==='/api/security/vulns')return route.fulfill(fail?{status:503,json:{detail:'Source locale indisponible'}}:{json:{items:[vuln],total:1,offset:0,limit:10}});
   if(url.pathname==='/api/security/vulns/'+vuln.id)return route.fulfill({json:vuln});
   if(url.pathname==='/api/security/notifications')return route.fulfill({json:{items:[{id:17,level:'critical',title:'CVE potentielle sur PHP',detail:'Applicabilité à vérifier <img src=x>',at:now,hosts:[{key:'web01'}]}]}});
   if(url.pathname==='/api/itsm/status')return route.fulfill({json:{available:true,protocol:1,configured:true}});
   if(url.pathname==='/api/itsm/detail')return route.fulfill({json:dossier});
   if(url.pathname==='/api/itsm/links')return route.fulfill({json:{items:[]}});
   if(url.pathname==='/api/v2/cockpit')return route.fulfill({json:{sources:[],counts:{}}});
   if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'"}});
  });
  await page.goto('http://console-security.test/#/serveur/web01');
  const briefing=page.getByRole('button',{name:'Fermer le bilan'});
  if(await briefing.isVisible())await briefing.click();
  await page.locator('[data-tab="incidents"]').click();
  await page.locator('.host-security [data-host-sec-review]').waitFor();
  assert.equal(posts.length,0,'ouvrir les incidents ne déclenche aucune écriture');
  await page.getByRole('button',{name:'Préparer un ticket de vérification'}).click();
  await page.locator('#itsm-take [type=submit]:not([disabled])').waitFor();
  await page.locator('#itsm-take [name=by]').fill('Opérateur');
  await page.locator('#itsm-take [type=submit]').click();
  assert.equal(posts.length,0,'signal potentiel : qualification humaine requise');
  await page.locator('#itsm-take [name=qualification]').fill('Vérifier les versions PHP et les correctifs rétroportés.');
  await page.locator('#itsm-take [type=submit]').click();
  await page.locator('[data-itsm-preview]').waitFor();
  assert.equal(posts[0].body.origin,'security_alert');
  assert.equal(posts[0].body.host_key,'web01');
  await page.locator('[data-itsm-close]').click();
  posts.length=0;
  await page.locator('[data-host-sec-review]').click();
  const form=page.locator('#host-sec-review-form');
  await form.waitFor();
  await form.getByRole('button',{name:'Valider et préparer le ticket'}).waitFor();
  assert.equal(await form.locator('script,img').count(),0,'les preuves HTML restent du texte');
  await form.getByRole('button',{name:'Valider et préparer le ticket'}).click();
  assert.equal(posts.length,0,'aucune validation sans vérification humaine');
  await form.locator('[name=verified]').check();
  await form.locator('[name=by]').fill('Opérateur');
  await form.locator('[name=note]').fill('Applicabilité vérifiée sur le paquet installé.');
  await form.getByRole('button',{name:'Valider et préparer le ticket'}).dblclick();
  await page.locator('#itsm-take [type=submit]:not([disabled])').waitFor();
  assert.equal(posts.length,1,'une seule validation ; aucun ticket créé automatiquement');
  assert.equal(posts[0].body.id,vuln.id);
  await page.locator('#itsm-take [type=submit]').click();
  await page.locator('[data-itsm-preview]').click();
  assert.equal(posts.filter(p=>p.path==='/api/itsm/create').length,0,'prévisualiser ne crée pas de ticket');
  await page.locator('[data-itsm-create]').click();
  await page.getByRole('link',{name:'Ouvrir dans GLPI #123'}).waitFor();
  assert.equal(posts.find(p=>p.path==='/api/itsm/take').body.origin,'vulnerability');
  assert.equal(posts.filter(p=>p.path==='/api/itsm/create').length,1);
  await page.locator('[data-itsm-close]').click();
  await page.setViewportSize({width:390,height:844});
  await page.locator('[data-host-sec-review]').click();
  await form.getByRole('button',{name:'Préparer / consulter le ticket GLPI'}).waitFor();
  assert.ok(await page.locator('#host-security-dialog').evaluate(el=>el.scrollWidth<=el.clientWidth+1));
  await page.locator('[data-host-sec-close]').click();
  fail=true;
  await page.locator('[data-host-sec-refresh]').click();
  await page.locator('.host-security [role=alert]').waitFor();
  assert.equal(await page.locator('.host-security [data-host-sec-review]').count(),1,'la dernière preuve reste visible sur erreur');
  // Un lecteur voit les preuves, mais ne peut pas lancer la préparation du ticket.
  viewer=true;fail=false;
  await page.reload();
  if(await briefing.isVisible())await briefing.click();
  await page.locator('[data-tab="incidents"]').click();
  await page.locator('[data-host-sec-review]').click();
  await form.getByText('La préparation du ticket est réservée aux administrateurs.').waitFor();
  assert.equal(await form.locator('[type=submit]').count(),0);
  assert.deepEqual(errors,[]);
  console.log('PASS: incidents serveur, preuves sécurité, validation, prévisualisation GLPI, double clic, lecture seule et mobile');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
