// Page « WAF / HA » : matrice de dégradation, accessibilité (axe-core), contraste des états et
// navigation au clavier seul. Données simulées, aucune requête réelle.
// Captures par onglet × thème × largeur : OPS_WAF_CAPTURES=1 (data/waf-captures, hors Git).
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const AXE=path.join(__dirname,'data/browser-test/node_modules/axe-core/axe.min.js');
if(!fs.existsSync(AXE))throw new Error('axe-core introuvable : npm install --prefix data/browser-test axe-core@4.10.2');

const at=new Date().toISOString(),ERR='Commande refusée ou indisponible (code 1)';
const sections=()=>({
 services:{status:'observed',data:[{name:'apache2',LoadState:'loaded',ActiveState:'active',SubState:'running'}]},
 apache_modules:{status:'observed',data:{security_module_loaded:true,modules:['security2_module']}},
 vhosts:{status:'observed',data:{declarations:['*:443 shop.example.test']}},
 engine:{status:'observed',data:{declarations:[{file:'/etc/modsecurity/modsecurity.conf',line:7,mode:'On'}]}},
 certificates:{status:'observed',data:{certificates:[]}},
 fail2ban:{status:'observed',data:{currently_banned:5,total_banned:412,currently_failed:3,total_failed:1287,banned_ips:['198.51.100.4']}},
 bantimes:{status:'observed',data:{bans:{}}},
 ignoreip:{status:'observed',data:{addresses:['192.0.2.1'],scope:'Exceptions IP'}},
 maxretry:{status:'observed',data:5},findtime:{status:'observed',data:600},bantime:{status:'observed',data:604800},
 tcp:{status:'observed',data:{summary:'TCP: 20 (estab 6)'}},
 sockets:{status:'observed',data:{close_wait_total:4,close_wait_outbound:3,close_wait_inbound:1,states:{ESTAB:6,'CLOSE-WAIT':4},total:20,by_upstream:[['192.0.2.20:8080',2]],process_visible:true,by_process:[['apache2',4]],by_pid:[['apache2:2101',2]],samples:[]}},
 conntrack:{status:'observed',data:100},conntrack_max:{status:'observed',data:262144},
 iptables:{status:'observed',data:{packets:12,rules:1}},
 traffic:{status:'observed',data:{requests:500,errors_5xx_pct:0.4,http_codes:{200:498,503:2},top_urls:[['/',300]],top_ips:[['198.51.100.7',120]],scope:{partial:false,unreadable:[],files_discovered:2,file_limit:96},window_seconds:[60,3600]}},
 modsecurity:{status:'observed',data:{alert_lines:4,anomaly_max:10,rules:[['949110',1]],clients:[['198.51.100.4',1]],events:[],scope:{partial:false,unreadable:[]}}}});
// Panneaux (titre h2) alimentés par chaque section de la sonde WAF, et compteur de synthèse associé.
const PANELS={services:['Protection et services'],apache_modules:['Protection et services'],certificates:['Certificats SSL/TLS'],
 fail2ban:['Politique Fail2ban'],ignoreip:['Liste blanche Fail2ban'],maxretry:['Politique Fail2ban'],findtime:['Politique Fail2ban'],bantime:['Politique Fail2ban'],
 tcp:['Réseau L3/L4'],sockets:['Connexions TCP'],conntrack:['Réseau L3/L4'],conntrack_max:['Réseau L3/L4'],iptables:['Réseau L3/L4'],
 traffic:['Distribution HTTP','Chemins les plus demandés','Adresses observées'],modsecurity:['Règles ModSecurity','Événements ModSecurity']};
const KPI={fail2ban:'IPs bannies',traffic:'Requêtes échantillonnées',modsecurity:'Lignes d’alerte ModSecurity'};
const host=(over={})=>({key:'waf1',name:'WAF principal',ip:'192.0.2.10',role:'WAF ModSecurity',status:'ok',stale:false,collected_at:at,services:[],checks:[],findings:[],history:[],
 waf:{collected_at:at,duration_ms:900,coverage:{measured:18,total:18},analysis:[],certificates:[],sections:sections(),apache:{sections:{}},apache_health:null,...over}});

(async()=>{
 const browser=await chromium.launch(launchOptions);
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}};window.__copied=[];Object.defineProperty(navigator,'clipboard',{value:{writeText:async t=>{window.__copied.push(t)}}})});
  await page.route('http://audit.test/**',route=>{
   const url=new URL(route.request().url());let data;
   if(url.pathname==='/axe.min.js')return route.fulfill({body:fs.readFileSync(AXE),contentType:'text/javascript'});
   if(url.pathname==='/api/overview')data={hosts:[host()],job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/whoami')data={role:'admin',mode:'local',authenticated:false,can_admin:true,can_operate:true};
   else if(url.pathname==='/api/hosts/waf1')data=host();
   else if(url.pathname==='/api/waf/waf1/bans')data={rows:[],summary:{listed:0,incoherent:0,verify:0,keep:0,campaigns:[]},coverage:{activity_known:true,ban_times:true},collected_at:at};
   else if(url.pathname==='/api/waf/waf1/apache-history')data={samples:[]};
   else if(url.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://audit.test/');
  await page.waitForFunction(()=>typeof navigate==='function'&&typeof wafEnhanceTables==='function'&&state.hosts.length>0);
  await page.evaluate(()=>navigate('WAF / HA'));
  await page.locator('.waf-workspace').waitFor();
  // Affiche une variante de collecte sans requête : même chemin de rendu que la page réelle.
  const show=h=>page.evaluate(h=>{state.hosts=[h];wafKey=h.key;wafDetails.set(h.key,h);render()},h);
  const panelText=title=>page.evaluate(t=>[...document.querySelectorAll('#content section.panel')].filter(p=>p.querySelector('h2')?.textContent.trim().startsWith(t)).map(p=>p.textContent).join('\n'),title);

  // 1. Matrice de dégradation des 18 sections de la sonde WAF : absente ou en échec.
  const names=await page.evaluate(()=>wafNames);
  for(const key of Object.keys(sections())){
   for(const mode of ['absent','error']){
    const h=host();
    if(mode==='absent')delete h.waf.sections[key];else h.waf.sections[key]={status:'unknown',error:ERR};
    await show(h);
    const label=key+' '+mode,cover=await panelText('Déclarations et couverture');
    if(mode==='absent')assert.match(await page.locator('.waf-missing').textContent(),new RegExp(names[key].replace(/[.*+?^${}()|[\]\\]/g,'\\$&')),label);
    else assert.match(cover,new RegExp('Inconnu\\s+'+names[key].replace(/[.*+?^${}()|[\]\\]/g,'\\$&')),label);
    for(const title of PANELS[key]||[]){
     const text=await panelText(title);
     assert.ok(text,label+' : panneau « '+title+' » présent');
     assert.match(text,mode==='absent'?/Non collecté|Non mesuré/:/Non mesuré/,label+' : '+title);
     assert.match(text,/Actualiser le WAF/,label+' : marche à suivre dans '+title);
     if(mode==='error')assert.ok(text.includes(ERR),label+' : raison affichée dans '+title);
     assert.doesNotMatch(text,/Dans les seuils/,label+' : '+title);
    }
    if(KPI[key])assert.match(await page.locator('.waf-stats').textContent(),new RegExp(KPI[key]+'Non mesuré'),label+' : compteur');
   }
  }
  // Sections Apache absentes ou en échec : chaque bloc dit « Non mesuré » et pourquoi.
  const APX={status:'Santé Apache',config:'Santé Apache',saturation:'Santé Apache',backends:'Santé des backends proxy',access:'Requêtes lentes'};
  for(const [key,title] of Object.entries(APX)){
   for(const mode of ['absent','error']){
    const h=host({apache:{sections:mode==='absent'?{}:{[key]:{status:'unknown',error:ERR}}}});
    await show(h);
    const text=await panelText(title);
    assert.match(text,/Non mesuré/,key+' '+mode);
    assert.ok(text.includes(mode==='absent'?'Non collecté par cette version de la sonde':ERR),key+' '+mode+' : raison');
    assert.equal(await page.locator('#content .apx-pill.lvl-ok').count(),0,key+' '+mode+' : aucune pastille OK sans mesure');
   }
  }
  // Évaluation incomplète : le diagnostic liste les mesures manquantes, sans pastille OK.
  await show(host({apache_health:{overall:'unknown',evaluated_at:at,summary:['Slow-request analysis N/A (access logs without %D).'],diagnostics:[],workers:{},close_wait:{thresholds:[200,300,1000]},
   cards:[{key:'workers',title:'APACHE WORKERS',value:'24 / 1000',level:'ok',note:''},{key:'slow',title:'SLOW REQUEST AVG',value:'N/A',level:'unknown',note:''}],errors:{access:'Journaux sans %D'}}}));
  assert.match(await panelText('Diagnostic Apache'),/Non mesuré : access \(Journaux sans %D\)/);
  // Échantillons partiels et sortie ss tronquée : « Partiel », jamais un compte présenté comme complet.
  const partial=host();
  partial.waf.sections.traffic.data.scope={partial:true,unreadable:['/var/log/apache2/a-access_log','/var/log/apache2/b-access_log'],files_discovered:120,file_limit:96};
  partial.waf.sections.modsecurity.data.scope={partial:true,unreadable:['/var/log/apache2/a-error_log']};
  Object.assign(partial.waf.sections.sockets.data,{truncated:true,lines_limit:200000});
  await show(partial);
  assert.match(await panelText('Distribution HTTP'),/Partiel[\s\S]*2 journal\(aux\) illisible\(s\), 120 découverts pour 96 lus/);
  assert.match(await panelText('Règles ModSecurity'),/Partiel/);
  assert.match(await panelText('Connexions TCP'),/Partiel[\s\S]*tronquée/);
  // Petit échantillon : pourcentage de 5xx déclaré non concluant.
  const small=host();Object.assign(small.waf.sections.traffic.data,{requests:2,errors_5xx_pct:50});
  await show(small);
  assert.match(await page.locator('.waf-stats').textContent(),/Échantillon trop faible : non concluant/);
  // Refus ModSecurity des journaux de vhost (E11) : total, répartition par journal, couverture partielle.
  const saturation={window_seconds:1800,counts:{AH00484:0,AH10159:0,AH03490:0},last:{},coverage_complete:true,scope:'Fenêtre : 30 dernières minutes.',
   modsecurity_denied:4,modsecurity_main_denied:1,modsecurity_vhosts:{by_file:[['/var/log/apache2/shop.example.test-error_log',2],['/var/log/apache2/api.example.test-error_log',1]],
    files_discovered:68,files_read:2,files_limit:96,unreadable:['/var/log/apache2/old.example.test-error_log'],not_read:[],partial:[],complete:false}};
  await show(host({apache:{sections:{saturation:{status:'observed',data:saturation}}}}));
  const satText=await panelText('Santé Apache');
  assert.match(satText,/Refus ModSecurity sur 30 min : 4, dont 1 dans error\.log principal\. 2 journal\(aux\) de vhost lu\(s\) sur 68/);
  assert.match(satText,/Partiel[\s\S]*1 illisible\(s\) : décompte minimal/);
  assert.match(satText,/shop\.example\.test-error_log\s*2/);
  // Collecte ancienne de la sonde : la section n'existe pas encore, la page le dit.
  delete saturation.modsecurity_vhosts;
  await show(host({apache:{sections:{saturation:{status:'observed',data:saturation}}}}));
  assert.match(await panelText('Santé Apache'),/Refus ModSecurity des vhosts : non collectés par cette version de la sonde/);
  // Collecte ancienne : aucun état « OK » affiché comme actuel.
  await show({...host({apache_health:{overall:'ok',evaluated_at:at,summary:['Apache healthy.'],diagnostics:[],workers:{},errors:{},close_wait:{thresholds:[200,300,1000]},
   cards:[{key:'workers',title:'APACHE WORKERS',value:'24 / 1000',level:'ok',note:''}]}}),stale:true});
  assert.equal(await page.locator('#content .apx-pill.lvl-ok').count(),0,'pastille OK sur collecte ancienne');
  assert.match(await panelText('Diagnostic Apache'),/Ancien · OK/);
  assert.ok(await page.locator('.waf-stale-banner').isVisible());

  // 2. axe-core (WCAG 2.1 A/AA) sur chaque onglet, thèmes clair et sombre.
  await show(host());
  await page.addScriptTag({url:'/axe.min.js'});
  const tabs=await page.locator('[data-waf-tab-button]').evaluateAll(b=>b.map(x=>x.dataset.wafTabButton));
  const violations=[];
  for(const theme of ['light','dark']){
   await page.evaluate(t=>{document.documentElement.dataset.theme=t;render()},theme);
   for(const tab of tabs){
    await page.locator('[data-waf-tab-button="'+tab+'"]').click();
    const found=await page.evaluate(async()=>(await axe.run('#content',{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21a','wcag21aa']}})).violations
     .filter(v=>['serious','critical'].includes(v.impact)).map(v=>v.id+' ('+v.nodes.length+') '+v.nodes.slice(0,2).map(n=>n.target.join(' ')).join(' | ')));
    violations.push(...found.map(v=>theme+'/'+tab+' : '+v));
   }
  }
  assert.deepEqual(violations,[],'axe-core : violations sérieuses ou critiques');

  // 3. Contraste mesuré des pastilles d'état (texte sur fond effectif), deux thèmes, seuil AA 4,5:1.
  const sample=host({apache_health:{overall:'orange',evaluated_at:at,summary:[],diagnostics:[],workers:{},errors:{},close_wait:{thresholds:[200,300,1000]},
   cards:['ok','yellow','orange','red','critical','unknown','info'].map(level=>({key:level,title:level.toUpperCase(),value:'1',level,note:''}))}});
  sample.waf.sections.services.data.push({name:'fail2ban',LoadState:'loaded',ActiveState:'failed',SubState:'failed'});
  sample.waf.analysis=[{severity:'critical',title:'Critique',evidence:'x'},{severity:'warning',title:'Avertissement',evidence:'x'},{severity:'unknown',title:'Inconnu',evidence:'x'}];
  const report=[];
  for(const theme of ['light','dark'])for(const stale of [false,true]){
   await page.evaluate(t=>{document.documentElement.dataset.theme=t},theme);
   await show({...sample,stale});
   // Toutes les pastilles : constats dépliés, chaque onglet affiché tour à tour.
   for(const tab of tabs){
   await page.evaluate(t=>{wafTab=t;wafShowTab();document.querySelectorAll('#content details').forEach(d=>{d.open=true})},tab);
   const ratios=await page.evaluate(()=>{
    const parse=c=>{const m=c.match(/rgba?\(([^)]+)\)/);if(m){const p=m[1].split(/[ ,/]+/).filter(Boolean).map(Number);return [p[0],p[1],p[2],p[3]??1]}
     const s=c.match(/color\(srgb ([^)]+)\)/);if(s){const p=s[1].split(/[ /]+/).filter(Boolean).map(Number);return [p[0]*255,p[1]*255,p[2]*255,p[3]??1]}return [0,0,0,0]};
    const over=(top,bottom)=>[0,1,2].map(i=>top[i]*top[3]+bottom[i]*(1-top[3])).concat(1);
    const background=el=>{const layers=[];for(let n=el;n;n=n.parentElement){const c=parse(getComputedStyle(n).backgroundColor);if(c[3]>0)layers.push(c);if(c[3]>=1)break}
     return layers.reverse().reduce((acc,c)=>over(c,acc),parse(getComputedStyle(document.body).backgroundColor))};
    const lum=c=>{const [r,g,b]=c.slice(0,3).map(v=>{v/=255;return v<=.03928?v/12.92:((v+.055)/1.055)**2.4});return .2126*r+.7152*g+.0722*b};
    return [...document.querySelectorAll('#content .badge, #content .apx-pill, #content .waf-stale-badge')].filter(el=>el.getClientRects().length).map(el=>{
     const bg=background(el),fg=over(parse(getComputedStyle(el).color),bg),a=lum(fg),b=lum(bg);
     return {cls:el.className,text:el.textContent.trim(),ratio:Math.round(((Math.max(a,b)+.05)/(Math.min(a,b)+.05))*100)/100}});
   });
   for(const r of ratios){const k=r.cls+' « '+r.text+' »',prev=report.find(x=>x.theme===theme&&x.badge===k);if(!prev)report.push({theme,badge:k,ratio:r.ratio});else prev.ratio=Math.min(prev.ratio,r.ratio)}
   }
  }
  const weak=report.filter(r=>r.ratio<4.5);
  console.log('Contraste des pastilles (min par pastille) :\n'+report.map(r=>'  '+r.theme+' '+r.ratio+' '+r.badge).join('\n'));
  assert.deepEqual(weak,[],'contraste < 4,5:1');

  // 4. Clavier seul : onglets (flèches), filtre, tri, copie d'une commande.
  await page.evaluate(()=>{document.documentElement.dataset.theme='dark'});
  const big=host();big.waf.sections.traffic.data.top_urls=Array.from({length:12},(_,i)=>['/page-'+i,i+1]);
  await show(big);
  await page.evaluate(()=>{wafTab='summary';wafShowTab();document.activeElement?.blur();window.scrollTo(0,0)});
  const active=()=>page.evaluate(()=>{const a=document.activeElement;return a?(a.dataset.wafTabButton?'tab:'+a.dataset.wafTabButton:a.dataset.wafFilter!=null?'filter':a.dataset.wafSort!=null?'sort':a.dataset.copy!=null?'copy':a.tagName):''});
  const tabUntil=async(want,max=200)=>{for(let i=0;i<max;i++){await page.keyboard.press('Tab');if((await active()).startsWith(want))return true}return false};
  assert.ok(await tabUntil('tab:'),'onglets atteignables au clavier');
  await page.keyboard.press('ArrowRight');await page.keyboard.press('ArrowRight');
  assert.equal(await active(),'tab:traffic');
  assert.equal(await page.locator('#waf-panel-traffic').isVisible(),true);
  assert.ok(await tabUntil('filter'),'filtre atteignable au clavier');
  await page.keyboard.type('page-1');
  const urlPanel=page.locator('section.panel',{has:page.locator('h2',{hasText:'Chemins les plus demandés'})});
  assert.equal(await urlPanel.locator('tbody tr:not([hidden])').count(),3,'page-1, page-10, page-11');
  assert.ok(await tabUntil('sort'),'tri atteignable au clavier');
  await page.keyboard.press('Enter');
  assert.equal(await urlPanel.locator('th[aria-sort=descending]').count(),1);
  await page.evaluate(()=>{document.querySelector('[data-waf-tab-button="traffic"]').focus()});
  for(let i=0;i<3;i++)await page.keyboard.press('ArrowRight');
  assert.equal(await active(),'tab:network');
  assert.ok(await tabUntil('copy'),'copie atteignable au clavier');
  await page.keyboard.press('Enter');
  await page.locator('#waf-panel-network button.is-copied').waitFor();
  assert.equal((await page.evaluate(()=>window.__copied)).length,1);

  // 5. Captures par onglet, thème et largeur (preuve visuelle, à la demande).
  if(process.env.OPS_WAF_CAPTURES){
   const dir=path.join(__dirname,'data','waf-captures');fs.mkdirSync(dir,{recursive:true});
   for(const theme of ['light','dark'])for(const width of [1440,768,390]){
    await page.setViewportSize({width,height:width===390?844:1000});
    await page.evaluate(t=>{document.documentElement.dataset.theme=t;render()},theme);
    for(const tab of tabs){await page.evaluate(t=>{wafTab=t;wafShowTab()},tab);await page.screenshot({path:path.join(dir,theme+'-'+width+'-'+tab+'.png'),fullPage:true})}
   }
   console.log('Captures : '+dir);
  }
  assert.deepEqual(errors,[],'aucune erreur console');
  console.log('test_ui_waf_audit : OK');
 } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exit(1)});
