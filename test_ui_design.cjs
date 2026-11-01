// Lot 6 : garde-fous de design. Sur les pages principales, bureau et mobile, thèmes sombre et
// clair : texte ≥ 12 px, cibles ≥ 24 px (bureau) et ≥ 44 px (mobile), contraste WCAG AA,
// aucun défilement horizontal, icônes légères, mouvement réduit respecté. Fixture synthétique.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const now=new Date().toISOString();
const host={key:'web01',name:'web01',ip:'192.0.2.10',registered:true,active_scope:true,status:'warning',cpu:41,ram:63,disk_max:88,environment:'PROD',role:'Web',
 services:[],findings:[{id:'d',severity:'warning',title:'Disque /var à 88 %',domain:'stockage',evidence:'df',commands:{}}],checks:[],history:[],coverage:{measured:12,total:15},collected_at:now,
 alerts:{counts:{total:1},items:[{id:'z',source:'Zabbix',severity:'critical',title:'Charge élevée',observed_at:now,fresh:true}]},source_details:[],network_evidence:{fresh:true,ping:true,collected_at:now}};
const incident={id:'SSH|web01|disk',source:'SSH',type:'disk',title:'Disque /var à 88 %',state:'open',severity:'warning',severity_max:'warning',opened_at:now,since:now,observed_at:now,last_seen_at:now,duration_seconds:3600,link:{host_key:'web01'},target:'web01'};
const health={generated_at:now,ready:true,not_ready_reasons:[],opscontrol:{uptime_seconds:60,database:{status:'ok',journal_mode:'wal'},database_size:{bytes:1},scheduler:{healthy:true,last:now},sse:{clients:0,total_since_start:0},tunnel:{}},
 collectors:[],jobs:{},errors:[],scope:'x',sources:[{key:'z',name:'Zabbix',provider:'Zabbix',reachable:true,last_success:now,fresh:true,credentials_loaded:true}],
 freshness:{hosts:1,ssh_fresh:1,ssh_measured:1,network_fresh:1,api_fresh:1,api_total:1,budget_seconds:900}};
const PAGES=['Vue globale','Serveurs','Incidents','Alertes','Sources','fiche'];
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  for(const theme of ['dark','light'])for(const viewport of [{width:1440,height:900},{width:390,height:844}]){
   const mobile=viewport.width<500,page=await browser.newPage({viewport,reducedMotion:'reduce'}),errors=[],assets=[];
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(t=>{window.EventSource=class extends EventTarget{constructor(){super()}close(){}};try{localStorage.setItem('infraops-theme',t)}catch{}},theme);
   await page.route('http://design.test/**',async route=>{
    const url=new URL(route.request().url());
    if(url.pathname.startsWith('/assets/'))assets.push(url.pathname);
    const json=j=>route.fulfill({json:j});
    if(url.pathname==='/api/overview')return json({hosts:[host],counts:{},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}});
    if(url.pathname==='/api/hosts/web01')return json(host);
    if(url.pathname==='/api/incidents')return json({items:[incident],total:1,counts:{open:1},active_by_severity:{warning:1},sources:['SSH'],sync:{at:now},policy:'Politique.'});
    if(url.pathname==='/api/incidents/suppressions')return json({items:[]});
    if(url.pathname==='/api/incidents/maintenance')return json({items:[],active:0});
    if(url.pathname==='/api/alerts')return json({alerts:[{id:'a',source:'SSH',severity:'critical',title:'Service en échec',fresh:true,observed_at:now,count:1,targets:[{name:'web01',host_key:'web01'}]}],counts:{critical:1,warning:0,preventive:0,info:0,info_stale:0},levels:[{key:'critical',label:'Critique',delay:'Immédiat'}],policy:[],sources:[],scope:'x'});
    if(url.pathname==='/api/self-monitoring')return json(health);
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
    const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
    if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
    return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'"}});
   });
   await page.goto('http://design.test/');
   await page.waitForFunction(()=>typeof state!=='undefined'&&state);
   assert.equal(await page.locator('html').getAttribute('data-theme'),theme);
   for(const name of PAGES){
    if(name==='fiche'){await page.evaluate(()=>openHost('web01'));await page.locator('.host-tabs').waitFor();}
    else{await page.evaluate(p=>{selected=null;hostDetail=null;navigate(p)},name);await page.waitForTimeout(600);}
    const where=theme+' '+(mobile?'mobile':'bureau')+' '+name;
    const r=await page.evaluate(min=>{
     const parse=c=>{const m=c.match(/rgba?\(([^)]+)\)/);if(!m)return null;const v=m[1].split(/[ ,\/]+/).filter(Boolean).map(Number);return {r:v[0],g:v[1],b:v[2],a:v.length>3?v[3]:1}};
     const lum=c=>{const f=x=>{x/=255;return x<=0.03928?x/12.92:((x+0.055)/1.055)**2.4};return 0.2126*f(c.r)+0.7152*f(c.g)+0.0722*f(c.b)};
     const bgOf=e=>{const st=[];for(let n=e;n;n=n.parentElement){const c=parse(getComputedStyle(n).backgroundColor);if(c&&c.a>0){st.push(c);if(c.a>=1)break}}let o={r:255,g:255,b:255};for(const c of st.reverse())o={r:c.r*c.a+o.r*(1-c.a),g:c.g*c.a+o.g*(1-c.a),b:c.b*c.a+o.b*(1-c.a)};return o};
     const small=[],contrast=[],targets=[];
     for(const e of document.querySelectorAll('main *, aside *')){
      if(!e.getClientRects().length)continue;const cs=getComputedStyle(e);
      if(e.matches('button,select,input:not([type=checkbox]):not([type=radio]),summary,[role=tab]')&&!e.closest('[hidden],.skip')){
       const b=e.getBoundingClientRect();if(b.height<min-0.5)targets.push(Math.round(b.height)+'px '+e.tagName.toLowerCase()+'.'+[...e.classList].join('.')+' «'+e.textContent.trim().slice(0,25)+'»')}
      if(![...e.childNodes].some(x=>x.nodeType===3&&x.textContent.trim()))continue;
      // font-size:0 = texte masqué volontairement (icône visible, nom accessible conservé), pas un petit texte.
      if(parseFloat(cs.fontSize)>0&&parseFloat(cs.fontSize)<12)small.push(cs.fontSize+' '+e.tagName.toLowerCase()+'.'+[...e.classList].join('.'));
      const fg=parse(cs.color);if(!fg||e.closest('[disabled],[aria-disabled=true]')||parseFloat(cs.opacity)<0.2)continue;
      const bg=bgOf(e),f={r:fg.r*fg.a+bg.r*(1-fg.a),g:fg.g*fg.a+bg.g*(1-fg.a),b:fg.b*fg.a+bg.b*(1-fg.a)};
      const [a,c]=[lum(f),lum(bg)].sort((x,y)=>y-x),ratio=(a+0.05)/(c+0.05);
      const large=parseFloat(cs.fontSize)>=18.66||(parseFloat(cs.fontSize)>=14&&parseInt(cs.fontWeight)>=700);
      if(ratio<(large?3:4.5))contrast.push(ratio.toFixed(2)+' '+e.tagName.toLowerCase()+'.'+[...e.classList].join('.')+' «'+e.textContent.trim().slice(0,25)+'»');
     }
     return {small:[...new Set(small)],contrast:[...new Set(contrast)],targets:[...new Set(targets)],overflow:document.documentElement.scrollWidth-document.documentElement.clientWidth};
    },mobile?44:24);
    assert.deepEqual(r.small,[],'texte < 12 px · '+where);
    assert.deepEqual(r.contrast,[],'contraste insuffisant · '+where);
    assert.deepEqual(r.targets,[],'cibles trop petites · '+where);
    assert.ok(r.overflow<=1,'défilement horizontal '+r.overflow+' px · '+where);
   }
   // Icônes : variantes légères uniquement (l'original de 1,1 Mo n'est plus téléchargé).
   assert.ok(assets.includes('/assets/opscontrol-icon-96.png'));
   assert.ok(!assets.includes('/assets/opscontrol-icon.png'),'icône de 1,1 Mo encore chargée');
   // Mouvement réduit : aucune transition ou animation perceptible.
   const motion=await page.evaluate(()=>[...document.querySelectorAll('main *')].filter(e=>{const c=getComputedStyle(e);
     const d=s=>Math.max(...s.split(',').map(x=>parseFloat(x)*(x.includes('ms')?1:1000)));return d(c.transitionDuration)>10||(c.animationName!=='none'&&d(c.animationDuration)>10)}).length);
   assert.equal(motion,0,'transition malgré prefers-reduced-motion');
   assert.deepEqual(errors,[]);
   await page.close();
  }
  const sizes=['opscontrol-icon-96.png','opscontrol-icon-64.png'].map(f=>fs.statSync(path.join(__dirname,'web','assets',f)).size);
  assert.ok(sizes.every(s=>s<40000),'icônes légères : '+sizes);
  console.log('PASS: design — texte ≥ 12 px, cibles 24/44 px, contraste AA sombre/clair, sans débordement, icônes légères, mouvement réduit');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
