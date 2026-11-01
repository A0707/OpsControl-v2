// WAF : thèmes séparés, mêmes preuves conservées, aucune action distante à la navigation.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  for(const viewport of [{width:1440,height:1000},{width:1280,height:720},{width:390,height:844}]){
   const page=await browser.newPage({viewport}),errors=[],posts=[],now=new Date().toISOString();
   page.on('pageerror',e=>errors.push(e.message));
   await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}}});
   const observed=data=>({status:'observed',data});
   const w={collected_at:now,coverage:{measured:12,total:14},sections:{
    services:observed([{name:'apache2.service',LoadState:'loaded',ActiveState:'active',SubState:'running'}]),
    fail2ban:observed({currently_banned:0,total_failed:4,total_banned:2}),
    apache_modules:observed({security_module_loaded:true}),traffic:observed({requests:40,errors_5xx_pct:2.5,http_codes:{200:39,500:1},top_urls:[['/accueil',20]],top_ips:[]}),
    modsecurity:observed({alert_lines:3,anomaly_max:7,rules:[['941100',3]],events:[{timestamp_raw:now,source:'audit.log',client:'192.0.2.10',rules:['941100'],action:'blocked',score:7}]}),
    ignoreip:observed({addresses:['127.0.0.1'],scope:'Jail observée'}),maxretry:observed(3),findtime:observed(60),bantime:observed(3600)},
    analysis:[{severity:'warning',title:'Anomalie WAF de test',evidence:'Preuve <script>danger</script>',check_command:'ss -tan'}],
    certificates:[{subject:'CN=*.example.test',not_after:'2027-01-01T00:00:00Z'}],recommendations:[]};
   const base={role:'WAF ModSecurity',registered:true,active_scope:true,status:'warning',stale:false,collected_at:now,services:[],checks:[],findings:[],history:[],coverage:{measured:10,total:15},waf:w};
   const hosts=[{...base,key:'waf01',name:'WAF principal',ip:'192.0.2.21'},{...base,key:'waf02',name:'WAF secours',ip:'192.0.2.22',stale:true}];
   let historyReads=0;
   await page.route('http://waf-organization.test/**',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(req.method()!=='GET'){posts.push(url.pathname);return route.fulfill({status:403,json:{detail:'Aucune écriture simulée'}});}
    if(url.pathname==='/api/overview')return route.fulfill({json:{hosts,counts:{warning:2},job:{running:false},jobs:{ssh:{running:false}},monitoring:{interval:0},availability:{sources:[]}}});
    if(url.pathname==='/api/tier0')return route.fulfill({json:{hosts:[{key:'waf01',name:'WAF principal',ip:'192.0.2.21',probe:{status:'up'}}],sources:[]}});
    if(url.pathname.startsWith('/api/hosts/'))return route.fulfill({json:hosts.find(h=>h.key===url.pathname.split('/').pop())});
    if(url.pathname.endsWith('/apache-history')){historyReads++;return route.fulfill({json:{samples:[]}});}
    if(url.pathname.endsWith('/bans'))return route.fulfill({json:{rows:[],summary:{listed:0,currently_banned:0,incoherent:0,verify:0,keep:0,campaigns:[]},coverage:{activity_known:true,ban_times:true},collected_at:now}});
    if(url.pathname==='/api/whoami')return route.fulfill({json:{mode:'local',role:'admin',can_admin:true,can_operate:true,authenticated:false}});
    if(url.pathname.startsWith('/api/'))return route.fulfill({status:404,json:{detail:'Non simulé'}});
    const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
    if(!fs.existsSync(file))return route.fulfill({status:404,body:''});
    return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.png')?'image/png':'text/html',headers:{'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'"}});
   });
   await page.goto('http://waf-organization.test/#/WAF%20%2F%20HA');
   const briefing=page.getByRole('button',{name:'Fermer le bilan'});if(await briefing.isVisible())await briefing.click();
   await page.locator('.waf-workspace').waitFor();
   assert.equal(await page.locator('[data-waf-tab-button]').count(),7);
   assert.ok(await page.locator('[data-waf-tab-button]').evaluateAll(buttons=>buttons.every(button=>{
    const bounds=button.getBoundingClientRect();
    return [...button.children].every(child=>child.getBoundingClientRect().bottom<=bounds.bottom+1);
   })),'les libellés et compteurs restent dans leur onglet, même sur un écran court');
   assert.equal(await page.locator('[role=tabpanel]:visible').count(),1);
   assert.equal(await page.locator('.t0-pills,.t0-grid').count(),0,'anciennes pastilles critiques retirées');
   assert.equal(historyReads,0,'historique non téléchargé avant son ouverture');
   await page.locator('[data-waf-tab-button=traffic]').click();
   await page.locator('#waf-panel-traffic').getByRole('heading',{name:'Règles ModSecurity',exact:true}).waitFor();
   assert.equal(await page.locator('#waf-panel-traffic').getByRole('heading',{name:'Politique Fail2ban',exact:true}).count(),0,'les anciennes colonnes ne mélangent plus les thèmes');
   await page.locator('[data-waf-tab-button=actions]').click();
   await page.locator('#waf-panel-actions').getByRole('heading',{name:'Politique Fail2ban',exact:true}).waitFor();
   await page.locator('#waf-panel-actions').getByRole('heading',{name:'Liste blanche Fail2ban observée',exact:true}).waitFor();
   await page.locator('[data-waf-tab-button=tls]').click();
   await page.locator('#waf-panel-tls').getByRole('heading',{name:'Certificats SSL/TLS · expiration',exact:true}).waitFor();
   assert.equal(await page.locator('[role=tabpanel]:visible').count(),1);
   await page.locator('[data-waf-tab-button=tls]').press('ArrowDown');
   assert.equal(await page.locator('[data-waf-tab-button=network]').getAttribute('aria-selected'),'true');
   await page.locator('[data-waf-tab-button=evidence]').click();
   await page.locator('#waf-panel-evidence').getByRole('heading',{name:'Historique des incidents Apache',exact:true}).waitFor();
   await page.waitForFunction(()=>document.querySelector('#apx-history')?.textContent.includes('Aucun échantillon'));
   assert.ok(historyReads>0);
   await page.locator('#waf-host-select').selectOption('waf02');
   await page.locator('.waf-hero').getByText(/MESURES ANCIENNES/).waitFor();
   assert.equal(await page.locator('[data-waf-tab-button=evidence]').getAttribute('aria-selected'),'true','onglet conservé au changement de WAF');
   assert.equal(posts.length,0,'navigation, filtres et historique restent en lecture seule');
   assert.equal(await page.locator('.waf-workspace script').count(),0);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=document.documentElement.clientWidth+1),'aucun débordement de la page');
   assert.deepEqual(errors,[]);
   await page.close();
  }
  console.log('PASS: WAF structuré en sept thèmes, preuves conservées, historique à la demande, clavier, mobile et pastilles supprimées');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exit(1);});
