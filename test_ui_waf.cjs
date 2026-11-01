// Page « WAF / HA » sur données simulées : fraîcheur, badges « non mesuré », libellés d'état,
// tri / filtre / « charger plus », copie des commandes, JSON repliable, 390 px et deux thèmes.
const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try {
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],posts=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});
  // Origine http non sécurisée : presse-papiers simulé pour vérifier le texte réellement copié.
  await page.addInitScript(()=>{window.EventSource=class extends EventTarget{close(){}};window.__copied=[];Object.defineProperty(navigator,'clipboard',{value:{writeText:async t=>{window.__copied.push(t)}}})});
  const at=new Date(Date.now()-86400000).toISOString();
  const urls=Array.from({length:60},(_,i)=>['/api/item-'+i+'-<b>x</b>',(i*7)%61]);
  // Certificat non joker expiré : l'ancien onglet TLS ne listait que les certificats joker (CN=*.…).
  const certificates=[{path:'/etc/ssl/wild.crt',subject:'CN = *.example.test',not_after:'2026-11-14T00:00:00+00:00',expiration_state:'Expire sous 30 jours',days_remaining:18},
   {path:'/etc/ssl/pay.crt',subject:'CN = pay.example.test',not_after:'2026-10-25T00:00:00+00:00',expiration_state:'Expiré',days_remaining:-2}];
  const waf={collected_at:at,duration_ms:1200,certificates,coverage:{measured:10,total:16},recommendations:['Vérifier la rotation des journaux'],
   analysis:[{severity:'warning',title:'5xx élevé',evidence:'12 % de réponses 5xx dans l’échantillon',solution_command:'# Examiner les backends en erreur',check_command:'sudo tail -n 50 /var/log/apache2/error.log'}],
   sections:{
    services:{status:'observed',data:[{name:'apache2',LoadState:'loaded',ActiveState:'active',SubState:'running'}]},
    fail2ban:{status:'observed',data:{currently_banned:3,total_failed:40,currently_failed:1,total_banned:9,banned_ips:[]}},
    traffic:{status:'observed',data:{requests:500,errors_5xx_pct:12,http_codes:{200:440,503:60},top_urls:urls,top_ips:[['198.51.100.7',80],['127.0.0.1',30]]}},
    modsecurity:{status:'observed',data:{alert_lines:4,anomaly_max:15,rules:[['949110',3]],events:[]}},
    sockets:{status:'observed',data:{close_wait_total:1200,close_wait_outbound:1100,close_wait_inbound:100,states:{ESTAB:30,'CLOSE-WAIT':1200},by_upstream:[['10.0.0.5:8080',1100]],process_visible:false,samples:[]}}}};
  const host={key:'waf1',name:'WAF principal',ip:'192.0.2.10',role:'WAF ModSecurity',status:'warning',stale:true,collected_at:at,services:[],checks:[],findings:[],waf,history:[{ts:at,waf:{banned:3,requests:500,errors_5xx_pct:12,alerts:4,close_wait:1200}}]};
  await page.route('http://waf.test/**',async route=>{
   const req=route.request(),url=new URL(req.url());let data;
   if(req.method()==='POST'){posts.push(url.pathname);return route.fulfill({json:{}});}
   if(url.pathname==='/api/overview')data={hosts:[host],job:{running:false},jobs:{},monitoring:{interval:0}};
   else if(url.pathname==='/api/whoami')data={role:'admin',mode:'local',authenticated:false,can_admin:true,can_operate:true};
   else if(url.pathname==='/api/hosts/waf1')data=host;
   else if(url.pathname==='/api/waf/waf1/bans')data={rows:[],summary:{listed:0,incoherent:0,verify:0,keep:0,campaigns:[]},coverage:{activity_known:true,ban_times:true},collected_at:at};
   else if(url.pathname==='/api/waf/waf1/apache-history')data={samples:[]};
   else if(url.pathname.startsWith('/api/'))data=[];
   if(data!==undefined)return route.fulfill({json:data});
   const file=path.join(__dirname,'web',url.pathname==='/'?'index.html':url.pathname);
   return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html'});
  });
  await page.goto('http://waf.test/');
  await page.waitForFunction(()=>typeof navigate==='function'&&typeof wafEnhanceTables==='function'&&state.hosts.length>0);
  await page.evaluate(()=>navigate('WAF / HA'));
  await page.locator('.waf-workspace').waitFor();

  // Ordre de lecture : compteurs puis constats en vue d'ensemble, panneau principal en tête de chaque onglet.
  const order=await page.evaluate(()=>Object.fromEntries([...document.querySelectorAll('[data-waf-panel]')].map(p=>[p.dataset.wafPanel,
   [...p.querySelector('.waf-topic-body').children].map(el=>el.matches('.waf-stats')?'KPI':(el.querySelector('h2')?.textContent||'').trim().split(' · ')[0])])));
  assert.deepEqual(order.summary,['KPI','','Constats WAF à examiner','Recommandations','Protection et services']);
  assert.equal(order.traffic[0],'Distribution HTTP');
  assert.ok(order.traffic.includes('Robots et activité WAF'),'titre traduit malgré sa précision de fenêtre');
  assert.equal(order.actions[0],'IP bannies');
  assert.deepEqual(order.network,['Connexions TCP','Réseau L3/L4']);
  assert.equal(order.evidence[0],'Déclarations et couverture');

  // En-tête : bandeau de fraîcheur visible, audit incomplet signalé, jamais présenté comme sain.
  assert.ok(await page.locator('.waf-hero .waf-stale-banner').isVisible(),'bandeau MESURES ANCIENNES visible');
  assert.match(await page.locator('.waf-stale-banner').innerText(),/MESURES ANCIENNES/);
  assert.match(await page.locator('.waf-hero').innerText(),/Audit incomplet/);
  // Constat et recommandation distingués.
  await page.getByText('5xx élevé').click();
  assert.match(await page.locator('.waf-finding').innerText(),/Constat · 12 %[\s\S]*Recommandation · Examiner/);

  // Tableaux : filtre, tri numérique, « charger plus » au-delà de 50 lignes, valeurs échappées.
  await page.getByRole('tab',{name:/Trafic et ModSecurity/}).click();
  const urlPanel=page.locator('section.panel',{has:page.locator('h2',{hasText:'Chemins les plus demandés'})});
  const rows=urlPanel.locator('tbody tr:not([hidden])');
  assert.equal(await rows.count(),50,'50 lignes affichées au départ');
  assert.equal(await urlPanel.locator('tbody b').count(),0,'contenu dynamique échappé');
  await urlPanel.getByRole('button',{name:/Afficher 50 lignes de plus/}).click();
  assert.equal(await rows.count(),60);
  assert.equal(await urlPanel.locator('.waf-table-more').isHidden(),true);
  await urlPanel.locator('[data-waf-sort="1"]').click();
  assert.equal(await urlPanel.locator('th[aria-sort=descending]').count(),1);
  const top=Number(await rows.first().locator('td').nth(1).innerText());
  assert.equal(top,Math.max(...urls.map(u=>u[1])),'tri décroissant');
  await urlPanel.locator('[data-waf-sort="1"]').click();
  assert.equal(Number(await rows.first().locator('td').nth(1).innerText()),0,'tri croissant');
  await urlPanel.locator('[data-waf-filter]').fill('item-5');
  assert.equal(await rows.count(),11,'item-5 et item-50…59');
  assert.match(await urlPanel.locator('[data-waf-count]').innerText(),/11 ligne\(s\) affichée\(s\) sur 11/);
  // Le filtre survit à un nouveau rendu (rafraîchissement temps réel).
  await page.evaluate(()=>render());
  assert.equal(await page.locator('[data-waf-filter]').first().inputValue(),'item-5');

  // Adresse locale dans les accès : signalée avant toute décision de ban.
  assert.match(await page.locator('#waf-panel-traffic').innerText(),/Adresses locales ou privées observées : 127\.0\.0\.1/);
  // Onglet TLS : tous les certificats, le plus urgent en tête, état en texte.
  await page.getByRole('tab',{name:/Certificats TLS/}).click();
  const tlsRows=await page.locator('#waf-panel-tls tbody tr').allInnerTexts();
  assert.equal(tlsRows.length,2);
  assert.match(tlsRows[0],/Expiré[\s\S]*pay\.example\.test[\s\S]*-2/);
  // Sections non collectées : visibles avec le badge « Non mesuré », jamais masquées.
  await page.getByRole('tab',{name:/Apache et backends/}).click();
  for(const title of ['URL les plus lentes','Concurrence estimée','Top IP - requêtes lentes']){
   const panel=page.locator('#waf-panel-apache section.panel',{has:page.locator('h2',{hasText:title})});
   assert.equal(await panel.count(),1,'section affichée : '+title);
   assert.match(await panel.innerText(),/Non mesuré/);
  }
  // Seuils CLOSE_WAIT : libellé texte en plus de la couleur.
  await page.getByRole('tab',{name:/Réseau et TCP/}).click();
  assert.match(await page.locator('.waf-cw-kpis .v2-kpi').first().innerText(),/Mesure ancienne · critique à la collecte · seuils 200 \/ 300 \/ 1000/);
  // Copie : texte copié, confirmation sur le bouton, mention « aucune commande exécutée » conservée.
  assert.match(await page.locator('.waf-cw').innerText(),/aucune commande exécutée par la plateforme/);
  const copy=page.locator('.waf-cw .command button[data-copy]').first();
  await copy.click();
  await page.locator('.waf-cw .command button.is-copied',{hasText:'Copié ✓'}).waitFor();
  assert.deepEqual(await page.evaluate(()=>window.__copied),['sudo ss -tanp state close-wait']);

  // Preuves : JSON brut replié, sondes attendues absentes listées « Non collecté ».
  await page.getByRole('tab',{name:/Preuves et historique/}).click();
  const cover=page.locator('section.panel',{has:page.locator('h2',{hasText:'Déclarations et couverture'})});
  assert.ok(await cover.locator('details').count()>=5);
  assert.equal(await cover.locator('details[open]').count(),0);
  assert.match(await cover.locator('.waf-missing').innerText(),/Non collecté[\s\S]*Capacité conntrack/);
  const download=page.waitForEvent('download');await page.locator('[data-export-waf]').click();
  const file=await download;await file.saveAs('data/waf-ui-export-test.json');
  assert.equal(JSON.parse(fs.readFileSync('data/waf-ui-export-test.json','utf8')).stale,true);
  fs.rmSync('data/waf-ui-export-test.json',{force:true});

  // Collecte en cours : bouton désactivé avec indicateur de chargement.
  await page.evaluate(()=>{state.job.running=true;render()});
  const refresh=page.locator('.waf-hero [data-audit-host]');
  assert.equal(await refresh.isDisabled(),true);
  assert.equal(await refresh.locator('.waf-spinner').count(),1);
  await page.evaluate(()=>{state.job.running=false;render()});

  // 390 px, thèmes clair et sombre : aucune barre de défilement horizontale de page, onglets défilants.
  for(const theme of ['light','dark']){
   await page.setViewportSize({width:390,height:844});
   await page.evaluate(t=>{document.documentElement.dataset.theme=t;render()},theme);
   await page.getByRole('tab',{name:/Trafic et ModSecurity/}).click();
   const width=await page.evaluate(()=>document.documentElement.scrollWidth);
   assert.ok(width<=391,theme+' : largeur de page '+width+' px à 390 px');
   assert.equal(await page.locator('.waf-topic-nav').evaluate(el=>getComputedStyle(el).overflowX),'auto');
   assert.equal(await page.locator('#waf-panel-traffic .waf-table thead').first().evaluate(el=>getComputedStyle(el).display),'none','tableaux en cartes sous 768 px');
   assert.equal(await page.locator('#waf-panel-traffic .waf-table td').first().getAttribute('data-label'),'Code');
   assert.ok(await page.locator('.waf-stale-banner').isVisible());
  }
  assert.deepEqual(posts,[],'aucune action déclenchée automatiquement');
  assert.deepEqual(errors,[],'aucune erreur console');
  console.log('test_ui_waf : OK');
 } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exit(1)});
