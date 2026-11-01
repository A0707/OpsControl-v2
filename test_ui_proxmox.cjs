// Browser fixtures only: no requests or mutations are sent to Proxmox.
const {chromium,launchOptions}=require('./browser-test.cjs');
(async()=>{
 const browser=await chromium.launch(launchOptions);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const vm={vmid:101,name:'app-demo',type:'qemu',status:'running',cpu_pct:25,cpu_capacity:4,memory_bytes:1073741824,memory_total_bytes:2147483648,disk_used_bytes:4294967296,disk_capacity_bytes:10737418240,disk_read_bytes:1024,network_in_bytes:2048,network_out_bytes:4096,uptime_seconds:90061};
  const storage={name:'local-lvm',status:'available',type:'lvmthin',shared:false,used_bytes:5368709120,total_bytes:10737418240};
  const inv={nodes_count:2,counts:{qemu:1,lxc:0,running:1,stopped:0,storage:1},summary:{nodes_online:1,cpu_pct:25,memory_bytes:1073741824,memory_total_bytes:2147483648,storage_used_bytes:5368709120,storage_total_bytes:10737418240,network_in_bytes:2048,network_out_bytes:4096},scope:'Fixture de test',nodes:[{name:'node-a',status:'online',reported:true,cpu_pct:25,cpu_capacity:8,memory_bytes:1073741824,memory_total_bytes:2147483648,guests:[vm],storages:[storage]},{name:'node-b',status:'offline',reported:true,guests:[],storages:[]}]};
  const source={key:'pve-demo',name:'Cluster DEMO — test',provider:'Proxmox',url:'https://example.test/api2/json/cluster/resources',last_result:{status:'observed',collected_at:new Date().toISOString(),inventory:inv}};
  await page.route('**/api/connections*',route=>route.fulfill({json:[source]}));
  await page.route('**/api/connections/pve-demo/collect',route=>{
   inv.nodes[0].guests=[];inv.nodes[1].guests=[vm];return route.fulfill({json:source.last_result});
  });
  await page.goto((process.env.OPS_URL || 'http://127.0.0.1:8001'));
  await page.locator('#nav [data-page="Proxmox"]').click();
  // Nœuds repliés par défaut (sauf nœud à surveiller) : on ouvre le nœud avant d'y chercher la VM.
  await page.locator('[data-pve-node="pve-demo|node-a"]').waitFor();
  await page.locator('[data-pve-node="pve-demo|node-a"]').evaluate(d=>d.open=true);
  await page.locator('[data-pve-node="pve-demo|node-a"]').getByText('app-demo',{exact:true}).waitFor();
  await page.locator('#pve-search').fill('101');
  await page.getByText('app-demo',{exact:true}).waitFor();
  await page.locator('#pve-search').fill('');
  await page.locator('[data-pve-mode="storage"]').click();
  await page.getByText('local-lvm',{exact:true}).waitFor();
  await page.locator('[data-pve-mode="overview"]').click();
  await page.locator('[data-pve-collect]').click();
  await page.locator('[data-pve-node="pve-demo|node-b"]').waitFor();
  await page.locator('[data-pve-node="pve-demo|node-b"]').evaluate(d=>d.open=true);
  await page.locator('[data-pve-node="pve-demo|node-b"]').getByText('app-demo',{exact:true}).waitFor();
  await page.screenshot({path:'data/proxmox-fixture-ui.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'data/proxmox-fixture-mobile.png',fullPage:true});
  source.last_result={status:'unknown',error:'Échec de vérification TLS. Autorité non reconnue.'};
  await page.evaluate(()=>render());
  await page.getByText(source.last_result.error,{exact:true}).waitFor();
  if(await page.getByText('app-demo',{exact:true}).count())throw Error('Stale fixture shown after failure');
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: Proxmox fixture hierarchy, search, migration, TLS error and desktop/mobile');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
