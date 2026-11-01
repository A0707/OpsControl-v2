const {chromium,launchOptions}=require('./browser-test.cjs');
const fs=require('fs');const path=require('path');
(async()=>{const browser=await chromium.launch(launchOptions);try{
const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));let posts=0;
await page.route('http://infraops.test/**',async route=>{const u=new URL(route.request().url());
if(u.pathname==='/api/overview')return route.fulfill({json:{hosts:[],counts:{},job:{running:false},monitoring:{interval:0}}});
if(u.pathname==='/api/sync'){if(route.request().method()==='POST'){posts++;return route.fulfill({json:{}})}return route.fulfill({json:{assets:[],sources:[],unmatched_guests:[{cluster:'pve',node:'n1',vmid:1,name:'web',reason:'Serveur absent'}],missing_providers:['Wazuh','Bacula','Zabbix'],job:{completed:0,total:0,errors:[]}}})}
if(u.pathname.startsWith('/api/'))return route.fulfill({json:[]});
const f=path.join(__dirname,'web',u.pathname==='/'?'index.html':u.pathname.slice(1));return route.fulfill({body:fs.readFileSync(f),contentType:f.endsWith('.js')?'application/javascript':f.endsWith('.css')?'text/css':'text/html'});
});
await page.goto('http://infraops.test');await page.locator('#nav [data-page="Sources"]').click();await page.locator('#v2-hub-tabs [data-go="Synchronisation"]').click();await page.getByText('VM à rapprocher (1)',{exact:true}).waitFor();await page.locator('#sync-all').click();if(posts!==1)throw Error('Collecte non declenchee');if(errors.length)throw Error(errors.join('\n'));console.log('PASS: navigation, sources absentes, VM non associee et synchronisation (API simulees).');
}finally{await browser.close()}})().catch(e=>{console.error(e);process.exitCode=1});
