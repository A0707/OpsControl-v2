// Sécurité & CVE : fixture synthétique, aucune requête ne quitte le navigateur.
// Vérifie les six sections, l'onglet SSH historique, la procédure de correction (texte),
// le workflow explicite, le dossier GLPI après validation et l'absence de POST à la navigation.
const {chromium, launchOptions} = require('./browser-test.cjs');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const OUT = path.join(__dirname, 'data', 'v2-captures'); fs.mkdirSync(OUT, {recursive: true});
(async () => {
  const browser = await chromium.launch(launchOptions);
  try {
    const context = await browser.newContext({viewport: {width: 1440, height: 900}, acceptDownloads: true});
    const page = await context.newPage(), errors = [], posts = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('console', m => { if (m.type() === 'error' && !/404/.test(m.text())) errors.push(m.text()); });
    await page.addInitScript(() => {
      window.EventSource = class extends EventTarget { close() {} };
      window.__copied = [];
      Object.defineProperty(navigator, 'clipboard', {value: {writeText: async t => { window.__copied.push(t); }}, configurable: true});
    });
    const now = new Date().toISOString();
    const vuln = {id: '00000000000000000001', host_key: 'web01', host_name: 'web01', host_ip: '192.0.2.10', environment: 'Production',
      cve: 'CVE-2026-1234', package: 'openssl', installed: '3.0.11-1~deb12u2', fixed: '3.0.15-1~deb12u1', sources: ['debian', 'wazuh'],
      confidence: 'confirmé', status: 'open', status_label: 'Détectée', first_seen: now, last_seen: now, owner: null, cvss: 9.8, kev: true,
      kev_due: '2026-11-10', severity: 'critical', updated_at: now,
      evidence: {source: 'Debian Security Tracker (DSA-5800-1, bookworm)', reason: 'Debian et Wazuh concordent',
        comparison: 'dpkg : 3.0.11-1~deb12u2 < 3.0.15-1~deb12u1', binaries: ['libssl3', 'openssl'],
        binary_versions: {libssl3: '3.0.11-1~deb12u2', openssl: '3.0.11-1~deb12u2'}, changelog_mentions: [],
        repository: 'Correctif disponible dans les dépôts configurés : 3.0.15-1~deb12u1 (bookworm-security)'}};
    const plan = {vuln: {id: vuln.id, cve: vuln.cve, host_key: 'web01', host_name: 'web01', status: 'open', status_label: 'Détectée', confidence: 'confirmé'},
      server: {key: 'web01', name: 'web01', ip: '192.0.2.10', environment: 'Production', vmid: 101, node: 'pve1'}, cve: vuln.cve, kev: true,
      package: 'openssl', binaries: ['libssl3', 'openssl'], installed: vuln.installed, fixed: vuln.fixed, impact: 'Bibliothèque TLS',
      backup_required: 'Oui : instantané Proxmox', precheck: ['apt-cache policy libssl3 openssl'], backup: ['qm snapshot 101 avant-cve20261234'],
      update: ['sudo apt-get update', 'sudo apt-get install --only-upgrade libssl3 openssl'], apply: ['sudo needrestart -r l'],
      verify: ['dpkg-query -W libssl3'], rollback: ['sudo apt-get install --allow-downgrades libssl3=3.0.11-1~deb12u2'], warnings: [],
      generated_at: now, generated_from: 'Relevé SSH ; aucun LLM.', text: 'Serveur : web01\n## Commandes de mise à jour proposées\nsudo apt-get install --only-upgrade libssl3 openssl'};
    const summary = {generated_at: now, counts: {open: 1, kev: 1, critical: 1, high: 0, to_verify: 0, validated: 0, in_progress: 0, resolved_30d: 2,
      hosts_affected: 1, hosts_scanned: 1, hosts_total: 2, wazuh_hosts: 1, notifications: 1, advisories_7d: 3},
      by_severity: {critical: 1}, top_hosts: [{host_key: 'web01', name: 'web01', environment: 'Production', count: 1, kev: 1, critical: 1, max_cvss: 9.8}],
      top_vulns: [vuln], syncs: {kev: {at: now, status: 'ok'}}, scope: 'Détections prouvées uniquement.'};
    // Veille : CVE PHP du 21/10/2026 (identifiants réels), serveurs et versions fictifs.
    const m = (id, host, status, instance, version, fixed, reason, extra = {}) => ({id, cve: 'CVE-2026-109618', host_key: host, host_name: host, tech: 'php',
      tech_label: 'PHP', instance, version, fixed, status, reason, origin: 'image', exposed: null, vuln_status: null, ...extra});
    const watch = {generated_at: now, total: 3, job: {running: false}, scope: 'Applicabilité calculée depuis les versions relevées.', exposed: {'wp-vps-01': 'exposition déclarée'},
      kpis: {sources_ok: 12, sources_error: 1, sources_total: 13, bulletins_24h: 4, bulletins: 9, confirmed: 1, potential: 1, not_applicable: 1, p1: 1,
        alerts_24h: 3, alerts_unread: 2, next_sync: now, feeds_auto: true, feeds_hours: 1},
      sources: [{key: 'php_advisories', label: 'PHP (avis de sécurité officiels)', status: 'ok', status_label: 'Opérationnelle', last_success: now, items: 5, failures: 0},
        {key: 'debian_dla', label: 'Debian Security Tracker (DLA)', status: 'error', status_label: 'En erreur', last_success: null, error: 'Source injoignable : TimeoutError',
          failures: 2, next_after: now}],
      cves: [
        {cve: 'CVE-2026-109618', cvss: 9.8, severity: 'critical', vendor_severity: 'critical', kev: false, epss: null, description: 'PHP uses longjmp() for out-of-memory errors…',
          status: 'confirmed', priority: {rank: 'P1', score: 12.8, why: ['gravité 9.8', 'exposée à Internet', 'applicabilité confirmée']}, techs: ['php'], tech_labels: ['PHP'],
          fixed: ['8.2.35', '8.3.36', '8.4.27-1~deb13u1'], ranges: ['PHP v < 8.2.35', 'PHP 8.3.0 ≤ v < 8.3.36'], exposed: ['wp-vps-01'], sources: ['nvd', 'php_advisories'],
          advisories: [{source: 'php_advisories', label: 'PHP (avis de sécurité officiels)', url: 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'}],
          counts: {confirmed: 1, potential: 1, not_applicable: 1}, nvd_status: 'Modified',
          hosts: [m('00000000000000000a01', 'wp-vps-01', 'confirmed', 'conteneur php1 (php:8.3.30-apache)', '8.3.30', '8.3.36', 'version 8.3.30 (image Docker officielle) dans une plage affectée (NVD)',
            {exposed: 'exposition déclarée', vuln_status: 'open'}),
            m('00000000000000000a02', 'wp-vps-03', 'potential', 'paquet php8.2', '8.2.31', '8.2.35', 'paquet de distribution : correctif rétroporté possible', {origin: 'distro'}),
            m('00000000000000000a03', 'wp-vps-05', 'not_applicable', 'conteneur php5 (php:8.3.36-fpm)', '8.3.36', null, 'version 8.3.36 hors des plages affectées (NVD)')]},
        {cve: 'CVE-2026-109619', cvss: 9.8, severity: 'critical', kev: false, epss: null, status: 'potential', priority: {rank: 'P2', score: 10.5, why: ['gravité 9.8']},
          techs: ['php'], tech_labels: ['PHP'], fixed: ['8.2.35'], ranges: ['PHP v < 8.2.35'], exposed: [], sources: ['nvd'], advisories: [], counts: {potential: 1},
          hosts: [m('00000000000000000a02', 'wp-vps-03', 'potential', 'paquet php8.2', '8.2.31', '8.2.35', 'rétroportage possible', {cve: 'CVE-2026-109619'})]},
        {cve: 'CVE-2024-4577', cvss: 9.8, severity: 'critical', kev: true, epss: 0.99987, status: 'not_applicable', priority: {rank: 'P1', score: 14.8, why: ['gravité 9.8']},
          techs: ['php'], tech_labels: ['PHP'], fixed: [], ranges: ['PHP 8.2.0 ≤ v < 8.2.20'], exposed: [], sources: ['nvd'], advisories: [], counts: {not_applicable: 1},
          hosts: [m('00000000000000000a04', 'legacy-php', 'not_applicable', 'conteneur legacy (php:8.2.10-fpm)', '8.2.10', null, 'configuration limitée à microsoft windows', {cve: 'CVE-2024-4577'})]}],
      techs: [{tech: 'php', label: 'PHP', hosts: 4, cves: 3, confirmed: 1, potential: 2, not_applicable: 2}],
      bulletins: [{source: 'wordpress', source_label: 'WordPress (annonces de sécurité)', id: 'w', title: 'Critical PHP Security Release', url: 'https://wordpress.org/news/2026/10/critical-php-security-release/',
        published: now, first_seen: now, cves: [], applicable: []}],
      alerts: [{id: 7, at: now, level: 'critical', kind: 'exposed', kind_label: 'Service exposé à Internet', priority: 'P1', title: 'CVE-2026-109618 sur un service exposé à Internet — PHP',
        detail: 'wp-vps-01 (exposition déclarée)', hosts: ['wp-vps-01'], read_at: null, emailed_at: now}],
      changes: [{cve: 'CVE-2026-109618', at: now, field: 'cvss', old: null, new: '9.8'}],
      filters: {techs: [{key: 'php', label: 'PHP'}, {key: 'wordpress', label: 'WordPress'}], sources: [{key: 'php_advisories', label: 'PHP (avis)'}], hosts: [{key: 'wp-vps-01', name: 'wp-vps-01'}]}};
    // Cas constaté : relevé SSH de 97 serveurs en cours ; la veille doit rester lançable.
    summary.job = {running: true, kind: 'scan', completed: 27, total: 97, actor: 'Operator',
      scan: {running: true, kind: 'scan', completed: 27, total: 97, actor: 'Operator'}, sync: {running: false, kind: 'sync'}};
    const recoPlan = {host: {key: 'web01', name: 'web01', environment: 'Production'}, exposed: 'WAF', level: 'P1', counts: {P1: 1, P2: 1, P3: 0, P4: 1},
      summary: '3 recommandation(s), priorité la plus haute P1 (Immédiate)', generated_at: now, generated_from: 'Aucun LLM, rien n’est exécuté.',
      text: 'Plan de correction — web01\n1. [P1 — Immédiate] Mettre à jour 1 paquet(s) vulnérable(s)\n     sudo apt-get install --only-upgrade libssl3 openssl',
      recommendations: [
        {order: 1, kind: 'packages', priority: 'P1', priority_label: 'Immédiate', title: 'Mettre à jour 1 paquet(s) vulnérable(s) — 1 CVE', cves: ['CVE-2026-1234'],
          why: ['1 vulnérabilité(s) ouverte(s) corrigée(s) par la distribution', 'CVE-2026-1234 exploitée activement (CISA KEV)'], impact: 'Bibliothèque TLS',
          precheck: ['apt-get -s install --only-upgrade libssl3 openssl   # simulation, aucune modification'], backup: ['qm snapshot 101 avant-maj-20261022'],
          apply: ['sudo apt-get update', 'sudo apt-get install --only-upgrade libssl3 openssl'], restart_steps: ['sudo needrestart -r l'],
          verify: ['dpkg --compare-versions …'], rollback: ['sudo apt-get install --allow-downgrades libssl3=3.0.11-1~deb12u2 openssl=3.0.11-1~deb12u2']},
        {order: 2, kind: 'reboot', priority: 'P2', priority_label: 'Sous 7 jours', title: 'Redémarrage en attente', cves: [], why: ['/var/run/reboot-required présent'],
          precheck: ['sudo needrestart -r l'], backup: [], apply: [], restart_steps: ['# Redémarrage dans la fenêtre validée (jamais automatique)'], verify: ['uname -r'], rollback: []},
        {order: 3, kind: 'coverage', priority: 'P4', priority_label: 'Planifiable', title: 'Compléter la couverture d’analyse', cves: [], why: ['Aucune détection Wazuh rapprochée'],
          precheck: [], backup: [], apply: ['Sécurité > Analyse par serveur > « Analyser »'], restart_steps: [], verify: [], rollback: []}]};
    const hosts = [{key: 'web01', name: 'web01', ip: '192.0.2.10', registered: true, active_scope: true, status: 'ok', services: [], findings: [], checks: [],
      coverage: {measured: 10, total: 15}, collected_at: now, environment: 'Production'}];
    const routes = {
      '/api/security/summary': summary,
      '/api/security/notifications': {items: [{id: 1, at: now, level: 'critical', title: 'CVE-2026-1234 exploitée activement (CISA KEV) sur 1 serveur(s)', detail: 'Priorité maximale', hosts: [{key: 'web01', name: 'web01'}], cve: vuln.cve}]},
      '/api/security/vulns': {items: [vuln], total: 1},
      ['/api/security/vulns/' + vuln.id]: {...vuln, cve_data: {cvss: 9.8, kev_action: 'Appliquer le correctif'}, events: [{at: now, actor: 'OpsControl', auth: 'system', action: 'detected', detail: 'Debian'}],
        advisories: [{source: 'certfr_avis', id: 'CERTFR-2026-AVI-0001', title: 'Vulnérabilité dans OpenSSL', url: 'https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/', published: now}], itsm: []},
      ['/api/security/vulns/' + vuln.id + '/plan']: plan,
      '/api/security/hosts': {items: [{key: 'web01', name: 'web01', ip: '192.0.2.10', environment: 'Production', os: 'Debian GNU/Linux 12 (bookworm)',
        support: {label: 'Support de sécurité jusqu’au 30/06/2028'}, packages: 812, collected_at: now, wazuh_at: now, reboot_required: true, docker: 'ok',
        counts: {open: 1, kev: 1, critical: 1}, collect_enabled: true}], job: {running: false}},
      '/api/security/hosts/web01': {host: {key: 'web01', name: 'web01', ip: '192.0.2.10', environment: 'Production'}, os: {pretty: 'Debian GNU/Linux 12 (bookworm)'},
        support: {label: 'Support de sécurité jusqu’au 30/06/2028'}, kernel: '6.1.0-18-amd64', reboot_required: true, manager: 'dpkg', collected_at: now, complete: true,
        account: 'infraops:22', packages_count: 812, upgradable_count: 4, components: [{component: 'OpenSSL', packages: ['libssl3', 'openssl'], versions: ['3.0.11-1~deb12u2'], binary: 'OpenSSL 3.0.11'},
          {component: 'PHP', packages: ['php8.2-cli'], versions: ['8.2.7-1~deb12u1'], binary: 'PHP 8.2.7 (cli)'}],
        docker: {state: 'ok', containers: [{name: 'app', image: 'php:8.1-apache', status: 'Up 3 days'}], images: [{repository: 'php', tag: '8.1-apache', id: 'abc', created: '2025'}],
          findings: [{repository: 'php', tag: '8.1-apache', id: 'abc', finding: 'php 8.1 hors support amont', level: 'warning'}]},
        wazuh: {connection: 'wazuh', agent_id: '001', at: now, complete: true, items: 3}, vulns: [vuln], scans: [{at: now, status: 'ok', packages: 812, actor: 'Operator'}], scope: 'Sans sudo.'},
      '/api/security/watch': watch,
      '/api/security/matches/plan': {...plan, vuln: undefined, cve: 'CVE-2026-109618', package: 'php', binaries: [], installed: '8.3.30', fixed: '8.3.36',
        update: ['docker compose pull php1 && docker compose up -d php1'], warnings: ['Détection à vérifier : applicabilité potentielle.'],
        match: {id: '00000000000000000a02', cve: 'CVE-2026-109618', host_key: 'wp-vps-03', status: 'potential', status_label: 'Potentielle', host_name: 'wp-vps-03'}},
      '/api/security/sources': {sources: watch.sources, keys: {nvd: false, github: false},
        mail: {configured: true, server: 'smtp.example.test:587', security: 'starttls', recipients: ['soc@example.test'], missing: []},
        wazuh: [], indexers: [{key: 'idx', name: 'Indexeur Wazuh'}], debian_fixes: {bookworm: 2100}, kev_count: 1400, job: {running: false},
        settings: {feeds_auto: true, feeds_hours: 1, scan_hours: 0, wazuh_indexer: '', mail_to: 'soc@example.test', mail_level: 'critical', epss_threshold: 0.5}},
      '/api/security/history': {events: [{at: now, actor: 'OpsControl', auth: 'system', action: 'detected', detail: 'Debian', cve: vuln.cve, host_name: 'web01'}],
        scans: [{at: now, host_key: 'web01', host_name: 'web01', status: 'ok', packages: 812, actor: 'Operator'}], syncs: [{at: now, source: 'kev', status: 'ok', items: 1400, new_items: 2}],
        trend: [{day: now.slice(0, 10), detected: 1, resolved: 2}], days: 30},
      '/api/itsm/status': {available: true, protocol: 1, configured: true},
      '/api/itsm/links': {items: [], sync: {}},
      '/api/whoami': {role: 'admin', authenticated: true, user: 'admin', can_admin: true, can_operate: true},
      '/api/overview': {hosts, counts: {}, job: {running: false}, jobs: {ssh: {running: false}}, monitoring: {interval: 0}, availability: {sources: []}},
      '/api/findings': {web01: []},
      '/api/hosts/web01': hosts[0],
      '/api/security/hosts/web01/recommendations': recoPlan,
      '/api/security/recommendations': {generated_at: now, counts: {P1: 1, P2: 0, P3: 0, P4: 0}, items: [{key: 'web01', name: 'web01', environment: 'Production',
        exposed: 'WAF', level: 'P1', counts: {P1: 1, P2: 1, P3: 0, P4: 1}, total: 3, top: [{priority: 'P1', title: 'Mettre à jour 1 paquet(s) vulnérable(s) — 1 CVE', kind: 'packages', cves: 1}]}]},
    };
    let navigating = true, watchDetails = 0;
    await page.route('http://security.test/**', async route => {
      const req = route.request(), url = new URL(req.url());
      if (req.method() !== 'GET') {
        posts.push({path: url.pathname, body: req.postDataJSON(), navigating});
        if (url.pathname === '/api/security/vulns/action') {
          vuln.status = 'validated'; vuln.status_label = 'Validée';
          routes['/api/security/vulns/' + vuln.id].status = 'validated';
          plan.vuln.status = 'validated'; plan.vuln.status_label = 'Validée';
          return route.fulfill({json: vuln});
        }
        if (url.pathname === '/api/security/matches/decide') return route.fulfill({json: {...watch.cves[0].hosts[1], status: 'confirmed', vuln_id: '00000000000000000002'}});
        if (url.pathname === '/api/itsm/take') return route.fulfill({json: {id: 'case', kind: 'Ticket', reference: 'OC-1', owner: 'admin', owner_auth: 'proxy', taken_at: now,
          status: 'pending', snapshot: {title: vuln.cve + ' — openssl', severity: 'critical'}, events: []}});
        return route.fulfill({json: {running: true, kind: 'scan'}});
      }
      if (url.pathname === '/api/itsm/detail') return route.fulfill({json: {id: 'case', kind: 'Ticket', reference: 'OC-1', owner: 'admin', owner_auth: 'proxy', taken_at: now,
        status: 'pending', snapshot: {title: vuln.cve + ' — openssl', severity: 'critical'}, events: []}});
      if (url.pathname === '/api/security/report') return route.fulfill({body: '﻿Serveur;CVE\r\n', contentType: 'text/csv; charset=utf-8',
        headers: {'Content-Disposition': 'attachment; filename="vulnerabilites-test.csv"'}});
      if(url.pathname==='/api/security/watch'){
        const ident=url.searchParams.get('cve');
        if(ident){watchDetails++;return route.fulfill({json:{...watch,cves:watch.cves.filter(c=>c.cve===ident),total:1}});}
        if(url.searchParams.get('projection')==='list')return route.fulfill({json:{...watch,cves:watch.cves.map(c=>({...c,hosts:[],detail_available:true}))}});
      }
      if (routes[url.pathname]) return route.fulfill({json: routes[url.pathname]});
      if (url.pathname.startsWith('/api/')) return route.fulfill({status: 404, json: {detail: 'Non simulé'}});
      const file = path.join(__dirname, 'web', url.pathname === '/' ? 'index.html' : url.pathname);
      if (!fs.existsSync(file)) return route.fulfill({status: 404, body: ''});
      return route.fulfill({body: fs.readFileSync(file), contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.png') ? 'image/png' : 'text/html',
        headers: {'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'"}});
    });
    await page.goto('http://security.test/#/Sécurité');
    // 1. Tableau de bord : KPI, notification ciblée, priorités.
    await page.locator('#sec-tab-dashboard.active').waitFor();
    await page.getByText('Exploitées (CISA KEV)').waitFor();
    await page.getByText('exploitée activement (CISA KEV) sur 1 serveur(s)').waitFor();
    assert.equal(await page.locator('[data-sec-tab]').count(), 7);
    // Audit UI du 31/10 : unités explicites (13.1) et onglets au clavier (accessibilité).
    await page.getByText(/couples serveur\/CVE/).first().waitFor();
    await page.locator('#sec-tab-dashboard').focus();
    await page.keyboard.press('ArrowRight');
    await page.locator('#sec-tab-vulns.active').waitFor();
    assert.equal(await page.evaluate(() => document.activeElement.id), 'sec-tab-vulns');
    await page.keyboard.press('Home');
    await page.locator('#sec-tab-dashboard.active').waitFor();
    await page.getByText('Relevé des paquets en cours : 27 / 97 serveur(s)').waitFor();
    assert.equal(await page.locator('[data-sec-scan]').isDisabled(), true, 'relevé déjà en cours');
    assert.equal(await page.locator('[data-sec-sync]').isDisabled(), false, 'la veille ne doit pas attendre le relevé SSH');
    await page.screenshot({path: path.join(OUT, 'security-dashboard.png'), fullPage: true});
    // 2. Vulnérabilités : détail déplié, preuve et workflow.
    await page.locator('[data-sec-tab="vulns"]').click();
    await page.locator('[data-sec-open]').first().click();
    await page.getByText('dpkg : 3.0.11-1~deb12u2 < 3.0.15-1~deb12u1').waitFor();
    await page.getByText('Ticket GLPI : disponible après validation de la vulnérabilité.').waitFor();
    // 3. Analyse par serveur : OS, composants, Docker hors support.
    await page.locator('[data-sec-tab="hosts"]').click();
    await page.locator('button[data-sec-host="web01"]').first().click();
    await page.getByText('ANALYSE DU SERVEUR').waitFor();
    await page.getByText('PHP 8.2.7 (cli)').waitFor();
    await page.getByText('php 8.1 hors support amont').waitFor();
    // 4. Veille : état des sources, CVE séparées par applicabilité, priorité, versions.
    await page.locator('[data-sec-tab="feeds"]').click();
    await page.getByText('Sources opérationnelles').waitFor();
    assert.equal(await page.locator('.v2-kpis').filter({hasText: 'Prochaine synchronisation'}).locator('text=<span').count(), 0, 'date échappée dans un indicateur');
    await page.locator('.sec-sources .sc-card.critical').getByText('Source injoignable : TimeoutError').waitFor();
    for (const status of ['confirmed', 'potential', 'not_applicable']) assert.equal(await page.locator('[data-sec-applicability="' + status + '"]').count(), 1, status);
    assert.equal(await page.locator('[data-sec-applicability="confirmed"] [data-sec-wopen="CVE-2026-109618"]').count(), 1);
    assert.equal(await page.locator('[data-sec-applicability="potential"] [data-sec-wopen="CVE-2026-109619"]').count(), 1);
    assert.equal(await page.locator('[data-sec-applicability="not_applicable"] [data-sec-wopen="CVE-2024-4577"]').count(), 1);
    await page.locator('[data-sec-applicability="confirmed"]').getByText('P1', {exact: true}).waitFor();
    await page.locator('[data-sec-wopen="CVE-2026-109618"]').click();
    await page.getByText('8.3.30 → 8.3.36').waitFor();
    assert.ok(watchDetails>0,'les preuves par serveur sont chargées seulement à l’ouverture');
    await page.locator('[data-sec-applicability="confirmed"]').getByText('Exposé', {exact: true}).waitFor();
    await page.screenshot({path: path.join(OUT, 'security-veille.png'), fullPage: true});
    // Filtres : produit transmis au serveur.
    await page.locator('#sec-w-tech').selectOption('php');
    await page.waitForFunction(() => document.querySelector('#sec-w-tech')?.value === 'php');
    for (const [view, text] of [['techs', 'CVE par technologie'], ['bulletins', 'Critical PHP Security Release'], ['alerts', 'Historique des alertes']]) {
      await page.locator('[data-sec-watch-view="' + view + '"]').click();
      await page.getByText(text).first().waitFor();
    }
    await page.locator('[data-sec-watch-view="settings"]').click();
    await page.locator('#sec-settings select[name="feeds_hours"]').waitFor();
    await page.locator('[data-sec-mail-test]').waitFor();
    await page.locator('[data-sec-watch-view="cves"]').click();
    // 5. Historique et rapports : tendance et export CSV produit par le serveur.
    await page.locator('[data-sec-tab="history"]').click();
    await page.getByRole('heading', {name: 'Tendance'}).waitFor();
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-sec-csv]').first().click()]);
    assert.equal(download.suggestedFilename(), 'vulnerabilites-test.csv');
    // 6. Onglet SSH historique conservé.
    await page.locator('[data-sec-tab="ssh"]').click();
    await page.getByRole('heading', {name: 'Contrôles de sécurité SSH'}).waitFor();
    assert.equal(posts.length, 0, 'navigation : aucune écriture ' + JSON.stringify(posts));
    navigating = false;
    // 6 bis. Veille : procédure pour une CVE potentielle, puis confirmation après vérification.
    await page.locator('[data-sec-tab="feeds"]').click();
    if (!(await page.locator('[data-sec-mplan="00000000000000000a02"]').count())) await page.locator('[data-sec-wopen="CVE-2026-109618"]').click();
    await page.locator('[data-sec-mplan="00000000000000000a02"]').first().click();
    await page.locator('#sec-tab-remediation.active').waitFor();
    await page.getByText('docker compose pull php1 && docker compose up -d php1').waitFor();
    await page.getByText('confirmer après vérification (onglet Veille)').waitFor();
    assert.equal(posts.length, 0, 'préparer une correction depuis la veille ne lance rien');
    await page.locator('[data-sec-tab="feeds"]').click();
    if (!(await page.locator('[data-sec-dnote]').count())) await page.locator('[data-sec-wopen="CVE-2026-109618"]').click();
    await page.locator('[data-sec-dnote="00000000000000000a02|CVE-2026-109618"]').fill('Changelog Debian vérifié : correctif absent');
    await page.locator('[data-sec-decide="confirm"][data-sec-mid="00000000000000000a02"][data-sec-mcve="CVE-2026-109618"]').click();
    await page.waitForFunction(() => document.querySelector('#toast')?.textContent.includes('Confirmée'));
    const decided = posts.find(p => p.path === '/api/security/matches/decide');
    assert.deepEqual([decided.body.decision, decided.body.note], ['confirm', 'Changelog Debian vérifié : correctif absent']);
    posts.length = 0;
    // 7. Préparer la correction : procédure texte, copie, aucune exécution.
    await page.locator('[data-sec-tab="vulns"]').click();
    await page.locator('[data-sec-plan]').first().click();
    await page.locator('#sec-tab-remediation.active').waitFor();
    await page.getByText('TEXTE À COPIER · RIEN N’EST EXÉCUTÉ').waitFor();
    await page.getByText('sudo apt-get install --only-upgrade libssl3 openssl').first().waitFor();
    await page.getByText('qm snapshot 101 avant-cve20261234').waitFor();
    await page.getByRole('button', {name: 'Copier la procédure complète'}).click();
    await page.waitForFunction(() => window.__copied.length === 1);
    assert.match(await page.evaluate(() => window.__copied[0]), /only-upgrade libssl3 openssl/);
    assert.equal(posts.length, 0, 'préparer la correction ne lance rien');
    // 8. Validation explicite, puis dossier GLPI possible.
    await page.getByRole('button', {name: 'Valider la vulnérabilité'}).click();
    await page.waitForFunction(() => document.querySelector('[data-itsm-origin="vulnerability"]'));
    assert.deepEqual(posts.map(p => p.path), ['/api/security/vulns/action']);
    assert.equal(posts[0].body.action, 'validate');
    await page.locator('[data-itsm-origin="vulnerability"]').first().click();
    await page.locator('#itsm-dialog').getByText('serveur, CVE, paquet, versions, responsable et plan de correction').waitFor();
    await page.locator('#itsm-dialog [type=submit]:not([disabled])').click();
    await page.waitForFunction(() => document.querySelector('#itsm-dialog')?.textContent.includes('OC-1'));
    const take = posts.find(p => p.path === '/api/itsm/take');
    assert.equal(take.body.origin, 'vulnerability');
    assert.equal(take.body.origin_id, vuln.id);
    await page.keyboard.press('Escape');
    // 9. Fiche serveur, onglet Sécurité : vulnérabilités collectées et preuves de CE serveur.
    const before = posts.length;
    await page.evaluate(() => openHost('web01'));
    await page.locator('.host-tabs [data-tab="security"]').click();
    await page.locator('#host-cve').getByText('CVE-2026-1234').waitFor();
    await page.locator('#host-cve').getByText('3.0.15-1~deb12u1').first().waitFor();
    await page.locator('#host-cve').getByText('812 paquet(s)').waitFor();
    await page.locator('#host-cve').getByText('Debian GNU/Linux 12 (bookworm)').waitFor();
    await page.getByText('Sécurité observable').waitFor();             // section historique conservée
    // Plan consolidé : priorités, preuves, étapes ; la première recommandation est dépliée.
    await page.locator('#host-plan').getByText('3 recommandation(s), priorité la plus haute P1 (Immédiate)').waitFor();
    assert.equal(await page.locator('#host-plan details.sec-plan-item').count(), 3);
    assert.equal(await page.locator('#host-plan details.sec-plan-item').first().evaluate(d => d.open), true);
    await page.locator('#host-plan').getByText('sudo apt-get install --only-upgrade libssl3 openssl').first().waitFor();
    await page.locator('#host-plan').getByText('Copier le plan complet').click();
    await page.waitForFunction(() => window.__copied.some(t => t.startsWith('Plan de correction — web01')));
    await page.screenshot({path: path.join(OUT, 'security-host-tab.png'), fullPage: true});
    assert.equal(posts.length, before, 'fiche serveur : lecture seule');
    await page.locator('#host-cve [data-sec-goto-plan="' + vuln.id + '"]').click();
    await page.locator('#sec-tab-remediation.active').waitFor();
    await page.getByText('TEXTE À COPIER · RIEN N’EST EXÉCUTÉ').waitFor();
    // Correctifs : recommandations par serveur, puis plan complet d'un serveur.
    await page.locator('[data-sec-reco="web01"]').click();
    await page.locator('[data-sec-reco-plan]').getByText('Redémarrage en attente').waitFor();
    assert.equal(posts.length, before, 'recommandations : lecture seule');
    // Mobile : pas de défilement horizontal de la page.
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('[data-sec-tab="dashboard"]').click();
    await page.screenshot({path: path.join(OUT, 'security-mobile.png'), fullPage: true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), true, 'défilement horizontal en mobile');
    assert.deepEqual(errors, []);
    console.log('test_ui_security : OK');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
