// OpsControl V2 — dashboard de la Vue globale.
// Chargé avant v2.js : expose v2RefreshOps au cycle de vie du shell.

// ---------------------------------------------------------------------------
// 4. Vue globale : centre d'exploitation.
// ---------------------------------------------------------------------------
let v2Cockpit = null, v2CockpitAt = 0, v2CockpitLoading = false;
async function v2LoadCockpit(force = false) {
  if (v2CockpitLoading || (!force && Date.now() - v2CockpitAt < 30000)) return;
  v2CockpitLoading = true;
  try { v2Cockpit = await api('/api/v2/cockpit'); v2CockpitAt = Date.now(); }
  catch { v2Cockpit = v2Cockpit || null; }
  finally { v2CockpitLoading = false; }
  v2RefreshOps();
}

// Catégories exclusives : une preuve ancienne est « Ancien » quel que soit son
// dernier état — elle ne peut ni rassurer (OK) ni alarmer (Critique) à tort.
const V2_FLEET = ['ok', 'critical', 'warning', 'unreachable', 'unknown']
  .map(code => [code, sevLabel(code, true), SEVERITY[code].tone])
  .concat([['stale', SEVERITY.stale.plural + ' / jamais audités', SEVERITY.stale.tone]]);
function v2FleetCategory(h) {
  if (h.stale || !h.collected_at) return 'stale';
  return ['ok', 'critical', 'warning', 'unreachable'].includes(h.status) ? h.status : 'unknown';
}

function v2Fleet(hosts) {
  const counts = Object.fromEntries(V2_FLEET.map(([k]) => [k, 0]));
  hosts.forEach(h => counts[v2FleetCategory(h)]++);
  const audited = hosts.filter(h => (h.coverage?.measured || 0) > 0).length;
  const recent = hosts.length - counts.stale;
  const netFresh = hosts.filter(h => h.network_evidence?.fresh).length;
  return '<article class="panel v2-card v2-fleet">' +
    ui.head('État du parc', ui.sourceTag('Audit SSH') + ui.sourceTag('Ping') + ui.fresh(v2LatestSsh(hosts), 'Dernière mesure', 900), '<button data-go="Serveurs">Parc →</button>', 'PARC · ' + hosts.length + ' SERVEUR(S) SUIVI(S)') +
    ui.stack(V2_FLEET.map(([k, label, t]) => ({ label, value: counts[k], tone: t,
      attrs: k === 'stale' ? 'data-go="Audit"' : 'data-status="' + k + '"' })), { label: 'État des serveurs' }) +
    '<div class="v2-kpis">' +
    ui.kpi('Couverture audit', audited + ' / ' + hosts.length, 'Au moins un contrôle SSH mesuré', audited === hosts.length ? 'ok' : 'unknown', 'data-go="Audit"') +
    ui.kpi('Preuves récentes', recent + ' / ' + hosts.length, 'Audit SSH dans le délai', recent === hosts.length ? 'ok' : 'unknown', 'data-go="Audit"') +
    ui.kpi('Disponibilité mesurée', netFresh + ' / ' + hosts.length, 'Ping de moins de 15 min', netFresh === hosts.length ? 'ok' : 'unknown', 'data-go="Réseau"') +
    '</div><p class="v2-formula">Répartition exclusive, sans score agrégé : « Ancien » l’emporte sur tout état, « Inconnu » n’est jamais compté OK. ' +
    'OK = dernier audit récent et contrôles mesurés concluants.</p></article>';
}

const V2_LIMITS = { cpu: [90, 98], ram: [90, 97], disk_max: [80, 90] };
function v2CapacityRow(hosts, key, label) {
  const rows = hosts.filter(h => !h.stale && ui.measured(h[key])).map(h => ({ h, v: Number(h[key]) }));
  const [warn, crit] = V2_LIMITS[key];
  const top = rows.reduce((a, b) => (!a || b.v > a.v ? b : a), null);
  const over = rows.filter(r => r.v >= warn).length, critical = rows.filter(r => r.v >= crit).length;
  const med = ui.median(rows.map(r => r.v));
  return '<div class="v2-cap-row">' + ui.gauge(label + ' · médiane', med, {
      thresholds: [warn, crit], hue: key === 'ram' ? 'violet' : key === 'disk_max' ? 'cyan' : 'blue',
      detail: rows.length + ' / ' + hosts.length + ' serveurs mesurés' }) +
    '<div class="v2-cap-facts"><span>Maximum <b>' + (top ? ui.fmt(top.v) + ' %' : 'Non mesuré') + '</b>' +
    (top ? ' <button class="link" data-host="' + escAttr(top.h.key) + '">' + esc(top.h.name) + '</button>' : '') + '</span>' +
    '<span class="' + (critical ? 'v2-crit' : over ? 'v2-warn' : '') + '"><b>' + over + '</b> ≥ ' + warn + ' % · <b>' + critical + '</b> ≥ ' + crit + ' %</span></div></div>';
}

function v2Capacity(hosts) {
  const pve = (v2Cockpit?.sources || []).find(s => s.provider === 'Proxmox' && s.detail);
  const cap = pve?.detail?.capacity || {};
  const ratio = (a, b) => ui.measured(a) && Number(b) > 0 ? Number(a) / Number(b) * 100 : null;
  const pveBlock = pve ? '<div class="v2-subhead">Cluster Proxmox ' + ui.sourceTag('API Proxmox') + ui.fresh(pve.collected_at, 'Lecture', 900) + '</div>' +
    '<div class="v2-gauge-grid">' +
    ui.gauge('CPU nœuds', cap.cpu_pct, { detail: 'Moyenne des nœuds visibles', stale: !pve.fresh }) +
    ui.gauge('Mémoire', ratio(cap.memory_bytes, cap.memory_total_bytes), { hue: 'violet', thresholds: [85, 95], detail: ui.bytes(cap.memory_bytes) + ' / ' + ui.bytes(cap.memory_total_bytes), stale: !pve.fresh }) +
    ui.gauge('Stockage', ratio(cap.storage_used_bytes, cap.storage_total_bytes), { hue: 'cyan', thresholds: [80, 90], detail: ui.bytes(cap.storage_used_bytes) + ' / ' + ui.bytes(cap.storage_total_bytes), stale: !pve.fresh }) +
    '</div>' : '';
  return '<article class="panel v2-card v2-capacity">' +
    ui.head('Capacité observée', ui.sourceTag('Audit SSH') + '<span class="mini">Mesures récentes uniquement</span>', '<button data-go="Serveurs">Détail →</button>', 'CPU · RAM · DISQUE') +
    v2CapacityRow(hosts, 'cpu', 'CPU') + v2CapacityRow(hosts, 'ram', 'RAM') + v2CapacityRow(hosts, 'disk_max', 'Disque le plus rempli') +
    pveBlock + '</article>';
}

const V2_PAGES = { Proxmox: 'Proxmox', Zabbix: 'Zabbix', Wazuh: 'Wazuh', Elasticsearch: 'Elasticsearch', Bacula: 'Sauvegardes' };
function v2IntegrationLines(s) {
  const d = s.detail, n = v => v ?? 'Non mesuré';
  if (!d) return ['Aucune donnée collectée pour le moment.'];
  if (s.provider === 'Proxmox') return [
    n(d.capacity?.nodes_online) + ' / ' + n(d.nodes_count) + ' nœuds en ligne · quorum ' + (d.quorate === true ? 'actif' : d.quorate === false ? 'PERDU' : 'non mesuré'),
    n(d.counts?.running) + ' invités démarrés · ' + n(d.counts?.stopped) + ' arrêtés · ' + n(d.counts?.storage_unavailable) + ' stockage(s) indisponible(s)'];
  if (s.provider === 'Zabbix') return [
    n(d.counts?.monitored) + ' hôtes surveillés · ' + n(d.counts?.unmonitored) + ' non surveillés',
    d.problems_measured ? n(d.problem_counts?.critical) + ' problèmes critiques · ' + n(d.problem_counts?.warning) + ' avertissements' : 'Problèmes non mesurés'];
  if (s.provider === 'Wazuh') {
    const st = d.agents?.states || {};
    return ['Manager ' + (d.manager_version || 'version non mesurée') + ' · ' + n(d.daemons?.running) + ' démons actifs · ' + n(d.daemons?.failed) + ' en échec',
      d.agents ? n(st.active) + ' agents actifs · ' + n(st.disconnected) + ' déconnectés · ' + n(st.never_connected) + ' jamais connectés' : 'Agents non mesurés'];
  }
  if (s.provider === 'Elasticsearch') return [
    'Cluster ' + (d.cluster_status || 'état non mesuré') + ' · ' + n(d.number_of_nodes) + ' nœuds',
    n(d.unassigned_shards) + ' shards non affectés · ' + (ui.measured(d.active_shards_percent_as_number) ? ui.fmt(d.active_shards_percent_as_number) + ' % actifs' : 'part de shards actifs non mesurée')];
  if (s.provider === 'Bacula') return [
    'Dernier job par client : ' + n(d.latest_counts?.ok) + ' OK · ' + n(d.latest_counts?.critical) + ' en échec · ' + n(d.latest_counts?.warning) + ' avert. · ' + n(d.latest_counts?.running) + ' en cours',
    'Dernière réussite observée : ' + (d.last_success || 'non mesurée')];
  return [];
}
// « Sain » exige des indicateurs réellement mesurés : un compteur absent (null) n'est pas
// un zéro, et la tuile reste « inconnu » au lieu de passer au vert (audit SUP-07).
const v2Measured = v => v !== null && v !== undefined;
function v2IntegrationTone(s) {
  if (!s.fresh) return 'unknown';
  const d = s.detail || {};
  if (s.provider === 'Proxmox') {
    const online = d.capacity?.nodes_online, total = d.nodes_count;
    if (d.quorate === false || d.counts?.storage_unavailable) return 'critical';
    if (v2Measured(online) && v2Measured(total) && online < total) return 'warning';
    return d.quorate === true || (v2Measured(online) && v2Measured(total)) ? 'ok' : 'unknown';
  }
  if (s.provider === 'Elasticsearch') return ui.tone(d.cluster_status);
  if (s.provider === 'Zabbix') return d.problem_counts?.critical ? 'critical' : d.problem_counts?.warning ? 'warning' : d.problems_measured ? 'ok' : 'unknown';
  if (s.provider === 'Bacula') {
    const c = d.latest_counts || {};
    if (c.critical) return 'critical';
    if (c.warning || c.unknown) return 'warning';      // état de job non reconnu : à vérifier
    // Dernière réussite trop ancienne (RPO) ou job bloqué en cours : jamais vert (audit SUP-19).
    if (d.overdue_count) return 'warning';
    if (d.overdue_count === null) return 'unknown';
    return v2Measured(c.ok) && (c.ok + (c.running || 0) + (c.pending || 0)) > 0 ? 'ok' : 'unknown';
  }
  if (s.provider === 'Wazuh') {
    if (d.daemons?.failed) return 'critical';
    if (d.agents?.states?.disconnected || d.daemons?.stopped) return 'warning';
    return v2Measured(d.daemons?.running) && d.agents ? 'ok' : 'unknown';
  }
  return 'info';
}
function v2Integrations() {
  const sources = v2Cockpit?.sources || (state.availability?.sources || []).map(s => ({ ...s, detail: null, status: s.status }));
  const missing = v2Cockpit?.missing_providers || [];
  const tiles = sources.map(s => {
    const t = v2IntegrationTone(s);
    const label = s.status === 'retained' ? 'Échec · données conservées' : !s.fresh ? (s.collected_at ? 'Données anciennes' : 'Jamais collecté') : { ok: 'Sain observé', warning: 'Avertissement', critical: 'Critique', info: 'Observé' }[t] || 'Observé';
    return '<button class="v2-integration ' + t + '" data-go="' + escAttr(V2_PAGES[s.provider] || 'Connexions API') + '">' +
      '<span class="v2-int-head"><b>' + esc(s.provider) + '</b>' + ui.pill(label, s.fresh ? t : 'unknown') + '</span>' +
      '<small class="v2-int-name">' + esc(s.name) + '</small>' +
      v2IntegrationLines(s).map(l => '<span class="v2-int-line">' + esc(l) + '</span>').join('') +
      '<span class="v2-int-foot">' + ui.fresh(s.collected_at, 'Lecture API', 900) + '</span>' +
      (s.error ? '<span class="v2-int-error">' + esc(s.error) + '</span>' : '') +
      (s.auth_configured === false ? '<span class="v2-int-error">Identifiants absents dans cette instance</span>' : '') + '</button>';
  }).join('') + missing.map(p => '<button class="v2-integration unknown" data-go="Connexions API"><span class="v2-int-head"><b>' + esc(p) + '</b>' + ui.pill('Non raccordé', 'unknown') + '</span><span class="v2-int-line">Aucune connexion configurée : aucune donnée, aucun état déduit.</span></button>').join('');
  return '<article class="panel v2-card v2-integrations">' +
    ui.head('Sources de supervision', '<span class="mini">Âge de la dernière lecture réussie · récent = moins de 15 min</span>', '<button data-go="Sources">Centre Sources →</button>', 'PROXMOX · ZABBIX · WAZUH · ELASTIC · BACULA') +
    '<div class="v2-int-grid">' + (tiles || ui.empty('Aucune source API configurée', 'Ajouter une connexion en lecture seule.', '<button data-go="Connexions API">Configurer</button>')) + '</div>' +
    '<p class="v2-formula">La santé d’une source décrit ce que son compte de lecture voit, dans son périmètre de droits ; elle ne remplace pas l’audit de chaque serveur.</p></article>';
}

function v2HomeKpis(hosts) {
  const c = dailyData?.counts || {}, sources = v2Sources();
  // Numérateur et dénominateur sur la MÊME liste (serveurs suivis) : « 48 / 1 » venait d'un
  // numérateur compté sur tout l'inventaire et d'un dénominateur sur les seuls serveurs suivis.
  const online = hosts.filter(h => h.active_scope).length;
  const critical = c.critical_recent ?? hosts.filter(h => !h.stale && h.status === 'critical').length;
  const recentAudits = hosts.filter(h => !h.stale && h.coverage?.measured > 0).length;
  const missing = c.audit_missing ?? hosts.filter(h => !h.collected_at || !(h.coverage?.measured > 0)).length;
  // Même liste que la barre d'état (v2Sources) : les deux ne peuvent plus se contredire.
  const fresh = sources.filter(s => s.fresh).length, total = sources.length;
  return '<section class="panel v2-command-summary">' + ui.head('Situation maintenant',
    '<span class="mini">Quatre chiffres opérables · données datées, aucun score artificiel</span>',
    '<button data-v2-command>⌘ Rechercher</button>', 'VUE OPÉRATEUR') +
    '<div class="v2-command-kpis">' +
    // Disponibilité réseau seulement (fiche 01.3) : une VM démarrée qui répond au ping ne prouve
    // ni l'état du système ni le bon fonctionnement des applications.
    ui.kpi('Joignables (réseau)', online + ' / ' + hosts.length, 'VM démarrée et ping récent · applications non vérifiées', online === hosts.length ? 'ok' : 'warning', 'data-go="Réseau"') +
    // Zéro critique n'est rassurant que s'il existe des preuves récentes (audit SUP-10).
    ui.kpi('Critiques récents', critical, recentAudits ? 'Preuves récentes uniquement' : 'Aucune preuve récente : absence non confirmée',
      critical ? 'critical' : recentAudits ? 'ok' : 'unknown', 'data-go="Incidents"') +
    ui.kpi('Audits à compléter', missing, 'Absent, ancien ou sans mesure', missing ? 'unknown' : 'ok', 'data-go="Audit"') +
    ui.kpi('Sources récentes', fresh + ' / ' + total, 'Collectes API de moins de 15 min', total && fresh === total ? 'ok' : 'warning', 'data-go="Sources"') +
    '</div></section>';
}

function v2AttentionNow() {
  const groups = dailyData ? (dailyData.priority_groups || dailyGroupes(dailyData.priorities || [])) : [];
  const rows = groups.slice(0, 3).map(g => {
    const n = g.total ?? (g.hosts || g.hotes || []).length, old = g.stale_total ?? g.anciens ?? 0;
    return '<button class="v2-attention-row" data-go="Alertes"><span>' + badge(g.severity || 'unknown') +
      '<b>' + esc(g.title || 'Observation à examiner') + '</b></span><small>' + esc(g.source || 'SSH') +
      ' · ' + n + ' observation(s)' + (old ? ' · ' + old + ' ancienne(s)' : '') + '</small></button>';
  }).join('');
  return '<section class="panel v2-attention-now">' + ui.head('À traiter maintenant',
    '<span class="mini">Trois causes prioritaires, sans doublons par serveur</span>',
    // Anomalies chroniques (fiche 01.3) : exclues des compteurs, jamais cachées, à un clic.
    '<button data-v2-chronic>Chroniques' + (alertData?.counts?.chronic != null ? ' · ' + alertData.counts.chronic : '') + '</button><button data-go="Incidents">Tout voir →</button>', 'PRIORITÉS') +
    (rows || ui.empty('Aucune priorité récente dans les données disponibles', 'Vérifier la couverture avant de conclure.')) + '</section>';
}

function v2OpsMarkup() {
  if (!state) return '';
  const hosts = onlineHosts();
  return '<section class="console-hero" aria-label="Pilotage des opérations"><div><span class="console-eyebrow">OPÉRATIONS · INFRASTRUCTURE · SÉCURITÉ</span>'+
    // Introduction réduite (audit UI du 31/10, fiche 01.2) : la grande carte d'accroche repoussait
    // les indicateurs et les priorités sous la ligne de flottaison.
    '<h2>Votre parc, vos priorités.</h2>'+
    '<div class="console-hero-actions"><button class="primary" data-go="Incidents">Traiter les incidents →</button><button data-go="Sécurité">Examiner la sécurité</button>'+
    '<button data-go="Serveurs">Explorer les serveurs</button></div></div><div class="console-hero-scope"><span>PÉRIMÈTRE SUIVI</span><strong>'+hosts.length+
    '</strong><span>serveur(s) enregistré(s)</span><small>sur '+state.hosts.length+' entrée(s) de l’inventaire consolidé</small>'+ui.fresh(v2LatestSsh(hosts),'Dernier audit',900)+'</div></section>'+
    '<div class="v2-command-grid">' + v2HomeKpis(hosts) + v2AttentionNow() + '</div>' + v2Integrations() +
    '<details class="panel v2-home-details" data-v2-home-details><summary><b>Détails techniques</b>' +
    '<span class="mini">Parc, capacité et intégrations</span></summary><div class="v2-ops-grid">' +
    v2Fleet(hosts) + v2Capacity(hosts) + '</div></details>';
}
// La synthèse vit hors de #content, juste sous le bandeau d'alertes et avant les
// tuiles des serveurs critiques : sur l'accueil, elle est la première lecture.
const v2OpsZone = document.createElement('section');
v2OpsZone.id = 'v2-ops';
v2OpsZone.className = 'v2-ops';
v2OpsZone.setAttribute('aria-label', 'Centre d’exploitation');
v2OpsZone.hidden = true;
function v2PlaceOps() {
  // Ordre voulu : bandeau d'alertes → synthèse V2 → serveurs critiques → page.
  // Les deux autres zones sont créées paresseusement par leurs modules : on
  // rétablit l'ordre à chaque passage, sans jamais recréer leurs éléments.
  const strip = document.getElementById('alert-strip'), t0 = document.getElementById('t0-zone');
  // Les onglets d'un centre restent collés au contenu : les bandeaux globaux passent au-dessus.
  const content = $('#content'), tabs = document.getElementById('v2-hub-tabs');
  const tail = tabs && tabs.isConnected && (tabs.compareDocumentPosition(content) & Node.DOCUMENT_POSITION_FOLLOWING) ? tabs : content;
  if (t0 && t0.nextElementSibling !== tail) tail.before(t0);
  const anchor = t0 || tail;
  if (v2OpsZone.nextElementSibling !== anchor) anchor.before(v2OpsZone);
  if (strip && strip.nextElementSibling !== v2OpsZone) v2OpsZone.before(strip);
}
// Accueil : la zone principale, invisible jusqu'au premier rendu de la synthèse (boot.js, v2.css),
// s'affiche d'un seul coup. Échec ou lenteur des données : affichée au plus tard après 4 s,
// jamais laissée masquée.
function v2HomeReady() { document.documentElement.dataset.homeReady = '1'; }
function v2RefreshOps() {
  const home = page === 'Vue globale' && !selected && !!state;
  v2PlaceOps();
  v2OpsZone.hidden = !home;
  // Révéler seulement si l'écran n'est réellement pas l'accueil : sans données (state vide),
  // l'accueil n'est pas encore rendu, et le révéler laisserait la synthèse pousser la page.
  if (!home) { if (state && (page !== 'Vue globale' || selected)) v2HomeReady(); return; }
  const target = v2OpsZone;
  const html = v2OpsMarkup();
  if (target.dataset.signature === html) return;
  // Ne pas arracher le focus clavier d'un bouton de la synthèse pendant un rafraîchissement.
  const focused = target.contains(document.activeElement) ? [...target.querySelectorAll('button')].indexOf(document.activeElement) : -1;
  // Les âges relatifs changent le HTML à chaque passage : sans cela, un <details> ouvert
  // par l'opérateur se refermait toutes les 30 s.
  const open = openDetails(target);  // par identité, pas par position (app.js)
  target.dataset.signature = html;
  target.innerHTML = html;
  restoreDetails(target, open);
  v2HomeReady();
  if (focused >= 0) target.querySelectorAll('button')[focused]?.focus({ preventScroll: true });
}
// Les boutons de la synthèse sont hors de #content : on leur applique les mêmes actions.
v2OpsZone.addEventListener('click', async e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-v2-command')) v2OpenCommand();
  else if (b.hasAttribute('data-v2-chronic')) {
    if (typeof incFilters === 'object') Object.assign(incFilters, {state: 'active', chronic: 'only', offset: 0});
    navigate('Incidents');
  }
  else if (b.dataset.go) navigate(b.dataset.go);
  else if (b.dataset.status) { navigate('Serveurs'); filters = { q: '', status: b.dataset.status, environment: '', role: '' }; render(); v2SavePrefs(); }
  else if (b.dataset.host) await openHost(b.dataset.host, b);
});

// Lot 5 : abonnements au lieu de réaffecter overview/loadDaily/dailyMarkup.
beforeRenderHooks.push(() => { if (state && !selected && page === 'Vue globale') v2LoadCockpit(); });
dailyLoadHooks.push(v2RefreshOps);
sourceLoaders['Vue globale'] = async function () { v2LoadCockpit(); await loadDaily(); };

// Priorités : chaque observation ancienne porte son propre marqueur, en plus du compteur du groupe.
dailyGroupTransforms.push(function (html, g) {
  const hosts = g.hosts || g.hotes || [];
  if (!hosts.some(p => p.stale)) return html;
  let i = 0;
  return html.replace(/<div class="row"><button class="link" data-host="[^"]*">[^<]*<\/button>/g, m => {
    const p = hosts[i++];
    return p?.stale ? m + '<span class="badge unknown">Preuve ancienne</span>' : m;
  });
});

// Le détail des sources quitte l'accueil (lot 3) : il doublait les tuiles V2 (même âge de
// lecture affiché trois fois). Remplacement : le centre Sources, une ligne par source.
dailyMarkupTransforms.push(function (html) {
  const start = '<section class="panel"><div class="panel-head"><h2>Sources de supervision</h2>';
  const end = '</div></section><details class="panel"><summary><b>Couverture à compléter</b>';
  const i = html.indexOf(start), j = html.indexOf(end, i);
  const simplified = i >= 0 && j > i ? html.slice(0, i) +
    '<p class="note v2-sources-moved">Fraîcheur, erreurs et périmètre de chaque source : <button class="link" data-go="Sources">centre Sources</button>.</p>' +
    html.slice(j + '</div></section>'.length) : html;
  return '<details class="panel v2-home-journal"><summary><b>Journal et couverture</b><span class="mini">Historique, sources et données manquantes</span></summary><div class="v2-home-journal-body">' + simplified + '</div></details>';
});
