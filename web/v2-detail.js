// OpsControl V2 — fiche serveur, chargée à la première ouverture.
// Extensions déclaratives : detailView conserve son identité.

// ---------------------------------------------------------------------------
// 5. Fiche serveur V2 : résumé, rapprochement des sources, onglets supplémentaires.
// ---------------------------------------------------------------------------
function v2HostSources(host) {
  const linked = state?.hosts.find(h => h.key === host.key) || {};
  const net = host.network_evidence || linked.network_evidence || {};
  const details = host.source_details || [];
  const guests = host.proxmox_matches || linked.proxmox_matches || [];
  const backup = host.backup_summary || linked.backup_summary || {};
  const byProvider = p => details.find(s => s.provider === p);
  const rows = [];
  const sshTone = !host.collected_at ? 'unknown' : host.stale ? 'unknown' : host.status;
  rows.push(['SSH (audit)', host.collected_at ? (host.stale ? 'Audit ancien' : labels[host.status] || 'Non mesuré') : 'Jamais audité', sshTone, host.collected_at,
    (host.coverage?.measured ?? 0) + ' / ' + (host.coverage?.total ?? 0) + ' contrôles mesurés']);
  rows.push(['Réseau (ping)', !net.collected_at ? 'Non mesuré' : !net.fresh ? 'Mesure ancienne' : net.ping === true ? 'Répond' : net.ping === false ? 'Sans réponse' : 'Non mesuré',
    !net.fresh ? 'unknown' : net.ping === true ? 'ok' : net.ping === false ? 'critical' : 'unknown', net.collected_at, 'ICMP peut être filtré : un échec seul ne prouve pas une panne']);
  if (guests.length === 1) {
    const g = guests[0];
    rows.push(['Proxmox (VM)', (g.fresh ? '' : 'Ancien · ') + ({ running: 'Démarrée', stopped: 'Arrêtée' }[g.status] || 'Inconnu'),
      !g.fresh ? 'unknown' : g.status === 'running' ? 'ok' : g.status === 'stopped' ? 'warning' : 'unknown', g.collected_at, (g.cluster || '') + ' / ' + (g.node || '') + ' / VM ' + g.vmid]);
  } else rows.push(['Proxmox (VM)', guests.length ? 'Association ambiguë' : 'Non rapproché', 'unknown', null, guests.length ? guests.length + ' VM candidates' : 'Aucune VM associée sans ambiguïté']);
  const zbx = byProvider('Zabbix');
  if (zbx) {
    const probs = zbx.evidence?.problems || [];
    rows.push(['Zabbix', !zbx.fresh ? 'Ancien' : zbx.evidence?.problems_measured === false ? 'Problèmes non mesurés' : probs.length ? probs.length + ' problème(s)' : 'Aucun problème remonté',
      !zbx.fresh || zbx.evidence?.problems_measured === false ? 'unknown' : probs.length ? 'warning' : 'ok', zbx.collected_at, 'Hôte ' + ({ monitored: 'surveillé', unmonitored: 'non surveillé' }[zbx.evidence?.host?.status] || 'état non mesuré')]);
  } else rows.push(['Zabbix', 'Non rapproché', 'unknown', null, 'Hôte Zabbix non associé']);
  const waz = byProvider('Wazuh');
  if (waz?.evidence?.agent) {
    const a = waz.evidence.agent;
    rows.push(['Wazuh (agent)', (waz.fresh ? '' : 'Ancien · ') + ({ active: 'Actif', disconnected: 'Déconnecté', never_connected: 'Jamais connecté', pending: 'En attente' }[a.status] || 'Inconnu'),
      !waz.fresh ? 'unknown' : a.status === 'active' ? 'ok' : a.status === 'disconnected' ? 'critical' : a.status === 'never_connected' ? 'warning' : 'unknown', waz.collected_at, 'Agent ' + (a.version || 'version non mesurée')]);
  } else rows.push(['Wazuh (agent)', 'Non rapproché', 'unknown', waz?.collected_at || null, 'Agent non associé : protection non démontrée']);
  if (backup.matched) {
    const t = backup.fresh ? ({ ok: 'ok', critical: 'critical', warning: 'warning', running: 'info' }[backup.severity] || 'unknown') : 'unknown';
    rows.push(['Bacula (sauvegarde)', (backup.fresh ? '' : 'Ancien · ') + ({ ok: 'Derniers jobs réussis', critical: 'Dernier passage en erreur', warning: 'Avertissement', running: 'En cours' }[backup.severity] || 'Résultat non mesuré'),
      t, backup.collected_at, backup.jobs_count + ' job(s) · dernière réussite ' + (backup.last_success || 'non mesurée')]);
  } else rows.push(['Bacula (sauvegarde)', 'Aucun job associé', 'unknown', null, 'Aucune sauvegarde observée : ce n’est pas une preuve d’absence']);
  return rows;
}

function v2HostSummary(host) {
  const rows = v2HostSources(host);
  const table = '<div class="table v2-source-matrix"><table><caption class="note">Chaque ligne est une observation indépendante, avec sa propre date. Les sources ne se remplacent pas entre elles.</caption><thead><tr><th scope="col">Source</th><th scope="col">État observé</th><th scope="col">Âge de la preuve</th><th scope="col">Détail</th></tr></thead><tbody>' +
    rows.map(([src, label, t, at, detail]) => '<tr><td><b>' + esc(src) + '</b></td><td>' + ui.pill(label, t) + '</td><td>' + (at ? ui.fresh(at, 'Donnée', 900) : '<span class="mini">Aucune donnée</span>') + '</td><td class="v2-wrap">' + esc(detail) + '</td></tr>').join('') +
    '</tbody></table></div>';
  return '<section class="panel v2-card v2-host-sources">' + ui.head('Rapprochement des sources', '<span class="mini">SSH, réseau, Proxmox, Zabbix, Wazuh, Bacula</span>', '', 'PROVENANCE') + table + '</section>';
}

function v2HostGauges(host) {
  const stale = !!host.stale;
  return '<div class="v2-gauge-grid v2-host-gauges">' +
    ui.gauge('CPU', host.cpu, { thresholds: V2_LIMITS.cpu, stale, source: 'SSH', detail: stamp(host.collected_at) }) +
    ui.gauge('RAM', host.ram, { thresholds: V2_LIMITS.ram, hue: 'violet', stale, source: 'SSH', detail: stamp(host.collected_at) }) +
    '<div class="host-capacity-summary'+(!host.storage_assessment?.fresh?' sev-none':'')+'">'+(host.storage_assessment?.capacity ?
      '<strong>'+esc(host.storage_assessment.capacity.mount)+'</strong> '+badge(host.storage_assessment.fresh?host.storage_assessment.capacity.capacity_severity:'unknown')+
      '<p>'+esc(host.storage_assessment.capacity.use_pct)+' % · '+esc(storageSize(host.storage_assessment.capacity.available_kb))+' disponibles</p>' :
      '<strong>Volume à identifier</strong><p>'+esc(host.disk_max==null?'Capacité non mesurée':host.disk_max+' % relevés — périmètre à vérifier')+'</p>')+
      '<p class="note">'+esc(stamp(host.storage_assessment?.collected_at||host.collected_at))+' · '+(host.storage_assessment?.fresh?'Mesure SSH récente':'Ancien ou non mesuré : état actuel non confirmé')+'</p>'+
      '<button data-goto-tab="storage">Volumes et inodes →</button></div>' +
    '</div>';
}

const v2ObsCache = new Map(), v2ObsLoading = new Set(), v2ObsFilters = new Map();
async function v2LoadObservability(key, force = false) {
  if (v2ObsLoading.has(key) || (!force && v2ObsCache.has(key))) return;
  v2ObsLoading.add(key);
  try { v2ObsCache.set(key, await api('/api/hosts/' + encodeURIComponent(key) + '/observability')); }
  catch (error) { v2ObsCache.set(key, { error: error.message, points: [], changes: [], trends: {} }); }
  finally { v2ObsLoading.delete(key); }
  if (selected === key && ['performance', 'incidents'].includes(detailTab)) render();
}
function v2TrendChart(data, key, label) {
  const values = (data.points || []).map((point, index) => ({ index, value: point[key] })).filter(p => ui.measured(p.value));
  const trend = data.trends?.[key] || {}, n = Math.max(1, (data.points || []).length - 1);
  const points = values.map(p => (p.index / n * 100).toFixed(2) + ',' + (72 - Number(p.value) * .64).toFixed(2)).join(' ');
  const latest = ui.measured(trend.last) ? ui.fmt(trend.last) + ' %' : 'Non mesuré';
  const delta = ui.measured(trend.delta) ? (trend.delta > 0 ? '+' : '') + ui.fmt(trend.delta) + ' pts' : 'Tendance indisponible';
  return '<article class="v2-trend-card"><header><span>' + esc(label) + '</span><strong>' + esc(latest) + '</strong></header>' +
    (values.length ? '<svg viewBox="0 0 100 80" role="img" aria-label="Évolution ' + esc(label) + '"><path class="v2-chart-grid" d="M0 8H100 M0 40H100 M0 72H100"/><polyline class="v2-chart-line v2-chart-' + key + '" points="' + points + '"/></svg>' : '<div class="v2-chart-empty">Aucune mesure</div>') +
    '<footer><span class="v2-trend-' + esc(trend.direction || 'stable') + '">' + esc(delta) + '</span><small>' + esc(trend.samples || 0) + ' point(s)</small></footer></article>';
}
function v2Timeline(host, data) {
  const rows = (data.changes || []).map(c => ({ ...c, type: 'changes' }));
  for (const alert of host.alerts?.items || []) rows.push({ at: alert.observed_at, type: 'alerts', source: alert.source,
    title: alert.title, severity: alert.severity, evidence: alert.evidence, fresh: alert.fresh });
  for (const source of host.source_details || []) rows.push({ at: source.collected_at, type: 'sources', source: source.provider,
    title: source.fresh ? 'Source observée récemment' : source.error ? 'Collecte en échec' : 'Observation ancienne',
    severity: source.fresh ? 'ok' : source.error ? 'warning' : 'unknown', evidence: source.error || source.scope });
  const network = host.network_evidence || {};
  if (network.collected_at) rows.push({ at: network.collected_at, type: 'sources', source: 'Réseau',
    title: network.ping === true ? 'Ping réussi' : network.ping === false ? 'Ping sans réponse' : 'Ping non mesuré',
    severity: !network.fresh ? 'unknown' : network.ping === true ? 'ok' : network.ping === false ? 'critical' : 'unknown' });
  for (const job of host.batches || []) if (job.collected_at || job.last_run) rows.push({ at: job.collected_at || job.last_run,
    type: 'sources', source: 'Batch', title: job.name + ' · ' + (job.state || 'état inconnu'),
    severity: job.state === 'failed' ? 'critical' : job.state === 'running' ? 'info' : 'unknown' });
  const filter = v2ObsFilters.get(host.key) || 'all';
  const filtered = rows.filter(r => r.at && (filter === 'all' || r.type === filter)).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50);
  return '<div class="v2-timeline">' + (filtered.map(row => '<article class="v2-timeline-row ' + esc(row.severity || 'unknown') + '">' +
    '<time datetime="' + escAttr(row.at) + '">' + esc(stamp(row.at)) + '</time><span class="v2-timeline-dot" aria-hidden="true"></span><div><header>' +
    ui.pill(row.source || 'OpsControl', row.severity || 'unknown') + '<b>' + esc(row.title) + '</b></header>' +
    (row.evidence ? '<p>' + esc(row.evidence) + '</p>' : '') + (!row.fresh && row.type === 'alerts' ? '<small>Observation à reconfirmer</small>' : '') + '</div></article>').join('') ||
    ui.empty('Aucun événement dans cette sélection', 'Les absences de mesure ne sont pas transformées en événements.')) + '</div>';
}
// Historique compact (une requête, chargée à la demande) : tendances dans l'onglet
// Performances, chronologie unifiée dans l'onglet Incidents.
function v2ObsState(host, title) {
  const data = v2ObsCache.get(host.key);
  if (!data) { v2LoadObservability(host.key); return { html: '<section class="panel"><h2>' + esc(title) + '</h2><p>Chargement de l’historique compact…</p></section>' }; }
  if (data.error) return { html: '<section class="panel">' + ui.empty('Historique indisponible', data.error, '<button data-v2-obs-retry="' + escAttr(host.key) + '">Réessayer</button>') + '</section>' };
  return { data };
}
function v2TrendsSection(host) {
  const { html, data } = v2ObsState(host, 'Tendances sur 7 jours');
  if (!data) return html;
  return '<section class="panel v2-observability">' + ui.head('Tendances sur 7 jours',
    ui.sourceTag('Audits SSH conservés') + '<span class="mini">' + esc(data.samples) + ' point(s) · aucune collecte supplémentaire</span>',
    '<button data-v2-obs-retry="' + escAttr(host.key) + '">↻ Actualiser</button>', 'HISTORIQUE COMPACT') +
    '<div class="v2-trends">' + v2TrendChart(data, 'cpu', 'CPU') + v2TrendChart(data, 'ram', 'RAM') + '</div>' +
    '<p class="note">Capacité et inodes : historique par volume dans <button class="link" data-goto-tab="storage">Stockage</button>.</p>' +
    '<p class="v2-formula">' + esc(data.scope) + '</p></section>';
}
function v2TimelineSection(host) {
  const { html, data } = v2ObsState(host, 'Chronologie unifiée');
  if (!data) return html;
  const filter = v2ObsFilters.get(host.key) || 'all';
  return '<section class="panel v2-chronology"><div class="v2-timeline-head"><div><h2>Chronologie unifiée</h2><p>Changements SSH et dernières preuves réseau, Zabbix, Wazuh, Bacula et Batch.</p></div>' +
    '<label>Afficher <select data-v2-obs-filter><option value="all">Tout</option><option value="changes" ' + (filter === 'changes' ? 'selected' : '') + '>Changements</option><option value="alerts" ' + (filter === 'alerts' ? 'selected' : '') + '>Alertes</option><option value="sources" ' + (filter === 'sources' ? 'selected' : '') + '>Sources</option></select></label></div>' +
    v2Timeline(host, data) + '</section>';
}
// Synthèse : trois points à traiter au plus, chacun avec sa source ; le détail est dans Incidents.
function v2HostPriorities(host) {
  const rank = { critical: 0, unreachable: 1, warning: 2 };
  const alerts = (host.alerts?.items || []).filter(a => a.fresh && a.severity in rank)
    .sort((a, b) => rank[a.severity] - rank[b.severity]).slice(0, 3);
  const old = (host.alerts?.items || []).filter(a => !a.fresh).length;
  return '<section class="panel v2-host-priorities">' + ui.head('À traiter sur ce serveur', '<span class="mini">Alertes récentes uniquement · ' + old + ' à reconfirmer</span>',
    '<button data-goto-tab="incidents">Tous les incidents →</button>') +
    (alerts.map(a => '<div class="row"><div>' + ui.pill(labels[a.severity] || a.severity, a.severity) + ' <b>' + esc(a.title) + '</b><p>' + esc(a.source) +
      ' · ' + esc(stamp(a.observed_at)) + '</p></div></div>').join('') ||
      ui.empty('Aucune alerte récente pour ce serveur', host.stale || !host.collected_at ? 'Audit SSH ancien ou absent : ce n’est pas une preuve de bon état.' : 'Vérifier la fraîcheur des sources ci-dessus avant de conclure.')) + '</section>';
}
let v2NetCache = null, v2NetAt = 0;
async function v2LoadNet() {
  if (Date.now() - v2NetAt < 30000 && v2NetCache) return;
  try { v2NetCache = await api('/api/network'); v2NetAt = Date.now(); } catch (e) { v2NetCache = { error: e.message, hosts: [] }; }
  if (selected && detailTab === 'network') render();
}
// Après « Vérifier » (endpoint réseau existant), relire la mesure une fois la sonde passée.
$('#content').addEventListener('click', e => {
  const retry = e.target.closest('[data-v2-obs-retry]');
  if (retry) { v2ObsCache.delete(retry.dataset.v2ObsRetry); v2LoadObservability(retry.dataset.v2ObsRetry, true); }
  if (selected && e.target.closest('[data-net-host]')) setTimeout(() => { v2NetAt = 0; v2LoadNet(); }, 4000);
});
$('#content').addEventListener('change', e => {
  if (e.target.hasAttribute('data-v2-obs-filter') && hostDetail) { v2ObsFilters.set(hostDetail.key, e.target.value); render(); }
});
function v2NetworkTab(host) {
  if (!v2NetCache) { v2LoadNet(); return '<div class="panel">Chargement des mesures réseau…</div>'; }
  const n = (v2NetCache.hosts || []).find(h => h.key === host.key);
  if (!n) return '<div class="panel">' + ui.empty('Aucune mesure réseau pour ce serveur', v2NetCache.error || 'Lancer une vérification réseau.', '<button data-net-host="' + escAttr(host.key) + '">Vérifier le réseau</button>') + '</div>';
  const yn = v => v === true ? ui.pill('Oui', 'ok') : v === false ? ui.pill('Non', 'critical') : ui.pill('Non mesuré', 'unknown');
  return '<section class="panel">' + ui.head('Réseau et accès SSH', ui.sourceTag('Sonde réseau OpsControl') + ui.fresh(n.collected_at, 'Mesure', 900), '<button data-net-host="' + escAttr(host.key) + '">↻ Vérifier</button>') +
    '<div class="v2-kpis">' + ui.kpi('Ping ICMP', n.ping === true ? 'Répond' : n.ping === false ? 'Sans réponse' : 'Non mesuré', 'ICMP peut être filtré', n.ping === true ? 'ok' : n.ping === false ? 'critical' : 'unknown') +
    ui.kpi('Clé hôte SSH', n.ssh_key_known === true ? 'Connue' : n.ssh_key_known === false ? 'Inconnue' : 'Non mesuré', 'Comparée au known_hosts', n.ssh_key_known === true ? 'ok' : n.ssh_key_known === false ? 'warning' : 'unknown') +
    ui.kpi('Ports observés', (n.ports || []).filter(p => p.ok).length + ' / ' + (n.ports || []).length, 'Ports TCP testés ouverts', '') + '</div>' +
    '<div class="table"><table><thead><tr><th>Port TCP</th><th>Ouvert</th></tr></thead><tbody>' + ((n.ports || []).map(p => '<tr><td>' + esc(p.port) + '</td><td>' + yn(p.ok) + '</td></tr>').join('') || '<tr><td colspan="2">Aucun port testé</td></tr>') + '</tbody></table></div>' +
    (host.fingerprint ? '<p class="note">Empreinte de configuration de l’audit : <code>' + esc(host.fingerprint.slice(0, 16)) + '…</code></p>' : '') +
    '<p class="note">Mesure en lecture : ping, connexion TCP, présence de l’empreinte dans known_hosts. Aucune clé n’est ajoutée automatiquement.</p></section>';
}
function v2BackupTab(host) {
  const b = host.backup_summary || state?.hosts.find(h => h.key === host.key)?.backup_summary || {};
  const bac = (host.source_details || []).find(s => s.provider === 'Bacula');
  const jobs = bac?.evidence?.recent_jobs || [];
  const tone = s => ({ ok: 'ok', critical: 'critical', warning: 'warning', running: 'info' }[s] || 'unknown');
  return '<section class="panel">' + ui.head('Sauvegardes observées', ui.sourceTag('API Bacula') + (b.collected_at ? ui.fresh(b.collected_at, 'Lecture', 900) : ''), '<button data-go="Sauvegardes">Toutes les sauvegardes →</button>') +
    (b.matched ? '<div class="v2-kpis">' + ui.kpi('Dernier résultat', { ok: 'Réussi', critical: 'En erreur', warning: 'Avertissement', running: 'En cours', pending: 'En attente' }[b.severity] || 'Non mesuré', b.fresh ? 'Collecte récente' : 'À reconfirmer', b.fresh ? tone(b.severity) : 'unknown') +
      ui.kpi('Jobs associés', b.jobs_count, 'Par nom et client, sans ambiguïté') + ui.kpi('Dernière réussite', b.last_success || 'Non mesurée', 'Fin de job observée', b.last_success ? '' : 'unknown') + '</div>' : ui.empty('Aucun job Bacula associé à ce serveur', 'Une configuration documentaire ne prouve pas qu’une sauvegarde a réussi.')) +
    (jobs.length ? '<div class="table"><table><thead><tr><th>Job</th><th>Résultat</th><th>Fin</th></tr></thead><tbody>' + jobs.map(j => '<tr><td>' + esc(j.name) + '</td><td>' + ui.pill(j.status_label || 'Non mesuré', tone(j.severity)) + '</td><td>' + esc(j.endtime || 'Non mesurée') + '</td></tr>').join('') + '</tbody></table></div>' : '') +
    '<p class="note">' + esc(b.scope || 'Dernier passage connu par job et client. Ne prouve pas la restaurabilité.') + '</p>' +
    (host.documented?.backup ? '<p class="note">Documentation (non observée) : ' + esc(host.documented.backup.paths || 'chemins non renseignés') + ' · rétention ' + esc(host.documented.backup.retention || 'non renseignée') + '</p>' : '') + '</section>';
}
// Lien vers l'analyse CVE du serveur : la page Sécurité (module paresseux) lit cette demande
// à son affichage ; capture pour passer avant la navigation déclenchée par data-go.
document.addEventListener('click', e => {
  const b = e.target.closest('[data-sec-goto-host],[data-sec-goto-plan],[data-sec-goto-mplan]');
  if (!b) return;
  if (b.dataset.secGotoHost) window.secRequestedHost = b.dataset.secGotoHost;
  if (b.dataset.secGotoPlan) window.secRequestedPlan = b.dataset.secGotoPlan;
  if (b.dataset.secGotoMplan) window.secRequestedMatchPlan = b.dataset.secGotoMplan;
}, true);

// Vulnérabilités CVE collectées pour CE serveur (/api/security/hosts/<clé> et la veille filtrée
// sur le serveur) : lues à l'ouverture de l'onglet Sécurité, en GET uniquement, relues au plus
// toutes les 60 s. Les actions (analyse, validation, correction, GLPI) restent dans Sécurité.
const hostCve = {key: null, at: 0, host: null, watch: null, plan: null, error: '', loading: false};
const HOST_CVE_SEVERITY = {critical: ['Critique', 'critical'], high: ['Élevée', 'warning'], medium: ['Moyenne', 'info'], low: ['Faible', 'unknown']};
const HOST_CVE_STATUS = {open: ['Détectée', 'warning'], validated: ['Validée', 'critical'], in_progress: ['Correction planifiée', 'info'],
  resolved: ['Corrigée (constatée)', 'ok'], false_positive: ['Faux positif', 'unknown'], accepted_risk: ['Risque accepté', 'unknown']};
const HOST_CVE_SOURCES = {debian: 'Debian', wazuh: 'Wazuh', upstream: 'Éditeur / NVD', manual: 'Vérifiée'};

function hostCveWhen(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? esc(value) : '<span title="' + escAttr(stamp(value)) + '">' +
    d.toLocaleString('fr-FR', {day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit'}) + '</span>';
}
function hostCveLink(cve) {
  if (/^GHSA(-[a-z0-9]{4}){3}$/.test(cve || '')) return '<a href="https://github.com/advisories/' + escAttr(cve) + '" target="_blank" rel="noopener noreferrer">' + esc(cve) + '</a>';
  return /^CVE-\d{4}-\d{4,7}$/.test(cve || '') ? '<a href="https://nvd.nist.gov/vuln/detail/' + escAttr(cve) + '" target="_blank" rel="noopener noreferrer">' + esc(cve) + '</a>' : esc(cve || '—');
}
function hostCveTable(headers, rows, empty) {
  if (!rows.length) return '<p class="mini">' + esc(empty) + '</p>';
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th scope="col">' + h + '</th>').join('') + '</tr></thead><tbody>' +
    rows.map(r => '<tr>' + r.map(c => '<td>' + (c ?? '—') + '</td>').join('') + '</tr>').join('') + '</tbody></table></div>';
}
function hostCveLoad(key, force = false) {
  if (hostCve.loading || (!force && hostCve.key === key && Date.now() - hostCve.at < 60000)) return;
  if (hostCve.key !== key) Object.assign(hostCve, {key, host: null, watch: null, plan: null, error: ''});
  hostCve.loading = true;
  Promise.all([api('/api/security/hosts/' + encodeURIComponent(key)), api('/api/security/watch?days=30&limit=500&host=' + encodeURIComponent(key)).catch(() => null),
    api('/api/security/hosts/' + encodeURIComponent(key) + '/recommendations').catch(() => null)])
    .then(([host, watch, plan]) => Object.assign(hostCve, {host, watch, plan, error: '', at: Date.now()}))
    .catch(error => Object.assign(hostCve, {error: error.status === 404 ? 'Module Sécurité indisponible sur le serveur OpsControl actif : redémarrez-le.' : error.message, at: Date.now()}))
    .finally(() => {
      hostCve.loading = false;
      const target = document.getElementById('host-cve');
      if (target && target.dataset.host === key) target.innerHTML = hostCveMarkup(key);
      const plan = document.getElementById('host-plan');
      if (plan && plan.dataset.host === key) plan.innerHTML = hostPlanMarkup(key);
    });
}
function hostCveMarkup(key) {
  if (hostCve.key !== key || (!hostCve.host && !hostCve.error)) return '<p role="status">Chargement des vulnérabilités collectées…</p>';
  if (hostCve.error) return '<p class="form-error" role="alert">' + esc(hostCve.error) + '</p>';
  const d = hostCve.host, w = hostCve.watch;
  const active = d.vulns.filter(v => ['open', 'validated', 'in_progress'].includes(v.status));
  const closed = d.vulns.filter(v => !['open', 'validated', 'in_progress'].includes(v.status));
  const kev = active.filter(v => v.kev).length, critical = active.filter(v => v.severity === 'critical').length;
  const matches = (w?.cves || []).flatMap(c => c.hosts.filter(m => m.host_key === key).map(m => ({...m, c})));
  const potential = matches.filter(m => m.status === 'potential');
  const notApplicable = matches.filter(m => m.status === 'not_applicable');
  const os = d.os || {};
  const kpis = '<div class="v2-kpis">' +
    ui.kpi('Vulnérabilités ouvertes', active.length, critical + ' critique(s) · ' + kev + ' exploitée(s) (KEV)', kev || critical ? 'critical' : active.length ? 'warning' : d.collected_at ? 'ok' : 'unknown') +
    ui.kpi('À vérifier', potential.length, 'Applicabilité potentielle (rétroportage, version incomplète)', potential.length ? 'warning' : '') +
    ui.kpi('Relevé des paquets', d.collected_at ? d.packages_count + ' paquet(s)' : 'Jamais relevé', d.collected_at ? 'Le ' + new Date(d.collected_at).toLocaleString('fr-FR') + (d.account ? ' · ' + d.account : '') : 'Lancer « Analyser » dans Sécurité', d.collected_at ? '' : 'unknown') +
    ui.kpi('Système', os.pretty || 'Inconnu', d.support ? d.support.label : 'Fin de support non référencée', d.support?.expired ? 'critical' : '') +
    ui.kpi('Redémarrage requis', d.reboot_required ? 'Oui' : d.collected_at ? 'Non signalé' : 'Non mesuré', 'Noyau en cours : ' + (d.kernel || '—'), d.reboot_required ? 'warning' : '') +
    ui.kpi('Wazuh (vulnérabilités)', d.wazuh ? d.wazuh.items + ' détection(s)' : 'Aucune donnée', d.wazuh ? 'Agent ' + d.wazuh.agent_id + ' · ' + new Date(d.wazuh.at).toLocaleString('fr-FR') : 'Agent non rapproché ou indexeur non configuré', d.wazuh ? '' : 'unknown') + '</div>';
  const vulnRows = active.map(v => {
    const [label, tone] = HOST_CVE_SEVERITY[v.severity] || ['Non évaluée', 'unknown'];
    const score = v.cvss ?? v.evidence?.wazuh?.cvss;
    const [status, statusTone] = HOST_CVE_STATUS[v.status] || [v.status, 'unknown'];
    return [ui.pill(label + (score != null ? ' ' + Number(score).toFixed(1) : ''), tone) + (v.kev ? ' ' + ui.pill('KEV', 'critical', 'Exploitée activement — échéance ' + (v.kev_due || '')) : ''),
      hostCveLink(v.cve) + (v.description ? '<small>' + esc(v.description.slice(0, 120)) + '</small>' : ''),
      '<b>' + esc(v.package) + '</b><small>' + esc((v.evidence?.binaries || []).slice(0, 4).join(', ')) + '</small>',
      esc(v.installed || '?') + ' → <b>' + esc(v.fixed || 'non fournie') + '</b>' + (v.evidence?.comparison ? '<small>' + esc(v.evidence.comparison) + '</small>' : ''),
      esc((v.sources || []).map(s => HOST_CVE_SOURCES[s] || s).join(' + ')) + '<small>' + esc(v.evidence?.source || '') + '</small>',
      ui.pill(v.confidence, v.confidence === 'confirmé' ? 'critical' : v.confidence === 'détecté' ? 'warning' : 'unknown', v.evidence?.reason || '') + '<small>' + esc(v.evidence?.reason || '') + '</small>',
      ui.pill(status, statusTone) + (typeof itsmBadge === 'function' ? itsmBadge('vulnerability', v.id, true) : '') + '<small>Depuis le ' + esc(new Date(v.first_seen).toLocaleDateString('fr-FR')) + '</small>',
      '<button data-go="Sécurité" data-sec-goto-plan="' + escAttr(v.id) + '">Préparer la correction</button>'];
  });
  const potentialRows = potential.map(m => [hostCveLink(m.c.cve) + '<small>' + esc(m.c.priority?.rank || '') + ' · ' + (m.c.cvss != null ? 'CVSS ' + m.c.cvss : '') + '</small>',
    esc(m.tech_label) + '<small>' + esc(m.instance) + '</small>', esc(m.version || 'inconnue') + ' → <b>' + esc(m.fixed || 'non publiée') + '</b>', esc(m.reason || ''),
    '<button data-go="Sécurité" data-sec-goto-mplan="' + escAttr(m.id + '|' + m.c.cve) + '">Vérifier et préparer</button>']);
  const comps = hostCveTable(['Composant', 'Versions installées', 'Paquets', 'Version annoncée'],
    (d.components || []).map(c => ['<b>' + esc(c.component) + '</b>', esc(c.versions.join(', ')), esc(c.packages.join(', ')), esc(c.binary || '—')]), 'Aucun composant clé relevé.');
  const dk = d.docker || {};
  const docker = dk.state === 'ok' ? hostCveTable(['Conteneur', 'Image', 'État'], dk.containers.map(c => [esc(c.name), esc(c.image), esc(c.status)]), 'Aucun conteneur en cours.') +
    (dk.findings.length ? hostCveTable(['Image', 'Tag', 'À vérifier'], dk.findings.map(f => [esc(f.repository), esc(f.tag), ui.pill(f.finding, f.level)]), '') : '')
    : '<p class="mini">' + esc({absent: 'Docker absent.', denied: 'Docker présent, accès refusé au compte de supervision.', error: 'Docker : erreur de lecture.'}[dk.state] || 'Docker non relevé.') + '</p>';
  const scans = hostCveTable(['Date', 'Résultat', 'Paquets', 'Par'], (d.scans || []).slice(0, 10).map(s => [hostCveWhen(s.at),
    esc(s.status) + (s.detail ? '<small>' + esc(s.detail) + '</small>' : ''), s.packages ?? '—', esc(s.actor || '')]), 'Aucun relevé.');
  return kpis +
    '<h3 class="section-title">Vulnérabilités ouvertes <span class="state-count">' + active.length + '</span></h3>' +
    hostCveTable(['Gravité', 'CVE', 'Paquet', 'Installée → corrigée', 'Sources', 'Confiance', 'Statut', ''], vulnRows,
      d.collected_at ? 'Aucune vulnérabilité ouverte prouvée sur ce serveur (relevé du ' + new Date(d.collected_at).toLocaleString('fr-FR') + ').' :
        'Aucun relevé des paquets : ce serveur n’a jamais été analysé, aucune conclusion possible.') +
    '<h3 class="section-title">À vérifier (applicabilité potentielle) <span class="state-count">' + potential.length + '</span></h3>' +
    hostCveTable(['CVE', 'Technologie', 'Version → cible', 'Pourquoi potentielle', ''], potentialRows, w ? 'Aucune CVE potentielle.' : 'Veille non disponible.') +
    (closed.length || notApplicable.length ? '<details><summary>Corrigées, écartées et non applicables (' + (closed.length + notApplicable.length) + ')</summary>' +
      hostCveTable(['CVE', 'Composant', 'État', 'Détail'], closed.map(v => [hostCveLink(v.cve), esc(v.package + ' ' + (v.installed || '')),
        ui.pill((HOST_CVE_STATUS[v.status] || [v.status])[0], (HOST_CVE_STATUS[v.status] || [0, 'unknown'])[1]), esc(v.note || (v.resolved_at ? 'Corrigée le ' + new Date(v.resolved_at).toLocaleString('fr-FR') : ''))])
        .concat(notApplicable.map(m => [hostCveLink(m.c.cve), esc(m.tech_label + ' ' + (m.version || '')), ui.pill('Non applicable', 'ok'), esc(m.reason || '')])), '') + '</details>' : '') +
    '<details><summary>Preuves du relevé : composants, Docker, relevés récents</summary><h4>Composants (PHP, Apache, OpenSSL…)</h4>' + comps +
    '<h4>Docker</h4>' + docker + '<h4>Relevés des paquets</h4>' + scans + '</details>' +
    '<p class="v2-formula">' + esc(d.scope || '') + ' Une vulnérabilité n’est ouverte que sur preuve (avis de la distribution, Wazuh, ou version d’un artefact de l’éditeur dans une plage publiée).</p>';
}
function hostCveSection(host) {
  return '<section class="panel">' + ui.head('Vulnérabilités CVE collectées', ui.sourceTag('Relevé SSH des paquets') + ui.sourceTag('Debian') + ui.sourceTag('Wazuh') + ui.sourceTag('NVD / éditeurs'),
    '<button data-host-cve-refresh="' + escAttr(host.key) + '">Relire</button> <button data-go="Sécurité" data-sec-goto-host="' + escAttr(host.key) + '">Analyser ce serveur →</button>') +
    '<div id="host-cve" data-host="' + escAttr(host.key) + '">' + hostCveMarkup(host.key) + '</div></section>';
}
// Plan de correction consolidé : vulnérabilités et risques du serveur, par priorité.
function hostPlanMarkup(key) {
  if (hostCve.key !== key || (!hostCve.host && !hostCve.error)) return '<p role="status">Chargement du plan de correction…</p>';
  if (hostCve.error) return '<p class="mini">Plan de correction indisponible : ' + esc(hostCve.error) + '</p>';
  if (!hostCve.plan) return '<p class="mini">Plan de correction indisponible sur le serveur OpsControl actif : redémarrez-le.</p>';
  return typeof securityPlanMarkup === 'function' ? securityPlanMarkup(hostCve.plan) : '';
}
function hostPlanSection(host) {
  return '<section class="panel">' + ui.head('Recommandations de correction', ui.sourceTag('Vulnérabilités prouvées') + ui.sourceTag('Veille') + ui.sourceTag('Audit SSH') + ui.sourceTag('Inventaire'),
    '', 'PLAN CONSOLIDÉ · TEXTE À COPIER') + '<div id="host-plan" data-host="' + escAttr(host.key) + '">' + hostPlanMarkup(host.key) + '</div></section>';
}
detailAfterRenderers.push(h => { if (selected && detailTab === 'security' && h?.key) hostCveLoad(h.key); });
document.addEventListener('click', e => {
  const b = e.target.closest('[data-host-cve-refresh]');
  if (b) hostCveLoad(b.dataset.hostCveRefresh, true);
});
function v2SecurityTab(host) {
  const findings = (host.findings || []).filter(f => /sécurité|security|permissions|ssh_policy|ssh|firewall|pare-feu|update|mise à jour/i.test((f.domain || '') + ' ' + (f.id || '')));
  const waz = (host.source_details || []).find(s => s.provider === 'Wazuh');
  const agent = waz?.evidence?.agent;
  const incomplete = (host.coverage?.measured || 0) < (host.coverage?.total || 0);
  const measuredFindings = findings.filter(f => f.severity !== 'unknown');
  return '<section class="panel">' + ui.head('Sécurité observable', ui.sourceTag('Audit SSH') + ui.sourceTag('Wazuh'), '<button data-go="Sécurité" data-sec-goto-host="' + escAttr(host.key) + '">Vulnérabilités CVE de ce serveur →</button>') +
    '<div class="v2-kpis">' + ui.kpi('Anomalies de sécurité', host.stale ? 'Audit ancien' : measuredFindings.length, (findings.length - measuredFindings.length) + ' contrôle(s) incomplet(s) en plus', host.stale ? 'unknown' : measuredFindings.length ? 'warning' : '') +
    ui.kpi('Agent Wazuh', agent ? ({ active: 'Actif', disconnected: 'Déconnecté', never_connected: 'Jamais connecté' }[agent.status] || 'Inconnu') : 'Non associé', agent ? 'Version ' + (agent.version || 'non mesurée') : 'Protection non démontrée', !waz?.fresh ? 'unknown' : agent?.status === 'active' ? 'ok' : 'warning') +
    ui.kpi('Couverture des contrôles', (host.coverage?.measured ?? 0) + ' / ' + (host.coverage?.total ?? 0), incomplete ? 'Incomplète : pas de conclusion de conformité' : 'Tous les contrôles mesurés', incomplete ? 'unknown' : '') + '</div>' +
    (findings.map(f => issue(host, f)).join('') || '<p class="note">Aucune anomalie de sécurité remontée par les contrôles accessibles. ' + (incomplete ? 'La couverture est incomplète : ce n’est pas une validation de conformité.' : 'Cela ne constitue pas une certification.') + '</p>') + '</section>';
}

// Lot 4 : sections par onglet. detailRenderers garde les clés historiques : le chargeur
// paresseux (ensureDetailModules) s'en sert pour vérifier que le module est enregistré.
Object.assign(detailRenderers,{
  observability:v2TrendsSection,
  network:v2NetworkTab,
  backup:v2BackupTab,
  security:v2SecurityTab
});
hostSection('summary',20,v2HostSummary);
hostSection('summary',25,v2HostPriorities);
hostSection('incidents',30,v2TimelineSection);
hostSection('performance',10,v2TrendsSection);
hostSection('network',20,v2NetworkTab);
hostSection('backup',10,v2BackupTab);
hostSection('security',4,hostPlanSection);
hostSection('security',5,hostCveSection);
hostSection('security',10,v2SecurityTab);
// Jauges V2 à la place des trois cartes CPU/RAM/disque de la Synthèse.
detailTransformers.push(function(html,host){
  return html.replace(/<div class="detail-grid">(?:<div class="card">.*?<\/div>){3}<\/div>/,v2HostGauges(host));
});
