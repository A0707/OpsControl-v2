// Sécurité & gestion des CVE (/api/security/*) : tableau de bord, vulnérabilités, analyse par
// serveur, veille, correctifs, historique. Module paresseux : chargé à la première ouverture.
// Navigation en GET uniquement ; seuls des boutons explicites envoient un POST (relevé SSH,
// synchronisation, workflow d'une vulnérabilité). Les correctifs restent du TEXTE à copier.
// L'ancienne vue « Contrôles de sécurité SSH » (security() d'app.js) reste un onglet.
subtitles['Sécurité'] = 'Vulnérabilités CVE prouvées par serveur, veille, correctifs préparés et suivis jusqu’à la clôture.';
ROLE_CONTROLS.push(['operator', '[data-sec-scan],[data-sec-scan-host],[data-sec-sync],[data-sec-action],[data-sec-read],[data-sec-decide]'],
  ['admin', '[data-sec-settings],[data-sec-mail-test]']);

const SEC_TABS = [['dashboard', 'Tableau de bord'], ['vulns', 'Vulnérabilités CVE'], ['hosts', 'Analyse par serveur'],
  ['feeds', 'Veille de sécurité'], ['remediation', 'Correctifs et remédiations'], ['history', 'Historique et rapports'],
  ['ssh', 'Contrôles SSH']];
const SEC_SEVERITY = {critical: ['Critique', 'critical'], high: ['Élevée', 'warning'], medium: ['Moyenne', 'info'],
  low: ['Faible', 'unknown'], none: ['Aucune', 'unknown']};
const SEC_STATUS = {open: ['Détectée', 'warning'], validated: ['Validée', 'critical'], in_progress: ['Correction planifiée', 'info'],
  resolved: ['Corrigée (constatée)', 'ok'], false_positive: ['Faux positif', 'unknown'], accepted_risk: ['Risque accepté', 'unknown']};
const SEC_CONFIDENCE = {'confirmé': 'critical', 'détecté': 'warning', 'à vérifier': 'unknown'};
const SEC_SOURCES = {debian: 'Debian', wazuh: 'Wazuh'};
let secTab = 'dashboard', secData = {}, secAt = {}, secErrors = {}, secHost = '', secPlanId = '', secOpen = new Set();
let secFilters = {status: 'active', severity: '', q: '', kev: false, host: ''};
let secHistoryDays = 30, secPackageQuery = '', secRecoHost = '';
let secOffset = 0, secWatchOffset = 0;
const SEC_NOTES_PAGE = 20;
let secNotesShown = SEC_NOTES_PAGE;
function secPager(data, kind) {
  const offset = data.offset || 0, limit = data.limit || 50, total = data.total || 0;
  return '<nav class="console-pagination" aria-label="Pagination '+kind+'"><span>'+Math.min(offset+1,total)+'–'+Math.min(offset+limit,total)+' sur '+total+'</span>'+
    '<button data-sec-page="'+kind+'" data-offset="'+Math.max(0,offset-limit)+'" '+(!offset?'disabled':'')+'>Précédent</button>'+
    '<button data-sec-page="'+kind+'" data-offset="'+(offset+limit)+'" '+(offset+limit>=total?'disabled':'')+'>Suivant</button></nav>';
}
try { secTab = localStorage.getItem('infraops.securite.onglet') || secTab; } catch { /* onglet par défaut */ }
if (!SEC_TABS.some(([k]) => k === secTab)) secTab = 'dashboard';

function secName() {
  if (operatorIdentity?.authenticated) return '';
  return typeof itsmDeclaredName === 'function' ? itsmDeclaredName() : '';
}
function secWhen(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? esc(value) : '<span title="' + escAttr(stamp(value)) + '">' +
    d.toLocaleString('fr-FR', {day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit'}) + '</span>';
}
function secSeverity(v) {
  const [label, tone] = SEC_SEVERITY[v.severity] || ['Non évaluée', 'unknown'];
  const score = v.cvss ?? v.evidence?.wazuh?.cvss;
  return ui.pill(label + (score != null ? ' ' + Number(score).toFixed(1) : ''), tone);
}
function secStatus(status) {
  const [label, tone] = SEC_STATUS[status] || [status, 'unknown'];
  return ui.pill(label, tone);
}
function secTable(headers, rows, empty) {
  if (!rows.length) return '<p class="mini">' + esc(empty) + '</p>';
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th scope="col">' + h + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + (c ?? '—') + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div>';
}
function secCve(cve) {
  return /^CVE-\d{4}-\d{4,7}$/.test(cve || '') ? '<a href="https://nvd.nist.gov/vuln/detail/' + escAttr(cve) +
    '" target="_blank" rel="noopener noreferrer">' + esc(cve) + '</a>' : esc(cve || '—');
}

// Lectures : chaque onglet a ses URL ; une donnée de moins de 30 s n'est pas relue.
function secUrls() {
  const f = secFilters;
  return {
    dashboard: ['/api/security/summary', '/api/security/notifications?unread=true'],
    vulns: ['/api/security/vulns?status=' + encodeURIComponent(f.status) + (f.host ? '&host=' + encodeURIComponent(f.host) : '') +
      (f.kev ? '&kev=true' : '') + '&severity='+encodeURIComponent(f.severity)+'&q='+encodeURIComponent(f.q)+'&limit=50&offset='+secOffset+'&projection=list'],
    hosts: ['/api/security/hosts'].concat(secHost ? ['/api/security/hosts/' + encodeURIComponent(secHost)] : []),
    feeds: [secWatchUrl(), '/api/security/sources'],
    remediation: ['/api/security/vulns?status=all', '/api/security/recommendations']
      .concat(secRecoHost ? ['/api/security/hosts/' + encodeURIComponent(secRecoHost) + '/recommendations'] : []).concat(secMatchPlan ? ['/api/security/matches/plan?id=' + secMatchPlan.id + '&cve=' + encodeURIComponent(secMatchPlan.cve)] :
      secPlanId ? ['/api/security/vulns/' + secPlanId + '/plan'] : []),
    history: ['/api/security/history?days=' + secHistoryDays],
    ssh: [],
  }[secTab] || [];
}
async function secLoad(force = false) {
  const urls = secUrls();
  const due = urls.filter(u => force || !secData[u] || Date.now() - (secAt[u] || 0) > 30000);
  if (!due.length) return;
  await Promise.all(due.map(async u => {
    try { secData[u] = await api(u); secAt[u] = Date.now(); delete secErrors[u]; }
    catch (error) { secErrors[u] = error.status === 404 ? 'Le serveur OpsControl actif ne connaît pas le module Sécurité : redémarrez-le.' : error.message; }
  }));
  secPaint();
}
function secGet(url) { return secData[url]; }

// Deux travaux indépendants (relevé SSH du parc, veille) : chacun son état et son bouton.
function secJobLine(job) {
  if (!job) return '';
  const what = job.kind === 'scan' ? 'Relevé des paquets' : 'Synchronisation de la veille et de Wazuh';
  if (job.running) return '<p class="note" role="status">' + what + ' en cours' +
    (job.total ? ' : ' + job.completed + ' / ' + job.total + ' serveur(s)' : '') + ' — lancé par ' + esc(job.actor || '?') + '.</p>';
  if (job.error) return '<p class="form-error">' + what + ' en échec : ' + esc(job.error) + '</p>';
  if (job.finished_at) {
    const a = job.result?.analysis;
    return '<p class="mini">' + what + ' terminé ' + secWhen(job.finished_at) + (a ? ' : ' + a.new + ' nouvelle(s), ' + a.resolved +
      ' corrigée(s) constatée(s), ' + a.reopened + ' réapparue(s).' : '.') + '</p>';
  }
  return '';
}
function secJob(job) {
  if (!job) return '';
  return job.scan || job.sync ? secJobLine(job.scan) + secJobLine(job.sync) : secJobLine(job);
}
function secToolbar(job) {
  const scanning = job?.scan ? job.scan.running : job?.running && job.kind === 'scan';
  const syncing = job?.sync ? job.sync.running : job?.running && job.kind === 'sync';
  const who = !operatorIdentity?.authenticated ? '<label class="mini">Votre nom (déclaratif) <input id="sec-by" maxlength="120" value="' +
    escAttr(secName()) + '"></label>' : '';
  return '<div class="filters">' + who + '<button data-sec-scan' + (scanning ? ' disabled' : '') +
    ' title="Relevé SSH en lecture seule des paquets de tous les serveurs">' + (scanning ? 'Relevé du parc en cours…' : 'Analyser le parc') + '</button>' +
    '<button data-sec-sync' + (syncing ? ' disabled' : '') + ' title="CISA KEV, NVD, EPSS, CERT-FR, Debian, PHP, WordPress, Fortinet, Proxmox et Wazuh">' +
    (syncing ? 'Synchronisation en cours…' : 'Synchroniser veille et Wazuh') + '</button></div>';
}
// Wazuh a trois capacités distinctes (audit UI du 31/10, fiche 12.2) : connexion au manager et
// agents (Sources → Wazuh), puis intégration des vulnérabilités, seule comptée ici.
function secWazuhCoverage(c) {
  return c.wazuh_hosts + ' avec vulnérabilités Wazuh intégrées' +
    (c.wazuh_hosts ? '' : ' · agents et connexion : Sources → Wazuh');
}
function secDashboard() {
  const s = secGet('/api/security/summary'), n = secGet('/api/security/notifications?unread=true');
  if (!s) return '<p>Chargement du tableau de bord…</p>';
  const c = s.counts;
  const kpis = '<div class="v2-kpis">' +
    // Unités explicites (audit UI du 31/10, fiche 13.1) : couples serveur/CVE, puis CVE uniques.
    ui.kpi('Vulnérabilités ouvertes', c.open, 'couples serveur/CVE · ' + (c.unique_cves ?? '?') + ' CVE unique(s) · ' + c.hosts_affected + ' serveur(s)', c.open ? 'warning' : '') +
    ui.kpi('Exploitées (CISA KEV)', c.kev, 'Priorité maximale', c.kev ? 'critical' : '') +
    ui.kpi('Critiques', c.critical, 'couples · ' + (c.critical_cves ?? '?') + ' CVE unique(s) · ' + (c.high || 0) + ' élevée(s)', c.critical ? 'critical' : '') +
    ui.kpi('À vérifier', c.to_verify, 'Rétroportage probable, release divergente ou preuve contradictoire') +
    ui.kpi('En correction', c.validated + c.in_progress, c.validated + ' validée(s), ' + c.in_progress + ' planifiée(s)') +
    ui.kpi('Corrigées (30 j)', c.resolved_30d, 'Constatées par une nouvelle analyse', c.resolved_30d ? 'ok' : '') +
    ui.kpi('Serveurs analysés', c.hosts_scanned + ' / ' + c.hosts_total, secWazuhCoverage(c), c.hosts_scanned < c.hosts_total ? 'warning' : '') +
    ui.kpi('Bulletins (7 j)', c.advisories_7d, c.notifications + ' notification(s) non lue(s)', c.notifications ? 'warning' : '') + '</div>';
  // Liste longue par lots (audit UI du 31/10, fiche 13.3) : 200 notifications déroulées d'un bloc
  // repoussaient les priorités ; le compteur annonce le total non lu, pas la page chargée.
  const notes = (n?.items || []), shownNotes = notes.slice(0, secNotesShown);
  const notifications = '<section class="panel"><h3>Notifications ciblées <span class="state-count">' + (c.notifications ?? notes.length) + '</span></h3>' +
    (notes.length ? '<button data-sec-read="all">Tout marquer comme lu</button>' + secTable(['Date', 'Notification', 'Serveurs', ''],
      shownNotes.map(x => [secWhen(x.at), ui.pill(x.level === 'critical' ? 'Critique' : x.level === 'warning' ? 'Parc concerné' : 'Info',
        x.level === 'critical' ? 'critical' : x.level === 'warning' ? 'warning' : 'info') + ' <b>' + esc(x.title) + '</b><small>' + esc(x.detail || '') + '</small>',
      x.hosts.slice(0, 6).map(h => esc(h.name)).join(', ') + (x.hosts.length > 6 ? ' … (+' + (x.hosts.length - 6) + ')' : ''),
      '<button data-sec-read="' + escAttr(x.id) + '">Lu</button>']), '') +
      (notes.length > shownNotes.length ? '<div class="more-row"><span class="mini">' + shownNotes.length + ' affichée(s) sur ' + notes.length + ' chargée(s)</span><button data-sec-notes-more>Afficher ' + Math.min(SEC_NOTES_PAGE, notes.length - shownNotes.length) + ' de plus</button></div>' : '') :
      '<p class="mini">Aucune notification non lue : seules les CVE exploitées, critiques ou citées par un bulletin récent en produisent.</p>') + '</section>';
  const hosts = '<section class="panel"><h3>Serveurs les plus exposés</h3>' + secTable(['Serveur', 'Environnement', 'Ouvertes', 'KEV', 'Critiques', 'CVSS max'],
    s.top_hosts.map(h => ['<button class="link" data-sec-host="' + escAttr(h.host_key) + '">' + esc(h.name) + '</button>', esc(h.environment || '—'),
      h.count, h.kev ? ui.pill(h.kev, 'critical') : '0', h.critical, h.max_cvss != null ? Number(h.max_cvss).toFixed(1) : '—']),
    'Aucune vulnérabilité ouverte. Cela ne prouve rien pour un serveur jamais analysé.') + '</section>';
  const top = '<section class="panel"><h3>Priorités</h3>' + secVulnRows(s.top_vulns, false) + '</section>';
  const syncs = Object.entries(s.syncs || {}).map(([k, v]) => esc(k) + ' ' + (v.status === 'ok' ? '✓' : '⚠') + ' ' + secWhen(v.at)).join(' · ');
  return kpis + secJob(s.job) + secToolbar(s.job) + notifications + top + hosts +
    '<p class="v2-formula">' + esc(s.scope) + (syncs ? '<br>Dernières synchronisations : ' + syncs : '<br>Aucune synchronisation de veille effectuée.') + '</p>';
}

// `details` : les vulnérabilités dépliées reçoivent leur ligne de détail juste en dessous.
function secVulnRows(items, details = false) {
  const headers = ['Priorité', 'CVE', 'Serveur', 'Paquet', 'Installée → corrigée', 'Sources', 'Confiance', 'Statut', ''];
  if (!items.length) return '<p class="mini">Aucune vulnérabilité sur ce périmètre.</p>';
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th scope="col">' + h + '</th>').join('') + '</tr></thead><tbody>' +
    items.map(v => '<tr>' + secVulnCells(v, details).map(c => '<td>' + c + '</td>').join('') + '</tr>' +
      (details && secOpen.has(v.id) ? secDetail(v.id) : '')).join('') + '</tbody></table></div>';
}
function secVulnCells(v, details) {
  return [secSeverity(v) + (v.kev ? ' ' + ui.pill('KEV', 'critical', 'Exploitée activement — échéance CISA ' + (v.kev_due || '')) : ''),
      secCve(v.cve), '<button class="link" data-sec-host="' + escAttr(v.host_key) + '">' + esc(v.host_name) + '</button><small>' + esc(v.environment || '') + '</small>',
      '<b>' + esc(v.package) + '</b><small>' + esc((v.evidence.binaries || []).slice(0, 3).join(', ')) + '</small>',
      esc(v.installed || '?') + ' → <b>' + esc(v.fixed || 'non fournie') + '</b>',
      (v.sources || []).map(s => esc(SEC_SOURCES[s] || s)).join(' + '),
      ui.pill(v.confidence, SEC_CONFIDENCE[v.confidence] || 'unknown', v.evidence.reason || ''),
      secStatus(v.status) + (typeof itsmBadge === 'function' ? itsmBadge('vulnerability', v.id, ['open', 'validated', 'in_progress'].includes(v.status)) : ''),
      (details ? '<button data-sec-open="' + escAttr(v.id) + '" aria-expanded="' + secOpen.has(v.id) + '">' + (secOpen.has(v.id) ? 'Masquer' : 'Détails') + '</button> ' :
        '<button data-sec-detail="' + escAttr(v.id) + '">Détails</button> ') +
      '<button data-sec-plan="' + escAttr(v.id) + '">Préparer la correction</button>'];
}

function secDetail(id) {
  const d = secGet('/api/security/vulns/' + id);
  if (!d) return '<tr><td colspan="9">Chargement du détail…</td></tr>';
  const ev = d.evidence || {}, w = ev.wazuh;
  const facts = [['Source', ev.source], ['Comparaison', ev.comparison], ['Dépôts configurés', ev.repository],
    ['Confiance', d.confidence + ' — ' + (ev.reason || '')], ['Paquets binaires', Object.entries(ev.binary_versions || {}).map(([k, v]) => k + ' ' + v).join(', ')],
    ['Changelog cite la CVE', (ev.changelog_mentions || []).join(', ') || 'non (ou paquet hors liste relue)'],
    ['Wazuh', w ? (w.package + ' ' + (w.version || '') + ' · ' + (w.severity || '') + (w.reference ? ' · ' + w.reference : '')) : 'non détectée par Wazuh'],
    ['CVSS (NVD)', d.cve_data?.cvss != null ? d.cve_data.cvss + ' ' + (d.cve_data.vector || '') : 'non enrichi'],
    ['CISA KEV', d.kev ? 'oui — action requise : ' + (d.cve_data?.kev_action || '') + ' (échéance ' + (d.kev_due || '?') + ')' : 'non listée'],
    ['Responsable', d.owner || 'non désigné'], ['Première détection', stamp(d.first_seen)], ['Dernière observation', stamp(d.last_seen)],
    ['Relevé des paquets', stamp(ev.collected_at)]];
  const can = {validate: ['open'], start: ['open', 'validated'], false_positive: ['open', 'validated', 'in_progress'],
    accept_risk: ['open', 'validated', 'in_progress'], reopen: ['false_positive', 'accepted_risk']};
  const labels = {validate: 'Valider la vulnérabilité', start: 'Planifier la correction', false_positive: 'Faux positif', accept_risk: 'Accepter le risque', reopen: 'Rouvrir'};
  const buttons = Object.entries(can).filter(([, from]) => from.includes(d.status)).map(([a]) => '<button data-sec-action="' + a + '" data-sec-id="' + escAttr(d.id) + '">' + labels[a] + '</button>').join(' ');
  const glpi = ['validated', 'in_progress'].includes(d.status) && typeof itsmEntry === 'function' ? itsmEntry('vulnerability', d.id, d.host_key) :
    '<p class="mini">Ticket GLPI : disponible après validation de la vulnérabilité.</p>';
  return '<tr class="sec-detail"><td colspan="9"><dl class="sc-facts">' + facts.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v || '—') + '</dd>').join('') + '</dl>' +
    (d.description || d.cve_data?.description ? '<p class="note">' + esc(d.description || d.cve_data.description) + '</p>' : '') +
    '<label>Note ou justification (obligatoire pour faux positif / risque accepté)<textarea data-sec-note="' + escAttr(d.id) + '" maxlength="2000"></textarea></label>' +
    '<label>Responsable <input data-sec-owner="' + escAttr(d.id) + '" maxlength="120" value="' + escAttr(d.owner || '') + '"></label>' +
    '<p>' + buttons + ' <button data-sec-action="assign" data-sec-id="' + escAttr(d.id) + '">Désigner le responsable</button> ' +
    '<button data-sec-action="note" data-sec-id="' + escAttr(d.id) + '">Ajouter la note</button></p>' + glpi +
    (d.advisories.length ? '<h4>Bulletins de veille citant cette CVE</h4><ul>' + d.advisories.map(a => '<li>' + secWhen(a.published) + ' · ' +
      (a.url ? '<a href="' + escAttr(a.url) + '" target="_blank" rel="noopener noreferrer">' + esc(a.title) + '</a>' : esc(a.title)) + '</li>').join('') + '</ul>' : '') +
    '<details><summary>Historique (' + d.events.length + ')</summary><ol>' + d.events.map(e => '<li>' + esc(stamp(e.at)) + ' · ' + esc(e.actor) +
      (e.auth === 'local' ? ' (déclaratif)' : '') + ' · ' + esc(e.detail || e.action) + '</li>').join('') + '</ol></details></td></tr>';
}

function secVulns() {
  const url = secUrls()[0], data = secGet(url);
  const f = secFilters;
  const filters = '<div class="filters"><input id="sec-q" type="search" placeholder="CVE, paquet ou serveur" value="' + escAttr(f.q) + '" aria-label="Rechercher">' +
    '<select id="sec-status" aria-label="Statut">' + [['active', 'À traiter'], ['all', 'Tous'], ...Object.entries(SEC_STATUS).map(([k, [l]]) => [k, l])]
      .map(([k, l]) => '<option value="' + k + '"' + (f.status === k ? ' selected' : '') + '>' + esc(l) + '</option>').join('') + '</select>' +
    '<select id="sec-severity" aria-label="Gravité"><option value="">Toutes gravités</option>' + Object.entries(SEC_SEVERITY).map(([k, [l]]) =>
      '<option value="' + k + '"' + (f.severity === k ? ' selected' : '') + '>' + l + '</option>').join('') + '<option value="unknown"' + (f.severity === 'unknown' ? ' selected' : '') + '>Non évaluée</option></select>' +
    '<label class="mini"><input type="checkbox" id="sec-kev"' + (f.kev ? ' checked' : '') + '> CISA KEV uniquement</label>' +
    (f.host ? '<button data-sec-clear-host>Serveur : ' + esc(f.host) + ' ✕</button>' : '') +
    '<button data-sec-csv>Exporter CSV</button></div>';
  if (!data) return filters + '<p>Chargement des vulnérabilités…</p>';
  const needle = f.q.toLowerCase();
  const items = data.items.filter(v => (!f.severity || (v.severity || 'unknown') === f.severity) &&
    (!needle || (v.cve + ' ' + v.package + ' ' + v.host_name).toLowerCase().includes(needle)));
  const table = secVulnRows(items.slice(0, 500), true);
  return filters + '<p class="mini">' + data.total + ' vulnérabilité(s). Priorité : exploitée (KEV), puis CVSS, puis production.</p>' + table + secPager(data,'vulns');
}

function secHosts() {
  const data = secGet('/api/security/hosts');
  if (!data) return '<p>Chargement de l’analyse par serveur…</p>';
  const list = '<section class="panel"><h3>Serveurs inventoriés</h3>' + secJob(data.job) + secToolbar(data.job) +
    secTable(['Serveur', 'Système', 'Paquets', 'Dernier relevé', 'Wazuh', 'Vulnérabilités', ''],
      data.items.map(h => ['<button class="link" data-sec-host="' + escAttr(h.key) + '">' + esc(h.name) + '</button><small><span class="ip">' + esc(h.ip || '') + '</span> · ' + esc(h.environment || '') + '</small>',
        esc(h.os || 'Inconnu') + (h.support ? '<small>' + esc(h.support.label) + '</small>' : '') + (h.reboot_required ? '<small>Redémarrage requis</small>' : ''),
        h.packages || '—', h.collected_at ? secWhen(h.collected_at) : (h.last_scan ? esc(h.last_scan.status) + '<small>' + esc(h.last_scan.detail || '') + '</small>' : 'Jamais analysé'),
        h.wazuh_at ? secWhen(h.wazuh_at) : '—',
        (h.counts.kev ? ui.pill(h.counts.kev + ' KEV', 'critical') + ' ' : '') + (h.counts.critical ? ui.pill(h.counts.critical + ' critique(s)', 'critical') + ' ' : '') + h.counts.open,
        h.collect_enabled ? '<button data-sec-scan-host="' + escAttr(h.key) + '"' + ((data.job?.scan ? data.job.scan.running : data.job?.running) ? ' disabled' : '') + '>Analyser</button>' : '<small>Collecte désactivée</small>']),
      'Aucun serveur dans l’inventaire.') + '</section>';
  return (secHost ? secHostDetail() : '') + list;
}

function secHostDetail() {
  const d = secGet('/api/security/hosts/' + encodeURIComponent(secHost));
  if (!d) return '<section class="panel"><p>Chargement de l’analyse du serveur…</p></section>';
  const os = d.os || {};
  const facts = [['Système', os.pretty || 'Inconnu'], ['Support', d.support?.label || 'Date de fin de support non référencée'],
    ['Noyau en cours', d.kernel || '—'], ['Redémarrage requis', d.reboot_required ? 'Oui (/var/run/reboot-required)' : 'Non signalé'],
    ['Gestionnaire', d.manager || '—'], ['Paquets installés', d.packages_count], ['Mises à jour disponibles', d.upgradable_count],
    ['Relevé', d.collected_at ? stamp(d.collected_at) + ' (' + (d.account || '') + ')' : 'Jamais relevé'],
    ['Wazuh', d.wazuh ? 'Agent ' + d.wazuh.agent_id + ' · ' + d.wazuh.items + ' détection(s) · ' + stamp(d.wazuh.at) + (d.wazuh.complete ? '' : ' (liste incomplète)') : 'Aucune donnée Wazuh rapprochée']];
  const comps = secTable(['Composant', 'Versions des paquets', 'Paquets', 'Version annoncée'],
    d.components.map(c => ['<b>' + esc(c.component) + '</b>', esc(c.versions.join(', ')), esc(c.packages.join(', ')), esc(c.binary || '—')]), 'Aucun composant clé identifié (relevé absent ?).');
  const dk = d.docker || {};
  const docker = dk.state === 'ok' ? secTable(['Conteneur', 'Image', 'État'], dk.containers.map(c => [esc(c.name), esc(c.image), esc(c.status)]), 'Aucun conteneur en cours.') +
    secTable(['Image', 'Tag', 'Créée', 'À vérifier'], dk.images.map(i => {
      const f = dk.findings.find(x => x.id === i.id && x.tag === i.tag);
      return [esc(i.repository), esc(i.tag), esc(i.created || '—'), f ? ui.pill(f.finding, f.level) : '—'];
    }), 'Aucune image.') : '<p class="mini">' + esc({absent: 'Docker absent.', denied: 'Docker présent, accès refusé au compte de supervision (droits).', error: 'Docker : erreur de lecture.'}[dk.state] || 'Docker non relevé.') + '</p>';
  const pkgUrl = '/api/security/packages/' + encodeURIComponent(secHost) + (secPackageQuery ? '?q=' + encodeURIComponent(secPackageQuery) : '');
  const pkgs = secGet(pkgUrl);
  return '<section class="panel">' + ui.head(esc(d.host.name || d.host.key), esc(d.host.ip || '') + ' · ' + esc(d.host.environment || ''),
    '<button data-sec-scan-host="' + escAttr(d.host.key) + '">Analyser ce serveur</button> <button data-sec-close-host>Fermer</button>', 'ANALYSE DU SERVEUR') +
    '<dl class="sc-facts">' + facts.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>' +
    '<h3>Vulnérabilités</h3>' + secVulnRows(d.vulns.filter(v => ['open', 'validated', 'in_progress'].includes(v.status)), false) +
    '<h3>Composants (PHP, Apache, OpenSSL…)</h3>' + comps + '<h3>Docker</h3>' + docker +
    '<details' + (secPackageQuery || pkgs ? ' open' : '') + '><summary>Paquets installés (preuve du relevé)</summary><div class="filters"><input id="sec-pkg-q" type="search" placeholder="Filtrer les paquets" value="' + escAttr(secPackageQuery) + '"><button data-sec-pkg>Afficher</button></div>' +
    (pkgs ? secTable(['Paquet', 'Version', 'Source', 'Mise à jour disponible'], pkgs.items.map(p => [esc(p.name), esc(p.version), esc(p.source + ' ' + p.source_version),
      p.upgradable ? esc(p.upgradable.candidate + ' (' + p.upgradable.suite + ')') : '—']), 'Aucun paquet.') : '') + '</details>' +
    '<details><summary>Relevés récents</summary>' + secTable(['Date', 'Résultat', 'Paquets', 'Par'], d.scans.map(s => [secWhen(s.at), esc(s.status) + (s.detail ? '<small>' + esc(s.detail) + '</small>' : ''), s.packages ?? '—', esc(s.actor || '')]), 'Aucun relevé.') + '</details>' +
    '<p class="v2-formula">' + esc(d.scope) + '</p></section>';
}

// Veille en ligne (/api/security/watch) : sources, CVE applicables par serveur et technologie,
// priorité, bulletins, historique des alertes. Relue toutes les 60 s tant que l'onglet est ouvert.
const SEC_WATCH_VIEWS = [['cves', 'CVE et serveurs concernés'], ['techs', 'CVE par technologie'], ['bulletins', 'Nouveaux bulletins'],
  ['alerts', 'Historique des alertes'], ['settings', 'Sources et réglages']];
const SEC_APPLICABILITY = {confirmed: ['Confirmée', 'critical'], potential: ['Potentielle', 'warning'], not_applicable: ['Non applicable', 'ok']};
const SEC_SOURCE_STATE = {ok: 'ok', error: 'critical', disabled: 'unknown', never: 'unknown'};
const SEC_RANK = {P1: 'critical', P2: 'warning', P3: 'info', P4: 'unknown'};
let secWatchView = 'cves', secWatchFilters = {tech: '', host: '', source: '', severity: '', status: ''}, secWatchOpen = new Set(), secMatchPlan = null;

function secWatchUrl() {
  const f = secWatchFilters;
  return '/api/security/watch?days=14&projection=list&limit=50&offset='+secWatchOffset + Object.entries(f).filter(([, v]) => v).map(([k, v]) => '&' + k + '=' + encodeURIComponent(v)).join('');
}
function secWatchDetails(c) {
  const d=c.detail_available?secData['watch-detail:'+c.cve]:c;
  if(!d)return '<p role="status">Chargement des serveurs concernés…</p>';
  if(d.error)return '<p class="form-error" role="alert">'+esc(d.error)+' · Fermer puis ouvrir les serveurs pour réessayer.</p>';
  return '<div class="table"><table><thead><tr><th>Serveur</th><th>Instance</th><th>Version → cible</th><th>Applicabilité</th><th></th></tr></thead><tbody>'+
    (d.hosts||[]).map(m=>secWatchHost(c,m)).join('')+'</tbody></table></div>';
}
function secCveLink(id) {
  if (/^GHSA(-[a-z0-9]{4}){3}$/.test(id || '')) return '<a href="https://github.com/advisories/' + escAttr(id) + '" target="_blank" rel="noopener noreferrer">' + esc(id) + '</a>';
  return secCve(id);
}
function secScores(c) {
  const parts = [c.cvss != null ? 'CVSS ' + Number(c.cvss).toFixed(1) : (c.vendor_severity ? 'Éditeur : ' + c.vendor_severity : 'Non évaluée')];
  if (c.epss != null) parts.push('EPSS ' + Math.round(c.epss * 100) + ' %');
  return (c.kev ? ui.pill('KEV', 'critical', 'Exploitée activement — échéance CISA ' + (c.kev_due || '')) + ' ' : '') +
    secSeverity({severity: c.severity, cvss: c.cvss, evidence: {}}) + '<small>' + esc(parts.join(' · ')) + '</small>';
}
function secWatchHost(c, m) {
  const [label, tone] = SEC_APPLICABILITY[m.status] || [m.status, 'unknown'];
  const decide = m.status === 'potential' || /après vérification/.test(m.reason || '') ?
    '<input data-sec-dnote="' + escAttr(m.id + '|' + c.cve) + '" maxlength="2000" placeholder="Ce qui a été vérifié (10 caractères min.)" aria-label="Justification">' +
    (m.status === 'potential' ? '<button data-sec-decide="confirm" data-sec-mid="' + escAttr(m.id) + '" data-sec-mcve="' + escAttr(c.cve) + '">Confirmer après vérification</button>' +
      '<button data-sec-decide="not_applicable" data-sec-mid="' + escAttr(m.id) + '" data-sec-mcve="' + escAttr(c.cve) + '">Non applicable</button>' :
      '<button data-sec-decide="reset" data-sec-mid="' + escAttr(m.id) + '" data-sec-mcve="' + escAttr(c.cve) + '">Retirer la décision</button>') : '';
  return '<tr><td><button class="link" data-sec-host="' + escAttr(m.host_key) + '">' + esc(m.host_name) + '</button>' +
    (m.exposed ? '<small>' + ui.pill('Exposé', 'critical', m.exposed) + '</small>' : '') + '</td>' +
    '<td>' + esc(m.tech_label) + '<small>' + esc(m.instance) + '</small></td><td>' + esc(m.version || 'inconnue') + ' → <b>' + esc(m.fixed || 'non publiée') + '</b></td>' +
    '<td>' + ui.pill(label, tone) + '<small>' + esc(m.reason || '') + '</small></td>' +
    '<td>' + (m.status !== 'not_applicable' ? '<button data-sec-mplan="' + escAttr(m.id) + '" data-sec-mcve="' + escAttr(c.cve) + '">Préparer la correction</button>' : '') +
    (m.vuln_status ? '<button data-sec-vuln-of="' + escAttr(m.host_key) + '" data-sec-vuln-cve="' + escAttr(c.cve) + '">Vulnérabilité (' + esc((SEC_STATUS[m.vuln_status] || [m.vuln_status])[0]) + ')</button>' : '') +
    decide + '</td></tr>';
}
function secWatchCves(items, status) {
  const rows = items.filter(c => c.status === status);
  if (!rows.length) return '<p class="mini">Aucune.</p>';
  return '<div class="table"><table><thead><tr>' + ['Priorité', 'CVE', 'Technologie', 'Gravité', 'Versions vulnérables → corrigées', 'Serveurs', 'Sources', '']
    .map(h => '<th scope="col">' + h + '</th>').join('') + '</tr></thead><tbody>' + rows.slice(0, 200).map(c => {
    const open = secWatchOpen.has(c.cve);
    const counts = c.counts || {};
    return '<tr><td>' + ui.pill(c.priority.rank, SEC_RANK[c.priority.rank] || 'unknown', c.priority.why.join(' · ')) + '<small>' + esc(c.priority.why.join(' · ')) + '</small></td>' +
      '<td>' + secCveLink(c.cve) + (c.description ? '<small>' + esc(c.description.slice(0, 140)) + '</small>' : '') + '</td>' +
      '<td>' + esc(c.tech_labels.join(', ')) + '</td><td>' + secScores(c) + '</td>' +
      '<td>' + esc(c.ranges.slice(0, 4).join(' ; ') || '—') + (c.fixed.length ? '<small>Corrigée : ' + esc(c.fixed.join(', ')) + '</small>' : '') + '</td>' +
      '<td>' + (counts.confirmed ? ui.pill(counts.confirmed + ' confirmé(s)', 'critical') + ' ' : '') + (counts.potential ? ui.pill(counts.potential + ' potentiel(s)', 'warning') + ' ' : '') +
      (counts.not_applicable ? '<small>' + counts.not_applicable + ' non applicable(s)</small>' : '') + (c.exposed.length ? '<small>Exposé : ' + esc(c.exposed.join(', ')) + '</small>' : '') + '</td>' +
      '<td>' + c.advisories.slice(0, 3).map(a => a.url ? '<a href="' + escAttr(a.url) + '" target="_blank" rel="noopener noreferrer">' + esc(a.label) + '</a>' : esc(a.label)).join('<br>') +
      (c.sources.includes('nvd') ? '<small>NVD' + (c.nvd_status ? ' · ' + esc(c.nvd_status) : '') + '</small>' : '') + '</td>' +
      '<td><button data-sec-wopen="' + escAttr(c.cve) + '" aria-expanded="' + open + '">' + (open ? 'Masquer' : 'Serveurs') + '</button></td></tr>' +
      (open ? '<tr class="sec-detail"><td colspan="8">'+secWatchDetails(c)+'</td></tr>' : '');
  }).join('') + '</tbody></table></div>' + (rows.length > 200 ? '<p class="mini">200 premières affichées.</p>' : '');
}
function secWatchFiltersMarkup(d) {
  const f = secWatchFilters, opt = (list, value) => list.map(([k, l]) => '<option value="' + escAttr(k) + '"' + (value === k ? ' selected' : '') + '>' + esc(l) + '</option>').join('');
  return '<div class="filters">' +
    '<select id="sec-w-tech" aria-label="Produit"><option value="">Tous les produits</option>' + opt(d.filters.techs.map(t => [t.key, t.label]), f.tech) + '</select>' +
    '<select id="sec-w-host" aria-label="Serveur"><option value="">Tous les serveurs</option>' + opt(d.filters.hosts.map(h => [h.key, h.name]), f.host) + '</select>' +
    '<select id="sec-w-source" aria-label="Source"><option value="">Toutes les sources</option>' + opt(d.filters.sources.map(s => [s.key, s.label]), f.source) + '</select>' +
    '<select id="sec-w-severity" aria-label="Criticité"><option value="">Toutes criticités</option>' + opt(Object.entries(SEC_SEVERITY).map(([k, [l]]) => [k, l]), f.severity) + '</select>' +
    '<select id="sec-w-status" aria-label="Applicabilité"><option value="">Toute applicabilité</option>' + opt(Object.entries(SEC_APPLICABILITY).map(([k, [l]]) => [k, l]), f.status) + '</select></div>';
}
function secWatchSettings(src) {
  if (!src) return '<p>Chargement des réglages…</p>';
  const s = src.settings, mail = src.mail || {};
  return '<section class="panel"><h3>Clés et e-mail</h3><dl class="sc-facts"><dt>Clé NVD</dt><dd>' + (src.keys?.nvd ? 'présente (NVD_API_KEY)' : 'absente : 40 CVE par passage, 5 requêtes / 30 s') + '</dd>' +
    '<dt>Jeton GitHub</dt><dd>' + (src.keys?.github ? 'présent (GITHUB_TOKEN)' : 'absent : 60 requêtes / heure, suffisant') + '</dd>' +
    '<dt>E-mail</dt><dd>' + (mail.configured ? esc(mail.server + ' (' + mail.security + ') → ' + mail.recipients.join(', ')) : 'non configuré : ' + esc((mail.missing || []).join(', '))) + '</dd></dl>' +
    '<p class="mini">Les clés et le mot de passe SMTP restent dans l’environnement du service (coffre DPAPI ou /etc/infraops/secrets.env), jamais dans la base.</p>' +
    (mail.configured ? '<button data-sec-mail-test>Envoyer un e-mail de test</button>' : '') + '</section>' +
    '<form id="sec-settings" class="panel"><h3>Automatismes</h3>' +
    '<label><input type="checkbox" name="feeds_auto"' + (s.feeds_auto ? ' checked' : '') + '> Synchronisation automatique de la veille et de Wazuh</label>' +
    '<label>Fréquence <select name="feeds_hours">' + [[1, 'Toutes les heures'], [3, 'Toutes les 3 h'], [6, 'Toutes les 6 h'], [12, 'Toutes les 12 h'], [24, 'Une fois par jour']]
      .map(([v, l]) => '<option value="' + v + '"' + (s.feeds_hours === v ? ' selected' : '') + '>' + l + '</option>').join('') + '</select></label>' +
    '<label>Relevé SSH automatique des paquets <select name="scan_hours">' + [[0, 'Désactivé (manuel)'], [24, 'Toutes les 24 h'], [168, 'Chaque semaine']].map(([v, l]) =>
      '<option value="' + v + '"' + (s.scan_hours === v ? ' selected' : '') + '>' + l + '</option>').join('') + '</select></label>' +
    '<label>Indexeur Wazuh ≥ 4.8 (connexion Elasticsearch) <select name="wazuh_indexer"><option value="">Aucun</option>' + src.indexers.map(i => '<option value="' + escAttr(i.key) + '"' +
      (s.wazuh_indexer === i.key ? ' selected' : '') + '>' + esc(i.name || i.key) + '</option>').join('') + '</select></label>' +
    '<label>Destinataires des alertes par e-mail <input name="mail_to" maxlength="1000" value="' + escAttr(s.mail_to || '') + '" placeholder="soc@exemple.ma, rssi@exemple.ma"></label>' +
    '<label>Niveau envoyé par e-mail <select name="mail_level"><option value="critical"' + (s.mail_level === 'critical' ? ' selected' : '') + '>Critique seulement</option>' +
      '<option value="warning"' + (s.mail_level === 'warning' ? ' selected' : '') + '>Critique et majeur</option></select></label>' +
    '<label>Seuil EPSS d’alerte (0,01 à 1) <input name="epss_threshold" type="number" min="0.01" max="1" step="0.01" value="' + escAttr(s.epss_threshold) + '"></label>' +
    '<button type="submit" data-sec-settings>Enregistrer les réglages</button></form>' +
    '<p class="mini">Correctifs Debian connus : ' + (Object.entries(src.debian_fixes || {}).map(([r, n]) => esc(r) + ' ' + n).join(' · ') || 'aucun') + ' · CVE exploitées (KEV) : ' + src.kev_count + '</p>';
}
function secFeeds() {
  const d = secGet(secWatchUrl()), src = secGet('/api/security/sources');
  if (!d) return secToolbar(src?.job) + '<p>Chargement de la veille…</p>';
  const k = d.kpis;
  const kpis = '<div class="v2-kpis">' +
    ui.kpi('Sources opérationnelles', k.sources_ok + ' / ' + k.sources_total, k.sources_error ? k.sources_error + ' en erreur' : 'Aucune erreur', k.sources_error ? 'warning' : 'ok') +
    ui.kpi('Nouveaux bulletins (24 h)', k.bulletins_24h, k.bulletins + ' sur la période') +
    ui.kpi('CVE confirmées', k.confirmed, 'Version installée dans une plage publiée', k.confirmed ? 'critical' : '') +
    ui.kpi('CVE potentielles', k.potential, 'Rétroportage possible ou version incomplète', k.potential ? 'warning' : '') +
    ui.kpi('Non applicables', k.not_applicable, 'Hors plage, plateforme exclue ou rétroporté') +
    ui.kpi('Priorité P1', k.p1, 'À traiter immédiatement', k.p1 ? 'critical' : '') +
    ui.kpi('Alertes (24 h)', k.alerts_24h, k.alerts_unread + ' non lue(s)', k.alerts_unread ? 'warning' : '') +
    ui.kpi('Prochaine synchronisation', k.next_sync ? new Date(k.next_sync).toLocaleString('fr-FR', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'}) : 'Désactivée', k.feeds_auto ? 'Toutes les ' + k.feeds_hours + ' h' : 'Manuelle uniquement') + '</div>';
  const sources = '<div class="sc-grid sec-sources">' + d.sources.filter(s => !s.key.startsWith('nvd:')).map(s =>
    '<article class="sc-card ' + (SEC_SOURCE_STATE[s.status] === 'critical' ? 'critical' : s.status === 'ok' ? 'ok' : '') + '"><h3>' + esc(s.label) + '</h3>' +
    '<div class="sc-pills">' + ui.pill(s.status_label, SEC_SOURCE_STATE[s.status] || 'unknown') + '</div>' +
    '<dl class="sc-facts"><dt>Dernier succès</dt><dd>' + (s.last_success ? secWhen(s.last_success) : 'Jamais') + '</dd>' +
    (s.items != null ? '<dt>Éléments</dt><dd>' + esc(s.items) + '</dd>' : '') +
    (s.error ? '<dt>Erreur</dt><dd>' + esc(s.error) + (s.failures ? ' (' + s.failures + ' fois)' : '') + (s.next_after ? '<small>Nouvel essai après ' + secWhen(s.next_after) + '</small>' : '') + '</dd>' : '') +
    '</dl></article>').join('') + '</div>';
  const views = '<div class="tabs host-tabs" role="tablist" aria-label="Vues de la veille">' + SEC_WATCH_VIEWS.map(([v, l]) =>
    '<button role="tab" aria-selected="' + (secWatchView === v) + '" class="' + (secWatchView === v ? 'active' : '') + '" data-sec-watch-view="' + v + '">' + esc(l) + '</button>').join('') + '</div>';
  let body = '';
  if (secWatchView === 'cves') {
    body = secWatchFiltersMarkup(d) + secPager(d,'watch') + '<p class="mini">' + d.total + ' CVE · les compteurs ci-dessous concernent la page affichée. Priorité : gravité, exploitation (KEV, EPSS), exposition Internet, applicabilité confirmée.</p>' +
      '<section class="panel" data-sec-applicability="confirmed"><h3>CVE confirmées <span class="state-count">' + d.cves.filter(c => c.status === 'confirmed').length + '</span></h3>' + secWatchCves(d.cves, 'confirmed') + '</section>' +
      '<section class="panel" data-sec-applicability="potential"><h3>CVE potentielles — à vérifier <span class="state-count">' + d.cves.filter(c => c.status === 'potential').length + '</span></h3>' + secWatchCves(d.cves, 'potential') + '</section>' +
      '<details class="panel" data-sec-applicability="not_applicable"><summary>CVE non applicables <span class="state-count">' + d.cves.filter(c => c.status === 'not_applicable').length + '</span></summary>' + secWatchCves(d.cves, 'not_applicable') + '</details>';
  } else if (secWatchView === 'techs') {
    body = '<section class="panel"><h3>CVE par technologie</h3>' + secTable(['Technologie', 'Serveurs', 'CVE', 'Confirmées', 'Potentielles', 'Non applicables', ''],
      d.techs.map(t => ['<b>' + esc(t.label) + '</b>', t.hosts, t.cves, t.confirmed ? ui.pill(t.confirmed, 'critical') : '0', t.potential ? ui.pill(t.potential, 'warning') : '0', t.not_applicable,
        '<button data-sec-wtech="' + escAttr(t.tech) + '">Voir les CVE</button>']), 'Aucune technologie corrélée : lancer une synchronisation puis une analyse du parc.') + '</section>';
  } else if (secWatchView === 'bulletins') {
    body = '<section class="panel"><h3>Nouveaux bulletins (14 jours)</h3>' + secTable(['Date', 'Source', 'Bulletin', 'CVE', 'Serveurs concernés'], d.bulletins.map(b => [secWhen(b.published || b.first_seen),
      esc(b.source_label), (b.url ? '<a href="' + escAttr(b.url) + '" target="_blank" rel="noopener noreferrer">' + esc(b.title) + '</a>' : '<b>' + esc(b.title) + '</b>') +
        (b.severity ? '<small>' + esc(b.severity) + (b.versions ? ' · versions publiées' : '') + '</small>' : ''),
      esc(b.cves.slice(0, 4).join(', ') + (b.cves.length > 4 ? ' …' : '')), b.applicable.length ? ui.pill(b.applicable.length + ' serveur(s)', 'warning') + '<small>' + esc(b.applicable.slice(0, 5).join(', ')) + '</small>' : '—']),
      'Aucun bulletin récent.') + '</section>' +
      '<section class="panel"><h3>CVE mises à jour par NVD</h3>' + secTable(['Date', 'CVE', 'Changement'], d.changes.map(ch => [secWhen(ch.at), secCveLink(ch.cve),
        esc({cvss: 'Score CVSS', nvd_status: 'Statut NVD', nvd_config: 'Versions affectées'}[ch.field] || ch.field) + ' : ' + esc(ch.old ?? '—') + ' → <b>' + esc(ch.new ?? '—') + '</b>']), 'Aucune modification relevée.') + '</section>';
  } else if (secWatchView === 'alerts') {
    body = '<section class="panel"><h3>Historique des alertes</h3>' + secTable(['Date', 'Niveau', 'Raison', 'Alerte', 'Serveurs', 'Suivi'], d.alerts.map(a => [secWhen(a.at),
      ui.pill(a.level === 'critical' ? 'Critique' : a.level === 'warning' ? 'Majeur' : 'Info', a.level === 'critical' ? 'critical' : a.level === 'warning' ? 'warning' : 'info') + (a.priority ? ' ' + ui.pill(a.priority, SEC_RANK[a.priority]) : ''),
      esc(a.kind_label), '<b>' + esc(a.title) + '</b><small>' + esc(a.detail || '') + '</small>', esc(a.hosts.slice(0, 5).join(', ') + (a.hosts.length > 5 ? ' …' : '')),
      (a.read_at ? 'Lue' : '<button data-sec-read="' + escAttr(a.id) + '">Marquer lue</button>') + '<small>' + (a.emailed_at ? 'E-mail envoyé ' + secWhen(a.emailed_at) : a.email_error ? 'E-mail en échec : ' + esc(a.email_error) : 'Non envoyée par e-mail') + '</small>']),
      'Aucune alerte.') + '</section>';
  } else {
    body = secWatchSettings(src);
  }
  return kpis + secJob(d.job) + secToolbar(d.job) + sources + views + body + '<p class="v2-formula">' + esc(d.scope) + '</p>';
}

function secRemediation() {
  const all = secGet('/api/security/vulns?status=all');
  const url = secMatchPlan ? '/api/security/matches/plan?id=' + secMatchPlan.id + '&cve=' + encodeURIComponent(secMatchPlan.cve) :
    secPlanId ? '/api/security/vulns/' + secPlanId + '/plan' : '';
  const plan = url ? secGet(url) : null;
  let html = '';
  if (url && !plan) html += '<section class="panel"><p>Préparation de la procédure…</p></section>';
  if (plan) {
    // Procédure d'une vulnérabilité (workflow) ou d'une correspondance de veille (confirmée ou potentielle).
    const meta = plan.vuln || {...plan.match, status_label: plan.match.status_label, confidence: plan.match.status === 'potential' ? 'à vérifier' : 'confirmé'};
    const facts = [['Serveur', (plan.server.name || plan.server.key) + ' (' + (plan.server.ip || '?') + ') — ' + (plan.server.environment || '')],
      ['CVE détectée', plan.cve + (plan.kev ? ' — exploitée activement (CISA KEV)' : '')], ['Composant vulnérable', plan.package + (plan.binaries.length ? ' (' + plan.binaries.join(', ') + ')' : '')],
      ['Version actuelle', plan.installed || 'inconnue'], ['Version cible (correctif officiel)', plan.fixed || 'non fournie par la source'], ['Impact potentiel', plan.impact],
      ['Sauvegarde préalable', plan.backup_required], ['État', meta.status_label + ' · ' + (plan.vuln ? 'confiance ' : 'applicabilité ') + meta.confidence]];
    html += '<section class="panel sec-plan">' + ui.head('Préparer la correction — ' + esc(plan.cve), esc(plan.server.name || ''),
      '<button data-copy="' + escAttr(plan.text) + '">Copier la procédure complète</button> <button data-sec-plan-close>Fermer</button>', 'TEXTE À COPIER · RIEN N’EST EXÉCUTÉ') +
      '<dl class="sc-facts">' + facts.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>' +
      plan.warnings.map(w => '<p class="form-error">⚠ ' + esc(w) + '</p>').join('') +
      [['Vérifications préalables (lecture seule)', plan.precheck], ['Sauvegarde préalable', plan.backup], ['Procédure de mise à jour', plan.update],
        ['Prise en compte (services, redémarrage)', plan.apply], ['Vérifications après correction', plan.verify], ['Procédure de rollback', plan.rollback]]
        .map(([t, lines]) => command(t, (lines || []).join('\n'))).join('') +
      '<p class="mini">' + esc(plan.generated_from) + ' Généré ' + secWhen(plan.generated_at) + '.</p>' +
      (plan.vuln && ['open', 'validated'].includes(plan.vuln.status) ? '<p>' + (plan.vuln.status === 'open' ? '<button data-sec-action="validate" data-sec-id="' + escAttr(plan.vuln.id) + '">Valider la vulnérabilité</button> ' : '') +
        '<button data-sec-action="start" data-sec-id="' + escAttr(plan.vuln.id) + '">Planifier la correction</button></p>' : '') +
      (plan.vuln && ['validated', 'in_progress'].includes(plan.vuln.status) && typeof itsmEntry === 'function' ? itsmEntry('vulnerability', plan.vuln.id, plan.vuln.host_key) : '') +
      (plan.match && plan.match.status === 'potential' ? '<p class="note">Applicabilité potentielle : confirmer après vérification (onglet Veille) pour ouvrir la vulnérabilité, la valider et créer le ticket GLPI.</p>' : '') + '</section>';
  }
  // Recommandations par serveur : plan consolidé (vulnérabilités et risques), par priorité.
  const fleet = secGet('/api/security/recommendations');
  if (secRecoHost) {
    const reco = secGet('/api/security/hosts/' + encodeURIComponent(secRecoHost) + '/recommendations');
    html += '<section class="panel" data-sec-reco-plan>' + ui.head('Plan de correction — ' + esc(reco?.host?.name || secRecoHost), esc(reco?.host?.environment || ''),
      '<button data-sec-host="' + escAttr(secRecoHost) + '">Analyse du serveur</button> <button data-sec-reco-close>Fermer</button>', 'PLAN CONSOLIDÉ · TEXTE À COPIER') +
      (typeof securityPlanMarkup === 'function' ? securityPlanMarkup(reco) : '') + '</section>';
  }
  html += '<section class="panel"><h3>Recommandations par serveur</h3>' + (fleet ? secTable(['Serveur', 'Priorité', 'P1 / P2 / P3 / P4', 'Premières recommandations', ''],
    fleet.items.filter(i => i.total).map(i => ['<b>' + esc(i.name) + '</b><small>' + esc(i.environment || '') + '</small>' + (i.exposed ? '<small>' + ui.pill('Exposé', 'critical', i.exposed) + '</small>' : ''),
      i.level ? ui.pill(i.level, {P1: 'critical', P2: 'warning', P3: 'info', P4: 'unknown'}[i.level]) : '—',
      ['P1', 'P2', 'P3', 'P4'].map(r => i.counts[r] || 0).join(' / '),
      i.top.map(t => esc(t.priority + ' · ' + t.title)).join('<br>') + (i.total > i.top.length ? '<small>… et ' + (i.total - i.top.length) + ' autre(s)</small>' : ''),
      '<button data-sec-reco="' + escAttr(i.key) + '">Voir le plan</button>']), 'Aucune recommandation : rien de prouvé à corriger avec les données disponibles.') :
    '<p>Chargement des recommandations…</p>') + '</section>';
  if (!all) return html + '<p>Chargement du suivi des remédiations…</p>';
  const groups = [['validated', 'Validées, à planifier'], ['in_progress', 'Correction planifiée'], ['resolved', 'Corrigées (constatées)'],
    ['accepted_risk', 'Risques acceptés'], ['false_positive', 'Faux positifs']];
  return html + groups.map(([status, title]) => {
    const items = all.items.filter(v => v.status === status).slice(0, 200);
    return '<section class="panel"><h3>' + esc(title) + ' <span class="state-count">' + all.items.filter(v => v.status === status).length + '</span></h3>' +
      secTable(['CVE', 'Serveur', 'Paquet', 'Responsable', status === 'resolved' ? 'Corrigée le' : 'Mise à jour', 'GLPI', ''], items.map(v => [secCve(v.cve),
        esc(v.host_name), esc(v.package + ' ' + (v.installed || '')) + (v.fixed ? '<small>→ ' + esc(v.fixed) + '</small>' : ''), esc(v.owner || '—'),
        secWhen(status === 'resolved' ? v.resolved_at : v.updated_at), typeof itsmBadge === 'function' ? itsmBadge('vulnerability', v.id) || '—' : '—',
        '<button data-sec-plan="' + escAttr(v.id) + '">Procédure</button>']), 'Aucune.') + '</section>';
  }).join('') + '<p class="v2-formula">Une vulnérabilité passe à « Corrigée » uniquement quand une nouvelle analyse constate la version corrigée ' +
    '(ou l’absence du paquet) sur toutes ses sources. Le ticket GLPI associé est alors résolu par le workflow ITSM.</p>';
}

function secHistory() {
  const d = secGet('/api/security/history?days=' + secHistoryDays);
  const head = '<div class="filters"><select id="sec-history-days" aria-label="Période">' + [[7, '7 jours'], [30, '30 jours'], [90, '90 jours'], [365, '1 an']]
    .map(([v, l]) => '<option value="' + v + '"' + (secHistoryDays === v ? ' selected' : '') + '>' + l + '</option>').join('') + '</select>' +
    '<button data-sec-csv>Rapport CSV (à traiter)</button><button data-sec-csv="all">Rapport CSV (tout)</button></div>';
  if (!d) return head + '<p>Chargement de l’historique…</p>';
  const trend = secTable(['Jour', 'Détectées', 'Corrigées'], d.trend.map(t => [esc(t.day), t.detected, t.resolved]), 'Aucun mouvement sur la période.');
  const labels = {detected: 'Détection', resolved: 'Correction constatée', reopened: 'Réapparition', validate: 'Validation', start: 'Planification',
    false_positive: 'Faux positif', accept_risk: 'Risque accepté', reopen: 'Réouverture', assign: 'Responsable', note: 'Note'};
  return head + '<section class="panel"><h3>Tendance</h3>' + trend + '</section>' +
    '<section class="panel"><h3>Journal des vulnérabilités <span class="state-count">' + d.events.length + '</span></h3>' + secTable(['Date', 'Action', 'CVE', 'Serveur', 'Par', 'Détail'],
      d.events.slice(0, 300).map(e => [secWhen(e.at), esc(labels[e.action] || e.action), secCve(e.cve), esc(e.host_name || ''), esc(e.actor) + (e.auth === 'local' ? '<small>déclaratif</small>' : ''), esc(e.detail || '')]), 'Aucun événement.') + '</section>' +
    '<section class="panel"><h3>Relevés SSH</h3>' + secTable(['Date', 'Serveur', 'Résultat', 'Paquets', 'Par'], d.scans.slice(0, 200).map(s => [secWhen(s.at), esc(s.host_name || s.host_key),
      esc(s.status) + (s.detail ? '<small>' + esc(s.detail) + '</small>' : ''), s.packages ?? '—', esc(s.actor || '')]), 'Aucun relevé.') + '</section>' +
    '<section class="panel"><h3>Synchronisations de veille</h3>' + secTable(['Date', 'Source', 'Résultat', 'Éléments', 'Nouveaux'], d.syncs.slice(0, 200).map(s => [secWhen(s.at), esc(s.source),
      esc(s.status) + (s.detail ? '<small>' + esc(s.detail) + '</small>' : ''), s.items ?? '—', s.new_items ?? '—']), 'Aucune synchronisation.') + '</section>';
}

function secMarkup() {
  const tabs = '<div class="tabs host-tabs" role="tablist" aria-label="Sections Sécurité">' + SEC_TABS.map(([k, v]) =>
    '<button role="tab" id="sec-tab-' + k + '" aria-controls="sec-panel" aria-selected="' + (secTab === k) + '" tabindex="' + (secTab === k ? 0 : -1) + '" class="' + (secTab === k ? 'active' : '') +
    '" data-sec-tab="' + k + '">' + esc(v) + '</button>').join('') + '</div>';
  const errors = secUrls().filter(u => secErrors[u]).map(u => '<p class="form-error" role="alert">' + esc(secErrors[u]) + '</p>').join('');
  const body = {dashboard: secDashboard, vulns: secVulns, hosts: secHosts, feeds: secFeeds, remediation: secRemediation, history: secHistory,
    ssh: () => typeof security === 'function' ? security() : ''}[secTab]();
  return tabs + errors + '<div id="sec-panel" role="tabpanel" aria-labelledby="sec-tab-' + secTab + '">' + body + '</div>';
}
function secPaint() {
  const root = document.getElementById('security-data');
  if (!root || page !== 'Sécurité' || selected) return;
  // Pas de repeinte pendant une saisie : le texte et le curseur seraient perdus.
  const active = document.activeElement;
  if (active && root.contains(active) && active.matches('textarea,input[type=search],input:not([type]),input[type=text]')) return;
  const scroll = window.scrollY;
  // Un onglet choisi au clavier garde le focus à travers les repeintes (chargement asynchrone).
  const tabFocus = active?.dataset?.secTab && root.contains(active) ? active.dataset.secTab : null;
  root.innerHTML = secMarkup();
  window.scrollTo(0, scroll);
  if (tabFocus) document.getElementById('sec-tab-' + tabFocus)?.focus();
}
pageRenderers['Sécurité'] = function () {
  // Demande venue de la fiche serveur (v2-detail.js) : analyse CVE de ce serveur.
  if (window.secRequestedPlan) { secPlanId = window.secRequestedPlan; secMatchPlan = null; secTab = 'remediation'; window.secRequestedPlan = null; }
  else if (window.secRequestedMatchPlan) {
    const [id, cve] = String(window.secRequestedMatchPlan).split('|');
    secMatchPlan = {id, cve}; secPlanId = ''; secTab = 'remediation'; window.secRequestedMatchPlan = null;
  } else if (window.secRequestedHost) { secHost = window.secRequestedHost; secTab = 'hosts'; }
  window.secRequestedHost = null;
  if (!document.getElementById('security-data')) $('#content').innerHTML = '<div id="security-data"></div>';
  // Le conteneur est conservé entre deux rendus : le repère de page (daily.js) est réajouté à chaque fois.
  $('#content').querySelectorAll(':scope > .page-guide').forEach(x => x.remove());
  secPaint();
  secLoad();
};
// Travail SSH ou veille en cours : suivi toutes les 5 s, seulement sur cette page.
poll('securite-travail', 5000, () => secLoad(true), {when: () => page === 'Sécurité' && !selected &&
  Object.values(secData).some(d => d?.job?.running)});
// Veille : quasi temps réel, relue chaque minute tant que l'onglet est affiché.
poll('securite-veille', 60000, () => secLoad(true), {when: () => page === 'Sécurité' && !selected && secTab === 'feeds'});

function secOpenTab(tab) {
  secTab = tab;
  try { localStorage.setItem('infraops.securite.onglet', tab); } catch { /* préférence non mémorisée */ }
  secPaint();
  secLoad();
}
async function secPost(url, body, b) {
  const by = document.getElementById('sec-by')?.value?.trim() ?? secName();
  if (!operatorIdentity?.authenticated && !by) { toast('Indiquez votre nom (mode local, déclaratif).'); document.getElementById('sec-by')?.focus(); return null; }
  if (by && typeof itsmRememberName === 'function') itsmRememberName(by);
  if (b) b.disabled = true;
  try { return await post(url, {...body, by}); }
  catch (error) { toast(error.message); return null; }
  finally { if (b?.isConnected) b.disabled = false; }
}
async function secCsv(b, status) {
  b.disabled = true;
  try {
    const r = await fetch('/api/security/report?format=csv&status=' + encodeURIComponent(status || 'active'), {credentials: 'same-origin'});
    if (!r.ok) throw new Error('Export CSV impossible (erreur ' + r.status + ').');
    const name = (r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'vulnerabilites.csv';
    const url = URL.createObjectURL(await r.blob());
    const link = document.createElement('a');
    link.href = url; link.download = name; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { toast(error.message); }
  finally { if (b.isConnected) b.disabled = false; }
}
function secRefreshAfterWrite() {
  for(const key of Object.keys(secData))if(key.startsWith('watch-detail:'))delete secData[key];
  secWatchOpen.clear();
  for (const k of Object.keys(secAt)) secAt[k] = 0;
  secLoad(true);
}

// Onglets Sécurité au clavier (audit UI du 31/10, accessibilité) : flèches, Début et Fin,
// comme les onglets WAF et ceux de la fiche serveur.
$('#content').addEventListener('keydown', e => {
  const tab = e.target.closest?.('[data-sec-tab]');
  if (page !== 'Sécurité' || !tab || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
  const keys = SEC_TABS.map(([k]) => k), at = keys.indexOf(tab.dataset.secTab);
  const next = e.key === 'Home' ? 0 : e.key === 'End' ? keys.length - 1 : (at + (e.key === 'ArrowRight' ? 1 : -1) + keys.length) % keys.length;
  e.preventDefault();
  secOpenTab(keys[next]);
  document.getElementById('sec-tab-' + keys[next])?.focus();
});
$('#content').addEventListener('click', async e => {
  if (page !== 'Sécurité' || selected) return;
  const b = e.target.closest('button');
  if (!b || b.disabled) return;
  if(b.dataset.secPage){if(b.dataset.secPage==='watch')secWatchOffset=Number(b.dataset.offset);else secOffset=Number(b.dataset.offset);secLoad();secPaint();return;}
  if (b.dataset.secTab) { secOpenTab(b.dataset.secTab); return; }
  if (b.hasAttribute('data-sec-notes-more')) { secNotesShown += SEC_NOTES_PAGE; secPaint(); return; }
  if (b.dataset.secHost) { secHost = b.dataset.secHost; secPackageQuery = ''; secOpenTab('hosts'); window.scrollTo(0, 0); return; }
  if (b.hasAttribute('data-sec-close-host')) { secHost = ''; secPaint(); return; }
  if (b.hasAttribute('data-sec-clear-host')) { secFilters.host = ''; secPaint(); secLoad(); return; }
  // Détails depuis un tableau compact (tableau de bord, fiche) : ouverts dans l'onglet Vulnérabilités.
  if (b.dataset.secDetail) {
    const id = b.dataset.secDetail;
    secOpen.add(id); secFilters = {...secFilters, status: 'all', q: '', severity: '', kev: false};
    secLoadDetail(id); secOpenTab('vulns'); return;
  }
  if (b.dataset.secOpen) {
    const id = b.dataset.secOpen;
    if (secOpen.has(id)) secOpen.delete(id);
    else { secOpen.add(id); secLoadDetail(id); }
    secPaint(); return;
  }
  if (b.dataset.secPlan) { secPlanId = b.dataset.secPlan; secMatchPlan = null; secOpenTab('remediation'); window.scrollTo(0, 0); return; }
  if (b.dataset.secMplan) { secMatchPlan = {id: b.dataset.secMplan, cve: b.dataset.secMcve}; secPlanId = ''; secOpenTab('remediation'); window.scrollTo(0, 0); return; }
  if (b.dataset.secReco) { secRecoHost = b.dataset.secReco; secPlanId = ''; secMatchPlan = null; secPaint(); secLoad(); window.scrollTo(0, 0); return; }
  if (b.hasAttribute('data-sec-reco-close')) { secRecoHost = ''; secPaint(); return; }
  if (b.hasAttribute('data-sec-plan-close')) { secPlanId = ''; secMatchPlan = null; secPaint(); return; }
  if (b.dataset.secWatchView) { secWatchView = b.dataset.secWatchView; secPaint(); return; }
  if (b.dataset.secWopen) {
    const c=b.dataset.secWopen;
    if(secWatchOpen.has(c))secWatchOpen.delete(c);
    else {
      secWatchOpen.add(c);
      const item=secGet(secWatchUrl())?.cves.find(v=>v.cve===c);
      if(item?.detail_available){
        delete secData['watch-detail:'+c];secPaint();
        try{const d=await api('/api/security/watch?limit=1&cve='+encodeURIComponent(c)+(secWatchFilters.host?'&host='+encodeURIComponent(secWatchFilters.host):''));secData['watch-detail:'+c]=d.cves.find(v=>v.cve===c)||{hosts:[]};}
        catch(error){secData['watch-detail:'+c]={error:error.message};}
      }
    }
    secPaint();return;
  }
  if (b.dataset.secWtech) { secWatchFilters.tech = b.dataset.secWtech; secWatchView = 'cves'; secLoad(); secPaint(); return; }
  if (b.dataset.secVulnOf) { secFilters = {...secFilters, host: b.dataset.secVulnOf, q: b.dataset.secVulnCve, status: 'all'}; secOpenTab('vulns'); return; }
  if (b.dataset.secDecide) {
    const note = document.querySelector('[data-sec-dnote="' + b.dataset.secMid + '|' + b.dataset.secMcve + '"]')?.value || '';
    const data = await secPost('/api/security/matches/decide', {id: b.dataset.secMid, cve: b.dataset.secMcve, decision: b.dataset.secDecide, note}, b);
    if (data) { toast(data.vuln_id && b.dataset.secDecide === 'confirm' ? 'Confirmée : vulnérabilité ouverte et validée (GLPI possible).' : 'Décision enregistrée.'); secRefreshAfterWrite(); }
    return;
  }
  if (b.hasAttribute('data-sec-mail-test')) {
    b.disabled = true;
    try { const r = await post('/api/security/mail/test', {}); toast('E-mail de test envoyé à ' + r.recipients.join(', ')); }
    catch (error) { toast(error.message); } finally { if (b.isConnected) b.disabled = false; }
    return;
  }
  if (b.hasAttribute('data-sec-pkg')) { secPackageQuery = document.getElementById('sec-pkg-q')?.value.trim() || ''; secLoadPackages(); return; }
  if (b.hasAttribute('data-sec-csv')) { secCsv(b, b.dataset.secCsv); return; }
  if (b.hasAttribute('data-sec-scan')) { if (await secPost('/api/security/scan', {}, b)) { toast('Relevé SSH lancé (lecture seule).'); secRefreshAfterWrite(); } return; }
  if (b.dataset.secScanHost) { if (await secPost('/api/security/hosts/' + encodeURIComponent(b.dataset.secScanHost) + '/scan', {}, b)) { toast('Analyse du serveur lancée.'); secRefreshAfterWrite(); } return; }
  if (b.hasAttribute('data-sec-sync')) { if (await secPost('/api/security/sync', {}, b)) { toast('Synchronisation de la veille lancée.'); secRefreshAfterWrite(); } return; }
  if (b.dataset.secRead) {
    const body = b.dataset.secRead === 'all' ? {all: true} : {ids: [Number(b.dataset.secRead)]};
    if (await secPost('/api/security/notifications/read', body, b)) secRefreshAfterWrite();
    return;
  }
  if (b.dataset.secAction) {
    const id = b.dataset.secId, action = b.dataset.secAction;
    const note = document.querySelector('[data-sec-note="' + id + '"]')?.value || '';
    const owner = document.querySelector('[data-sec-owner="' + id + '"]')?.value || '';
    const data = await secPost('/api/security/vulns/action', {id, action, note, owner}, b);
    if (data) {
      toast('Enregistré : ' + (SEC_STATUS[data.status]?.[0] || data.status));
      delete secData['/api/security/vulns/' + id];
      if (secOpen.has(id)) secLoadDetail(id);
      if (secPlanId === id) delete secData['/api/security/vulns/' + id + '/plan'];
      secRefreshAfterWrite();
    }
  }
});
function secLoadDetail(id) {
  api('/api/security/vulns/' + id).then(d => { secData['/api/security/vulns/' + id] = d; secPaint(); }).catch(error => toast(error.message));
}
async function secLoadPackages() {
  const url = '/api/security/packages/' + encodeURIComponent(secHost) + (secPackageQuery ? '?q=' + encodeURIComponent(secPackageQuery) : '');
  try { secData[url] = await api(url); } catch (error) { toast(error.message); }
  secPaint();
}
$('#content').addEventListener('change', e => {
  if (page !== 'Sécurité' || selected) return;
  const t = e.target;
  if (t.id === 'sec-status') { secOffset=0; secFilters.status = t.value; secLoad(); secPaint(); }
  else if (t.id === 'sec-severity') { secOffset=0; secFilters.severity = t.value; secLoad(); secPaint(); }
  else if (t.id === 'sec-kev') { secOffset=0; secFilters.kev = t.checked; secLoad(); secPaint(); }
  else if (t.id && t.id.startsWith('sec-w-')) { secWatchOffset=0; secWatchFilters[t.id.slice(6)] = t.value; secLoad(); secPaint(); }
  else if (t.id === 'sec-history-days') { secHistoryDays = Number(t.value); secLoad(); secPaint(); }
});
$('#content').addEventListener('input', e => {
  if (page !== 'Sécurité' || selected || e.target.id !== 'sec-q') return;
  secFilters.q = e.target.value;
  clearTimeout(secFilters.timer);
  secFilters.timer = setTimeout(() => {
    // Repeinte hors saisie (garde de secPaint), puis focus et curseur rendus à la fin du texte.
    secOffset=0; e.target.blur(); secPaint(); secLoad();
    const input = document.getElementById('sec-q');
    if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  }, 350);
});
$('#content').addEventListener('submit', async e => {
  if (page !== 'Sécurité' || e.target.id !== 'sec-settings') return;
  e.preventDefault();
  const f = e.target.elements;
  const b = e.target.querySelector('[type=submit]');
  b.disabled = true;
  try {
    await post('/api/security/settings', {feeds_auto: f.feeds_auto.checked, feeds_hours: Number(f.feeds_hours.value), scan_hours: Number(f.scan_hours.value),
      wazuh_indexer: f.wazuh_indexer.value, mail_to: f.mail_to.value.trim(), mail_level: f.mail_level.value, epss_threshold: Number(f.epss_threshold.value)});
    toast('Réglages sécurité enregistrés.');
    secRefreshAfterWrite();
  } catch (error) { toast(error.message); }
  finally { if (b.isConnected) b.disabled = false; }
});
