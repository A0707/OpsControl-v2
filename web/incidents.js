// Centre d'incidents : journal persistant (/api/incidents). Toutes les actions sont
// locales à OpsControl (prise en charge, suppression, réactivation) : aucune n'est
// transmise aux produits supervisés.
navGroups[0][1].splice(1, 0, ['Incidents', 'alert']);
subtitles.Incidents = 'Les événements les plus récents, leurs preuves datées et leur prise en charge.';

const INC_STATE = {open: ['Ouvert', 'info'], reopened: ['Réapparu', 'warning'], acknowledged: ['Pris en charge', 'info'],
  investigating: ['En investigation', 'warning'], suppressed: ['Masqué', 'unknown'], resolved: ['Résolu', 'ok']};
const INC_SEVERITY = Object.fromEntries(['critical', 'warning', 'preventive', 'info']
  .map(code => [code, [sevLabel(code), SEVERITY[code].tone]]));
const INC_EVENT = {opened: 'Ouverture', ack: 'Prise en charge', suppress: 'Suppression temporaire', reactivated: 'Réactivation',
  resolved: 'Résolution', reopened: 'Réapparition', severity_changed: 'Changement de gravité', ack_expired: 'Fin de prise en charge',
  investigation_started: 'Investigation démarrée', investigation_expired: 'Fin de l’investigation',
  suppression_expired: 'Fin de suppression', resolution_blocked: 'Résolution impossible (collecte incomplète)'};
const incFilters = {state: 'active', severity: '', source: '', q: '', chronic: 'exclude', order: 'recent', age:'all', view: '', offset: 0};
// Vues enregistrées (audit UI du 31/10, fiche 02.1) : mêmes filtres côté serveur que la passation.
function incViewParams() {
  if (incFilters.view === 'unowned') return {owner: '__none__', evidence: 'all'};
  if (incFilters.view === 'mine' && operatorIdentity?.authenticated) return {owner: operatorIdentity.user, evidence: 'all'};
  if (incFilters.view === 'stale') return {owner: '', evidence: 'stale'};
  return {owner: '', evidence: 'all'};
}
const incOpen = new Set();
const incEvents = new Map();
let incData = null, incSuppressions = null, incMaintenance = null, incRequest = 0, incFeedError = '';

function incDuration(seconds) {
  if (seconds == null) return 'Inconnue';
  const m = Math.floor(seconds / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
  return d ? d + ' j ' + h % 24 + ' h' : h ? h + ' h ' + m % 60 + ' min' : m + ' min';
}
function incStatePill(i) {
  const [label, tone] = INC_STATE[i.state] || ['Inconnu', 'unknown'];
  const permanent = i.state === 'suppressed' && !i.suppressed_until ? ' (permanent)' : '';
  return ui.pill(label + permanent, tone);
}
function incOwner(i) {
  if (!i.owner || !['acknowledged', 'investigating', 'suppressed'].includes(i.state)) return '<span class="mini">Personne</span>';
  const until = ['acknowledged', 'investigating'].includes(i.state) ? i.ack_until : i.suppressed_until;
  return '<b>' + esc(i.owner) + '</b>' + (i.owner_authenticated ? '' : ' <small title="Nom saisi en mode local">(déclaratif)</small>') +
    '<small>' + (until ? 'jusqu’au ' + incShort(until) : 'sans échéance') + '</small>' + (i.note ? '<small>« ' + esc(i.note) + ' »</small>' : '');
}
function incTarget(i) {
  return i.link?.host_key ? '<button class="link" data-host="' + escAttr(i.link.host_key) + '">' + esc(i.target) + '</button>' :
    esc(i.target === 'global' ? 'Toute la source' : i.target);
}
function incActions(i) {
  if (i.state === 'resolved') return '';
  const reactivate = ['acknowledged', 'investigating', 'suppressed'].includes(i.state);
  return '<div class="inc-actions">' + (i.state !== 'acknowledged' ? '<button data-inc-action="ack" data-inc-id="' + escAttr(i.id) + '">Reconnaître</button>' : '') +
    (i.state !== 'investigating' ? '<button data-inc-action="investigate" data-inc-id="' + escAttr(i.id) + '">Investiguer</button>' : '') +
    (i.state !== 'suppressed' ? '<button data-inc-action="suppress" data-inc-id="' + escAttr(i.id) + '" title="Masquer : retiré des compteurs, toujours suivi, motif et échéance obligatoires">Masquer…</button>' : '') +
    (reactivate ? '<button data-inc-action="reactivate" data-inc-id="' + escAttr(i.id) + '">Réactiver</button>' : '') + '</div>';
}
function incEventsMarkup(id) {
  const events = incEvents.get(id);
  if (!events) return '<p class="mini">Chargement de l’historique…</p>';
  return '<ol class="inc-timeline">' + events.map(e => {
    const d = e.detail || {};
    const extra = [d.severity && (INC_SEVERITY[d.previous]?.[0] ? INC_SEVERITY[d.previous][0] + ' → ' : '') + (INC_SEVERITY[d.severity]?.[0] || d.severity),
      d.duration && ({'24h': '24 h', '7d': '7 jours', permanent: 'permanente'}[d.duration]), d.reason, d.note && '« ' + d.note + ' »'].filter(Boolean).join(' · ');
    return '<li>' + exactTimeMarkup(e.at) + '<b>' + esc(INC_EVENT[e.kind] || e.kind) + '</b>' +
      (e.actor ? ' par ' + esc(e.actor) + (e.actor_authenticated ? '' : ' (déclaratif)') : '') + (extra ? '<small>' + esc(extra) + '</small>' : '') + '</li>';
  }).join('') + '</ol>';
}
// Les secondes et le fuseau sont visibles : l'infobulle n'est plus la seule preuve datée.
function incShort(value) {
  return exactTimeMarkup(value);
}
function incEventDate(i) {
  const kind = i.event_kind || (i.state === 'resolved' ? 'resolved' : i.reopened_at ? 'reopened' : i.since_basis);
  const at = i.event_at || (i.state === 'resolved' ? i.resolved_at : i.reopened_at) || i.since || i.opened_at;
  const label = {resolved:'Résolution',reopened:'Réapparition',source:'Début déclaré par la source',journal:'Premier suivi OpsControl'}[kind] || 'Premier suivi OpsControl';
  return '<span class="inc-date-label">' + label + '</span><b>' + incShort(at) + '</b>';
}
function incStartContext(i) {
  const since = i.since || i.opened_at;
  const event = i.event_at || (i.state === 'resolved' ? i.resolved_at : i.reopened_at) || since;
  const initial = Date.parse(event) !== Date.parse(since) ? 'Début initial : ' + incShort(since) + ' · ' : '';
  return '<small>' + initial + 'Durée : ' + esc(incDuration(i.duration_seconds)) + '</small>';
}
function incRow(i) {
  const [sevLabel, sevTone] = INC_SEVERITY[i.severity] || ['Inconnue', 'unknown'];
  const open = incOpen.has(i.id);
  const age=i.recency||(()=>{const n=ageSeconds(i.event_at||i.reopened_at||i.since||i.opened_at);return n===null||n<0?'unknown':n<=86400?'recent':'old';})();
  const ageLabel={recent:i.event_kind==='journal'?'Nouveau suivi · < 24 h':'Nouveau · < 24 h',old:'Ancien · > 24 h',unknown:'Ancienneté inconnue'}[age];
  return '<tr class="inc-row" data-inc-key="' + escAttr(i.id) + '"><td class="inc-status"><span class="inc-pills">' + ui.pill(sevLabel, sevTone) + incStatePill(i) + '</span><span class="inc-recency">'+ui.pill(ageLabel,age==='recent'?'info':'unknown')+'</span>' +
    (i.severity_max !== i.severity ? '<small>max : ' + esc(INC_SEVERITY[i.severity_max]?.[0] || i.severity_max) + '</small>' : '') +
    (i.reopen_count ? '<small>' + i.reopen_count + ' réapparition(s)</small>' : '') + (i.chronic ? '<small>Chronique</small>' : '') + '</td>' +
    '<td class="inc-title"><button class="link inc-toggle-title" data-inc-toggle="' + escAttr(i.id) + '" aria-expanded="' + open + '" title="' + (open ? 'Masquer' : 'Afficher') + ' la preuve et l’historique">' +
    '<span aria-hidden="true">' + (open ? '▾ ' : '▸ ') + '</span>' + esc(i.title) + '</button><small>' + esc(i.source) + ' · ' + esc(i.type) +
    (i.target && String(i.title).includes(i.target) && !i.link?.host_key ? '' : ' · cible : ' + incTarget(i)) + '</small>' +
    (i.maintenance ? '<span class="inc-maintenance">Maintenance · ' + esc(i.maintenance.name) + ' · jusqu’au ' + esc(stamp(i.maintenance.ends_at)) + '</span>' : '') +
    (i.confirmation_blocked ? '<small class="inc-blocked" title="' + escAttr(i.confirmation_blocked_reason) + '">Résolution impossible : ' + esc(i.confirmation_blocked_reason) + '</small>' : '') +
    '</td>' +
    '<td class="inc-when">' + incEventDate(i) + incStartContext(i) +
    '<span class="inc-proof"><span class="inc-date-label">Dernière preuve</span>' + incShort(i.observed_at) +
    (i.observed_at ? '<small>' + ui.fresh(i.observed_at, 'Preuve', 900) + '</small>' : '<small>Date de preuve inconnue</small>') + '</span></td>' +
    '<td class="inc-act"><div class="inc-owner">' + incOwner(i) + '</div>' + incActions(i) + '</td></tr>' +
    (open ? '<tr class="inc-detail" data-inc-detail-key="' + escAttr(i.id) + '"><td colspan="4"><div class="inc-detail-grid"><div><h3>Preuve</h3><pre>' + esc(i.evidence || 'Aucune preuve textuelle transmise par la source.') + '</pre>' +
      '<p class="note">Règle : ' + esc(i.rule || 'non renseignée') + ' · début déclaré par la source : ' + incShort(i.first_observed_at) + ' · suivi par OpsControl depuis le ' + incShort(i.opened_at) + ' · vu pour la dernière fois par OpsControl : ' + incShort(i.last_seen_at) + '</p></div><div><h3>Historique</h3>' + incEventsMarkup(i.id) + '</div></div>' + (typeof itsmEntry === 'function' ? itsmEntry('incident', i.id) : '') + '</td></tr>' : '');
}
function incMarkup() {
  if (!incData) return '<div class="panel">' + (incFeedError ? '<p role="alert" class="form-error">Journal indisponible : ' + esc(incFeedError) + '</p>' : 'Chargement du journal d’incidents…') + '</div>';
  const c = incData.counts || {}, s = incData.active_by_severity || {};
  const sync = incData.sync || {};
  // Journal jamais rapproché : aucun chiffre, sinon « 0 ouvert » passerait pour un parc sain.
  const pending = !sync.at;
  // Dernier rapprochement en échec : les compteurs datent du précédent ; « 0 » n'est donc
  // pas une preuve de parc sain et ne s'affiche jamais en vert (audit SUP-09).
  const zero = sync.error || incFeedError ? 'unknown' : 'ok';
  const kpis = pending ? ui.empty('Journal pas encore rapproché', 'Le rapprochement a lieu au démarrage, après chaque collecte et toutes les 60 s. Aucun compteur n’est affiché avant.') : '<div class="v2-kpis inc-kpis">' +
    ui.kpi('Ouverts', (c.open || 0) + (c.reopened || 0), sync.error ? 'Dernier rapprochement en échec' : (c.reopened || 0) + ' réapparu(s)', (c.open || c.reopened) ? 'critical' : zero, 'data-inc-state="active"') +
    ui.kpi('Critiques actifs', s.critical || 0, 'Hors chroniques et suppressions', s.critical ? 'critical' : zero, 'data-inc-severity="critical"') +
    ui.kpi('Pris en charge', c.acknowledged || 0, 'Avec responsable et échéance', '', 'data-inc-state="acknowledged"') +
    ui.kpi('En investigation', c.investigating || 0, 'Diagnostic actif et tracé', (c.investigating || 0) ? 'warning' : '', 'data-inc-state="investigating"') +
    ui.kpi('Masqués', c.suppressed || 0, 'Toujours suivis, motif et échéance', c.suppressed ? 'unknown' : '', 'data-inc-state="suppressed"') +
    ui.kpi('Résolus', c.resolved || 0, 'Absents d’une collecte complète', '', 'data-inc-state="resolved"') +
    ui.kpi('Maintenances actives', incData.maintenance_active || 0, 'Incidents visibles, hors compteur actionnable', incData.maintenance_active ? 'info' : '') +
    ui.kpi('Chroniques', incData.chronic_active || 0, 'Déclencheurs ouverts depuis plus de 30 jours', incData.chronic_active ? 'unknown' : '', 'data-inc-chronic="only"') + '</div>';
  const opt = (v, l, cur) => '<option value="' + escAttr(v) + '"' + (v === cur ? ' selected' : '') + '>' + esc(l) + '</option>';
  const ageCounts=incData.recency_counts||{};
  const ageTabs='<div class="inc-age-tabs" role="group" aria-label="Ancienneté des incidents">'+[['all','Tous'],['recent','Nouveaux · 24 h'],['old','Anciens'],['unknown','Ancienneté inconnue']].map(([k,label])=>
    '<button id="inc-age-'+k+'" data-inc-age="'+k+'" aria-pressed="'+(incFilters.age===k)+'">'+label+(ageCounts[k]!=null?' <b>'+ageCounts[k]+'</b>':k==='all'&&Object.keys(ageCounts).length?' <b>'+Object.values(ageCounts).reduce((a,b)=>a+b,0)+'</b>':'')+'</button>').join('')+'</div>';
  const filters = '<div class="filters inc-filters"><input id="inc-search" type="search" placeholder="Titre, cible ou type…" value="' + escAttr(incFilters.q) + '" aria-label="Rechercher un incident">' +
    '<select id="inc-state" aria-label="État">' + [['active', 'Actifs'], ['open', 'Ouverts'], ['reopened', 'Réapparus'], ['acknowledged', 'Pris en charge'], ['investigating', 'En investigation'], ['suppressed', 'Masqués'], ['resolved', 'Résolus'], ['all', 'Tous']].map(([v, l]) => opt(v, l, incFilters.state)).join('') + '</select>' +
    '<select id="inc-severity" aria-label="Gravité">' + [['', 'Toutes gravités']].concat(Object.entries(INC_SEVERITY).map(([k, v]) => [k, v[0]])).map(([v, l]) => opt(v, l, incFilters.severity)).join('') + '</select>' +
    '<select id="inc-source" aria-label="Source">' + [['', 'Toutes sources']].concat((incData.sources || []).map(x => [x, x])).map(([v, l]) => opt(v, l, incFilters.source)).join('') + '</select>' +
    '<select id="inc-chronic" aria-label="Chroniques">' + [['exclude', 'Sans chroniques'], ['include', 'Avec chroniques'], ['only', 'Chroniques seules']].map(([v, l]) => opt(v, l, incFilters.chronic)).join('') + '</select>' +
    '<select id="inc-view" aria-label="Vue enregistrée">' + [['', 'Toutes les prises en charge'], ['unowned', 'Sans responsable'], ...(operatorIdentity?.authenticated ? [['mine', 'À moi']] : []), ['stale', 'Preuve ancienne']].map(([v, l]) => opt(v, l, incFilters.view)).join('') + '</select></div>' +
    '<div class="inc-list-context"><label>Trier <select id="inc-order" aria-label="Ordre des incidents">' + [['recent','Plus récents d’abord'],['severity','Gravité puis plus récents'],['observed','Dernière preuve reçue'],['oldest','Plus anciens d’abord']].map(([v,l])=>opt(v,l,incFilters.order)).join('') + '</select></label><p>Dates à la seconde · Africa/Casablanca (UTC selon la date)<br>Nouvelle occurrence ou réapparition ; un rafraîchissement ne change pas le début.</p></div>';
  const items = incData.items || [];
  const table = items.length ? '<div class="table inc-table"><table><caption class="note">' + incData.total + ' incident(s) · ' + (incFilters.offset + 1) + ' à ' + (incFilters.offset + items.length) + '</caption><thead><tr>' +
    ['Gravité / état', 'Incident et cible', 'Événement et preuve', 'Prise en charge'].map(h => '<th scope="col">' + h + '</th>').join('') + '</tr></thead><tbody>' + items.map(incRow).join('') + '</tbody></table></div>' +
    '<div class="filters"><button data-inc-page="-1"' + (incFilters.offset ? '' : ' disabled') + '>Précédent</button><button data-inc-page="1"' + (incFilters.offset + items.length >= incData.total ? ' disabled' : '') + '>Suivant</button></div>' :
    pending ? '' : ui.empty('Aucun incident pour ces critères', incFilters.state === 'active' ? 'Aucun incident actif dans les observations disponibles. Vérifier la fraîcheur des sources avant de conclure.' : '');
  return '<section class="panel">' + ui.head('Journal d’incidents', (sync.at ? ui.fresh(sync.at, 'Rapprochement', 120) + ' · ' + incShort(sync.at) : '<span class="mini">Rapprochement en attente</span>') +
    (sync.error ? '<span class="form-error">Rapprochement en échec : ' + esc(sync.error) + ' · rien n’a été résolu</span>' : ''), '<button data-inc-sync>Rapprocher maintenant</button>', 'PERSISTANT · LOCAL') +
    '<div id="inc-feed-status" role="status">' + (incFeedError ? '<p role="alert" class="form-error">Actualisation impossible : ' + esc(incFeedError) + ' · dernière liste reçue conservée. Les critères affichés sont à reconfirmer.</p>' : '') + '</div>' +
    kpis + ageTabs + '<p class="inc-age-guide">Ancienneté = dernière occurrence ou premier suivi. Traitement = état de prise en charge. Notifications : critiques de moins de 15 min, avec preuve récente.</p>'+filters + '<div id="inc-list">' + table + '</div><p class="v2-formula">' + esc(incData.policy || '') + ' Les actions sont locales à OpsControl ; aucune n’est transmise aux produits supervisés.</p></section>' +
    incMaintenanceMarkup() + incSuppressionsMarkup();
}
function incMaintenanceMarkup() {
  const rows = incMaintenance?.items || [];
  // Aucune fenêtre : une seule ligne (le panneau vide occupait ~270 px), bouton et politique conservés.
  if (!rows.length) return '<section class="panel inc-maint-empty" id="inc-maintenance"><div><b>Fenêtres de maintenance</b> · <span class="mini">aucune active ou planifiée — anti-bruit explicite, preuves et résolution inchangées</span></div>' +
    '<button data-inc-maintenance-new>+ Planifier</button><p class="v2-formula">' + esc(incMaintenance?.policy || '') + '</p></section>';
  return '<section class="panel" id="inc-maintenance">' + ui.head('Fenêtres de maintenance',
    '<span class="mini">' + (incMaintenance?.active || 0) + ' active(s) · preuves et résolution inchangées</span>',
    '<button data-inc-maintenance-new>+ Planifier</button>', 'ANTI-BRUIT EXPLICITE') +
    (rows.length ? '<div class="table"><table><thead><tr><th>Fenêtre</th><th>Périmètre</th><th>Début</th><th>Fin</th><th>Créée par</th><th></th></tr></thead><tbody>' + rows.map(w =>
      '<tr><td><b>' + esc(w.name) + '</b>' + (w.active ? '<span class="badge observed">Active</span>' : '<small>Planifiée</small>') + (w.note ? '<small>' + esc(w.note) + '</small>' : '') + '</td>' +
      '<td>' + esc(w.source || 'Toutes les sources') + '<small>' + esc(w.target || 'Toutes les cibles') + '</small></td><td>' + esc(stamp(w.starts_at)) + '</td><td>' + esc(stamp(w.ends_at)) + '</td>' +
      '<td>' + esc(w.actor) + (w.actor_authenticated ? '' : '<small>(déclaratif)</small>') + '</td><td><button data-inc-maintenance-delete="' + w.id + '">Annuler</button></td></tr>').join('') + '</tbody></table></div>' :
      ui.empty('Aucune maintenance active ou planifiée', 'Planifier une fenêtre pour réduire le bruit sans masquer les preuves.')) +
    '<p class="v2-formula">' + esc(incMaintenance?.policy || '') + '</p></section>';
}
async function incRefreshAlertNoisePolicy() {
  if (typeof loadAlertMaintenance !== 'function') return;
  await loadAlertMaintenance(true);
  if (typeof alertStrip === 'function') alertStrip();
  if (typeof alertNotify === 'function') alertNotify();
}
function incSuppressionsMarkup() {
  const rows = incSuppressions?.items || [];
  if (!rows.length) return '<div id="inc-suppressions"></div>';
  return '<section class="panel" id="inc-suppressions">' + ui.head('Suppressions actives', '<span class="mini">' + rows.length + ' incident(s) masqué(s), toujours suivis</span>') +
    '<div class="table"><table><thead><tr><th>Incident</th><th>Cible</th><th>Par</th><th>Échéance</th><th></th></tr></thead><tbody>' +
    rows.map(i => '<tr><td>' + esc(i.title) + '<small>' + esc(i.source) + '</small></td><td>' + incTarget(i) + '</td><td>' + esc(i.owner || '—') + (i.owner_authenticated ? '' : ' <small>(déclaratif)</small>') + (i.note ? '<small>« ' + esc(i.note) + ' »</small>' : '') +
      '</td><td>' + (i.suppressed_until ? esc(stamp(i.suppressed_until)) : '<b>Permanente</b>') + '</td><td><button data-inc-action="reactivate" data-inc-id="' + escAttr(i.id) + '">Réactiver</button></td></tr>').join('') + '</tbody></table></div></section>';
}

function incQuery() {
  const p = new URLSearchParams({state: incFilters.state, severity: incFilters.severity, source: incFilters.source, q: incFilters.q,
    chronic: incFilters.chronic, order: incFilters.order, age:incFilters.age, ...incViewParams(), limit: '20', offset: String(incFilters.offset)});  // tri avant pagination côté serveur
  return '/api/incidents?' + p;
}
function incReconcileList(current, next) {
  const currentBody = current?.querySelector('tbody'), nextBody = next?.querySelector('tbody');
  if (!currentBody || !nextBody) return false;
  const previous = new Map([...currentBody.querySelectorAll(':scope > .inc-row')].map(row => [row.dataset.incKey, row]));
  const nodes = [];
  for (const row of nextBody.querySelectorAll(':scope > .inc-row')) {
    const detail = row.nextElementSibling?.classList.contains('inc-detail') ? row.nextElementSibling : null;
    const prior = previous.get(row.dataset.incKey);
    const priorDetail = prior?.nextElementSibling?.classList.contains('inc-detail') ? prior.nextElementSibling : null;
    // L'âge des preuves change chaque seconde sans changement métier. Garder la
    // ligne et ses contrôles lorsque seule cette horloge diffère évite de perdre le focus.
    let keep = prior && prior.outerHTML === row.outerHTML;
    if(prior && !keep){
      const before=prior.cloneNode(true),after=row.cloneNode(true);
      for(const el of before.querySelectorAll('.data-age'))el.textContent='';
      for(const el of after.querySelectorAll('.data-age'))el.textContent='';
      keep=before.outerHTML===after.outerHTML;
      if(keep){const ages=[...row.querySelectorAll('.data-age')];prior.querySelectorAll('.data-age').forEach((el,n)=>{el.textContent=ages[n].textContent;});}
    }
    nodes.push(keep ? prior : row);
    if (detail) nodes.push(priorDetail && priorDetail.outerHTML === detail.outerHTML ? priorDetail : detail);
  }
  currentBody.replaceChildren(...nodes);
  const caption = current.querySelector('caption'), nextCaption = next.querySelector('caption');
  if (caption && nextCaption) caption.textContent = nextCaption.textContent;
  const pager = current.querySelector(':scope > .filters'), nextPager = next.querySelector(':scope > .filters');
  if (pager && nextPager && pager.outerHTML !== nextPager.outerHTML) pager.replaceWith(nextPager);
  return true;
}
function incPaint(full) {
  const target = document.getElementById('incidents-data');
  if (!target) return;
  const focus = document.activeElement?.id, pos = document.activeElement?.selectionStart;
  if (full || !document.getElementById('inc-list')) target.innerHTML = incMarkup();
  else {
    const tmp = document.createElement('div');
    tmp.innerHTML = incMarkup();
    // Rafraîchissement partiel : les champs de filtre restent montés (focus et saisie conservés).
    const nextList = tmp.querySelector('#inc-list'), currentList = target.querySelector('#inc-list');
    if (!incReconcileList(currentList, nextList) && nextList && currentList) currentList.replaceWith(nextList);
    ['.inc-kpis', '.inc-age-tabs', '#inc-maintenance', '#inc-suppressions', '#inc-feed-status'].forEach(sel => { const next = tmp.querySelector(sel), cur = target.querySelector(sel); if (next && cur && next.outerHTML !== cur.outerHTML) cur.replaceWith(next); });
    const head = tmp.querySelector('.v2-head'), curHead = target.querySelector('.v2-head');
    if (head && curHead) curHead.replaceWith(head);
  }
  if (focus && document.getElementById(focus) && document.activeElement?.id !== focus) {
    const el = document.getElementById(focus);
    el.focus({preventScroll: true});
    if (pos != null && el.setSelectionRange) el.setSelectionRange(pos, pos);
  }
}
async function loadIncidents(full = false) {
  if (!document.getElementById('incidents-data')) return;
  const id = ++incRequest;
  try {
    const [data, suppressions, maintenance] = await Promise.all([api(incQuery()), api('/api/incidents/suppressions'), api('/api/incidents/maintenance')]);
    if (id !== incRequest) return; // réponse tardive d'un filtre précédent : ignorée
    if (!(data.items || []).length && data.total > 0 && incFilters.offset >= data.total) {
      incFilters.offset = Math.floor((data.total - 1) / 20) * 20;
      return loadIncidents(full);
    }
    incFeedError = '';
    incData = data;
    incSuppressions = suppressions;
    incMaintenance = maintenance;
    incPaint(full);
  } catch (e) {
    if (id === incRequest) { incFeedError = e.message; incPaint(!incData); }
  }
}
async function incLoadEvents(id) {
  try {
    const data = await api('/api/incidents/events?id=' + encodeURIComponent(id));
    incEvents.set(id, data.events);
  } catch (e) { incEvents.set(id, [{at: null, kind: 'Historique indisponible : ' + e.message}]); }
  incPaint(false);
}

// Dialogue de prise en charge / suppression : durée, note, nom si mode local.
const incDialog = document.createElement('dialog');
incDialog.id = 'incident-dialog';
document.body.append(incDialog);
function incOpenDialog(action, id) {
  // Aussi les incidents affichés dans une fiche serveur (web/host-incidents.js).
  const item = (incData?.items || []).concat(incSuppressions?.items || [], typeof hostIncidentItems === 'function' ? hostIncidentItems() : []).find(i => i.id === id);
  const local = !operatorIdentity?.authenticated;
  const title = {ack: 'Reconnaître', investigate: 'Démarrer l’investigation', suppress: 'Masquer', reactivate: 'Réactiver'}[action];
  let who = '';
  try { who = localStorage.getItem('infraops.operateur') || operatorIdentity?.default_name || ''; } catch { /* stockage indisponible */ }
  incDialog.innerHTML = '<form id="incident-form" method="dialog"><div class="panel-head"><h2>' + esc(title) + '</h2><button type="button" data-inc-close>Fermer</button></div>' +
    '<p><b>' + esc(item?.title || id) + '</b><br><span class="mini">' + esc(item?.source || '') + ' · ' + esc(item?.target || '') + '</span></p>' +
    (action === 'reactivate' ? '<p class="note">L’incident redevient actif : bandeau et notifications reprennent.</p>' :
      '<label>Durée<select name="duration"><option value="24h">24 heures</option><option value="7d">7 jours</option><option value="permanent">Permanente (jusqu’à réactivation)</option></select></label>' +
      (action === 'suppress' ? '<p class="note">Masquer retire l’incident des compteurs sans le résoudre : il reste suivi, réapparaît à l’échéance et se résout seulement sur collecte complète.</p>' : '')) +
    (local ? '<label>Votre nom (mode local non authentifié : déclaratif)<input name="by" required maxlength="60" value="' + escAttr(who) + '"></label>' :
      '<p class="note">Enregistré au nom de <b>' + esc(operatorIdentity.user) + '</b> (identité du reverse proxy).</p>') +
    (action === 'suppress' ? '<label>Motif (obligatoire)<input name="note" required minlength="3" maxlength="300" placeholder="Maintenance, faux positif connu, ticket…"></label>' :
      '<label>Note (facultative)<input name="note" maxlength="300" placeholder="Ticket, action en cours…"></label>') +
    '<input type="hidden" name="id" value="' + escAttr(id) + '"><input type="hidden" name="action" value="' + escAttr(action) + '">' +
    '<p class="form-error" role="alert"></p><div class="panel-head"><span class="mini">Action locale à OpsControl</span><button class="primary" type="submit">' + esc(title) + '</button></div></form>';
  incDialog.showModal();
  incDialog.querySelector('input[name=by]')?.focus();
}
incDialog.addEventListener('click', e => { if (e.target.closest('[data-inc-close]')) incDialog.close(); });
incDialog.addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target, values = Object.fromEntries(new FormData(form)), button = form.querySelector('[type=submit]');
  const body = {id: values.id, note: values.note || '', by: values.by || ''};
  if (values.action !== 'reactivate') body.duration = values.duration;
  button.disabled = true;
  try {
    await post('/api/incidents/' + values.action, body);
    if (values.by) { try { localStorage.setItem('infraops.operateur', values.by); } catch { /* stockage indisponible */ } }
    incDialog.close();
    incEvents.delete(values.id);
    toast({ack: 'Incident reconnu.', investigate: 'Investigation démarrée.', suppress: 'Suppression enregistrée : incident masqué, toujours suivi.', reactivate: 'Incident réactivé.'}[values.action]);
    await loadIncidents(false);
  } catch (error) { form.querySelector('.form-error').textContent = error.message; }
  finally { button.disabled = false; }
});

const maintenanceDialog = document.createElement('dialog');
maintenanceDialog.id = 'maintenance-dialog';
document.body.append(maintenanceDialog);
function incOpenMaintenanceDialog() {
  const local = !operatorIdentity?.authenticated;
  let who = '';
  try { who = localStorage.getItem('infraops.operateur') || operatorIdentity?.default_name || ''; } catch { /* stockage indisponible */ }
  const start = new Date(Date.now() + 5 * 60000), end = new Date(Date.now() + 65 * 60000);
  const localDate = date => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  maintenanceDialog.innerHTML = '<form id="maintenance-form" method="dialog"><div class="panel-head"><h2>Planifier une maintenance</h2><button type="button" data-maint-close>Fermer</button></div>' +
    '<p class="note">La fenêtre réduit les compteurs actionnables. Les incidents restent visibles, suivis et ne sont jamais résolus par la maintenance.</p>' +
    '<label>Nom<input name="name" required minlength="3" maxlength="120" placeholder="Maintenance hyperviseur"></label><div class="inc-maint-grid">' +
    '<label>Début<input name="starts_at" type="datetime-local" required value="' + localDate(start) + '"></label><label>Fin<input name="ends_at" type="datetime-local" required value="' + localDate(end) + '"></label>' +
    '<label>Source<select name="source"><option value="">Toutes les sources</option>' + (incData?.sources || []).map(s => '<option value="' + escAttr(s) + '">' + esc(s) + '</option>').join('') + '</select></label>' +
    '<label>Cible (facultatif)<input name="target" maxlength="200" placeholder="web01"></label></div>' +
    (local ? '<label>Votre nom (déclaratif)<input name="by" required maxlength="60" value="' + escAttr(who) + '"></label>' : '<p class="note">Créée par <b>' + esc(operatorIdentity.user) + '</b>.</p>') +
    '<label>Note<input name="note" maxlength="300" placeholder="Ticket, périmètre, précautions…"></label><p class="form-error" role="alert"></p>' +
    '<div class="panel-head"><span class="mini">Durée maximale : 30 jours</span><button class="primary" type="submit">Planifier</button></div></form>';
  maintenanceDialog.showModal();
  maintenanceDialog.querySelector('input[name=name]')?.focus();
}
maintenanceDialog.addEventListener('click', e => { if (e.target.closest('[data-maint-close]')) maintenanceDialog.close(); });
maintenanceDialog.addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target, values = Object.fromEntries(new FormData(form)), button = form.querySelector('[type=submit]');
  button.disabled = true;
  try {
    await post('/api/incidents/maintenance', {...values, starts_at: new Date(values.starts_at).toISOString(), ends_at: new Date(values.ends_at).toISOString()});
    if (values.by) { try { localStorage.setItem('infraops.operateur', values.by); } catch { /* stockage indisponible */ } }
    maintenanceDialog.close(); toast('Maintenance planifiée.'); await incRefreshAlertNoisePolicy(); await loadIncidents(false);
  } catch (error) { form.querySelector('.form-error').textContent = error.message; }
  finally { button.disabled = false; }
});

$('#content').addEventListener('click', async e => {
  if (page !== 'Incidents' || selected) return;
  const ageButton=e.target.closest('[data-inc-age]');
  if(ageButton){incFilters.age=ageButton.dataset.incAge;incFilters.offset=0;await loadIncidents(false);return;}
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-inc-maintenance-new')) { incOpenMaintenanceDialog(); return; }
  if (b.dataset.incMaintenanceDelete) {
    if (!confirm('Annuler cette fenêtre de maintenance ? Les incidents concernés redeviennent actionnables.')) return;
    let by = ''; try { by = localStorage.getItem('infraops.operateur') || operatorIdentity?.default_name || ''; } catch { /* stockage indisponible */ }
    try { await post('/api/incidents/maintenance/delete', {id: Number(b.dataset.incMaintenanceDelete), by}); toast('Maintenance annulée.'); await incRefreshAlertNoisePolicy(); await loadIncidents(false); }
    catch (error) { $('#error').textContent = error.message; }
    return;
  }
  if (b.dataset.incAction) { incOpenDialog(b.dataset.incAction, b.dataset.incId); return; }
  if (b.dataset.incToggle) {
    const id = b.dataset.incToggle;
    if (incOpen.has(id)) incOpen.delete(id); else { incOpen.add(id); if (!incEvents.has(id)) incLoadEvents(id); }
    incPaint(false);
    return;
  }
  if (b.dataset.incPage) { incFilters.offset = Math.max(0, incFilters.offset + Number(b.dataset.incPage) * 50); loadIncidents(false); return; }
  if (b.hasAttribute('data-inc-sync')) {
    b.disabled = true;
    try { await post('/api/incidents/sync'); await loadIncidents(false); } catch (error) { $('#error').textContent = error.message; } finally { if (b.isConnected) b.disabled = false; }
    return;
  }
  if (b.dataset.incState || b.dataset.incSeverity || b.dataset.incChronic) {
    Object.assign(incFilters, {state: b.dataset.incState || 'active', severity: b.dataset.incSeverity || '', chronic: b.dataset.incChronic || 'exclude', offset: 0});
    loadIncidents(true);
  }
});
$('#content').addEventListener('input', e => {
  if (e.target.id !== 'inc-search') return;
  incFilters.q = e.target.value;
  incFilters.offset = 0;
  clearTimeout(incDialog.searchTimer);
  incDialog.searchTimer = setTimeout(() => loadIncidents(false), 250);
});
$('#content').addEventListener('change', e => {
  const key = {'inc-state': 'state', 'inc-severity': 'severity', 'inc-source': 'source', 'inc-chronic': 'chronic', 'inc-order':'order', 'inc-view': 'view'}[e.target.id];
  if (!key) return;
  incFilters[key] = e.target.value;
  incFilters.offset = 0;
  loadIncidents(false);
});

pageRenderers.Incidents = function () {
  $('#content').innerHTML = '<div id="incidents-data">' + incMarkup() + '</div>';
  loadIncidents(true);
};
sourceLoaders['Incidents'] = () => loadIncidents(false);
