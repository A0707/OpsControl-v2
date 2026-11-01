// Page « Compléter l'inventaire » : propositions prouvées, validées par l'opérateur.
// Rien n'est appliqué sans un clic ; chaque proposition montre ses preuves.
subtitles['Compléter l’inventaire'] = 'Rôles, environnements et services critiques proposés à partir des preuves collectées.';

let invData = null, invChoix = new Set(), invFiltre = '';
const INV_CONFIANCE = { 'élevée': 'ok', moyenne: 'warning', conflit: 'critical' };

function invPreuves(p) {
  return ['role', 'environment', 'services'].flatMap(k => (p[k]?.evidence || []).map(e => '<li>' + esc(e) + '</li>')).join('');
}

// Par défaut, ne sont cochées que les lignes sans ambiguïté.
function invSure(p) {
  const r = p.role?.confidence;
  return r ? r === 'élevée' : Boolean(p.services || p.environment);
}

function invLigne(p) {
  const r = p.role;
  const role = r ? (r.value ? '<b>' + esc(r.value) + '</b>' : '<i>aucune proposition</i>') +
    ' <span class="badge ' + INV_CONFIANCE[r.confidence] + '">' + esc(r.confidence) + '</span>' : '<span class="note">' + esc(p.current.role) + '</span>';
  const env = p.environment ? '<b>' + esc(p.environment.value) + '</b>' : '<span class="note">' + esc(p.current.environment || '—') + '</span>';
  const services = p.services ? p.services.value.map(s => '<code>' + esc(s) + '</code>').join(' ') : '<span class="note">—</span>';
  const applicable = Boolean((r && r.value) || p.environment || p.services);
  return '<tr><td>' + (applicable ? '<input type="checkbox" data-inv-key="' + escAttr(p.key) + '"' + (invChoix.has(p.key) ? ' checked' : '') +
      ' aria-label="Sélectionner ' + esc(p.name) + '">' : '') + '</td>' +
    '<td><button class="link" data-host="' + escAttr(p.key) + '">' + esc(p.name) + '</button><small><span class="ip">' + esc(p.ip || '') + '</span>' +
      (p.audited ? '' : ' · jamais audité : nom seul') + '</small></td>' +
    '<td>' + role + '</td><td>' + env + '</td><td class="wrap">' + services + '</td>' +
    '<td class="wrap"><details><summary>Preuves</summary><ul class="inv-preuves">' + invPreuves(p) + '</ul></details></td></tr>';
}

function invMarkup() {
  if (!invData) return '<div class="panel">Analyse de l’inventaire…</div>';
  const n = invData.counts, q = invFiltre.trim().toLowerCase();
  const lignes = invData.suggestions.filter(p => !q || (p.name + ' ' + (p.role?.value || '') + ' ' + (p.services?.value || []).join(' ')).toLowerCase().includes(q));
  return '<div class="stats alert-stats">' +
    '<div class="card stat-card warning"><span class="stat-dot"></span>Rôles à renseigner<strong>' + n.role_missing + '</strong><small>sur ' + n.hosts + ' serveurs</small></div>' +
    '<div class="card stat-card"><span class="stat-dot"></span>Rôles proposés<strong>' + n.role_proposed + '</strong><small>avec preuves</small></div>' +
    '<div class="card stat-card warning"><span class="stat-dot"></span>Services critiques déclarés<strong>' + n.services_declared + '</strong><small>sur tout le parc</small></div>' +
    '<div class="card stat-card"><span class="stat-dot"></span>Services proposés<strong>' + n.services_proposed + '</strong><small>observés en fonctionnement</small></div></div>' +
    '<section class="panel"><div class="panel-head"><h2>Propositions <span class="state-count">' + lignes.length + '</span></h2>' +
    '<div><button data-inv-tout>Tout cocher</button> <button data-inv-rien>Tout décocher</button> ' +
    '<button class="primary" data-inv-appliquer' + (invChoix.size ? '' : ' disabled') + '>Appliquer la sélection (' + invChoix.size + ')</button></div></div>' +
    '<p class="note">Conventions apprises de votre inventaire : ' + esc(Object.entries(invData.conventions?.codes || {}).map(([c, r]) => c + ' → ' + r).join(' · ') || 'aucune') +
    '. Vérifiez chaque ligne : un service peut tourner sur un serveur dont ce n’est pas le rôle (ex. une base PostgreSQL sur un bastion).</p>' +
    '<div class="filters"><input id="inv-search" type="search" placeholder="Filtrer : serveur, rôle, service" value="' + escAttr(invFiltre) + '"></div>' +
    '<div class="table"><table><thead><tr><th></th><th>Serveur</th><th>Rôle proposé</th><th>Environnement</th><th>Services à déclarer critiques</th><th>Justification</th></tr></thead><tbody>' +
    lignes.map(invLigne).join('') + '</tbody></table></div>' +
    '<p class="note">' + esc(invData.scope) + '</p></section>';
}

async function invCharger() {
  try {
    invData = await api('/api/inventory/suggestions');
    if (!invChoix.size) invData.suggestions.filter(invSure).forEach(p => invChoix.add(p.key));
  } catch (e) { $('#error').textContent = e.message; }
  if (page === 'Compléter l’inventaire' && !selected) invDessiner();
}

function invDessiner() {
  const cible = $('#inv-data');
  if (!cible) return;
  const focus = document.activeElement?.id === 'inv-search';
  cible.innerHTML = invMarkup();
  if (focus) { const i = $('#inv-search'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }
}

pageRenderers['Compléter l’inventaire'] = function () {
  $('#content').innerHTML = '<div id="inv-data"></div>';
  invDessiner();
  invCharger();
};

$('#content').addEventListener('input', e => { if (e.target.id === 'inv-search') { invFiltre = e.target.value; invDessiner(); } });
$('#content').addEventListener('change', e => {
  const k = e.target.dataset?.invKey;
  if (!k) return;
  if (e.target.checked) invChoix.add(k); else invChoix.delete(k);
  const b = document.querySelector('[data-inv-appliquer]');
  if (b) { b.disabled = !invChoix.size; b.textContent = 'Appliquer la sélection (' + invChoix.size + ')'; }
});
$('#content').addEventListener('click', async e => {
  if (e.target.closest('[data-inv-tout]')) { invData.suggestions.forEach(p => invChoix.add(p.key)); invDessiner(); return; }
  if (e.target.closest('[data-inv-rien]')) { invChoix.clear(); invDessiner(); return; }
  const b = e.target.closest('[data-inv-appliquer]');
  if (!b || !invChoix.size) return;
  const changes = invData.suggestions.filter(p => invChoix.has(p.key)).map(p => ({
    key: p.key, role: p.role?.value || null, environment: p.environment?.value || null, services: p.services?.value || [],
  }));
  if (!confirm('Appliquer ' + changes.length + ' proposition(s) à l’inventaire ?\n\nLe dernier audit de ces serveurs sera marqué « configuration modifiée » jusqu’au prochain (≤ 10 min en rotation).')) return;
  b.disabled = true;
  try {
    const r = await post('/api/inventory/apply', { changes });
    toast(r.updated.length + ' serveur(s) mis à jour dans l’inventaire.');
    invChoix.clear();
    await load();
    invCharger();
  } catch (error) { $('#error').textContent = error.message; b.disabled = false; }
});
