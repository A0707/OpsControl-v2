// Accès SSH depuis l'interface (host_access.py) :
// - « Empreintes SSH à confirmer » (page Serveurs) : lecture regroupée des empreintes des serveurs
//   en « clé absente / différente », comparaison, confirmation tapée « OUI », enregistrement ;
// - « Tester la connexion » (fiche serveur) : diagnostic par étape et par compte/port ;
// - « Modifier plusieurs serveurs » (page Serveurs) : rôle, environnement, criticité, compte, port.
// Rien n'est exécuté sur les serveurs en dehors de lectures SSH, comme la collecte.
const hostAccessDialog = document.createElement('dialog');
hostAccessDialog.id = 'host-access-dialog';
document.body.append(hostAccessDialog);
let hostKeyPending = null, hostKeyPendingAt = 0, hostKeyScan = null;

async function hostKeyRefreshPending(force) {
  if (!force && hostKeyPending && Date.now() - hostKeyPendingAt < 60000) return hostKeyPending;
  try { hostKeyPending = (await api('/api/ssh/host-keys')).hosts; hostKeyPendingAt = Date.now(); } catch { hostKeyPending = hostKeyPending || []; }
  return hostKeyPending;
}

function hostAccessOpen(html) {
  hostAccessDialog.innerHTML = '<div class="panel-head"><h2>' + html.title + '</h2><button type="button" data-ha-close>Fermer</button></div>' + html.body;
  if (!hostAccessDialog.open) hostAccessDialog.showModal();
}

// ------------------------------------------------------------------ empreintes
async function hostKeysOpen(preselect) {
  const pending = await hostKeyRefreshPending(true);
  const list = preselect && !pending.some(p => p.key === preselect)
    ? [{key: preselect, name: state?.hosts.find(h => h.key === preselect)?.name || preselect, ip: state?.hosts.find(h => h.key === preselect)?.ip, state: 'à lire'}].concat(pending)
    : pending;
  hostKeyScan = null;
  hostAccessOpen({title: 'Empreintes SSH à confirmer', body: list.length
    ? '<p>OpsControl refuse tout serveur dont l’empreinte SSH est inconnue ou a changé : c’est ce qui empêche une usurpation. ' +
      'Lire les empreintes, les <b>comparer à la console du serveur</b>, puis confirmer.</p>' +
      '<div class="table"><table><thead><tr><th></th><th>Serveur</th><th>IP</th><th>État</th></tr></thead><tbody>' +
      list.map(p => '<tr><td><input type="checkbox" data-hk-pick value="' + escAttr(p.key) + '" ' + (!preselect || p.key === preselect ? 'checked' : '') +
        ' aria-label="Sélectionner ' + escAttr(p.name) + '"></td><td>' + esc(p.name) + '</td><td class="ip">' + esc(p.ip) + '</td><td>' +
        (p.state === 'changed' ? '<span class="badge critical">● Clé différente</span>' : p.state === 'absent' ? '<span class="badge warning">● Clé absente</span>' :
          p.state === 'never' ? '<span class="badge unknown">● Jamais connecté</span>' : esc(p.state)) +
        '</td></tr>').join('') + '</tbody></table></div>' +
      '<p class="form-error" role="alert"></p><button class="primary" type="button" data-hostkeys-scan>Lire les empreintes des serveurs cochés</button><section id="hk-result"></section>'
    : '<p>Aucun serveur en échec d’empreinte dans les dernières collectes.</p>'});
}

async function hostKeysScan() {
  const keys = [...hostAccessDialog.querySelectorAll('[data-hk-pick]:checked')].map(i => i.value);
  const error = hostAccessDialog.querySelector('.form-error'), out = $('#hk-result'), button = hostAccessDialog.querySelector('[data-hostkeys-scan]');
  if (!keys.length) { error.textContent = 'Cocher au moins un serveur.'; return; }
  error.textContent = ''; button.disabled = true; out.innerHTML = '<p class="note">Lecture des empreintes par le même chemin SSH que la plateforme (bastion compris)…</p>';
  try {
    hostKeyScan = await post('/api/ssh/host-keys/scan', {keys});
    const rows = hostKeyScan.hosts;
    out.innerHTML = '<p class="instruction">' + esc(hostKeyScan.warning) + '</p>' +
      command('Sur chaque serveur (console ou accès de confiance)', 'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done') +
      '<div class="table"><table><thead><tr><th></th><th>Serveur</th><th>Empreintes présentées</th><th>Résultat</th></tr></thead><tbody>' +
      rows.map(r => '<tr><td>' + (r.status === 'captured' && !r.already_known ? '<input type="checkbox" data-hk-accept value="' + escAttr(r.key) +
          '" aria-label="Enregistrer ' + escAttr(r.name) + '">' : '') + '</td><td>' + esc(r.name) + '<small class="ip">' + esc(r.ip) + '</small></td><td>' +
        (r.fingerprints.map(f => '<code>' + esc(f.type) + ' ' + esc(f.sha256) + '</code>').join('<br>') || '—') + '</td><td>' +
        (r.status !== 'captured' ? '<span class="badge unknown">● Injoignable</span><small>Aucune empreinte : tester la connexion (réseau, port).</small>'
          : r.already_known ? '<span class="badge ok">● Déjà connue</span>'
          : r.replaces_existing ? '<span class="badge critical">● Remplacera l’ancienne clé</span><small>Changement d’empreinte : réinstallation du serveur, ou interception. Vérifier avant tout.</small>'
          : '<span class="badge warning">● Nouvelle</span>') + '</td></tr>').join('') + '</tbody></table></div>' +
      (rows.some(r => r.status === 'captured' && !r.already_known)
        ? '<label>J’ai comparé les empreintes cochées à une source de confiance. Taper <b>OUI</b> pour confirmer' +
          (rows.some(r => r.status === 'captured' && r.replaces_existing)
            ? ' — ou <b>REMPLACER</b> si une clé déjà enregistrée change (réinstallation confirmée à la console)' : '') +
          '<input id="hk-confirm" autocomplete="off" maxlength="10" placeholder="OUI"></label>' +
          '<button class="primary" type="button" data-hostkeys-accept>Enregistrer les empreintes cochées</button><p class="note">Lecture valable 15 minutes.</p>'
        : '<p class="note">Rien à enregistrer.</p>');
  } catch (e) { out.innerHTML = ''; error.textContent = e.message; }
  finally { button.disabled = false; }
}

async function hostKeysAccept() {
  const keys = [...hostAccessDialog.querySelectorAll('[data-hk-accept]:checked')].map(i => i.value);
  const error = hostAccessDialog.querySelector('.form-error');
  if (!keys.length) { error.textContent = 'Cocher les empreintes vérifiées à enregistrer.'; return; }
  try {
    const r = await post('/api/ssh/host-keys/accept', {scan_id: hostKeyScan.scan_id, keys, confirm: $('#hk-confirm').value});
    hostKeyPending = null;
    $('#hk-result').innerHTML = '<p class="instruction">' + r.written.length + ' empreinte(s) enregistrée(s)' +
      (r.written.some(w => w.replaced) ? ', dont ' + r.written.filter(w => w.replaced).length + ' remplacée(s)' : '') + '. ' + esc(r.note) + '</p>' +
      r.written.map(w => '<button type="button" data-test-connection="' + escAttr(w.key) + '">Tester ' + esc(state?.hosts.find(h => h.key === w.key)?.name || w.key) + '</button>').join(' ');
  } catch (e) { error.textContent = e.message; }
}

// ------------------------------------------------------------------ test de connexion
function hostTestMarkup(r) {
  const mark = ok => ok === true ? '<span class="badge ok">● OK</span>' : ok === false ? '<span class="badge critical">● Échec</span>' : '<span class="badge unknown">● Inconnu</span>';
  return '<p class="instruction"><b>' + (r.ok ? 'Connexion réussie' : 'Connexion impossible') + '</b> — ' + esc(r.summary) + '</p>' +
      '<div class="table"><table><thead><tr><th>Étape</th><th>Résultat</th><th>Détail</th></tr></thead><tbody>' +
      r.steps.map(s => '<tr><td>' + esc(s.step) + '</td><td>' + mark(s.ok) + '</td><td>' + esc(s.detail) + '</td></tr>').join('') +
      r.attempts.map(a => '<tr><td>SSH ' + esc(a.user) + '@' + esc(r.ip) + ':' + esc(a.port) + '</td><td>' + mark(a.ok) + '<small>' + esc(a.duration_ms) + ' ms</small></td><td>' +
        esc(a.detail) + '</td></tr>').join('') + '</tbody></table></div>';
}

async function hostTestOpen(key) {
  const h = state?.hosts.find(x => x.key === key);
  hostAccessOpen({title: 'Tester la connexion · ' + esc(h?.name || key), body: '<p class="note">Sonde réseau, empreinte, puis essai SSH en lecture (« uptime ») par compte et port…</p>'});
  try {
    const r = await post('/api/hosts/' + encodeURIComponent(key) + '/test', {});
    hostAccessOpen({title: 'Tester la connexion · ' + esc(r.name), body: hostTestMarkup(r) +
      (!r.ok && r.cause === 'host_key' ? '<button class="primary" type="button" data-hostkeys-open="' + escAttr(key) + '">Vérifier et enregistrer l’empreinte</button>' : '') +
      (r.ok ? '<button type="button" data-audit-host="' + escAttr(key) + '">↻ Auditer ce serveur</button>' : '') +
      '<p class="note">Comptes et ports essayés dans l’ordre de l’inventaire (serveur, sinon réglage SSH global).</p>'});
  } catch (e) {
    hostAccessOpen({title: 'Tester la connexion', body: '<p role="alert">' + esc(e.message) + '</p>'});
  }
}

// ------------------------------------------------------------------ modification groupée
let bulkQuery = '';
function bulkRows() {
  const q = bulkQuery.toLowerCase();
  return (state?.hosts || []).filter(h => !q || [h.name, h.ip, h.role, h.environment].join(' ').toLowerCase().includes(q));
}
function bulkOpen() {
  const roles = [...new Set((state?.hosts || []).map(h => h.role).filter(Boolean))].sort();
  const envs = [...new Set((state?.hosts || []).map(h => h.environment).filter(Boolean))].sort();
  hostAccessOpen({title: 'Modifier plusieurs serveurs', body:
    '<form id="bulk-form"><label>Filtrer <input id="bulk-q" type="search" value="' + escAttr(bulkQuery) + '" placeholder="Nom, IP, rôle, environnement…"></label>' +
    '<div class="filters"><button type="button" data-bulk-all="1">Cocher les serveurs affichés</button><button type="button" data-bulk-all="0">Tout décocher</button><span class="mini" id="bulk-count"></span></div>' +
    '<div class="table bulk-list" id="bulk-list"></div><button type="button" data-bulk-test>Tester la connexion des serveurs cochés</button><p class="note">Paramètres enregistrés de chaque serveur · 10 serveurs maximum.</p><div id="bulk-test-results" aria-live="polite"></div>' +
    '<h3>Modifications (champ vide ou « inchangé » : non modifié)</h3><div class="edit-grid">' +
    '<label>Rôle<input name="role" list="bulk-roles" maxlength="80" placeholder="inchangé"></label><datalist id="bulk-roles">' + roles.map(r => '<option value="' + escAttr(r) + '">').join('') + '</datalist>' +
    '<label>Environnement<input name="environment" list="bulk-envs" maxlength="80" placeholder="inchangé"></label><datalist id="bulk-envs">' + envs.map(r => '<option value="' + escAttr(r) + '">').join('') + '</datalist>' +
    '<label>Criticité<select name="criticality"><option value="">inchangée</option><option value="standard">standard</option><option value="critical">critique</option></select></label>' +
    '<label>Compte SSH<input name="user" maxlength="64" placeholder="inchangé" pattern="[A-Za-z_][A-Za-z0-9_.-]{0,63}"></label>' +
    '<label>Port SSH<input name="port" type="number" min="1" max="65535" placeholder="inchangé"></label>' +
    '<label>Collecte<select name="collect_enabled"><option value="">inchangée</option><option value="true">activée</option><option value="false">désactivée</option></select></label></div>' +
    '<p class="note">Compte, port et collecte changent la façon de joindre les serveurs : refusés pendant une collecte. Rôle « WAF ModSecurity » exact pour activer la sonde WAF.</p>' +
    '<p class="form-error" role="alert"></p><button class="primary" type="submit">Appliquer aux serveurs cochés</button></form>'});
  bulkPaint();
}
const bulkPicked = new Set();
function bulkPaint() {
  const list = $('#bulk-list');
  if (!list) return;
  list.innerHTML = '<table><thead><tr><th></th><th>Serveur</th><th>IP</th><th>Rôle</th><th>Environnement</th></tr></thead><tbody>' +
    bulkRows().map(h => '<tr><td><input type="checkbox" data-bulk-pick value="' + escAttr(h.key) + '"' + (bulkPicked.has(h.key) ? ' checked' : '') +
      ' aria-label="Sélectionner ' + escAttr(h.name) + '"></td><td>' + esc(h.name) + '</td><td class="ip">' + esc(h.ip) + '</td><td>' + esc(h.role) +
      '</td><td>' + esc(h.environment) + '</td></tr>').join('') + '</tbody></table>';
  $('#bulk-count').textContent = bulkPicked.size + ' serveur(s) coché(s)';
}
async function bulkTestConnections(button) {
  const keys = [...bulkPicked], target = $('#bulk-test-results');
  if (!keys.length || keys.length > 10) { target.textContent = 'Cocher de 1 à 10 serveurs pour ce test.'; return; }
  target.innerHTML = '<p>Tests de connexion en cours…</p>'; button.disabled = true;
  try {
    for (const key of keys) {
      if (!target.isConnected || !hostAccessDialog.open) break;
      const host = state?.hosts.find(h => h.key === key);
      try {
        const result = await post('/api/hosts/' + encodeURIComponent(key) + '/test', {});
        if (target.isConnected) target.insertAdjacentHTML('beforeend', '<details><summary>' + esc(host?.name || key) + ' · ' + (result.ok ? 'Réussite' : 'Échec') + '</summary>' + hostTestMarkup(result) + '</details>');
      } catch (error) {
        if (target.isConnected) target.insertAdjacentHTML('beforeend', '<p>' + esc(host?.name || key) + ' · ' + esc(error.message) + '</p>');
      }
    }
    if (target.isConnected) target.querySelector('p').textContent = 'Tests terminés · aucun paramètre enregistré.';
  } finally { if (button.isConnected) button.disabled = false; }
}

async function bulkSubmit(form) {
  const v = Object.fromEntries(new FormData(form));
  const body = {keys: [...bulkPicked]};
  for (const f of ['role', 'environment', 'criticality', 'user']) if (v[f]?.trim()) body[f] = v[f].trim();
  if (v.port) body.port = Number(v.port);
  if (v.collect_enabled) body.collect_enabled = v.collect_enabled === 'true';
  const error = form.querySelector('.form-error');
  if (!body.keys.length) { error.textContent = 'Cocher au moins un serveur.'; return; }
  if (Object.keys(body).length === 1) { error.textContent = 'Indiquer au moins une modification.'; return; }
  // Modification de N serveurs d'un coup, désactivation de collecte comprise : confirmation (audit FE-08).
  const what = Object.keys(body).filter(k => k !== 'keys').join(', ');
  if (!confirm('Modifier ' + body.keys.length + ' serveur(s) (' + what + ')' +
    (body.collect_enabled === false ? ' et DÉSACTIVER leur collecte' : '') + ' ?')) return;
  try {
    const r = await post('/api/manage/hosts/bulk', body);
    hostAccessDialog.close(); bulkPicked.clear();
    toast(r.updated.length + ' serveur(s) modifié(s).');
    await load();
  } catch (e) { error.textContent = e.message; }
}

// ------------------------------------------------------------------ branchements
renderHooks.push(async function () {
  if (!state) return;
  if (selected && hostDetail) {
    $('.detail-banner')?.insertAdjacentHTML('beforeend', '<button data-test-connection="' + escAttr(selected) + '">Tester la connexion</button>');
  } else if (page === 'Serveurs') {
    const bar = document.createElement('div');
    bar.className = 'filters host-access-bar';
    bar.innerHTML = '<button type="button" data-bulk-open>Modifier plusieurs serveurs</button>';
    $('#content').prepend(bar);
    const pending = await hostKeyRefreshPending(false);
    if (pending.length && bar.isConnected) {
      bar.insertAdjacentHTML('afterbegin', '<button type="button" class="primary" data-hostkeys-open>Empreintes SSH à confirmer (' + pending.length + ')</button>');
    }
  }
});
document.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-ha-close')) { hostAccessDialog.close(); return; }
  if (b.hasAttribute('data-hostkeys-open')) { hostKeysOpen(b.dataset.hostkeysOpen || null); return; }
  if (b.hasAttribute('data-hostkeys-scan')) { hostKeysScan(); return; }
  if (b.hasAttribute('data-hostkeys-accept')) { hostKeysAccept(); return; }
  if (b.dataset.testConnection) { hostTestOpen(b.dataset.testConnection); return; }
  if (b.hasAttribute('data-bulk-open')) { bulkOpen(); return; }
  if (b.hasAttribute('data-bulk-test')) { bulkTestConnections(b); return; }
  if (b.dataset.bulkAll) {
    bulkRows().forEach(h => b.dataset.bulkAll === '1' ? bulkPicked.add(h.key) : bulkPicked.delete(h.key));
    bulkPaint();
  }
});
// Le dialogue est hors de #content : copie et audit y sont gérés ici (même comportement).
hostAccessDialog.addEventListener('click', async e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-copy')) {
    try { await navigator.clipboard.writeText(b.dataset.copy); toast('Commande copiée · aucune exécution'); }
    catch { toast('Copie indisponible : sélectionner le texte de la commande.'); }
  } else if (b.dataset.auditHost) {
    b.disabled = true;
    try { await post('/api/hosts/' + encodeURIComponent(b.dataset.auditHost) + '/refresh'); toast('Audit lancé.'); hostAccessDialog.close(); await load(); }
    catch (err) { toast(err.message); b.disabled = false; }
  }
});
hostAccessDialog.addEventListener('change', e => {
  if (e.target.matches('[data-bulk-pick]')) { e.target.checked ? bulkPicked.add(e.target.value) : bulkPicked.delete(e.target.value); $('#bulk-count').textContent = bulkPicked.size + ' serveur(s) coché(s)'; }
});
hostAccessDialog.addEventListener('input', e => { if (e.target.id === 'bulk-q') { bulkQuery = e.target.value; bulkPaint(); } });
hostAccessDialog.addEventListener('submit', e => { if (e.target.id === 'bulk-form') { e.preventDefault(); bulkSubmit(e.target); } });
