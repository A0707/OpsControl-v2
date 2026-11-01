// La création GLPI reste une action humaine distincte des collectes et des alertes.
const itsmDialog = document.createElement('dialog');
itsmDialog.id = 'itsm-dialog';
itsmDialog.setAttribute('aria-label', 'Gestion ITSM / GLPI');
document.body.append(itsmDialog);
ROLE_CONTROLS.push(['admin', '[data-itsm-origin],[data-itsm-preview],[data-itsm-create],[data-itsm-reconcile]']);
const ITSM_STATES = {pending: 'En attente', creating: 'Création en cours', linked: 'Associé',
  failed: 'Échec sans création confirmée', uncertain: 'Résultat incertain — création bloquée', partial: 'Objet créé — association à vérifier'};
let itsmCurrent = null, itsmPreview = null, itsmBy = '', itsmOpenRequest = 0;

function itsmDeclaredName() {
  if (itsmBy) return itsmBy;
  // Dernier nom saisi sur ce navigateur, sinon nom par défaut du poste (INFRAOPS_LOCAL_OPERATOR).
  try { return (localStorage.getItem('infraops.operateur') || operatorIdentity?.default_name || '').trim().slice(0, 120); }
  catch { return operatorIdentity?.default_name || ''; }
}
function itsmRememberName(value) {
  itsmBy = (value || '').trim();
  if (itsmBy) {
    try { localStorage.setItem('infraops.operateur', itsmBy); } catch { /* Le champ reste utilisable sans stockage. */ }
  }
}

function itsmError(error) {
  return [404, 405].includes(error.status) ?
    'Le serveur OpsControl actif ne dispose pas des routes ITSM attendues. Redémarrez OpsControl pour charger le backend mis à jour, puis rechargez la page. Aucun dossier ni ticket GLPI n’a été créé par cette demande.' : error.message;
}

// Correspondance origine → dossier (GET /api/itsm/links, sans URL ni destination GLPI) :
// badge « GLPI #28 · Nouveau » lisible par tous les rôles. Relue au plus toutes les 60 s ;
// le statut GLPI est relu côté serveur par le fil de fond (15 min), qui résout aussi le ticket
// quand l'anomalie est résolue dans OpsControl (solution GLPI, après délai de confirmation).
let itsmLinks = {items: [], at: 0, loading: false, signature: ''};
function itsmLinksLoad(force = false) {
  if (itsmLinks.loading || (!force && Date.now() - itsmLinks.at < 60000)) return;
  itsmLinks.loading = true;
  api('/api/itsm/links').then(data => {
    const items = Array.isArray(data?.items) ? data.items : [], signature = JSON.stringify(items);
    const changed = signature !== itsmLinks.signature;
    itsmLinks = {items, at: Date.now(), loading: false, signature};
    if (changed) itsmRepaint();
  }).catch(() => { itsmLinks.loading = false; itsmLinks.at = Date.now(); });  // Sans liens : pas de badge, rien de bloquant.
}
// Seules les vues qui affichent un badge sont repeintes, et seulement si les liens ont changé.
function itsmRepaint() {
  if (document.getElementById('alert-data') && typeof alertPaint === 'function') alertPaint(false);
  const zbx = document.getElementById('zbx-data');
  if (zbx && typeof zabbixMarkup === 'function') zbx.innerHTML = zabbixMarkup();
  if (selected && detailTab === 'incidents' && document.querySelector('.host-incidents')) render();
  if (document.getElementById('security-data') && typeof secPaint === 'function') secPaint();
}
// Dossier le plus récent de l'élément : incident et vulnérabilité par identifiant exact ; alerte
// (« id|début ») et problème Zabbix (« connexion|trigger|début ») par préfixe.
function itsmLinkFor(origin, key) {
  itsmLinksLoad();
  return itsmLinks.items.find(c => c.origin === origin && (['incident', 'vulnerability'].includes(origin) ? c.origin_id === key : String(c.origin_id).startsWith(key + '|'))) || null;
}
// `active` : l'élément est affiché comme en cours sur la page (alerte, problème Zabbix) ;
// un ticket résolu ou clos est alors incohérent, même avant la prochaine relecture serveur.
function itsmBadge(origin, key, active = false) {
  const c = itsmLinkFor(origin, key);
  if (!c) return '';
  const done = ['5', '6'].includes(String(c.remote_status || ''));
  const warning = active ? (done ? 'Ticket GLPI ' + String(c.remote_status_label || '').toLowerCase() + ', anomalie toujours active' : '') : (c.mismatch || '');
  const label = c.remote_id ? 'GLPI #' + c.remote_id + ' · ' + (c.remote_status_label || 'statut non lu') : 'Dossier ' + c.reference + ' · ' + (ITSM_STATES[c.status] || c.status);
  const title = 'Dossier ITSM ' + c.reference + (c.remote_checked_at ? ' · statut GLPI relu le ' + stamp(c.remote_checked_at) : '');
  return '<button type="button" class="badge itsm-badge ' + (warning ? 'warning' : !c.remote_id ? '' : done ? 'ok' : 'observed') + '" data-itsm-open="' + escAttr(c.id) +
    '" title="' + escAttr(title) + '">' + esc(label) + '</button>' + (warning ? '<span class="badge warning itsm-mismatch">⚠ ' + esc(warning) + '</span>' : '');
}

function itsmEntry(origin, id, host = '') {
  return '<section class="panel"><h3>Gestion ITSM / GLPI</h3><p>Prise en charge et transmission volontaire avec prévisualisation.</p>' +
    (roleAllows('admin') ? '<button data-itsm-origin="' + escAttr(origin) + '" data-itsm-id="' + escAttr(id) +
      '" data-itsm-host="' + escAttr(host) + '">Consulter / prendre en charge</button>' : '<p>Actions réservées aux administrateurs.</p>') + '</section>';
}

const itsmIssue = issue;
issue = function(h, f) {
  return itsmIssue(h, f).replace('</article>', itsmEntry('finding', f.id || f.title, h.key) + '</article>');
};
hostSection('audit', 25, h => '<section class="panel"><h2>Gestion ITSM / GLPI</h2><p>Choisissez un constat pour qualifier un incident ou un problème structurel.</p>' +
  (h.findings || []).map(f => '<details><summary>' + esc(f.title) + '</summary>' + itsmEntry('finding', f.id || f.title, h.key) + '</details>').join('') + '</section>');

async function itsmStart(origin, id, host) {
  const request = ++itsmOpenRequest;
  itsmPreview = null;
  itsmDialog.innerHTML = '<form id="itsm-take"><div class="panel-head"><h2>Gestion ITSM / GLPI</h2><button type="button" data-itsm-close>Fermer</button></div>' +
    '<p class="itsm-reference">Référence source : ' + esc(id) + '</p>' + ({
      incident: '<p>S’il est encore ouvert, l’incident sera pris en charge à votre nom (24 h) en même temps que le dossier.</p>',
      alert: '<p>L’alerte est relue par le serveur au moment de la prise en charge. Une cause déjà transmise rouvre son dossier existant.</p>',
      zabbix: '<p>Le problème Zabbix est relu dans la dernière collecte. Un trigger déjà transmis rouvre son dossier existant.</p>',
      vulnerability: '<p>La vulnérabilité validée est relue par le serveur : serveur, CVE, paquet, versions, responsable et plan de correction sont joints au ticket. Le ticket est résolu quand une analyse constate la correction.</p>',
      security_alert: '<p>Ticket de vérification : ce signal ne confirme pas l’applicabilité de la CVE. Décrivez les vérifications attendues. Lire la notification ne clôture pas ce dossier ; sa clôture sera manuelle dans GLPI.</p>',
    }[origin] || '<p>Qualifiez le constat d’audit et enregistrez sa prise en charge avant toute transmission à GLPI.</p>') +
    '<label>Type<select name="kind"><option value="Ticket">Incident ponctuel</option><option value="Problem">Problème récurrent ou structurel (ITIL)</option></select></label>' +
    '<label>'+(origin==='security_alert'?'Vérifications attendues (10 caractères minimum)':'Qualification (obligatoire pour un problème)')+'<textarea name="qualification" maxlength="2000"></textarea></label>' +
    (!operatorIdentity?.authenticated ? '<label>Votre nom (déclaratif)<input name="by" maxlength="120" required value="' + escAttr(itsmDeclaredName()) + '"></label>' : '') +
    '<input type="hidden" name="origin" value="' + escAttr(origin) + '"><input type="hidden" name="origin_id" value="' + escAttr(id) +
    '"><input type="hidden" name="host_key" value="' + escAttr(host) + '">' +
    (origin === 'incident' ? '<input type="hidden" name="acknowledge" value="true">' : '') + '<p class="form-error" role="alert"></p>' +
    '<p class="mini" role="status" data-itsm-status>Vérification du backend ITSM…</p>' +
    '<button type="submit" disabled>Prendre en charge / consulter le dossier</button></form>';
  itsmDialog.showModal();
  const form = itsmDialog.querySelector('form');
  const kind = form.elements.kind, qualification = form.elements.qualification;
  const qualify = () => { qualification.required = kind.value === 'Problem'||origin==='security_alert'; qualification.minLength = qualification.required ? 10 : 0; };
  kind.addEventListener('change', qualify);
  qualify();
  try {
    const status = await api('/api/itsm/status');
    if (!status.available || status.protocol !== 1) throw new Error('Version du backend ITSM incompatible : mettre à jour puis redémarrer OpsControl.');
    if (request !== itsmOpenRequest || !form.isConnected) return;
    form.dataset.backendReady = '1';
    form.querySelector('[data-itsm-status]').textContent = 'Prise en charge locale uniquement ; la création GLPI demandera une prévisualisation et une confirmation.' +
      (status.configured === false ? ' GLPI non configuré sur le serveur : ' + (status.reason || '') + '.' : '') +
      (status.transport === 'http' ? ' Attention : liaison GLPI en HTTP non chiffré (dérogation configurée).' : '');
    form.querySelector('[type=submit]').disabled = !roleAllows('admin');
  } catch (error) {
    if (request === itsmOpenRequest && form.isConnected) {
      form.querySelector('[data-itsm-status]').textContent = 'Backend ITSM indisponible';
      form.querySelector('.form-error').textContent = itsmError(error);
    }
  }
}

async function itsmShow(id) {
  const data = await api('/api/itsm/detail?id=' + encodeURIComponent(id));
  itsmCurrent = data;
  const d = data.snapshot;
  itsmDialog.innerHTML = '<div class="panel-head"><h2>Gestion ITSM / GLPI — ' + esc(data.kind) + '</h2><button data-itsm-close>Fermer</button></div>' +
    '<h3>' + esc(d.title) + '</h3><dl>' + [['Référence', data.reference], ['Statut OpsControl à la prise en charge', d.state],
      ['Responsable', data.owner + (data.owner_auth === 'proxy' ? '' : ' (déclaratif)')], ['Détection / observation', d.opened_at || d.observed_at || 'Inconnue'],
      ['Prise en charge', stamp(data.taken_at)], ['Criticité', d.severity], ['Source', d.source], ['Synchronisation', ITSM_STATES[data.status] || data.status],
      ['Numéro GLPI', data.remote_id || 'Non associé'], ['Statut GLPI observé', (data.remote_status_label || data.remote_status || 'Non lu') + (data.remote_checked_at ? ' (relu le ' + stamp(data.remote_checked_at) + ')' : '')],
      ['Dernier résultat', data.last_error || (data.status === 'linked' ? 'Objet et groupe observateur vérifiés' : 'En attente')]]
      .map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('') + '</dl>' +
    (data.url ? '<p><a target="_blank" rel="noopener noreferrer" href="' + escAttr(data.url) + '">Ouvrir dans GLPI #' + esc(data.remote_id) + '</a></p>' : '') +
    (!operatorIdentity?.authenticated && roleAllows('admin') ? '<label>Votre nom pour cette opération (mode local : déclaratif)<input data-itsm-by name="by" maxlength="120" required value="' + escAttr(itsmDeclaredName()) + '"></label>' : '') +
    (roleAllows('admin') ? (['pending', 'failed'].includes(data.status) ? '<button data-itsm-preview>Prévisualiser ' + (data.status === 'failed' ? 'avant de réessayer' : 'le ticket') + '</button>' :
      '<button data-itsm-reconcile>' + (data.status === 'linked' ? 'Lire le statut GLPI' : 'Rapprocher / vérifier l’association') + '</button>') : '') +
    '<div id="itsm-preview"></div><p class="form-error" role="alert"></p><details><summary>Historique des opérations</summary><ol>' +
    data.events.map(e => '<li>' + esc(stamp(e.at)) + ' · ' + esc(e.actor) + ' · ' + esc(e.action) + ' : ' + esc(e.result) + '</li>').join('') + '</ol></details>';
}

document.addEventListener('click', e => {
  const b = e.target.closest('[data-itsm-origin]');
  if (b) itsmStart(b.dataset.itsmOrigin, b.dataset.itsmId, b.dataset.itsmHost || '');
});
itsmDialog.addEventListener('submit', async e => {
  e.preventDefault();
  if (e.target.dataset.backendReady !== '1') return;
  const values = Object.fromEntries(new FormData(e.target)), b = e.target.querySelector('[type=submit]');
  if (!operatorIdentity?.authenticated && !(values.by || '').trim()) {
    const input = e.target.elements.by;
    input.value = '';
    input.focus();
    input.reportValidity();
    return;
  }
  b.disabled = true;
  try {
    itsmRememberName(values.by);
    values.by = itsmBy;
    const data = await post('/api/itsm/take', values);
    await itsmShow(data.id);
  } catch (err) { itsmDialog.querySelector('.form-error').textContent = itsmError(err); }
  finally { b.disabled = false; }
});
itsmDialog.addEventListener('click', async e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-itsm-close')) { itsmDialog.close(); return; }
  if (!b.matches('[data-itsm-preview],[data-itsm-create],[data-itsm-reconcile]')) return;
  if (!operatorIdentity?.authenticated) {
    const input = itsmDialog.querySelector('[data-itsm-by]');
    const name = (input?.value || '').trim();
    if (!name) {
      itsmDialog.querySelector('.form-error').textContent = 'Saisissez votre nom pour effectuer cette opération en mode local.';
      if (input) { input.value = ''; input.focus(); input.reportValidity(); }
      return;
    }
    itsmRememberName(name);
  }
  itsmDialog.querySelector('.form-error').textContent = '';
  b.disabled = true;
  try {
    const body = {id: itsmCurrent.id, by: itsmBy};
    if (b.hasAttribute('data-itsm-preview')) {
      itsmPreview = await post('/api/itsm/preview', body);
      const target = itsmDialog.querySelector('#itsm-preview');
      // Seul le HTML généré et échappé côté serveur est rendu ; aucun HTML distant.
      target.innerHTML = '<h3>' + esc(itsmPreview.payload.name) + '</h3>' + itsmPreview.payload.content +
        '<p>Entité GLPI : ' + esc(itsmPreview.payload.entities_id) + ' · demandeur : ' + esc(itsmPreview.payload._users_id_requester) +
        ' · groupe observateur : ' + esc(itsmPreview.observer_id) +
        (itsmPreview.payload._groups_id_assign ? ' · statut à la création : En cours, assigné au groupe ' + esc(itsmPreview.payload._groups_id_assign) : '') +
        '</p><p class="note">'+(itsmCurrent.origin==='security_alert'?'Ticket de vérification : clôture manuelle dans GLPI, après contrôle des preuves.':'Résolution automatique : quand l’anomalie est résolue dans OpsControl, une solution est ajoutée au ticket et GLPI le passe à « Résolu ».')+'</p><button data-itsm-create>Confirmer et créer dans GLPI</button>';
    } else {
      const reconcile = b.hasAttribute('data-itsm-reconcile');
      b.textContent = 'Opération en cours…';
      await post(reconcile ? '/api/itsm/reconcile' : '/api/itsm/create', {...body, confirmed: true, preview_hash: itsmPreview?.preview_hash || ''});
      await itsmShow(body.id);
    }
  } catch (err) { itsmDialog.querySelector('.form-error').textContent = err.message; }
  finally { b.disabled = false; }
});

navGroups[0][1].push(['Dossiers ITSM', 'alert']);
subtitles['Dossiers ITSM'] = 'Historique des transmissions volontaires vers GLPI.';
pageRenderers['Dossiers ITSM'] = function() {
  const target = document.getElementById('content');
  target.innerHTML = '<section class="panel" id="itsm-list">Chargement…</section>';
  api('/api/itsm/cases').then(data => {
    const list = document.getElementById('itsm-list');
    if (!list) return;
    const odd = data.items.filter(c => c.mismatch).length;
    list.innerHTML = '<h2>Dossiers ITSM</h2>' + (odd ? '<p class="instruction" role="note">' + odd + ' incohérence(s) entre OpsControl et GLPI : à vérifier dans GLPI.</p>' : '') +
      data.items.map(c => '<p><button data-itsm-open="' + escAttr(c.id) + '">' +
      esc(c.snapshot.title) + '</button> · ' + esc(c.kind) + ' · ' + esc(ITSM_STATES[c.status]) +
      (c.remote_id ? ' · GLPI #' + esc(c.remote_id) + ' · ' + esc(c.remote_status_label || c.remote_status || 'statut non lu') : '') +
      (c.mismatch ? ' <span class="badge warning itsm-mismatch">⚠ ' + esc(c.mismatch) + '</span>' : '') + '</p>').join('');
  }).catch(err => { const list = document.getElementById('itsm-list'); if (list) list.textContent = err.message; });
};
document.addEventListener('click', async e => {
  const b = e.target.closest('[data-itsm-open]');
  if (!b) return;
  itsmPreview = null;
  try { await itsmShow(b.dataset.itsmOpen); itsmDialog.showModal(); }
  catch (err) { toast(err.message); }
});
// Après une création ou un rapprochement : badges relus aussitôt.
itsmDialog.addEventListener('close', () => itsmLinksLoad(true));
