// Enrichit la page Sauvegardes avec les jobs réellement collectés par l'API
// Baculum, au-dessus du tableau documentaire existant.
//
// Autonome comme wazuh.js et zabbix.js : son propre helper de tableau, aucune
// dépendance envers les autres vues additionnelles.
subtitles.Sauvegardes = 'Jobs Bacula collectés par API et chemins documentés de l’inventaire.';

let baculaSources = [];

const baculaClasses = { ok: 'ok', warning: 'warning', critical: 'critical', running: 'active', pending: 'unknown', unknown: 'unknown' };

function baculaBadge(job, stale) {
  return '<span class="badge ' + (stale ? 'unknown' : (baculaClasses[job.severity] || 'unknown')) + '">' +
    (stale ? 'Ancien · ' : '') + esc(job.status_label) + '</span>';
}

function baculaTable(headers, rows) {
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th>' + esc(h) + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + (c == null ? '—' : c) + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div>' + (rows.length ? '' : '<p class="note">Aucun job dans la collecte disponible.</p>');
}

// Audit UI du 31/10 (fiches 09.1 et 09.2) : sauvegardes, copies et restaurations sont
// distinguées ; une incrémentale vide réussie n'est ni un échec ni une preuve de couverture.
const BACULA_LEVELS = {F: 'Complète', I: 'Incrémentale', D: 'Différentielle', V: 'Vérification', B: 'Base'};
function baculaTypes(types) {
  const parts = Object.entries(types || {}).sort((a, b) => b[1] - a[1]).map(([label, n]) => n + ' ' + label.toLowerCase());
  return parts.length ? ' : ' + esc(parts.join(', ')) : '';
}
function baculaEmpty(j) {
  return j.bytes === 0 && j.severity === 'ok' && ['I', 'D'].includes(j.level)
    ? '<small>Aucune modification depuis la sauvegarde précédente</small>' : '';
}
function baculaSize(bytes) {
  if (bytes == null) return 'Non mesuré';
  const unites = ['o', 'Kio', 'Mio', 'Gio', 'Tio'];
  let v = Number(bytes), i = 0;
  while (v >= 1024 && i < unites.length - 1) { v /= 1024; i++; }
  return v.toLocaleString('fr-FR', { maximumFractionDigits: 1 }) + ' ' + unites[i];
}

function baculaMarkup() {
  return baculaSources.map(c => {
    const r = sourceResult(c), inv = r.inventory;
    // sourceFresh (source-ui.js) exige aussi que la collecte ait réussi : une
    // réponse en erreur horodatée à l'instant n'est pas une donnée fraîche.
    const stale = !sourceFresh(r);
    let html = '<section class="panel"><div class="panel-head"><div><h2>' + esc(c.name) + '</h2>' +
      '<p>Source : ' + esc(c.url) + '</p></div>' +
      '<button class="primary" data-bacula-collect="' + escAttr(c.key) + '">Collecter ce Director</button></div>' +
      '<p>Dernière collecte : ' + stamp(r.collected_at) + (stale ? ' · À actualiser' : '') + '</p>' +
      (r.inventory?.collection ? '<p class="note">Lecture ' + esc(r.inventory.collection) + (r.collection_note ? ' · ' + esc(r.collection_note) : '') + '</p>' : '');

    html += sourceStatus(c);
    if (r.error) html += '<p role="alert" class="instruction">' + esc(r.error) + '</p>';
    if (!inv) {
      return html + '<p>Aucun inventaire API disponible. Vérifier la connexion puis collecter /api/v2/jobs.</p>' +
        '<button data-go="Connexions API">Configurer la connexion</button></section>';
    }
    if (r.warning) html += '<p class="instruction">' + esc(r.warning) + '</p>';

    // État actuel = dernier passage de chaque job. Les compteurs historiques
    // restent visibles, mais nommés comme tels : ils couvrent des mois.
    const n = inv.counts || {}, cur = inv.latest_counts;
    html += cur
      ? '<div class="service-summary"><span>' + (inv.latest || []).length + ' job(s) distinct(s)' + baculaTypes(inv.latest_types) + '</span>' +
        '<span>' + (cur.critical || 0) + ' en échec au dernier passage</span>' +
        '<span>' + (cur.warning || 0) + ' avec avertissement</span>' +
        '<span>' + (cur.ok || 0) + ' terminé(s) sans erreur</span>' +
        '<span>' + (cur.running || 0) + ' en cours</span>' +
        ((cur.unknown || 0) ? '<span>' + cur.unknown + ' état non reconnu</span>' : '') + '</div>'
      : '<p class="instruction">Collecte antérieure au calcul de l’état par job : relancer la collecte.</p>';
    html += '<p>Dernier job terminé sans erreur : <b>' + esc(inv.last_success || 'aucun dans cette collecte') + '</b></p>' +
      '<p class="note">Historique complet' + (inv.history_since ? ' depuis ' + esc(inv.history_since) : '') + ' : ' +
      (inv.jobs_count || 0) + ' passage(s), dont ' + (n.critical || 0) + ' en erreur et ' + (n.warning || 0) +
      ' avec avertissement. Ces totaux décrivent le passé, pas l’état actuel.</p>' +
      '<p class="note">' + esc(inv.scope) + '</p></section>';

    const row = j => [baculaBadge(j, stale), esc(j.name), esc(j.type_label || '—'), esc(j.client || '—'), esc(BACULA_LEVELS[j.level] || j.level || '—'),
      esc(j.endtime || 'Non terminé'), esc(baculaSize(j.bytes)) + baculaEmpty(j), j.files == null ? 'Non mesuré' : esc(j.files)];
    const headers = ['État', 'Job', 'Type', 'Client', 'Niveau', 'Fin', 'Volume', 'Fichiers'];
    if (inv.latest) {
      html += '<section class="panel"><h2>État actuel — dernier passage de chaque job</h2>' +
        baculaTable(headers, inv.latest.map(row)) + '</section>';
    }
    html += '<details class="panel"><summary>Historique récent — ' + (inv.jobs || []).length + ' passage(s), anomalies en tête</summary>' +
      (inv.jobs_truncated ? '<p class="note">' + inv.jobs_truncated + ' passage(s) plus ancien(s) comptés mais non conservés.</p>' : '') +
      baculaTable(headers, (inv.jobs || []).slice(0, 500).map(row)) + '</details>';
    return html;
  }).join('');
}

async function loadBacula() {
  const target = $('#bacula-data');
  if (!target) return;
  try {
    const sources = await api(sourceUrl('Bacula'));
    if (!target.isConnected) return;
    baculaSources = sources.filter(c => c.provider === 'Bacula');
    target.innerHTML = baculaMarkup() || '<section class="panel"><h2>Aucune connexion Bacula configurée</h2>' +
      '<p>Ajouter une connexion HTTPS vers /api/v2/jobs de votre API Baculum, avec un compte de lecture.</p>' +
      '<button data-go="Connexions API">Ajouter une connexion API</button></section>';
  } catch (e) {
    if (target.isConnected) target.textContent = e.message;
  }
}

renderHooks.push(function () {
  if (page !== 'Sauvegardes' || selected) return;
  // Les jobs réellement collectés passent avant le tableau documentaire :
  // une preuve d'exécution vaut mieux qu'un chemin déclaré dans un classeur.
  $('#content').insertAdjacentHTML('afterbegin', '<div id="bacula-data">Chargement des jobs Bacula…</div>');
  loadBacula();
});

$('#content').addEventListener('click', async e => {
  const b = e.target.closest('[data-bacula-collect]');
  if (!b) return;
  b.disabled = true;
  b.textContent = 'Collecte…';
  try {
    await post('/api/connections/' + encodeURIComponent(b.dataset.baculaCollect) + '/collect');
    await loadBacula();
  } catch (error) {
    $('#error').textContent = error.message;
  } finally {
    b.disabled = false;
    b.textContent = 'Collecter ce Director';
  }
});

// Enregistrement aupres du socle : app.js n'a pas a connaitre ce module.
sourceLoaders['Sauvegardes']=loadBacula;
