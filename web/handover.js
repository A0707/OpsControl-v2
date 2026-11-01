// Passation (/api/handover) : ce qui a CHANGÉ sur une période et qui fait quoi.
// À distinguer du « Bilan à l'ouverture » (briefing.js), qui montre l'état courant.
// Lecture seule : la page lit le journal d'incidents et les dossiers ITSM, sans aucune
// action ni collecte. Le texte à copier est construit par le serveur (identique au CSV).
{
  const list = navGroups[0][1];
  const at = list.findIndex(([p]) => p === 'Incidents');
  list.splice(at < 0 ? list.length : at + 1, 0, ['Passation', 'audit']);
}
subtitles.Passation = 'Fin de journée ou début de shift : ce qui a changé sur la période et qui fait quoi. L’état courant est dans le Bilan à l’ouverture.';

const HO_PERIODS = [[8, '8 h'], [12, '12 h'], [24, '24 h'], [48, '48 h'], [72, '3 jours'], [168, '7 jours']];
const HO_SEVERITY = {critical: ['Critique', 'critical'], warning: ['Majeur', 'warning'], preventive: ['Préventif', 'info'], info: ['Information', 'unknown']};
const HO_STATE = {open: 'Ouvert', reopened: 'Réapparu', acknowledged: 'Pris en charge', investigating: 'En investigation',
  suppressed: 'Masqué', resolved: 'Résolu'};
const HO_TAKE = {ack: 'Prise en charge', investigation_started: 'Investigation', suppress: 'Suppression temporaire'};
const HO_DURATION = {'24h': '24 h', '7d': '7 jours', permanent: 'sans échéance'};
const HO_ITSM = {pending: 'En attente', creating: 'Création en cours', linked: 'Associé', failed: 'Échec sans création confirmée',
  uncertain: 'Résultat incertain', partial: 'Objet créé — association à vérifier'};
let hoHours = 24, hoData = null, hoError = '', hoRequest = 0;

function hoUrl(format) {
  return '/api/handover?hours=' + hoHours + (format ? '&format=' + format : '');
}
function hoWhen(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? esc(value) : '<span title="' + escAttr(stamp(value)) + '">' +
    d.toLocaleString('fr-FR', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'}) + '</span>';
}
function hoAge(seconds) {
  const h = Math.floor((seconds || 0) / 3600);
  return h >= 24 ? Math.floor(h / 24) + ' j ' + h % 24 + ' h' : h + ' h';
}
function hoWho(name, authenticated) {
  return '<b>' + esc(name || 'inconnu') + '</b>' + (authenticated ? '' : ' <small title="Nom saisi en mode local">(déclaratif)</small>');
}
function hoWhat(i) {
  const [label, tone] = HO_SEVERITY[i.severity] || ['Non classée', 'unknown'];
  const target = i.target && i.target !== 'global' ? (i.host_key ? '<button class="link" data-host="' + escAttr(i.host_key) + '">' + esc(i.target) + '</button>' : esc(i.target)) : '';
  return ui.pill(label, tone) + ' <b>' + esc(i.title || 'Incident') + '</b><small>' + [esc(i.source || ''), target].filter(Boolean).join(' · ') + '</small>';
}
function hoTable(key, title, items, total, headers, row, emptyText) {
  const more = total > items.length ? '<p class="note">… et ' + (total - items.length) + ' autre(s) : voir le journal d’incidents.</p>' : '';
  return '<section class="panel ho-section" data-ho-section="' + escAttr(key) + '"><h3>' + esc(title) + ' <span class="state-count">' + total + '</span></h3>' +
    (items.length ? '<div class="table ho-table"><table><thead><tr>' + headers.map(h => '<th scope="col">' + h + '</th>').join('') +
      '</tr></thead><tbody>' + items.map(i => '<tr>' + row(i).map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') + '</tbody></table></div>' + more
      : '<p class="mini">' + esc(emptyText) + '</p>') + '</section>';
}

function hoMarkup() {
  const periods = '<label class="ho-period">Période <select id="ho-hours" aria-label="Période de la passation">' +
    HO_PERIODS.map(([h, l]) => '<option value="' + h + '"' + (h === hoHours ? ' selected' : '') + '>' + l + '</option>').join('') + '</select></label>';
  const actions = periods + '<button data-ho-copy' + (hoData ? '' : ' disabled') + '>Copier le texte</button>' +
    '<button data-ho-csv>Exporter CSV</button>' +
    '<button data-briefing-open title="État courant du parc">Bilan à l’ouverture</button>';
  if (!hoData) return '<section class="panel">' + ui.head('Passation', '', actions, 'LECTURE SEULE') +
    (hoError ? '<p class="form-error">' + esc(hoError) + '</p>' : '<p>Chargement de la passation…</p>') + '</section>';
  const d = hoData, c = d.counts || {}, t = d.thresholds || {}, sync = d.sync || {};
  const meta = '<span class="mini">Du ' + hoWhen(d.period.start) + ' au ' + hoWhen(d.period.end) + '</span>' +
    (sync.error ? '<span class="form-error">Dernier rapprochement en échec : chiffres du précédent</span>'
      : sync.at ? ui.fresh(sync.at, 'Journal rapproché', 120) : '');
  const kpis = '<div class="v2-kpis ho-kpis">' +
    ui.kpi('Sans responsable', c.unowned || 0, 'Ouverts depuis plus de ' + t.unowned_hours + ' h', c.unowned ? 'critical' : '') +
    ui.kpi('Échéances proches', c.expiring || 0, 'Prises en charge expirant dans les ' + t.expiring_hours + ' h', c.expiring ? 'warning' : '') +
    ui.kpi('Nouveaux', c.new || 0, 'Ouverts ou réapparus sur la période') +
    ui.kpi('Résolus', c.resolved || 0, 'Absents d’une collecte complète') +
    ui.kpi('Prises en charge', c.taken || 0, Object.entries(d.by_actor || {}).map(([a, n]) => a + ' ' + n).join(' · ') || 'Personne sur la période') +
    ui.kpi('Tickets GLPI', c.tickets || 0, c.tickets_pending ? c.tickets_pending + ' dossier(s) sans numéro confirmé' : 'Créés sur la période', c.tickets_pending ? 'warning' : '') + '</div>';
  const todo = hoTable('unowned', 'Sans responsable depuis plus de ' + t.unowned_hours + ' h', d.unowned, c.unowned,
    ['Incident', 'Sans responsable depuis', 'État'],
    i => [hoWhat(i), '<b>' + esc(hoAge(i.age_seconds)) + '</b><small>' + hoWhen(i.since) + '</small>',
      esc(HO_STATE[i.state] || i.state) + (i.expired_owner ? '<small>prise en charge de ' + esc(i.expired_owner) + ' expirée</small>' : '')],
    'Aucun incident ancien sans responsable.') +
    (d.chronic_unowned ? '<p class="note">' + d.chronic_unowned + ' anomalie(s) chronique(s) (plus de 30 jours) sans responsable, non listée(s).</p>' : '') +
    hoTable('expiring', 'Prises en charge qui expirent dans les ' + t.expiring_hours + ' h', d.expiring, c.expiring,
      ['Incident', 'Responsable', 'Expire'],
      i => [hoWhat(i), hoWho(i.owner, i.owner_authenticated) + (i.note ? '<small>« ' + esc(i.note) + ' »</small>' : ''), hoWhen(i.until)],
      'Aucune prise en charge n’expire dans ce délai.') +
    (c.tickets_pending ? hoTable('tickets_pending', 'Dossiers ITSM sans ticket GLPI confirmé', d.tickets_pending, c.tickets_pending,
      ['Référence', 'Incident', 'Statut', 'Demandé par'],
      i => ['<b>' + esc(i.reference) + '</b>', hoWhat(i), esc(HO_ITSM[i.status] || i.status), hoWho(i.owner, i.owner_authenticated) + '<small>' + hoWhen(i.taken_at) + '</small>'], '') : '');
  const changed = hoTable('new', 'Nouveaux incidents', d.new, c.new, ['Date', 'Incident', 'État actuel'],
    i => [hoWhen(i.at), hoWhat(i), esc(HO_STATE[i.state] || i.state) + (i.reopened ? '<small>réapparition</small>' : '')],
    'Aucun nouvel incident sur la période.') +
    hoTable('resolved', 'Incidents résolus', d.resolved, c.resolved, ['Date', 'Incident', 'Depuis'],
      i => [hoWhen(i.at), hoWhat(i), i.reappeared ? '<b>Réapparu</b><small>' + esc(HO_STATE[i.state] || i.state) + '</small>' : 'Toujours résolu'],
      'Aucune résolution sur la période.') +
    hoTable('taken', 'Prises en charge', d.taken, c.taken, ['Date', 'Qui', 'Action', 'Incident'],
      i => [hoWhen(i.at), hoWho(i.actor, i.actor_authenticated),
        esc(HO_TAKE[i.action] || i.action) + (HO_DURATION[i.duration] ? '<small>' + esc(HO_DURATION[i.duration]) + '</small>' : '') +
        (i.note ? '<small>« ' + esc(i.note) + ' »</small>' : ''), hoWhat(i)],
      'Aucune prise en charge sur la période.') +
    hoTable('tickets', 'Tickets GLPI créés', d.tickets, c.tickets, ['Référence', 'GLPI', 'Incident', 'Par'],
      i => ['<b>' + esc(i.reference) + '</b>', (i.kind === 'Ticket' ? 'Ticket' : 'Problème') + ' n° <b>' + esc(i.glpi_id) + '</b>' +
        (i.glpi_status ? '<small>statut GLPI : ' + esc(i.glpi_status) + '</small>' : ''), hoWhat(i),
        hoWho(i.owner, i.owner_authenticated) + '<small>' + hoWhen(i.created_at) + '</small>'],
      'Aucun ticket GLPI créé sur la période.');
  return '<section class="panel">' + ui.head('Passation', meta, actions, 'LECTURE SEULE') + kpis +
    (hoError ? '<p class="form-error">' + esc(hoError) + '</p>' : '') + '</section>' +
    '<h2 class="ho-group">À traiter</h2>' + todo + '<h2 class="ho-group">Ce qui a changé</h2>' + changed +
    '<details class="panel ho-text"><summary>Aperçu du texte à copier (Teams, mail)</summary><pre id="ho-text">' + esc(d.text || '') + '</pre></details>' +
    '<p class="v2-formula">' + esc(d.scope || '') + '</p>';
}

function hoPaint(background = false) {
  const target = document.getElementById('handover-data');
  if (!target) return;
  // Rafraîchissement de fond (30 s) : ne pas refermer la liste de période en cours de choix.
  if (background && target.contains(document.activeElement) && document.activeElement.id === 'ho-hours') return;
  const open = target.querySelector('.ho-text')?.open;
  target.innerHTML = hoMarkup();
  if (open) target.querySelector('.ho-text').open = true;
}
async function loadHandover(background = false) {
  if (!document.getElementById('handover-data')) return;
  const id = ++hoRequest;
  try {
    const data = await api(hoUrl());
    if (id !== hoRequest) return;  // réponse tardive d'une période précédente : ignorée
    // Réponse incomplète (ancien serveur) : pas de rapport plutôt qu'une passation vide trompeuse.
    if (!data || !data.counts || !data.period) throw new Error('Réponse de passation inattendue : redémarrer OpsControl.');
    hoData = data; hoError = '';
  } catch (error) {
    if (id !== hoRequest) return;
    hoError = error.status === 404 ? 'Le serveur OpsControl actif ne connaît pas la passation : redémarrez-le pour charger le backend mis à jour.' : error.message;
  }
  hoPaint(background);
}

async function hoCsv(b) {
  // CSV construit par le serveur (mêmes données que la page) ; BOM et « ; » pour Excel en français.
  b.disabled = true;
  try {
    const r = await fetch(hoUrl('csv'), {credentials: 'same-origin'});
    if (!r.ok) throw new Error('Export CSV impossible (erreur ' + r.status + ').');
    const name = (r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'passation.csv';
    const url = URL.createObjectURL(await r.blob());
    const link = document.createElement('a');
    link.href = url; link.download = name; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { toast(error.message); }
  finally { if (b.isConnected) b.disabled = false; }
}

$('#content').addEventListener('click', async e => {
  if (page !== 'Passation' || selected) return;
  const csvButton = e.target.closest('button[data-ho-csv]');
  if (csvButton) { hoCsv(csvButton); return; }
  const b = e.target.closest('button[data-ho-copy]');
  if (!b || !hoData) return;
  try { await navigator.clipboard.writeText(hoData.text); toast('Texte de passation copié.'); }
  catch {
    // Presse-papiers refusé (contexte non sécurisé) : le texte reste sélectionnable dans l'aperçu.
    const details = document.querySelector('.ho-text');
    if (details) details.open = true;
    const pre = document.getElementById('ho-text');
    if (pre) getSelection().selectAllChildren(pre);
    toast('Copie indisponible : texte sélectionné dans l’aperçu (Ctrl+C).');
  }
});
$('#content').addEventListener('change', e => {
  if (e.target.id !== 'ho-hours') return;
  hoHours = Number(e.target.value) || 24;
  hoData = null;
  hoPaint();
  loadHandover();
});

pageRenderers.Passation = function () {
  $('#content').innerHTML = '<div id="handover-data">' + hoMarkup() + '</div>';
  loadHandover();
};
sourceLoaders.Passation = () => loadHandover(true);
