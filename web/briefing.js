// Bilan à l'ouverture (/api/briefing) : ce qu'il faut savoir AVANT de regarder l'écran.
//
// Le bandeau d'alertes n'interrompt que pour une preuve récente. En ouvrant l'application
// le matin, un incident de la nuit pouvait donc rester silencieux (preuve « à reconfirmer »),
// et une source muette laissait croire à un parc sain. Le bilan s'affiche :
//   - à la première consultation de la session du navigateur ;
//   - au retour sur l'onglet après 30 min d'absence, si le bilan a changé et n'est pas sain.
// Pendant le contrôle de démarrage (sources API + sondes réseau), il se met à jour seul.
// Lecture seule : « Revérifier maintenant » relance les mêmes collectes de lecture que
// le bouton de disponibilité (/api/availability/refresh).

const BRIEFING_SHOWN_KEY = 'infraops.bilan.affiche';
const BRIEFING_AWAY_MS = 30 * 60 * 1000;
const BRIEFING_POLL_MS = 4000;
const BRIEFING_LABELS = {critical: 'Critique', warning: 'À vérifier', unverified: 'Non confirmé', ok: 'Sain'};
const BRIEFING_BADGES = {critical: 'critical', warning: 'warning', unverified: 'unknown', ok: 'ok'};
let briefingData = null, briefingTimer = null, briefingRecheckUntil = 0, briefingHiddenAt = 0;

const briefingDialog = document.createElement('dialog');
briefingDialog.id = 'briefing-dialog';
briefingDialog.className = 'v2-dialog briefing-dialog';
briefingDialog.setAttribute('aria-labelledby', 'briefing-title');
document.body.append(briefingDialog);

function briefingSignature(data) {
  return data.level + '|' + data.sections.map(s => s.key + ':' + s.items.map(i => i.id || i.title).join(',')).join(';');
}
function briefingStore(get, value) {
  try {
    if (get) return sessionStorage.getItem(BRIEFING_SHOWN_KEY);
    sessionStorage.setItem(BRIEFING_SHOWN_KEY, value);
  } catch { /* stockage indisponible : le bilan sera simplement réaffiché */ }
  return null;
}
function briefingAge(iso) {
  const s = ageSeconds(iso);
  if (s === null || s < 0) return '';
  return typeof t0Ago === 'function' ? 'il y a ' + t0Ago(s) : '';
}

function briefingItem(i) {
  const meta = [i.source, i.count > 1 ? i.count + ' cibles' : '', briefingAge(i.observed_at)].filter(Boolean).join(' · ');
  return '<li><div><b>' + esc(i.title) + '</b>' + (meta ? ' <span class="mini">' + esc(meta) + '</span>' : '') +
    (i.detail ? '<p>' + esc(i.detail) + '</p>' : '') + '</div>' +
    (i.host_key ? '<button data-briefing-host="' + escAttr(i.host_key) + '">Fiche ↗</button>'
      : i.page ? '<button data-briefing-go="' + escAttr(i.page) + '">Ouvrir</button>' : '') + '</li>';
}

function briefingMarkup(data) {
  const c = data.counts || {};
  const notes = [c.acknowledged ? c.acknowledged + ' critique(s) prise(s) en charge' : '',
    c.maintenance ? c.maintenance + ' en maintenance' : '',
    c.chronic ? c.chronic + ' anomalie(s) chronique(s) (> 30 j) non comptée(s)' : ''].filter(Boolean);
  const startup = data.startup || {};
  return '<div class="v2-dialog-card"><header><div><span class="badge ' + BRIEFING_BADGES[data.level] + '">' +
    esc(BRIEFING_LABELS[data.level] || data.level) + '</span><h2 id="briefing-title">Bilan à l’ouverture</h2>' +
    '<p class="briefing-headline">' + esc(data.headline) + '</p></div>' +
    '<button type="button" data-briefing-close aria-label="Fermer le bilan">×</button></header><div class="briefing-body">' +
    (data.checking || Date.now() < briefingRecheckUntil
      ? '<p class="briefing-checking" role="status">' + (data.checking
        ? 'Contrôle de démarrage en cours : sources API et sondes réseau relues. Ce bilan se met à jour seul.'
        : 'Revérification en cours : ce bilan se met à jour seul.') + '</p>' : '') +
    (startup.note ? '<p class="note">' + esc(startup.note) + '</p>' : '') +
    data.sections.map(s => '<section class="briefing-section briefing-' + escAttr(s.severity) + '"><h3>' + esc(s.title) +
      ' <span class="state-count">' + s.count + '</span></h3>' + (s.note ? '<p class="note">' + esc(s.note) + '</p>' : '') +
      '<ul>' + s.items.map(briefingItem).join('') + '</ul>' +
      (s.count > s.items.length ? '<button class="link" data-briefing-go="' + escAttr(s.page) + '">Voir les ' +
        (s.count - s.items.length) + ' autres</button>' : '') + '</section>').join('') +
    (data.sections.length ? '' : '<p class="empty">Aucun incident critique, aucune source en défaut, collecte saine.</p>') +
    (notes.length ? '<p class="note">' + esc(notes.join(' · ')) + '</p>' : '') +
    '</div><footer><span>' + esc(data.scope || '') + '</span><div class="briefing-actions">' +
    '<button type="button" data-briefing-recheck>Revérifier maintenant</button>' +
    (data.counts?.critical || data.counts?.reconfirm ? '<button type="button" class="primary" data-briefing-go="Alertes">Voir les alertes</button>' : '') +
    '<button type="button" data-briefing-close>J’ai pris connaissance</button></div></footer></div>';
}

function briefingPaint() {
  const scroll = briefingDialog.querySelector('.briefing-body')?.scrollTop || 0;
  briefingDialog.innerHTML = briefingMarkup(briefingData);
  const body = briefingDialog.querySelector('.briefing-body');
  if (body) body.scrollTop = scroll;
}

function briefingOpen() {
  if (!briefingData) return;
  briefingPaint();
  if (!briefingDialog.open) briefingDialog.showModal();
  briefingStore(false, briefingSignature(briefingData));
  briefingSchedule();
}

// Rafraîchit le bilan tant qu'il est ouvert et qu'une vérification est en cours.
function briefingSchedule() {
  clearTimeout(briefingTimer);
  if (!briefingDialog.open || !(briefingData?.checking || Date.now() < briefingRecheckUntil)) return;
  briefingTimer = setTimeout(async () => {
    await loadBriefing();
    if (briefingDialog.open && briefingData) briefingPaint();
    briefingSchedule();
  }, BRIEFING_POLL_MS);
}

async function loadBriefing() {
  try {
    const data = await api('/api/briefing');
    // Ancienne API ou réponse tronquée : pas de bilan plutôt qu'un faux « sain ».
    if (!data || !Array.isArray(data.sections) || !BRIEFING_LABELS[data.level]) return null;
    briefingData = data;
  } catch { return null; }
  return briefingData;
}

async function briefingOnOpen() {
  const data = await loadBriefing();
  if (!data) return;
  const dejaVu = briefingStore(true);
  if (dejaVu !== null) return;
  if (data.level === 'ok' && !data.checking) {
    briefingStore(false, briefingSignature(data));
    toast('Bilan : ' + data.headline + '.');
    return;
  }
  briefingOpen();
}

document.addEventListener('visibilitychange', async () => {
  if (document.hidden) { briefingHiddenAt = Date.now(); return; }
  if (!briefingHiddenAt || Date.now() - briefingHiddenAt < BRIEFING_AWAY_MS) return;
  briefingHiddenAt = 0;
  const data = await loadBriefing();
  if (data && data.level !== 'ok' && briefingSignature(data) !== briefingStore(true)) briefingOpen();
});

briefingDialog.addEventListener('close', () => clearTimeout(briefingTimer));
briefingDialog.addEventListener('click', async e => {
  if (e.target === briefingDialog) { briefingDialog.close(); return; }
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-briefing-close')) briefingDialog.close();
  else if (b.dataset.briefingGo) { briefingDialog.close(); navigate(b.dataset.briefingGo); }
  else if (b.dataset.briefingHost) { briefingDialog.close(); openHost(b.dataset.briefingHost, b); }
  else if (b.hasAttribute('data-briefing-recheck')) {
    b.disabled = true;
    try {
      await post('/api/availability/refresh', {});
      briefingRecheckUntil = Date.now() + 60000;
      toast('Revérification lancée : sources API et sondes réseau.');
      briefingPaint();
      briefingSchedule();
    } catch (error) { toast(error.message); b.disabled = false; }
  }
});
// Réouverture à la demande (bouton du panneau « Incidents critiques » de l'accueil).
document.addEventListener('click', async e => {
  if (!e.target.closest('button[data-briefing-open]')) return;
  if (await loadBriefing()) briefingOpen();
});

briefingOnOpen();
