// OpsControl V2 — shell, navigation et cycle de vie.
//
// Chargé en DERNIER : tous les modules ont déjà enregistré leurs pages et leurs
// enveloppes de render/detailView. Ce fichier ne remplace aucune collecte ; il
// réorganise la navigation et ajoute l'état global de fraîcheur. Le dashboard
// et la fiche serveur vivent dans v2-dashboard.js et v2-detail.js.
// Toutes les données viennent des endpoints existants et de /api/v2/cockpit
// (synthèse en lecture des dernières collectes enregistrées).
document.documentElement.dataset.ui = 'v2';

// ---------------------------------------------------------------------------
// 1. Navigation par domaines. Les libellés de page (data-page) ne changent pas :
//    ils servent d'identifiants aux modules, aux tests et aux liens data-go.
// ---------------------------------------------------------------------------
// Centres : une seule entrée de menu, des onglets pour les vues sœurs (lot 3). Les
// identifiants de page ne changent pas — liens data-go, adresse #/…, tests — : seules
// les entrées de menu disparaissent. Aucune vue n'est supprimée.
const V2_HUBS = {
  Incidents: [['Incidents', 'Journal'], ['Alertes', 'Alertes en direct'], ['Problèmes', 'Constats d’audit'], ['Dossiers ITSM', 'ITSM / GLPI'],
    ['Passation', 'Passation']],
  Sources: [['Sources', 'Vue d’ensemble'], ['Zabbix', 'Zabbix'], ['Wazuh', 'Wazuh'], ['Elasticsearch', 'Elasticsearch'],
    ['Connexions API', 'Connexions'], ['Synchronisation', 'Synchronisation']]
};
const v2HubOf = p => Object.keys(V2_HUBS).find(hub => V2_HUBS[hub].some(([member]) => member === p)) || null;
const v2HubMembers = () => Object.values(V2_HUBS).flatMap(members => members.map(([p]) => p));

(function regroupNavigation() {
  const icons = new Map(navGroups.flatMap(([, items]) => items));
  const domains = [
    ['PILOTAGE', ['Vue globale', 'Incidents']],
    ['PARC', ['Serveurs', 'Services', 'Audit', 'Batch / Planification']],
    ['INFRASTRUCTURE', ['Proxmox', 'Réseau', 'Sauvegardes', 'Partages', 'WAF / HA']],
    ['SUPERVISION & SÉCURITÉ', ['Sources', 'Sécurité']],
    ['DONNÉES & CONFIGURATION', ['Inventaire', 'Compléter l’inventaire', 'Connexion', 'Santé d’OpsControl']]
  ];
  // Les vues sœurs d'un centre sont « placées » : elles ne deviennent pas des orphelines du menu.
  const placed = new Set(domains.flatMap(([, pages]) => pages).concat(v2HubMembers()));
  // Une page ajoutée par un module futur n'est jamais perdue : elle rejoint le dernier domaine.
  const orphans = [...icons.keys()].filter(p => !placed.has(p));
  const groups = domains.map(([title, pages], i) => [title,
    pages.concat(i === domains.length - 1 ? orphans : []).filter(p => icons.has(p)).map(p => [p, icons.get(p)])]);
  navGroups.splice(0, navGroups.length, ...groups.filter(([, items]) => items.length));
  navigation();
})();
const v2DefaultNav = navGroups.map(([title, items]) => [title, items.map(item => [...item])]);

const brandSmall = document.querySelector('.brand small');
if (brandSmall) brandSmall.textContent = 'MONITORING • OPERATIONS • SECURITY · V2';

// ---------------------------------------------------------------------------
// 2. Barre d'état globale : collecte, fraîcheur des sources, dernière mesure SSH.
// ---------------------------------------------------------------------------
const v2StatusBar = document.createElement('div');
v2StatusBar.id = 'v2-status';
v2StatusBar.className = 'v2-status';
v2StatusBar.setAttribute('role', 'status');
v2StatusBar.setAttribute('aria-label', 'État global de la collecte');
document.querySelector('.topbar .top-actions')?.insertAdjacentElement('beforebegin', v2StatusBar);

function v2LatestSsh(hosts) {
  return hosts.map(h => h.collected_at).filter(Boolean).sort().at(-1) || null;
}

// Liste UNIQUE des sources API (dernière vue globale) : barre d'état et indicateur
// « Sources récentes » la lisent toutes deux, sans pouvoir se contredire.
function v2Sources() {
  return state?.availability?.sources || (typeof v2Cockpit !== 'undefined' && v2Cockpit?.sources) || [];
}

function v2StatusMarkup() {
  if (!state) return ui.pill('Chargement…', 'unknown');
  const jobs = state.jobs || { ssh: state.job };
  const running = Object.entries(jobs).filter(([, j]) => j?.running);
  const sources = v2Sources();
  const freshCount = sources.filter(s => s.fresh).length;
  const staleNames = sources.filter(s => !s.fresh).map(s => s.name + (s.error ? ' : ' + s.error : ''));
  const collect = running.length
    ? '<span class="v2-status-collect">' + ui.pill('Collecte ' + running.map(([n, j]) => n.toUpperCase() + ' ' + (j.completed || 0) + '/' + (j.total || 0)).join(' · '), 'info') + '</span>'
    : '';
  const api = sources.length
    ? ui.pill('Sources API ' + freshCount + '/' + sources.length + ' récentes', freshCount === sources.length ? 'ok' : 'warning',
        staleNames.length ? 'Anciennes ou en échec : ' + staleNames.join(' | ') : 'Toutes les sources ont une collecte réussie de moins de 15 min.')
    : ui.pill('Aucune source API', 'unknown');
  const realtime = typeof realtimeLive === 'function' && realtimeLive()
    ? ui.pill('Temps réel', 'ok', 'Flux /api/events connecté et actif')
    : ui.pill('Temps réel interrompu', 'unknown', 'Actualisation périodique de secours');
  return collect + api + '<span class="v2-status-age">' + ui.fresh(v2LatestSsh(state.hosts || []), 'Mesure SSH', 900) + '</span>' + realtime;
}

function v2UpdateStatus() {
  const html = v2StatusMarkup();
  const jobs = state?.jobs || { ssh: state?.job };
  v2StatusBar.dataset.busy = Object.values(jobs).some(j => j?.running) ? 'true' : 'false';
  // Comparaison hors horodatage relatif : updateAges() fait déjà vivre le texte.
  if (v2StatusBar.dataset.signature !== html) { v2StatusBar.dataset.signature = html; v2StatusBar.innerHTML = html; }
}

// Identité : « Session locale · non authentifiée » tant que le reverse proxy ne l'atteste pas.
async function v2LoadIdentity() {
  const label = document.querySelector('.local-label');
  try {
    operatorIdentity = await api('/api/whoami');
  } catch { operatorIdentity = { authenticated: false, label: 'Session locale · identité inconnue' }; }
  if (label) {
    label.textContent = operatorIdentity.label;
    label.title = operatorIdentity.label + (operatorIdentity.detail ? ' — ' + operatorIdentity.detail : '');
    label.classList.toggle('is-local', !operatorIdentity.authenticated);
  }
}
v2LoadIdentity();

// ---------------------------------------------------------------------------
// 3. Navigation mémorisée : page dans l'URL (#/Proxmox), filtres et tri par page.
// ---------------------------------------------------------------------------
const V2_PREFS = 'opscontrol-v2-prefs';
let v2NavOrder = [], v2Favorites = [], v2Density = 'comfortable', v2Noc = false, v2Look = 'classic';
function v2ReadPrefs() {
  try { return JSON.parse(localStorage.getItem(V2_PREFS) || '{}') || {}; } catch { return {}; }
}
function v2SavePrefs() {
  const pages = Object.fromEntries([...pageFilters.entries()].filter(([p]) => p !== page));
  pages[page] = { ...filters };
  try { localStorage.setItem(V2_PREFS, JSON.stringify({ ...v2ReadPrefs(), pages, sortKey, sortDir,
    navOrder: v2NavOrder, favorites: v2Favorites, density: v2Density, noc: v2Noc, look: v2Look })); } catch { /* stockage indisponible */ }
}
(function restorePrefs() {
  const prefs = v2ReadPrefs();
  for (const [p, f] of Object.entries(prefs.pages || {})) {
    if (f && typeof f === 'object') pageFilters.set(p, { q: String(f.q || ''), status: String(f.status || ''), environment: String(f.environment || ''), role: String(f.role || '') });
  }
  if (typeof prefs.sortKey === 'string') sortKey = prefs.sortKey;
  if (prefs.sortDir === 1 || prefs.sortDir === -1) sortDir = prefs.sortDir;
  v2NavOrder = Array.isArray(prefs.navOrder) ? prefs.navOrder.map(String) : [];
  v2Favorites = Array.isArray(prefs.favorites) ? prefs.favorites.map(String) : [];
  v2Density = prefs.density === 'compact' ? 'compact' : 'comfortable';
  v2Noc = prefs.noc === true;
  v2Look = prefs.look === 'premium' ? 'premium' : 'classic';
})();

// ---------------------------------------------------------------------------
// 3a. Poste opérateur : densité, mode NOC, favoris et palette de commandes.
//     Tout reste côté navigateur afin de ne rien ajouter au chemin critique API.
// ---------------------------------------------------------------------------
function v2ApplyShellPrefs(save = false) {
  const previousDisplay = document.documentElement.dataset.display;
  document.documentElement.dataset.density = v2Density;
  document.documentElement.dataset.display = v2Noc ? 'noc' : 'standard';
  // Apparence premium : attribut retiré (et non mis à « classic ») pour qu'aucune règle de premium.css ne subsiste.
  if (v2Look === 'premium') document.documentElement.dataset.look = 'premium';
  else delete document.documentElement.dataset.look;
  const look = document.querySelector('[data-v2-look]');
  if (look) {
    look.textContent = v2Look === 'premium' ? 'Classique' : 'Premium';
    look.title = v2Look === 'premium' ? 'Revenir à l’interface classique' : 'Essayer l’apparence premium (ce poste uniquement)';
    look.setAttribute('aria-pressed', String(v2Look === 'premium'));
  }
  const density = document.querySelector('[data-v2-density]');
  if (density) {
    density.textContent = v2Density === 'compact' ? 'Confort' : 'Compact';
    density.title = v2Density === 'compact' ? 'Revenir à l’affichage confortable' : 'Afficher davantage d’informations';
    density.setAttribute('aria-pressed', String(v2Density === 'compact'));
  }
  const noc = document.querySelector('[data-v2-noc]');
  if (noc) {
    noc.textContent = v2Noc ? 'Quitter NOC' : 'Mode NOC';
    noc.setAttribute('aria-pressed', String(v2Noc));
  }
  // La mosaïque NOC doit suivre le changement de mode sans attendre une sonde.
  if (previousDisplay !== document.documentElement.dataset.display && typeof t0Render === 'function') t0Render();
  if (save) v2SavePrefs();
}

function v2ApplyNavPrefs() {
  const rank = new Map(v2NavOrder.map((p, i) => [p, i]));
  const favorite = new Set(v2Favorites);
  const groups = v2DefaultNav.map(([title, items]) => [title, items.map(item => [...item]).sort((a, b) => {
    const favoriteDelta = Number(favorite.has(b[0])) - Number(favorite.has(a[0]));
    if (favoriteDelta) return favoriteDelta;
    return (rank.get(a[0]) ?? 999) - (rank.get(b[0]) ?? 999);
  })]);
  navGroups.splice(0, navGroups.length, ...groups);
}

navigationHooks.push(function () {
  // Vue sœur d'un centre : l'entrée du centre reste active dans le menu et le sélecteur mobile.
  const hub = selected ? null : v2HubOf(page);
  if (hub && hub !== page) {
    const button = document.querySelector('#nav [data-page="' + hub + '"]');
    if (button) { button.classList.add('active'); button.setAttribute('aria-current', 'page'); }
    const mobile = document.getElementById('mobile-nav');
    if (mobile) mobile.value = hub;
  }
  v2RenderHubTabs();
  const favorite = new Set(v2Favorites);
  document.querySelectorAll('#nav [data-page]').forEach(button => {
    const isFavorite = favorite.has(button.dataset.page);
    button.classList.toggle('v2-favorite', isFavorite);
    button.title = isFavorite ? button.dataset.page + ' · favori' : button.dataset.page;
    let mark = button.querySelector('.v2-favorite-mark');
    if (isFavorite && !mark) button.insertAdjacentHTML('beforeend', '<span class="v2-favorite-mark" aria-hidden="true">★</span>');
    else if (!isFavorite) mark?.remove();
  });
});

// Onglets du centre courant, hors de #content : les vues sœurs réécrivent #content
// sans jamais les effacer. Boutons data-go (gestionnaire global d'app.js).
const v2HubTabs = document.createElement('nav');
v2HubTabs.id = 'v2-hub-tabs';
v2HubTabs.className = 'v2-hub-tabs';
v2HubTabs.hidden = true;
function v2HubCount(p) {
  if (p === 'Alertes' && typeof alertInterrupting === 'function' && typeof alertData !== 'undefined' && alertData) return alertInterrupting().length;
  if (p === 'Problèmes' && state) return incidents(state.hosts).filter(x => !x.h.stale).length;
  return 0;
}
function v2RenderHubTabs() {
  const content = document.getElementById('content');
  // Déplacer un élément lui fait perdre le focus : on ne le replace que s'il est absent ou
  // après #content (d'autres zones, masquées hors accueil, peuvent s'intercaler).
  if (!v2HubTabs.isConnected || !(v2HubTabs.compareDocumentPosition(content) & Node.DOCUMENT_POSITION_FOLLOWING)) content.before(v2HubTabs);
  const hub = selected ? null : v2HubOf(page);
  v2HubTabs.hidden = !hub;
  if (!hub) { v2HubTabs.dataset.signature = ''; return; }
  const html = V2_HUBS[hub].map(([p, label]) => {
    const n = v2HubCount(p);
    return '<button data-go="' + escAttr(p) + '"' + (p === page ? ' class="active" aria-current="page"' : '') + '>' + esc(label) +
      (n ? '<span class="nav-count">' + n + '</span>' : '') + '</button>';
  }).join('');
  if (v2HubTabs.dataset.signature === html) return;
  const focused = v2HubTabs.contains(document.activeElement) ? document.activeElement.dataset.go : null;
  v2HubTabs.setAttribute('aria-label', 'Vues du centre ' + hub);
  v2HubTabs.dataset.signature = html;
  v2HubTabs.innerHTML = html;
  if (focused) v2HubTabs.querySelector('[data-go="' + focused + '"]')?.focus({ preventScroll: true });
}

function v2Dialog(id, label) {
  let dialog = document.getElementById(id);
  if (dialog) return dialog;
  dialog = document.createElement('dialog');
  dialog.id = id;
  dialog.className = 'v2-dialog';
  dialog.setAttribute('aria-label', label);
  document.body.append(dialog);
  dialog.addEventListener('click', e => { if (e.target === dialog) dialog.close(); });
  return dialog;
}

function v2OpenCommand() {
  const dialog = v2Dialog('v2-command-dialog', 'Rechercher une page');
  const pages = navGroups.flatMap(([title, items]) => items.map(([name]) => [name, title]));
  // Les vues sœurs restent trouvables par la recherche, rattachées à leur centre.
  for (const [hub, members] of Object.entries(V2_HUBS))
    for (const [name, label] of members) if (!pages.some(([p]) => p === name)) pages.push([name, hub + ' › ' + label]);
  dialog.innerHTML = '<form method="dialog" class="v2-dialog-card"><header><div><span class="eyebrow">NAVIGATION RAPIDE</span><h2>Aller à…</h2></div><button aria-label="Fermer">×</button></header>' +
    '<label class="v2-command-search"><span>Rechercher</span><input id="v2-command-search" autocomplete="off" placeholder="Serveurs, Proxmox, alertes…"></label>' +
    '<div class="v2-command-list">' + pages.map(([name, group]) => '<button type="button" data-v2-page="' + escAttr(name) + '"><span>' + esc(name) + '</span><small>' + esc(group) + '</small></button>').join('') + '</div>' +
    '<footer><span><kbd>↑</kbd><kbd>↓</kbd> parcourir</span><span><kbd>Entrée</kbd> ouvrir · <kbd>Échap</kbd> fermer</span></footer></form>';
  dialog.showModal();
  const input = dialog.querySelector('input'), buttons = () => [...dialog.querySelectorAll('[data-v2-page]:not([hidden])')];
  input.addEventListener('input', () => {
    const q = input.value.trim().toLocaleLowerCase('fr');
    dialog.querySelectorAll('[data-v2-page]').forEach(b => { b.hidden = !b.dataset.v2Page.toLocaleLowerCase('fr').includes(q); });
  });
  dialog.addEventListener('click', e => { const b = e.target.closest('[data-v2-page]'); if (b) { dialog.close(); navigate(b.dataset.v2Page); } }, { once: true });
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); buttons()[0]?.focus(); }
    if (e.key === 'Enter' && buttons()[0]) { e.preventDefault(); buttons()[0].click(); }
  });
  dialog.querySelector('.v2-command-list').addEventListener('keydown', e => {
    if (!['ArrowDown', 'ArrowUp'].includes(e.key)) return;
    e.preventDefault(); const list = buttons(), at = list.indexOf(document.activeElement);
    list[(at + (e.key === 'ArrowDown' ? 1 : -1) + list.length) % list.length]?.focus();
  });
  input.focus();
}

function v2RenderNavDialog(dialog) {
  dialog.innerHTML = '<form method="dialog" class="v2-dialog-card v2-nav-card"><header><div><span class="eyebrow">ESPACE PERSONNEL</span><h2>Personnaliser la navigation</h2></div><button aria-label="Fermer">×</button></header>' +
    '<p class="note">Les favoris remontent dans chaque domaine. Les flèches changent l’ordre localement.</p><div class="v2-nav-editor">' + navGroups.map(([title, items]) =>
      '<section><h3>' + esc(title) + '</h3>' + items.map(([name]) => '<div class="v2-nav-row"><button type="button" data-v2-favorite="' + escAttr(name) + '" aria-pressed="' + v2Favorites.includes(name) + '" title="Ajouter ou retirer des favoris">' + (v2Favorites.includes(name) ? '★' : '☆') + '</button><span>' + esc(name) + '</span><button type="button" data-v2-move="-1" data-v2-page="' + escAttr(name) + '" aria-label="Monter ' + esc(name) + '">↑</button><button type="button" data-v2-move="1" data-v2-page="' + escAttr(name) + '" aria-label="Descendre ' + esc(name) + '">↓</button></div>').join('') + '</section>').join('') +
    '</div><footer><span>Enregistré sur ce navigateur</span><button>Terminé</button></footer></form>';
}

function v2OpenNavEditor() {
  const dialog = v2Dialog('v2-nav-dialog', 'Personnaliser la navigation');
  v2RenderNavDialog(dialog); dialog.showModal();
}

function v2CommitNav() {
  v2NavOrder = navGroups.flatMap(([, items]) => items.map(([name]) => name));
  v2SavePrefs(); navigation();
  const dialog = document.getElementById('v2-nav-dialog');
  if (dialog?.open) v2RenderNavDialog(dialog);
}

document.addEventListener('click', e => {
  const favorite = e.target.closest('[data-v2-favorite]');
  if (favorite) {
    const name = favorite.dataset.v2Favorite;
    v2Favorites = v2Favorites.includes(name) ? v2Favorites.filter(p => p !== name) : [...v2Favorites, name];
    v2ApplyNavPrefs(); v2CommitNav(); return;
  }
  const move = e.target.closest('[data-v2-move]');
  if (move) {
    const delta = Number(move.dataset.v2Move), name = move.dataset.v2Page;
    const group = navGroups.find(([, items]) => items.some(([p]) => p === name));
    if (!group) return;
    const at = group[1].findIndex(([p]) => p === name), next = Math.max(0, Math.min(group[1].length - 1, at + delta));
    if (at !== next) [group[1][at], group[1][next]] = [group[1][next], group[1][at]];
    v2CommitNav();
  }
});

// Mobile : les deux sélecteurs d'intervalle passent derrière « Réglages » ; état et bouton
// d'actualisation restent visibles (la barre occupait ~160 px du premier écran).
(function v2InstallControlToggle() {
  const control = document.querySelector('.control');
  if (!control || control.querySelector('.control-toggle')) return;
  control.insertAdjacentHTML('beforeend', '<button type="button" class="control-toggle" aria-expanded="false">Réglages</button>');
  control.querySelector('.control-toggle').addEventListener('click', e => {
    const open = control.classList.toggle('is-open');
    e.currentTarget.setAttribute('aria-expanded', String(open));
  });
})();

function v2InstallShellControls() {
  const actions = document.querySelector('.top-actions');
  if (!actions || actions.querySelector('[data-v2-command]')) return;
  actions.querySelector('#theme')?.insertAdjacentHTML('beforebegin',
    '<button class="v2-shell-button" data-v2-nav title="Personnaliser la navigation" aria-label="Personnaliser la navigation"><span aria-hidden="true">☷</span><span class="v2-shell-label" aria-hidden="true"> Menu</span></button>' +
    '<button class="v2-shell-button" data-v2-command title="Rechercher une page (Ctrl+K)" aria-label="Rechercher une page"><span aria-hidden="true">⌕</span><span class="v2-shell-label" aria-hidden="true"> Rechercher</span></button>' +
    '<button class="v2-shell-button v2-shell-text" data-v2-density aria-pressed="false" title="Densité de l’affichage">Compact</button>' +
    '<button class="v2-shell-button v2-shell-text" data-v2-noc aria-pressed="false" title="Mode NOC (écran mural)">Mode NOC</button>' +
    '<button class="v2-shell-button v2-shell-text" data-v2-look aria-pressed="false" title="Apparence de l’interface">Premium</button>');
  actions.addEventListener('click', e => {
    if (e.target.closest('[data-v2-command]')) v2OpenCommand();
    else if (e.target.closest('[data-v2-nav]')) v2OpenNavEditor();
    else if (e.target.closest('[data-v2-density]')) { v2Density = v2Density === 'compact' ? 'comfortable' : 'compact'; v2ApplyShellPrefs(true); }
    else if (e.target.closest('[data-v2-look]')) { v2Look = v2Look === 'premium' ? 'classic' : 'premium'; v2ApplyShellPrefs(true); }
    else if (e.target.closest('[data-v2-noc]')) { v2Noc = !v2Noc; if (v2Noc && page !== 'Vue globale') navigate('Vue globale'); v2ApplyShellPrefs(true); }
  });
  v2ApplyShellPrefs();
}

window.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); v2OpenCommand(); }
  else if (e.key === 'Escape' && v2Noc && !document.querySelector('dialog[open]')) { v2Noc = false; v2ApplyShellPrefs(true); }
});

v2ApplyNavPrefs();
v2InstallShellControls();
const v2Pages = () => new Set(navGroups.flatMap(([, items]) => items.map(([p]) => p)).concat(v2HubMembers()));
function v2PageFromHash() {
  try { const p = decodeURIComponent(location.hash.replace(/^#\/?/, '')); return v2Pages().has(p) ? p : null; } catch { return null; }
}
// Routes : #/<page> ou #/serveur/<clé>[/<onglet>]. pushState quand la page ou le serveur
// change : le bouton Retour revient à l'écran précédent et une fiche serveur se partage
// ou se met en favori. Simple changement d'onglet : replaceState (pas d'entrée d'historique).
let v2RouteBase = null, v2PendingRoute = null;
function v2Route() {
  const m = location.hash.replace(/^#\/?/, '').match(/^serveur\/([^/]+)(?:\/([\w-]+))?$/);
  if (m) {
    try {
      const tab = HOST_TABS.some(([k]) => k === m[2]) ? m[2] : 'summary';
      return { host: decodeURIComponent(m[1]), tab };
    } catch { return null; }
  }
  const p = v2PageFromHash();
  return p ? { page: p } : null;
}
function v2SyncHash() {
  if (v2PendingRoute) return;
  const base = selected ? '#/serveur/' + encodeURIComponent(selected) : '#/' + encodeURIComponent(page);
  const target = base + (selected && detailTab && detailTab !== 'summary' ? '/' + detailTab : '');
  if (location.hash !== target) {
    if (v2RouteBase !== null && v2RouteBase !== base) history.pushState(null, '', target);
    else history.replaceState(null, '', target);
  }
  v2RouteBase = base;
}
function v2ApplyRoute() {
  const r = v2Route();
  if (!r) return;
  if (r.host) {
    if (selected !== r.host) {
      openHost(r.host).then(() => { if (selected === r.host && detailTab !== r.tab) { detailTab = r.tab; render(); } });
    } else if (detailTab !== r.tab) { detailTab = r.tab; render(); }
  } else if (r.page !== page || selected) navigate(r.page);
}
window.addEventListener('popstate', v2ApplyRoute);
window.addEventListener('hashchange', v2ApplyRoute);
$('#content').addEventListener('input', e => { if (e.target.id === 'search') v2SavePrefs(); });
$('#content').addEventListener('change', e => { if (e.target.dataset.filter) v2SavePrefs(); });
$('#content').addEventListener('click', e => {
  if (e.target.closest('[data-sort],[data-reset],[data-status]')) setTimeout(v2SavePrefs, 0);
});

// ---------------------------------------------------------------------------
// 6. Enveloppes de cycle de vie : barre d'état après chaque chargement, page
//    mémorisée dans l'URL, marqueur de page pour la mise en forme.
// ---------------------------------------------------------------------------
loadHooks.push(() => { v2UpdateStatus(); v2RefreshOps(); });
renderHooks.push(function () {
  document.getElementById('content').dataset.page = selected ? 'server' : page;
  document.getElementById('content').dataset.detailTab = selected ? detailTab : '';
  const hub = selected ? null : v2HubOf(page);
  if (hub && hub !== page) $('#breadcrumb').textContent = hub + ' / ' + V2_HUBS[hub].find(([p]) => p === page)[1];
  v2RefreshOps();
  v2SyncHash();
  v2UpdateStatus();
});
poll('barre-d-etat', 5000, v2UpdateStatus);

(function startV2() {
  const route = v2Noc ? { page: 'Vue globale' } : v2Route();
  if (route?.host) {
    // Lien direct vers une fiche serveur : l'URL n'est pas réécrite tant que la fiche charge.
    v2PendingRoute = route;
    openHost(route.host).finally(() => {
      v2PendingRoute = null;
      if (selected === route.host && detailTab !== route.tab) detailTab = route.tab;
      render();
    });
    return;
  }
  const initial = route?.page;
  if (initial && initial !== page) navigate(initial);
  else render();
})();
