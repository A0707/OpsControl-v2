/* Phase 4 — pont progressif entre le shell historique et la vue Parc modulaire.
 *
 * Le shell reste propriétaire de l'état et du polling. La vue reçoit un
 * instantané et des intentions : aucune seconde boucle réseau, aucun état
 * concurrent. Si l'import échoue, `render()` retombe sur le tableau historique.
 */
(function installParcNext() {
  // Une seule clé de préférences pour toute l'interface (opscontrol-v2-prefs, champ « parc ») ;
  // l'ancienne clé propre au parc est reprise une fois puis supprimée.
  const PREFS_KEY = 'opscontrol-v2-prefs', LEGACY_KEY = 'infraops.parc.preferences';
  const defaults = {query: '', status: '', environment: '', role: '', sortKey: 'status', sortDirection: 1, density: 'compact'};
  let preferences = {...defaults}, view = null, loading = null;
  try {
    const all = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}') || {};
    const legacy = JSON.parse(localStorage.getItem(LEGACY_KEY) || 'null');
    preferences = {...defaults, ...(legacy || {}), ...(all.parc || {})};
    if (legacy) {
      localStorage.setItem(PREFS_KEY, JSON.stringify({...all, parc: preferences}));
      localStorage.removeItem(LEGACY_KEY);
    }
  } catch { /* confort facultatif */ }

  const root = document.createElement('div');
  root.id = 'next-parc';
  root.className = 'n-app n-embedded';
  root.dataset.density = preferences.density;

  function save() {
    try {
      const all = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}') || {};
      localStorage.setItem(PREFS_KEY, JSON.stringify({...all, parc: preferences}));
    } catch { /* stockage facultatif */ }
    if (typeof v2SavePrefs === 'function') v2SavePrefs();
  }

  function syncLegacyFilters() {
    preferences.query = filters.q || '';
    preferences.status = filters.status || '';
    preferences.environment = filters.environment || '';
    preferences.role = filters.role || '';
    preferences.sortKey = sortKey || preferences.sortKey;
    preferences.sortDirection = sortDir || preferences.sortDirection;
  }

  function snapshot() {
    const hosts = onlineHosts(), counts = {};
    for (const host of hosts) counts[host.status] = (counts[host.status] || 0) + 1;
    const job = state?.jobs?.ssh || state?.job || {};
    return {
      hosts, counts,
      // Total de l'inventaire consolidé : le parc géré est toujours annoncé avec son dénominateur.
      inventoryTotal: (state?.hosts || []).length,
      job: {running: Boolean(job.running), completed: job.completed || 0, total: job.total || hosts.length, error: job.error || null},
      monitoring: state?.monitoring || {interval: 0, next_at: null},
      pending: !state, error: null, preferences,
      availability: state?.availability || {exclusions: {}},
    };
  }

  function update() { if (view) view.update(snapshot()); }

  function setPreference(key, value) {
    if (key === 'sortDirection') value = Number(value) === -1 ? -1 : 1;
    preferences[key] = value;
    if (key === 'query') filters.q = value;
    if (['status', 'environment', 'role'].includes(key)) filters[key] = value;
    if (key === 'sortKey') sortKey = value;
    if (key === 'sortDirection') sortDir = value;
    pageFilters.set('Serveurs', {...filters});
    save(); update();
  }

  function resetFilters() {
    Object.assign(preferences, {query: '', status: '', environment: '', role: ''});
    filters = {q: '', status: '', environment: '', role: ''};
    pageFilters.set('Serveurs', {...filters});
    save(); update();
  }

  function fallback(error) {
    console.error('Vue Parc optimisée indisponible, retour au rendu historique.', error);
    delete pageRenderers.Serveurs;
    root.remove();
    if (page === 'Serveurs' && !selected) render();
  }

  function paint() {
    if (page !== 'Serveurs' || selected || !state) return;
    syncLegacyFilters();
    const content = document.getElementById('content');
    // Les anciens wrappers ajoutent encore quelques blocs de chrome après le
    // renderer central. On repart donc du root unique à chaque cycle : leurs
    // ajouts restent au nombre de un, tandis que les 84 lignes sont conservées.
    if (root.parentNode !== content) content.replaceChildren(root);
    else for (const sibling of [...content.children]) if (sibling !== root) sibling.remove();
    if (view) { update(); return; }
    root.textContent = 'Chargement de la vue optimisée du parc…';
    if (!loading) loading = import('/next/parc-view.js?v=8429ffac').then(({mountParcView}) => {
      root.textContent = '';
      view = mountParcView(root, {
        refreshAll: async () => { await post('/api/refresh'); await load(); },
        audit: async (key) => { await post('/api/hosts/' + encodeURIComponent(key) + '/refresh'); await load(); },
        setInterval: async (seconds) => { await post('/api/monitoring', {interval: Number(seconds)}); await load(); },
        setPreference, resetFilters,
        isBusy: () => Boolean(state?.jobs?.ssh?.running || state?.job?.running),
        isActive: () => page === 'Serveurs' && !selected && root.isConnected,
        open: (key) => openHost(key),
      });
      update();
    }).catch(fallback);
  }

  pageRenderers.Serveurs = paint;
  if (page === 'Serveurs' && state && !selected) render();
})();
