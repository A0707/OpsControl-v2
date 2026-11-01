/**
 * Composant principal : la console « Parc serveurs ».
 *
 * C'est la vue de travail quotidienne sur ~84 serveurs. Ses objectifs, dans
 * cet ordre : voir vite ce qui ne va pas, filtrer sans quitter le clavier,
 * et ne jamais présenter une mesure absente ou ancienne comme un état sain.
 *
 * Contrat du composant :
 *   mountParcView(root, actions) -> { update(state) }
 * Le squelette est construit une seule fois ; `update` ne fait que corriger
 * les nœuds concernés. Aucune reconstruction complète, donc pas de perte de
 * focus ni de saut de défilement pendant les rafraîchissements automatiques.
 */
import { h, append, clear, reconcile, setText, setClass, setFill, delegate } from './dom.js';
import { STATUS_LABELS, STATUS_RANK, STALE_AFTER_MS, pct, stamp, relative, metricLevel, metricAria } from './format.js';

/** Colonnes du tableau. `sort` absent = colonne non triable. */
const COLUMNS = [
  { id: 'name',         title: 'Serveur',     sort: 'name' },
  { id: 'ip',           title: 'Adresse IP',  sort: 'ip',       secondary: true },
  { id: 'role',         title: 'Rôle / env.', sort: 'role',     secondary: true },
  { id: 'status',       title: 'État',        sort: 'status' },
  { id: 'cpu',          title: 'CPU',         sort: 'cpu' },
  { id: 'ram',          title: 'RAM',         sort: 'ram' },
  { id: 'disk_max',     title: 'Disque max',  sort: 'disk_max' },
  { id: 'services',     title: 'Services',                       secondary: true },
  { id: 'backup',       title: 'Backup',                         secondary: true },
  { id: 'coverage',     title: 'Couverture',                    secondary: true },
  { id: 'collected_at', title: 'Collecte',    sort: 'collected_at' },
  { id: 'go',           title: '' },
];

/** Filtres rapides par gravite, dans l'ordre ou l'exploitation les consulte. */
// Pluriels du vocabulaire unique SEVERITY (web/app.js), mêmes mots en secours.
const PLURAL = { critical: 'Critiques', unreachable: 'Injoignables', warning: 'Majeurs', unknown: 'Inconnus', ok: 'OK' };
const plural = code => (typeof SEVERITY !== 'undefined' && SEVERITY[code] ? SEVERITY[code].plural : PLURAL[code]);
const STATUS_CHIPS = [{ value: '', label: 'Tous' }]
  .concat(['critical', 'unreachable', 'warning', 'unknown', 'ok'].map(value => ({ value, label: plural(value) })));

/** Un serveur est « obsolète » si sa dernière collecte dépasse le seuil de fraîcheur. */
function isStale(host) {
  if (host.stale != null) return Boolean(host.stale);
  return !host.collected_at || Date.now() - Date.parse(host.collected_at) > STALE_AFTER_MS;
}

/** Filtre + tri. Fonction pure : testable sans navigateur. */
export function selectHosts(hosts, preferences) {
  const { query, status, environment, role, sortKey, sortDirection } = preferences;
  const needle = query.trim().toLowerCase();
  const filtered = hosts.filter((host) => {
    if (needle && !`${host.name} ${host.ip} ${host.role || ''}`.toLowerCase().includes(needle)) return false;
    if (status && host.status !== status) return false;
    if (environment && host.environment !== environment) return false;
    if (role && host.role !== role) return false;
    return true;
  });
  return filtered.sort((a, b) => {
    const left = sortKey === 'status' ? STATUS_RANK[a.status] ?? 9 : a[sortKey];
    const right = sortKey === 'status' ? STATUS_RANK[b.status] ?? 9 : b[sortKey];
    // Une valeur absente n'est ni grande ni petite : elle part en fin de liste.
    if (left == null) return right == null ? 0 : 1;
    if (right == null) return -1;
    const order = typeof left === 'number' && typeof right === 'number'
      ? left - right
      : String(left).localeCompare(String(right), 'fr', { numeric: true });
    return order * sortDirection || a.name.localeCompare(b.name, 'fr', { numeric: true });
  });
}

/** Pastille d'état. `unknown` couvre « jamais collecté » comme « obsolète ». */
function badge(status) {
  const known = Object.hasOwn(STATUS_LABELS, status);
  return h('span', { class: `n-badge ${known ? status : 'unknown'}` },
    h('span', { class: 'n-dot', 'aria-hidden': 'true' }),
    STATUS_LABELS[status] || status);
}

/**
 * Jauge d'une mesure. Le remplissage est posé par CSSOM (`setFill`) : la CSP
 * du serveur interdit les attributs style, mais pas l'écriture depuis un
 * script déjà chargé. Voir la note d'en-tête de dom.js.
 */
function metricCell() {
  const value = h('span', { class: 'n-metric-value' });
  const fill = h('i', { class: 'n-fill' });
  const track = h('span', { class: 'n-meter', role: 'img' }, fill);
  const node = h('td', { class: 'n-num' }, h('div', { class: 'n-metric' }, value, track));
  return {
    node,
    update(host, key) {
      const raw = host[key];
      const level = metricLevel(key, raw);
      const stale = isStale(host);
      const names = { cpu: 'CPU', ram: 'RAM', disk_max: 'Disque' };
      setText(value, pct(raw));
      setClass(track, `n-meter${level && level !== 'normal' ? ` ${level}` : ''}${stale ? ' stale' : ''}`);
      track.setAttribute('aria-label', `${names[key]} : ${metricAria(key, raw)}${stale ? ', mesure ancienne' : ''}`);
      // Aucune barre quand rien n'a ete mesure : le vide doit se voir.
      setFill(fill, level === null ? 0 : raw);
      fill.hidden = level === null;
    },
  };
}

/** Une ligne de tableau, avec ses cellules mémorisées pour la mise à jour. */
function createRow(actions) {
  const name = h('button', { class: 'n-link', type: 'button', 'data-action': 'open' });
  const hypervisor = h('small', { class: 'n-sub' });
  const ip = h('td', { class: 'n-mono n-secondary' });
  const roleText = h('span');
  const envText = h('small', { class: 'n-sub' });
  const statusCell = h('td');
  const cpu = metricCell();
  const ram = metricCell();
  const disk = metricCell();
  const services = h('td', { class: 'n-secondary n-mini' });
  const backup = h('td', { class: 'n-secondary n-mini' });
  const coverage = h('td', { class: 'n-secondary n-mini' });
  const collected = h('td', { class: 'n-mini' });
  const audit = h('button', { class: 'n-ghost', type: 'button', 'data-action': 'audit', text: 'Auditer' });

  const node = h('tr', { tabindex: '-1' },
    h('td', {}, name, hypervisor),
    ip,
    h('td', { class: 'n-secondary' }, roleText, envText),
    statusCell,
    cpu.node, ram.node, disk.node,
    services, backup,
    coverage,
    collected,
    h('td', { class: 'n-right' }, audit));

  return {
    node,
    update(host) {
      const stale = isStale(host);
      node.dataset.key = host.key;
      node.dataset.status = host.status;
      setClass(node, stale ? 'n-stale' : '');
      setText(name, host.name);
      name.dataset.key = host.key;
      // Compatibilité pendant la migration : les outils existants repèrent
      // encore les liens vers une fiche avec data-host.
      name.dataset.host = host.key;
      // Une valeur absente répétée sur chaque ligne masque les informations utiles.
      // Le nœud reste affiché lorsqu'il est connu et éditable depuis la fiche.
      setText(hypervisor, host.node || '');
      setText(ip, host.ip);
      setText(roleText, host.role || 'À renseigner');
      setText(envText, host.environment || '—');
      clear(statusCell);
      // Cause principale (audit UI du 31/10, fiche 03.3) : une ligne critique s'explique sans
      // ouvrir la fiche, même quand CPU, RAM et disque sont dans les limites.
      append(statusCell, [badge(host.status), stale ? h('small', { class: 'n-sub', text: 'État à actualiser' }) : null,
        host.status_reason ? h('small', { class: 'n-sub status-reason', text: `Cause : ${host.status_reason}` }) : null]);
      cpu.update(host, 'cpu');
      ram.update(host, 'ram');
      disk.update(host, 'disk_max');
      const units = host.all_services || host.service_states || [];
      const failed = units.filter((unit) => unit.status === 'failed').length;
      setText(services, stale ? 'À actualiser' : failed ? `${failed} en échec` : (host.services || []).length ? 'Voir les contrôles' : 'À configurer');
      clear(backup);
      const saved = host.backup_summary;
      if (!saved?.matched) append(backup, [h('span', {class: 'n-badge unknown', text: 'Aucun job associé'})]);
      else {
        const labels = {ok: 'Derniers jobs réussis', critical: 'Dernier passage en erreur', warning: 'Avertissement', running: 'Job en cours', pending: 'Job en attente', unknown: 'Résultat non mesuré'};
        const tone = saved.fresh ? ({ok: 'ok', critical: 'critical', warning: 'warning', running: 'ok'}[saved.severity] || 'unknown') : 'unknown';
        const link = h('button', {class: 'n-link', type: 'button', 'data-action': 'open', dataset: {key: host.key, host: host.key}},
          h('span', {class: `n-badge ${tone}`, text: labels[saved.severity] || labels.unknown}));
        append(backup, [link, h('small', {class: 'n-sub', text: `${saved.jobs_count} job(s) · ${saved.fresh ? 'Collecte récente' : 'À reconfirmer'}`})]);
      }
      const c = host.coverage || { measured: 0, total: 15 };
      const missing = host.coverage_missing || [];
      setText(coverage, `${c.measured} / ${c.total}${c.measured > 0 && c.measured < c.total ? ' · partiel' : ''}`);
      coverage.title = missing.length ? `Non observés : ${missing.join(', ')}` : '';
      // Jamais mesuré : état explicite d'un serveur inscrit, pas une panne (audit A5).
      setText(collected, host.collected_at ? `Mesures SSH : ${relative(host.collected_at).toLowerCase()}` : 'Première collecte en attente');
      collected.title = stamp(host.collected_at);
      audit.dataset.key = host.key;
      audit.disabled = Boolean(actions.isBusy && actions.isBusy());
    },
  };
}

/**
 * Monte la console dans `root`.
 * @param {Element} root
 * @param {{open, audit, refreshAll, setPreference, resetFilters, setInterval, isBusy}} actions
 */
export function mountParcView(root, actions) {
  // --- Bandeau : identité de la vue, volume, action principale -------------
  const countBadge = h('span', { class: 'n-count' });
  const progress = h('p', { class: 'n-progress', role: 'status', 'aria-live': 'polite' });
  const refreshButton = h('button', { class: 'n-primary', type: 'button', 'data-action': 'refresh-all' }, 'Auditer tout le parc');
  const intervalSelect = h('select', { class: 'n-select', 'data-action': 'interval', 'aria-label': 'Fréquence d’actualisation automatique' },
    ...[[0, 'Actualisation manuelle'], [60, 'Chaque minute'], [300, 'Toutes les 5 min'], [900, 'Toutes les 15 min']]
      .map(([value, label]) => h('option', { value }, label)));

  const header = h('header', { class: 'n-head' },
    h('div', { class: 'n-head-text' },
      h('h1', {}, 'Parc serveurs', countBadge),
      progress),
    h('div', { class: 'n-head-actions' }, intervalSelect, refreshButton));

  // --- Bannière d'erreur : masquée tant qu'il n'y a rien à dire ------------
  const banner = h('p', { class: 'n-banner', role: 'alert', hidden: true });
  const scope = h('div', { class: 'n-scope', role: 'status' });

  // --- Barre d'outils ------------------------------------------------------
  const search = h('input', {
    class: 'n-search', type: 'search', id: 'search', 'data-action': 'query',
    placeholder: 'Rechercher un hostname, une IP, un rôle…',
    'aria-label': 'Rechercher un serveur', 'aria-keyshortcuts': 'Slash',
  });
  const chips = h('div', { class: 'n-chips', role: 'group', 'aria-label': 'Filtrer par état' },
    ...STATUS_CHIPS.map((chip) => h('button', {
      class: 'n-chip', type: 'button', 'data-action': 'status', 'aria-pressed': 'false',
      dataset: { value: chip.value },
    }, h('span', { class: 'n-chip-label' }, chip.label), h('span', { class: 'n-chip-count' }))));
  const environmentSelect = h('select', { class: 'n-select', 'data-action': 'environment', 'aria-label': 'Filtrer par environnement' });
  const roleSelect = h('select', { class: 'n-select', 'data-action': 'role', 'aria-label': 'Filtrer par rôle' });
  const densityButton = h('button', { class: 'n-ghost', type: 'button', 'data-action': 'density', 'aria-pressed': 'false' }, 'Densité');
  const resetButton = h('button', { class: 'n-ghost', type: 'button', 'data-action': 'reset', hidden: true }, 'Effacer les filtres');

  const toolbar = h('div', { class: 'n-toolbar' },
    search,
    chips,
    h('div', { class: 'n-toolbar-end' }, environmentSelect, roleSelect, densityButton, resetButton));

  // --- Résumé annoncé aux lecteurs d'écran à chaque changement de filtre ---
  const summary = h('p', { class: 'n-summary', role: 'status', 'aria-live': 'polite' });

  // --- Tableau -------------------------------------------------------------
  const headCells = new Map();
  const headRow = h('tr', {}, ...COLUMNS.map((column) => {
    const cell = h('th', {
      scope: 'col',
      class: column.secondary ? 'n-secondary' : '',
      'aria-sort': 'none',
    });
    if (column.sort) {
      cell.append(h('button', { class: 'n-sort', type: 'button', 'data-action': 'sort', dataset: { key: column.sort } },
        column.title, h('span', { class: 'n-sort-mark', 'aria-hidden': 'true' })));
    } else {
      cell.textContent = column.title;
      if (!column.title) cell.setAttribute('aria-label', 'Actions');
    }
    headCells.set(column.id, cell);
    return cell;
  }));

  const tbody = h('tbody');
  const empty = h('div', { class: 'n-empty', hidden: true });
  const table = h('div', { class: 'n-table-scroll', tabindex: '0', role: 'region', 'aria-label': 'Tableau du parc, défilement horizontal' },
    h('table', { class: 'n-table' },
      h('caption', { class: 'n-visually-hidden' }, 'Parc serveurs : état, mesures et dernière collecte'),
      h('thead', {}, headRow),
      tbody));

  const shortcuts = h('p', { class: 'n-shortcuts' },
    h('kbd', {}, '/'), ' rechercher · ',
    h('kbd', {}, 'Flèches'), ' parcourir · ',
    h('kbd', {}, 'Entrée'), ' ouvrir · ',
    h('kbd', {}, 'Échap'), ' effacer les filtres');

  append(root, [header, banner, scope, h('section', { class: 'n-panel' }, toolbar, summary, table, empty, shortcuts)]);

  // ---------------------------------------------------------------------
  // Événements : un seul point d'entrée par type, lisible d'un coup d'œil.
  // ---------------------------------------------------------------------
  let lastPreferences = { sortKey: 'status', sortDirection: 1 };

  delegate(root, 'click', {
    'refresh-all': () => actions.refreshAll(),
    open: (_event, element) => actions.open(element.dataset.key),
    audit: (_event, element) => actions.audit(element.dataset.key),
    status: (_event, element) => actions.setPreference('status', element.dataset.value),
    reset: () => actions.resetFilters(),
    density: () => actions.setPreference('density', root.dataset.density === 'compact' ? 'cosy' : 'compact'),
    sort: (_event, element) => {
      const key = element.dataset.key;
      actions.setPreference('sortDirection', lastPreferences.sortKey === key ? -lastPreferences.sortDirection : 1);
      actions.setPreference('sortKey', key);
    },
  });
  delegate(root, 'input', { query: (event) => actions.setPreference('query', event.target.value) });
  delegate(root, 'change', {
    environment: (event) => actions.setPreference('environment', event.target.value),
    role: (event) => actions.setPreference('role', event.target.value),
    interval: (event) => actions.setInterval(event.target.value),
  });

  // Raccourcis clavier : une console d'exploitation se pilote sans souris.
  document.addEventListener('keydown', (event) => {
    if (actions.isActive && !actions.isActive()) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName);
    if (event.key === '/' && !typing) { event.preventDefault(); search.focus(); search.select(); return; }
    if (event.key === 'Escape' && (!typing || event.target === search)) { actions.resetFilters(); search.blur(); return; }
    if (typing) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      const rows = [...tbody.rows];
      if (!rows.length) return;
      event.preventDefault();
      const current = document.activeElement && document.activeElement.closest('tr');
      const index = rows.indexOf(current);
      const step = event.key === 'ArrowDown' ? 1 : -1;
      const next = rows[Math.max(0, Math.min(rows.length - 1, index < 0 ? 0 : index + step))];
      next.focus();
      next.scrollIntoView({ block: 'nearest' });
    }
    if (event.key === 'Enter' && document.activeElement && document.activeElement.tagName === 'TR') {
      actions.open(document.activeElement.dataset.key);
    }
  });

  // ---------------------------------------------------------------------
  // Mise à jour : appelée à chaque changement d'état ou de préférence.
  // ---------------------------------------------------------------------
  function fillOptions(select, values, current, allLabel) {
    const wanted = ['', ...values];
    if (select.__values !== wanted.join(' ')) {
      clear(select);
      append(select, wanted.map((value) => h('option', { value }, value || allLabel)));
      select.__values = wanted.join(' ');
    }
    if (select.value !== current) select.value = current;
  }

  function update(state) {
    const preferences = lastPreferences = { ...state.preferences };
    root.dataset.density = preferences.density;

    // En-tête et progression
    setText(countBadge, String(state.hosts.length));
    setText(progress, state.job.running
      ? `Audit en cours : ${state.job.completed} / ${state.job.total} serveurs`
      : state.monitoring.interval
        ? `Prochaine collecte : ${stamp(state.monitoring.next_at * 1000)}`
        : 'Collecte manuelle · aucune modification distante');
    refreshButton.disabled = state.job.running;
    intervalSelect.value = String(state.monitoring.interval || 0);

    const message = state.error || state.job.error || '';
    setText(banner, message);
    banner.hidden = !message;

    clear(scope);
    if (state.hosts.length) {
      const total = state.inventoryTotal ?? state.hosts.length, n = state.hosts.length;
      append(scope, [h('p', {}, `${n} serveur${n > 1 ? 's' : ''} du parc géré sur ${total} entrée${total > 1 ? 's' : ''} de l’inventaire consolidé · ${total - n} hors parc géré (découvertes ou sans preuve d’enregistrement) · Un arrêt ou un ping en échec ne retire pas un serveur du parc.`)]);
    } else {
      append(scope, [h('b', {}, 'Aucun serveur confirmé en ligne pour le moment'),
        h('p', {}, 'La liste attend un état Proxmox démarré et un ping récent.'),
        ...Object.entries(state.availability?.exclusions || {}).map(([reason, count]) => h('p', {}, `${count} · ${reason}`))]);
    }

    // Filtres
    if (search.value !== preferences.query) search.value = preferences.query;
    fillOptions(environmentSelect, [...new Set(state.hosts.map((x) => x.environment).filter(Boolean))].sort(), preferences.environment, 'Tous les environnements');
    fillOptions(roleSelect, [...new Set(state.hosts.map((x) => x.role).filter(Boolean))].sort(), preferences.role, 'Tous les rôles');
    for (const chip of chips.children) {
      const value = chip.dataset.value;
      const active = preferences.status === value;
      chip.setAttribute('aria-pressed', String(active));
      setClass(chip, `n-chip${active ? ' active' : ''}${value ? ` ${value}` : ''}`);
      setText(chip.querySelector('.n-chip-count'), value ? String(state.counts[value] || 0) : String(state.hosts.length));
    }
    const filtering = Boolean(preferences.query || preferences.status || preferences.environment || preferences.role);
    resetButton.hidden = !filtering;
    densityButton.setAttribute('aria-pressed', String(preferences.density === 'cosy'));

    // Indicateurs de tri, y compris pour les lecteurs d'écran
    for (const column of COLUMNS) {
      if (!column.sort) continue;
      const cell = headCells.get(column.id);
      const active = preferences.sortKey === column.sort;
      cell.setAttribute('aria-sort', active ? (preferences.sortDirection === 1 ? 'ascending' : 'descending') : 'none');
      // Repère purement visuel (aria-hidden) : l'ordre réel est porté par aria-sort.
      setText(cell.querySelector('.n-sort-mark'), active ? (preferences.sortDirection === 1 ? '▲' : '▼') : '');
    }

    // Lignes
    const visible = selectHosts(state.hosts, preferences);
    reconcile(tbody, visible, (host) => host.key, () => createRow(actions));

    setText(summary, state.pending
      ? 'Chargement du dernier état connu…'
      : `${visible.length} serveur${visible.length > 1 ? 's' : ''} affiché${visible.length > 1 ? 's' : ''} sur ${state.hosts.length}${filtering ? ' · filtres actifs' : ''}`);
    setText(empty, filtering
      ? 'Aucun serveur ne correspond à ces critères.'
      : 'Aucun serveur dans l’inventaire.');
    empty.hidden = visible.length > 0 || state.pending;

    // Roving tabindex : la tabulation traverse le tableau d'un bloc,
    // les flèches naviguent ligne par ligne à l'intérieur.
    [...tbody.rows].forEach((row, index) => { row.tabIndex = index === 0 ? 0 : -1; });
  }

  return { update };
}
