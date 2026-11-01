// Découverte réseau (network_discovery.py) : balayage d'une plage privée (ping, ports courts,
// bannière SSH, DNS inverse), type et système probables, puis ajout des machines nouvelles aux
// serveurs. Bouton « Découvrir des serveurs » sur la page Serveurs (administrateur).
// Les machines ajoutées passent ensuite par « Empreintes SSH à confirmer » (host-access.js).
let discoveryData = null, discoveryTimer = null, discoveryFilter = 'new';
const discoveryPicked = new Set();
let discoveryTab = 'scan', discoveryHistory = null, discoveryUsePve = false;
const DISCOVERY_STATUS = {inventory: ['Déjà dans l’inventaire', 'ok'], new_ssh: ['Nouvelle · SSH ouvert', 'warning'], new: ['Nouvelle · sans SSH', 'unknown']};

async function discoveryLoad() {
  discoveryData = await api('/api/discovery');
  discoveryPaint();
  clearTimeout(discoveryTimer);
  if (discoveryData.job.running && hostAccessDialog.open) discoveryTimer = setTimeout(() => discoveryLoad().catch(() => {}), 2000);
}

function discoveryOpen() {
  discoveryTab = 'scan'; discoveryUsePve = false; discoveryHistory = null;
  hostAccessOpen({title: 'Découvrir des serveurs', body:
    '<p>Balayage actif d’une plage privée : ping, ports ' + '<span id="disc-ports">22, 3300, 80, 443, 3389, 445, 8006</span>' +
    ', bannière SSH et nom DNS. Type et système sont <b>probables</b> (aucune connexion authentifiée). ' +
    'Un IDS ou Wazuh peut signaler ce balayage.</p>' +
    '<div role="tablist" aria-label="Découverte réseau"><button id="disc-tab-scan" role="tab" aria-selected="true" aria-controls="disc-scan-panel" data-disc-tab="scan">Dernier balayage</button> <button id="disc-tab-history" role="tab" aria-selected="false" aria-controls="disc-history-panel" data-disc-tab="history">Historique</button></div>' +
    '<div id="disc-scan-panel" role="tabpanel" aria-labelledby="disc-tab-scan"><div class="filters"><label>Plage <input id="disc-range" maxlength="43" value="10.77.0.0/24"></label>' +
    '<button class="primary" type="button" data-disc-scan>Lancer la découverte</button></div>' +
    '<p class="form-error" role="alert"></p><section id="disc-result"><p class="note">Chargement du dernier balayage…</p></section></div><section id="disc-history-panel" role="tabpanel" aria-labelledby="disc-tab-history" hidden></section>'});
  discoveryLoad().catch(e => { $('#disc-result').innerHTML = '<p role="alert">' + esc(e.message) + '</p>'; });
}

function discoveryRows() {
  return (discoveryData?.items || []).filter(i => discoveryFilter === 'all' || (discoveryFilter === 'new' ? i.status !== 'inventory' : i.status === discoveryFilter));
}

function discoveryPaint() {
  const out = $('#disc-result');
  if (!out || !discoveryData) return;
  const d = discoveryData, job = d.job;
  if (d.default_range && $('#disc-range') && !$('#disc-range').dataset.touched && d.range) $('#disc-range').value = d.range;
  const progress = job.running ? '<p class="instruction">Balayage de ' + esc(job.range) + ' en cours : ' + esc(job.completed) + ' / ' + esc(job.total) + ' adresses…</p>'
    : job.error ? '<p role="alert">Balayage interrompu : ' + esc(job.error) + '</p>' : '';
  if (!d.at) { out.innerHTML = progress || '<p class="note">Aucun balayage effectué.</p>'; return; }
  const c = d.counts, rows = discoveryRows();
  const chip = (key, label, n) => '<button type="button" data-disc-filter="' + key + '" aria-pressed="' + (discoveryFilter === key) + '"' +
    (discoveryFilter === key ? ' class="primary"' : '') + '>' + label + ' (' + n + ')</button>';
  const missing = (d.inventory_missing || []).length ? '<div class="instruction"><b>Machines de l’inventaire non observées dans cette plage</b><ul>' + d.inventory_missing.map(h => '<li><button class="link" data-disc-open="' + escAttr(h.key) + '">' + esc(h.name) + '</button> · ' + esc(h.ip) + '</li>').join('') + '</ul><p>Une absence de réponse ne prouve pas un arrêt.</p></div>' : '';
  out.innerHTML = progress + missing +
    '<p class="mini">' + esc(d.range) + ' · ' + stamp(d.at) + (d.duration_s ? ' · ' + esc(d.duration_s) + ' s' : '') + ' · ' + d.items.length + ' machine(s) répondent</p>' +
    '<div class="filters">' + chip('new', 'Nouvelles', c.new_ssh + c.new) + chip('new_ssh', 'Nouvelles avec SSH', c.new_ssh) +
      chip('inventory', 'Déjà dans l’inventaire', c.inventory) + chip('all', 'Toutes', d.items.length) + '</div>' +
    (rows.length ? '<div class="table"><table><thead><tr><th></th><th>IP</th><th>Nom DNS</th><th>Type · système (probable)</th><th>Ping</th><th>Ports ouverts</th><th>Statut</th></tr></thead><tbody>' +
      rows.map(i => {
        // Statut inconnu (version serveur plus récente) : affiché tel quel, jamais une erreur JS (FE-08).
        const [label, tone] = DISCOVERY_STATUS[i.status] || [String(i.status || 'Statut inconnu'), 'unknown'];
        return '<tr><td>' + (i.status === 'inventory' ? '' : '<input type="checkbox" data-disc-pick value="' + escAttr(i.ip) + '"' +
            (discoveryPicked.has(i.ip) ? ' checked' : '') + ' aria-label="Sélectionner ' + escAttr(i.ip) + '">') + '</td>' +
          '<td class="ip">' + esc(i.ip) + '</td><td>' + esc(i.dns || '—') + discoveryProxmox(i) + '</td>' +
          '<td>' + esc(i.type) + (i.os ? '<small>' + esc(i.os) + '</small>' : '') + (i.ssh_banner ? '<small><code>' + esc(i.ssh_banner) + '</code></small>' : '') + '</td>' +
          '<td>' + (i.ping ? 'Oui' + (i.ttl ? '<small>TTL ' + esc(i.ttl) + '</small>' : '') : 'Non') + '</td>' +
          '<td>' + (i.ports.length ? esc(i.ports.join(', ')) : '—') + (i.ssh_port ? '<small>SSH : ' + esc(i.ssh_port) + '</small>' : '') + '</td>' +
          '<td><span class="badge ' + tone + '">● ' + esc(label) + '</span>' + (i.inventory ? '<small><button type="button" class="link" data-disc-open="' +
            escAttr(i.inventory.key) + '">' + esc(i.inventory.name) + '</button></small>' : '') + '</td></tr>';
      }).join('') + '</tbody></table></div>' : '<p class="note">Aucune machine pour ce filtre.</p>') +
    (c.new_ssh + c.new ? '<div class="filters"><button type="button" data-disc-pickall>Cocher les nouvelles avec SSH</button>' +
      '<button class="primary" type="button" data-disc-add>Ajouter aux serveurs (' + discoveryPicked.size + ')</button></div>' +
      '<label><input id="disc-use-pve" type="checkbox"' + (discoveryUsePve ? ' checked' : '') + '> Utiliser les noms et nœuds Proxmox proposés (correspondances uniques récentes)</label>' +
    '<p class="note">Ajout avec le rôle et l’environnement « À renseigner », le port SSH détecté et le nom DNS. ' +
      'Confirmer ensuite leur empreinte SSH avant le premier audit.</p>' : '');
}

function discoveryProxmox(item) {
  const proposal = item.proxmox_proposal;
  if (proposal) return '<small>Proxmox proposé : ' + esc(proposal.name) + ' · nœud ' + esc(proposal.node) +
    ' · ' + esc(proposal.source) + (proposal.fresh ? '' : ' · observation ancienne') + '</small>';
  return (item.proxmox_matches || []).length > 1 ? '<small>Correspondance Proxmox ambiguë · aucun nom appliqué</small>' : '';
}

function discoveryHistoryPaint() {
  const target = $('#disc-history-panel');
  if (!target || !discoveryHistory) return;
  const rows = discoveryHistory.scans || [];
  const changes = scan => {
    const diff = scan.changes;
    if (!diff) return scan.status === 'failed' ? 'Scan interrompu · différences non calculées' : 'Premier scan conservé de cette plage';
    return '<details><summary>' + diff.appeared.length + ' apparues · ' + diff.disappeared.length + ' non observées · ' + diff.ports_changed.length + ' changements de ports</summary>' +
      '<p>Apparues : ' + esc(diff.appeared.join(', ') || 'Aucune') + '</p><p>Non observées : ' + esc(diff.disappeared.join(', ') || 'Aucune') + '</p>' +
      diff.ports_changed.map(h => '<p>' + esc(h.ip) + ' : ' + esc(h.before.join(', ') || 'Aucun port') + ' → ' + esc(h.after.join(', ') || 'Aucun port') + '</p>').join('') + '</details>';
  };
  target.innerHTML = '<p>' + esc(discoveryHistory.scope) + '</p><button data-disc-history-reload>Actualiser l’historique</button>' +
    (rows.length ? '<div class="table"><table><thead><tr><th>Date / plage</th><th>Durée</th><th>État</th><th>Machines</th><th>Différences</th></tr></thead><tbody>' +
      rows.map(s => '<tr><td>' + stamp(s.at) + '<small>' + esc(s.range) + '</small></td><td>' + esc(s.duration_s) + ' s</td><td>' +
        (s.status === 'completed' ? 'Terminé' : 'Interrompu') + (s.error ? '<small>' + esc(s.error) + '</small>' : '') + '</td><td>' + esc(s.hosts_count) + '</td><td>' + changes(s) + '</td></tr>').join('') + '</tbody></table></div>' : '<p>Aucun balayage conservé.</p>') +
    (discoveryHistory.next_before_id ? '<button data-disc-history-next="' + escAttr(discoveryHistory.next_before_id) + '">Balayages précédents</button>' : '');
}

async function discoveryHistoryLoad(before) {
  const target = $('#disc-history-panel');
  if (!target) return;
  try {
    const data = await api('/api/discovery/history' + (before ? '?before_id=' + encodeURIComponent(before) : ''));
    if (!target.isConnected) return;
    discoveryHistory = data; discoveryHistoryPaint();
  } catch (error) { if (target.isConnected) target.textContent = error.message; }
}

function discoverySelectTab(tab) {
  discoveryTab = tab;
  for (const name of ['scan', 'history']) {
    $('#disc-' + name + '-panel').hidden = name !== tab;
    $('#disc-tab-' + name).setAttribute('aria-selected', String(name === tab));
  }
  if (tab === 'history') discoveryHistoryLoad();
}

async function discoveryScan() {
  const error = hostAccessDialog.querySelector('.form-error');
  error.textContent = '';
  const range = $('#disc-range').value.trim();
  // Balayage actif : un IDS peut le signaler. Confirmation explicite (audit FE-08).
  if (!confirm('Lancer un balayage actif (ping et ports) de ' + range + ' ? Un IDS peut le signaler.')) return;
  try {
    await post('/api/discovery/scan', {range});
    discoveryPicked.clear();
    await discoveryLoad();
  } catch (e) { error.textContent = e.message; }
}

async function discoveryAdd() {
  const error = hostAccessDialog.querySelector('.form-error');
  if (!discoveryPicked.size) { error.textContent = 'Cocher au moins une machine nouvelle.'; return; }
  if (!confirm('Ajouter ' + discoveryPicked.size + ' machine(s) à l’inventaire ? Leurs empreintes SSH resteront à confirmer.')) return;
  try {
    const r = await post('/api/discovery/add', {ips: [...discoveryPicked], use_proxmox_names: discoveryUsePve});
    discoveryPicked.clear();
    hostKeyPending = null;
    await load();
    await discoveryLoad();
    $('#disc-result').insertAdjacentHTML('afterbegin', '<p class="instruction">' + r.added.length + ' serveur(s) ajouté(s). ' + esc(r.note || '') +
      '</p><button class="primary" type="button" data-hostkeys-open>Confirmer leurs empreintes SSH</button>');
  } catch (e) { error.textContent = e.message; }
}

renderHooks.push(function () {
  if (!state || selected || page !== 'Serveurs') return;
  const bar = document.querySelector('.host-access-bar');
  bar?.insertAdjacentHTML('beforeend', '<button type="button" data-discovery-open>Découvrir des serveurs</button>');
});
document.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b) return;
  if (b.hasAttribute('data-discovery-open')) { discoveryOpen(); return; }
  if (!b.closest('#host-access-dialog')) return;
  if (b.dataset.discTab) discoverySelectTab(b.dataset.discTab);
  else if (b.hasAttribute('data-disc-history-reload')) discoveryHistoryLoad();
  else if (b.dataset.discHistoryNext) discoveryHistoryLoad(b.dataset.discHistoryNext);
  else if (b.hasAttribute('data-disc-scan')) discoveryScan();
  else if (b.hasAttribute('data-disc-add')) discoveryAdd();
  else if (b.dataset.discFilter) { discoveryFilter = b.dataset.discFilter; discoveryPaint(); }
  else if (b.hasAttribute('data-disc-pickall')) {
    (discoveryData?.items || []).filter(i => i.status === 'new_ssh').forEach(i => discoveryPicked.add(i.ip));
    discoveryPaint();
  } else if (b.dataset.discOpen) { hostAccessDialog.close(); openHost(b.dataset.discOpen); }
});
hostAccessDialog.addEventListener('change', e => {
  if (e.target.id === 'disc-use-pve') discoveryUsePve = e.target.checked;
  if (e.target.matches('[data-disc-pick]')) {
    e.target.checked ? discoveryPicked.add(e.target.value) : discoveryPicked.delete(e.target.value);
    const add = hostAccessDialog.querySelector('[data-disc-add]');
    if (add) add.textContent = 'Ajouter aux serveurs (' + discoveryPicked.size + ')';
  }
});
hostAccessDialog.addEventListener('input', e => { if (e.target.id === 'disc-range') e.target.dataset.touched = '1'; });

hostAccessDialog.addEventListener('keydown', e => {
  if (!e.target.matches('[data-disc-tab]') || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
  e.preventDefault();
  const tab = e.key === 'Home' ? 'scan' : e.key === 'End' ? 'history' : discoveryTab === 'scan' ? 'history' : 'scan';
  discoverySelectTab(tab); $('#disc-tab-' + tab).focus();
});
