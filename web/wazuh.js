// Vue Wazuh : démons du manager, agents et identité, à partir de la collecte API.
// Volontairement autonome (son propre helper de tableau) : aucune dépendance
// envers waf.js ou proxmox.js, donc aucun ordre de chargement à respecter
// entre cette page et les autres vues additionnelles.
subtitles.Wazuh = 'Manager Wazuh : démons, agents déclarés et version, collectés par API.';

let wazuhSources = [], wazuhQuery='';

const wazuhDaemonLabels = { running: 'En cours', stopped: 'Arrêté', failed: 'En échec', unknown: 'Inconnu' };
const wazuhDaemonClasses = { running: 'ok', stopped: 'unknown', failed: 'critical', unknown: 'unknown' };
const wazuhAgentClasses = { active: 'ok', disconnected: 'critical', never_connected: 'warning', pending: 'unknown' };

function wazuhBadge(status, stale) {
  const cls = stale ? 'unknown' : (wazuhDaemonClasses[status] || 'unknown');
  return '<span class="badge ' + cls + '">' + (stale ? 'Ancien · ' : '') + esc(wazuhDaemonLabels[status] || status) + '</span>';
}

function wazuhTable(headers, rows) {
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th>' + esc(h) + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + (c == null ? '—' : c) + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div>' + (rows.length ? '' : '<p class="note">Aucune donnée dans la collecte disponible.</p>');
}

function wazuhMarkup() {
  return wazuhSources.map(c => {
    const r = sourceResult(c), inv = r.inventory;
    // Même seuil de fraîcheur que le reste de la plateforme (15 minutes).
    const stale = !sourceFresh(r);
    let html = '<section class="panel"><div class="panel-head"><div><h2>' + esc(c.name) + '</h2>' +
      '<p>Source : ' + esc(c.url) + '</p></div>' +
      '<button class="primary" data-wazuh-collect="' + escAttr(c.key) + '">Collecter ce manager</button></div>' +
      '<p>Dernière collecte : ' + stamp(r.collected_at) + (stale ? ' · À actualiser' : '') + '</p>';

    html += sourceStatus(c);
    if (r.error) html += '<p role="alert" class="instruction">' + esc(r.error) + '</p>';
    if (!inv) {
      return html + '<p>Aucun inventaire API disponible. Vérifier la connexion puis collecter /manager/status.</p>' +
        '<button data-go="Connexions API">Configurer la connexion</button></section>';
    }

    const counts = inv.counts || {};
    html += '<div class="service-summary"><span>' + (counts.running || 0) + ' démon(s) en cours</span>' +
      '<span>' + (counts.stopped || 0) + ' arrêté(s)</span>' +
      '<span>' + (counts.failed || 0) + ' en échec</span>' +
      '<span>' + (counts.unknown || 0) + ' état inconnu</span></div>' +
      '<p class="note">' + esc(inv.scope) + '</p>';

    if (inv.manager && inv.manager.version) {
      html += '<p>Version du manager : <b>' + esc(inv.manager.version) + '</b>' +
        (inv.manager.max_agents ? ' · Capacité déclarée : ' + esc(inv.manager.max_agents) + ' agents' : '') + '</p>';
    }
    // Un échec de source secondaire est signalé, jamais masqué derrière un zéro.
    if (r.secondary_errors) {
      html += Object.entries(r.secondary_errors)
        .map(([name, message]) => '<p class="note">Source « ' + esc(name) + ' » indisponible : ' + esc(message) + '</p>').join('');
    }
    html += '</section>';

    html += '<section class="panel"><h2>Agents déclarés</h2>';
    if (!inv.agents) {
      html += '<p>Répartition des agents non collectée. Le compte API doit pouvoir lire /agents/summary/status.</p>';
    } else {
      html += '<div class="stats">' + inv.agents.states.map(s =>
        '<div class="card ' + (stale ? '' : (wazuhAgentClasses[s.key] || '')) + '"><small>' + esc(s.label) + '</small>' +
        '<strong>' + (s.count == null ? 'Non mesuré' : esc(s.count)) + '</strong></div>').join('') +
        '<div class="card"><small>Total déclaré</small><strong>' +
        (inv.agents.total == null ? 'Non mesuré' : esc(inv.agents.total)) + '</strong></div></div>' +
        '<p class="note">' + esc(inv.agents.scope) + '</p>';
    }
    html += '</section>';

    html += '<section class="panel"><h2>Démons du manager (' + (inv.daemons_count || 0) + ')</h2>' +
      wazuhTable(['Démon', 'État'], (inv.daemons || []).filter(d=>!wazuhQuery||d.name.toLowerCase().includes(wazuhQuery.toLowerCase())).map(d => [esc(d.name), wazuhBadge(d.status, stale)])) +
      '<p class="note">Un démon arrêté peut être désactivé volontairement. Confirmer les fonctions attendues avant de conclure à une panne. Un démon « en cours » ne prouve ni ' +
      'l’ingestion des événements ni la fraîcheur des règles.</p></section>';
    return html;
  }).join('') || '<section class="panel"><h2>Aucune connexion Wazuh configurée</h2>' +
    '<p>Ajouter une connexion vers /manager/status avec un compte de lecture.</p>' +
    '<button data-go="Connexions API">Ajouter une connexion API</button></section>';
}

async function loadWazuh() {
  const target = $('#wazuh-data');
  if (!target) return;
  try {
    const sources = await api(sourceUrl('Wazuh'));
    if (!target.isConnected) return;
    wazuhSources = sources.filter(c => c.provider === 'Wazuh');
    const signature=JSON.stringify(wazuhSources)+String(wazuhSources.map(c=>sourceFresh(sourceResult(c))));if(target.dataset.signature!==signature){target.dataset.signature=signature;target.innerHTML=wazuhMarkup();}
  } catch (e) {
    if (target.isConnected) target.textContent = e.message;
  }
}

pageRenderers.Wazuh = function () {
  const focus=document.activeElement?.id==='wazuh-search', cursor=document.activeElement?.selectionStart;
  $('#content').innerHTML = '<section class="panel"><div class="panel-head"><h2>Manager, agents et démons</h2>' +
    '<button data-go="Connexions API">Connexions API</button></div>' +
    '<p class="note">Collecte en lecture seule via l’API Wazuh. Le jeton est ré-obtenu à chaque collecte ; ' +
    'aucune règle, aucun agent et aucune configuration ne sont modifiés depuis ce cockpit.</p></section>' +
    '<label>Rechercher un démon <input id="wazuh-search" type="search" value="'+escAttr(wazuhQuery)+'"></label><div id="wazuh-data">'+wazuhMarkup()+'</div>';
  if(focus){$('#wazuh-search').focus();$('#wazuh-search').setSelectionRange(cursor,cursor);}
  loadWazuh();
};

$('#content').addEventListener('click', async e => {
  const b = e.target.closest('[data-wazuh-collect]');
  if (!b) return;
  b.disabled = true;
  b.textContent = 'Collecte…';
  try {
    await post('/api/connections/' + encodeURIComponent(b.dataset.wazuhCollect) + '/collect');
    await loadWazuh();
  } catch (error) {
    $('#error').textContent = error.message;
  } finally {
    b.disabled = false;
    b.textContent = 'Collecter ce manager';
  }
});

$('#content').addEventListener('input',e=>{if(e.target.id==='wazuh-search'){wazuhQuery=e.target.value;const total=wazuhSources.reduce((n,c)=>{const inv=sourceResult(c).inventory||{};return n+(inv.daemons||[]).length+(inv.agents_inventory||[]).length},0);deferLargeRender('wazuh-search',total>100,()=>{const target=$('#wazuh-data');if(target)target.innerHTML=wazuhMarkup()})}});

// Enregistrement aupres du socle : app.js n'a pas a connaitre ce module.
sourceLoaders['Wazuh']=loadWazuh;
