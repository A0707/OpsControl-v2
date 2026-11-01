// Vue Zabbix : hôtes supervisés et triggers actuellement en anomalie.
// Autonome comme wazuh.js : son propre helper de tableau, aucune dépendance
// envers les autres vues additionnelles.
subtitles.Zabbix = 'Hôtes supervisés et anomalies actives, collectés par l’API JSON-RPC.';

let zabbixSources = [], zabbixQuery = '', zabbixLevel='';

const zabbixHostLabels = { monitored: 'Supervisé', unmonitored: 'Non supervisé', unknown: 'Inconnu' };
const zabbixHostClasses = { monitored: 'ok', unmonitored: 'unknown', unknown: 'unknown' };

function zabbixBadge(status, stale) {
  return '<span class="badge ' + (stale ? 'unknown' : (zabbixHostClasses[status] || 'unknown')) + '">' +
    (stale ? 'Ancien · ' : '') + esc(zabbixHostLabels[status] || status) + '</span>';
}

function zabbixSeverity(problem, stale) {
  const cls = stale ? 'unknown' : problem.severity;
  return '<span class="badge ' + esc(cls) + '">' + esc(problem.severity_label) + '</span>';
}

function zabbixTable(headers, rows) {
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th>' + esc(h) + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + (c == null ? '—' : c) + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div>' + (rows.length ? '' : '<p class="note">Aucune ligne pour ces critères.</p>');
}

function zabbixMarkup() {
  const query = zabbixQuery.trim().toLowerCase();
  return zabbixSources.map(c => {
    const r = sourceResult(c), inv = r.inventory;
    const stale = !sourceFresh(r);
    let html = '<section class="panel"><div class="panel-head"><div><h2>' + esc(c.name) + '</h2>' +
      '<p>Source : ' + esc(c.url) + '</p></div>' +
      '<button class="primary" data-zbx-collect="' + escAttr(c.key) + '">Collecter cette instance</button></div>' +
      '<p>Dernière collecte : ' + stamp(r.collected_at) + (stale ? ' · À actualiser' : '') + '</p>';

    html += sourceStatus(c);
    if (r.error) html += '<p role="alert" class="instruction">' + esc(r.error) + '</p>';
    if (!inv) {
      return html + '<p>Aucun inventaire API disponible. Vérifier la connexion puis collecter /api_jsonrpc.php.</p>' +
        '<button data-go="Connexions API">Configurer la connexion</button></section>';
    }
    if (r.warning) html += '<p class="instruction">' + esc(r.warning) + '</p>';

    const counts = inv.counts || {}, problems = inv.problem_counts;
    html += '<div class="service-summary"><span>' + (inv.hosts_count || 0) + ' hôte(s) visible(s)</span>' +
      '<span>' + (counts.monitored || 0) + ' supervisé(s)</span>' +
      '<span>' + (counts.unmonitored || 0) + ' non supervisé(s)</span>' +
      (problems ? '<span>' + (problems.critical || 0) + ' anomalie(s) critique(s)</span>' +
        '<span>' + (problems.warning || 0) + ' avertissement(s)</span>' : '<span>Anomalies non collectées</span>') +
      '</div><p class="note">' + esc(inv.scope) + '</p></section>';

    // Anomalies d'abord : c'est ce qu'on vient chercher sur une page Zabbix.
    html += '<section class="panel"><h2>Anomalies actives' +
      (inv.problems ? ' (' + inv.problems.length + ')' : '') + '</h2>';
    if (!inv.problems) {
      html += '<p>' + esc(inv.problems_error || 'Anomalies non collectées.') + '</p>';
    } else {
      const visible = inv.problems.filter(p => (!zabbixLevel||p.severity===zabbixLevel) && (!query ||
        (p.description + ' ' + p.hosts.join(' ')).toLowerCase().includes(query)));
      // Ticket GLPI (web/itsm.js) : le serveur relit le trigger dans cette collecte. Le badge
      // du dossier existant est visible par tous ; le bouton reste réservé aux administrateurs.
      const glpi = roleAllows('admin');
      html += zabbixTable(['Gravité', 'Anomalie', 'Hôte(s) concerné(s)', 'GLPI'], visible.map(p => {
        const badge = typeof itsmBadge === 'function' ? itsmBadge('zabbix', c.key + '|' + p.triggerid, !stale) : '';
        return [zabbixSeverity(p, stale), esc(p.description), esc(p.hosts.join(' · ') || 'Non renseigné'),
          (badge + (glpi ? '<button data-itsm-origin="zabbix" data-itsm-id="' + escAttr(p.triggerid) + '" data-itsm-host="' + escAttr(c.key) + '">Ticket GLPI</button>' : '')) || null];
      })) +
        '<p class="note">' + esc(inv.problems_scope || '') + '</p>';
    }
    html += '</section>';

    const hosts = (inv.hosts || []).filter(h => !query ||
      (h.name + ' ' + h.host + ' ' + h.addresses.join(' ')).toLowerCase().includes(query));
    html += '<section class="panel"><h2>Hôtes supervisés</h2>' +
      zabbixTable(['Nom affiché', 'Nom technique', 'État', 'Adresse(s)', 'Serveur OpsControl'], hosts.map(h =>
        [esc(h.name), esc(h.host), zabbixBadge(h.status, stale), esc(h.addresses.join(' · ') || 'Non renseignée'), linkedServer([h.host,h.name,...h.addresses])])) +
      (inv.ignored ? '<p class="note">' + esc(inv.ignored) + ' entrée(s) ignorée(s) : format inattendu.</p>' : '') +
      '</section>';
    return html;
  }).join('') || '<section class="panel"><h2>Aucune connexion Zabbix configurée</h2>' +
    '<p>Ajouter une connexion vers https://VOTRE-ZABBIX/api_jsonrpc.php avec un jeton API en lecture.</p>' +
    '<button data-go="Connexions API">Ajouter une connexion API</button></section>';
}

async function loadZabbix() {
  const target = $('#zbx-data');
  if (!target) return;
  try {
    const sources = await api(sourceUrl('Zabbix'));
    if (!target.isConnected) return;
    zabbixSources = sources.filter(c => c.provider === 'Zabbix');
    const signature=JSON.stringify(zabbixSources)+String(zabbixSources.map(c=>sourceFresh(sourceResult(c))));if(target.dataset.signature!==signature){target.dataset.signature=signature;target.innerHTML=zabbixMarkup();}
  } catch (e) {
    if (target.isConnected) target.textContent = e.message;
  }
}

pageRenderers.Zabbix = function () {
  const focus=document.activeElement?.id==='zbx-search', cursor=document.activeElement?.selectionStart;
  $('#content').innerHTML = '<section class="panel"><div class="panel-head"><h2>Supervision Zabbix</h2>' +
    '<button data-go="Connexions API">Connexions API</button></div>' +
    '<label>Rechercher une anomalie ou un hôte <input id="zbx-search" value="' + escAttr(zabbixQuery) +
    '" placeholder="Ex. prdlabzbx01, disque, charge…"></label>' +
    '<p class="note">Requêtes JSON-RPC de lecture figées côté serveur (host.get, trigger.get) : ' +
    'aucune commande n’est construite depuis cette page, aucune action n’est exécutée sur Zabbix.</p></section>' +
    '<label>Gravité <select id="zbx-level"><option value="">Toutes</option><option value="critical">'+sevLabel('critical')+'</option><option value="warning">'+sevLabel('warning')+'</option><option value="unknown">Autres / non classées</option></select></label><div id="zbx-data">'+zabbixMarkup()+'</div>';
  $('#zbx-level').value=zabbixLevel;
  if(focus){$('#zbx-search').focus();$('#zbx-search').setSelectionRange(cursor,cursor);}
  loadZabbix();
};

$('#content').addEventListener('input', e => {
  if (e.target.id !== 'zbx-search') return;
  zabbixQuery = e.target.value;
  const total=zabbixSources.reduce((n,c)=>{const inv=sourceResult(c).inventory||{};return n+(inv.hosts||[]).length+(inv.problems||[]).length},0);
  deferLargeRender('zbx-search',total>100,()=>{const target=$('#zbx-data');if(target)target.innerHTML=zabbixMarkup()});
});

$('#content').addEventListener('click', async e => {
  const b = e.target.closest('[data-zbx-collect]');
  if (!b) return;
  b.disabled = true;
  b.textContent = 'Collecte…';
  try {
    await post('/api/connections/' + encodeURIComponent(b.dataset.zbxCollect) + '/collect');
    await loadZabbix();
  } catch (error) {
    $('#error').textContent = error.message;
  } finally {
    b.disabled = false;
    b.textContent = 'Collecter cette instance';
  }
});

$('#content').addEventListener('change',e=>{if(e.target.id==='zbx-level'){zabbixLevel=e.target.value;$('#zbx-data').innerHTML=zabbixMarkup();}});

// Enregistrement aupres du socle : app.js n'a pas a connaitre ce module.
sourceLoaders['Zabbix']=loadZabbix;
