function wafIpLocation(location) {
  if (location?.status === 'observed') return esc([location.country, location.city, location.asn, location.organization].filter(Boolean).join(' · '));
  return location?.status === 'private' ? 'Adresse non publique' : 'Localisation non mesurée';
}

function wafBanCsv(rows) {
  const cell = value => {
    let text = String(value ?? '');
    if (/^[\s]*[=+@-]|^[\t\r\n]/.test(text)) text = "'" + text;
    return '"' + text.replaceAll('"', '""') + '"';
  };
  const columns = ['IP','Verdict','Réseau','Pays','Ville','ASN','Organisation','Date du ban Fail2ban','Première observation','Dernière observation','Ban courant observé depuis','Rebannissements observés','Requêtes échantillonnées'];
  return '\ufeff' + [columns, ...rows.map(r => [r.ip,r.verdict,r.network,r.location?.country,r.location?.city,r.location?.asn,r.location?.organization,r.banned_at,r.first_observed,r.last_observed,r.current_observed_since,r.reban_count,r.requests])].map(row => row.map(cell).join(';')).join('\r\n');
}

document.addEventListener('click', e => {
  if (!e.target.closest('[data-waf-ban-export]') || !wafBanData) return;
  const url = URL.createObjectURL(new Blob([wafBanCsv(wafBanRows(wafBanData))], {type:'text/csv;charset=utf-8'}));
  const link = document.createElement('a'); link.href = url; link.download = 'ip-bannies.csv'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// Page WAF : IP bannies par Fail2ban, analysées (/api/waf/{clé}/bans, waf_bans.py).
//
// Verdict par IP (incohérent / à vérifier / maintenir) et sa justification, contexte réseau,
// activité observée dans les échantillons de journaux, date et échéance du ban. Les boutons
// « Vérifier » et « Débannir » préparent des commandes à COPIER : OpsControl n'exécute rien
// sur le WAF. Une IP à la fois, volontairement : pas de déblocage en masse.
const WAF_BAN_PAGE = 50;
const WAF_VERDICT = {incoherent: ['Incohérent', 'critical'], verify: ['À vérifier', 'warning'], keep: ['Maintenir', 'ok']};
let wafBanData = null, wafBanKey = '', wafBanAt = 0, wafBanLoading = false;
let wafBanRequest = 0, wafBanPendingKey = '';
let wafBanQuery = '', wafBanVerdict = '', wafBanKind = '', wafBanOffset = 0;

async function wafBanLoad(key) {
  if (wafBanLoading && wafBanPendingKey === key) return;
  const request = ++wafBanRequest;
  wafBanPendingKey = key;
  wafBanLoading = true;
  try {
    const data = await api('/api/waf/' + encodeURIComponent(key) + '/bans');
    if(request !== wafBanRequest)return;
    wafBanData = data;
    wafBanKey = key; wafBanAt = Date.now();
    wafBanPaint();
  } catch (e) {
    const target = document.getElementById('waf-ban-analysis');
    if (request === wafBanRequest && target?.dataset.key === key) target.innerHTML = '<h2>IP bannies · analyse</h2><p role="alert">' + esc(e.message) + '</p>';
  } finally {
    if(request === wafBanRequest)wafBanLoading = false;
  }
}

function wafBanRows(d) {
  const q = wafBanQuery.toLowerCase();
  return d.rows.filter(r => (!wafBanVerdict || r.verdict === wafBanVerdict) && (!wafBanKind || r.kind === wafBanKind) &&
    (!q || (r.ip + ' ' + r.network + ' ' + (r.inventory || '') + ' ' + r.modsec_rules.join(' ')).toLowerCase().includes(q)));
}

function wafBanWhen(r) {
  const observed = r.current_observed_since ? '<small>Ban observé depuis ' + stamp(r.current_observed_since) + '</small><small>Première observation : ' + stamp(r.first_observed) + '</small><small>Dernière observation : ' + stamp(r.last_observed) + ' · ' + esc(r.reban_count || 0) + ' rebannissement(s) observé(s)</small>' : '';
  if (!r.banned_at) return '<span class="mini">Date Fail2ban non disponible</span>' + observed;
  const permanent = r.duration_seconds === -1;
  return esc(r.banned_at) + '<small>' + (permanent ? 'Permanent' : 'Échéance ' + esc(r.expires_at)) + '</small>' + observed;
}

function wafBanBody(key) {
  const d = wafBanKey === key ? wafBanData : null;
  if (!d) return '<h2>IP bannies · analyse</h2><p class="note">Chargement de l’analyse des bans…</p>';
  const s = d.summary, c = d.coverage, rows = wafBanRows(d);
  if (wafBanOffset >= rows.length) wafBanOffset = 0;
  const page = rows.slice(wafBanOffset, wafBanOffset + WAF_BAN_PAGE);
  const card = (label, value, tone, verdict) => '<button class="card stat-card ' + tone + '" data-waf-ban-verdict="' + verdict + '"' +
    ' aria-pressed="' + (wafBanVerdict === verdict) + '"><span class="stat-dot"></span>' + label + '<strong>' + esc(value) + '</strong></button>';
  const kinds = [...new Set(d.rows.map(r => r.kind))].sort();
  const notes = [];
  if (!c.activity_known) notes.push('Activité non rapprochée des journaux : la dernière collecte précède cette analyse. Actualiser le WAF.');
  if (!c.ban_times) notes.push('Dates de ban non disponibles' + (c.ban_times_status === 'unknown'
    ? ' : « fail2ban-client get apache-modsecurity banip --with-time » refusé (sudoers, voir docs/SERVICE-ACCOUNT.md) ou Fail2ban < 0.11.'
    : ' : actualiser le WAF.'));
  if (c.clock) notes.push('Horodatages en ' + c.clock + '.');
  return '<div class="panel-head"><div><h2>IP bannies · analyse</h2><p class="mini">Jail apache-modsecurity · ' +
      (d.collected_at ? 'collecte du ' + stamp(d.collected_at) : 'aucune collecte') + (d.stale ? ' · PREUVES ANCIENNES' : '') + '</p></div><button type="button" data-waf-ban-export>Exporter la liste filtrée en CSV</button></div>' +
    '<div class="stats waf-ban-stats">' + card('Listées', s.listed + (s.currently_banned != null && s.currently_banned !== s.listed ? ' / ' + s.currently_banned : ''), 'info', '') +
      card('Incohérentes', s.incoherent, s.incoherent ? 'critical' : 'ok', 'incoherent') +
      card('À vérifier', s.verify, s.verify ? 'warning' : 'ok', 'verify') + card('Maintenir', s.keep, 'ok', 'keep') + '</div>' +
    // Liste plafonnée par la sonde : verdicts, campagnes et export portent sur un échantillon (audit WAF-06).
    (s.currently_banned != null && Number(s.currently_banned) > Number(s.listed)
      ? '<p class="instruction">Liste plafonnée : ' + esc(s.listed) + ' IP analysées sur ' + esc(s.currently_banned) +
        ' bannies. Verdicts, campagnes et export CSV portent sur cet échantillon.</p>' : '') +
    (s.campaigns.length ? '<p class="instruction">Réseaux concentrant des bans (campagne probable, ou robot d’indexation à traiter par règle plutôt qu’IP par IP) : ' +
      s.campaigns.map(x => '<button class="link" data-waf-ban-net="' + escAttr(x.network) + '">' + esc(x.network) + '</button> (' + esc(x.bans) + ')').join(' · ') + '</p>' : '') +
    (d.recommendations || []).map(r => '<p class="instruction"><b>' + esc(r.network) + '</b> · ' + esc(r.text) + (r.rule ? '<small>Règle proposée (texte) : ' + esc(r.rule) + '</small>' : '') + '</p>').join('') +
    '<details><summary>IP les plus actives dans l’échantillon d’accès</summary>' + (d.top_traffic || []).map(r => '<p>' + esc(r.ip) + ' · ' + esc(r.requests) + ' requêtes' + (r.sample_response_bytes != null ? ' · ' + esc(r.sample_response_bytes) + ' octets de réponse échantillonnés' : '') + ' · ' + wafIpLocation(r.location) + '</p>').join('') + '<p>Comptage WAF échantillonné ; octets issus de la fenêtre Apache, qui peut différer. Ni débit ni volume total. Localisation approximative.</p></details>' +
    '<div class="filters"><label>Rechercher <input id="waf-ban-q" type="search" maxlength="80" value="' + escAttr(wafBanQuery) +
      '" placeholder="IP, réseau, règle, serveur…"></label><label>Nature <select id="waf-ban-kind"><option value="">Toutes</option>' +
      kinds.map(k => '<option ' + (k === wafBanKind ? 'selected' : '') + '>' + esc(k) + '</option>').join('') + '</select></label>' +
      (wafBanVerdict || wafBanQuery || wafBanKind ? '<button type="button" data-waf-ban-reset>Effacer les filtres</button>' : '') + '</div>' +
    (page.length ? '<div class="table waf-table"><table><thead><tr><th>IP</th><th>Verdict</th><th>Nature · réseau</th><th>ModSecurity</th>' +
      '<th>Requêtes</th><th>Banni le</th><th>Commandes</th></tr></thead><tbody>' + page.map(r => {
        const [label, tone] = WAF_VERDICT[r.verdict];
        return '<tr><td class="ip">' + esc(r.ip) + (r.inventory ? '<small>' + esc(r.inventory) + '</small>' : '') + '</td>' +
          '<td><span class="badge ' + tone + '">● ' + esc(label) + '</span><small>' + r.reasons.map(esc).join('<br>') + '</small></td>' +
          '<td>' + esc(r.kind) + '<small>' + esc(r.network) + (r.network_bans > 1 ? ' · ' + esc(r.network_bans) + ' bannies' : '') + '</small></td>' +
          '<td>' + (r.modsec_lines ? esc(r.modsec_lines) + ' ligne(s)<small>' + esc(r.modsec_rules.join(', ')) + '</small>' : '—') + '</td>' +
          '<td>' + esc(r.requests || '—') + '</td><td>' + wafBanWhen(r) + '</td>' +
          '<td><button type="button" data-waf-ban-cmd="inspect" data-ip="' + escAttr(r.ip) + '">Vérifier</button> ' +
          '<button type="button" data-waf-ban-cmd="unban" data-ip="' + escAttr(r.ip) + '">Débannir</button></td></tr>';
      }).join('') + '</tbody></table></div>' +
      (rows.length > WAF_BAN_PAGE ? '<div class="table-foot"><span>' + (wafBanOffset + 1) + '–' + Math.min(wafBanOffset + WAF_BAN_PAGE, rows.length) +
        ' sur ' + rows.length + '</span><span><button type="button" data-waf-ban-page="-1"' + (wafBanOffset ? '' : ' disabled') + '>← Précédentes</button> ' +
        '<button type="button" data-waf-ban-page="1"' + (wafBanOffset + WAF_BAN_PAGE < rows.length ? '' : ' disabled') + '>Suivantes →</button></span></div>' : '')
      : '<p class="empty">' + (d.rows.length ? 'Aucune IP pour ces filtres.' : 'Aucune IP bannie dans la dernière collecte.') + '</p>') +
    notes.map(n => '<p class="note">' + esc(n) + '</p>').join('') +
    '<p class="note">Verdict indicatif, fondé sur les seules lectures du WAF (aucune requête externe ; localisation indicative issue d’une base CSV locale). « Vérifier » et « Débannir » ' +
    'préparent des commandes à copier : rien n’est exécuté depuis OpsControl.</p>';
}

function wafBanMarkup(key) {
  if (key !== wafBanKey || Date.now() - wafBanAt > 60000) wafBanLoad(key);
  return '<section class="panel" id="waf-ban-analysis" data-waf-section="actions" data-key="' + escAttr(key) + '">' + wafBanBody(key) + '</section>';
}

function wafBanPaint() {
  const target = document.getElementById('waf-ban-analysis');
  if (!target) return;
  const focused = document.activeElement?.id;
  target.innerHTML = wafBanBody(target.dataset.key);
  if (typeof wafEnhanceTables === 'function') wafEnhanceTables(target);  // libellés de colonnes pour l'affichage mobile
  if (focused === 'waf-ban-q') { const input = $('#waf-ban-q'); input?.focus(); input?.setSelectionRange(input.value.length, input.value.length); }
}

// Commandes préparées : dialogue existant (waf-controls.js), pré-rempli et soumis.
async function wafBanCommand(action, ip) {
  const key = document.getElementById('waf-ban-analysis')?.dataset.key;
  if (!key) return;
  openWafCommand(key);
  const form = document.getElementById('waf-command-form');
  form.querySelector('[name=ip]').value = ip;
  form.querySelector('[name=action]').value = action;
  form.requestSubmit();
}

document.addEventListener('click', e => {
  const zone = e.target.closest('#waf-ban-analysis');
  if (!zone) return;
  const cmd = e.target.closest('[data-waf-ban-cmd]');
  if (cmd) { wafBanCommand(cmd.dataset.wafBanCmd, cmd.dataset.ip); return; }
  const verdict = e.target.closest('[data-waf-ban-verdict]');
  if (verdict) { wafBanVerdict = wafBanVerdict === verdict.dataset.wafBanVerdict ? '' : verdict.dataset.wafBanVerdict; wafBanOffset = 0; wafBanPaint(); return; }
  const net = e.target.closest('[data-waf-ban-net]');
  if (net) { wafBanQuery = net.dataset.wafBanNet.replace(/\.0\/24$|::\/64$/, ''); wafBanOffset = 0; wafBanPaint(); return; }
  const page = e.target.closest('[data-waf-ban-page]');
  if (page) { wafBanOffset = Math.max(0, wafBanOffset + Number(page.dataset.wafBanPage) * WAF_BAN_PAGE); wafBanPaint(); return; }
  if (e.target.closest('[data-waf-ban-reset]')) { wafBanQuery = ''; wafBanVerdict = ''; wafBanKind = ''; wafBanOffset = 0; wafBanPaint(); }
});
document.addEventListener('input', e => {
  if (e.target.id === 'waf-ban-q') { wafBanQuery = e.target.value.trim(); wafBanOffset = 0; wafBanPaint(); }
});
document.addEventListener('change', e => {
  if (e.target.id === 'waf-ban-kind') { wafBanKind = e.target.value; wafBanOffset = 0; wafBanPaint(); }
});
