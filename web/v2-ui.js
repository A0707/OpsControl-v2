import { esc, escAttr } from '/frontend-utils.js?v=1bbce635';

// OpsControl V2 — composants d'interface partagés.
//
// Règles communes à tous les composants :
// - toute valeur est échappée (esc) ; aucun HTML fourni par une source n'est injecté ;
// - une valeur absente s'affiche « Non mesuré », jamais 0 ni une barre pleine ;
// - la CSP interdit les styles en ligne : les largeurs passent par des classes
//   quantifiées v2-w0…v2-w100 définies dans v2.css ;
// - la couleur suit une seule convention : vert = observé sain, orange =
//   avertissement, rouge = critique mesuré, gris = inconnu / ancien / non mesuré.
export function createUi({ freshnessMarkup }) {
  const TONES = {
    ok: 'ok', pass: 'ok', active: 'ok', online: 'ok', available: 'ok', green: 'ok', success: 'ok',
    info: 'info', observed: 'info', running: 'info',
    warning: 'warning', yellow: 'warning', degraded: 'warning',
    critical: 'critical', unreachable: 'critical', fail: 'critical', failed: 'critical',
    offline: 'critical', unavailable: 'critical', red: 'critical',
    unknown: 'unknown', stale: 'unknown', retained: 'unknown', inactive: 'unknown', pending: 'unknown'
  };
  const tone = s => TONES[s] || 'unknown';
  const clamp = n => Math.max(0, Math.min(100, Math.round(Number(n))));
  const measured = v => v != null && v !== '' && Number.isFinite(Number(v));
  const fmt = (v, digits = 1) => measured(v) ? Number(v).toLocaleString('fr-FR', { maximumFractionDigits: digits }) : 'Non mesuré';

  function pill(text, status = 'unknown', title = '') {
    return '<span class="v2-pill ' + tone(status) + '"' + (title ? ' title="' + escAttr(title) + '"' : '') + '><i aria-hidden="true"></i>' + esc(text) + '</span>';
  }

  function sourceTag(name, detail = '') {
    return '<span class="v2-source" title="Source de la donnée">' + esc(name) + (detail ? ' · ' + esc(detail) : '') + '</span>';
  }

  // Jauge horizontale : seuils [avertissement, critique] ; stale grise la jauge.
  function gauge(label, value, opts = {}) {
    const { detail = '', thresholds = [75, 90], hue = 'blue', stale = false, source = '' } = opts;
    const ok = measured(value), n = ok ? clamp(value) : 0;
    const severity = !ok ? 'none' : n >= thresholds[1] ? 'critical' : n >= thresholds[0] ? 'warning' : 'normal';
    const valueText = ok ? fmt(value) + ' %' : 'Non mesuré';
    return '<div class="v2-gauge hue-' + esc(hue) + ' sev-' + severity + (stale ? ' is-stale' : '') + '">' +
      '<div class="v2-gauge-head"><span>' + esc(label) + '</span><strong>' + esc(valueText) + '</strong></div>' +
      // Sans mesure, pas de rôle « meter » : il exige aria-valuenow (WCAG, relevé par axe-core).
      (ok ? '<div class="v2-track" role="meter" aria-label="' + escAttr(label) + '" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' + n + '">'
        : '<div class="v2-track" role="img" aria-label="' + escAttr(label) + ' : non mesuré">') + '<i class="v2-w' + n + '"></i></div>' +
      '<small>' + esc(detail || (ok ? '' : 'Aucune mesure disponible')) + (stale ? ' · mesure ancienne' : '') +
      (source ? ' · ' + esc(source) : '') + '</small></div>';
  }

  // Barre de répartition : segments {label, value, tone, attrs}. Les pourcentages
  // sont arrondis pour l'affichage seulement ; les nombres restent exacts.
  function stack(segments, opts = {}) {
    const total = segments.reduce((a, s) => a + (Number(s.value) || 0), 0);
    const bar = total ? segments.filter(s => s.value > 0).map(s =>
      '<i class="v2-seg ' + tone(s.tone) + ' v2-w' + clamp(s.value / total * 100) + '" title="' + escAttr(s.label + ' : ' + s.value) + '"></i>').join('') : '';
    const legend = segments.map(s => {
      const inner = '<i class="v2-dot ' + tone(s.tone) + '" aria-hidden="true"></i><span>' + esc(s.label) + '</span><b>' + esc(s.value) + '</b>';
      return s.attrs ? '<button class="v2-legend-item" ' + s.attrs + '>' + inner + '</button>' : '<span class="v2-legend-item">' + inner + '</span>';
    }).join('');
    return '<div class="v2-stack" role="img" aria-label="' + escAttr(opts.label || 'Répartition') + ' : ' +
      esc(segments.map(s => s.label + ' ' + s.value).join(', ')) + '">' + (bar || '<i class="v2-seg unknown v2-w100"></i>') + '</div>' +
      '<div class="v2-legend">' + legend + '</div>';
  }

  function kpi(label, value, note = '', status = '', attrs = '') {
    const tag = attrs ? 'button' : 'div';
    return '<' + tag + ' class="v2-kpi ' + (status ? tone(status) : '') + '" ' + attrs + '><span>' + esc(label) + '</span><strong>' +
      esc(value ?? 'Non mesuré') + '</strong>' + (note ? '<small>' + esc(note) + '</small>' : '') + '</' + tag + '>';
  }

  function empty(title, text = '', action = '') {
    return '<div class="v2-empty"><b>' + esc(title) + '</b>' + (text ? '<p>' + esc(text) + '</p>' : '') + action + '</div>';
  }

  function head(title, meta = '', actions = '', eyebrow = '') {
    return '<div class="v2-head"><div>' + (eyebrow ? '<span class="eyebrow">' + esc(eyebrow) + '</span>' : '') +
      '<h2>' + esc(title) + '</h2>' + (meta ? '<div class="v2-meta">' + meta + '</div>' : '') + '</div>' +
      (actions ? '<div class="v2-actions">' + actions + '</div>' : '') + '</div>';
  }

  // Âge d'une preuve : texte relatif mis à jour chaque seconde par freshness.js.
  const fresh = (value, label = 'Donnée', budget = 900) => freshnessMarkup(value, label, budget);

  function bytes(value) {
    if (!measured(value)) return 'Non mesuré';
    const units = ['o', 'Kio', 'Mio', 'Gio', 'Tio', 'Pio'];
    let v = Number(value), i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toLocaleString('fr-FR', { maximumFractionDigits: i < 3 ? 0 : 1 }) + ' ' + units[i];
  }

  function median(values) {
    if (!values.length) return null;
    const s = [...values].sort((a, b) => a - b), m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  return { tone, pill, sourceTag, gauge, stack, kpi, empty, head, fresh, bytes, fmt, measured, median, clamp };
}
