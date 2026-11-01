// Plan de correction consolidé d'un serveur (/api/security/hosts/<clé>/recommendations).
// Rendu commun à la fiche serveur (onglet Sécurité) et à la page Sécurité (Correctifs).
// Lecture seule : les commandes sont du TEXTE à copier, rien n'est exécuté.
const SEC_PLAN_TONE = {P1: 'critical', P2: 'warning', P3: 'info', P4: 'unknown'};
const SEC_PLAN_KIND = {packages: 'Paquets du système', upstream: 'Composant applicatif', verify: 'Vérification', os: 'Système',
  reboot: 'Redémarrage', pending: 'Mises à jour', images: 'Images Docker', audit: 'Audit SSH', coverage: 'Couverture'};
const SEC_PLAN_STEPS = [['precheck', 'Vérifications préalables (lecture seule)'], ['backup', 'Sauvegarde préalable'], ['apply', 'Correction proposée'],
  ['restart_steps', 'Prise en compte (services, redémarrage)'], ['verify', 'Vérifications après correction'], ['rollback', 'Retour arrière']];

function securityPlanMarkup(plan, {open = 1} = {}) {
  if (!plan) return '<p role="status">Chargement du plan de correction…</p>';
  const recs = plan.recommendations || [];
  const counts = plan.counts || {};
  const head = '<div class="sec-plan-summary"><p><b>' + esc(plan.summary) + '</b>' + (plan.exposed ? ' · ' + ui.pill('Exposé à Internet', 'critical', plan.exposed) : '') + '</p>' +
    '<p class="mini">' + ['P1', 'P2', 'P3', 'P4'].map(r => ui.pill(r + ' : ' + (counts[r] || 0), counts[r] ? SEC_PLAN_TONE[r] : 'unknown')).join(' ') + '</p>' +
    (recs.length ? '<button data-copy="' + escAttr(plan.text || '') + '">Copier le plan complet</button>' : '') + '</div>';
  return head + recs.map((r, i) => '<details class="sec-plan-item"' + (i < open ? ' open' : '') + ' data-sec-plan-kind="' + escAttr(r.kind) + '">' +
    '<summary>' + ui.pill(r.priority + ' · ' + r.priority_label, SEC_PLAN_TONE[r.priority] || 'unknown') + ' <b>' + esc(r.order + '. ' + r.title) + '</b>' +
    ' <small>' + esc(SEC_PLAN_KIND[r.kind] || r.kind) + (r.cves.length ? ' · ' + r.cves.length + ' CVE' : '') + '</small></summary>' +
    '<ul>' + r.why.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul>' +
    (r.cves.length ? '<p class="mini">CVE : ' + esc(r.cves.slice(0, 20).join(', ') + (r.cves.length > 20 ? ' …' : '')) + '</p>' : '') +
    (r.impact ? '<p class="note">Impact : ' + esc(r.impact) + '</p>' : '') +
    (r.requires_adaptation ? '<p class="form-error">Commande à adapter au contexte avant usage.</p>' : '') +
    SEC_PLAN_STEPS.filter(([k]) => (r[k] || []).length).map(([k, t]) => command(t, r[k].join('\n'))).join('') + '</details>').join('') +
    '<p class="v2-formula">' + esc(plan.generated_from || '') + '</p>';
}
