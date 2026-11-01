// Les constats détaillés sont lourds et ne servent qu'aux vues Problèmes et
// Sécurité. Ils restent hors de /api/overview et sont chargés à la demande.
let findingsComplets = null, findingsCharges = 0, findingsEnCours = false;

async function chargerFindingsComplets() {
  if (findingsEnCours) return;
  findingsEnCours = true;
  try {
    findingsComplets = await api('/api/findings');
    findingsCharges = Date.now();
    if (['Problèmes', 'Sécurité'].includes(page) && !selected) render();
  } catch (e) {
    $('#error').textContent = e.message;
  } finally {
    findingsEnCours = false;
  }
}

beforeRenderHooks.push(function () {
  const needs = ['Problèmes', 'Sécurité'].includes(page) && !selected;
  if (needs && (!findingsComplets || Date.now() - findingsCharges > 60000)) chargerFindingsComplets();
  if (needs && findingsComplets) {
    (state?.hosts || []).forEach(h => { h.findings = findingsComplets[h.key] || []; });
  }
});
