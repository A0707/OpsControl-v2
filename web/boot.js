// Démarrage synchrone, avant les feuilles de style (audit UI transversal du 01/11) :
// thème, densité et route sont posés AVANT le premier rendu. Appliqués plus tard par
// app.js et v2.js, ils faisaient basculer le thème (sombre puis clair) et décaler toute
// la mise en page (CLS ~1 sur l'accueil). Fichier externe : la CSP interdit le script en ligne.
(function () {
  var root = document.documentElement, prefs = {}, theme = null;
  try { theme = localStorage.getItem('infraops-theme'); } catch (e) { /* stockage indisponible */ }
  try { prefs = JSON.parse(localStorage.getItem('opscontrol-v2-prefs') || '{}') || {}; } catch (e) { prefs = {}; }
  if (theme !== 'light' && theme !== 'dark') {
    theme = window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  root.dataset.theme = theme;
  root.dataset.ui = 'v2';
  // Apparence premium (premium.css) : essai par poste, la V2 reste le défaut de production.
  if (prefs.look === 'premium') root.dataset.look = 'premium';
  root.dataset.density = prefs.density === 'compact' ? 'compact' : 'comfortable';
  root.dataset.display = prefs.noc === true ? 'noc' : 'standard';
  var hash = '';
  try { hash = decodeURIComponent(location.hash.replace(/^#\/?/, '')); } catch (e) { hash = ''; }
  // Accueil : URL sans route ou route « Vue globale ». La zone principale reste invisible
  // jusqu'au premier rendu de la synthèse (data-home-ready), qui l'affiche d'un seul coup.
  root.dataset.route = !hash || hash === 'Vue globale' ? 'home' : 'page';
  // Filet de sécurité : zone principale affichée au plus tard après 4 s, même si un script
  // ou une donnée manque (elle n'est jamais laissée invisible).
  setTimeout(function () { root.dataset.shellReady = '1'; root.dataset.homeReady = '1'; }, 4000);
}());
