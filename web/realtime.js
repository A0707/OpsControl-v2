// Abonnement temps réel au flux /api/events (Server-Sent Events).
//
// Principe : le serveur ne pousse PAS les données, seulement le fait qu'elles
// ont changé. L'interface décide ensuite quoi recharger — c'est ce qui permet
// de garder un seul chemin de rendu, déjà éprouvé, au lieu d'en maintenir deux.
//
// Le sondage périodique d'app.js reste en place et sert de filet : si le flux
// n'est pas disponible (proxy qui coupe, serveur ancien, onglet restauré),
// l'interface continue de fonctionner exactement comme avant. Un temps réel qui
// tombe ne doit jamais laisser un écran figé sans que personne le sache.

let realtimeSource = null;
let realtimeConnected = false;

// Repli exponentiel borné : un serveur arrêté ne doit pas être bombardé de
// tentatives, mais un redémarrage doit être rattrapé en quelques secondes.
let realtimeBackoff = 1000;
const REALTIME_BACKOFF_MAX = 30000;
let realtimeLastState = null;

function realtimeStatus(connected) {
  realtimeConnected = connected;
  const cible = $('#progress');
  if (!cible) return;
  cible.dataset.realtime = connected ? 'on' : 'off';
  cible.title = connected
    ? 'Flux temps réel actif : les changements arrivent sans attendre.'
    : 'Flux temps réel indisponible — actualisation périodique de secours.';
}

// État « temps réel » UNIQUE, lu par la barre d'état et le bandeau de la voie rapide :
// ils divergeaient (pastille verte « Temps réel » à côté de « Temps réel interrompu »).
// Vivant = flux connecté ET dernière poussée de la voie rapide de moins de 15 s :
// un flux ouvert mais muet n'apporte plus de temps réel.
const REALTIME_SILENCE_MAX = 15;
function realtimeLive() {
  if (!realtimeConnected) return false;
  if (typeof t0LastPush === 'undefined') return true;
  return (Date.now() - t0LastPush) / 1000 < REALTIME_SILENCE_MAX;
}

function realtimeConnect() {
  // Reconnexion planifiée pendant que l'onglet était caché : on attend son retour
  // (visibilitychange rouvre le flux), au lieu de rouvrir un SSE invisible (audit FE-05).
  if (realtimeSource || typeof EventSource === 'undefined' || document.hidden) return;
  let source;
  try {
    source = new EventSource('/api/events');
  } catch {
    realtimeStatus(false);
    return;
  }
  realtimeSource = source;

  source.addEventListener('ready', () => {
    realtimeBackoff = 1000;
    realtimeStatus(true);
    loadAlerts(); // Also resynchronize after a disconnect or a hidden tab.
  });

  // Les ticks de progression mettent à jour le bandeau sans recharger le lourd
  // /api/overview. Une source ou un job terminé déclenche seulement la vue utile.
  source.addEventListener('state', event => {
    realtimeStatus(true);
    let current;
    try { current = JSON.parse(event.data); } catch {
      // Compatibilité avec un serveur ancien (ou un proxy qui retire data) :
      // conserver le signal immédiat des incidents, puis resynchroniser doucement.
      loadAlerts();scheduleLoad(250);return;
    }
    const previous = realtimeLastState;
    realtimeLastState = current;
    applyRealtimeState(current);
    // Premier message : la page vient de charger /api/overview, qui porte la révision des
    // sources. Comparer évite un second chargement complet au démarrage (audit UI du 31/10,
    // performances : overview, alertes, daily et briefing étaient relus ~5 s après l'ouverture).
    const known = previous ? previous.api_revision : state?.api_revision;
    const apiChanged = known === undefined || known === null || current.api_revision !== known;
    const completed = previous && ['ssh','network','api','batch'].some(name => previous[name]?.running && !current[name]?.running);
    if (apiChanged) {
      const provider = current.api_change?.provider;
      if (!selected && sourceLoaders[page]) {
        overviewDirty = true;
        if (!provider || provider === page) sourceLoaders[page]();
      } else scheduleLoad(250);
    } else if (completed) scheduleLoad(250);
    if (apiChanged || completed) loadAlerts();
  });

  // Voie rapide : ici le serveur pousse l'ÉTAT lui-même (serveurs critiques,
  // quelques Ko), pas un signal. critical.js l'affiche sans aucun rechargement.
  source.addEventListener('tier0', e => {
    realtimeStatus(true);
    try { window.dispatchEvent(new CustomEvent('infraops:tier0', { detail: JSON.parse(e.data) })); } catch { /* message illisible : ignoré */ }
  });

  source.onerror = () => {
    // EventSource se reconnecte seul, mais pas si le serveur a disparu : on
    // ferme et on replanifie nous-mêmes pour garder la main sur la cadence.
    source.close();
    if (realtimeSource === source) realtimeSource = null;
    realtimeStatus(false);
    setTimeout(realtimeConnect, realtimeBackoff);
    realtimeBackoff = Math.min(realtimeBackoff * 2, REALTIME_BACKOFF_MAX);
  };
}

// Le flux est inutile tant que personne ne regarde : on le coupe avec l'onglet,
// au même titre que la garde document.hidden de load().
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (realtimeSource) { realtimeSource.close(); realtimeSource = null; }
    realtimeStatus(false);
  } else {
    realtimeBackoff = 1000;
    realtimeConnect();
  }
});

if (!document.hidden) realtimeConnect();
