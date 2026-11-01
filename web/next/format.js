/**
 * Formatage et vocabulaire d'affichage.
 *
 * Couche volontairement sans DOM ni état : testable isolément et réutilisable
 * par n'importe quelle vue. Tout ce qui est « comment on nomme les choses en
 * français » vit ici et nulle part ailleurs.
 */

/** Libellés métier des états : vocabulaire unique SEVERITY (web/app.js) quand l'interface
 *  est chargée ; mêmes mots en secours si ce module est utilisé seul (tests). */
const FALLBACK = { ok: 'OK', critical: 'Critique', warning: 'Majeur', unreachable: 'Injoignable', unknown: 'Inconnu' };
export const STATUS_LABELS = Object.fromEntries(Object.keys(FALLBACK).map(code =>
  [code, typeof SEVERITY !== 'undefined' && SEVERITY[code] ? SEVERITY[code].label : FALLBACK[code]]));

/** Ordre de tri par gravité : ce qui doit être traité en premier vient en premier. */
export const STATUS_RANK = { critical: 0, unreachable: 1, warning: 2, unknown: 3, ok: 4 };

/** Seuils d'alerte/critique par mesure. Alignés sur audit_engine.enrich (côté serveur). */
export const THRESHOLDS = { cpu: [90, 98], ram: [90, 97], disk_max: [80, 90] };

/** Au-delà de cette ancienneté, une mesure n'est plus présentée comme un état courant. */
export const STALE_AFTER_MS = 15 * 60 * 1000;

/** Pourcentage lisible, ou tiret si la mesure n'existe pas (jamais « 0 % » par défaut). */
export function pct(value) {
  return value == null || !Number.isFinite(Number(value)) ? '—' : `${value} %`;
}

/** Date absolue localisée, utilisée en info-bulle et pour les preuves d'audit. */
export function stamp(value) {
  return value ? new Date(value).toLocaleString('fr-FR') : 'Jamais collecté';
}

/** Date relative compacte, utilisée en colonne de tableau. */
export function relative(value) {
  if (!value) return 'Jamais';
  const minutes = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 60000));
  if (minutes < 1) return 'À l’instant';
  if (minutes < 60) return `Il y a ${minutes} min`;
  if (minutes < 1440) return `Il y a ${Math.floor(minutes / 60)} h`;
  return `Il y a ${Math.floor(minutes / 1440)} j`;
}

/**
 * Niveau d'une mesure au regard de ses seuils.
 * Renvoie null quand la valeur est absente : « non mesuré » n'est pas « normal ».
 */
export function metricLevel(key, value) {
  if (value == null || !Number.isFinite(Number(value))) return null;
  const [warn, crit] = THRESHOLDS[key] || THRESHOLDS.cpu;
  const n = Number(value);
  return n >= crit ? 'critical' : n >= warn ? 'warning' : 'normal';
}

/** Phrase lue par les lecteurs d'écran à la place de la barre graphique. */
export function metricAria(key, value) {
  const level = metricLevel(key, value);
  if (level === null) return 'Non mesuré';
  const suffix = { critical: 'seuil critique dépassé', warning: 'seuil d’alerte dépassé', normal: 'dans les limites' }[level];
  return `${value} %, ${suffix}`;
}
