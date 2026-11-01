/**
 * Construction du DOM par objets, pas par chaînes HTML.
 *
 * Pourquoi ce choix plutôt que `innerHTML = '<td>' + esc(x) + '</td>'` :
 *
 *  1. Sûreté par construction : `textContent` n'interprète jamais de balise.
 *     Il n'y a plus de `esc()` à ne pas oublier — l'oubli devient impossible,
 *     là où le rendu par chaînes laisse une faille à chaque interpolation.
 *  2. Compatible avec la CSP stricte du serveur (`style-src 'self'`).
 *     Mesuré sur cette application : un `style="width:37.5%"` injecté via
 *     innerHTML est ignoré par le navigateur (largeur calculée « auto »),
 *     alors qu'un `node.style.setProperty('width','37.5%')` depuis un script
 *     déjà chargé s'applique normalement. Construire le DOM restitue donc le
 *     rendu exact des jauges, sans classes quantifiées .w0…w100.
 *  3. Mise à jour incrémentale possible : on garde une référence sur chaque
 *     nœud, donc on peut corriger une cellule sans détruire la ligne — ce qui
 *     préserve le focus clavier, la sélection de texte et la position de
 *     défilement pendant les rafraîchissements automatiques.
 */

/**
 * Crée un élément.
 * @param {string} tag
 * @param {object} props  class, dataset, aria-*, on* (écouteurs), attributs.
 * @param {...(Node|string|null|false|Array)} children
 *
 * Note volontaire : `props.style` n'est pas géré. Le style passe par des
 * classes ; les rares valeurs calculées passent par `setFill` ci-dessous.
 */
export function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  append(node, children);
  return node;
}

/** Ajoute des enfants en aplatissant les tableaux et en ignorant null/false. */
export function append(parent, children) {
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    parent.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return parent;
}

/** Largeur de remplissage d'une jauge, en pourcentage borné. */
export function setFill(node, value) {
  const n = Math.max(0, Math.min(100, Number(value) || 0));
  node.style.setProperty('width', `${n}%`);
}

/** Écrit du texte seulement s'il a changé : évite de casser une sélection en cours. */
export function setText(node, value) {
  const text = String(value);
  if (node.textContent !== text) node.textContent = text;
}

/** Idem pour une classe. */
export function setClass(node, value) {
  if (node.className !== value) node.className = value;
}

/**
 * Réconciliation d'une liste par clé stable.
 *
 * Réutilise les nœuds existants, crée ceux qui manquent, retire ceux qui sont
 * partis, puis remet tout le monde dans l'ordre demandé. C'est ce qui permet
 * un rafraîchissement toutes les 2 s sans reconstruire 84 lignes de tableau
 * — et donc sans perdre le focus ni la position de lecture de l'opérateur.
 *
 * @param {Element} parent
 * @param {Array} items
 * @param {(item:any)=>string} keyOf   identifiant stable d'un élément
 * @param {(item:any)=>{node:Element, update:(item:any)=>void}} create
 */
export function reconcile(parent, items, keyOf, create) {
  const previous = parent.__rows || new Map();
  const next = new Map();
  for (const item of items) {
    const key = keyOf(item);
    const row = previous.get(key) || create(item);
    row.update(item);
    next.set(key, row);
  }
  for (const [key, row] of previous) if (!next.has(key)) row.node.remove();
  // Remise en ordre : on ne touche au DOM que si la position a réellement changé.
  let cursor = null;
  for (const row of next.values()) {
    const expected = cursor ? cursor.nextSibling : parent.firstChild;
    if (expected !== row.node) parent.insertBefore(row.node, expected);
    cursor = row.node;
  }
  parent.__rows = next;
  return next;
}

/**
 * Délégation d'événements centralisée.
 *
 * Un seul écouteur par conteneur et par type, au lieu d'une pile d'écouteurs
 * anonymes ajoutés par des fichiers successifs : on peut lire toutes les
 * actions possibles d'une vue au même endroit, et le débogage cesse d'être
 * « lequel des dix-sept gestionnaires a répondu ? ».
 *
 * @param {Element} root
 * @param {string} type       'click', 'input', 'change', 'keydown'…
 * @param {Record<string, (event:Event, element:Element)=>void>} handlers
 *        clé = valeur de l'attribut data-action
 */
export function delegate(root, type, handlers) {
  root.addEventListener(type, (event) => {
    const element = event.target.closest('[data-action]');
    const handler = element && handlers[element.dataset.action];
    if (handler) handler(event, element);
  });
}

/** Vide un conteneur sans passer par innerHTML. */
export function clear(node) {
  while (node.firstChild) node.firstChild.remove();
  delete node.__rows;
  return node;
}
