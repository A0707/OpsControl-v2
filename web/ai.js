// Assistant local : aucune commande reçue du modèle n'est exécutable.
(() => {
  let token = '', controller = null, conversation = null;
  const turns = [];
  navGroups.push(['ASSISTANCE', [['Assistant IA', 'audit']]]);
  const headers = () => ({'X-Cockpit-Request': '1', 'Content-Type': 'application/json', 'X-OpsControl-AI-Token': token});
  async function request(path, options = {}) {
    const response = await fetch('/api/ai/' + path, {...options, headers: headers()});
    if (!response.ok) {
      const body = await response.json();
      const error = new Error(typeof body.detail === 'string' ? body.detail : 'Requête invalide');
      error.status = response.status;
      throw error;
    }
    return response;
  }
  function transcript() {
    const target = document.getElementById('ai-transcript');
    if (!target) return;
    target.replaceChildren();
    for (const turn of turns.slice(-40)) {
      const article = document.createElement('article');
      const title = document.createElement('h3');
      title.textContent = turn.role === 'user' ? 'Vous' : 'Assistant · ' + (turn.model || 'local');
      const pre = document.createElement('pre');
      pre.textContent = turn.text;
      article.append(title, pre);
      if (turn.role !== 'user') {
        const copy = document.createElement('button');
        copy.textContent = 'Copier la réponse / les commandes';
        copy.addEventListener('click', () => navigator.clipboard.writeText(turn.text).catch(() => notice('Copie indisponible dans ce navigateur.')));
        article.append(copy);
      }
      for (const source of turn.sources || []) {
        const link = document.createElement('button');
        link.textContent = source.path + ':' + source.line;
        link.addEventListener('click', async () => {
          try {
            const result = await (await request('document?path=' + encodeURIComponent(source.path) + '&line=' + source.line)).json();
            document.getElementById('ai-source').textContent = result.path + ':' + result.line + '\n' + result.text;
          } catch (error) { notice(error.message); }
        });
        article.append(link);
      }
      target.append(article);
    }
  }
  // Audit UI du 31/10 (fiches 18.1 et 18.2) : état indisponible explicite, destination et
  // traitement des données affichés avant tout envoi.
  function available(enabled, reason) {
    document.querySelectorAll('#ai-form input, #ai-form textarea, #ai-form select, #ai-form button, #ai-history, #ai-clear, #ai-new')
      .forEach(element => { element.disabled = !enabled; });
    const panel = document.getElementById('ai-unavailable');
    if (panel) {
      panel.hidden = enabled;
      panel.textContent = enabled ? '' : (reason || 'Assistant indisponible') + ' Activation par l’administrateur de l’instance ; aucune question ne peut être envoyée ni aucun historique chargé.';
    }
  }
  function policy(data) {
    const target = document.getElementById('ai-policy');
    if (!target || !data) return;
    target.textContent = 'Destination : ' + data.destination + ' (' + data.endpoint + ') · Envoyé : ' + data.sent + ' · ' + data.redaction + ' · Historique : ' + data.history + '.';
  }
  function notice(text) { const element = document.getElementById('ai-status'); if (element) element.textContent = text; }
  async function status() {
    try {
      const result = await (await request('status')).json();
      notice((result.connected ? 'LM Studio connecté · ' : 'LM Studio indisponible · ') + result.model + (result.available === false ? ' · modèle absent : le charger dans LM Studio' : '') + (result.detail ? ' · ' + result.detail : ''));
      const option = document.querySelector('#ai-mode option:last-child');
      if (option) option.disabled = !result.code_access;
      policy(result.data_policy);
      available(true);
    } catch (error) {
      notice(error.message);
      // Assistant désactivé côté serveur (503) : rien ne doit paraître utilisable (fiche 18.1).
      if (error.status === 503) available(false, error.message);
    }
  }
  beforeRenderHooks.push(() => { if (page !== 'Assistant IA') controller?.abort(); });
  pageRenderers['Assistant IA'] = () => {
    $('#content').innerHTML = `<section class="panel ai-panel"><h2>Assistant IA local</h2>
      <p>Diagnostic en lecture seule. Vérifiez les hypothèses et les commandes proposées. Les patchs s’appliquent uniquement depuis l’outil développeur local après validation.</p>
      <p id="ai-status" role="status" aria-live="polite">Vérification de LM Studio…</p>
      <p id="ai-unavailable" class="instruction" role="alert" hidden></p>
      <p id="ai-policy" class="note">Destination des données : vérification en cours.</p>
      <label>Jeton IA pour une session locale <input id="ai-token" type="password" autocomplete="off"></label>
      <button id="ai-connect">Vérifier la connexion</button><button id="ai-history">Charger mon historique</button><button id="ai-clear">Effacer mon historique</button><button id="ai-new">Nouvelle conversation</button>
      <div id="ai-transcript" aria-live="polite"></div>
      <form id="ai-form"><label>Mode <select id="ai-mode"><option>supervision</option><option>incidents</option><option>sécurité</option><option>développement</option></select></label>
      <label>Clé du serveur (facultatif) <input id="ai-host" maxlength="120"></label>
      <label>Clé de connexion API (facultatif : Zabbix, Wazuh, Proxmox, Elastic, Bacula) <input id="ai-source-key" maxlength="120"></label>
      <label>Observations ou logs filtrés <textarea id="ai-observation" maxlength="1800" rows="3"></textarea></label>
      <label>Votre question <textarea id="ai-message" required maxlength="1800" rows="4"></textarea></label>
      <button id="ai-send" class="primary" type="submit">Envoyer</button><button id="ai-stop" type="button">Interrompre</button></form>
      <pre id="ai-source" aria-label="Source documentaire"></pre></section>`;
    document.getElementById('ai-token').value = token;
    document.getElementById('ai-connect').onclick = () => { token = document.getElementById('ai-token').value; status(); };
    document.getElementById('ai-new').onclick = () => { controller?.abort(); conversation = null; turns.length = 0; transcript(); };
    document.getElementById('ai-stop').onclick = () => controller?.abort();
    document.getElementById('ai-history').onclick = async () => {
      try {
        const result = await (await request('history')).json();
        turns.length = 0;
        for (const turn of result.items) {
          turns.push({role: 'user', text: turn.question}, {role: 'assistant', text: turn.answer, sources: turn.sources});
        }
        conversation = result.items.at(-1)?.conversation || null;
        transcript();
      } catch (error) { notice(error.message); }
    };
    document.getElementById('ai-clear').onclick = async () => {
      if (!confirm('Effacer votre historique IA local ?')) return;
      try { await request('history/clear', {method: 'POST', body: '{}'}); turns.length = 0; conversation = null; transcript(); } catch (error) { notice(error.message); }
    };
    document.getElementById('ai-form').onsubmit = async event => {
      event.preventDefault();
      if (controller) return;
      token = document.getElementById('ai-token').value;
      const message = document.getElementById('ai-message').value.trim();
      if (!message) return;
      const body = {message, mode: document.getElementById('ai-mode').value, observation: document.getElementById('ai-observation').value, conversation, host_key: document.getElementById('ai-host').value.trim() || null, source_key: document.getElementById('ai-source-key').value.trim() || null, stream: true};
      controller = new AbortController();
      document.getElementById('ai-send').disabled = true;
      turns.push({role: 'user', text: message}); transcript(); notice('Génération en cours. La réponse sera affichée après filtrage des secrets.');
      try {
        const response = await request('chat', {method: 'POST', body: JSON.stringify(body), signal: controller.signal});
        const reader = response.body.getReader(), decoder = new TextDecoder();
        let buffer = '', received = false;
        for (;;) {
          const {done, value} = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, {stream: true});
          if (buffer.length > 100000) throw new Error('Réponse trop volumineuse');
          let split;
          while ((split = buffer.indexOf('\n\n')) >= 0) {
            const frame = buffer.slice(0, split); buffer = buffer.slice(split + 2);
            const data = frame.split('\n').find(line => line.startsWith('data: '));
            if (!data) continue;
            const result = JSON.parse(data.slice(6));
            if (frame.includes('event: error')) throw new Error(result.detail);
            conversation = result.conversation;
            turns.push({role: 'assistant', text: result.answer, sources: result.sources, model: result.model}); transcript(); received = true;
          }
        }
        notice(received ? 'Réponse terminée · sources consultables ci-dessus.' : 'Génération interrompue ou flux incomplet.');
      } catch (error) { notice(error.name === 'AbortError' ? 'Génération interrompue. Le worker se libère au prochain retour du modèle ou au timeout.' : error.message); }
      finally { controller = null; const button = document.getElementById('ai-send'); if (button) button.disabled = false; }
    };
    transcript(); status();
  };
})();
