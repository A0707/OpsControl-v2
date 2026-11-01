// Sélecteur « Audit SSH » : réaudit périodique en rotation (ssh_refresh.py).
// Distinct de « Actualisation » (réseau, API, Zabbix) : un audit SSH complet
// ouvre une quinzaine de connexions par serveur, c'est un choix à part.
(function () {
  const control = document.querySelector('.control');
  if (!control) return;
  const label = document.createElement('label');
  label.title = 'Réaudit SSH en rotation : quelques serveurs par minute, les plus anciens d’abord. ' +
    'Serveurs critiques au plus toutes les 5 min, injoignables au plus toutes les 30 min.';
  label.innerHTML = 'Audit SSH <select id="ssh-interval"><option value="0">Manuel</option>' +
    '<option value="600">Toutes les 10 min</option><option value="1800">Toutes les 30 min</option>' +
    '<option value="3600">Toutes les heures</option></select>';
  control.appendChild(label);
  const select = label.querySelector('select');

  async function charger() {
    try {
      const etat = await api('/api/ssh-refresh');
      select.value = String(etat.interval);
      label.dataset.last = etat.last_launch ? 'Dernier lot : ' + etat.last_count + ' serveur(s), ' + stamp(etat.last_launch) : '';
      label.title = label.title.split(' · ')[0] + (label.dataset.last ? ' · ' + label.dataset.last : '');
    } catch (e) { /* serveur ancien sans ce réglage : le sélecteur reste sur Manuel */ }
  }

  select.addEventListener('change', async () => {
    try {
      await post('/api/ssh-refresh', { interval: Number(select.value) });
      toast(Number(select.value) ? 'Réaudit SSH en rotation activé.' : 'Réaudit SSH repassé en manuel.');
      charger();
    } catch (error) {
      $('#error').textContent = error.message;
    }
  });

  charger();
  poll('reaudit-ssh-reglage', 60000, charger);
})();
