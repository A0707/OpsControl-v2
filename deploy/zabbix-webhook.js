// Type de média Zabbix « InfraOps » — script du webhook (Administration →
// Types de média → Créer → Type : Webhook). Collez ce script dans « Script ».
//
// Paramètres du type de média (nom = valeur) :
//   url        = https://infraops.example.test/api/webhooks/zabbix
//   token      = <valeur de INFRAOPS_WEBHOOK_TOKEN sur le serveur InfraOps>
//   eventid    = {EVENT.ID}
//   status     = {EVENT.STATUS}
//   host       = {HOST.NAME}
//   host_ip    = {HOST.IP}
//   trigger    = {EVENT.NAME}
//   severity   = {EVENT.SEVERITY}
//   event_time = {EVENT.DATE} {EVENT.TIME}
//
// Lecture seule côté InfraOps : l'événement est affiché, jamais exécuté.
var params = JSON.parse(value);
var request = new HttpRequest();
request.addHeader('Content-Type: application/json');
request.addHeader('Authorization: Bearer ' + params.token);
var body = JSON.stringify({
  eventid: params.eventid,
  status: params.status,
  host: params.host,
  host_ip: params.host_ip,
  trigger: params.trigger,
  severity: params.severity,
  event_time: params.event_time
});
var response = request.post(params.url, body);
if (request.getStatus() !== 202) {
  throw 'InfraOps a répondu ' + request.getStatus() + ' : ' + response;
}
return 'OK';
