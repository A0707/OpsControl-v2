{-120m} [:error] [pid 2101:tid 1401] [client 198.51.100.4:52345] [client 198.51.100.4] ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 10)"] [hostname "shop.example.test"] [uri "/login"] [unique_id "M1"]
{-25m} [:notice] [pid 900] ModSecurity for Apache/2.9.7 (http://www.modsecurity.org/) configured.
{-25m} [:notice] [pid 900] ModSecurity: APR compiled version="1.7.2"; loaded version="1.7.2"
{-10m} [:error] [pid 2101:tid 1402] [client 198.51.100.9:52346] [client 198.51.100.9] ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 15)"] [hostname "192.0.2.10"] [uri "/"] [unique_id "M2"]
{-5m} [mpm_event:error] [pid 900:tid 1] AH03490: scoreboard is full, not at MaxRequestWorkers.Increase ServerLimit.
