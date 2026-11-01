from ssh import RunResult
BASE={
 'metrics':'cpu 100 0 100 800 0 0 0 0\ncpu 110 0 110 880 0 0 0 0\nMemTotal: 1000 kB\nMemAvailable: 600 kB',
 'df':'Filesystem Size Used Avail Use% Mounted on\n/dev/a 100G 20G 80G 20% /',
 'services':'cron.service loaded active running cron\nbackup.service loaded inactive dead backup\nnginx.service loaded active running nginx',
 'os':'PRETTY_NAME="Debian GNU/Linux 12"','uptime':'up 12 days',
 'identity':'Linux\nuid=1000(operator) gid=1000(operator)\n6.1.0',
 'inodes':'Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/a 10000 100 9900 1% /',
 'network':'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*',
 'timers':'NEXT LEFT LAST PASSED UNIT ACTIVATES\n1 timers listed.',
 'clock':'NTP=yes\nNTPSynchronized=yes','ssh_policy':'permitrootlogin prohibit-password\npasswordauthentication no',
 'permissions':'644 root /etc/passwd\n640 root /etc/shadow',
 'storage':'##MOUNTS\n/ /dev/sda1 ext4 rw,relatime\n##DF\nFilesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 104857600 20971520 83886080 20% /\n##INODES\nFilesystem Type Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 ext4 6553600 131072 6422528 2% /\n##REMOTE\n##LVM\nINDISPONIBLE\n##ZFS\nINDISPONIBLE\n##SMART\nsda|SMART overall-health self-assessment test result: PASSED\n##IO1\n   8 0 sda 10 0 200 5 8 0 160 4 0 1 9\n##CPU1\ncpu 100 0 50 800 20 0 0 0\n##IO2\n   8 0 sda 12 0 240 6 9 0 176 5 0 1 10\n##CPU2\ncpu 110 0 55 870 22 0 0 0\n##PROC\n    PID COMMAND %CPU %MEM\n   1 systemd 0.1 0.2\n##PORTS\nNetid State Recv-Q Send-Q Local Address:Port\ntcp LISTEN 0 128 0.0.0.0:22\n##FIREWALL\nStatus: active\n##FAIL2BAN\nINDISPONIBLE\n##SSHFAIL\n0',
 'errors':'-- No entries --','cron_user':'# test crontab\n0 1 * * * /usr/local/bin/backup',
 # Relevé des applications (onglet « Applications ») : sortie complète, du premier au dernier marqueur.
 'apps':'##OS\nDebian GNU/Linux 12 (bookworm)\n##RUNNING\nnginx.service\n##ENABLED\nnginx.service\n##PORTS\n0.0.0.0:22\n0.0.0.0:443\n'
        '##JAVA\n##NODE\n##PYTHON\n##PHP\n##DOCKER\nABSENT\n##SWARM\n##VHOSTS\n##VHOSTFILES\n##WEBAPPS\n##UNITFILES\n'
        '##INSTALL\nROOT|1700000000\n##PAQUETS\nKERNEL|6.1.0-25-amd64\ndpkg|nginx|1.22.1-9\n##DIRS\n/opt/app'
}
def runner(ip,op,cfg,requester):
 return RunResult(True,0,BASE[op],'',1)

