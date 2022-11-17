# Solution du CTF Who Wants To Be King: 2 de VulnHub

Après avoir solutionné [Who Wants To Be King: 1](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Who%20Wants%20To%20Be%20King%3A%201.md), je me suis penché sur le second opus histoire de voir s'il était aussi mauvais ou non que le premier. C'est par pure curiosité scientifique. je dirais même que je suis dans une approche éthologique humaine.

```
Nmap scan report for 192.168.56.58
Host is up (0.00022s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD
80/tcp   open  http        Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1h PHP/7.2.34 mod_perl/2.0.11 Perl/v5.32.0)
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.56.58/dashboard/
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1h PHP/7.2.34 mod_perl/2.0.11 Perl/v5.32.0
139/tcp  open  netbios-ssn Samba smbd 4.6.2
443/tcp  open  ssl/http    Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1h PHP/7.2.34 mod_perl/2.0.11 Perl/v5.32.0)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1h PHP/7.2.34 mod_perl/2.0.11 Perl/v5.32.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2004-10-01T09:10:30
|_Not valid after:  2010-09-30T09:10:30
| http-title: Welcome to XAMPP
|_Requested resource was https://192.168.56.58/dashboard/
445/tcp  open  netbios-ssn Samba smbd 4.6.2
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.56.1' is not allowed to connect to this MariaDB server
```

## Humour brésilien

D'expérience, les scanners ont parfois du mal à dialoguer avec SMB. Rien de mieux que d'utiliser  ce vieux  briscard de `smbclient` :

```shellsession
$ smbclient -U "" -N -L //192.168.56.58

        Sharename       Type      Comment
        ---------       ----      -------
        liteshare       Disk      
        IPC$            IPC       IPC Service (Linux Lite Shares)
SMB1 disabled -- no workgroup available
```

Le partage en question est inacessible mais on sait au moins qu'il y en a un.

Quand on accéde au port 80 on est directement redirigé sur une instance de XAMPP :

> **Welcome to XAMPP for Linux 7.2.34**

7.2.34 semble être la version de PHP qu'on retrouve dans le phpinfo disponible. On retient que le document root est `/opt/lampp/htdocs`.

Le fichier de log est à un emplacement que je n'aurais pas trouvé sans le phpinfo : `/opt/lampp/logs/php_error_log`.

Devant le manque d'informations supplémentaires, je lance `feroxbuster` qui trouve un blog Wordpress :

```shellsession
$ feroxbuster -u http://192.168.56.58/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.58/
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
301        7l       20w      239c http://192.168.56.58/webalizer
403       45l      115w        0c http://192.168.56.58/phpmyadmin
301        7l       20w      239c http://192.168.56.58/wordpress
301        7l       20w      239c http://192.168.56.58/dashboard
301        7l       20w      233c http://192.168.56.58/img
302        0l        0w        0c http://192.168.56.58/
[####################] - 48s    62260/62260   0s      found:6       errors:0      
[####################] - 47s    62260/62260   1303/s  http://192.168.56.58/
```

L'URL `/wordpress` redirige vers `http://armbjorn/wordpress/`. Il faut donc rajouter une entrée au `/etc/hosts`.

On peux aussi lancer `wpscan` dessus. Attention à là aussi passer l'option pour la correspondance de l'hôte :

```bash
docker run --add-host armbjorn:192.168.56.58 -it --rm wpscanteam/wpscan --url http://armbjorn/wordpress/ -e ap,at,cb,dbe --plugins-detection aggress
```

```
[+] WordPress theme in use: twentytwenty
 | Location: http://armbjorn/wordpress/wp-content/themes/twentytwenty/
 | Latest Version: 2.1 (up to date)
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Style URL: http://armbjorn/wordpress/wp-content/themes/twentytwenty/style.css
 | Style Name: are you ok? armbjorn
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: "aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj11RXQ1bFlYd1QtVQo="...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
```

```
[+] akismet
 | Location: http://armbjorn/wordpress/wp-content/plugins/akismet/
 | Latest Version: 5.0.1
 | Last Updated: 2022-11-08T05:36:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/akismet/, status: 403
 |
 | The version could not be determined.

[+] meta-generator-and-version-info-remover
 | Location: http://armbjorn/wordpress/wp-content/plugins/meta-generator-and-version-info-remover/
 | Last Updated: 2022-06-12T04:01:00.000Z
 | Readme: http://armbjorn/wordpress/wp-content/plugins/meta-generator-and-version-info-remover/readme.txt
 | [!] The version is out of date, the latest version is 15.0
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/meta-generator-and-version-info-remover/, status: 200
 |
 | Version: 11.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/meta-generator-and-version-info-remover/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/meta-generator-and-version-info-remover/readme.txt

[+] stop-user-enumeration
 | Location: http://armbjorn/wordpress/wp-content/plugins/stop-user-enumeration/
 | Last Updated: 2022-11-14T22:13:00.000Z
 | Readme: http://armbjorn/wordpress/wp-content/plugins/stop-user-enumeration/readme.txt
 | [!] The version is out of date, the latest version is 1.4.5
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/stop-user-enumeration/, status: 200
 |
 | Version: 1.3.29 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/stop-user-enumeration/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/stop-user-enumeration/readme.txt

[+] wps-limit-login
 | Location: http://armbjorn/wordpress/wp-content/plugins/wps-limit-login/
 | Last Updated: 2022-05-25T13:10:00.000Z
 | Readme: http://armbjorn/wordpress/wp-content/plugins/wps-limit-login/readme.txt
 | [!] The version is out of date, the latest version is 1.5.6
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/wps-limit-login/, status: 200
 |
 | Version: 1.5 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/wps-limit-login/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://armbjorn/wordpress/wp-content/plugins/wps-limit-login/readme.txt
```

On peut voir que l'auteur a rajouté quelques plugins de sécurité pour rendre impossible les attaques brute force.

Il a aussi édité le `readme` du thème par défaut (`twentytwenty`) pour que certains indices apparaissent lors du scan.

Ici l'indice est `spiderman` qui est le nom d'un dossier à l'adresse `/wordpress/spiderman`. On l'aurait aussi trouvé via une énumération web.

A cette adresse se trouve un fichier baptisé secret qui est en réalité une archive ZIP contenant 3 images, toutes des meme en rapport avec le comic book Spiderman (à priori piochés sur [@_spidermemes](https://twitter.com/_spidermemes)).

```shellsession
$ file secret
secret: Zip archive data, at least v2.0 to extract, compression method=deflate
$ unzip -l secret
Archive:  secret
  Length      Date    Time    Name
---------  ---------- -----   ----
    58188  2020-12-12 09:52   5212ed22df5f1.jpeg
    13701  2020-12-12 09:53   5269255c8fa23.jpeg
    58521  2020-12-12 11:04   541b1217c0c16.jpeg
---------                     -------
   130410                     3 files
```

L'une de ces images contient des métadonnées :

```
ExifTool Version Number         : 12.45
File Name                       : 541b1217c0c16.jpeg
Directory                       : .
File Size                       : 59 kB
File Modification Date/Time     : 2020:12:12 11:04:31+01:00
File Access Date/Time           : 2022:11:17 09:36:34+01:00
File Inode Change Date/Time     : 2022:11:17 09:36:07+01:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
Make                            : armbjorn - spiderman is sexy?
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Current IPTC Digest             : 392a623de95c8b4c5139d474a9e4d524
Source                          : uwer89j
Image Width                     : 478
Image Height                    : 360
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 478x360
Megapixels                      : 0.172
```

On pourrait imaginer que `uwer89j` est une métadonnée provenant réellement de l'image originale. En revanche aucun doute que celle préfixée du nom de l'auteur du CTF est custom.

En toute logique les identifiants `armjborn` / `spiderman is sexy?` devraient être acceptés sur l'interface d'administration du `Wordpress`.... mais ce n'est pas le cas.

## Joint de culasse

On passe donc directement en mode sous le capot en modifiant l'entrée GRUB au boot de la VM pour lancer un bash root.

Déjà il n'y a pas d'utilisateur Unix nommé `armbjorn`. Juste un utilisateur nommé `osboxes`.

A l'aide des identifiants MySQL choppés dans le fichier de configuration du Wordpress je peux accèder à la table `wp_users` et obtenir le hash de `armbjorn` : `$P$BYh0g8tGfkHg2LR6QxbgHkCTnica3.0`.

Le hash ne tombe pas avec ce qu'on a trouvé jusqu'à présent. L'utilisateur de RockYou ne semble aboutit nul part non plus.

Mais admettons que l'on soit parvenu à récupérer un accès au Wordpress, éditer un fichier PHP du thème présent puis obtenir un web shell.

On aurait alors noté la présence de deux fichiers lisibles dans le dossier de `osboxes` :

```
-rw-rw-r--  1 osboxes osboxes 72239 Dec  8  2020 dict.txt
-rw-rw-r--  1 osboxes osboxes   358 Dec  8  2020 hi.zip
```

On aurait vu que le ZIP était protégé par mot de passe donc on aurait utillisé `zip2john` avant de casser le hash et extraire le fichier :

```shellsession
$ ./john --wordlist=dict.txt  hello.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
inbox            (hi.zip/hello)     
1g 0:00:00:00 DONE 20.00g/s 163840p/s 163840c/s 163840C/s the..wage
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Le fichier contient un indice :

> Hey Mary James, how are you today?  
> 
> The other time we were on a romantic date you asked me to give you Uncle Ben's password, well it's in the sqlite file in the browser folder  
> 
> Ilove you Spiderman (100% peter parker, never black spiderman)

## Double peine

Ok donc il faut récupérer un mot de passe dans un des fichiers sqlite du dossier Mozilla de l'utilisateur `osboxes`.

Sauf que... le dossier n'est pas accessible en lecture :

```shellsession
daemon@osboxes:/opt/lampp/htdocs$ ls /home/osboxes/.mozilla/
ls: cannot open directory '/home/osboxes/.mozilla/': Permission denied
```

`daemon` étant l'utilisateur que l'on aurait récupéré ici si on avait pu avoir un webshell.

J'ai tenté de casser le hash de l'utilisateur `osboxes` aussi... sans succès.

Effectivement si on disposait de droits nécessaires on aurait eu le mot de passe :

```shellsession
$ sqlite3 firefox/wjjbvyxi.default-release/formhistory.sqlite
SQLite version 3.39.3 2022-09-05 11:02:23
Enter ".help" for usage hints.
sqlite> .tables
moz_deleted_formhistory  moz_history_to_sources 
moz_formhistory          moz_sources            
sqlite> select * from moz_formhistory;
1|searchbar-history|http://passwordofrootis:goodbyeseeyoulater/|1|1607445708246000|1607445708246000|rKYjrm8mS2aJOo8G
```

Et finalement obtenu le flag final :

```
 root  ~  cat nice.txt 
_________                                     __        .__          __  .__               
\_   ___ \  ____   ____    ________________ _/  |_ __ __|  | _____ _/  |_|__| ____   ____  
/    \  \/ /  _ \ /    \  / ___\_  __ \__  \\   __\  |  \  | \__  \\   __\  |/  _ \ /    \ 
\     \___(  <_> )   |  \/ /_/  >  | \// __ \|  | |  |  /  |__/ __ \|  | |  (  <_> )   |  \
 \______  /\____/|___|  /\___  /|__|  (____  /__| |____/|____(____  /__| |__|\____/|___|  /
        \/            \//_____/            \/                     \/                    \/ 

Have a good day
```

Bref le CTF est cassé, je vais gagner du temps en ne regardant pas les CTFs du même auteur.
