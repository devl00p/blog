# Solution du Cyber-Security Challenge Australia 2014 (Crypto)

Quand je commence une nouvelle épreuve du *CySCA 2014*, c'est avec appréhension que je me demande ce que sera la prochaine.  

Pourtant quand j'arrive à la fin de l'épreuve en cours le choix de la suivante m'apparaît comme une évidence.  

C'est ainsi que je me suis retrouvé sur les épreuves de cryptanalyse du *CySCA* qui à ma plus grande surprise sont passées comme une formalité.  

Il ne me reste donc ensuite que 3 types d'épreuves : *"Random"*, *Android Forensics* (c'est qui ce *Dalvik* ? ;-) et *Exploitation* (12 exercices au total).  

Standard Galactic Alphabet (120 points)
---------------------------------------

Voici l'annonce de cette exercice de crypto :  

> Perform a white box evaluation of the custom encryption used in Fortcerts "Slightly Secure Shell" program. Identify any vulnerabilites in their implementation and demonstrate that they can be exploited to gain confidential information. The server is running at 192.168.1.64:12433

La connexion au serveur est révélatrice :  

```plain
$ ncat 192.168.1.64 12433 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.64:12433.
You have connected to the Slightly Secure Shell server of Fortress Certifications.
#>hello
helloRunning command: 'hello'
kqdSkqeQtuwt^//2uwv2mmeS(wS2pwL2nS(

Key reset
#>
id
idRunning command: 'id'
$pfI$pshak6fFk6?ciisIF6Ic<6'c=IF

Key reset
#>
echo aaaa
echo aaaaRunning command: 'echo aaaa'
++++

Key reset
#>
^C
```

A chaque réponse la clé servant à chiffrer l'output est réinitialisée mais pour *"hello"* (une commande qui n'existe pas) et *id* on semble avoir des réponses proches puisqu'on retrouve par exemples des caractères qui se répètent en première et 5ème position.  

Ajouté à ça on trouve des caractères doublés (*mm* pour hello, *ii* pour id) qui correspondent vraisemblablement aux 2 m dans *"command not found"*. Chose qui se vérifie en comparant les positions supposées des letters o, n et d dans les réponses.  

Comme sur les autres épreuves le binaire sur le serveur doit tourner dans un chroot ce qui explique l'absence de la commande id.  

Mais l'utilisation de la commande echo interne à bash permet d'être sûr à 100% qu'on a affaire à un chiffrement par substitution.  

Comble de la facilité pour cet exercice, une partie du code Python du programme nous est fourni :  

```python
def execute_command(command,plain,coded):
    print "Running command: bash %s" % command
    proc = subprocess.Popen(("/bin/bash","-c",command),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    proc.wait()
    stdoutdata = proc.stdout.read()
    stdoutdata += proc.stderr.read()
    output = ""
    for letter in stdoutdata:
        if letter in plain:
            output += coded[plain.find(letter)]
        else:
            output += letter

    return output

def handle_client(conn,addr):
    plain = "`1234567890-=~!@#$%^&*()_+[]\{}|;':\",./<>?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "
    conn.send("You have connected to the Slightly Secure Shell server of Fortress Certifications.\n")
    coded = shuffle_plain(plain)

    command = ""
    conn.send("#>")
    while 1:
        data = conn.recv(1)
        if not data: break

        if data == "\x7f" or data == "\x08":
            if len(command) > 0:
                command = command[:-1]
            continue
        if data == "\n" or data =="\r":
            if len(command) == 0: continue
            conn.send("Running command: '%s'\n" % command)
            cmd_stdout = execute_command(command,plain,coded)
            conn.sendall(cmd_stdout+"\n")
            command = ""
            conn.sendall("Key reset\n")
            coded = shuffle_plain(plain)
            conn.sendall("#>")
        else:
            if data not in plain:
                continue
            command += data

        conn.sendall(data)

    conn.close()
```

La technique d'attaque que j'ai choisi est très simple : puisque la clé de substitution est réinitialisée entre chaque input il faut envoyer deux commandes à la fois.  

La première commande consiste à faire afficher la totalité des caractères via echo afin de déterminer la table de substitution ce qui nous permettra de déchiffrer en toute facilité l'output de la commande suivante.  

```python
# -*- coding: utf-8 -*-
import socket
import re
import sys

def read_while(sock_fd, marker):
    while True:
        buffer = sock_fd.recv(1024)
        if marker in buffer:
            return buffer
            break

def send_command(sock_fd, command):
    cmd = """echo '`1234567890-=~!@#$%^&*()_+[]\{}|;'"'"':",./<>?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ';"""
    cmd += command
    sock_fd.send(cmd)
    sock_fd.send("\n")
    n = 0
    # consume echoed input
    while n < len(cmd):
        n += len(sock_fd.recv(1))

def decode_output(sock_fd):
    plain = "`1234567890-=~!@#$%^&*()_+[]\{}|;':\",./<>?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ "
    status, coded, encoded = sock_fd.recv(4096).split("\n", 2)
    if encoded.endswith("\n\nKey reset\n#>\n"):
        encoded = encoded[:-15]

    clear = ""
    for letter in encoded:
        clear += (plain[coded.find(letter)] if letter in coded else letter)
    return clear

sock = socket.socket()
sock.connect(('192.168.1.64', 12433))

cmd = sys.argv[1]
read_while(sock, "#>")
print "Sending command", cmd
send_command(sock, cmd)
print decode_output(sock)
sock.close()
```

Utilisation :  

```plain
$ python client.py "ls -al"
Sending command ls -al
total 28
drwxr-xr-x 6 0 0 4096 Mar 14  2014 .
drwxr-xr-x 6 0 0 4096 Mar 14  2014 ..
drwxr-xr-x 2 0 0 4096 Mar 19  2014 bin
drwxr-xr-x 2 0 0 4096 Mar 14  2014 dev
drwxr-xr-x 2 0 0 4096 Mar 14  2014 etc
-rw-r--r-- 1 0 0   20 Mar 14  2014 flag.txt
drwxr-xr-x 3 0 0 4096 Mar 14  2014 lib
$ python client.py "cat flag.txt"
Sending command cat flag.txt
CaviarBakedShame966
```

Compression Session (200 points)
--------------------------------

> Perform a white box evaluation of the Fortcerts highly secure key generation server. Identify and exploit any vulnerabilities in the implementation that will lead to a disclosure of secret data. The server is running at 192.168.1.64:9999

```plain
$ ncat 192.168.1.64 9999 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.64:9999.
                Welcome to the Keygen server.
                ==============================
[+]All access is monitored and any unauthorised access will be treated as CRIME
a
df86be2eada129d0cdb58bc18ccb6fcfde3ea688d19dc6389c2921a58ca23c609ff61d141569da2d398a65393898e88b19efb07fbf1e467565ecbc37a31e63caaa9c3146a8860111^C
```

A première vu ça ne semble pas gagné : on rentre un caractère et en retour on en a une sacré quantité.  

L'extrait du code fourni est le suivant :  

```python
def compress(d):
        c = zlib.compressobj()
        return(c.compress(d) + c.flush(zlib.Z_SYNC_FLUSH)).encode("hex")

def encrypt(aes,d):
        return aes.encrypt(d).encode("hex")

def handle_client(conn, addr):
        AESKey = os.urandom(32)
        ctr = Counter.new(128)

        aes = AES.new(AESKey, AES.MODE_CTR, counter=ctr)

        BANNER = "\t\tWelcome to the Keygen server.\n\t\t"
        BANNER += "="*30
        BANNER += "\n[+]All access is monitored and any unauthorised access will be treated as CRIME\n"
        conn.send(BANNER)

        SECRET = 'Key:' + helpers.load_flag()

        data = conn.recv(2048).strip()

        while len(data):
                data = compress(SECRET + data)
                data = encrypt(aes, data)

                conn.send(data)

                data = conn.recv(2048).strip()

        conn.close()
```

Heureusement en voyant *CRIME* écrit en majuscules j'ai tout de suite tilté que ça faisait référence à l'attaque sur SSL/TLS révélée en septembre 2012.  

Le principe expliqué notamment [sur StackExchange](https://security.stackexchange.com/questions/19911/crime-how-to-beat-the-beast-successor) est le suivant :  

Quand on demande une page web à un serveur HTTP ce dernier retourne souvent les données compressées avec une indication dans l'entête *Content-Encoding* (ex: gzip ou deflate).  

Si en plus les communications sont chiffrées par TLS/SSL alors ce sont ces données compressées qui seront chiffrées et transmises sur le réseau.  

Maintenant comment fonctionnent les algorithmes de compression ? Principalement en exploitant les répétitions.  

Ainsi si on veut compresser la phrase *"Science sans conscience n'est que ruine de l'âme"* alors l'algorithme de compression déterminera par exemple que les caractères *"cience "* apparaissent deux fois et qu'il peut être efficace de créer une table de compression (pour simplifier, mettons que le caractère z permet de marquer la chaîne *"cience "*) et remplacer les occurrences de *"cience "* par z.  

L'attaque *CRIME* nécessite que l'attaquant puisse injecter des données dans les communications avant qu'elles soient compressées, chiffrées et envoyées avec des données légitimes.  

En exploitant le principe de la compression il pourra déterminer la présence de certaines chaînes de caractères. Il pourra commencer par injecter *"xtvqkpm"* (qui n'est probablement pas présent dans la page), noter la taille de la communication résultante puis recommencer en injectant cette fois *"science"*.  

Si cette communication est plus courte que la précédente (alors que les deux chaines font 7 caractères) alors cela signifie que *"science"* est déjà présent dans la page et que l'algo de compression a fait son boulot.  

En situation réelle un attaquant cherchera plutôt à faire passer la chaîne *"Set-Cookie: "* qu'il injectera dans le navigateur de la victime via un XSS et passera différentes valeurs jusqu'à trouver l'identifiant de cookie.  

Dans le cas de notre challenge il n'y a que nous et le serveur mais le principe reste le même car le programme concatène la chaîne *"Key:"* avec le flag à trouver puis les données que l'on lui soumet avant de les compresser, les chiffrer et nous les retourner.  

Mon attaque consiste à créer une chaîne en partant de *"Key:"* à laquelle je tente de rajouter à chaque fois un caractère parmi ceux utilisés pour les flags (majuscules, minuscules, chiffres). Si pour l'un des caractères le texte chiffré est plus court qu'avec les autres alors il s'agit d'une partie du flag : j’arrête et je passe à la position suivante :  

```python
# devloop - CySCA 2014 - Compression Session
# CRIME exploitation
import socket
import string

sock = socket.socket()
sock.connect(('192.168.1.64', 9999))
sock.recv(1024)

known = "Key:"
alphabet = string.letters + string.digits + "\n"
while True:
    min_size =  6000
    good_letter = '|'
    for letter in alphabet:
        sock.send(known + letter)
        size = len(sock.recv(9096))
        if size < min_size:
            min_size = size
            good_letter = letter
    if good_letter == "\n":
        break
    known += good_letter
sock.close()

print "Extracted:", known
```

L'exécution est rapide :  

```plain
$ time python crime.py 
Extracted: Key:DrizzleVerandaFinger576Key

real    0m0.370s
user    0m0.037s
sys     0m0.025s
```

Chop Suey (280 points)
----------------------

> Senior staff at Fortcerts have expressed objections to the use of white box evaluation methodology with the argument "real attackers won't have source code access". Perform a black box evaluation of the Fortcerts very secure encryption service. Diagnose and identify any crypto vulnerabilities in the service that can be used to recover encrypted data. The very secure encryption service is running at 192.168.1.64:1337

Cette fois pas de code à disposition.  

Deux commandes sont disponibles sur le serveur. L'une retourne vraisemblablement le flag chiffré avec un IV (vecteur d'initialisation) l'autre permet de chiffrer les données que l'on soumet mais on ne peut pas choisir l'IV nous même.  

```plain
$ ncat 192.168.1.64 1337 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.64:1337.
Key Reset!
    Welcome to the FortCerts Certified Data Encryption Service
            This program uses very secure encryption
Commands:
E - Encrypt specified data
D - Dump service stored data
Output is in format <IV>:<Encrypted Data>
D
1dcf:4c4335997a34d67a1d880444668cb1c4a8ea47604e20
Key Reset!
D
f61d:e08844d029d02a65e12aadf397c61a53ad461ea9f110
Key Reset!
E
Invalid use of encrypt. Usage E,<valuetoencrypt>
E,test
3964:f96ca587
E,test
013d:e006fff5
D
b5fb:89c23c185c149d301fb3287ebfc405a4cf67ce8b08e6
Key Reset!
^C
```

On est donc en présence d'une attaque à texte clair choisi.  

Pour un même texte clair c'est difficile de faire la corrélation entre l'algo et l'IV...  

```plain
E,aaaaaaaa
81ab:002e998b49589ce8
E,aaaaaaaa
f0e1:6651b13dedcfe460
E,aaaaaaaa
8304:6f67669f951dc5d0
E,aaaaaaaa
ef25:61947a1149f059a8
E,aaaaaaaa
00b0:95cebaed60d7f226
```

J'ai choisi d'envoyer a, puis aa, puis aaa... et à chaque fois essayer autant de fois que nécessaire jusqu'à ce que le serveur utilise l'IV que je souhaite (une chance sur 65536...) ce qui s'est avéré payant :  

```plain
E,a
0000:7d
E,aa
0000:7d4c
E,aaa
0000:7d4c46
E,aaaa
0000:7d4c4604
E,aaaaa
0000:7d4c4604ef
E,aaaaaa
0000:7d4c4604ef88
E,aaaaaaa
0000:7d4c4604ef8893
E,aaaaaaaa
0000:7d4c4604ef889362
```

Le chiffrement fonctionne donc bêtement caractère par caractère.  

Pour retrouver le flag il suffit de prendre l'une des réponses obtenues via la commande D en attendant le même IV et en testant chaque caractère possible...  

```python
import socket
import string

def read_while(sock_fd, marker):
    while True:
        buffer = sock_fd.recv(1024)
        if marker in buffer:
            return buffer
            break

sock = socket.socket()
sock.connect(('192.168.1.64', 1337))
read_while(sock, "Output is in format <IV>:<Encrypted Data>")
alphabet = string.letters + string.digits
secret = "4c4335997a34d67a1d880444668cb1c4a8ea47604e20"

known = ""
count = 0
while True:
    found_letter = False
    for letter in alphabet: # Test every possible letter
        while True: # Until we get the encoded value with the wanted IV
            sock.send("E," + known + letter + "\n")
            count += 1
            result = sock.recv(2048).strip()
            if ':' not in result:
                print repr(result)
                exit()
            iv, encoded = result.split(':')
            if iv == "1dcf":
                if secret == encoded:
                    print "Final result:", known
                    print "Number of requests:", count
                    exit()
                elif secret.startswith(encoded):
                    known += letter
                    # print known
                    found_letter = True
                    break
                else:
                    # This letter is not valid
                    break
        if found_letter:
            break

sock.close()
```

Forcément ça prend un peu de temps puisqu'en comptant sur une chance normale le nombre de combinaisons maxi à tester est de :  

32768 \* *le nombre de caractères à tester* \* *le nombre de caractères à trouver* = 42663936  

Heureusement on n'a pas à refaire une connexion TCP à chaque tentative.  

```plain
$ time python chop.py

Final result: FriendNoticeBelfast52
Number of requests: 28287215

real    112m14.425s
user    4m42.657s
sys     4m59.497s
```

Presque deux heures et 28287215 tentatives (forcément car j'ai mis les lettres en premier).  

Il y a plein de façons d'améliorer l'attaque :  

* prendre de nombreuses combinaisons (IV, flag chiffré) comme élément de comparaison pour augmenter ses chances (on prend un peu de temps en + au début mais au final on en gagne)
* utiliser un dictionnaire et une librairie de complétion de mot (quand on rentre "Belf" dans *WordReference* il ne propose que belfry et Belfast...)
* dans l'alphabet utilisé organiser les lettres selon leur fréquence d'apparition en anglais

Jusqu'à présent l'épreuve crypto est celle qui m'a pris le moins de temps o\_O

*Published May 16 2015 at 16:31*