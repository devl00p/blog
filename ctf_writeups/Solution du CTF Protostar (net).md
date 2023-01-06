# Solution du CTF Protostar (net)

Je continue sur le [CTF Protostar](https://vulnhub.com/entry/exploit-exercises-protostar-v2,32/) mais cette fois sur les exercices `net`. Il s'agit plus d'exercices de reverse-engineering.

Les binaires correspondants écoutent sur le réseau d'où leur nom  :

```
tcp        0      0 0.0.0.0:2996            0.0.0.0:*               LISTEN      1432/net3       
tcp        0      0 0.0.0.0:2997            0.0.0.0:*               LISTEN      1430/net2       
tcp        0      0 0.0.0.0:2998            0.0.0.0:*               LISTEN      1428/net1       
tcp        0      0 0.0.0.0:2999            0.0.0.0:*               LISTEN      1426/net0
```

il y a aussi un binaire `net4` sur le système mais il s'avère qu'il s'agit juste de la version dépouillée des autres binaires : il met bien un port en écoute mais la fonction de callback attendue pour gérer les communications est vide.

## Level 0

Le programme donne un entier et demande à ce qu'on lui envoit en little-endian sur 32 bits comme un entier serait représenté en mémoire dans un programme informatique :

```shellsession
$ ncat 192.168.56.95 2999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.95:2999.
Please send '88717732' as a little endian 32bit int
```

L'entier demandé change à chaque fois.

On peut résoudre le problème directement depuis Python :

```python
$ python
Python 2.7.18 (default, Apr 23 2020, 09:27:04) [GCC] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> import struct
>>> sock = socket.socket()
>>> sock.connect(('192.168.56.95', 2999))
>>> sock.recv(1024)
"Please send '1664743977' as a little endian 32bit int\n"
>>> sock.send(struct.pack("<I", 1664743977))
4
>>> sock.recv(1024)
'Thank you sir/madam\n'
>>> sock.close()
```

## Level 1

Cette fois pas d'indications mais c'est bien sûr l'inverse qui est demandé :

```shellsession
ncat 192.168.56.95 2998 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.95:2998.
H�h
```

C'est parti :

```python
$ python
Python 2.7.18 (default, Apr 23 2020, 09:27:04) [GCC] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> import struct
>>> sock = socket.socket()
>>> sock.connect(('192.168.56.95', 2998))
>>> data = sock.recv(1024)
>>> num = struct.unpack("<I", data)[0]
>>> sock.send(str(num).encode())
10
>>> sock.recv(1024)
'you correctly sent the data\n'
>>> sock.close()
```

## Level 2

Ca semble plus énigmatique :

```shellsession
$ ncat 192.168.56.95 2997 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.95:2997.
R���DnE
```

Via le décompilateur de `Cutter` il semble que le programme donne 4 entiers qu'il faut additionner :

```c
#include <stdint.h>
 
uint32_t run (void) {
    int32_t var_24h;
    int32_t var_20h;
    int32_t var_10h;
    unsigned long var_ch;
    const char * buf;
    size_t nbytes;
    var_ch = 0;
    var_10h = 0;
    while (var_10h <= 3) {
        ebx = var_10h;
        eax = random ();
        *((ebp + ebx*4 - 0x20)) = eax;
        eax = var_10h;
        eax = *((ebp + eax*4 - 0x20));
        var_ch += eax;
        eax = var_10h;
        edx = eax*4;
        eax = &var_20h;
        eax += edx;
        eax = write (0, 4, eax);
        if (eax != 4) {
            errx (1, 0x8049c94);
        }
        var_10h++;
    }
    eax = &var_24h;
    eax = read (0, 4, eax);
    if (eax != 4) {
        errx (1, 0x8049c98);
    }
    eax = var_24h;
    if (var_ch == eax) {
        puts ("you added them correctly");
    } else {
        puts ("sorry, try again. invalid");
    }
    return eax;
}

```

La difficulté en Python réside dans le fait que les entiers ne sont pas bornés à 32 bits, il faut donc utiliser un masque :

```python
$ python
Python 2.7.18 (default, Apr 23 2020, 09:27:04) [GCC] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> import struct
>>> sock = socket.socket()
>>> sock.connect(('192.168.56.95', 2997))
>>> numbers = sock.recv(1024)
>>> len(numbers)
16
>>> result = sum(struct.unpack("<IIII", numbers))  # On additionne les 4 nombres
>>> sock.send(struct.pack("<I", result))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
struct.error: 'I' format requires 0 <= number <= 4294967295
>>> sock.send(struct.pack("<I", 0xffffffff & result))
4
>>> sock.recv(1024)
'you added them correctly\n'
```

## Level 3

Toujours plus compliqué, cet exercice demande de bonnes connaissances en reverse-engineering et/ou debugging.

La fonction `run()` qui gère le client est la suivante :

```nasm
run (int32_t arg_8h);
; var int32_t var_12h @ ebp-0x12
; var void *var_10h @ ebp-0x10
; var unsigned long var_ch @ ebp-0xc
; arg int32_t arg_8h @ ebp+0x8
; var const char *var_4h @ esp+0x4
; var const char *var_8h @ esp+0x8
0x08049a26      push ebp
0x08049a27      mov ebp, esp
0x08049a29      sub esp, 0x28
0x08049a2c      mov dword [var_8h], 2 ; int32_t arg_8h ; Lit 2 octets dans l'ordre reseau et les converti en ordre host
0x08049a34      lea eax, [var_12h]
0x08049a37      mov dword [var_4h], eax ; int32_t arg_10h
0x08049a3b      mov eax, dword [arg_8h]
0x08049a3e      mov dword [esp], eax ; int32_t arg_ch
0x08049a41      call nread         ; sym.nread ;  sym.nread(const char *arg_ch, unsigned long arg_10h, int fildes)
0x08049a46      movzx eax, word [var_12h]
0x08049a4a      movzx eax, ax
0x08049a4d      mov dword [esp], eax
0x08049a50      call ntohs         ; sym.imp.ntohs
0x08049a55      mov word [var_12h], ax
0x08049a59      movzx eax, word [var_12h]
0x08049a5d      movzx eax, ax
0x08049a60      mov dword [esp], eax ; size_t size
0x08049a63      call malloc        ; sym.imp.malloc ; alloue la taille qui a ete recue ; void *malloc(size_t size)
0x08049a68      mov dword [var_10h], eax
0x08049a6b      cmp dword [var_10h], 0
0x08049a6f      jne 0x8049a90
0x08049a71      movzx eax, word [var_12h]
0x08049a75      movzx eax, ax
0x08049a78      mov dword [var_8h], eax
0x08049a7c      mov dword [var_4h], str.malloc_failure_for__d_bytes ; 0x8049fd8
0x08049a84      mov dword [esp], 1 ; int eval
0x08049a8b      call errx          ; sym.imp.errx ; void errx(int eval)
0x08049a90      movzx eax, word [var_12h]
0x08049a94      movzx eax, ax
0x08049a97      mov dword [var_8h], eax ; int32_t arg_8h
0x08049a9b      mov eax, dword [var_10h]
0x08049a9e      mov dword [var_4h], eax ; int32_t arg_10h
0x08049aa2      mov eax, dword [arg_8h]
0x08049aa5      mov dword [esp], eax ; int32_t arg_ch
0x08049aa8      call nread         ; sym.nread ;  sym.nread(const char *arg_ch, unsigned long arg_10h, int fildes)
0x08049aad      mov eax, dword [var_10h]
0x08049ab0      movzx eax, byte [eax]
0x08049ab3      movzx eax, al
0x08049ab6      cmp eax, 0x17      ; 23
0x08049ab9      jne 0x8049b09
0x08049abb      movzx eax, word [var_12h]
0x08049abf      sub eax, 1
0x08049ac2      movzx eax, ax
0x08049ac5      mov edx, dword [var_10h]
0x08049ac8      add edx, 1
0x08049acb      mov dword [var_4h], eax ; int32_t arg_8h
0x08049acf      mov dword [esp], edx ; int32_t arg_ch
0x08049ad2      call login         ; sym.login
0x08049ad7      mov dword [var_ch], eax
0x08049ada      cmp dword [var_ch], 0
0x08049ade      je 0x8049ae7
0x08049ae0      mov eax, str.successful ; 0x8049ff4
0x08049ae5      jmp 0x8049aec
0x08049ae7      mov eax, str.failed ; 0x8049fff
0x08049aec      mov dword [var_8h], eax ; int32_t arg_8h
0x08049af0      mov dword [var_4h], 0x21 ; '!' ; 33 ; int32_t arg_10h
0x08049af8      mov eax, dword [arg_8h]
0x08049afb      mov dword [esp], eax ; int32_t arg_ch
0x08049afe      call send_string   ; sym.send_string
0x08049b03      nop
0x08049b04      jmp 0x8049a2c
0x08049b09      mov dword [var_8h], str.what_you_talkin_about_willis ; 0x804a006 ; int32_t arg_8h
0x08049b11      mov dword [var_4h], 0x3a ; ':' ; 58 ; int32_t arg_10h
0x08049b19      mov eax, dword [arg_8h]
0x08049b1c      mov dword [esp], eax ; const char *arg_ch
0x08049b1f      call send_string   ; sym.send_string
0x08049b24      jmp 0x8049a2c
```

J'ai balancé ce code a ChatGPT qui a donné l'interprétation suivante :

> This is a function written in C programming language. It appears to be reading in a value from an input stream and then allocating memory on the heap based on that value.
> 
> The value is read in using the `nread` function and then converted from network byte order to host byte order using the `ntohs` function. If the memory allocation fails, the function prints an error message and exits.
> 
> After the memory is successfully allocated, the function reads in another value from the input stream and checks if it is equal to 23.
> 
> If it is, the function continues execution with some additional processing. Otherwise, it frees the previously allocated memory and exits.

Effectivement le code utilise d'abord 2 octets sur le réseau avec la fonction `nread` qui a le prototype suivant :

```c
int nread(int socket, char *buffer, int length);
```

Ces deux octets sont convertis de la notation réseau (big-endian) vers la notation de l'architecture machine (ici little-endian).

L'entier ainsi obtenu sert de taille pour faire un `malloc` puis un second appel à `nread` pour écrire les données dans le buffer alloué.

Sur cette seconde lecture le programme s'attend à ce que le premier octet corespond à `0x17`.

Ensuite un appel à la fonction `login()` est effectué. Cette fonction reçoit deux arguments :

- le buffer à partir de son second octet donc sans le `0x17`

- la taille telle qu'annoncée moins un (du au retrait du premier octet)

La fonction `login()` a été l'une des plus difficile à comprendre :

```nasm
login (void *arg_8h, const char *arg_ch);
; var unsigned long var_2ch @ ebp-0x2c
; var const char *var_1ch @ ebp-0x1c
; var const char *var_18h @ ebp-0x18
; var const char *ptr @ ebp-0x14
; var int32_t var_10h @ ebp-0x10
; var unsigned long var_ch @ ebp-0xc
; arg void *arg_8h @ ebp+0x8
; arg const char *arg_ch @ ebp+0xc
; var const char *s2 @ esp+0x4
; var int32_t var_8h @ esp+0x8
0x08049861      push ebp
0x08049862      mov ebp, esp
0x08049864      sub esp, 0x48
0x08049867      mov eax, dword [arg_ch]
0x0804986a      mov word [var_2ch], ax
0x0804986e      cmp word [var_2ch], 2
0x08049873      ja 0x8049889
0x08049875      mov dword [s2], str.invalid_login_packet_length ; 0x8049f78
0x0804987d      mov dword [esp], 1 ; int eval
0x08049884      call errx          ; sym.imp.errx ; void errx(int eval)
0x08049889      mov dword [var_1ch], 0
0x08049890      mov eax, dword [var_1ch]
0x08049893      mov dword [var_18h], eax
0x08049896      mov eax, dword [var_18h]
0x08049899      mov dword [ptr], eax
0x0804989c      movzx eax, word [var_2ch]
0x080498a0      mov dword [var_8h], eax ; void **dest
0x080498a4      mov eax, dword [arg_8h]
0x080498a7      mov dword [s2], eax ; int32_t arg_ch
0x080498ab      lea eax, [ptr]
0x080498ae      mov dword [esp], eax ; int32_t arg_10h
0x080498b1      call get_string    ; sym.get_string
0x080498b6      mov dword [var_10h], eax
0x080498b9      mov eax, dword [var_10h]
0x080498bc      movzx edx, word [var_2ch]
0x080498c0      mov ecx, edx
0x080498c2      sub cx, ax
0x080498c5      mov eax, ecx
0x080498c7      movzx edx, ax
0x080498ca      mov eax, dword [var_10h]
0x080498cd      add eax, dword [arg_8h]
0x080498d0      mov dword [var_8h], edx ; void **dest
0x080498d4      mov dword [s2], eax ; const char *arg_ch
0x080498d8      lea eax, [var_18h]
0x080498db      mov dword [esp], eax ; int32_t arg_10h
0x080498de      call get_string    ; sym.get_string
0x080498e3      add dword [var_10h], eax
0x080498e6      mov eax, dword [var_10h]
0x080498e9      movzx edx, word [var_2ch]
0x080498ed      mov ecx, edx
0x080498ef      sub cx, ax
0x080498f2      mov eax, ecx
0x080498f4      movzx edx, ax
0x080498f7      mov eax, dword [var_10h]
0x080498fa      add eax, dword [arg_8h]
0x080498fd      mov dword [var_8h], edx ; void **dest
0x08049901      mov dword [s2], eax ; const char *arg_ch
0x08049905      lea eax, [var_1ch]
0x08049908      mov dword [esp], eax ; int32_t arg_10h
0x0804990b      call get_string    ; sym.get_string
0x08049910      add dword [var_10h], eax
0x08049913      mov dword [var_ch], 0
0x0804991a      mov eax, dword [ptr]
0x0804991d      mov dword [s2], str.net3 ; 0x8049f94 ; const char *s2
0x08049925      mov dword [esp], eax ; const char *s1
0x08049928      call strcmp        ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
0x0804992d      or dword [var_ch], eax
0x08049930      mov eax, dword [var_18h]
0x08049933      mov dword [s2], str.awesomesauce ; 0x8049f99 ; const char *s2
0x0804993b      mov dword [esp], eax ; const char *s1
0x0804993e      call strcmp        ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
0x08049943      or dword [var_ch], eax
0x08049946      mov eax, dword [var_1ch]
0x08049949      mov dword [s2], str.password ; 0x8049fa6 ; const char *s2
0x08049951      mov dword [esp], eax ; const char *s1
0x08049954      call strcmp        ; sym.imp.strcmp ; int strcmp(const char *s1, const char *s2)
0x08049959      or dword [var_ch], eax
0x0804995c      mov eax, dword [ptr]
0x0804995f      mov dword [esp], eax ; void *ptr
0x08049962      call free          ; sym.imp.free ; void free(void *ptr)
0x08049967      mov eax, dword [var_18h]
0x0804996a      mov dword [esp], eax ; void *ptr
0x0804996d      call free          ; sym.imp.free ; void free(void *ptr)
0x08049972      mov eax, dword [var_1ch]
0x08049975      mov dword [esp], eax ; void *ptr
0x08049978      call free          ; sym.imp.free ; void free(void *ptr)
0x0804997d      cmp dword [var_ch], 0
0x08049981      sete al
0x08049984      movzx eax, al
0x08049987      leave
0x08049988      ret
```

Ici ChatGPT était assez à côté de la plaque.

Pour bien comprendre ce que fait cette fonction il faut comprendre comment fonctione `getstring()`. Cette fonction a le prototype suivant :

```c
int getstring(void **dest, char *buffer, int size);
```

Cette fonction reçoit un paramètre `size` mais ce dernier sert uniquement comme une protection : si la chaine à extraire (explications après) est plus grande que la totalité du buffer alors le programme indique que la paquet est malformé.

Ce qui se passe c'est que le premier octet de buffer est lu comme étant la taille de la chaine de caractère qui suit. Cette taille est utilisée pour faire un `malloc` et la chaine qui se trouve après la taille est copiée via `strcpy()`.

La fonction retourne ensuite la taille de la chaine extraite + 1 :

```nasm
get_string (void **dest, const char *arg_ch, int32_t arg_10h);
; var unsigned long var_1ch @ ebp-0x1c
; var size_t size @ ebp-0x9
; arg void **dest @ ebp+0x8
; arg const char *arg_ch @ ebp+0xc
; arg int32_t arg_10h @ ebp+0x10
; var const char *src @ esp+0x4
0x080497fa      push ebp
0x080497fb      mov ebp, esp
0x080497fd      sub esp, 0x38
0x08049800      mov eax, dword [arg_10h]
0x08049803      mov word [var_1ch], ax
0x08049807      mov eax, dword [arg_ch] ; <- la chaine d'entrée
0x0804980a      movzx eax, byte [eax] ; <- récupération de la taille sur le premier octet
0x0804980d      mov byte [size], al
0x08049810      movzx eax, byte [size]
0x08049814      cmp ax, word [var_1ch] ; <- compare avec la taille reçue en argument
0x08049818      jbe 0x804982e
0x0804981a      mov dword [src], str.badly_formed_packet ; 0x8049f64
0x08049822      mov dword [esp], 1 ; int eval
0x08049829      call errx          ; sym.imp.errx ; void errx(int eval)
0x0804982e      movzx eax, byte [size]
0x08049832      mov dword [esp], eax ; size_t size
0x08049835      call malloc        ; sym.imp.malloc ; void *malloc(size_t size)
0x0804983a      mov edx, eax
0x0804983c      mov eax, dword [dest]
0x0804983f      mov dword [eax], edx
0x08049841      mov eax, dword [arg_ch]
0x08049844      lea edx, [eax + 1]
0x08049847      mov eax, dword [dest]
0x0804984a      mov eax, dword [eax]
0x0804984c      mov dword [src], edx ; const char *src
0x08049850      mov dword [esp], eax ; char *dest
0x08049853      call strcpy        ; sym.imp.strcpy ; char *strcpy(char *dest, const char *src)
0x08049858      movzx eax, byte [size] ; <- prend la taille lut, incrémente et retourne
0x0804985c      add eax, 1
0x0804985f      leave
0x08049860      ret
```

Dans `login()` il y a plusieurs appels successifs à `getstring()` avec le premier argument qui change et qui doit correspondre à un tableau de pointeurs où sont stockées les adresses retournées par `malloc()`.

Le premier appel est tout simple, il passe la chaine qui a été reçue sur le réseau avec sa taille, en revanche juste après  cet appel il prend la taille initiale et y retranche le résultat de `getstring()` pour obtenir la taille restante et incrémente aussi le pointeur sur la chaine d'autant de caractères.

Ainsi sur l'appel suivant à `getstring()` il extrait une seconde chaine depuis le buffer reçu. Il y a donc plusieurs chaines présentes dans le paquet qui commence par `0x17`, chacune précédée d'un octet correspondant à sa taille... mais pas uniquement !

Pour que tout fonctionne sans problèmes il faut aussi que ces chaines aient un octet nul terminal (en raison de l'utilisation de `strcpy()`) sans quoi on peut écraser des données sur le tas (et provoquer un crash lors d'un appel à `free()`) et ici notre objectif est juste que tout fonctionne correctement.

Par conséquent quand on spécifie la longueur d'une chaine dans le paquet on doit aussi compter son `'\0'` terminal.

La fin de `login()` procéde à 3 `strcmp()` avec les chaines suivantes : `net3`, `awesomesauce`, `password`.

Au final la solution est :

```python
import socket
import struct

sock = socket.socket()
sock.connect(("192.168.56.95", 2996))
words = ["net3", "awesomesauce", "password"]
packet = b"\x17"
for word in words:
    packet += struct.pack("<b", len(word) + 1) + word.encode() + b"\0"

sock.send(struct.pack(">H", len(packet)))  # envoie la taille du paquet sur 2 octets
sock.send(packet)  # envoie le paquet avec son header 0x17
print(sock.recv(2048))
sock.close()
```

Ce qui nous donne l'output `b'\x00\x0b!successful'`

Après avoir résolu les exercices j'ai regardé sur le web et découvert que certains ont pu le faire en s'aidant du code source... Mais ceux-ci ne sont pas présents sur l'image fournit par VulnHub.

Voir par exemple [Exploit-Exercises: Protostar (Net Levels)](https://73696e65.github.io/2015/07/exploit-exercises-protostar-net-levels) pour les curieux.

*Publié le 6 janvier 2023*
