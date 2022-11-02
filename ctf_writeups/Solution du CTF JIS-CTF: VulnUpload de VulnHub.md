# Solution du CTF JIS-CTF: VulnUpload de VulnHub

Le CTF [JIS-CTF: VulnUpload](https://www.vulnhub.com/entry/jis-ctf-vulnupload,228/) se présente comme un CTF pour débutants sur lequel il faut récupérer 5 flags.  

L'auteur indique qu'il faut en moyenne une heure et demi pour récupérer tous les flags. On met le chrono et c'est parti :)   

Fast and furious
----------------

Deux ports ouverts et de nombreux indices dans un *robots.txt* :  

```plain
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 af:b9:68:38:77:7c:40:f6:bf:98:09:ff:d9:5f:73:ec (RSA)
|_  256 b9:df:60:1e:6d:6f:d7:f6:24:fd:ae:f8:e3:cf:16:ac (ECDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 8 disallowed entries
| / /backup /admin /admin_area /r00t /uploads
|_/uploaded_files /flag
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-title: Sign-Up/Login Form
|_Requested resource was login.php
```

A l'adresse */admin\_area/* on trouve des identifiants pour la page de login (l'index du site en fait) :  

```plain
<!--	username : admin
	password : 3v1l_H@ck3r
	The 2nd flag is : {7412574125871236547895214}
-->
```

A l'adresse */flag* se trouve le permier flag :  

> The 1st flag is : {8734509128730458630012095}

Une bonne partie des dossiers indiqué dans le *robots.txt* n'est pas présent. Il y a toutefois le *uploaded\_files* qui est valide, et comme le nom du CTF laisse entendre la présence d'un script d'upload c'est utile.  

Effectivement une fois connecté avec les identifiants on arrive directement sur le formulaire d'upload. J'envoie une backdoor PHP sans y croire une seconde avec l'extension .php en me disant qu'il faudra sans doute tricher sur le content-type ou autre... mais en fait ça passe et la backdoor se retrouve dans *uploaded\_files* :p   

Python n'est pas présent sur le système mais perl y est. Avec [dc.pl](https://raw.githubusercontent.com/nikicat/web-malware-collection/master/Backdoors/PL/dc.pl) j'abandonne ma backdoor PHP pour un reverse shell cradot mais interactif.  

Dans */var/www/html* il y a un flag qu'on ne peut pas lire :  

```plain
-rw-r----- 1 technawi technawi 132 Apr 21  2017 flag.txt
```

Cet utilisateur a l'air intéressant, fouillons dans les pages du site :  

```plain
$ grep -r technawi * 2> /dev/null
hint.txt:try to find user technawi password to read the flag.txt file, you can find it in a hidden file ;)
index.php:            <a class="tzine" href="http://www.technawi.net">Powered by : Technawi[dot]net</a>
```

dans ce même fichier *hint.txt* un autre flag :  

> The 3rd flag is : {7645110034526579012345670}

Toujours autour du même user :  

```plain
$ find / -user technawi 2> /dev/null
/etc/mysql/conf.d/credentials.txt
/var/www/html/flag.txt
/home/technawi
/home/technawi/.cache
/home/technawi/.bash_history
/home/technawi/.sudo_as_admin_successful
/home/technawi/.profile
/home/technawi/.bashrc
/home/technawi/.bash_logout
$ cat /etc/mysql/conf.d/credentials.txt
The 4th flag is : {7845658974123568974185412}

username : technawi
password : 3vilH@ksor
```

Ces identifiants permettent d'avoir un accès SSH :)   

On peut enfin accéder au flag qui nous restait :  

```plain
The 5th flag is : {5473215946785213456975249}

Good job :)

You find 5 flags and got their points and finish the first scenario....
```

That's it ! L'utilisateur peut sudo en root donc pas besoin de chercher plus loin.  

Gone in 20 minutes
------------------

Voilà c'était vraiment du basique mais on était prévenu.

*Published March 16 2018 at 12:04*