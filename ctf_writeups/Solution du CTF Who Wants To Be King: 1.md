# Solution du CTF Who Wants To Be King: 1

[Who Wants To Be King: 1](https://vulnhub.com/entry/who-wants-to-be-king-1,610/) est un CTF pour débutant. La description annonce que Google est notre ami... ça promet.

Sans spoiler, si vous êtes bloqués sur un problème de mot de passe, réferez vous à [game-of-thrones/characters.json](https://github.com/jeffreylancaster/game-of-thrones/blob/master/data/characters.json) :p

```
Nmap scan report for 192.168.56.57
Host is up (0.00019s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7f552d63a8864f901f053cc99f40b3f2 (RSA)
|   256 e97111ed17fa4806a76b5bb60e1b11b8 (ECDSA)
|_  256 db7442c437c3aea05c3026cb1aef7652 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 31K   2020-12-01 11:23  skeylogger
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Toute l'énumération est résumée ici ! On télécharge donc le binaire qui est juste la version compilée de [simple-key-logger: A simple keylogger for Linux systems](https://github.com/gsingh93/simple-key-logger).

On applique la commande `strings` dessus et on finit par trouver une chaine étrange :

```
logfile
device
Could not determine keyboard device file
ZHJhY2FyeXMK
Usage: skeylogger [OPTION]
Logs pressed keys
  -h, --help            Displays this help message
  -v, --version         Displays version information
  -l, --logfile         Path to the logfile
  -d, --device          Path to device file (/dev/input/eventX)
Simple Key Logger version 0.0.1
```

Le base64 se décode en `dracarys`. Je connais la série *Game of Thrones* donc je sais au moins quel est l'univers en rapport. On pourrait récupérer la liste des personnages et appliquer un brute force SSH mais le login attendu est vraisemblablement `daenerys` :

```shellsession
$ ssh daenerys@192.168.56.57
daenerys@192.168.56.57's password: 
Last login: Tue Dec  1 11:38:40 2020 from 192.168.0.105
daenerys@osboxes:~$ id
uid=1001(daenerys) gid=1001(daenerys) groups=1001(daenerys)
daenerys@osboxes:~$ sudo -l
Matching Defaults entries for daenerys on osboxes:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, pwfeedback

User daenerys may run the following commands on osboxes:
    (root) NOPASSWD: /usr/bin/mint-refresh-cache
    (root) NOPASSWD: /usr/lib/linuxmint/mintUpdate/synaptic-workaround.py
    (root) NOPASSWD: /usr/lib/linuxmint/mintUpdate/dpkg_lock_check.sh
```

Aucun des fichiers dans cette liste n'existe.

Dans le dossier de l'utilisateur se trouve un fichier `secret` avec le contenu suivant :

> find home, pls

C'est toujours difficile de retrouver un fichier qui n'a pas de particularités (contrairement à un binaire setuid ou un exécutable appartenant à root mais modifiable) dans un système de fichiers...

Je remarque que le fichier `secret` précédent ainsi que le fichier `skeylogger` du début datent tous les deux du 1er décembre 2020. Je vais donc utiliser find pour obtenir la liste des fichiers créés ce jour (il y en a quand même un paquet) :

```shellsession
daenerys@osboxes:~$ find . -type f -newermt 2020-12-01 ! -newermt 2020-12-02
./.bashrc
./.gtkrc-2.0
./.bash_logout
./.bash_history
--- snip ---
./secret
./.local/share/daenerys.zip
./.local/share/flatpak/.changed
--- snip ---
```

Qu'il y a t-il dans ce fichier zip ?

```shellsession
daenerys@osboxes:~$ unzip  ./.local/share/daenerys.zip
Archive:  ./.local/share/daenerys.zip
 extracting: djkdsnkjdsn             
daenerys@osboxes:~$ file djkdsnkjdsn 
djkdsnkjdsn: ASCII text
daenerys@osboxes:~$ cat djkdsnkjdsn 
/usr/share/sounds/note.txt

daenerys@osboxes:~$ cat /usr/share/sounds/note.txt
I'm khal.....
```

Cette fois il s'agit de *Khal Drogo*. Ici le mot de passe pour root est khaldrogo :

```shellsession
daenerys@osboxes:~$ su root
Password: 
root@osboxes:/home/daenerys# cd /root/
root@osboxes:~# ls
nice.txt
root@osboxes:~# cat nice.txt 
¡Congratulation!


You have a good day!



aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1nTjhZRjBZZmJFawo=
```

Au final un CTF sans grand intérêt qui ne vous apprend rien de particulier.

*Publié le 16 novembre 2022*
