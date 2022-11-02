# Solution du CTF Replay de VulnHub

Bons journaux
-------------

[Replay](https://www.vulnhub.com/entry/replay-1,278/) est un CTF proposé par *c0rruptedb1t* sur *VulnHub*.  

Le précédent CTF du même auteur [ne m'avait pas fait bonne impression](http://devloop.users.sourceforge.net/index.php?article159/solution-du-ctf-bob-1-0-1-de-vulnhub) mais il ne faut pas rester sur ses à priori :p  

Pizza yolo
----------

```plain
Nmap scan report for 192.168.2.2
Host is up (0.00029s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
| ssh-hostkey: 
|   2048 54:35:aa:49:eb:90:09:a1:28:f3:0c:9a:fb:01:52:0d (RSA)
|   256 e7:0b:6e:52:00:51:74:11:b6:cd:c6:cf:25:3a:1b:84 (ECDSA)
|_  256 3b:38:da:d7:16:23:64:68:8f:52:12:8a:14:07:6a:53 (ED25519)
80/tcp    open     http
| http-robots.txt: 1 disallowed entry 
|_/bob_bd.zip
|_http-title: Site doesn't have a title (text/html).
1337/tcp  open     waste
5678/tcp  filtered rrac
54799/tcp filtered unknown
```

*Nmap* nous mâche un peu le travail avec la présence d'un *robots.txt* révélant la présence d'une archive zip.  

Cette archive contient deux fichiers :  

```plain
Archive:  bob_bd.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     1159  2018-12-07 01:21   changelog.txt
   161192  2018-12-06 12:48   client.bin
---------                     -------
   162351                     2 files
```

La description du CTF mentionne plusieurs façons d'arriver à nos fins, sachant que la solution *hard-way* requiert de ne pas lire le changelog et de ne pas utiliser un éditeur hexa.  

On oublie donc ce fichier changelog et pour ce qui est du binaire (ELF 64 en PIE, linké et strippé) on le met de côté quelques minutes même si on se doute qu'il a un lien avec le port 1337 qui fait tourner un service inconnu.  

Le serveur web livre le site personnel de bob (*bob295018409@gmail.com*) sur lequel ce dernier partage son CV. Au vu des émoticônes de palmiers et hamacs et la police de caractère *Comic Sans* des familles ce cher Bob risque d'avoir du mal à trouver un travail :p  

A part ça il semble utiliser son site comme un block-note pour mots de passe car on trouve le commentaire *P1:qGQjwO4h6g* au début du code HTML.  

Un *gobuster* ne nous ramène rien d'intéressant donc il est temps de nous pencher sur ce binaire !  

Analyse en très molo
--------------------

Quand on lance le binaire il nous demande de saisir l'adresse IP du service. Ça donne ceci :  

```plain
IP: 192.168.2.2
Enter Password: toto
Command to be executed: echo Hello World, you are currently running as: ;whoami

CH1:
Attempting to connect...

 -= Auth Failed Closing Connection... =- 

Traceback (most recent call last):
  File "/home/c0rruptedb1t/MEGA/Projects And Operations/Project Replay/scripts/client.py", line 86, in <module>
socket.error: [Errno 104] Connection reset by peer
```

Le traceback Python n'est pas un troll mais s'explique simplement par le fait que le code Python a été compilé avec [Nuikta](https://nuitka.net/pages/overview.html).  

Cela se détermine aisément en appliquant un *strings* sur le binaire. Au passage on voit les noms de fonctions internes au langage Python (commençant par *Py*) comme quoi l'interpréteur n'est pas compressé.  

On remarque aussi d'autres chaines d'intérêt :  

```plain

Enter Password:
sendmsgkeyencodexornotes00admincmd;echo Hello World, you are currently running as: ;whoami
decodestring
--=======NOTES=======--
 +Buy new milk (the current one is chunky)
 +2nd half of password is: h0TAIRNXuQcDu9Lqsyul
 +Find a new job
 +Call mom
=====[END]=====
commandlettersrecvoschoicesystem
-= TERMINATING CONNNECTION =- 
client_socketrandominputstrclearraw_input
Command to be executed:
replacejointimebase64
?exit1230012300admincmd;
SOCK_STREAM
connectsleepoutdataappendXORtmp
Attempting to connect...(
Definitely the password I swear -> password123 <-
Definitely the password I sweartypesbye<module>
encodestringnums
Hello there you're not being naughty are you? bob_pass123456789
```

Ces chaînes apparaissent en réalité accolées, j'ai découpé en lignes pour que ce soit plus lisible. Les habitués de Python sauront reconnaître les mots clés du langage dans ce charabia.  

Lancer un *ltrace* ou un *strace* retourne bien trop d'output sans intérêt. Le mieux que l'on puisse faire est de lancer *Wireshark* et de surveiller les communications générées entre notre machine et celle du CTF :  

![VulnHub Replay CTF first trafic analysis](https://github.com/devl00p/blog/raw/master/images/vulnhub/replay_trafic1.png)

Le premier comportement suspect c'est la façon dont sont envoyées les données au serveur, par petits blocs, ce qui explique notamment le temps de traitement assez long.  

Sans trop de difficultés on devine qu'une fois que le serveur a envoyé la chaîne *CH1:*  au client ce dernier envoie la représentation décimale de chaque caractère du mot de passe saisi (la lettre t correspond à 116, et la lettre o à 111).  

Le client envoie ensuite un padding composé des caractères 0 jusqu'à obtenir l'équivalent de 30 envois.  



*Published July 19 2019 at 18 49*