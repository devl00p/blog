# Solution du CTF Pandora's Box de VulnHub (RSA level)

[La précédente étape](https://github.com/devl00p/blog/blob/main/ctf_writeups/Solution%20du%20CTF%20Pandora's%20Box%20de%20VulnHub%20(level%205).md) qui nous avait donné un shell root nous avait laissé avec un flag au format txt sur les mains. Voci son contenu :

```shellsession
$ cat fl4gz0r.tXt                                                                                                      
 _______  _______  __    _  ______   _______  ______    _______  __   _______    _______  _______  __   __             
|       ||   _   ||  |  | ||      | |       ||    _ |  |   _   ||  | |       |  |  _    ||  _    ||  |_|  |            
|    _  ||  |_|  ||   |_| ||  _    ||   _   ||   | ||  |  |_|  ||__| |  _____|  | |_|   || | |   ||       |            
|   |_| ||       ||       || | |   ||  | |  ||   |_||_ |       |     | |_____   |       || | |   ||       |            
|    ___||       ||  _    || |_|   ||  |_|  ||    __  ||       |     |_____  |  |  _   | | |_|   | |     |             
|   |    |   _   || | |   ||       ||       ||   |  | ||   _   |      _____| |  | |_|   ||       ||   _   |            
|___|    |__| |__||_|  |__||______| |_______||___|  |_||__| |__|     |_______|  |_______||_______||__| |__|            
                                                                                                                       
                                                                                                                       
                                                                                                                       
Goobjob! It seems like you r00ted Pandora's box I hope you liked the challenges as much as I enjoyed making them.      
It's time for you to collect your flag, the only thing is that it's encrypted with RSA 256 bits, can you crack it?     
                                                                                                                       
encrypted_flag: 0x41a31d931bd8c7dd1707942484075b4ae98a6e98c40a9b21f7424c7e91ac1fca                                     
                                                                                                                       
PublicKey info                                                                                                         
--------------                                                                                                         
E: 0x10001                                                                                                             
N: 0xD4572CED12D668BC34A4F36311B9A80AB212D7986AA9417B6FD9D474076605F9                                                  
                                                                                                                       
                                                                                                                       
Credits:                                                                                                               
Special thanks to Barrebas and Jelle for testing the challenges and the feedback, you guys r0ck!
```

Ces histoire de RSA à casser sont un classique de certains CTFs. A tel point qu'il en est ressortit un projet nommé [RsaCtfTool: RSA attack tool (mainly for ctf) - retreive private key from weak public key and/or uncipher data](https://github.com/RsaCtfTool/RsaCtfTool).

On va d'abord récupérer la clé privée via le modulo et l'exposant donnés dans le fichier :

```shellsession
$ python RsaCtfTool.py -n 0xD4572CED12D668BC34A4F36311B9A80AB212D7986AA9417B6FD9D474076605F9 -e 0x10001 --private

[*] Testing key /tmp/tmps4606bw9.
attack initialized...
attack initialized...
[*] Performing factordb attack on /tmp/tmps4606bw9.
[*] Attack success with factordb method !

Results for /tmp/tmps4606bw9:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIGrAgEAAiEA1Fcs7RLWaLw0pPNjEbmoCrIS15hqqUF7b9nUdAdmBfkCAwEAAQIg
GRWLSx5Ukd7Z4TqXU3q5LQMv+Ky5ar4ZyMZ6TcJ3v7kCEQDk5n+l6BUcfejBSWqJ
dLQjAhEA7XrIFeNZPHM3EQjQU+YBMwIRANhDirDWUDPmJeWQlq6d658CEQDQFNVc
2GhIX2vQsThZSx+hAhB/nIYYew5GTSg7bUMSTbWu
-----END RSA PRIVATE KEY-----
```

Je recopie cette clé dans un fichier puis je place le contenu chiffré dans un autre via cette commande :

```bash
echo -n 41a31d931bd8c7dd1707942484075b4ae98a6e98c40a9b21f7424c7e91ac1fca | xxd -p -r > cypher
```

Il n'y a plus qu'à déchiffrer le texte chiffré :

```shellsession
$ python RsaCtfTool.py --key private_key --uncipherfile cypher 
private argument is not set, the private key will not be displayed, even if recovered.

Unciphered data :
HEX : 0x666c61673a7b315f6834636b33645f346e645f7230307433645f70623078217d
INT (big endian) : 46327402290918174043635208345514425153295095445754209757332636002669011935613
INT (little endian) : 56598241540051872119636592348093658341646336008225128263608138536930647305318
utf-8 : flag:{1_h4ck3d_4nd_r00t3d_pb0x!}
utf-16 : 汦条笺弱㑨正搳㑟摮牟〰㍴彤扰砰紡STR : b'flag:{1_h4ck3d_4nd_r00t3d_pb0x!}'
HEX : 0x41a31d931bd8c7dd1707942484075b4ae98a6e98c40a9b21f7424c7e91ac1fca
INT (big endian) : 29688535346160019177103397808175541291644232862557580642913337300571801788362
INT (little endian) : 91423158695692576025449137483171354249749058586351633960520436465765126611777
utf-16 : ꍁ錝𖷇ܗ⒔ބ䩛諩顮ૄ↛䋷繌겑쨟STR : b'A\xa3\x1d\x93\x1b\xd8\xc7\xdd\x17\x07\x94$\x84\x07[J\xe9\x8an\x98\xc4\n\x9b!\xf7BL~\x91\xac\x1f\xca'
```

On a bien notre flag !

*Publié le 27 décembre 2022*
